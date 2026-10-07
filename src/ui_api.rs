//! Authenticated, persistent sessions and format-preserving web rule editing.
use crate::{
    config::UiConfig,
    error::{Context, Result, ensure},
    rules::RuleSet,
    state::{Policy, SharedPolicy},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rama::http::{Body, Method, Request, Response, StatusCode, body::util::BodyExt, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table};

/// A fixed one-year lifetime in seconds, shared by the cookie and session record.
const SESSION_LIFETIME: u64 = 365 * 24 * 60 * 60;

/// UI API settings and a lock serializing reads, updates, and session mutations.
pub struct Api {
    config: UiConfig,
    directory: PathBuf,
    policy: SharedPolicy,
    lock: Mutex<()>,
    domains: crate::domains::Domains,
}

/// Credentials accepted by the login endpoint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}

/// A private disk record invalidated by expiration or changed configured credentials.
#[derive(Serialize, Deserialize)]
struct Session {
    username: String,
    expires_at: u64,
    credentials: String,
}

/// One editable allow table, referencing its original table to retain comments.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    index: Option<usize>,
    fields: BTreeMap<String, toml::Value>,
}

/// The original document acts as a revision token for optimistic concurrency.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesDocument {
    revision: String,
    rules: Vec<Draft>,
}

impl Api {
    /// Attach the UI's startup settings to the active policy and rules directory.
    pub fn new(
        config: UiConfig,
        directory: PathBuf,
        policy: SharedPolicy,
        domains: crate::domains::Domains,
    ) -> Self {
        Self {
            config,
            directory,
            policy,
            domains,
            lock: Mutex::new(()),
        }
    }

    /// Route API requests and report internal failures without disclosing host details.
    pub async fn response(&self, request: Request) -> Response {
        let _guard = self.lock.lock().await;
        match self.handle(request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!(%error, "UI API request failed");
                json(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": "Server operation failed"}),
                )
            }
        }
    }

    /// Authenticate endpoints and constrain browser writes to same-origin JSON requests.
    async fn handle(&self, request: Request) -> Result<Response> {
        let path = request.uri().path_or_root().to_string();
        let method = request.method().clone();
        if !matches!(method, Method::GET | Method::POST | Method::PUT) {
            return Ok(json(
                StatusCode::METHOD_NOT_ALLOWED,
                &serde_json::json!({"error": "Method not allowed"}),
            ));
        }
        if method != Method::GET {
            let headers = request.headers();
            let cross_site =
                headers.get("sec-fetch-site").is_some_and(|value| value == "cross-site");
            let bad_origin = headers.get(header::ORIGIN).is_some_and(|origin| {
                let Ok(origin) = origin.to_str() else {
                    return true;
                };
                let authority =
                    origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://"));
                authority.is_none()
                    || authority != headers.get(header::HOST).and_then(|value| value.to_str().ok())
            });
            let is_json = headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.split(';').next() == Some("application/json"));
            if cross_site || bad_origin || !is_json {
                return Ok(json(
                    StatusCode::FORBIDDEN,
                    &serde_json::json!({"error": "Same-origin JSON requests required"}),
                ));
            }
        }
        if path == "/api/login" && method == Method::POST {
            let login: Login = match read_json(request).await {
                Ok(value) => value,
                Err(_) => {
                    return Ok(json(
                        StatusCode::BAD_REQUEST,
                        &serde_json::json!({"error": "Invalid login request"}),
                    ));
                }
            };
            if !self.credentials_match(&login.username, &login.password) {
                return Ok(unauthorized());
            }
            let token = self.create_session()?;
            let mut response =
                json(StatusCode::OK, &serde_json::json!({"username": self.config.username}));
            response.headers_mut().insert(header::SET_COOKIE, format!("exwall_session={token}; Path=/api; HttpOnly; SameSite=Strict; Max-Age={SESSION_LIFETIME}").parse().unwrap());
            return Ok(response);
        }
        if !self.authenticated(&request)? {
            return Ok(unauthorized());
        }
        match (method, path.as_str()) {
            (Method::GET, "/api/session") => {
                Ok(json(StatusCode::OK, &serde_json::json!({"username": self.config.username})))
            }
            (Method::POST, "/api/logout") => {
                if let Some(token) = cookie_token(&request) {
                    match fs::remove_file(self.session_path(token)) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let mut response = json(StatusCode::OK, &serde_json::json!({}));
                response.headers_mut().insert(
                    header::SET_COOKIE,
                    "exwall_session=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0"
                        .parse()
                        .unwrap(),
                );
                Ok(response)
            }
            (Method::GET, "/api/domains") => Ok(json(StatusCode::OK, &self.domains.snapshot())),
            (Method::GET, "/api/rules") => Ok(json(StatusCode::OK, &self.read_rules()?)),
            (Method::PUT, "/api/rules") => {
                let draft: RulesDocument = match read_json(request).await {
                    Ok(value) => value,
                    Err(_) => {
                        return Ok(json(
                            StatusCode::BAD_REQUEST,
                            &serde_json::json!({"error": "Invalid rules request"}),
                        ));
                    }
                };
                let current = self.read_rules()?;
                if draft.revision != current.revision {
                    return Ok(json(
                        StatusCode::CONFLICT,
                        &serde_json::json!({"error": "05-web.toml changed. Reload before saving."}),
                    ));
                }
                let edited = match edit_rules(&draft) {
                    Ok(edited) => edited,
                    Err(error) => {
                        return Ok(json(
                            StatusCode::BAD_REQUEST,
                            &serde_json::json!({"error": error.to_string()}),
                        ));
                    }
                };
                fs::create_dir_all(&self.directory)?;
                let path = self.directory.join("05-web.toml");
                // The root-owned rules directory deliberately permits edits only to this file.
                // Reuse its inode so exwall does not need directory write permissions.
                let mut file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)?;
                ensure!(file.metadata()?.is_file(), "web rules must be a regular file");
                let mut latest = String::new();
                file.read_to_string(&mut latest)?;
                if latest != draft.revision {
                    return Ok(json(
                        StatusCode::CONFLICT,
                        &serde_json::json!({"error": "05-web.toml changed. Reload before saving."}),
                    ));
                }
                use std::io::{Seek, SeekFrom};
                file.seek(SeekFrom::Start(0))?;
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                file.write_all(edited.as_bytes())?;
                file.set_len(edited.len() as u64)?;
                file.sync_all()?;
                if !self.policy.load().config.watch_rules {
                    let rules = RuleSet::load_existing(&self.directory)?;
                    let current = self.policy.load_full();
                    self.policy.store(Arc::new(Policy {
                        config: current.config.clone(),
                        rules,
                    }));
                }
                Ok(json(StatusCode::OK, &self.read_rules()?))
            }
            _ => {
                Ok(json(StatusCode::NOT_FOUND, &serde_json::json!({"error": "Endpoint not found"})))
            }
        }
    }

    /// Compare fixed-size digests so password comparison does not leak matching prefixes.
    fn credentials_match(&self, username: &str, password: &str) -> bool {
        if self.config.username.is_empty() || self.config.password.is_empty() {
            return false;
        }
        let provided = credential_digest(username, password);
        let expected = credential_digest(&self.config.username, &self.config.password);
        bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
    }

    /// Accept HTTP Basic credentials or a valid persistent session cookie.
    fn authenticated(&self, request: &Request) -> Result<bool> {
        if let Some(authorization) = request.headers().get(header::AUTHORIZATION) {
            let credentials = authorization
                .to_str()
                .ok()
                .and_then(|value| value.strip_prefix("Basic "))
                .and_then(|value| STANDARD.decode(value).ok())
                .and_then(|value| String::from_utf8(value).ok());
            return Ok(credentials
                .and_then(|value| {
                    value
                        .split_once(':')
                        .map(|(username, password)| self.credentials_match(username, password))
                })
                .unwrap_or(false));
        }
        let Some(token) = cookie_token(request) else {
            return Ok(false);
        };
        let path = self.session_path(token);
        let text = match fs::read(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let Ok(session) = serde_json::from_slice::<Session>(&text) else {
            return Ok(false);
        };
        if session.expires_at <= now()? {
            fs::remove_file(path)?;
            return Ok(false);
        }
        Ok(!self.config.username.is_empty()
            && !self.config.password.is_empty()
            && session.username == self.config.username
            && session.credentials
                == credential_digest(&self.config.username, &self.config.password))
    }

    /// Write an unpredictable bearer token to a private JSON record that survives restart.
    fn create_session(&self) -> Result<String> {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&self.config.sessions_dir)?;
        fs::set_permissions(&self.config.sessions_dir, fs::Permissions::from_mode(0o700))?;
        let mut random = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let session = Session {
            username: self.config.username.clone(),
            expires_at: now()? + SESSION_LIFETIME,
            credentials: credential_digest(&self.config.username, &self.config.password),
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.session_path(&token))?;
        file.write_all(&serde_json::to_vec(&session)?)?;
        file.sync_all()?;
        Ok(token)
    }

    /// Resolve a previously validated token beneath the configured session directory.
    fn session_path(&self, token: &str) -> PathBuf {
        self.config.sessions_dir.join(format!("{token}.json"))
    }

    /// Read ordinary field values while retaining the original document for comment preservation.
    fn read_rules(&self) -> Result<RulesDocument> {
        let revision = match fs::read_to_string(self.directory.join("05-web.toml")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        let document = revision.parse::<DocumentMut>().context("parse 05-web.toml")?;
        let parsed: toml::Value = toml::from_str(&revision)?;
        let mut rules = Vec::new();
        if let Some(item) = document.get("allow") {
            let tables = item.clone().into_array_of_tables().map_err(|_| {
                crate::error::Error::message("allow must be an array of rule tables")
            })?;
            for (index, table) in tables.iter().enumerate() {
                let mut fields = BTreeMap::new();
                for (key, _) in table {
                    fields.insert(key.to_owned(), parsed["allow"][index][key].clone());
                }
                rules.push(Draft {
                    index: Some(index),
                    fields,
                });
            }
        }
        Ok(RulesDocument {
            revision,
            rules,
        })
    }
}

/// Rebuild edited tables while preserving unchanged items and validating firewall semantics.
fn edit_rules(draft: &RulesDocument) -> Result<String> {
    let mut document =
        draft.revision.parse::<DocumentMut>().context("parse original 05-web.toml")?;
    let original = match document.get("allow") {
        Some(item) => item
            .clone()
            .into_array_of_tables()
            .map_err(|_| crate::error::Error::message("allow must be an array of rule tables"))?,
        None => ArrayOfTables::new(),
    };
    let original_values: toml::Value = toml::from_str(&draft.revision)?;
    let mut tables = ArrayOfTables::new();
    let mut indices = std::collections::HashSet::new();
    for rule in &draft.rules {
        let mut table = match rule.index {
            Some(index) => {
                ensure!(indices.insert(index), "duplicate original rule index");
                original.get(index).context("unknown original rule index")?.clone()
            }
            None => Table::new(),
        };
        table.retain(|key, _| rule.fields.contains_key(key));
        for (key, field) in &rule.fields {
            let wrapper = BTreeMap::from([("value", field)]);
            let rendered = toml_edit::ser::to_document(&wrapper).context("render rule field")?;
            let value = rendered.get("value").context("missing field value")?.clone();
            ensure!(value.is_value(), "expected a TOML value");
            // Semantically unchanged fields retain their original comments and syntax.
            let unchanged = original_values
                .get("allow")
                .and_then(|rules| rule.index.and_then(|index| rules.get(index)))
                .and_then(|original| original.get(key))
                == Some(field);
            if !unchanged {
                let mut value = value;
                if let (Some(old), Some(new)) =
                    (table.get(key).and_then(Item::as_value), value.as_value_mut())
                {
                    *new.decor_mut() = old.decor().clone();
                }
                if let Some(existing) = table.get_mut(key) {
                    *existing = value;
                } else {
                    table.insert(key, value);
                }
            }
        }
        tables.push(table);
    }
    if tables.is_empty() {
        document.remove("allow");
    } else {
        document["allow"] = Item::ArrayOfTables(tables);
    }
    let edited = document.to_string();
    RuleSet::parse(&edited, "05-web.toml")?;
    Ok(edited)
}

/// Return Unix time while retaining an explanatory source for clock failures.
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_secs())
}

/// Hash length-delimited credentials for constant-time comparisons and session invalidation.
fn credential_digest(username: &str, password: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(username.len().to_be_bytes());
    digest.update(username.as_bytes());
    digest.update(password.as_bytes());
    format!("{:x}", digest.finalize())
}

/// Extract only canonical hexadecimal session tokens to prevent pathname traversal.
fn cookie_token(request: &Request) -> Option<&str> {
    request.headers().get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|cookie| {
        let token = cookie.trim().strip_prefix("exwall_session=")?;
        (token.len() == 64
            && token.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then_some(token)
    })
}

/// Decode a bounded JSON body without allowing unbounded client allocations.
async fn read_json<T: serde::de::DeserializeOwned>(request: Request) -> Result<T> {
    let body = rama::http::body::util::Limited::new(request.into_body(), 1024 * 1024);
    let bytes = body.collect().await.context("read JSON request")?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

/// Encode API results with cache prevention and browser MIME enforcement.
fn json(status: StatusCode, value: &impl Serialize) -> Response {
    let mut response = Response::new(Body::from(
        serde_json::to_vec(value).expect("API JSON values are serializable"),
    ));
    *response.status_mut() = status;
    response.headers_mut().insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response.headers_mut().insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}

/// Report missing authentication without triggering a browser-native login dialog.
fn unauthorized() -> Response {
    json(StatusCode::UNAUTHORIZED, &serde_json::json!({"error": "Authentication required"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// Construct isolated APIs whose rule and session files never touch host service paths.
    fn test_api(directory: &std::path::Path, watch_rules: bool) -> Api {
        let config = Config {
            watch_rules,
            ..Config::default()
        };
        let policy = Arc::new(arc_swap::ArcSwap::from_pointee(Policy {
            config,
            rules: RuleSet::default(),
        }));
        Api::new(
            UiConfig {
                username: "admin".into(),
                password: "secret:password".into(),
                sessions_dir: directory.join("sessions"),
                ..UiConfig::default()
            },
            directory.join("rules"),
            policy,
            crate::domains::Domains::default(),
        )
    }

    /// Build JSON requests with optional Basic or cookie authentication.
    fn request(
        method: Method,
        path: &str,
        authentication: Option<(&str, &str)>,
        body: &impl Serialize,
    ) -> Request {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((name, value)) = authentication {
            builder = builder.header(name, value);
        }
        builder.body(Body::from(serde_json::to_vec(body).unwrap())).unwrap()
    }

    /// Decode typed response documents for assertions on the actual API representation.
    async fn decode<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Exercise cookie creation, private storage, restart persistence, revocation, and expiry.
    #[tokio::test]
    async fn persistent_session_lifecycle() {
        let temporary = tempfile::tempdir().unwrap();
        let api = test_api(temporary.path(), false);
        let unauthorized = api.response(request(Method::GET, "/api/rules", None, &())).await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let wrong = api
            .response(request(
                Method::POST,
                "/api/login",
                None,
                &serde_json::json!({"username": "admin", "password": "wrong"}),
            ))
            .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let response = api
            .response(request(
                Method::POST,
                "/api/login",
                None,
                &serde_json::json!({"username": "admin", "password": "secret:password"}),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap().to_owned();
        assert!(cookie.contains("HttpOnly; SameSite=Strict; Max-Age=31536000"));
        let token = cookie.split(';').next().unwrap().strip_prefix("exwall_session=").unwrap();
        let path = api.session_path(token);
        let session: Session = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(session.expires_at >= now().unwrap() + SESSION_LIFETIME - 1);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&api.config.sessions_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let restarted = test_api(temporary.path(), false);
        let response = restarted
            .response(request(Method::GET, "/api/session", Some(("cookie", &cookie)), &()))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut changed = test_api(temporary.path(), false);
        changed.config.password = "changed".into();
        assert_eq!(
            changed
                .response(request(Method::GET, "/api/session", Some(("cookie", &cookie)), &()))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let expired = Session {
            expires_at: now().unwrap() - 1,
            ..session
        };
        fs::write(&path, serde_json::to_vec(&expired).unwrap()).unwrap();
        assert_eq!(
            api.response(request(Method::GET, "/api/session", Some(("cookie", &cookie)), &()))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert!(!path.exists());
        let token = api.create_session().unwrap();
        let cookie = format!("exwall_session={token}");
        let logout = api
            .response(request(
                Method::POST,
                "/api/logout",
                Some(("cookie", &cookie)),
                &serde_json::json!({}),
            ))
            .await;
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(logout.headers()[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
        assert!(!api.session_path(&token).exists());
        assert!(
            cookie_token(&request(
                Method::GET,
                "/api/session",
                Some(("cookie", "exwall_session=../../etc/passwd")),
                &()
            ))
            .is_none()
        );
    }

    /// Verify Basic authentication, comment retention, validation, conflicts, and manual reload.
    #[tokio::test]
    async fn edits_validate_and_reload_without_watcher() {
        let temporary = tempfile::tempdir().unwrap();
        let api = test_api(temporary.path(), false);
        fs::create_dir_all(&api.directory).unwrap();
        let original = "# Web rules\n[[allow]]\n# Host comment\ndomain = 'old.test' # Keep this\nmethods = ['GET']\n[[allow.inject_headers]]\nname = 'X-Example'\nvalue = 'original'\n";
        fs::write(api.directory.join("05-web.toml"), original).unwrap();
        fs::write(api.directory.join("other.toml"), "[[allow]]\ndomain = 'other.test'\n").unwrap();
        let basic = format!("Basic {}", STANDARD.encode("admin:secret:password"));
        let auth = Some(("authorization", basic.as_str()));
        let response = api.response(request(Method::GET, "/api/rules", auth, &())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut draft: RulesDocument = decode(response).await;
        assert_eq!(draft.rules[0].fields["domain"].as_str(), Some("old.test"));
        assert_eq!(draft.rules[0].fields["inject_headers"][0]["name"].as_str(), Some("X-Example"));
        draft.rules[0].fields.insert("domain".into(), "new.test".into());
        let response = api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(api.policy.load().rules.dns_rule("new.test").is_some());
        assert!(api.policy.load().rules.dns_rule("other.test").is_some());
        let saved = fs::read_to_string(api.directory.join("05-web.toml")).unwrap();
        assert!(saved.contains("# Web rules"));
        assert!(saved.contains("# Host comment"));
        assert!(saved.contains("# Keep this"));
        assert!(saved.contains("methods = ['GET']"));
        assert!(saved.contains("[[allow.inject_headers]]"));
        let stale = api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        draft = api.read_rules().unwrap();
        draft.rules[0].fields.insert("domain_regex".into(), "[".into());
        assert_eq!(
            api.response(request(Method::PUT, "/api/rules", auth, &draft)).await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(fs::read_to_string(api.directory.join("05-web.toml")).unwrap(), saved);
        draft.rules.clear();
        assert_eq!(
            api.response(request(Method::PUT, "/api/rules", auth, &draft)).await.status(),
            StatusCode::OK
        );
        assert!(api.policy.load().rules.dns_rule("new.test").is_none());
        assert!(api.policy.load().rules.dns_rule("other.test").is_some());
    }

    /// Round-trip plain JSON strings, lists, booleans, and headers without user-supplied escaping.
    #[test]
    fn edits_serialize_typed_values_and_preserve_unchanged_documents() {
        let temporary = tempfile::tempdir().unwrap();
        let api = test_api(temporary.path(), false);
        fs::create_dir_all(&api.directory).unwrap();
        let fields = serde_json::json!({
            "domain_regex": [r"^one\.test$", r"^two\.test$"],
            "methods": ["GET", "POST"],
            "pathname_pattern": "/api/*",
            "pathname_regex": "^/api/",
            "stream": false,
            "inject_headers": [{"name": "X-Example", "value": "a \"quoted\" value \\ suffix"}]
        });
        let draft: RulesDocument = serde_json::from_value(serde_json::json!({
            "revision": "",
            "rules": [{"index": null, "fields": fields}]
        }))
        .unwrap();
        let saved = edit_rules(&draft).unwrap();
        let parsed: toml::Value = toml::from_str(&saved).unwrap();
        assert_eq!(serde_json::to_value(&parsed["allow"][0]).unwrap(), fields);
        fs::write(api.directory.join("05-web.toml"), &saved).unwrap();
        let read = api.read_rules().unwrap();
        assert_eq!(serde_json::to_value(&read.rules[0].fields).unwrap(), fields);
        assert_eq!(edit_rules(&read).unwrap(), saved);

        let mut changed = read;
        changed.rules[0].fields.insert("methods".into(), "ANY".into());
        changed.rules[0].fields.remove("domain_regex");
        changed.rules[0].fields.insert("domain".into(), "example.com".into());
        changed.rules[0].fields.insert("include_subdomains".into(), true.into());
        let saved = edit_rules(&changed).unwrap();
        let parsed: toml::Value = toml::from_str(&saved).unwrap();
        assert_eq!(parsed["allow"][0]["methods"].as_str(), Some("ANY"));
        assert_eq!(parsed["allow"][0]["domain"].as_str(), Some("example.com"));
        assert_eq!(parsed["allow"][0]["include_subdomains"].as_bool(), Some(true));
    }

    /// Ensure saves notify the real filesystem watcher without directly publishing a policy.
    #[tokio::test]
    async fn edits_are_picked_up_by_watcher() {
        let temporary = tempfile::tempdir().unwrap();
        let api = test_api(temporary.path(), true);
        fs::create_dir_all(&api.directory).unwrap();
        let mut watcher = crate::rules_watch::RulesWatcher::new(&api.directory).unwrap();
        let basic = format!("Basic {}", STANDARD.encode("admin:secret:password"));
        let draft = RulesDocument {
            revision: String::new(),
            rules: vec![Draft {
                index: None,
                fields: BTreeMap::from([("domain".into(), "watched.test".into())]),
            }],
        };
        let response = api
            .response(request(Method::PUT, "/api/rules", Some(("authorization", &basic)), &draft))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(api.policy.load().rules.rules.is_empty());
        tokio::time::timeout(std::time::Duration::from_secs(5), watcher.changed()).await.unwrap();
        watcher.reload(&api.policy).unwrap();
        assert!(api.policy.load().rules.dns_rule("watched.test").is_some());
    }

    /// Reject cross-origin mutations, malformed authentication, and disabled credentials.
    #[tokio::test]
    async fn rejects_unsafe_or_unauthenticated_requests() {
        let temporary = tempfile::tempdir().unwrap();
        let mut api = test_api(temporary.path(), false);
        let basic = format!("Basic {}", STANDARD.encode("admin:secret:password"));
        let mut cross_origin =
            request(Method::PUT, "/api/rules", Some(("authorization", &basic)), &());
        cross_origin.headers_mut().insert(header::HOST, "localhost:58000".parse().unwrap());
        cross_origin.headers_mut().insert(header::ORIGIN, "http://other.test".parse().unwrap());
        assert_eq!(api.response(cross_origin).await.status(), StatusCode::FORBIDDEN);
        let mut form = request(Method::POST, "/api/login", None, &());
        form.headers_mut().insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert_eq!(api.response(form).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            api.response(request(
                Method::GET,
                "/api/rules",
                Some(("authorization", "Basic !!!")),
                &()
            ))
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        api.config.password.clear();
        assert!(!api.credentials_match("admin", ""));
        assert_eq!(
            api.response(request(Method::GET, "/api/rules", Some(("authorization", &basic)), &()))
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
