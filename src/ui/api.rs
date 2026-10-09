//! The authenticated JSON API used by the web UI.

use super::{
    auth::{AuthError, Authenticator},
    rules_doc::{RulesDocError, RulesDocument, edit_document, read_document},
    web_rules::{WebRulesFile, WriteOutcome},
};
use crate::{
    error::ErrorChain,
    runtime::{ReloadError, ReloadHandle},
    telemetry::DomainStats,
};
use rama::http::{
    Body, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, body::util::BodyExt,
    header,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{io, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::Mutex;

/// Bound body reads independently of the byte limit so idle clients cannot retain connections.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest accepted JSON request body.
const BODY_LIMIT: usize = 1024 * 1024;
/// Expire the legacy cookie without ever using it to authenticate a request.
pub const CLEAR_COOKIE: &str = "exwall_session=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0";
/// The message shown when the file changed underneath an edit.
const CONFLICT_MESSAGE: &str = "05-web.toml changed. Reload before saving.";
/// The message shown when a save was written but the ruleset could not be activated.
const NOT_ACTIVATED_MESSAGE: &str = "05-web.toml was saved, but the rules could not be activated; \
     the previous rules remain active. Check the other rule files and the service log.";

/// Credentials accepted by the login endpoint.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    /// The submitted username.
    username: String,
    /// The submitted password.
    password: String,
}

/// Server-side failures reported to clients only as a generic 500.
#[derive(Debug, Error)]
pub enum InternalError {
    /// Session storage failed.
    #[error("session storage")]
    Auth(#[from] AuthError),
    /// The rules file could not be read or written.
    #[error("access 05-web.toml")]
    RulesFile(#[source] io::Error),
    /// The stored rules file is unreadable.
    #[error("read 05-web.toml")]
    Document(#[source] RulesDocError),
    /// A blocking file task failed.
    #[error("file task failed")]
    Task(#[from] tokio::task::JoinError),
}

/// Every API failure, mapped to exactly one status and JSON message.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The method is not GET, POST, or PUT.
    #[error("Method not allowed")]
    MethodNotAllowed,
    /// A write did not come from a same-origin JSON request.
    #[error("Same-origin JSON requests required")]
    CrossOrigin,
    /// The body did not arrive in time.
    #[error("Request body timed out")]
    BodyTimeout,
    /// The login body is malformed or too large.
    #[error("Invalid login request")]
    InvalidLogin,
    /// The rules body is malformed or too large.
    #[error("Invalid rules request")]
    InvalidRules,
    /// Authentication is missing or invalid.
    #[error("Authentication required")]
    Unauthorized,
    /// No such endpoint.
    #[error("Endpoint not found")]
    NotFound,
    /// The rules file changed since the client read it.
    #[error("{CONFLICT_MESSAGE}")]
    Conflict,
    /// The edited rules are invalid.
    #[error("{0}")]
    Validation(String),
    /// The edited file was written, but the complete ruleset could not be published.
    ///
    /// Typically another rule file is invalid; the previous policy stays active
    /// and the saved rules take effect once the ruleset loads again.
    #[error("{NOT_ACTIVATED_MESSAGE}")]
    NotActivated(#[source] Arc<ReloadError>),
    /// A server-side failure.
    #[error("Server operation failed")]
    Internal(#[from] InternalError),
}

impl ApiError {
    /// The HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::CrossOrigin => StatusCode::FORBIDDEN,
            Self::BodyTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::InvalidLogin | Self::InvalidRules | Self::Validation(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::NotActivated(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Render the error as a JSON response, logging server-side failures with their causes.
    ///
    /// Causes are logged rather than returned so responses never disclose host details.
    pub fn into_response(self) -> Response {
        match &self {
            Self::Internal(error) => {
                tracing::error!(error = %ErrorChain(error), "UI API request failed");
            }
            Self::NotActivated(error) => {
                tracing::error!(
                    error = %ErrorChain(error.as_ref()),
                    "saved UI rules could not be activated; keeping previous policy"
                );
            }
            _ => {}
        }
        json(self.status(), &serde_json::json!({ "error": self.to_string() }))
    }
}

impl From<AuthError> for ApiError {
    /// Session failures are internal errors.
    fn from(error: AuthError) -> Self {
        Self::Internal(InternalError::Auth(error))
    }
}

/// Why a JSON body could not be decoded.
enum BodyError {
    /// The body did not arrive within the deadline.
    Timeout,
    /// The body was too large, unreadable, or not the expected JSON.
    Invalid,
}

/// UI API state and a lock serializing rule reads and writes after body collection.
pub struct Api {
    /// Credential and session checks.
    auth: Authenticator,
    /// The editable rules file.
    rules: WebRulesFile,
    /// Activates saved rules.
    reload: ReloadHandle,
    /// Domain counters and denials.
    stats: DomainStats,
    /// Serializes rule reads and writes.
    lock: Mutex<()>,
}

impl Api {
    /// Assemble the API from its services.
    pub fn new(
        auth: Authenticator,
        rules: WebRulesFile,
        reload: ReloadHandle,
        stats: DomainStats,
    ) -> Self {
        Self {
            auth,
            rules,
            reload,
            stats,
            lock: Mutex::new(()),
        }
    }

    /// Route an API request, converting every failure to its JSON response.
    pub async fn response(&self, request: Request) -> Response {
        match self.handle(request).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        }
    }

    /// Authenticate endpoints and constrain browser writes to same-origin JSON requests.
    async fn handle(&self, request: Request) -> Result<Response, ApiError> {
        let path = request.uri().path_or_root().into_owned();
        let method = request.method().clone();
        if !matches!(method, Method::GET | Method::POST | Method::PUT) {
            return Err(ApiError::MethodNotAllowed);
        }
        if method != Method::GET && !is_same_origin_json(request.headers()) {
            return Err(ApiError::CrossOrigin);
        }
        if method == Method::POST && path == "/api/login" {
            return self.login(request).await;
        }
        if !self.auth.authenticate(request.headers()).await? {
            return Err(ApiError::Unauthorized);
        }
        match (method, path.as_str()) {
            (Method::GET, "/api/session") => {
                Ok(json(StatusCode::OK, &serde_json::json!({ "username": self.auth.username() })))
            }
            (Method::POST, "/api/logout") => {
                self.auth.logout(request.headers()).await?;
                Ok(with_cleared_cookie(json(StatusCode::OK, &serde_json::json!({}))))
            }
            (Method::GET, "/api/http-denials") => {
                Ok(json(StatusCode::OK, &self.stats.denials_snapshot()))
            }
            (Method::GET, "/api/domains") => Ok(json(StatusCode::OK, &self.stats.snapshot())),
            (Method::GET, "/api/rules") => {
                let _guard = self.lock.lock().await;
                Ok(json(StatusCode::OK, &self.read_rules().await?))
            }
            (Method::PUT, "/api/rules") => self.save_rules(request).await,
            _ => Err(ApiError::NotFound),
        }
    }

    /// Exchange valid credentials for a persistent bearer token.
    async fn login(&self, request: Request) -> Result<Response, ApiError> {
        let login: Login = read_json(request).await.map_err(|error| match error {
            BodyError::Timeout => ApiError::BodyTimeout,
            BodyError::Invalid => ApiError::InvalidLogin,
        })?;
        let Some(token) = self.auth.login(&login.username, &login.password).await? else {
            return Err(ApiError::Unauthorized);
        };
        let body = serde_json::json!({ "username": self.auth.username(), "token": token });
        Ok(with_cleared_cookie(json(StatusCode::OK, &body)))
    }

    /// Validate and write edited rules, then activate them before responding.
    ///
    /// The response is sent only after the complete ruleset has been published,
    /// so a successful save is already enforced. If publishing fails, the write
    /// is kept and reported as not activated.
    async fn save_rules(&self, request: Request) -> Result<Response, ApiError> {
        // No shared lock is held while waiting for client-controlled bytes.
        let draft: RulesDocument = read_json(request).await.map_err(|error| match error {
            BodyError::Timeout => ApiError::BodyTimeout,
            BodyError::Invalid => ApiError::InvalidRules,
        })?;
        let _guard = self.lock.lock().await;
        let current = self.read_rules().await?;
        if draft.revision != current.revision {
            return Err(ApiError::Conflict);
        }
        let edited = edit_document(&draft)
            .map_err(|error| ApiError::Validation(ErrorChain(&error).to_string()))?;
        let rules = self.rules.clone();
        let revision = draft.revision.clone();
        let outcome =
            tokio::task::spawn_blocking(move || rules.replace_if_unchanged(&revision, &edited))
                .await
                .map_err(InternalError::Task)?
                .map_err(InternalError::RulesFile)?;
        if outcome == WriteOutcome::Conflict {
            return Err(ApiError::Conflict);
        }
        self.reload.reload_rules().await.map_err(ApiError::NotActivated)?;
        Ok(json(StatusCode::OK, &self.read_rules().await?))
    }

    /// Read the rules file into editable drafts off the async runtime.
    async fn read_rules(&self) -> Result<RulesDocument, InternalError> {
        let rules = self.rules.clone();
        let text = tokio::task::spawn_blocking(move || rules.read())
            .await?
            .map_err(InternalError::RulesFile)?;
        read_document(text).map_err(InternalError::Document)
    }
}

/// Require a JSON content type and a same-origin (or absent) Origin for state changes.
fn is_same_origin_json(headers: &HeaderMap) -> bool {
    let cross_site = headers.get("sec-fetch-site").is_some_and(|value| value == "cross-site");
    let bad_origin = headers.get(header::ORIGIN).is_some_and(|origin| {
        let Ok(origin) = origin.to_str() else {
            return true;
        };
        let authority = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://"));
        authority.is_none()
            || authority != headers.get(header::HOST).and_then(|value| value.to_str().ok())
    });
    let is_json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(';').next() == Some("application/json"));
    !cross_site && !bad_origin && is_json
}

/// Decode a bounded JSON body without allowing unbounded client allocations or waits.
async fn read_json<T: DeserializeOwned>(request: Request) -> Result<T, BodyError> {
    let body = rama::http::body::util::Limited::new(request.into_body(), BODY_LIMIT);
    let collected = tokio::time::timeout(BODY_TIMEOUT, body.collect())
        .await
        .map_err(|_| BodyError::Timeout)?
        .map_err(|_| BodyError::Invalid)?;
    serde_json::from_slice(&collected.to_bytes()).map_err(|_| BodyError::Invalid)
}

/// Expire the legacy session cookie on a response.
fn with_cleared_cookie(mut response: Response) -> Response {
    response.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static(CLEAR_COOKIE));
    response
}

/// Encode an API result with cache prevention and browser MIME enforcement.
fn json(status: StatusCode, value: &impl Serialize) -> Response {
    let body = serde_json::to_vec(value).expect("API JSON values are serializable");
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::RuntimeSettings,
        policy::{Host, LoadError, MissingDirectory, Policy, load_rules},
        runtime::{PolicyStore, Reloader},
        ui::{
            auth::{Credentials, FileSessionStore, RandomTokens},
            rules_doc::Draft,
        },
    };
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{fs, path::Path};

    /// An API wired to a running reloader over temporary directories.
    struct Harness {
        /// The API under test.
        api: Api,
        /// The policy the reloader publishes.
        store: Arc<PolicyStore>,
        /// The rules directory.
        rules: std::path::PathBuf,
        /// The sessions directory.
        sessions: std::path::PathBuf,
    }

    /// Construct an isolated API whose files never touch host service paths.
    fn harness(directory: &Path, password: &str) -> Harness {
        let rules = directory.join("rules");
        let sessions = directory.join("sessions");
        let loaded: Result<_, LoadError> = load_rules(&rules, MissingDirectory::Empty);
        let store =
            Arc::new(PolicyStore::new(Policy::new(RuntimeSettings::default(), loaded.unwrap())));
        let (reloader, handle) =
            Reloader::new(directory.join("config.toml"), rules.clone(), store.clone(), None);
        tokio::spawn(reloader.run());
        let auth = Authenticator::new(
            Credentials::new("admin", password),
            Arc::new(FileSessionStore::new(sessions.clone())),
            Arc::new(RandomTokens),
        );
        let api = Api::new(auth, WebRulesFile::new(rules.clone()), handle, DomainStats::default());
        Harness {
            api,
            store,
            rules,
            sessions,
        }
    }

    /// Build JSON requests with optional authentication.
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
    async fn decode<T: DeserializeOwned>(response: Response) -> T {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Log in through the API and return a bearer Authorization value.
    async fn login(api: &Api, password: &str) -> String {
        let response = api
            .response(request(
                Method::POST,
                "/api/login",
                None,
                &serde_json::json!({"username": "admin", "password": password}),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::SET_COOKIE], CLEAR_COOKIE);
        let body: serde_json::Value = decode(response).await;
        assert_eq!(body["username"], "admin");
        format!("Bearer {}", body["token"].as_str().unwrap())
    }

    /// Reject both ambient cookies and replay of session files issued before bearer migration.
    #[tokio::test]
    async fn rejects_cookie_authentication_and_legacy_sessions() {
        let temporary = tempfile::tempdir().unwrap();
        let harness = harness(temporary.path(), "secret:password");
        let bearer = login(&harness.api, "secret:password").await;
        let token = bearer.strip_prefix("Bearer ").unwrap();
        let cookie = format!("exwall_session={token}");
        let response = harness
            .api
            .response(request(Method::GET, "/api/rules", Some(("cookie", &cookie)), &()))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let path = harness.sessions.join(format!("{token}.json"));
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("bearer");
        fs::write(path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let response = harness
            .api
            .response(request(Method::GET, "/api/rules", Some(("authorization", &bearer)), &()))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Keep authenticated requests responsive while login or rule-upload bodies are stalled.
    #[tokio::test]
    async fn slow_bodies_do_not_lock_other_requests() {
        let temporary = tempfile::tempdir().unwrap();
        let harness = harness(temporary.path(), "secret");
        let bearer = login(&harness.api, "secret").await;
        for (method, path) in [(Method::POST, "/api/login"), (Method::PUT, "/api/rules")] {
            let mut stalled = request(method, path, Some(("authorization", &bearer)), &());
            *stalled.body_mut() = Body::from_stream(rama::stream::pending::<
                Result<rama::bytes::Bytes, std::io::Error>,
            >());
            let slow = harness.api.response(stalled);
            tokio::pin!(slow);
            assert!(tokio::time::timeout(Duration::from_millis(20), &mut slow).await.is_err());
            let response = tokio::time::timeout(
                Duration::from_secs(1),
                harness.api.response(request(
                    Method::GET,
                    "/api/rules",
                    Some(("authorization", &bearer)),
                    &(),
                )),
            )
            .await
            .expect("a stalled body must not lock the API");
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    /// Bearer sessions persist privately, survive restart, and are revoked by logout.
    #[tokio::test]
    async fn persistent_session_lifecycle() {
        let temporary = tempfile::tempdir().unwrap();
        let harness = harness(temporary.path(), "secret:password");
        let unauthorized =
            harness.api.response(request(Method::GET, "/api/rules", None, &())).await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let wrong = harness
            .api
            .response(request(
                Method::POST,
                "/api/login",
                None,
                &serde_json::json!({"username": "admin", "password": "wrong"}),
            ))
            .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let bearer = login(&harness.api, "secret:password").await;
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&harness.sessions).unwrap().permissions().mode() & 0o777, 0o700);
        let restarted = self::harness(temporary.path(), "secret:password");
        let session = restarted
            .api
            .response(request(Method::GET, "/api/session", Some(("authorization", &bearer)), &()))
            .await;
        assert_eq!(session.status(), StatusCode::OK);
        assert_eq!(decode::<serde_json::Value>(session).await["username"], "admin");
        let changed = self::harness(temporary.path(), "changed");
        let rejected = changed
            .api
            .response(request(Method::GET, "/api/session", Some(("authorization", &bearer)), &()))
            .await;
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        let logout = harness
            .api
            .response(request(
                Method::POST,
                "/api/logout",
                Some(("authorization", &bearer)),
                &serde_json::json!({}),
            ))
            .await;
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(logout.headers()[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
        assert_eq!(fs::read_dir(&harness.sessions).unwrap().count(), 0);
        let after = harness
            .api
            .response(request(Method::GET, "/api/session", Some(("authorization", &bearer)), &()))
            .await;
        assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
    }

    /// Verify Basic authentication, comment retention, validation, conflicts, and activation.
    #[tokio::test]
    async fn edits_validate_and_activate_rules() {
        let temporary = tempfile::tempdir().unwrap();
        let harness = harness(temporary.path(), "secret:password");
        fs::create_dir_all(&harness.rules).unwrap();
        let original = "# Web rules\n[[allow]]\n# Host comment\ndomain = 'old.test' # Keep this\nmethods = ['GET']\n[[allow.inject_headers]]\nname = 'X-Example'\nvalue = 'original'\n";
        fs::write(harness.rules.join("05-web.toml"), original).unwrap();
        fs::write(harness.rules.join("other.toml"), "[[allow]]\ndomain = 'other.test'\n").unwrap();
        let basic = format!("Basic {}", STANDARD.encode("admin:secret:password"));
        let auth = Some(("authorization", basic.as_str()));
        let response = harness.api.response(request(Method::GET, "/api/rules", auth, &())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut draft: RulesDocument = decode(response).await;
        draft.rules[0].fields.insert("domain".into(), "new.test".into());
        let response = harness.api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let allows = |host: &str| harness.store.load().rules.dns_rule(&Host::new(host)).is_some();
        assert!(allows("new.test"));
        assert!(allows("other.test"));
        let saved = fs::read_to_string(harness.rules.join("05-web.toml")).unwrap();
        assert!(saved.contains("# Keep this"));
        let stale = harness.api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = decode(stale).await;
        assert_eq!(body["error"], CONFLICT_MESSAGE);
        let mut draft = harness.api.read_rules().await.unwrap();
        draft.rules[0].fields.insert("domain_regex".into(), "[".into());
        let invalid = harness.api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = decode(invalid).await;
        assert!(body["error"].as_str().unwrap().starts_with("05-web.toml:allow#1"));
        assert_eq!(fs::read_to_string(harness.rules.join("05-web.toml")).unwrap(), saved);
        draft.rules.clear();
        let cleared = harness.api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(cleared.status(), StatusCode::OK);
        assert!(!allows("new.test"));
        assert!(allows("other.test"));
    }

    /// A save blocked by another invalid file is kept on disk and reported as not activated.
    #[tokio::test]
    async fn saves_report_when_other_files_block_activation() {
        let temporary = tempfile::tempdir().unwrap();
        let harness = harness(temporary.path(), "secret");
        fs::create_dir_all(&harness.rules).unwrap();
        fs::write(harness.rules.join("other.toml"), "[[allow]]\nunknown = 1\n").unwrap();
        let basic = format!("Basic {}", STANDARD.encode("admin:secret"));
        let auth = Some(("authorization", basic.as_str()));
        let mut draft: RulesDocument =
            decode(harness.api.response(request(Method::GET, "/api/rules", auth, &())).await).await;
        draft.rules.push(Draft {
            index: None,
            fields: [("domain".to_owned(), "saved.test".into())].into(),
        });
        let before = harness.store.snapshot();
        let response = harness.api.response(request(Method::PUT, "/api/rules", auth, &draft)).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: serde_json::Value = decode(response).await;
        assert_eq!(body["error"], NOT_ACTIVATED_MESSAGE);
        assert!(!body["error"].as_str().unwrap().contains("other.toml"));
        let saved = fs::read_to_string(harness.rules.join("05-web.toml")).unwrap();
        assert!(saved.contains("saved.test"));
        assert!(Arc::ptr_eq(&before, &harness.store.snapshot()));
    }

    /// Reject cross-origin mutations, unknown endpoints, methods, and disabled credentials.
    #[tokio::test]
    async fn rejects_unsafe_or_unauthenticated_requests() {
        let temporary = tempfile::tempdir().unwrap();
        let harness = harness(temporary.path(), "secret:password");
        let basic = format!("Basic {}", STANDARD.encode("admin:secret:password"));
        let mut cross_origin =
            request(Method::PUT, "/api/rules", Some(("authorization", &basic)), &());
        cross_origin.headers_mut().insert(header::HOST, "localhost:58000".parse().unwrap());
        cross_origin.headers_mut().insert(header::ORIGIN, "http://other.test".parse().unwrap());
        assert_eq!(harness.api.response(cross_origin).await.status(), StatusCode::FORBIDDEN);
        let mut form = request(Method::POST, "/api/login", None, &());
        form.headers_mut().insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        assert_eq!(harness.api.response(form).await.status(), StatusCode::FORBIDDEN);
        let delete = request(Method::DELETE, "/api/rules", Some(("authorization", &basic)), &());
        assert_eq!(harness.api.response(delete).await.status(), StatusCode::METHOD_NOT_ALLOWED);
        let missing = request(Method::GET, "/api/missing", Some(("authorization", &basic)), &());
        assert_eq!(harness.api.response(missing).await.status(), StatusCode::NOT_FOUND);
        let malformed = request(Method::POST, "/api/login", None, &serde_json::json!({"user": 1}));
        assert_eq!(harness.api.response(malformed).await.status(), StatusCode::BAD_REQUEST);
        let disabled = self::harness(temporary.path(), "");
        let response = disabled
            .api
            .response(request(Method::GET, "/api/rules", Some(("authorization", &basic)), &()))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Each API error has one status and a JSON body carrying its message.
    #[tokio::test]
    async fn errors_map_to_status_and_json() {
        for (error, status) in [
            (ApiError::MethodNotAllowed, 405),
            (ApiError::CrossOrigin, 403),
            (ApiError::BodyTimeout, 408),
            (ApiError::InvalidLogin, 400),
            (ApiError::InvalidRules, 400),
            (ApiError::Unauthorized, 401),
            (ApiError::NotFound, 404),
            (ApiError::Conflict, 409),
            (ApiError::Validation("bad".into()), 400),
            (ApiError::NotActivated(Arc::new(ReloadError::Unavailable)), 500),
            (ApiError::Internal(InternalError::RulesFile(io::Error::other("secret path"))), 500),
        ] {
            let message = error.to_string();
            let response = error.into_response();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body: serde_json::Value = decode(response).await;
            assert_eq!(body["error"], message);
            assert!(!message.contains("secret path"));
        }
    }
}
