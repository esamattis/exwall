//! UI authentication: configured credentials, HTTP Basic, and persistent bearer sessions.

use crate::BoxFuture;
use base64::{Engine, engine::general_purpose::STANDARD};
use rama::http::{HeaderMap, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// A fixed one-year lifetime in seconds for persistent bearer sessions.
pub const SESSION_LIFETIME: u64 = 365 * 24 * 60 * 60;
/// Random bytes in a session token.
const TOKEN_BYTES: usize = 32;

/// Session storage or token generation failures.
#[derive(Debug, Error)]
pub enum AuthError {
    /// A session file operation failed.
    #[error("{operation} session")]
    Session {
        /// What was being done.
        operation: &'static str,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// Random token bytes could not be read.
    #[error("generate session token")]
    Token(#[source] io::Error),
    /// The system clock precedes the Unix epoch.
    #[error("system clock precedes Unix epoch")]
    Clock(#[from] std::time::SystemTimeError),
    /// A session record could not be encoded.
    #[error("encode session")]
    Encode(#[from] serde_json::Error),
    /// A blocking session task failed.
    #[error("session task failed")]
    Task(#[from] tokio::task::JoinError),
}

/// Hash length-delimited credentials for constant-time comparisons and session invalidation.
pub fn credential_digest(username: &str, password: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(username.len().to_be_bytes());
    digest.update(username.as_bytes());
    digest.update(password.as_bytes());
    format!("{:x}", digest.finalize())
}

/// The configured UI account; absent when either value is empty.
#[derive(Clone)]
pub struct Credentials {
    /// The login name.
    username: String,
    /// The digest of the configured username and password.
    digest: String,
}

impl Credentials {
    /// Enable login only when both values are configured.
    pub fn new(username: &str, password: &str) -> Option<Self> {
        if username.is_empty() || password.is_empty() {
            return None;
        }
        Some(Self {
            username: username.to_owned(),
            digest: credential_digest(username, password),
        })
    }

    /// Compare fixed-size digests so comparison does not leak matching prefixes.
    pub fn matches(&self, username: &str, password: &str) -> bool {
        let provided = credential_digest(username, password);
        bool::from(provided.as_bytes().ct_eq(self.digest.as_bytes()))
    }
}

/// Extract canonical 64-hex-digit bearer tokens, rejecting anything usable as a path.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let token = headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    let canonical = token.len() == TOKEN_BYTES * 2
        && token.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    canonical.then_some(token)
}

/// The decoded value of an `Authorization: Basic` header; `Some(None)` when malformed.
fn basic_credentials(headers: &HeaderMap) -> Option<Option<(String, String)>> {
    let encoded =
        headers.get(header::AUTHORIZATION)?.to_str().ok()?.strip_prefix("Basic ")?.to_owned();
    let decoded = STANDARD.decode(encoded).ok().and_then(|value| String::from_utf8(value).ok());
    Some(decoded.and_then(|value| {
        value.split_once(':').map(|(username, password)| (username.to_owned(), password.to_owned()))
    }))
}

/// A private on-disk session, invalidated by expiry or changed credentials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Requires the bearer format so earlier cookie sessions are invalidated.
    pub bearer: bool,
    /// The account that logged in.
    pub username: String,
    /// Unix time after which the session is invalid.
    pub expires_at: u64,
    /// The credential digest at login time.
    pub credentials: String,
}

/// Generates unpredictable session tokens.
pub trait TokenSource: Send + Sync {
    /// Return a new lowercase hexadecimal token of 64 digits.
    fn token(&self) -> io::Result<String>;
}

/// Tokens from the kernel's random number generator.
pub struct RandomTokens;

impl TokenSource for RandomTokens {
    /// Read random bytes from /dev/urandom and hex-encode them.
    fn token(&self) -> io::Result<String> {
        let mut random = [0u8; TOKEN_BYTES];
        fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

/// Persistent session records keyed by token.
pub trait SessionStore: Send + Sync {
    /// Store a new record, failing if the token already exists.
    fn create<'a>(
        &'a self,
        token: &'a str,
        record: &'a SessionRecord,
    ) -> BoxFuture<'a, Result<(), AuthError>>;
    /// Load a record; unreadable or unparsable records are `None`.
    fn load<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, AuthError>>;
    /// Remove a record if it exists.
    fn remove<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), AuthError>>;
}

/// Sessions stored as private JSON files, accessed off the async runtime.
pub struct FileSessionStore {
    /// The private sessions directory.
    directory: PathBuf,
}

impl FileSessionStore {
    /// Store sessions in `directory`, created with mode 0700 on first login.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
        }
    }

    /// The file holding a previously validated token's record.
    pub fn path(&self, token: &str) -> PathBuf {
        self.directory.join(format!("{token}.json"))
    }
}

/// Create the private directory and a new 0600 session file.
fn create_session_file(directory: &Path, path: &Path, contents: &[u8]) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Remove a file, treating absence as success.
fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

impl SessionStore for FileSessionStore {
    /// Write the record to a new private file.
    fn create<'a>(
        &'a self,
        token: &'a str,
        record: &'a SessionRecord,
    ) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async move {
            let contents = serde_json::to_vec(record)?;
            let directory = self.directory.clone();
            let path = self.path(token);
            tokio::task::spawn_blocking(move || create_session_file(&directory, &path, &contents))
                .await?
                .map_err(|source| AuthError::Session {
                    operation: "create",
                    source,
                })
        })
    }

    /// Read and parse the record file.
    fn load<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<Option<SessionRecord>, AuthError>> {
        Box::pin(async move {
            let path = self.path(token);
            let read = tokio::task::spawn_blocking(move || fs::read(path)).await?;
            let bytes = match read {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(source) => {
                    return Err(AuthError::Session {
                        operation: "read",
                        source,
                    });
                }
            };
            Ok(serde_json::from_slice(&bytes).ok())
        })
    }

    /// Delete the record file if present.
    fn remove<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Result<(), AuthError>> {
        Box::pin(async move {
            let path = self.path(token);
            tokio::task::spawn_blocking(move || remove_if_present(&path)).await?.map_err(|source| {
                AuthError::Session {
                    operation: "remove",
                    source,
                }
            })
        })
    }
}

/// Return the current Unix time in seconds.
fn now() -> Result<u64, AuthError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

/// Validates credentials and manages persistent bearer sessions.
pub struct Authenticator {
    /// The configured account, if login is enabled.
    credentials: Option<Credentials>,
    /// Session persistence.
    sessions: Arc<dyn SessionStore>,
    /// Session token generation.
    tokens: Arc<dyn TokenSource>,
}

impl Authenticator {
    /// Combine configured credentials with session storage and token generation.
    pub fn new(
        credentials: Option<Credentials>,
        sessions: Arc<dyn SessionStore>,
        tokens: Arc<dyn TokenSource>,
    ) -> Self {
        Self {
            credentials,
            sessions,
            tokens,
        }
    }

    /// The configured username, or empty when login is disabled.
    pub fn username(&self) -> &str {
        self.credentials.as_ref().map_or("", |credentials| credentials.username.as_str())
    }

    /// Check login credentials; disabled login never matches.
    pub fn credentials_match(&self, username: &str, password: &str) -> bool {
        self.credentials.as_ref().is_some_and(|credentials| credentials.matches(username, password))
    }

    /// Create a persistent session for valid credentials, returning its token.
    pub async fn login(&self, username: &str, password: &str) -> Result<Option<String>, AuthError> {
        let Some(credentials) = &self.credentials else {
            return Ok(None);
        };
        if !credentials.matches(username, password) {
            return Ok(None);
        }
        let token = self.tokens.token().map_err(AuthError::Token)?;
        let record = SessionRecord {
            bearer: true,
            username: credentials.username.clone(),
            expires_at: now()? + SESSION_LIFETIME,
            credentials: credentials.digest.clone(),
        };
        self.sessions.create(&token, &record).await?;
        Ok(Some(token))
    }

    /// Accept HTTP Basic credentials or an explicitly supplied persistent bearer token.
    ///
    /// Cookies are never consulted, so other local origins cannot ride a session.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<bool, AuthError> {
        if let Some(basic) = basic_credentials(headers) {
            return Ok(basic
                .is_some_and(|(username, password)| self.credentials_match(&username, &password)));
        }
        let Some(token) = bearer_token(headers) else {
            return Ok(false);
        };
        let Some(record) = self.sessions.load(token).await? else {
            return Ok(false);
        };
        if record.expires_at <= now()? {
            self.sessions.remove(token).await?;
            return Ok(false);
        }
        let Some(credentials) = &self.credentials else {
            return Ok(false);
        };
        Ok(record.bearer
            && record.username == credentials.username
            && record.credentials == credentials.digest)
    }

    /// Revoke the presented bearer session, if any.
    pub async fn logout(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        if let Some(token) = bearer_token(headers) {
            self.sessions.remove(token).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A deterministic token source for tests.
    struct SequentialTokens(Mutex<u8>);

    impl TokenSource for SequentialTokens {
        /// Return 64 copies of an incrementing hexadecimal digit.
        fn token(&self) -> io::Result<String> {
            let mut next = self.0.lock().unwrap();
            *next += 1;
            Ok(format!("{:x}", *next % 16).repeat(64))
        }
    }

    /// Build headers with one Authorization value.
    fn authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    /// Build an authenticator over a temporary file store.
    fn authenticator(directory: &Path, password: &str) -> Authenticator {
        Authenticator::new(
            Credentials::new("admin", password),
            Arc::new(FileSessionStore::new(directory.join("sessions"))),
            Arc::new(SequentialTokens(Mutex::new(0))),
        )
    }

    /// Length-delimited digests distinguish shifted username/password boundaries.
    #[test]
    fn digests_are_length_delimited_and_disabled_logins_never_match() {
        assert_ne!(credential_digest("ab", "c"), credential_digest("a", "bc"));
        assert!(Credentials::new("admin", "").is_none());
        assert!(Credentials::new("", "secret").is_none());
        let credentials = Credentials::new("admin", "secret:password").unwrap();
        assert!(credentials.matches("admin", "secret:password"));
        assert!(!credentials.matches("admin", "secret"));
    }

    /// Basic credentials split on the first colon; malformed values never authenticate.
    #[tokio::test]
    async fn basic_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let auth = authenticator(directory.path(), "secret:password");
        let valid = format!("Basic {}", STANDARD.encode("admin:secret:password"));
        assert!(auth.authenticate(&authorization(&valid)).await.unwrap());
        assert!(!auth.authenticate(&authorization("Basic !!!")).await.unwrap());
        let wrong = format!("Basic {}", STANDARD.encode("admin:wrong"));
        assert!(!auth.authenticate(&authorization(&wrong)).await.unwrap());
    }

    /// Tokens are canonical lowercase hex; path-like values are rejected.
    #[test]
    fn bearer_tokens_are_canonical() {
        let token = "a".repeat(64);
        assert_eq!(bearer_token(&authorization(&format!("Bearer {token}"))), Some(token.as_str()));
        assert!(bearer_token(&authorization("Bearer ../../etc/passwd")).is_none());
        assert!(bearer_token(&authorization(&format!("Bearer {}", "A".repeat(64)))).is_none());
        assert!(bearer_token(&HeaderMap::new()).is_none());
    }

    /// Sessions persist privately, survive restart, expire, and are revoked by logout.
    #[tokio::test]
    async fn session_lifecycle_with_injected_tokens() {
        let directory = tempfile::tempdir().unwrap();
        let auth = authenticator(directory.path(), "secret");
        assert_eq!(auth.login("admin", "wrong").await.unwrap(), None);
        let token = auth.login("admin", "secret").await.unwrap().unwrap();
        assert_eq!(token, "1".repeat(64));
        let store = FileSessionStore::new(directory.path().join("sessions"));
        let path = store.path(&token);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let bearer = authorization(&format!("Bearer {token}"));
        let restarted = authenticator(directory.path(), "secret");
        assert!(restarted.authenticate(&bearer).await.unwrap());
        let changed = authenticator(directory.path(), "changed");
        assert!(!changed.authenticate(&bearer).await.unwrap());
        let mut record: SessionRecord = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        record.expires_at = now().unwrap() - 1;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(!auth.authenticate(&bearer).await.unwrap());
        assert!(!path.exists());
        let token = auth.login("admin", "secret").await.unwrap().unwrap();
        let bearer = authorization(&format!("Bearer {token}"));
        auth.logout(&bearer).await.unwrap();
        assert!(!store.path(&token).exists());
        assert!(!auth.authenticate(&bearer).await.unwrap());
    }
}
