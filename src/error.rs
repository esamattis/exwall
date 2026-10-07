//! Typed application errors shared by configuration, policy, and host integration.
use thiserror::Error;

/// Application failures with preserved source errors where the backend provides them.
#[derive(Debug, Error)]
pub enum Error {
    /// A configuration value, policy entry, or host-state invariant is invalid.
    #[error("{0}")]
    Invalid(String),
    /// A filesystem, socket, or subprocess operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// TOML could not be deserialized into the supported configuration format.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    /// A configured regular expression could not be compiled or evaluated.
    #[error(transparent)]
    Regex(#[from] fancy_regex::Error),
    /// Certificate generation or CA parsing failed.
    #[error(transparent)]
    Certificate(#[from] rcgen::Error),
    /// A rustls certificate or TLS configuration failed validation.
    #[error(transparent)]
    Tls(#[from] rama::tls::rustls::dep::rustls::Error),
    /// A PEM object could not be decoded.
    #[error(transparent)]
    Pem(#[from] rama::crypto::pki_types::pem::Error),
    /// A DNS message could not be parsed or serialized.
    #[error(transparent)]
    Dns(#[from] hickory_proto::ProtoError),
    /// A saved JSON snapshot is malformed.
    #[error(transparent)]
    State(#[from] serde_json::Error),
    /// A temporary file could not be atomically installed.
    #[error(transparent)]
    Persist(#[from] tempfile::PersistError),
    /// An integer returned by a system utility is malformed.
    #[error(transparent)]
    Integer(#[from] std::num::ParseIntError),
    /// A protocol length cannot fit in its wire representation.
    #[error(transparent)]
    Length(#[from] std::num::TryFromIntError),
    /// A command-line IP address is malformed.
    #[error(transparent)]
    Address(#[from] std::net::AddrParseError),
    /// A system utility returned non-UTF-8 text.
    #[error(transparent)]
    Encoding(#[from] std::string::FromUtf8Error),
    /// An OS pathname contains a NUL byte.
    #[error(transparent)]
    Path(#[from] std::ffi::NulError),
    /// An asynchronous operation exceeded its time limit.
    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
    /// A background task panicked or was unexpectedly cancelled.
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    /// A Rama service reported a failure at its dynamic service boundary.
    #[error(transparent)]
    Rama(#[from] rama::error::BoxError),
    /// A failure annotated with the operation or configuration entry that caused it.
    #[error("{message}: {source}")]
    Context {
        message: String,
        #[source]
        source: rama::error::BoxError,
    },
}

impl Error {
    /// Construct an invariant failure from a caller-provided explanation.
    pub fn message(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// Adapt APIs that return an error message without a source error type.
    pub fn msg(message: impl Into<String>) -> Self {
        Self::message(message)
    }
}

/// Result type used by application operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Add operational context while preserving backend error sources.
pub trait Context<T> {
    /// Attach a description of the failing operation.
    fn context(self, message: impl Into<String>) -> Result<T>;
    /// Compute the operation description only if this result is a failure.
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: Into<rama::error::BoxError>> Context<T> for std::result::Result<T, E> {
    /// Wrap the source error with a description of its operation.
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Context {
            message: message.into(),
            source: source.into(),
        })
    }

    /// Lazily wrap the source error with a description of its operation.
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|source| Error::Context {
            message: message(),
            source: source.into(),
        })
    }
}

impl<T> Context<T> for Option<T> {
    /// Convert an absent required value into an invariant failure.
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| Error::message(message))
    }

    /// Describe a missing required value only when it is absent.
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.ok_or_else(|| Error::message(message()))
    }
}

/// Return a typed invariant failure with a formatted explanation.
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::error::Error::message(format!($($arg)*))) };
}
pub(crate) use bail;

/// Require an invariant before proceeding with a configuration or host operation.
macro_rules! ensure {
    ($condition:expr, $($arg:tt)*) => {
        if !$condition { $crate::error::bail!($($arg)*); }
    };
}
pub(crate) use ensure;
