//! The small top-level error type and helpers for rendering error chains.
//!
//! Each module owns a `thiserror` enum describing its own failures. Display
//! implementations describe only their own operation; underlying causes are
//! exposed through `source()` and rendered by [`ErrorChain`].

use std::{error::Error as StdError, fmt};
use thiserror::Error;

/// Failures returned by a command-line operation.
#[derive(Debug, Error)]
pub enum Error {
    /// The configuration file could not be read or validated.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The rules directory could not be loaded.
    #[error(transparent)]
    Rules(#[from] crate::policy::LoadError),
    /// CA material could not be created or validated.
    #[error(transparent)]
    Ca(#[from] crate::ca::CaError),
    /// Web UI credentials could not be generated or saved.
    #[error(transparent)]
    Credentials(#[from] crate::credentials::CredentialsError),
    /// A privileged lifecycle hook failed.
    #[error(transparent)]
    Hook(#[from] crate::host::HookError),
    /// The proxy service failed to start or stopped abnormally.
    #[error(transparent)]
    Serve(#[from] crate::app::ServeError),
    /// The asynchronous runtime could not be created.
    #[error("create async runtime")]
    Runtime(#[source] std::io::Error),
}

/// Display an error followed by every underlying source, separated by colons.
pub struct ErrorChain<'a>(pub &'a (dyn StdError + 'static));

impl fmt::Display for ErrorChain<'_> {
    /// Render `outer: inner: root` without repeating transparent wrappers.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)?;
        let mut current = self.0.source();
        while let Some(source) = current {
            write!(formatter, ": {source}")?;
            current = source.source();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An error with a message and an optional cause, used to build chains in tests.
    #[derive(Debug, Error)]
    #[error("{message}")]
    struct Layer {
        /// The description of this layer.
        message: &'static str,
        /// The next error in the chain.
        #[source]
        source: Option<Box<Layer>>,
    }

    /// Render every layer of a nested error exactly once.
    #[test]
    fn renders_each_source_once() {
        let error = Layer {
            message: "outer",
            source: Some(Box::new(Layer {
                message: "middle",
                source: Some(Box::new(Layer {
                    message: "root",
                    source: None,
                })),
            })),
        };
        assert_eq!(ErrorChain(&error).to_string(), "outer: middle: root");
    }
}
