//! Failures of privileged lifecycle hooks.

use std::{io, path::PathBuf};
use thiserror::Error;

/// A failed hook operation; enforcement is retained unless stop succeeds.
#[derive(Debug, Error)]
pub enum HookError {
    /// A program could not be started.
    #[error("run {program}")]
    Spawn {
        /// The program name.
        program: String,
        /// The spawn error.
        #[source]
        source: io::Error,
    },
    /// A mutating command exited unsuccessfully.
    #[error("{command}: {stderr}")]
    CommandFailed {
        /// The rendered command.
        command: String,
        /// Its standard error.
        stderr: String,
    },
    /// A probe failed for a reason other than expected absence.
    #[error("{program} probe failed: {stderr}")]
    ProbeFailed {
        /// The iptables program.
        program: &'static str,
        /// Its standard error.
        stderr: String,
    },
    /// `id` failed for a reason other than an unknown user.
    #[error("failed to look up user {user}")]
    UserLookup {
        /// The account name.
        user: String,
    },
    /// The proxy account's IDs could not be resolved.
    #[error("cannot resolve service account {user}")]
    ServiceAccount {
        /// The account name.
        user: String,
    },
    /// A required account does not exist.
    #[error("unknown bypass/proxy/resolver user: {user}")]
    UnknownUser {
        /// The account name.
        user: String,
    },
    /// `sysctl` failed.
    #[error("sysctl {name}: {stderr}")]
    Sysctl {
        /// The sysctl name.
        name: String,
        /// Its standard error.
        stderr: String,
    },
    /// A sysctl did not report 0 or 1.
    #[error("invalid sysctl {name}")]
    SysctlValue {
        /// The sysctl name.
        name: String,
    },
    /// Saved sysctl values are not 0 or 1.
    #[error("invalid saved sysctls")]
    InvalidSavedSysctls,
    /// Restoring saved sysctls failed.
    #[error("failed to restore sysctls: {0}")]
    RestoreSysctls(String),
    /// Hooks were invoked without root privileges.
    #[error("systemd hooks require root (use --dry-run to inspect)")]
    NotRoot,
    /// The state directory is not a private directory owned by the hook user.
    #[error("runtime directory must be owned by the hook user and cannot be a symlink")]
    UnsafeStateDirectory,
    /// A state file has unexpected ownership, permissions, or type.
    #[error("invalid permissions/owner/type on {}", path.display())]
    UnsafeStateFile {
        /// The state file.
        path: PathBuf,
    },
    /// A state file cannot be decoded; it is kept for diagnosis.
    #[error("corrupt state {}", path.display())]
    CorruptState {
        /// The state file.
        path: PathBuf,
        /// The decoding error.
        #[source]
        source: serde_json::Error,
    },
    /// A state snapshot could not be encoded.
    #[error("encode state")]
    EncodeState(#[source] serde_json::Error),
    /// A filesystem operation failed.
    #[error("{operation} {}", path.display())]
    Io {
        /// What was being done.
        operation: &'static str,
        /// The affected path.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// The lifecycle lock could not be acquired.
    #[error("failed to lock hooks")]
    Lock(#[source] io::Error),
    /// systemd-resolved is not running.
    #[error("systemd-resolved must be active before replacing resolv.conf")]
    ResolverInactive,
    /// The resolved stub file is missing or not loopback-only.
    #[error("resolved stub must exist and use only loopback nameservers")]
    InvalidStub,
    /// resolv.conf is neither a file nor a symlink.
    #[error("resolv.conf must be a file or symlink")]
    InvalidResolvConf,
    /// The saved resolver snapshot is inconsistent.
    #[error("invalid saved resolver state")]
    InvalidResolverState,
    /// Ownership could not be restored.
    #[error("failed to restore file ownership")]
    Chown(#[source] io::Error),
    /// The UI rules path is not a regular file.
    #[error("UI rules must be a regular file")]
    WebRulesNotFile,
    /// Installation failed after the guard was installed.
    #[error("startup failed; enforcement retained; repair and retry or explicitly run hook stop")]
    StartFailed(#[source] Box<HookError>),
    /// One or more stop steps failed.
    #[error("stop hook failed: {0}")]
    StopFailed(String),
}

/// Build a filesystem error for `path`.
pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
) -> impl FnOnce(io::Error) -> HookError {
    let path = path.into();
    move |source| HookError::Io {
        operation,
        path,
        source,
    }
}
