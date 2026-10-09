//! Root-private snapshots of host state that hooks must restore exactly.

use super::{
    error::{HookError, io_error},
    iptables::Family,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// The saved forwarding sysctls.
pub const FORWARDING_FILE: &str = "forwarding.json";
/// The saved resolver configuration.
pub const RESOLVER_FILE: &str = "resolver.json";
/// The lifecycle lock file.
pub const LOCK_FILE: &str = "hook.lock";

/// The IPv4 forwarding sysctl.
pub const IPV4_FORWARD: &str = "net.ipv4.ip_forward";
/// The IPv6 forwarding sysctl.
pub const IPV6_FORWARD: &str = "net.ipv6.conf.all.forwarding";
/// The IPv4 ICMP redirect sysctl.
pub const SEND_REDIRECTS: &str = "net.ipv4.conf.all.send_redirects";

/// A private directory owned by the hook's effective user.
pub struct StateDir {
    /// The directory path.
    path: PathBuf,
    /// The required owner of the directory and its files.
    owner: u32,
}

impl StateDir {
    /// Use `path` without creating it; files must be owned by `owner`.
    pub fn new(path: PathBuf, owner: u32) -> Self {
        Self {
            path,
            owner,
        }
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create or validate the directory as a non-symlink owned by the hook user, mode 0700.
    pub fn prepare(&self) -> Result<(), HookError> {
        if !self.path.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .create(&self.path)
                .map_err(io_error("create state directory", &self.path))?;
        }
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(io_error("inspect state directory", &self.path))?;
        if !metadata.is_dir() || metadata.uid() != self.owner {
            return Err(HookError::UnsafeStateDirectory);
        }
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700))
            .map_err(io_error("restrict state directory", &self.path))
    }

    /// Persist a 0600 snapshot atomically without replacing existing state.
    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<(), HookError> {
        let path = self.path.join(name);
        let write = || -> io::Result<()> {
            let mut file = tempfile::NamedTempFile::new_in(&self.path)?;
            file.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
            let encoded = serde_json::to_vec(value).map_err(io::Error::other)?;
            file.write_all(&encoded)?;
            file.write_all(b"\n")?;
            file.as_file().sync_all()?;
            file.persist_noclobber(&path).map_err(|error| error.error)?;
            Ok(())
        };
        write().map_err(io_error("save state", &path))
    }

    /// Read a snapshot only after validating its ownership, permissions, and type.
    ///
    /// A corrupt snapshot is an error and is left in place for diagnosis.
    pub fn read<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, HookError> {
        let path = self.path.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error("inspect state", &path)(error)),
        };
        if !metadata.is_file() || metadata.uid() != self.owner || metadata.mode() & 0o777 != 0o600 {
            return Err(HookError::UnsafeStateFile {
                path,
            });
        }
        let bytes = fs::read(&path).map_err(io_error("read state", &path))?;
        serde_json::from_slice(&bytes).map(Some).map_err(|source| HookError::CorruptState {
            path,
            source,
        })
    }

    /// Delete a snapshot after it has been restored.
    pub fn remove(&self, name: &str) -> Result<(), HookError> {
        let path = self.path.join(name);
        fs::remove_file(&path).map_err(io_error("remove state", &path))
    }
}

/// The on-disk forwarding format, kept compatible with earlier releases.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardingFile {
    /// IPv4 forwarding, IPv6 forwarding, and IPv4 send_redirects, in that order.
    values: [u8; 3],
}

/// The original values of the forwarding and redirect sysctls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "ForwardingFile", into = "ForwardingFile")]
pub struct Forwarding {
    /// `net.ipv4.ip_forward`.
    pub ipv4_forward: u8,
    /// `net.ipv6.conf.all.forwarding`.
    pub ipv6_forward: u8,
    /// `net.ipv4.conf.all.send_redirects`.
    pub send_redirects: u8,
}

impl From<ForwardingFile> for Forwarding {
    /// Decode the positional file format.
    fn from(file: ForwardingFile) -> Self {
        let [ipv4_forward, ipv6_forward, send_redirects] = file.values;
        Self {
            ipv4_forward,
            ipv6_forward,
            send_redirects,
        }
    }
}

impl From<Forwarding> for ForwardingFile {
    /// Encode the positional file format.
    fn from(state: Forwarding) -> Self {
        Self {
            values: [state.ipv4_forward, state.ipv6_forward, state.send_redirects],
        }
    }
}

impl Forwarding {
    /// The values exwall sets while running: forwarding on, redirects off.
    pub const ACTIVE: Forwarding = Forwarding {
        ipv4_forward: 1,
        ipv6_forward: 1,
        send_redirects: 0,
    };

    /// Each sysctl name paired with its value.
    pub fn entries(&self) -> [(&'static str, u8); 3] {
        [
            (IPV4_FORWARD, self.ipv4_forward),
            (IPV6_FORWARD, self.ipv6_forward),
            (SEND_REDIRECTS, self.send_redirects),
        ]
    }

    /// Reject values other than 0 and 1.
    pub fn validate(&self) -> Result<(), HookError> {
        if self.entries().iter().all(|(_, value)| *value <= 1) {
            Ok(())
        } else {
            Err(HookError::InvalidSavedSysctls)
        }
    }

    /// Report whether forwarding was originally disabled for `family`, needing a guard.
    pub fn needs_forward_guard(&self, family: Family) -> bool {
        let value = match family {
            Family::V4 => self.ipv4_forward,
            Family::V6 => self.ipv6_forward,
        };
        value == 0
    }
}

/// Original resolver contents or symlink target and filesystem metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverSnapshot {
    /// The owner's user ID.
    pub uid: u32,
    /// The owner's group ID.
    pub gid: u32,
    /// The permission bits.
    pub mode: u32,
    /// The file contents, when resolv.conf was a regular file.
    pub content: Option<Vec<u8>>,
    /// The link target, when resolv.conf was a symlink.
    pub target: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The effective UID of the test process.
    fn euid() -> u32 {
        // SAFETY: geteuid has no pointer arguments or preconditions.
        unsafe { libc::geteuid() }
    }

    /// Snapshots round-trip in the legacy positional format and are never clobbered.
    #[test]
    fn saves_private_snapshots_without_clobbering() {
        let directory = tempfile::tempdir().unwrap();
        let state = StateDir::new(directory.path().join("state"), euid());
        state.prepare().unwrap();
        let saved = Forwarding {
            ipv4_forward: 0,
            ipv6_forward: 1,
            send_redirects: 1,
        };
        state.save(FORWARDING_FILE, &saved).unwrap();
        let path = state.path().join(FORWARDING_FILE);
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"values\":[0,1,1]}\n");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(state.path()).unwrap().mode() & 0o777, 0o700);
        assert!(state.save(FORWARDING_FILE, &Forwarding::ACTIVE).is_err());
        assert_eq!(state.read::<Forwarding>(FORWARDING_FILE).unwrap(), Some(saved));
        assert!(saved.needs_forward_guard(Family::V4));
        assert!(!saved.needs_forward_guard(Family::V6));
        state.remove(FORWARDING_FILE).unwrap();
        assert_eq!(state.read::<Forwarding>(FORWARDING_FILE).unwrap(), None);
    }

    /// Corrupt, exposed, or invalid snapshots are errors and are left in place.
    #[test]
    fn rejects_corrupt_or_exposed_state() {
        let directory = tempfile::tempdir().unwrap();
        let state = StateDir::new(directory.path().to_owned(), euid());
        let path = directory.path().join(FORWARDING_FILE);
        fs::write(&path, b"bad").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = state.read::<Forwarding>(FORWARDING_FILE).unwrap_err();
        assert!(error.to_string().starts_with("corrupt state "));
        assert!(path.exists());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            state.read::<Forwarding>(FORWARDING_FILE),
            Err(HookError::UnsafeStateFile { .. })
        ));
        let invalid = Forwarding {
            ipv4_forward: 2,
            ..Forwarding::ACTIVE
        };
        assert!(matches!(invalid.validate(), Err(HookError::InvalidSavedSysctls)));
    }
}
