//! Resolver replacement and restoration, and the service-owned UI rules file.

use super::{
    error::{HookError, io_error},
    state::{RESOLVER_FILE, ResolverSnapshot, StateDir},
    system::System,
};
use std::{
    ffi::CString,
    fs,
    io::Write,
    net::IpAddr,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
};

/// The resolver file and the systemd-resolved stub that replaces it.
#[derive(Clone, Debug)]
pub struct ResolverPaths {
    /// The system resolver configuration.
    pub resolv_conf: PathBuf,
    /// systemd-resolved's loopback stub configuration.
    pub resolved_stub: PathBuf,
}

impl Default for ResolverPaths {
    /// The standard system locations.
    fn default() -> Self {
        Self {
            resolv_conf: "/etc/resolv.conf".into(),
            resolved_stub: "/run/systemd/resolve/stub-resolv.conf".into(),
        }
    }
}

/// Detect resolver configurations that contain non-loopback nameservers.
pub fn has_external_nameservers(text: &str) -> bool {
    text.lines().any(|line| {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        if fields.next() != Some("nameserver") {
            return false;
        }
        fields.next().is_some_and(|address| {
            let address = address.split('%').next().unwrap_or("");
            address.parse::<IpAddr>().map(|ip| !ip.is_loopback()).unwrap_or(true)
        })
    })
}

/// Read a resolver file and check for external nameservers.
fn file_has_external_nameservers(path: &Path) -> Result<bool, HookError> {
    let text = fs::read_to_string(path).map_err(io_error("read resolver configuration", path))?;
    Ok(has_external_nameservers(&text))
}

/// Save external resolver configuration and switch to the resolved stub.
pub fn replace_resolver(
    system: &dyn System,
    state: &StateDir,
    paths: &ResolverPaths,
) -> Result<(), HookError> {
    if !file_has_external_nameservers(&paths.resolv_conf)? {
        return Ok(());
    }
    if !system.resolver_active()? {
        return Err(HookError::ResolverInactive);
    }
    if !paths.resolved_stub.is_file() || file_has_external_nameservers(&paths.resolved_stub)? {
        return Err(HookError::InvalidStub);
    }
    if state.read::<ResolverSnapshot>(RESOLVER_FILE)?.is_none() {
        state.save(RESOLVER_FILE, &snapshot_resolver(&paths.resolv_conf)?)?;
    }
    replace_symlink(&paths.resolv_conf, &paths.resolved_stub, None)
}

/// Capture resolv.conf's contents or link target and its metadata.
fn snapshot_resolver(path: &Path) -> Result<ResolverSnapshot, HookError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error("inspect resolver", path))?;
    let is_link = metadata.file_type().is_symlink();
    if !metadata.is_file() && !is_link {
        return Err(HookError::InvalidResolvConf);
    }
    let content = if metadata.is_file() {
        Some(fs::read(path).map_err(io_error("read resolver", path))?)
    } else {
        None
    };
    let target = if is_link {
        Some(fs::read_link(path).map_err(io_error("read resolver link", path))?)
    } else {
        None
    };
    Ok(ResolverSnapshot {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        content,
        target,
    })
}

/// Restore the saved resolver unless an administrator changed it meanwhile.
pub fn restore_resolver(state: &StateDir, paths: &ResolverPaths) -> Result<(), HookError> {
    let Some(snapshot) = state.read::<ResolverSnapshot>(RESOLVER_FILE)? else {
        return Ok(());
    };
    if snapshot.content.is_some() == snapshot.target.is_some() {
        return Err(HookError::InvalidResolverState);
    }
    match fs::symlink_metadata(&paths.resolv_conf) {
        Ok(_) if fs::read_link(&paths.resolv_conf).ok().as_ref() != Some(&paths.resolved_stub) => {
            tracing::info!(
                "resolv.conf changed by administrator; preserving current configuration"
            );
            return state.remove(RESOLVER_FILE);
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(io_error("inspect resolver", &paths.resolv_conf)(error));
        }
        _ => {}
    }
    if let Some(target) = &snapshot.target {
        replace_symlink(&paths.resolv_conf, target, Some((snapshot.uid, snapshot.gid)))?;
    } else if let Some(content) = &snapshot.content {
        restore_file(&paths.resolv_conf, content, &snapshot)?;
    }
    state.remove(RESOLVER_FILE)
}

/// Atomically install saved resolver contents with their original ownership and mode.
fn restore_file(path: &Path, content: &[u8], snapshot: &ResolverSnapshot) -> Result<(), HookError> {
    let parent = path.parent().ok_or(HookError::InvalidResolvConf)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .map_err(io_error("create resolver file", parent))?;
    file.write_all(content).map_err(io_error("write resolver file", path))?;
    chown_fd(file.as_file(), snapshot.uid, snapshot.gid)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(snapshot.mode))
        .map_err(io_error("restore resolver mode", path))?;
    file.as_file().sync_all().map_err(io_error("sync resolver file", path))?;
    file.persist(path).map_err(|error| io_error("install resolver file", path)(error.error))?;
    Ok(())
}

/// Restore ownership on an open file.
fn chown_fd(file: &fs::File, uid: u32, gid: u32) -> Result<(), HookError> {
    // SAFETY: the fd is borrowed from a live file; uid/gid are recorded metadata.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(HookError::Chown(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Atomically replace a path with a symlink, optionally restoring the link's ownership.
pub fn replace_symlink(
    path: &Path,
    target: &Path,
    owner: Option<(u32, u32)>,
) -> Result<(), HookError> {
    let parent = path.parent().ok_or(HookError::InvalidResolvConf)?;
    let directory =
        tempfile::tempdir_in(parent).map_err(io_error("create temporary directory", parent))?;
    let temporary = directory.path().join("link");
    symlink(target, &temporary).map_err(io_error("create symlink", &temporary))?;
    if let Some((uid, gid)) = owner {
        let name = CString::new(temporary.as_os_str().as_bytes())
            .map_err(|error| HookError::Chown(std::io::Error::other(error)))?;
        // SAFETY: the CString lives across the call and is a valid NUL-terminated path.
        if unsafe { libc::lchown(name.as_ptr(), uid, gid) } != 0 {
            return Err(HookError::Chown(std::io::Error::last_os_error()));
        }
    }
    fs::rename(&temporary, path).map_err(io_error("install symlink", path))
}

/// Create the UI rules file if needed and make it private to the service account.
///
/// Existing rules are retained, and a file descriptor opened with `O_NOFOLLOW`
/// prevents ownership changes through symlinks.
pub fn prepare_web_rules_file(path: &Path, uid: u32, gid: u32) -> Result<(), HookError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_error("open UI rules", path))?;
    let metadata = file.metadata().map_err(io_error("inspect UI rules", path))?;
    if !metadata.is_file() {
        return Err(HookError::WebRulesNotFile);
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(io_error("restrict UI rules", path))?;
    chown_fd(&file, uid, gid)?;
    file.sync_all().map_err(io_error("sync UI rules", path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The effective user and group of the test process.
    fn ids() -> (u32, u32) {
        // SAFETY: these identity syscalls take no pointers and have no preconditions.
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    /// Verify private UI file creation, repeated-start preservation, and symlink rejection.
    #[test]
    fn private_web_rules_file() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("05-web.toml");
        let (uid, gid) = ids();
        prepare_web_rules_file(&path, uid, gid).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        fs::write(&path, "[[allow]]\ndomain = 'retained.test'\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        prepare_web_rules_file(&path, uid, gid).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!((metadata.uid(), metadata.gid()), (uid, gid));
        assert!(fs::read_to_string(&path).unwrap().contains("retained.test"));
        let target = temporary.path().join("untouched");
        fs::write(&target, "target").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert!(prepare_web_rules_file(&path, uid, gid).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "target");
    }

    /// Verify resolver restoration and preservation of administrator replacements.
    #[test]
    fn resolver_restoration_preserves_files_symlinks_and_admin_edits() {
        let dir = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();
        let state = StateDir::new(dir.path().join("state"), uid);
        state.prepare().unwrap();
        let paths = ResolverPaths {
            resolv_conf: dir.path().join("resolv.conf"),
            resolved_stub: dir.path().join("stub"),
        };
        let snapshot = |mode, content: Option<&[u8]>, target: Option<&str>| ResolverSnapshot {
            uid,
            gid,
            mode,
            content: content.map(<[u8]>::to_vec),
            target: target.map(PathBuf::from),
        };
        state.save(RESOLVER_FILE, &snapshot(0o640, Some(b"nameserver 192.0.2.1\n"), None)).unwrap();
        replace_symlink(&paths.resolv_conf, &paths.resolved_stub, None).unwrap();
        restore_resolver(&state, &paths).unwrap();
        assert_eq!(fs::read(&paths.resolv_conf).unwrap(), b"nameserver 192.0.2.1\n");
        assert_eq!(fs::metadata(&paths.resolv_conf).unwrap().mode() & 0o777, 0o640);

        state.save(RESOLVER_FILE, &snapshot(0o777, None, Some("original-target"))).unwrap();
        replace_symlink(&paths.resolv_conf, &paths.resolved_stub, None).unwrap();
        restore_resolver(&state, &paths).unwrap();
        assert_eq!(fs::read_link(&paths.resolv_conf).unwrap(), PathBuf::from("original-target"));

        state.save(RESOLVER_FILE, &snapshot(0o640, Some(b"old"), None)).unwrap();
        replace_symlink(&paths.resolv_conf, Path::new("admin-target"), None).unwrap();
        restore_resolver(&state, &paths).unwrap();
        assert_eq!(fs::read_link(&paths.resolv_conf).unwrap(), PathBuf::from("admin-target"));
        assert_eq!(state.read::<ResolverSnapshot>(RESOLVER_FILE).unwrap(), None);
    }

    /// Only non-loopback nameservers count as external.
    #[test]
    fn detects_external_nameservers() {
        assert!(has_external_nameservers("nameserver 192.0.2.1\n"));
        assert!(has_external_nameservers("# comment\nnameserver fe80::1%eth0\n"));
        assert!(!has_external_nameservers("nameserver 127.0.0.53\noptions edns0\n"));
        assert!(!has_external_nameservers("# nameserver 192.0.2.1\nnameserver ::1\n"));
        assert!(has_external_nameservers("nameserver not-an-address\n"));
    }
}
