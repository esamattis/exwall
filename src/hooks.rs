//! systemd's privileged start/stop hooks, with exact resolver and forwarding-state restoration.
use crate::error::{Context, Result, ensure};
use crate::{
    config::Config,
    firewall::{Firewall, user_exists},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    process::Command,
};

const SYSCTLS: [&str; 3] =
    ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding", "net.ipv4.conf.all.send_redirects"];

/// The exact original values of forwarding and redirect sysctls.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Forwarding {
    values: [u8; 3],
}

/// Original resolver contents or symlink target and filesystem metadata.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolverState {
    uid: u32,
    gid: u32,
    mode: u32,
    content: Option<Vec<u8>>,
    target: Option<PathBuf>,
}

/// Host paths and listener settings used by privileged service hooks.
pub struct Hooks {
    pub state_dir: PathBuf,
    pub resolv_conf: PathBuf,
    pub resolved_stub: PathBuf,
    pub proxy_user: String,
    pub proxy_port: u16,
    pub dns_port: u16,
    pub dry_run: bool,
}
impl Default for Hooks {
    /// Return the installed service paths and mitmwall-compatible ports.
    fn default() -> Self {
        Self {
            state_dir: "/run/ramawall".into(),
            resolv_conf: "/etc/resolv.conf".into(),
            resolved_stub: "/run/systemd/resolve/stub-resolv.conf".into(),
            proxy_user: "ramawall".into(),
            proxy_port: 58080,
            dns_port: 58053,
            dry_run: false,
        }
    }
}

/// Read or write a boolean-valued sysctl using the system utility.
fn sysctl(name: &str, value: Option<u8>) -> Result<u8> {
    let mut command = Command::new("sysctl");
    if let Some(value) = value {
        command.args(["-w", &format!("{name}={value}")]);
    } else {
        command.args(["-n", name]);
    }
    let output = command.output()?;
    ensure!(output.status.success(), "sysctl {name}: {}", String::from_utf8_lossy(&output.stderr));
    if let Some(value) = value {
        return Ok(value);
    }
    let value: u8 = String::from_utf8(output.stdout)?.trim().parse()?;
    ensure!(value <= 1, "invalid sysctl {name}");
    Ok(value)
}

impl Hooks {
    /// Create clients for both IPv4 and IPv6 policy.
    fn firewalls(&self) -> [Firewall; 2] {
        [
            Firewall {
                command: "iptables",
                dry_run: self.dry_run,
            },
            Firewall {
                command: "ip6tables",
                dry_run: self.dry_run,
            },
        ]
    }

    /// Create or validate the private hook-state directory.
    fn private_directory(&self) -> Result<()> {
        if !self.state_dir.exists() {
            fs::DirBuilder::new().recursive(true).create(&self.state_dir)?;
        }
        let metadata = fs::symlink_metadata(&self.state_dir)?;
        // SAFETY: geteuid has no pointer arguments or preconditions.
        ensure!(
            metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
            "runtime directory must be owned by the hook user and cannot be a symlink"
        );
        fs::set_permissions(&self.state_dir, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    /// Persist a root-private snapshot atomically without replacing existing state.
    fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.state_dir)?;
        file.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;
        serde_json::to_writer(&mut file, value)?;
        file.write_all(b"\n")?;
        file.as_file().sync_all()?;
        file.persist_noclobber(self.state_dir.join(name))?;
        Ok(())
    }

    /// Read a snapshot only after validating its ownership, permissions, and type.
    fn read<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        let path = self.state_dir.join(name);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        // SAFETY: geteuid has no pointer arguments or preconditions.
        ensure!(
            metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o777 == 0o600,
            "invalid permissions/owner/type on {}",
            path.display()
        );
        Ok(Some(
            serde_json::from_slice(&fs::read(&path)?)
                .with_context(|| format!("corrupt state {}", path.display()))?,
        ))
    }

    /// Preserve original sysctls, guard new forwarding, and enable interception.
    fn forwarding_start(&self) -> Result<()> {
        let state = match self.read::<Forwarding>("forwarding.json")? {
            Some(state) => state,
            None => {
                let state = Forwarding {
                    values: [
                        sysctl(SYSCTLS[0], None)?,
                        sysctl(SYSCTLS[1], None)?,
                        sysctl(SYSCTLS[2], None)?,
                    ],
                };
                self.save("forwarding.json", &state)?;
                state
            }
        };
        ensure!(state.values.iter().all(|v| *v <= 1), "invalid saved sysctls");
        for (i, firewall) in self.firewalls().iter().enumerate() {
            if state.values[i] == 0 {
                firewall.forward_guard(true)?;
            }
        }
        for (name, value) in SYSCTLS.into_iter().zip([1, 1, 0]) {
            sysctl(name, Some(value))?;
        }
        Ok(())
    }

    /// Restore saved sysctls before removing their forwarding guards.
    fn forwarding_stop(&self) -> Result<()> {
        if let Some(state) = self.read::<Forwarding>("forwarding.json")? {
            ensure!(state.values.iter().all(|v| *v <= 1), "invalid saved sysctls");
            let mut errors = Vec::new();
            for (name, value) in SYSCTLS.into_iter().zip(state.values) {
                if let Err(error) = sysctl(name, Some(value)) {
                    errors.push(error.to_string());
                }
            }
            ensure!(errors.is_empty(), "failed to restore sysctls: {}", errors.join("; "));
            for (i, firewall) in self.firewalls().iter().enumerate() {
                if state.values[i] == 0 {
                    firewall.forward_guard(false)?;
                }
            }
            fs::remove_file(self.state_dir.join("forwarding.json"))?;
        }
        Ok(())
    }

    /// Save external resolver configuration and switch to the resolved stub.
    fn resolver_start(&self, enabled: bool) -> Result<()> {
        if !enabled || !external_nameservers(&self.resolv_conf)? {
            return Ok(());
        }
        ensure!(
            Command::new("systemctl")
                .args(["is-active", "--quiet", "systemd-resolved.service"])
                .status()?
                .success(),
            "systemd-resolved must be active before replacing resolv.conf"
        );
        ensure!(
            self.resolved_stub.is_file() && !external_nameservers(&self.resolved_stub)?,
            "resolved stub must exist and use only loopback nameservers"
        );
        if self.read::<ResolverState>("resolver.json")?.is_none() {
            let metadata = fs::symlink_metadata(&self.resolv_conf)?;
            ensure!(
                metadata.is_file() || metadata.file_type().is_symlink(),
                "resolv.conf must be a file or symlink"
            );
            let state = ResolverState {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
                content: if metadata.is_file() {
                    Some(fs::read(&self.resolv_conf)?)
                } else {
                    None
                },
                target: if metadata.file_type().is_symlink() {
                    Some(fs::read_link(&self.resolv_conf)?)
                } else {
                    None
                },
            };
            self.save("resolver.json", &state)?;
        }
        replace_symlink(&self.resolv_conf, &self.resolved_stub, None)?;
        Ok(())
    }

    /// Restore the saved resolver unless an administrator changed it meanwhile.
    fn resolver_stop(&self) -> Result<()> {
        let Some(state) = self.read::<ResolverState>("resolver.json")? else {
            return Ok(());
        };
        ensure!(state.content.is_some() != state.target.is_some(), "invalid saved resolver state");
        match fs::symlink_metadata(&self.resolv_conf) {
            Ok(_)
                if fs::read_link(&self.resolv_conf).ok().as_ref() != Some(&self.resolved_stub) =>
            {
                tracing::info!(
                    "resolv.conf changed by administrator; preserving current configuration"
                );
                fs::remove_file(self.state_dir.join("resolver.json"))?;
                return Ok(());
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => (),
        }
        if let Some(target) = state.target {
            replace_symlink(&self.resolv_conf, &target, Some((state.uid, state.gid)))?;
        } else if let Some(content) = state.content {
            let mut file = tempfile::NamedTempFile::new_in(
                self.resolv_conf.parent().context("resolver has no parent")?,
            )?;
            file.write_all(&content)?;
            chown_fd(file.as_file(), state.uid, state.gid)?;
            file.as_file().set_permissions(fs::Permissions::from_mode(state.mode))?;
            file.as_file().sync_all()?;
            file.persist(&self.resolv_conf)?;
        }
        fs::remove_file(self.state_dir.join("resolver.json"))?;
        Ok(())
    }

    /// Serialize hook operations and restore host state on startup failure.
    pub fn run(&self, start: bool, config: Option<&Config>) -> Result<()> {
        if self.dry_run {
            if start {
                let config = config.context("start requires config")?;
                for firewall in self.firewalls() {
                    firewall.setup_guard()?;
                    firewall.install(
                        config,
                        &self.proxy_user,
                        &[],
                        self.proxy_port,
                        self.dns_port,
                    )?;
                    firewall.clear_setup_guard()?;
                }
                println!(
                    "# Live start also saves/restores forwarding sysctls and resolv.conf; dry-run changes neither."
                );
            } else {
                for firewall in self.firewalls() {
                    firewall.clear()?;
                }
            }
            return Ok(());
        }
        // SAFETY: geteuid has no pointer arguments or preconditions.
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "systemd hooks require root (use --dry-run to inspect)"
        );
        self.private_directory()?;
        let lock = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.state_dir.join("hook.lock"))?;
        // SAFETY: fd belongs to the live lock file; LOCK_EX is a valid operation.
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
            "failed to lock hooks"
        );
        if start {
            let config = config.context("start requires config")?;
            for user in config
                .bypass_users
                .iter()
                .map(String::as_str)
                .chain([self.proxy_user.as_str(), "systemd-resolve"])
            {
                ensure!(user_exists(user)?, "unknown bypass/proxy/resolver user: {user}");
            }
            let ntp = ["systemd-timesync", "_chrony", "ntp"]
                .into_iter()
                .filter_map(|user| match user_exists(user) {
                    Ok(true) => Some(Ok(user.to_owned())),
                    Ok(false) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<Vec<_>>>()?;
            let work = (|| -> Result<()> {
                for firewall in self.firewalls() {
                    firewall.setup_guard()?;
                }
                self.resolver_start(config.manage_resolv_conf)?;
                self.forwarding_start()?;
                for firewall in self.firewalls() {
                    firewall.install(
                        config,
                        &self.proxy_user,
                        &ntp,
                        self.proxy_port,
                        self.dns_port,
                    )?;
                }
                for firewall in self.firewalls() {
                    firewall.clear_setup_guard()?;
                }
                Ok(())
            })();
            if let Err(error) = work {
                // Keep egress closed until ExecStopPost cleans up a failed start.
                let forwarding = self.forwarding_stop();
                let resolver = self.resolver_stop();
                let message = format!(
                    "startup failed (state restoration: forwarding={forwarding:?}, \
                     resolver={resolver:?}); stop hook must clean firewall rules"
                );
                return Err(error).context(message);
            }
        } else {
            // Restore forwarding before removing guards; preserve guards on restoration failure.
            let forwarding = self.forwarding_stop();
            let mut failures = Vec::new();
            if let Err(error) = forwarding {
                failures.push(error.to_string());
            } else {
                for firewall in self.firewalls() {
                    if let Err(error) = firewall.clear() {
                        failures.push(error.to_string());
                    }
                }
            }
            if let Err(error) = self.resolver_stop() {
                failures.push(error.to_string());
            }
            ensure!(failures.is_empty(), "stop hook failed: {}", failures.join("; "));
        }
        Ok(())
    }
}

/// Restore ownership on a temporary resolver file before installing it.
fn chown_fd(file: &fs::File, uid: u32, gid: u32) -> Result<()> {
    // SAFETY: fd is borrowed from a live file; uid/gid are recorded metadata.
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
        "failed to restore file ownership"
    );
    Ok(())
}

/// Atomically replace a resolver path with a symlink and optional ownership.
fn replace_symlink(path: &Path, target: &Path, owner: Option<(u32, u32)>) -> Result<()> {
    let dir = tempfile::tempdir_in(path.parent().context("symlink has no parent")?)?;
    let temp = dir.path().join("link");
    symlink(target, &temp)?;
    if let Some((uid, gid)) = owner {
        use std::os::unix::ffi::OsStrExt;
        let path_c = std::ffi::CString::new(temp.as_os_str().as_bytes())?;
        // SAFETY: CString lives across the syscall and contains a valid NUL-terminated pathname.
        ensure!(
            unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } == 0,
            "failed to restore symlink ownership"
        );
    }
    fs::rename(temp, path)?;
    Ok(())
}

/// Detect resolver configurations that contain non-loopback nameservers.
fn external_nameservers(path: &Path) -> Result<bool> {
    let text = fs::read_to_string(path)?;
    for line in text.lines() {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(address) = fields.next()
            && address
                .split('%')
                .next()
                .unwrap_or("")
                .parse::<std::net::IpAddr>()
                .map(|ip| !ip.is_loopback())
                .unwrap_or(true)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Verify resolver restoration and preservation of administrator replacements.
    #[test]
    fn resolver_restoration_preserves_files_symlinks_and_admin_edits() {
        let dir = tempfile::tempdir().unwrap();
        let hook = Hooks {
            state_dir: dir.path().join("state"),
            resolv_conf: dir.path().join("resolv.conf"),
            resolved_stub: dir.path().join("stub"),
            ..Hooks::default()
        };
        hook.private_directory().unwrap();
        fs::write(&hook.resolv_conf, b"nameserver 192.0.2.1\n").unwrap();
        let metadata = fs::metadata(&hook.resolv_conf).unwrap();
        hook.save(
            "resolver.json",
            &ResolverState {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o640,
                content: Some(b"nameserver 192.0.2.1\n".to_vec()),
                target: None,
            },
        )
        .unwrap();
        replace_symlink(&hook.resolv_conf, &hook.resolved_stub, None).unwrap();
        hook.resolver_stop().unwrap();
        assert_eq!(fs::read(&hook.resolv_conf).unwrap(), b"nameserver 192.0.2.1\n");
        assert_eq!(fs::metadata(&hook.resolv_conf).unwrap().mode() & 0o777, 0o640);
        hook.save(
            "resolver.json",
            &ResolverState {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o777,
                content: None,
                target: Some("original-target".into()),
            },
        )
        .unwrap();
        replace_symlink(&hook.resolv_conf, &hook.resolved_stub, None).unwrap();
        hook.resolver_stop().unwrap();
        assert_eq!(fs::read_link(&hook.resolv_conf).unwrap(), PathBuf::from("original-target"));
        hook.save(
            "resolver.json",
            &ResolverState {
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: 0o640,
                content: Some(b"old".to_vec()),
                target: None,
            },
        )
        .unwrap();
        replace_symlink(&hook.resolv_conf, Path::new("admin-target"), None).unwrap();
        hook.resolver_stop().unwrap();
        assert_eq!(fs::read_link(&hook.resolv_conf).unwrap(), PathBuf::from("admin-target"));
    }

    /// Preserve corrupt snapshots so cleanup can be repaired and retried.
    #[test]
    fn corrupt_state_fails_without_removing_it() {
        let dir = tempfile::tempdir().unwrap();
        let hook = Hooks {
            state_dir: dir.path().to_owned(),
            ..Hooks::default()
        };
        fs::write(dir.path().join("forwarding.json"), b"bad").unwrap();
        fs::set_permissions(dir.path().join("forwarding.json"), fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(hook.forwarding_stop().is_err());
        assert!(dir.path().join("forwarding.json").exists());
    }
}
