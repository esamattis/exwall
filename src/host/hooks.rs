//! systemd's privileged guard/start/stop hooks, with exact resolver and forwarding restoration.

use super::{
    error::HookError,
    files::{ResolverPaths, prepare_web_rules_file, replace_resolver, restore_resolver},
    firewall::Firewall,
    iptables::{BUILTIN_OUTPUT, Family, GUARD_CHAIN, OUTPUT_CHAIN, Table},
    plan::{
        EgressPolicy, GuardUsers, NTP_USERS, RESOLVER_USER, clear_guard_steps,
        clear_setup_guard_steps, clear_steps, forward_guard_steps, guard_jump, guard_steps,
        install_steps, setup_guard_steps,
    },
    state::{FORWARDING_FILE, Forwarding, LOCK_FILE, StateDir},
    system::System,
};
use crate::{cli, config::StaticConfig, error::ErrorChain, ui::WEB_RULES_FILE};
use std::{fs, os::unix::io::AsRawFd, path::PathBuf};

/// Host paths and listener settings used by privileged service hooks.
#[derive(Clone, Debug)]
pub struct HookSettings {
    /// Directory containing administrator rules and the private UI rules file.
    pub rules_dir: PathBuf,
    /// Private directory for state snapshots and the lifecycle lock.
    pub state_dir: PathBuf,
    /// Resolver configuration paths.
    pub resolver: ResolverPaths,
    /// The proxy's account.
    pub proxy_user: String,
    /// The proxy port targeted by redirects.
    pub proxy_port: u16,
    /// The DNS port targeted by redirects.
    pub dns_port: u16,
}

impl Default for HookSettings {
    /// The installed service paths and mitmwall-compatible ports.
    fn default() -> Self {
        Self {
            rules_dir: cli::DEFAULT_RULES_DIR.into(),
            state_dir: cli::DEFAULT_STATE_DIR.into(),
            resolver: ResolverPaths::default(),
            proxy_user: cli::DEFAULT_PROXY_USER.into(),
            proxy_port: cli::DEFAULT_PROXY_PORT,
            dns_port: cli::DEFAULT_DNS_PORT,
        }
    }
}

/// The held lifecycle lock; dropping it releases the lock.
pub struct LifecycleLock {
    /// The locked file.
    _file: fs::File,
}

/// Whether hooks change the host or only preview firewall changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Apply every change.
    Live,
    /// Print firewall changes; leave files, sysctls, and the resolver untouched.
    DryRun,
}

/// Privileged lifecycle operations over a [`System`].
pub struct Hooks<'a> {
    /// Paths and ports.
    settings: HookSettings,
    /// Where commands run.
    system: &'a dyn System,
    /// Live or preview.
    mode: Mode,
    /// Receives dry-run explanations.
    notes: &'a dyn Fn(&str),
}

impl<'a> Hooks<'a> {
    /// Run hooks with `settings` on `system`; `notes` receives dry-run explanations.
    pub fn new(
        settings: HookSettings,
        system: &'a dyn System,
        mode: Mode,
        notes: &'a dyn Fn(&str),
    ) -> Self {
        Self {
            settings,
            system,
            mode,
            notes,
        }
    }

    /// The private state directory.
    fn state(&self) -> StateDir {
        StateDir::new(self.settings.state_dir.clone(), self.system.effective_uid())
    }

    /// Clients for both address families.
    fn firewalls(&self) -> [Firewall<'a>; 2] {
        Family::ALL.map(|family| Firewall::new(self.system, family))
    }

    /// Acquire the private lifecycle lock before changing enforcement or saved state.
    pub fn lock(&self) -> Result<LifecycleLock, HookError> {
        if self.system.effective_uid() != 0 {
            return Err(HookError::NotRoot);
        }
        let state = self.state();
        state.prepare()?;
        let path = state.path().join(LOCK_FILE);
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(HookError::Lock)?;
        // SAFETY: the fd belongs to the live lock file; LOCK_EX is a valid operation.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(HookError::Lock(std::io::Error::last_os_error()));
        }
        Ok(LifecycleLock {
            _file: file,
        })
    }

    /// Look up which guard-exempt accounts exist.
    fn guard_users(&self) -> Result<GuardUsers, HookError> {
        let mut users = GuardUsers::default();
        for user in [self.settings.proxy_user.as_str(), RESOLVER_USER] {
            if self.system.user_exists(user)? {
                users.exempt.push(user.to_owned());
            }
        }
        users.ntp = self.ntp_users()?;
        Ok(users)
    }

    /// Return the NTP accounts that exist on this host.
    fn ntp_users(&self) -> Result<Vec<String>, HookError> {
        let mut present = Vec::new();
        for user in NTP_USERS {
            if self.system.user_exists(user)? {
                present.push(user.to_owned());
            }
        }
        Ok(present)
    }

    /// Establish fail-closed enforcement before configuration failures can abort startup.
    ///
    /// Existing installed policy or an attached guard is preserved unchanged.
    pub fn guard(&self) -> Result<(), HookError> {
        let mut users = None;
        for firewall in self.firewalls() {
            if firewall.chain_exists(Table::Filter, OUTPUT_CHAIN)? {
                // A start after a failed cleanup retains the complete previous policy.
                continue;
            }
            if firewall.chain_exists(Table::Filter, GUARD_CHAIN)?
                && firewall.rule_exists(Table::Filter, BUILTIN_OUTPUT, &guard_jump())?
            {
                continue;
            }
            if users.is_none() {
                users = Some(self.guard_users()?);
            }
            let users = users.as_ref().expect("guard users were just resolved");
            firewall.apply_all(&guard_steps(users, firewall.family()))?;
        }
        Ok(())
    }

    /// Install egress policy, saving the resolver and forwarding state first.
    ///
    /// Failures retain enforcement and the original snapshots until `stop`
    /// removes policy and restores host state.
    pub fn start(&self, config: &StaticConfig) -> Result<(), HookError> {
        if self.mode == Mode::Live {
            let required = config
                .bypass_users
                .iter()
                .map(String::as_str)
                .chain([self.settings.proxy_user.as_str(), RESOLVER_USER]);
            for user in required {
                if !self.system.user_exists(user)? {
                    return Err(HookError::UnknownUser {
                        user: user.to_owned(),
                    });
                }
            }
        }
        let ntp_users = self.ntp_users()?;
        let policy = EgressPolicy {
            bypass_users: &config.bypass_users,
            bypasses: &config.iptables.bypass,
            proxy_user: &self.settings.proxy_user,
            ntp_users: &ntp_users,
            proxy_port: self.settings.proxy_port,
            dns_port: self.settings.dns_port,
        };
        self.install(config, &policy).map_err(|error| HookError::StartFailed(Box::new(error)))?;
        if self.mode == Mode::DryRun {
            (self.notes)(
                "Live start also saves/restores forwarding sysctls and resolv.conf; dry-run changes neither.",
            );
        }
        Ok(())
    }

    /// Block new connections, prepare host state, install policy, then lift the guards.
    fn install(&self, config: &StaticConfig, policy: &EgressPolicy<'_>) -> Result<(), HookError> {
        let firewalls = self.firewalls();
        for firewall in &firewalls {
            firewall.apply_all(&setup_guard_steps())?;
        }
        self.prepare_web_rules()?;
        if self.mode == Mode::Live {
            if config.manage_resolv_conf {
                replace_resolver(self.system, &self.state(), &self.settings.resolver)?;
            }
            self.enable_forwarding()?;
        }
        for firewall in &firewalls {
            firewall.apply_all(&install_steps(policy, firewall.family()))?;
        }
        for firewall in &firewalls {
            firewall.apply_all(&clear_guard_steps())?;
            firewall.apply_all(&clear_setup_guard_steps())?;
        }
        Ok(())
    }

    /// Create the UI rules file owned by the proxy account with mode 0600.
    fn prepare_web_rules(&self) -> Result<(), HookError> {
        let path = self.settings.rules_dir.join(WEB_RULES_FILE);
        if self.mode == Mode::DryRun {
            (self.notes)(&format!(
                "Create/retain {} owned by {} with mode 0600",
                path.display(),
                self.settings.proxy_user
            ));
            return Ok(());
        }
        let (uid, gid) = self.system.user_ids(&self.settings.proxy_user)?;
        fs::create_dir_all(&self.settings.rules_dir)
            .map_err(super::error::io_error("create rules directory", &self.settings.rules_dir))?;
        prepare_web_rules_file(&path, uid, gid)
    }

    /// Save original sysctls once, guard newly enabled forwarding, and enable interception.
    fn enable_forwarding(&self) -> Result<(), HookError> {
        let state = self.state();
        let saved = match state.read::<Forwarding>(FORWARDING_FILE)? {
            Some(saved) => saved,
            None => {
                let saved = Forwarding {
                    ipv4_forward: self.system.read_sysctl(super::state::IPV4_FORWARD)?,
                    ipv6_forward: self.system.read_sysctl(super::state::IPV6_FORWARD)?,
                    send_redirects: self.system.read_sysctl(super::state::SEND_REDIRECTS)?,
                };
                state.save(FORWARDING_FILE, &saved)?;
                saved
            }
        };
        saved.validate()?;
        for firewall in self.firewalls() {
            if saved.needs_forward_guard(firewall.family()) {
                firewall.apply_all(&forward_guard_steps(true))?;
            }
        }
        for (name, value) in Forwarding::ACTIVE.entries() {
            self.system.write_sysctl(name, value)?;
        }
        Ok(())
    }

    /// Restore saved sysctls before removing their forwarding guards.
    fn restore_forwarding(&self) -> Result<(), HookError> {
        let state = self.state();
        let Some(saved) = state.read::<Forwarding>(FORWARDING_FILE)? else {
            return Ok(());
        };
        saved.validate()?;
        let errors: Vec<String> = saved
            .entries()
            .into_iter()
            .filter_map(|(name, value)| self.system.write_sysctl(name, value).err())
            .map(|error| ErrorChain(&error).to_string())
            .collect();
        if !errors.is_empty() {
            return Err(HookError::RestoreSysctls(errors.join("; ")));
        }
        for firewall in self.firewalls() {
            if saved.needs_forward_guard(firewall.family()) {
                firewall.apply_all(&forward_guard_steps(false))?;
            }
        }
        state.remove(FORWARDING_FILE)
    }

    /// Restore saved host state and remove managed chains without reading configuration.
    ///
    /// Forwarding is restored before guards are removed; firewall cleanup is
    /// skipped if that fails so enforcement is retained.
    pub fn stop(&self) -> Result<(), HookError> {
        if self.mode == Mode::DryRun {
            for firewall in self.firewalls() {
                firewall.apply_all(&clear_steps())?;
            }
            (self.notes)("Live stop also restores saved forwarding sysctls and resolv.conf.");
            return Ok(());
        }
        let mut failures = Vec::new();
        match self.restore_forwarding() {
            Err(error) => failures.push(ErrorChain(&error).to_string()),
            Ok(()) => {
                for firewall in self.firewalls() {
                    if let Err(error) = firewall.apply_all(&clear_steps()) {
                        failures.push(ErrorChain(&error).to_string());
                    }
                }
            }
        }
        if let Err(error) = restore_resolver(&self.state(), &self.settings.resolver) {
            failures.push(ErrorChain(&error).to_string());
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(HookError::StopFailed(failures.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        host::{
            command::{CommandOutput, CommandSpec},
            iptables::{FORWARD_COMMENT, NAT_CHAIN, SETUP_COMMENT},
            simulate::{SimulatedTables, is_mutation},
            system::DryRunSystem,
        },
    };
    use std::{
        collections::BTreeMap,
        io,
        os::unix::fs::{MetadataExt, PermissionsExt},
        sync::{Arc, Mutex},
    };

    /// A recording fake host with simulated iptables, accounts, sysctls, and resolver.
    struct FakeSystem {
        /// Simulated tables per family.
        tables: Mutex<BTreeMap<Family, SimulatedTables>>,
        /// Sysctl values by name.
        sysctls: Mutex<BTreeMap<String, u8>>,
        /// Existing accounts and their IDs.
        users: BTreeMap<String, (u32, u32)>,
        /// Every command run, rendered.
        commands: Mutex<Vec<CommandSpec>>,
    }

    impl FakeSystem {
        /// A host with forwarding disabled for IPv4 only and the usual accounts.
        fn new() -> Self {
            // SAFETY: these identity syscalls take no pointers and have no preconditions.
            let ids = unsafe { (libc::geteuid(), libc::getegid()) };
            let users = ["root", "exwall", RESOLVER_USER, "_chrony"]
                .into_iter()
                .map(|user| (user.to_owned(), ids))
                .collect();
            let sysctls = [
                (super::super::state::IPV4_FORWARD, 0),
                (super::super::state::IPV6_FORWARD, 1),
                (super::super::state::SEND_REDIRECTS, 1),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect();
            Self {
                tables: Mutex::new(BTreeMap::new()),
                sysctls: Mutex::new(sysctls),
                users,
                commands: Mutex::new(Vec::new()),
            }
        }

        /// A snapshot of every family's tables.
        fn tables(&self) -> BTreeMap<Family, SimulatedTables> {
            self.tables.lock().unwrap().clone()
        }

        /// The current sysctl values in IPv4, IPv6, redirects order.
        fn sysctl_values(&self) -> Vec<u8> {
            let sysctls = self.sysctls.lock().unwrap();
            [
                super::super::state::IPV4_FORWARD,
                super::super::state::IPV6_FORWARD,
                super::super::state::SEND_REDIRECTS,
            ]
            .iter()
            .map(|name| sysctls[*name])
            .collect()
        }

        /// The number of state-changing iptables commands run so far.
        fn mutations(&self) -> usize {
            self.commands
                .lock()
                .unwrap()
                .iter()
                .filter(|command| command.program.ends_with("tables") && is_mutation(&command.args))
                .count()
        }
    }

    impl System for FakeSystem {
        /// Interpret iptables, id, and sysctl commands against the fake host.
        fn run(&self, command: &CommandSpec) -> io::Result<CommandOutput> {
            self.commands.lock().unwrap().push(command.clone());
            let args = &command.args;
            match command.program.as_str() {
                "iptables" | "ip6tables" => {
                    let family = if command.program == "iptables" {
                        Family::V4
                    } else {
                        Family::V6
                    };
                    let mut tables = self.tables.lock().unwrap();
                    Ok(tables.entry(family).or_default().execute(family, args))
                }
                "id" => Ok(match self.users.get(&args[2]) {
                    Some((uid, gid)) => CommandOutput::ok(
                        if args[0] == "-u" {
                            uid
                        } else {
                            gid
                        }
                        .to_string(),
                    ),
                    None => CommandOutput::failed(1, "no such user"),
                }),
                "sysctl" if args[0] == "-n" => {
                    Ok(CommandOutput::ok(self.sysctls.lock().unwrap()[&args[1]].to_string()))
                }
                "sysctl" => {
                    let (name, value) = args[1].split_once('=').unwrap();
                    self.sysctls.lock().unwrap().insert(name.to_owned(), value.parse().unwrap());
                    Ok(CommandOutput::ok(""))
                }
                other => Err(io::Error::other(format!("unexpected program {other}"))),
            }
        }

        /// Use the test process's UID so private-directory checks pass.
        fn effective_uid(&self) -> u32 {
            // SAFETY: geteuid has no pointer arguments or preconditions.
            unsafe { libc::geteuid() }
        }
    }

    /// Settings pointing every path into `root`.
    fn settings(root: &std::path::Path) -> HookSettings {
        HookSettings {
            rules_dir: root.join("rules"),
            state_dir: root.join("state"),
            resolver: ResolverPaths {
                resolv_conf: root.join("resolv.conf"),
                resolved_stub: root.join("stub"),
            },
            ..HookSettings::default()
        }
    }

    /// A configuration without resolver management.
    fn config(extra: &str) -> Config {
        Config::parse(&format!("manage_resolv_conf = false\nbypass_users = ['root']\n{extra}"))
            .unwrap()
    }

    /// Ignore dry-run notes.
    fn silent(_: &str) {}

    /// Rendered rules of one chain.
    fn chain(
        tables: &BTreeMap<Family, SimulatedTables>,
        family: Family,
        table: Table,
        name: &str,
    ) -> Vec<String> {
        tables[&family]
            .rules(table, name)
            .unwrap_or_default()
            .iter()
            .map(|rule| rule.join(" "))
            .collect()
    }

    /// Start installs ordered policy, saves state once, and removes temporary guards.
    #[test]
    fn start_installs_policy_and_saves_original_state() {
        let root = tempfile::tempdir().unwrap();
        let system = FakeSystem::new();
        let hooks = Hooks::new(settings(root.path()), &system, Mode::Live, &silent);
        let config = config("[[iptables.bypass]]\nnetwork = '192.0.2.19/24'\nport = 443\n");
        hooks.state().prepare().unwrap();
        hooks.guard().unwrap();
        hooks.start(&config.startup).unwrap();

        let tables = system.tables();
        for family in Family::ALL {
            let output = chain(&tables, family, Table::Filter, BUILTIN_OUTPUT);
            assert_eq!(output.first().map(String::as_str), Some("-j EXWALL_OUTPUT"));
            assert!(!output.iter().any(|rule| rule.contains(SETUP_COMMENT)));
            assert!(!tables[&family].has_chain(Table::Filter, GUARD_CHAIN));
            let nat = chain(&tables, family, Table::Nat, NAT_CHAIN);
            let redirect = nat.iter().position(|rule| rule.contains("REDIRECT")).unwrap();
            assert!(
                nat.iter().position(|rule| rule.contains("--uid-owner root")).unwrap() < redirect
            );
            assert_eq!(chain(&tables, family, Table::Nat, BUILTIN_OUTPUT), ["-j EXWALL_NAT"]);
            let ntp = chain(&tables, family, Table::Filter, OUTPUT_CHAIN);
            assert!(ntp.iter().any(|rule| rule.contains("--uid-owner _chrony")));
        }
        let v4_nat = chain(&tables, Family::V4, Table::Nat, NAT_CHAIN);
        let bypass = v4_nat.iter().position(|rule| rule.contains("192.0.2.0/24")).unwrap();
        assert!(bypass < v4_nat.iter().position(|rule| rule.contains("REDIRECT")).unwrap());
        assert!(
            !chain(&tables, Family::V6, Table::Nat, NAT_CHAIN)
                .iter()
                .any(|rule| rule.contains("192.0.2.0"))
        );
        assert_eq!(
            chain(&tables, Family::V4, Table::Filter, "FORWARD"),
            [format!("-m comment --comment {FORWARD_COMMENT} -j DROP")]
        );
        assert!(chain(&tables, Family::V6, Table::Filter, "FORWARD").is_empty());
        assert_eq!(system.sysctl_values(), [1, 1, 0]);
        let state = root.path().join("state").join(FORWARDING_FILE);
        assert_eq!(fs::read_to_string(&state).unwrap(), "{\"values\":[0,1,1]}\n");
        let web = root.path().join("rules").join(WEB_RULES_FILE);
        assert_eq!(fs::metadata(&web).unwrap().mode() & 0o777, 0o600);
    }

    /// Repeated starts are idempotent, guard preserves installed policy, and stop restores exactly.
    #[test]
    fn restart_guard_and_stop_are_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let system = FakeSystem::new();
        let hooks = Hooks::new(settings(root.path()), &system, Mode::Live, &silent);
        let config = config("");
        hooks.state().prepare().unwrap();
        let baseline = system.tables();
        hooks.guard().unwrap();
        hooks.start(&config.startup).unwrap();
        let installed = system.tables();
        let saved = fs::read(root.path().join("state").join(FORWARDING_FILE)).unwrap();
        hooks.start(&config.startup).unwrap();
        assert_eq!(system.tables(), installed);
        assert_eq!(fs::read(root.path().join("state").join(FORWARDING_FILE)).unwrap(), saved);
        let before = system.mutations();
        hooks.guard().unwrap();
        assert_eq!(system.mutations(), before);

        hooks.stop().unwrap();
        hooks.stop().unwrap();
        let mut restored = system.tables();
        let mut expected = baseline;
        for family in Family::ALL {
            restored.entry(family).or_default();
            expected.entry(family).or_default();
        }
        assert_eq!(restored, expected);
        assert_eq!(system.sysctl_values(), [0, 1, 1]);
        assert!(!root.path().join("state").join(FORWARDING_FILE).exists());
    }

    /// The bootstrap guard denies by default and is removed by stop.
    #[test]
    fn guard_installs_a_bootstrap_policy_that_stop_removes() {
        let root = tempfile::tempdir().unwrap();
        let system = FakeSystem::new();
        let hooks = Hooks::new(settings(root.path()), &system, Mode::Live, &silent);
        hooks.state().prepare().unwrap();
        hooks.guard().unwrap();
        let tables = system.tables();
        for family in Family::ALL {
            assert_eq!(chain(&tables, family, Table::Filter, BUILTIN_OUTPUT), ["-j EXWALL_GUARD"]);
            let guard = chain(&tables, family, Table::Filter, GUARD_CHAIN);
            assert_eq!(guard.last().map(String::as_str), Some("-j DROP"));
            assert!(guard.iter().any(|rule| rule == "-m owner --uid-owner exwall -j ACCEPT"));
        }
        let before = system.mutations();
        hooks.guard().unwrap();
        assert_eq!(system.mutations(), before);
        hooks.stop().unwrap();
        for family in Family::ALL {
            assert!(chain(&system.tables(), family, Table::Filter, BUILTIN_OUTPUT).is_empty());
        }
    }

    /// Corrupt forwarding state fails startup without touching sysctls or the file.
    #[test]
    fn corrupt_state_fails_without_removing_it() {
        let root = tempfile::tempdir().unwrap();
        let system = FakeSystem::new();
        let hooks = Hooks::new(settings(root.path()), &system, Mode::Live, &silent);
        hooks.state().prepare().unwrap();
        let path = root.path().join("state").join(FORWARDING_FILE);
        fs::write(&path, b"not json\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = hooks.start(&config("").startup).unwrap_err();
        assert!(ErrorChain(&error).to_string().contains("corrupt state"));
        assert_eq!(system.sysctl_values(), [0, 1, 1]);
        assert_eq!(fs::read(&path).unwrap(), b"not json\n");
        assert!(hooks.stop().is_err());
        assert!(path.exists());
    }

    /// Unknown required accounts abort startup before any firewall change.
    #[test]
    fn unknown_users_abort_before_changes() {
        let root = tempfile::tempdir().unwrap();
        let system = FakeSystem::new();
        let hooks = Hooks::new(settings(root.path()), &system, Mode::Live, &silent);
        let config =
            Config::parse("manage_resolv_conf = false\nbypass_users = ['missing']").unwrap();
        let error = hooks.start(&config.startup).unwrap_err();
        assert_eq!(error.to_string(), "unknown bypass/proxy/resolver user: missing");
        assert_eq!(system.mutations(), 0);
    }

    /// The lock requires root.
    #[test]
    fn lock_requires_root() {
        // SAFETY: geteuid has no pointer arguments or preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let system = FakeSystem::new();
        let hooks = Hooks::new(settings(root.path()), &system, Mode::Live, &silent);
        assert!(matches!(hooks.lock(), Err(HookError::NotRoot)));
    }

    /// A writer whose contents can be inspected after use.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        /// Append to the shared buffer.
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        /// Nothing is buffered.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Dry runs print a consistent plan and never spawn processes or touch state.
    #[test]
    fn dry_run_prints_a_complete_plan() {
        let root = tempfile::tempdir().unwrap();
        let captured = Captured::default();
        let system = DryRunSystem::new(BTreeMap::new(), Box::new(captured.clone()));
        let note = |text: &str| system.note(text);
        let hooks = Hooks::new(settings(root.path()), &system, Mode::DryRun, &note);
        hooks.guard().unwrap();
        hooks.start(&config("").startup).unwrap();
        let printed = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = printed.lines().collect();
        assert_eq!(lines[0], "iptables -w 10 -t filter -N EXWALL_GUARD");
        assert!(lines.contains(&"iptables -w 10 -t filter -N EXWALL_OUTPUT"));
        assert!(lines.contains(&"ip6tables -w 10 -t nat -I OUTPUT -j EXWALL_NAT"));
        assert!(lines.contains(&"ip6tables -w 10 -t filter -X EXWALL_GUARD"));
        assert!(lines.iter().any(|line| line.starts_with("# Create/retain")));
        assert!(lines.last().unwrap().starts_with("# Live start also"));
        assert!(!root.path().join("state").exists());
        assert!(!root.path().join("rules").exists());
    }
}
