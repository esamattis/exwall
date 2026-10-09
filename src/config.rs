//! mitmwall-compatible `config.toml` parsing.
//!
//! Settings are split by lifetime: [`StaticConfig`] is applied once at startup
//! (firewall, resolver, logging, access log, UI), while [`RuntimeSettings`] is
//! the subset that SIGHUP republishes to running request handlers.

use serde::Deserialize;
use std::{
    fs, io,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
};
use thiserror::Error;

/// A complete validated configuration file.
#[derive(Clone, Debug)]
pub struct Config {
    /// Settings applied only when the service or hooks start.
    pub startup: StaticConfig,
    /// Settings republished to request handlers on SIGHUP.
    pub runtime: RuntimeSettings,
}

/// Startup-only settings; changing them requires a restart.
#[derive(Clone, Debug)]
pub struct StaticConfig {
    /// Application tracing verbosity.
    pub log_level: LogLevel,
    /// Access-log destination and retention.
    pub access_log: AccessLogConfig,
    /// Embedded web UI listeners and credentials.
    pub ui: UiConfig,
    /// Whether hooks replace upstream nameservers with the resolved stub.
    pub manage_resolv_conf: bool,
    /// Legacy mitmwall setting, validated but unused.
    pub flow_history_clear_interval: u64,
    /// Legacy mitmwall setting, validated but unused.
    pub flow_history_keep_entries: u64,
    /// Local accounts whose traffic bypasses enforcement.
    pub bypass_users: Vec<String>,
    /// Destination networks and ports bypassing the proxy.
    pub iptables: Iptables,
}

/// Settings that running request handlers observe through the policy store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeSettings {
    /// When true, DNS queries must match allow rules.
    pub block_dns: bool,
    /// Automatically reload rules when the rules directory changes.
    pub watch_rules: bool,
}

impl Default for RuntimeSettings {
    /// Enforce DNS rules and watch the rules directory by default.
    fn default() -> Self {
        Self {
            block_dns: true,
            watch_rules: true,
        }
    }
}

/// mitmwall log-level names accepted in `log_level`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    /// Verbose diagnostics, including executed hook commands.
    Debug,
    /// Normal operational messages.
    Info,
    /// Recoverable problems.
    Warning,
    /// Failures.
    Error,
    /// Alias of `Error` retained for mitmwall compatibility.
    Critical,
}

impl LogLevel {
    /// Parse a case-insensitive, whitespace-tolerant mitmwall level name.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_lowercase().as_str() {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    /// Translate the level to a tracing filter directive.
    pub fn tracing_directive(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warn",
            Self::Error | Self::Critical => "error",
        }
    }
}

/// HTTP UI bind addresses and port, applied when the service starts.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Literal IPv4/IPv6 bind addresses; an empty list disables the UI.
    pub hosts: Vec<IpAddr>,
    /// Shared TCP port for every configured interface.
    pub port: u16,
    /// Login account; an empty username or password disables authenticated API access.
    pub username: String,
    /// Login password shared by bearer login and HTTP Basic authentication.
    pub password: String,
    /// Directory containing private, persistent JSON sessions.
    pub sessions_dir: PathBuf,
}

impl Default for UiConfig {
    /// Restrict the UI to IPv4 loopback on port 58000 by default.
    fn default() -> Self {
        Self {
            hosts: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port: 58000,
            username: String::new(),
            password: String::new(),
            sessions_dir: "/var/lib/exwall/ui/sessions/".into(),
        }
    }
}

/// Access-log destination and periodic size-based retention settings.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AccessLogConfig {
    /// File receiving access-log rows.
    pub path: PathBuf,
    /// Number of written rows between file-size checks.
    pub check_interval: u64,
    /// Size above which the file is trimmed at a check.
    pub max_size_bytes: u64,
    /// Number of newest rows retained when trimming.
    pub keep_entries: usize,
}

impl Default for AccessLogConfig {
    /// Log to the service directory and check every 100 entries against a 10 MiB limit.
    fn default() -> Self {
        Self {
            path: "/var/log/exwall/access.log".into(),
            check_interval: 100,
            max_size_bytes: 10 * 1024 * 1024,
            keep_entries: 1000,
        }
    }
}

/// Operator-configured exceptions to outbound enforcement.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Iptables {
    /// TCP destinations bypassing the proxy.
    pub bypass: Vec<Bypass>,
}

/// A TCP destination network and port that bypass proxy filtering.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bypass {
    /// Destination network, normalized to its network address.
    #[serde(deserialize_with = "deserialize_network")]
    pub network: ipnet::IpNet,
    /// Destination TCP port.
    pub port: u16,
}

/// Accept a CIDR network or a single IP address, as Python's ip_network does.
fn deserialize_network<'de, D>(deserializer: D) -> Result<ipnet::IpNet, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if let Ok(network) = value.parse::<ipnet::IpNet>() {
        return Ok(network);
    }
    value.parse::<IpAddr>().map(ipnet::IpNet::from).map_err(serde::de::Error::custom)
}

/// The raw TOML document before validation and lifetime splitting.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    /// Unvalidated log-level name.
    log_level: String,
    /// Access-log settings.
    access_log: AccessLogConfig,
    /// UI settings.
    ui: UiConfig,
    /// Rule watching toggle.
    watch_rules: bool,
    /// DNS enforcement toggle.
    block_dns: bool,
    /// Resolver management toggle.
    manage_resolv_conf: bool,
    /// Legacy setting.
    flow_history_clear_interval: u64,
    /// Legacy setting.
    flow_history_keep_entries: u64,
    /// Exempt accounts.
    bypass_users: Vec<String>,
    /// Destination bypasses.
    iptables: Iptables,
}

impl Default for RawConfig {
    /// Return the built-in settings used when keys or the whole file are absent.
    fn default() -> Self {
        let runtime = RuntimeSettings::default();
        Self {
            log_level: "info".into(),
            access_log: AccessLogConfig::default(),
            ui: UiConfig::default(),
            watch_rules: runtime.watch_rules,
            block_dns: runtime.block_dns,
            manage_resolv_conf: true,
            flow_history_clear_interval: 1000,
            flow_history_keep_entries: 500,
            // The Python hook defaults to no bypass users; the shipped config includes root/_apt.
            bypass_users: Vec::new(),
            iptables: Iptables::default(),
        }
    }
}

/// A configuration document that is syntactically or semantically invalid.
#[derive(Debug, Error)]
pub enum InvalidConfig {
    /// The TOML could not be deserialized into the supported format.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    /// `log_level` is not a supported name.
    #[error("invalid log_level")]
    LogLevel,
    /// A legacy flow-history value is zero.
    #[error("flow history settings must be positive integers")]
    FlowHistory,
    /// `access_log.path` does not name a file.
    #[error("access_log.path must name a file")]
    AccessLogPath,
    /// An access-log retention value is zero.
    #[error("access log retention settings must be positive integers")]
    AccessLogRetention,
    /// A bypass user name is empty.
    #[error("bypass_users must contain nonempty names")]
    BypassUsers,
    /// `ui.sessions_dir` is empty.
    #[error("ui.sessions_dir must not be empty")]
    SessionsDir,
    /// `ui.port` is zero.
    #[error("ui.port must be 1..65535")]
    UiPort,
    /// `ui.hosts` repeats an address.
    #[error("ui.hosts must not contain duplicate addresses")]
    DuplicateUiHost,
    /// A bypass port is zero.
    #[error("bypass port must be 1..65535")]
    BypassPort,
}

/// Failures loading the configuration file from disk.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file exists but could not be read.
    #[error("read config {}", path.display())]
    Read {
        /// The configuration path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The file contents are invalid.
    #[error("config {}", path.display())]
    Invalid {
        /// The configuration path.
        path: PathBuf,
        /// The validation failure.
        #[source]
        source: InvalidConfig,
    },
}

impl Default for Config {
    /// Return the built-in settings used when config.toml is absent.
    fn default() -> Self {
        Self::validate(RawConfig::default()).expect("built-in defaults are valid")
    }
}

impl Config {
    /// Read configuration from disk, using defaults only when the file is absent.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).map_err(|source| ConfigError::Invalid {
                path: path.to_owned(),
                source,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Read {
                path: path.to_owned(),
                source,
            }),
        }
    }

    /// Deserialize and validate all runtime and firewall settings.
    pub fn parse(text: &str) -> Result<Self, InvalidConfig> {
        Self::validate(toml::from_str(text)?)
    }

    /// Check value constraints and split settings by lifetime.
    fn validate(raw: RawConfig) -> Result<Self, InvalidConfig> {
        let log_level = LogLevel::parse(&raw.log_level).ok_or(InvalidConfig::LogLevel)?;
        if raw.flow_history_clear_interval == 0 || raw.flow_history_keep_entries == 0 {
            return Err(InvalidConfig::FlowHistory);
        }
        if raw.access_log.path.file_name().is_none() {
            return Err(InvalidConfig::AccessLogPath);
        }
        if raw.access_log.check_interval == 0
            || raw.access_log.max_size_bytes == 0
            || raw.access_log.keep_entries == 0
        {
            return Err(InvalidConfig::AccessLogRetention);
        }
        if raw.bypass_users.iter().any(String::is_empty) {
            return Err(InvalidConfig::BypassUsers);
        }
        if raw.ui.sessions_dir.as_os_str().is_empty() {
            return Err(InvalidConfig::SessionsDir);
        }
        if raw.ui.port == 0 {
            return Err(InvalidConfig::UiPort);
        }
        for (index, host) in raw.ui.hosts.iter().enumerate() {
            if raw.ui.hosts[..index].contains(host) {
                return Err(InvalidConfig::DuplicateUiHost);
            }
        }
        let mut iptables = raw.iptables;
        for bypass in &mut iptables.bypass {
            if bypass.port == 0 {
                return Err(InvalidConfig::BypassPort);
            }
            bypass.network = bypass.network.trunc();
        }
        Ok(Self {
            startup: StaticConfig {
                log_level,
                access_log: raw.access_log,
                ui: raw.ui,
                manage_resolv_conf: raw.manage_resolv_conf,
                flow_history_clear_interval: raw.flow_history_clear_interval,
                flow_history_keep_entries: raw.flow_history_keep_entries,
                bypass_users: raw.bypass_users,
                iptables,
            },
            runtime: RuntimeSettings {
                block_dns: raw.block_dns,
                watch_rules: raw.watch_rules,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify shipped defaults, network normalization, and strict validation.
    #[test]
    fn configuration_compatibility() {
        let config = Config::parse(include_str!("../config-default.toml")).unwrap();
        assert_eq!(config.startup.bypass_users, ["root", "_apt"]);
        assert_eq!(config.startup.access_log, AccessLogConfig::default());
        assert_eq!(config.startup.ui, UiConfig::default());
        assert_eq!(config.startup.log_level, LogLevel::Info);
        assert!(config.runtime.watch_rules);
        assert!(config.runtime.block_dns);
        assert!(Config::parse("").unwrap().runtime.watch_rules);
        assert!(!Config::parse("watch_rules = false").unwrap().runtime.watch_rules);
        let config =
            Config::parse("[[iptables.bypass]]\nnetwork = '192.168.5.19/24'\nport = 1234").unwrap();
        assert_eq!(config.startup.iptables.bypass[0].network.to_string(), "192.168.5.0/24");
        let config = Config::parse("[[iptables.bypass]]\nnetwork = '::1'\nport = 443").unwrap();
        assert_eq!(config.startup.iptables.bypass[0].network.to_string(), "::1/128");
        for text in [
            "block_dns = 1",
            "watch_rules = 1",
            "log_level = 'verbose'",
            "[ui]\nport = 0",
            "[ui]\nport = 65536",
            "[ui]\nhosts = ['localhost']",
            "[ui]\nhosts = ['127.0.0.1', '127.0.0.1']",
            "[ui]\ntypo = true",
            "[ui]\nsessions_dir = ''",
            "flow_history_keep_entries = 0",
            "typo = true",
            "bypass_users = ['']",
            "[access_log]\npath = ''",
            "[access_log]\npath = '/'",
            "[access_log]\ncheck_interval = 0",
            "[access_log]\nmax_size_bytes = 0",
            "[access_log]\nkeep_entries = 0",
            "[access_log]\ntypo = 1",
            "[[iptables.bypass]]\nnetwork = '::1'\nport = 0",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }

    /// Accept mitmwall level aliases with surrounding whitespace and mixed case.
    #[test]
    fn log_levels_map_to_tracing_directives() {
        for (text, directive) in [
            (" DEBUG ", "debug"),
            ("info", "info"),
            ("Warning", "warn"),
            ("error", "error"),
            ("critical", "error"),
        ] {
            let config = Config::parse(&format!("log_level = '{text}'")).unwrap();
            assert_eq!(config.startup.log_level.tracing_directive(), directive);
        }
    }

    /// Accept access-log overrides while retaining defaults for omitted fields.
    #[test]
    fn access_log_configuration() {
        let config = Config::parse(
            "[access_log]\npath = '/tmp/access.log'\ncheck_interval = 5\nmax_size_bytes = 4096\nkeep_entries = 20",
        )
        .unwrap();
        assert_eq!(
            config.startup.access_log,
            AccessLogConfig {
                path: "/tmp/access.log".into(),
                check_interval: 5,
                max_size_bytes: 4096,
                keep_entries: 20,
            }
        );
    }

    /// Accept multiple literal bind interfaces, partial overrides, and disabled UI.
    #[test]
    fn ui_configuration() {
        let config = Config::parse("[ui]\nhosts = ['127.0.0.1', '::1']\nport = 8080").unwrap();
        assert_eq!(config.startup.ui.port, 8080);
        assert_eq!(config.startup.ui.hosts.len(), 2);
        assert!(Config::parse("[ui]\nhosts = []").unwrap().startup.ui.hosts.is_empty());
        assert_eq!(
            Config::parse("[ui]\nport = 8081").unwrap().startup.ui.hosts,
            UiConfig::default().hosts
        );
    }

    /// A missing file yields defaults while a malformed file reports its path.
    #[test]
    fn load_distinguishes_missing_and_invalid_files() {
        let directory = tempfile::tempdir().unwrap();
        let missing = Config::load(&directory.path().join("absent.toml")).unwrap();
        assert_eq!(missing.runtime, RuntimeSettings::default());
        let path = directory.path().join("config.toml");
        fs::write(&path, "not valid TOML").unwrap();
        let error = Config::load(&path).unwrap_err();
        assert!(matches!(error, ConfigError::Invalid { .. }));
        assert!(error.to_string().contains("config.toml"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
