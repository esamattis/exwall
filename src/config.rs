use crate::error::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Runtime settings compatible with mitmwall config.toml.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log_level: String,
    pub access_log: AccessLogConfig,
    pub ui: UiConfig,
    /// Automatically reload validated rules when the rules directory changes.
    pub watch_rules: bool,
    pub block_dns: bool,
    pub manage_resolv_conf: bool,
    pub flow_history_clear_interval: u64,
    pub flow_history_keep_entries: u64,
    pub bypass_users: Vec<String>,
    pub iptables: Iptables,
}

impl Default for Config {
    /// Return the built-in settings used when config.toml is absent.
    fn default() -> Self {
        Self {
            log_level: "info".into(),
            access_log: AccessLogConfig::default(),
            ui: UiConfig::default(),
            watch_rules: true,
            block_dns: true,
            manage_resolv_conf: true,
            flow_history_clear_interval: 1000,
            flow_history_keep_entries: 500,
            // The Python hook defaults to no bypass users; the shipped config includes root/_apt.
            bypass_users: Vec::new(),
            iptables: Iptables::default(),
        }
    }
}

/// HTTP UI bind addresses and port, applied when the service starts.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    /// Literal IPv4/IPv6 bind addresses; an empty list disables the UI.
    pub hosts: Vec<std::net::IpAddr>,
    /// Shared TCP port for every configured interface.
    pub port: u16,
    /// Login account; an empty username or password disables authenticated API access.
    pub username: String,
    /// Login password shared by cookie login and HTTP Basic authentication.
    pub password: String,
    /// Directory containing private, persistent JSON cookie sessions.
    pub sessions_dir: PathBuf,
}

impl Default for UiConfig {
    /// Restrict the UI to IPv4 loopback on port 58000 by default.
    fn default() -> Self {
        Self {
            hosts: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
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
    pub path: PathBuf,
    pub check_interval: u64,
    pub max_size_bytes: u64,
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
    pub bypass: Vec<Bypass>,
}

/// A TCP destination network and port that bypass proxy filtering.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bypass {
    #[serde(deserialize_with = "deserialize_network")]
    pub network: ipnet::IpNet,
    pub port: u16,
}

/// Accept a CIDR network or a single IP address, as Python's ip_network does.
fn deserialize_network<'de, D>(deserializer: D) -> std::result::Result<ipnet::IpNet, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;

    if let Ok(network) = value.parse::<ipnet::IpNet>() {
        return Ok(network);
    }

    value.parse::<std::net::IpAddr>().map(ipnet::IpNet::from).map_err(serde::de::Error::custom)
}

impl Config {
    /// Read configuration from disk, using defaults only when the file is absent.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("config {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Deserialize and validate all runtime and firewall settings.
    pub fn parse(text: &str) -> Result<Self> {
        let mut config: Self = toml::from_str(text)?;
        config.log_level = config.log_level.trim().to_lowercase();
        ensure!(
            ["debug", "info", "warning", "error", "critical"].contains(&config.log_level.as_str()),
            "invalid log_level"
        );
        ensure!(
            config.flow_history_clear_interval > 0 && config.flow_history_keep_entries > 0,
            "flow history settings must be positive integers"
        );
        ensure!(
            config.access_log.path.file_name().is_some()
                && !config.access_log.path.as_os_str().is_empty(),
            "access_log.path must name a file"
        );
        ensure!(
            config.access_log.check_interval > 0
                && config.access_log.max_size_bytes > 0
                && config.access_log.keep_entries > 0,
            "access log retention settings must be positive integers"
        );
        ensure!(
            config.bypass_users.iter().all(|s| !s.is_empty()),
            "bypass_users must contain nonempty names"
        );
        ensure!(
            !config.ui.sessions_dir.as_os_str().is_empty(),
            "ui.sessions_dir must not be empty"
        );
        ensure!(config.ui.port > 0, "ui.port must be 1..65535");
        for (index, host) in config.ui.hosts.iter().enumerate() {
            ensure!(
                !config.ui.hosts[..index].contains(host),
                "ui.hosts must not contain duplicate addresses"
            );
        }
        for bypass in &mut config.iptables.bypass {
            ensure!(bypass.port > 0, "bypass port must be 1..65535");
            bypass.network = bypass.network.trunc();
        }
        Ok(config)
    }

    /// Translate mitmwall log-level names to tracing filter directives.
    pub fn tracing_level(&self) -> &str {
        match self.log_level.as_str() {
            "warning" => "warn",
            "critical" => "error",
            level => level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Verify shipped defaults, network normalization, and strict validation.
    #[test]
    fn configuration_compatibility() {
        let config = Config::parse(include_str!("../config-default.toml")).unwrap();
        assert_eq!(config.bypass_users, ["root", "_apt"]);
        assert_eq!(config.access_log, AccessLogConfig::default());
        assert_eq!(config.ui, UiConfig::default());
        assert!(config.watch_rules);
        assert!(Config::parse("").unwrap().watch_rules);
        assert!(!Config::parse("watch_rules = false").unwrap().watch_rules);
        let config =
            Config::parse("[[iptables.bypass]]\nnetwork = '192.168.5.19/24'\nport = 1234").unwrap();
        assert_eq!(config.iptables.bypass[0].network.to_string(), "192.168.5.0/24");
        let config = Config::parse("[[iptables.bypass]]\nnetwork = '::1'\nport = 443").unwrap();
        assert_eq!(config.iptables.bypass[0].network.to_string(), "::1/128");
        for text in [
            "block_dns = 1",
            "watch_rules = 1",
            "[ui]\nport = 0",
            "[ui]\nport = 65536",
            "[ui]\nhosts = ['localhost']",
            "[ui]\nhosts = ['127.0.0.1', '127.0.0.1']",
            "[ui]\ntypo = true",
            "flow_history_keep_entries = 0",
            "typo = true",
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

    /// Accept access-log overrides while retaining defaults for omitted fields.
    #[test]
    fn access_log_configuration() {
        let config = Config::parse("[access_log]\npath = '/tmp/access.log'\ncheck_interval = 5\nmax_size_bytes = 4096\nkeep_entries = 20").unwrap();
        assert_eq!(
            config.access_log,
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
        assert_eq!(config.ui.port, 8080);
        assert_eq!(config.ui.hosts.len(), 2);
        assert!(Config::parse("[ui]\nhosts = []").unwrap().ui.hosts.is_empty());
        assert_eq!(Config::parse("[ui]\nport = 8081").unwrap().ui.hosts, UiConfig::default().hosts);
    }
}
