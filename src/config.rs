use crate::error::{Context, Result, ensure};
use serde::Deserialize;
use std::{fs, path::Path};

/// Runtime settings compatible with mitmwall config.toml.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log_level: String,
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
            config.bypass_users.iter().all(|s| !s.is_empty()),
            "bypass_users must contain nonempty names"
        );
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
        let config =
            Config::parse("[[iptables.bypass]]\nnetwork = '192.168.5.19/24'\nport = 1234").unwrap();
        assert_eq!(config.iptables.bypass[0].network.to_string(), "192.168.5.0/24");
        let config = Config::parse("[[iptables.bypass]]\nnetwork = '::1'\nport = 443").unwrap();
        assert_eq!(config.iptables.bypass[0].network.to_string(), "::1/128");
        for text in [
            "block_dns = 1",
            "flow_history_keep_entries = 0",
            "typo = true",
            "[[iptables.bypass]]\nnetwork = '::1'\nport = 0",
        ] {
            assert!(Config::parse(text).is_err(), "{text}");
        }
    }
}
