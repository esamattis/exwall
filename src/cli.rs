//! Command-line definitions. This module is the single source of default values.

use clap::{Args, FromArgMatches, Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

/// Default configuration file path.
pub const DEFAULT_CONFIG: &str = "/etc/exwall/config.toml";
/// Default directory of TOML allow-rule files.
pub const DEFAULT_RULES_DIR: &str = "/etc/exwall/rules.d";
/// Default dual-stack HTTP(S) proxy listener.
pub const DEFAULT_LISTEN: &str = "[::]:58080";
/// Default dual-stack UDP/TCP DNS listener.
pub const DEFAULT_DNS_LISTEN: &str = "[::]:58053";
/// Default upstream resolver (the systemd-resolved stub).
pub const DEFAULT_DNS_UPSTREAM: &str = "127.0.0.53:53";
/// Default directory containing the persistent CA.
pub const DEFAULT_CA_DIR: &str = "/var/lib/exwall";
/// Default account running the proxy service.
pub const DEFAULT_PROXY_USER: &str = "exwall";
/// Default private directory for hook state snapshots.
pub const DEFAULT_STATE_DIR: &str = "/run/exwall";
/// Default proxy port targeted by firewall redirects.
pub const DEFAULT_PROXY_PORT: u16 = 58080;
/// Default DNS port targeted by firewall redirects.
pub const DEFAULT_DNS_PORT: u16 = 58053;

/// Command-line paths shared by validation, service, and privileged hooks.
#[derive(Debug, Parser)]
#[command(name = "exwall", version, about)]
pub struct Cli {
    /// Configuration file; built-in defaults apply when it is absent.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Directory of TOML allow-rule files.
    #[arg(long, global = true, default_value = DEFAULT_RULES_DIR)]
    pub rules_dir: PathBuf,
    /// The operation to run; serving is the default.
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    /// Return the selected command, substituting `serve` with default arguments.
    pub fn command_or_default(&self) -> Command {
        match &self.command {
            Some(command) => command.clone(),
            None => Command::Serve(ServeArgs::defaults()),
        }
    }
}

/// Supported operator commands; running without a command starts the proxy.
#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Run HTTP(S) interception and DNS listeners without changing the firewall.
    Serve(ServeArgs),
    /// Validate all configuration and rule files without starting listeners.
    Check,
    /// Generate a local CA once, preserving an existing CA.
    InitCa(CaArgs),
    /// Run a privileged systemd lifecycle hook.
    Hook(HookArgs),
    /// Generate web UI credentials in the configuration file and print the login.
    UiCredentials(UiCredentialsArgs),
}

/// Listener, upstream, and CA settings for the proxy service.
#[derive(Clone, Debug, Args)]
pub struct ServeArgs {
    /// HTTP(S) proxy listener address.
    #[arg(long, default_value = DEFAULT_LISTEN)]
    pub listen: SocketAddr,
    /// UDP and TCP DNS listener address.
    #[arg(long, default_value = DEFAULT_DNS_LISTEN)]
    pub dns_listen: SocketAddr,
    /// Upstream DNS resolver receiving authorized queries.
    #[arg(long, default_value = DEFAULT_DNS_UPSTREAM)]
    pub dns_upstream: SocketAddr,
    /// Directory containing the CA certificate and key.
    #[arg(long, default_value = DEFAULT_CA_DIR)]
    pub ca_dir: PathBuf,
}

impl ServeArgs {
    /// Build the clap-declared defaults, keeping them defined in one place.
    pub fn defaults() -> Self {
        let command = Self::augment_args(clap::Command::new("serve"));
        let matches = command.get_matches_from(["serve"]);
        Self::from_arg_matches(&matches).expect("serve defaults are valid")
    }
}

/// Settings for CA generation.
#[derive(Clone, Debug, Args)]
pub struct CaArgs {
    /// Directory receiving the CA certificate and key.
    #[arg(long, default_value = DEFAULT_CA_DIR)]
    pub ca_dir: PathBuf,
}

/// Settings for web UI credential generation.
#[derive(Clone, Debug, Args)]
pub struct UiCredentialsArgs {
    /// Login name; defaults to the configured name, or "admin" when none is set.
    #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
    pub username: Option<String>,
    /// Keep existing complete credentials instead of generating a new password.
    #[arg(long)]
    pub if_missing: bool,
}

/// Settings shared by every privileged hook operation.
#[derive(Clone, Debug, Args)]
pub struct HookArgs {
    /// The lifecycle operation to run.
    #[command(subcommand)]
    pub action: HookAction,
    /// Print firewall commands without changing the host.
    #[arg(long)]
    pub dry_run: bool,
    /// Account running the proxy, exempt from enforcement.
    #[arg(long, default_value = DEFAULT_PROXY_USER)]
    pub proxy_user: String,
    /// Private directory for lifecycle state snapshots.
    #[arg(long, default_value = DEFAULT_STATE_DIR)]
    pub state_dir: PathBuf,
    /// Proxy port receiving redirected HTTP(S).
    #[arg(long, default_value_t = DEFAULT_PROXY_PORT)]
    pub proxy_port: u16,
    /// DNS port receiving redirected queries.
    #[arg(long, default_value_t = DEFAULT_DNS_PORT)]
    pub dns_port: u16,
}

/// Firewall hook operations invoked by systemd's privileged lifecycle commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Subcommand)]
pub enum HookAction {
    /// Preserve existing enforcement or install a minimal configuration-independent deny policy.
    Guard,
    /// Install egress policy and save the original resolver and sysctl state.
    Start,
    /// Restore saved host state and remove managed firewall chains.
    Stop,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The implicit serve command uses exactly the declared defaults.
    #[test]
    fn default_command_is_serve_with_declared_defaults() {
        let cli = Cli::parse_from(["exwall"]);
        let Command::Serve(args) = cli.command_or_default() else {
            panic!("expected serve");
        };
        assert_eq!(args.listen, DEFAULT_LISTEN.parse::<SocketAddr>().unwrap());
        assert_eq!(args.dns_listen, DEFAULT_DNS_LISTEN.parse::<SocketAddr>().unwrap());
        assert_eq!(args.dns_upstream, DEFAULT_DNS_UPSTREAM.parse::<SocketAddr>().unwrap());
        assert_eq!(args.ca_dir, PathBuf::from(DEFAULT_CA_DIR));
        assert_eq!(cli.config, PathBuf::from(DEFAULT_CONFIG));
    }

    /// Hook options precede the action, matching the systemd unit and docs/usage.md.
    #[test]
    fn parses_hook_options_before_action() {
        let cli = Cli::parse_from([
            "exwall",
            "--rules-dir",
            "/tmp/rules",
            "hook",
            "--dry-run",
            "--proxy-user",
            "root",
            "--proxy-port",
            "1234",
            "start",
        ]);
        let Some(Command::Hook(hook)) = cli.command else {
            panic!("expected hook");
        };
        assert!(hook.dry_run);
        assert_eq!(hook.action, HookAction::Start);
        assert_eq!(hook.proxy_user, "root");
        assert_eq!(hook.proxy_port, 1234);
        assert_eq!(hook.dns_port, DEFAULT_DNS_PORT);
        assert_eq!(cli.rules_dir, PathBuf::from("/tmp/rules"));
    }
}
