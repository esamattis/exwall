//! TOML-driven transparent HTTP(S) and DNS egress filtering for Linux.
mod access_log;
mod ca;
mod command_log;
mod config;
mod dns;
mod error;
mod firewall;
mod hooks;
mod pathname;
mod proxy;
mod rules;
mod rules_watch;
mod state;
mod udp;
mod ui;

use crate::error::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::net::{TcpListener, UdpSocket};

/// Command-line paths shared by validation, service, and privileged hooks.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/exwall/config.toml")]
    config: PathBuf,
    #[arg(long, global = true, default_value = "/etc/exwall/rules.d")]
    rules_dir: PathBuf,
    #[command(subcommand)]
    command: Option<Action>,
}

/// Supported operator commands; running without a command starts the proxy.
#[derive(Subcommand)]
enum Action {
    /// Run HTTP(S) interception and DNS listeners without changing the firewall.
    Serve {
        #[arg(long, default_value = "[::]:58080")]
        listen: SocketAddr,
        #[arg(long, default_value = "[::]:58053")]
        dns_listen: SocketAddr,
        #[arg(long, default_value = "127.0.0.53:53")]
        dns_upstream: SocketAddr,
        #[arg(long, default_value = "/var/lib/exwall")]
        ca_dir: PathBuf,
    },
    /// Validate all configuration and rule files without starting listeners.
    Check,
    /// Generate a local CA once, preserving an existing CA.
    InitCa {
        #[arg(long, default_value = "/var/lib/exwall")]
        ca_dir: PathBuf,
    },
    /// Run a privileged systemd lifecycle hook.
    Hook {
        #[command(subcommand)]
        action: HookAction,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "exwall")]
        proxy_user: String,
        #[arg(long, default_value = "/run/exwall")]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 58080)]
        proxy_port: u16,
        #[arg(long, default_value_t = 58053)]
        dns_port: u16,
    },
}

/// Firewall hook operations invoked by systemd's privileged lifecycle commands.
#[derive(Subcommand)]
enum HookAction {
    /// Preserve existing enforcement or install a minimal configuration-independent deny policy.
    Guard,
    /// Install egress policy and save the original resolver and sysctl state.
    Start,
    /// Restore saved host state and remove managed firewall chains.
    Stop,
}

/// Dispatch CLI operations and report contextual failures.
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let action = cli.command.unwrap_or(Action::Serve {
        listen: "[::]:58080".parse()?,
        dns_listen: "[::]:58053".parse()?,
        dns_upstream: "127.0.0.53:53".parse()?,
        ca_dir: "/var/lib/exwall".into(),
    });
    // Configuration failures must never prevent guarding or stopping the firewall.
    match action {
        Action::Hook {
            action,
            dry_run,
            proxy_user,
            state_dir,
            proxy_port,
            dns_port,
        } => {
            let hook_config = config::Config::load(&cli.config);
            let log_level = hook_config.as_ref().map_or("info", |config| config.tracing_level());
            init_logging(log_level);
            let hooks = hooks::Hooks {
                dry_run,
                proxy_user,
                state_dir,
                proxy_port,
                dns_port,
                ..hooks::Hooks::default()
            };
            if matches!(action, HookAction::Guard | HookAction::Start) {
                hooks.guard()?;
            }
            if matches!(action, HookAction::Guard) {
                return Ok(());
            }
            let start = matches!(action, HookAction::Start);
            let config = if start {
                let config = hook_config?;
                rules::RuleSet::load(&cli.rules_dir)?;
                Some(config)
            } else {
                None
            };
            hooks.run(start, config.as_ref())?;
        }
        Action::InitCa {
            ca_dir,
        } => {
            ca::init(&ca_dir)?;
            println!("CA certificate: {}", ca_dir.join(ca::CERT_FILE).display());
        }
        Action::Check => {
            config::Config::load(&cli.config)?;
            let rules = rules::RuleSet::load(&cli.rules_dir)?;
            println!("Configuration valid; {} allow rules", rules.rules.len());
        }
        Action::Serve {
            listen,
            dns_listen,
            dns_upstream,
            ca_dir,
        } => {
            serve(cli.config, cli.rules_dir, listen, dns_listen, dns_upstream, ca_dir).await?;
        }
    }
    Ok(())
}

/// Initialize application logging at the level selected by the TOML configuration.
fn init_logging(log_level: &str) {
    let filter = tracing_subscriber::EnvFilter::new(log_level);
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
}

/// Bind TCP with explicit dual-stack behavior for IPv6 wildcard addresses.
fn tcp_listener(address: SocketAddr) -> Result<TcpListener> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

/// Bind UDP with explicit dual-stack behavior for IPv6 wildcard addresses.
fn udp_listener(address: SocketAddr) -> Result<UdpSocket> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// Run listeners, watch rule changes, and atomically reload the full policy on SIGHUP.
async fn serve(
    config_path: PathBuf,
    rules_dir: PathBuf,
    listen: SocketAddr,
    dns_listen: SocketAddr,
    dns_upstream: SocketAddr,
    ca_dir: PathBuf,
) -> Result<()> {
    ensure!(listen.port() != 0 && dns_listen.port() != 0, "listener ports must be nonzero");
    ensure!(
        dns_upstream.port() != dns_listen.port() || dns_upstream.ip() != dns_listen.ip(),
        "DNS upstream cannot be the DNS listener"
    );
    let config = config::Config::load(&config_path)?;
    let access_log_config = config.access_log.clone();
    let ui_config = config.ui.clone();
    init_logging(config.tracing_level());
    let mut rules_watcher = if config.watch_rules {
        Some(rules_watch::RulesWatcher::new(&rules_dir)?)
    } else {
        None
    };
    let policy = Arc::new(arc_swap::ArcSwap::from_pointee(state::Policy {
        config,
        rules: rules::RuleSet::load(&rules_dir)?,
    }));
    let authority =
        Arc::new(ca::Authority::load(&ca_dir).context("load CA; run exwall init-ca first")?);
    let http = tcp_listener(listen).context("bind HTTP proxy")?;
    let dns_tcp = tcp_listener(dns_listen).context("bind DNS TCP")?;
    let dns_udp = udp_listener(dns_listen).context("bind DNS UDP")?;
    let ui_listeners = ui::bind(&ui_config)?;
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        let _ = shutdown_receiver.await;
    });
    let (access_log, mut access_task) = access_log::AccessLog::start(access_log_config).await?;
    let proxy = proxy::Proxy {
        access_log: access_log.clone(),
        policy: policy.clone(),
        authority,
        exec: rama::rt::Executor::graceful(shutdown.guard()),
    };
    let dns = dns::Dns::new(policy.clone(), dns_upstream, access_log.clone());
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut http_task = tokio::spawn(proxy.serve(http));
    let mut dns_task = tokio::spawn(dns.serve(dns_udp, dns_tcp));
    let mut ui_task =
        tokio::spawn(ui::serve(ui_listeners, rama::rt::Executor::graceful(shutdown.guard())));
    let mut access_finished = false;
    tracing::info!(hosts = ?ui_config.hosts, port = ui_config.port, "UI listeners configured");
    tracing::info!(%listen, %dns_listen, rules = policy.load().rules.rules.len(), "exwall ready");
    let result = loop {
        tokio::select! {
            result = &mut access_task => {
                access_finished = true;
                break result.context("access-log task failed")
                    .and_then(|result| result)
                    .and_then(|()| Err(error::Error::message("access-log actor exited unexpectedly")));
            }
            result = &mut http_task => {
                break result.context("HTTP listener task failed").and_then(|result| result);
            }
            result = &mut ui_task => {
                break result.context("UI task failed").and_then(|result| result);
            }
            result = &mut dns_task => {
                break result.context("DNS listener task failed").and_then(|result| result);
            }
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = async {
                match rules_watcher.as_mut() {
                    Some(watcher) => watcher.changed().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let Some(watcher) = rules_watcher.as_ref() else {
                    continue;
                };
                match watcher.reload(&policy) {
                    Ok(()) => tracing::info!(
                        rules = policy.load().rules.rules.len(),
                        "automatically reloaded rules"
                    ),
                    Err(error) => tracing::error!(%error, "rule reload rejected; keeping previous policy"),
                }
            }
            _ = hangup.recv() => {
                let reloaded = load_policy(&config_path, &rules_dir);
                match reloaded {
                    Ok(new_policy) => {
                        if new_policy.config.watch_rules && rules_watcher.is_none() {
                            match rules_watch::RulesWatcher::new(&rules_dir) {
                                Ok(watcher) => rules_watcher = Some(watcher),
                                Err(error) => {
                                    tracing::error!(%error, "reload rejected; keeping previous policy");
                                    continue;
                                }
                            }
                        } else if !new_policy.config.watch_rules {
                            rules_watcher = None;
                        }
                        tracing::info!(
                            rules = new_policy.rules.rules.len(),
                            "reloaded policy; restart service to apply firewall/resolver/log-level/access-log/UI changes"
                        );
                        policy.store(Arc::new(new_policy));
                    }
                    Err(error) => tracing::error!(%error, "reload rejected; keeping previous policy"),
                }
            }
        }
    };
    let _ = shutdown_sender.send(());
    if !http_task.is_finished() {
        http_task.abort();
        let _ = http_task.await;
    }
    if !dns_task.is_finished() {
        dns_task.abort();
        let _ = dns_task.await;
    }
    if !ui_task.is_finished() {
        ui_task.abort();
        let _ = ui_task.await;
    }
    let graceful_result = shutdown
        .shutdown_with_limit(std::time::Duration::from_secs(10))
        .await
        .context("graceful shutdown");
    // Wait for cancelled handlers to submit their entries and drop the final sender.
    drop(access_log);
    let access_result = if access_finished {
        Ok(())
    } else {
        access_task.await.context("join access-log actor").and_then(|result| result)
    };
    result.and(graceful_result).and(access_result)
}

/// Compile a complete policy before publishing it to either HTTP or DNS handlers.
fn load_policy(
    config_path: &std::path::Path,
    rules_dir: &std::path::Path,
) -> Result<state::Policy> {
    Ok(state::Policy {
        config: config::Config::load(config_path)?,
        rules: rules::RuleSet::load_existing(rules_dir)?,
    })
}
