//! The `serve` command: build services, supervise them, and shut down in order.

use super::init_logging;
use crate::{
    ca::{Authority, CaError},
    cli::{Cli, ServeArgs},
    config::{Config, ConfigError},
    dns::{DnsError, DnsService, SocketUpstream},
    error::ErrorChain,
    net::{self, Stack},
    policy::{Host, LoadError, LocalHostname, MissingDirectory, Policy, load_rules},
    proxy::{HttpUpstream, Proxy, ProxyError},
    runtime::{PolicyStore, ReloadHandle, Reloader, RulesWatcher, WatchError},
    telemetry::{self, AccessLogError, AccessLogTask},
    ui::{
        self, Api, UiError, WebRulesFile,
        auth::{Authenticator, Credentials, FileSessionStore, RandomTokens},
    },
};
use rama::rt::Executor;
use std::{collections::HashMap, future::Future, io, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    sync::oneshot,
    task::{Id, JoinError, JoinSet},
};

/// The TCP listen backlog for proxy and DNS listeners.
const BACKLOG: i32 = 1024;
/// How long in-flight graceful tasks may run after shutdown begins.
const GRACEFUL_LIMIT: Duration = Duration::from_secs(10);
/// How long the closed access log may take to write its final batch.
const DRAIN_LIMIT: Duration = Duration::from_secs(5);
/// The kernel's record of this host's name.
const KERNEL_HOSTNAME: &str = "/proc/sys/kernel/hostname";

/// Why a supervised task stopped.
#[derive(Debug, Error)]
pub enum TaskFailure {
    /// The HTTP proxy listener failed.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    /// The DNS listeners failed.
    #[error(transparent)]
    Dns(#[from] DnsError),
    /// A UI listener failed.
    #[error(transparent)]
    Ui(#[from] UiError),
    /// The task panicked.
    #[error("task panicked")]
    Panicked(#[source] JoinError),
}

/// Service startup and supervision failures.
#[derive(Debug, Error)]
pub enum ServeError {
    /// A listener port is zero.
    #[error("listener ports must be nonzero")]
    ZeroPort,
    /// The upstream resolver is this service's own DNS listener.
    #[error("DNS upstream cannot be the DNS listener")]
    DnsLoop,
    /// The configuration is invalid.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The rules are invalid.
    #[error(transparent)]
    Rules(#[from] LoadError),
    /// The rules watcher could not start.
    #[error(transparent)]
    Watcher(#[from] WatchError),
    /// The CA could not be loaded.
    #[error("load CA; run exwall init-ca first")]
    Ca(#[source] CaError),
    /// The proxy port could not be bound.
    #[error("bind HTTP proxy")]
    BindHttp(#[source] io::Error),
    /// The DNS TCP port could not be bound.
    #[error("bind DNS TCP")]
    BindDnsTcp(#[source] io::Error),
    /// The DNS UDP port could not be bound.
    #[error("bind DNS UDP")]
    BindDnsUdp(#[source] io::Error),
    /// A UI address could not be bound.
    #[error(transparent)]
    Ui(#[from] UiError),
    /// The access log failed.
    #[error(transparent)]
    AccessLog(#[from] AccessLogError),
    /// The access-log actor stopped while the service was running.
    #[error("access-log actor exited unexpectedly")]
    AccessLogExited,
    /// The access-log actor panicked.
    #[error("access-log task failed")]
    AccessLogTask(#[source] JoinError),
    /// The access log did not finish its final write in time.
    #[error("access log did not drain before the shutdown deadline")]
    DrainTimeout,
    /// Signal handlers could not be installed.
    #[error("install signal handler")]
    Signal(#[source] io::Error),
    /// A supervised task failed.
    #[error("{name} task failed")]
    Task {
        /// The task's name.
        name: &'static str,
        /// Why it failed.
        #[source]
        source: TaskFailure,
    },
    /// A supervised task returned although it should run until shutdown.
    #[error("{name} task exited unexpectedly")]
    TaskExited {
        /// The task's name.
        name: &'static str,
    },
    /// In-flight work did not finish within the graceful limit.
    #[error("graceful shutdown")]
    Shutdown(#[source] rama::error::BoxError),
}

/// A signal the supervisor reacts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignalEvent {
    /// SIGTERM or SIGINT: stop with success.
    Stop,
    /// SIGHUP: reload configuration and rules.
    Hangup,
}

/// Where supervisor signals come from.
enum Signals {
    /// Process signal handlers.
    Process {
        /// SIGTERM.
        terminate: Signal,
        /// SIGINT.
        interrupt: Signal,
        /// SIGHUP.
        hangup: Signal,
    },
    /// Events injected by tests without touching process-wide handlers.
    #[cfg(test)]
    Injected(tokio::sync::mpsc::Receiver<SignalEvent>),
}

impl Signals {
    /// Install handlers for every supervised process signal.
    fn install() -> Result<Self, ServeError> {
        let install = |kind| signal(kind).map_err(ServeError::Signal);
        Ok(Self::Process {
            terminate: install(SignalKind::terminate())?,
            interrupt: install(SignalKind::interrupt())?,
            hangup: install(SignalKind::hangup())?,
        })
    }

    /// Wait for the next signal.
    async fn next(&mut self) -> SignalEvent {
        match self {
            Self::Process {
                terminate,
                interrupt,
                hangup,
            } => {
                tokio::select! {
                    _ = terminate.recv() => SignalEvent::Stop,
                    _ = interrupt.recv() => SignalEvent::Stop,
                    _ = hangup.recv() => SignalEvent::Hangup,
                }
            }
            #[cfg(test)]
            Self::Injected(events) => match events.recv().await {
                Some(event) => event,
                None => std::future::pending().await,
            },
        }
    }
}

/// Named long-running tasks; any completion is a service failure.
struct Supervisor {
    /// The running tasks.
    tasks: JoinSet<Result<(), TaskFailure>>,
    /// Task names by ID, for reporting panics.
    names: HashMap<Id, &'static str>,
}

impl Supervisor {
    /// Create an empty supervisor.
    fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            names: HashMap::new(),
        }
    }

    /// Spawn a named task.
    fn spawn<F>(&mut self, name: &'static str, task: F)
    where
        F: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        let handle = self.tasks.spawn(task);
        self.names.insert(handle.id(), name);
    }

    /// Wait for the first task to finish and describe why that is a failure.
    async fn next_failure(&mut self) -> ServeError {
        let Some(joined) = self.tasks.join_next_with_id().await else {
            return std::future::pending().await;
        };
        match joined {
            Ok((id, Ok(()))) => ServeError::TaskExited {
                name: self.name(id),
            },
            Ok((id, Err(source))) => ServeError::Task {
                name: self.name(id),
                source,
            },
            Err(error) => ServeError::Task {
                name: self.name(error.id()),
                source: TaskFailure::Panicked(error),
            },
        }
    }

    /// Look up a task's name.
    fn name(&self, id: Id) -> &'static str {
        self.names.get(&id).copied().unwrap_or("unknown")
    }

    /// Cancel every task and wait until they are gone.
    async fn shutdown(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

/// Reject listener configurations that cannot work.
fn validate(args: &ServeArgs) -> Result<(), ServeError> {
    if args.listen.port() == 0 || args.dns_listen.port() == 0 {
        return Err(ServeError::ZeroPort);
    }
    if args.dns_upstream == args.dns_listen {
        return Err(ServeError::DnsLoop);
    }
    Ok(())
}

/// Run listeners, watch rule changes, and reload the full policy on SIGHUP until signalled.
pub async fn run(cli: &Cli, args: ServeArgs) -> Result<(), ServeError> {
    validate(&args)?;
    let config = Config::load(&cli.config)?;
    init_logging(config.startup.log_level);
    // Watch before loading so no change between the two is missed.
    let watcher = if config.runtime.watch_rules {
        Some(RulesWatcher::new(&cli.rules_dir)?)
    } else {
        None
    };
    let rules = load_rules(&cli.rules_dir, MissingDirectory::Empty)?;
    let store = Arc::new(PolicyStore::new(Policy::new(config.runtime, rules)));
    let authority = Arc::new(Authority::load(&args.ca_dir).map_err(ServeError::Ca)?);
    let http =
        net::tcp_listener(args.listen, Stack::Dual, BACKLOG).map_err(ServeError::BindHttp)?;
    let dns_tcp =
        net::tcp_listener(args.dns_listen, Stack::Dual, BACKLOG).map_err(ServeError::BindDnsTcp)?;
    let dns_udp = net::udp_socket(args.dns_listen, Stack::Dual).map_err(ServeError::BindDnsUdp)?;
    let ui_listeners = ui::bind(&config.startup.ui)?;
    let telemetry::AccessLog {
        sink,
        task: access_log,
        closer: close_access_log,
    } = telemetry::start(config.startup.access_log.clone()).await?;
    let mut signals = Signals::install()?;

    let (begin_shutdown, shutdown_requested) = oneshot::channel::<()>();
    let graceful = rama::graceful::Shutdown::new(async move {
        let _ = shutdown_requested.await;
    });
    let (reloader, reload) =
        Reloader::new(cli.config.clone(), cli.rules_dir.clone(), store.clone(), watcher);
    let mut supervisor = Supervisor::new();
    {
        let exec = Executor::graceful(graceful.guard());
        let upstream = Arc::new(HttpUpstream::new(exec.clone()));
        let proxy = Proxy::new(sink.clone(), store.clone(), authority, upstream, exec.clone());
        supervisor.spawn("HTTP proxy", async move { Ok(proxy.serve(http).await?) });
        let dns = DnsService::new(
            store.clone(),
            Arc::new(SocketUpstream::new(args.dns_upstream)),
            sink.clone(),
            local_hostname(),
        );
        supervisor.spawn("DNS", async move { Ok(dns.serve(dns_udp, dns_tcp).await?) });
        if !ui_listeners.is_empty() {
            let api = Arc::new(build_api(&config, cli, reload.clone(), &sink));
            supervisor.spawn("UI", async move { Ok(ui::serve(ui_listeners, exec, api).await?) });
        }
        supervisor.spawn("policy reloader", async move {
            reloader.run().await;
            Ok(())
        });
    }
    // Only request handlers may keep the access log open.
    drop(sink);
    tracing::info!(
        hosts = ?config.startup.ui.hosts,
        port = config.startup.ui.port,
        "UI listeners configured"
    );
    tracing::info!(
        listen = %args.listen,
        dns_listen = %args.dns_listen,
        rules = store.load().rules.len(),
        "exwall ready"
    );

    let mut access_log = Some(access_log);
    let outcome = supervise(&mut supervisor, &mut access_log, &mut signals, &reload).await;
    if let Err(error) = &outcome {
        tracing::error!(error = %ErrorChain(error), "shutting down after failure");
    }
    let _ = begin_shutdown.send(());
    supervisor.shutdown().await;
    drop(reload);
    let graceful_result = graceful
        .shutdown_with_limit(GRACEFUL_LIMIT)
        .await
        .map(|_| ())
        .map_err(|error| ServeError::Shutdown(error.into()));
    // Handlers that outlived the graceful limit must not hold back queued events.
    close_access_log.close();
    let drain_result = match access_log {
        Some(task) => drain(task).await,
        None => Ok(()),
    };
    outcome.and(graceful_result).and(drain_result)
}

/// Read the kernel hostname for the DNS exception, disabling it if unavailable.
///
/// A failed read must not fall back to an empty name, which would otherwise
/// authorize queries for the DNS root.
fn local_hostname() -> LocalHostname {
    match std::fs::read_to_string(KERNEL_HOSTNAME) {
        Ok(name) => LocalHostname::new(Host::new(&name)),
        Err(error) => {
            tracing::warn!(%error, "cannot read the local hostname; its DNS exception is disabled");
            LocalHostname::default()
        }
    }
}

/// Assemble the UI API from configuration and shared services.
fn build_api(config: &Config, cli: &Cli, reload: ReloadHandle, sink: &telemetry::EventSink) -> Api {
    let ui = &config.startup.ui;
    let auth = Authenticator::new(
        Credentials::new(&ui.username, &ui.password),
        Arc::new(FileSessionStore::new(ui.sessions_dir.clone())),
        Arc::new(RandomTokens),
    );
    Api::new(auth, WebRulesFile::new(cli.rules_dir.clone()), reload, sink.stats().clone())
}

/// Wait for a stop signal or the first failure, forwarding SIGHUP to the reloader.
async fn supervise(
    supervisor: &mut Supervisor,
    access_log: &mut Option<AccessLogTask>,
    signals: &mut Signals,
    reload: &ReloadHandle,
) -> Result<(), ServeError> {
    let Some(task) = access_log.as_mut() else {
        return Err(ServeError::AccessLogExited);
    };
    loop {
        tokio::select! {
            error = supervisor.next_failure() => return Err(error),
            finished = &mut *task => {
                *access_log = None;
                return Err(match finished {
                    Ok(Ok(())) => ServeError::AccessLogExited,
                    Ok(Err(error)) => ServeError::AccessLog(error),
                    Err(error) => ServeError::AccessLogTask(error),
                });
            }
            event = signals.next() => match event {
                SignalEvent::Stop => return Ok(()),
                SignalEvent::Hangup => reload.request_policy_reload(),
            },
        }
    }
}

/// Wait for the closed access-log actor to write its final batch.
async fn drain(task: AccessLogTask) -> Result<(), ServeError> {
    match tokio::time::timeout(DRAIN_LIMIT, task).await {
        Ok(Ok(result)) => Ok(result?),
        Ok(Err(error)) => Err(ServeError::AccessLogTask(error)),
        Err(_) => Err(ServeError::DrainTimeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build serve arguments from addresses.
    fn args(listen: &str, dns_listen: &str, upstream: &str) -> ServeArgs {
        ServeArgs {
            listen: listen.parse().unwrap(),
            dns_listen: dns_listen.parse().unwrap(),
            dns_upstream: upstream.parse().unwrap(),
            ca_dir: "/nonexistent".into(),
        }
    }

    /// Zero ports and DNS forwarding loops are rejected before anything starts.
    #[test]
    fn validates_listener_settings() {
        assert!(validate(&args("[::]:1", "[::]:2", "127.0.0.53:53")).is_ok());
        assert!(matches!(
            validate(&args("[::]:0", "[::]:2", "127.0.0.53:53")),
            Err(ServeError::ZeroPort)
        ));
        assert!(matches!(
            validate(&args("[::]:1", "127.0.0.1:2", "127.0.0.1:2")),
            Err(ServeError::DnsLoop)
        ));
    }

    /// The first finished task is reported by name; a clean return is still a failure.
    #[tokio::test]
    async fn reports_the_first_finished_task_by_name() {
        let mut supervisor = Supervisor::new();
        supervisor.spawn("forever", std::future::pending());
        supervisor.spawn("returns", async { Ok(()) });
        let error = supervisor.next_failure().await;
        assert_eq!(error.to_string(), "returns task exited unexpectedly");
        supervisor.spawn("fails", async {
            Err(TaskFailure::Proxy(ProxyError::Accept(io::Error::other("boom"))))
        });
        let error = supervisor.next_failure().await;
        assert_eq!(
            ErrorChain(&error).to_string(),
            "fails task failed: accept proxy connection: boom"
        );
        supervisor.shutdown().await;
        assert!(supervisor.tasks.is_empty());
    }

    /// Build a reloader handle whose reloader is never run.
    fn idle_reload(directory: &std::path::Path) -> (Reloader, ReloadHandle) {
        let store = Arc::new(PolicyStore::new(Policy::new(Default::default(), Default::default())));
        Reloader::new(directory.join("c"), directory.join("r"), store, None)
    }

    /// A failed access-log actor fails the service; a clean exit is also unexpected.
    #[tokio::test]
    async fn access_log_exit_fails_the_service() {
        let mut supervisor = Supervisor::new();
        supervisor.spawn("forever", std::future::pending());
        let (_events, receiver) = tokio::sync::mpsc::channel(1);
        let mut signals = Signals::Injected(receiver);
        let directory = tempfile::tempdir().unwrap();
        let (_reloader, reload) = idle_reload(directory.path());
        let mut access_log: Option<AccessLogTask> = Some(tokio::spawn(async { Ok(()) }));
        let result = supervise(&mut supervisor, &mut access_log, &mut signals, &reload).await;
        assert!(matches!(result, Err(ServeError::AccessLogExited)));
        assert!(access_log.is_none());
        supervisor.shutdown().await;
    }

    /// SIGHUP requests a policy reload; SIGTERM/SIGINT stop successfully.
    #[tokio::test]
    async fn signals_reload_or_stop() {
        let mut supervisor = Supervisor::new();
        supervisor.spawn("forever", std::future::pending());
        let (events, receiver) = tokio::sync::mpsc::channel(2);
        let mut signals = Signals::Injected(receiver);
        let directory = tempfile::tempdir().unwrap();
        let (mut reloader, reload) = idle_reload(directory.path());
        let mut access_log: Option<AccessLogTask> = Some(tokio::spawn(std::future::pending()));
        events.send(SignalEvent::Hangup).await.unwrap();
        events.send(SignalEvent::Stop).await.unwrap();
        let result = supervise(&mut supervisor, &mut access_log, &mut signals, &reload).await;
        assert!(result.is_ok());
        let (trigger, _) = reloader.step().await.unwrap();
        assert_eq!(trigger, crate::runtime::Trigger::Hangup);
        supervisor.shutdown().await;
    }
}
