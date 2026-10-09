//! The single task that publishes new policies.
//!
//! Rule-file notifications, SIGHUP, and UI saves all funnel into one
//! [`Reloader`], so policy updates are serialized and none can overwrite
//! another with stale settings.

use super::{
    store::PolicyStore,
    watcher::{RulesWatcher, WatchError},
};
use crate::{
    config::{Config, ConfigError},
    error::ErrorChain,
    policy::{LoadError, MissingDirectory, Policy, RuleSet, load_rules},
};
use std::{path::PathBuf, sync::Arc};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

/// Pending requests accepted before senders must wait.
const REQUEST_CAPACITY: usize = 16;

/// A rejected reload; the previous policy stays active.
#[derive(Debug, Error)]
pub enum ReloadError {
    /// The rules directory could not be loaded.
    #[error("load rules")]
    Rules(#[from] LoadError),
    /// The configuration file could not be loaded.
    #[error("load configuration")]
    Config(#[from] ConfigError),
    /// A newly enabled rules watcher could not be created.
    #[error("enable rules watcher")]
    Watcher(#[from] WatchError),
    /// The blocking load task failed.
    #[error("reload task failed")]
    Task(#[from] tokio::task::JoinError),
    /// The reloader is no longer running.
    #[error("policy reloader is unavailable")]
    Unavailable,
}

/// The number of published rules, or the shared reason the reload was rejected.
pub type ReloadResult = Result<usize, Arc<ReloadError>>;

/// Why a reload happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The rules watcher observed a change.
    Watcher,
    /// A UI save asked for the rules to be reloaded.
    Request,
    /// SIGHUP asked for configuration and rules to be reloaded.
    Hangup,
}

/// A message to the reloader.
enum ReloadRequest {
    /// Reload the rules directory and report the new rule count.
    Rules {
        /// Receives the reload result.
        reply: oneshot::Sender<ReloadResult>,
    },
    /// Reload configuration and rules together (SIGHUP).
    Policy,
}

/// A cloneable way to ask the reloader for work.
#[derive(Clone)]
pub struct ReloadHandle {
    /// The reloader's request queue.
    sender: mpsc::Sender<ReloadRequest>,
}

impl ReloadHandle {
    /// Reload every rule file and wait until the result is published or rejected.
    pub async fn reload_rules(&self) -> ReloadResult {
        let (reply, response) = oneshot::channel();
        let request = ReloadRequest::Rules {
            reply,
        };
        if self.sender.send(request).await.is_err() {
            return Err(Arc::new(ReloadError::Unavailable));
        }
        response.await.unwrap_or_else(|_| Err(Arc::new(ReloadError::Unavailable)))
    }

    /// Ask for a full configuration and rules reload without waiting for it.
    pub fn request_policy_reload(&self) {
        if self.sender.try_send(ReloadRequest::Policy).is_err() {
            tracing::warn!("policy reload already pending or reloader unavailable");
        }
    }
}

/// Owns the rules watcher and applies every reload in order.
pub struct Reloader {
    /// Configuration file reread on SIGHUP.
    config_path: PathBuf,
    /// Rules directory reread on every reload.
    rules_dir: PathBuf,
    /// The published policy.
    store: Arc<PolicyStore>,
    /// The active watcher when `watch_rules` is enabled.
    watcher: Option<RulesWatcher>,
    /// Requests from UI saves and signals.
    requests: mpsc::Receiver<ReloadRequest>,
}

impl Reloader {
    /// Create a reloader and the handle used to send it requests.
    pub fn new(
        config_path: PathBuf,
        rules_dir: PathBuf,
        store: Arc<PolicyStore>,
        watcher: Option<RulesWatcher>,
    ) -> (Self, ReloadHandle) {
        let (sender, requests) = mpsc::channel(REQUEST_CAPACITY);
        let reloader = Self {
            config_path,
            rules_dir,
            store,
            watcher,
            requests,
        };
        (
            reloader,
            ReloadHandle {
                sender,
            },
        )
    }

    /// Handle triggers until every handle has been dropped.
    pub async fn run(mut self) {
        while self.step().await.is_some() {}
    }

    /// Wait for one trigger, apply it, and report what happened; `None` means shut down.
    pub async fn step(&mut self) -> Option<(Trigger, ReloadResult)> {
        let watcher = self.watcher.as_mut();
        let request = tokio::select! {
            request = self.requests.recv() => Some(request?),
            () = changed(watcher) => None,
        };
        let Some(request) = request else {
            let result = self.reload_rules().await.map_err(Arc::new);
            log_rules_result(&result, "automatically reloaded rules");
            return Some((Trigger::Watcher, result));
        };
        match request {
            ReloadRequest::Rules {
                reply,
            } => {
                let result = self.reload_rules().await.map_err(Arc::new);
                log_rules_result(&result, "reloaded rules after UI edit");
                // The requester may have gone away; the policy is published either way.
                let _ = reply.send(result.clone());
                Some((Trigger::Request, result))
            }
            ReloadRequest::Policy => {
                let result = self.reload_policy().await.map_err(Arc::new);
                match &result {
                    Ok(count) => tracing::info!(
                        rules = count,
                        "reloaded policy; restart service to apply firewall/resolver/log-level/access-log/UI changes"
                    ),
                    Err(error) => tracing::error!(
                        error = %ErrorChain(error.as_ref()),
                        "reload rejected; keeping previous policy"
                    ),
                }
                Some((Trigger::Hangup, result))
            }
        }
    }

    /// Load the complete rules directory and publish it with the current settings.
    async fn reload_rules(&self) -> Result<usize, ReloadError> {
        let rules = self.load_rules().await?;
        let count = rules.len();
        self.store.replace_rules(rules);
        Ok(count)
    }

    /// Load configuration and rules, update the watcher, and publish both together.
    async fn reload_policy(&mut self) -> Result<usize, ReloadError> {
        let config_path = self.config_path.clone();
        let config = tokio::task::spawn_blocking(move || Config::load(&config_path)).await??;
        let rules = self.load_rules().await?;
        if !config.runtime.watch_rules {
            self.watcher = None;
        } else if self.watcher.is_none() {
            self.watcher = Some(RulesWatcher::new(&self.rules_dir)?);
        }
        let count = rules.len();
        self.store.replace(Policy::new(config.runtime, rules));
        Ok(count)
    }

    /// Load rules off the async runtime, rejecting a missing directory.
    async fn load_rules(&self) -> Result<RuleSet, ReloadError> {
        let rules_dir = self.rules_dir.clone();
        let rules =
            tokio::task::spawn_blocking(move || load_rules(&rules_dir, MissingDirectory::Reject))
                .await??;
        Ok(rules)
    }
}

/// Wait for a watcher change, or forever when watching is disabled.
async fn changed(watcher: Option<&mut RulesWatcher>) {
    match watcher {
        Some(watcher) => watcher.changed().await,
        None => std::future::pending().await,
    }
}

/// Log the outcome of a rules-only reload.
fn log_rules_result(result: &ReloadResult, success: &'static str) {
    match result {
        Ok(count) => tracing::info!(rules = count, "{success}"),
        Err(error) => tracing::error!(
            error = %ErrorChain(error.as_ref()),
            "rule reload rejected; keeping previous policy"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::RuntimeSettings, policy::Host};
    use std::{fs, path::Path, time::Duration};

    /// Create a reloader over `directory`, optionally watching it.
    fn reloader(
        config: &Path,
        directory: &Path,
        watch: bool,
    ) -> (Reloader, ReloadHandle, Arc<PolicyStore>) {
        let rules = load_rules(directory, MissingDirectory::Empty).unwrap();
        let store = Arc::new(PolicyStore::new(Policy::new(RuntimeSettings::default(), rules)));
        let watcher = watch.then(|| RulesWatcher::new(directory).unwrap());
        let (reloader, handle) =
            Reloader::new(config.to_owned(), directory.to_owned(), store.clone(), watcher);
        (reloader, handle, store)
    }

    /// Wait for and apply the next trigger within a bounded time.
    async fn next(reloader: &mut Reloader) -> (Trigger, ReloadResult) {
        tokio::time::timeout(Duration::from_secs(5), reloader.step()).await.unwrap().unwrap()
    }

    /// Report whether the active rules authorize DNS for `host`.
    fn allows(store: &PolicyStore, host: &str) -> bool {
        store.load().rules.dns_rule(&Host::new(host)).is_some()
    }

    /// Exercise edits, invalid input, recovery, atomic saves, additions, and deletion.
    #[tokio::test]
    async fn watches_changes_and_retains_last_valid_rules() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("rules");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("allow.toml");
        fs::write(&file, "[[allow]]\ndomain = 'original.test'\n").unwrap();
        let config = temporary.path().join("config.toml");
        let (mut reloader, _handle, store) = reloader(&config, &directory, true);
        let original = store.snapshot();

        fs::write(&file, "[[allow]]\ndomain_regex = '['\n").unwrap();
        let (trigger, result) = next(&mut reloader).await;
        assert_eq!(trigger, Trigger::Watcher);
        assert!(result.is_err());
        assert!(Arc::ptr_eq(&original, &store.snapshot()));

        fs::write(&file, "[[allow]]\ndomain = 'updated.test'\n").unwrap();
        next(&mut reloader).await.1.unwrap();
        assert!(allows(&store, "updated.test"));
        assert!(!allows(&store, "original.test"));
        assert_eq!(store.load().runtime, original.runtime);

        let replacement = directory.join("save.tmp");
        fs::write(&replacement, "[[allow]]\ndomain = 'renamed.test'\n").unwrap();
        fs::rename(&replacement, &file).unwrap();
        next(&mut reloader).await.1.unwrap();
        assert!(allows(&store, "renamed.test"));

        let extra = directory.join("extra.toml");
        fs::write(&extra, "[[allow]]\ndomain = 'extra.test'\n").unwrap();
        assert_eq!(next(&mut reloader).await.1.unwrap(), 2);
        fs::remove_file(&extra).unwrap();
        assert_eq!(next(&mut reloader).await.1.unwrap(), 1);

        let previous = store.snapshot();
        fs::remove_dir_all(&directory).unwrap();
        assert!(next(&mut reloader).await.1.is_err());
        assert!(Arc::ptr_eq(&previous, &store.snapshot()));
        fs::create_dir(&directory).unwrap();
        fs::write(&file, "[[allow]]\ndomain = 'recreated.test'\n").unwrap();
        next(&mut reloader).await.1.unwrap();
        assert!(allows(&store, "recreated.test"));

        fs::remove_file(&file).unwrap();
        assert_eq!(next(&mut reloader).await.1.unwrap(), 0);
    }

    /// Begin with an absent rules directory and observe its first complete ruleset.
    #[tokio::test]
    async fn watches_initially_missing_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("rules");
        let config = temporary.path().join("config.toml");
        let (mut reloader, _handle, store) = reloader(&config, &directory, true);
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("allow.toml"), "[[allow]]\ndomain = 'created.test'\n").unwrap();
        next(&mut reloader).await.1.unwrap();
        assert!(allows(&store, "created.test"));
    }

    /// UI requests reload synchronously and report rejection without publishing.
    #[tokio::test]
    async fn requested_reloads_reply_with_their_result() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().to_owned();
        let config = temporary.path().join("config.toml");
        let (reloader, handle, store) = reloader(&config, &directory, false);
        let task = tokio::spawn(reloader.run());
        fs::write(directory.join("a.toml"), "[[allow]]\ndomain = 'ui.test'\n").unwrap();
        assert_eq!(handle.reload_rules().await.unwrap(), 1);
        assert!(allows(&store, "ui.test"));
        let before = store.snapshot();
        fs::write(directory.join("b.toml"), "[[allow]]\nunknown = 1\n").unwrap();
        let error = handle.reload_rules().await.unwrap_err();
        assert!(matches!(*error, ReloadError::Rules(_)));
        assert!(Arc::ptr_eq(&before, &store.snapshot()));
        drop(handle);
        task.await.unwrap();
    }

    /// SIGHUP republishes settings and toggles the watcher on and off.
    #[tokio::test]
    async fn policy_reloads_apply_settings_and_toggle_watching() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("rules");
        fs::create_dir(&directory).unwrap();
        let config = temporary.path().join("config.toml");
        let (mut reloader, handle, store) = reloader(&config, &directory, true);

        fs::write(&config, "watch_rules = false\nblock_dns = false\n").unwrap();
        handle.request_policy_reload();
        let (trigger, result) = next(&mut reloader).await;
        assert_eq!(trigger, Trigger::Hangup);
        result.unwrap();
        assert!(!store.load().runtime.block_dns);
        assert!(reloader.watcher.is_none());

        fs::write(&config, "not valid TOML").unwrap();
        let before = store.snapshot();
        handle.request_policy_reload();
        let error = next(&mut reloader).await.1.unwrap_err();
        assert!(matches!(*error, ReloadError::Config(_)));
        assert!(Arc::ptr_eq(&before, &store.snapshot()));

        fs::write(&config, "watch_rules = true\n").unwrap();
        handle.request_policy_reload();
        next(&mut reloader).await.1.unwrap();
        assert!(store.load().runtime.block_dns);
        assert!(reloader.watcher.is_some());
        fs::write(directory.join("a.toml"), "[[allow]]\ndomain = 'watched.test'\n").unwrap();
        assert_eq!(next(&mut reloader).await.0, Trigger::Watcher);
        assert!(allows(&store, "watched.test"));
    }
}
