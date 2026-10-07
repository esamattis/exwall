//! Filesystem notifications and atomic replacement of validated allow rules.

use crate::{
    error::{Context, Result},
    rules::RuleSet,
    state::{Policy, SharedPolicy},
};
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{path::Path, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::mpsc;

/// A live directory watch with a bounded queue of pending rule changes.
pub struct RulesWatcher {
    directory: PathBuf,
    /// Retain and refresh native watches across directory replacement.
    watcher: RecommendedWatcher,
    changes: mpsc::Receiver<()>,
    /// Preserve pending reloads when another service event cancels the wait future.
    reload_at: Option<tokio::time::Instant>,
}

impl RulesWatcher {
    /// Watch the nearest existing parent so directory creation and replacement are observed.
    pub fn new(directory: &Path) -> Result<Self> {
        let directory = std::path::absolute(directory)?;
        let (sender, changes) = mpsc::channel(1);
        let watched_directory = directory.clone();
        let watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
            match result {
                Ok(event) if affects_rules(&event, &watched_directory) => {
                    // A full queue already guarantees a reload of the latest disk contents.
                    let _ = sender.try_send(());
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "rules watcher failed; keeping previous policy");
                }
            }
        })?;
        let mut watcher = Self {
            directory,
            watcher,
            changes,
            reload_at: None,
        };
        watcher.refresh_watches()?;
        Ok(watcher)
    }

    /// Watch immediate files and the nearest parent without traversing unrelated directories.
    fn refresh_watches(&mut self) -> Result<()> {
        let parent = self
            .directory
            .ancestors()
            .skip(1)
            .find(|ancestor| ancestor.is_dir())
            .context("rules directory has no existing parent")?;
        self.watcher.watch(parent, RecursiveMode::NonRecursive)?;
        if self.directory.is_dir() {
            self.watcher.watch(&self.directory, RecursiveMode::NonRecursive)?;
        }
        Ok(())
    }

    /// Coalesce save events briefly before requesting a reload, ignoring read notifications.
    pub async fn changed(&mut self) {
        let deadline = match self.reload_at {
            Some(deadline) => deadline,
            None => {
                if self.changes.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
                let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
                self.reload_at = Some(deadline);
                deadline
            }
        };
        tokio::time::sleep_until(deadline).await;
        self.reload_at = None;
        while self.changes.try_recv().is_ok() {}
        if let Err(error) = self.refresh_watches() {
            tracing::error!(%error, "could not refresh rules watcher; keeping previous watches");
        }
    }

    /// Publish all validated rules together while retaining the current runtime configuration.
    pub fn reload(&self, policy: &SharedPolicy) -> Result<()> {
        let rules = RuleSet::load_existing(&self.directory)?;
        let current = policy.load_full();
        policy.store(Arc::new(Policy {
            config: current.config.clone(),
            rules,
        }));
        Ok(())
    }
}

/// Recognize mutations of the rules directory, its ancestors, or immediate TOML files.
fn affects_rules(event: &Event, directory: &Path) -> bool {
    if event.kind.is_access() {
        return false;
    }
    event.need_rescan()
        || event.paths.iter().any(|path| {
            directory.starts_with(path)
                || (path.parent() == Some(directory)
                    && path.extension().is_some_and(|extension| extension == "toml"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::fs;

    /// Wait for a real notification and apply its complete ruleset within a bounded time.
    async fn reload_change(watcher: &mut RulesWatcher, policy: &SharedPolicy) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5), watcher.changed()).await.unwrap();
        watcher.reload(policy)
    }

    /// Exercise edits, invalid input, recovery, atomic saves, additions, and deletion.
    #[tokio::test]
    async fn watches_changes_and_retains_last_valid_rules() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("rules");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("allow.toml");
        fs::write(&file, "[[allow]]\ndomain = 'original.test'\n").unwrap();
        let mut watcher = RulesWatcher::new(&directory).unwrap();
        let policy = Arc::new(arc_swap::ArcSwap::from_pointee(Policy {
            config: Config::default(),
            rules: RuleSet::load(&directory).unwrap(),
        }));
        let original = policy.load_full();

        fs::write(&file, "[[allow]]\ndomain_regex = '['\n").unwrap();
        assert!(reload_change(&mut watcher, &policy).await.is_err());
        assert!(Arc::ptr_eq(&original, &policy.load_full()));

        fs::write(&file, "[[allow]]\ndomain = 'updated.test'\n").unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert!(policy.load().rules.dns_rule("updated.test").is_some());
        assert!(policy.load().rules.dns_rule("original.test").is_none());
        assert_eq!(policy.load().config.block_dns, original.config.block_dns);

        let replacement = directory.join("save.tmp");
        fs::write(&replacement, "[[allow]]\ndomain = 'renamed.test'\n").unwrap();
        fs::rename(&replacement, &file).unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert!(policy.load().rules.dns_rule("renamed.test").is_some());

        let extra = directory.join("extra.toml");
        fs::write(&extra, "[[allow]]\ndomain = 'extra.test'\n").unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert_eq!(policy.load().rules.rules.len(), 2);
        fs::remove_file(&extra).unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert_eq!(policy.load().rules.rules.len(), 1);

        let previous = policy.load_full();
        fs::remove_dir_all(&directory).unwrap();
        assert!(reload_change(&mut watcher, &policy).await.is_err());
        assert!(Arc::ptr_eq(&previous, &policy.load_full()));
        fs::create_dir(&directory).unwrap();
        fs::write(&file, "[[allow]]\ndomain = 'recreated.test'\n").unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert!(policy.load().rules.dns_rule("recreated.test").is_some());

        fs::remove_file(&file).unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert!(policy.load().rules.rules.is_empty());
    }

    /// Begin with an absent rules directory and observe its first complete ruleset.
    #[tokio::test]
    async fn watches_initially_missing_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("rules");
        let mut watcher = RulesWatcher::new(&directory).unwrap();
        let policy = Arc::new(arc_swap::ArcSwap::from_pointee(Policy {
            config: Config::default(),
            rules: RuleSet::load(&directory).unwrap(),
        }));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("allow.toml"), "[[allow]]\ndomain = 'created.test'\n").unwrap();
        reload_change(&mut watcher, &policy).await.unwrap();
        assert!(policy.load().rules.dns_rule("created.test").is_some());
    }
}
