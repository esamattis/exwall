//! Filesystem notifications for the rules directory, coalesced into reload requests.

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::sync::mpsc;

/// How long save events are coalesced before a reload.
const DEBOUNCE: Duration = Duration::from_millis(100);

/// A rules watcher that could not be created or refreshed.
#[derive(Debug, Error)]
pub enum WatchError {
    /// The rules directory path could not be made absolute.
    #[error("resolve rules directory {}", path.display())]
    Resolve {
        /// The configured rules directory.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// No ancestor of the rules directory exists.
    #[error("rules directory {} has no existing parent", path.display())]
    NoParent {
        /// The configured rules directory.
        path: PathBuf,
    },
    /// The notification backend failed.
    #[error("watch rules directory")]
    Notify(#[from] notify::Error),
}

/// A live directory watch with a bounded queue of pending rule changes.
pub struct RulesWatcher {
    /// The absolute rules directory.
    directory: PathBuf,
    /// Retain and refresh native watches across directory replacement.
    watcher: RecommendedWatcher,
    /// Change notifications from the backend thread.
    changes: mpsc::Receiver<()>,
    /// Preserve pending reloads when another event cancels the wait future.
    reload_at: Option<tokio::time::Instant>,
}

impl RulesWatcher {
    /// Watch the nearest existing parent so directory creation and replacement are observed.
    pub fn new(directory: &Path) -> Result<Self, WatchError> {
        let directory = std::path::absolute(directory).map_err(|source| WatchError::Resolve {
            path: directory.to_owned(),
            source,
        })?;
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
    fn refresh_watches(&mut self) -> Result<(), WatchError> {
        let parent =
            self.directory.ancestors().skip(1).find(|ancestor| ancestor.is_dir()).ok_or_else(
                || WatchError::NoParent {
                    path: self.directory.clone(),
                },
            )?;
        self.watcher.watch(parent, RecursiveMode::NonRecursive)?;
        if self.directory.is_dir() {
            self.watcher.watch(&self.directory, RecursiveMode::NonRecursive)?;
        }
        Ok(())
    }

    /// Wait for a change, then coalesce save events briefly before returning.
    ///
    /// The method is cancellation-safe: a pending debounce deadline survives
    /// when the future is dropped by a `select!`.
    pub async fn changed(&mut self) {
        let deadline = match self.reload_at {
            Some(deadline) => deadline,
            None => {
                if self.changes.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
                let deadline = tokio::time::Instant::now() + DEBOUNCE;
                self.reload_at = Some(deadline);
                deadline
            }
        };
        tokio::time::sleep_until(deadline).await;
        self.reload_at = None;
        while self.changes.try_recv().is_ok() {}
        if let Err(error) = self.refresh_watches() {
            tracing::error!(
                error = %crate::error::ErrorChain(&error),
                "could not refresh rules watcher; keeping previous watches"
            );
        }
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
    use notify::event::{AccessKind, CreateKind, EventKind};

    /// Only TOML files directly inside the directory, or the directory's ancestors, matter.
    #[test]
    fn filters_relevant_events() {
        let directory = Path::new("/etc/exwall/rules.d");
        let event = |kind, path: &str| Event::new(kind).add_path(PathBuf::from(path));
        let create = EventKind::Create(CreateKind::File);
        assert!(affects_rules(&event(create, "/etc/exwall/rules.d/a.toml"), directory));
        assert!(affects_rules(&event(create, "/etc/exwall/rules.d"), directory));
        assert!(affects_rules(&event(create, "/etc/exwall"), directory));
        assert!(!affects_rules(&event(create, "/etc/exwall/rules.d/a.txt"), directory));
        assert!(!affects_rules(&event(create, "/etc/exwall/rules.d/sub/a.toml"), directory));
        let access = EventKind::Access(AccessKind::Any);
        assert!(!affects_rules(&event(access, "/etc/exwall/rules.d/a.toml"), directory));
    }
}
