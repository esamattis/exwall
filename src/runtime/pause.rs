//! A temporary, self-expiring pause of rule-based blocking.

use crate::policy::Enforcement;
use std::{sync::Mutex, time::Duration};
use tokio::time::Instant;

/// When blocking resumes, if it is paused.
///
/// The deadline is compared on every check rather than cleared by a timer, so
/// blocking resumes exactly when the pause ends even if no task runs then.
#[derive(Debug, Default)]
pub struct BlockingPause {
    /// The monotonic instant at which blocking resumes; `None` when not paused.
    until: Mutex<Option<Instant>>,
}

impl BlockingPause {
    /// Pause blocking for `duration` from now, replacing any earlier pause.
    pub fn pause(&self, duration: Duration) {
        *self.lock() = Some(Instant::now() + duration);
    }

    /// End the pause immediately, reporting whether one was active.
    pub fn resume(&self) -> bool {
        let previous = self.lock().take();
        previous.is_some_and(|until| until > Instant::now())
    }

    /// How long blocking stays paused; `None` when it is enforced.
    pub fn remaining(&self) -> Option<Duration> {
        let until = (*self.lock())?;
        let remaining = until.saturating_duration_since(Instant::now());
        (!remaining.is_zero()).then_some(remaining)
    }

    /// Whether requests no rule allows are currently denied.
    pub fn enforcement(&self) -> Enforcement {
        if self.remaining().is_some() {
            Enforcement::Paused
        } else {
            Enforcement::Enforced
        }
    }

    /// Lock the deadline, recovering it if a holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        self.until.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pause lifts enforcement until its deadline and then expires on its own.
    #[tokio::test(start_paused = true)]
    async fn pause_expires_after_its_duration() {
        let pause = BlockingPause::default();
        assert_eq!(pause.enforcement(), Enforcement::Enforced);
        assert_eq!(pause.remaining(), None);
        pause.pause(Duration::from_secs(300));
        assert_eq!(pause.enforcement(), Enforcement::Paused);
        tokio::time::advance(Duration::from_secs(299)).await;
        assert_eq!(pause.remaining(), Some(Duration::from_secs(1)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(pause.enforcement(), Enforcement::Enforced);
        assert_eq!(pause.remaining(), None);
        assert!(!pause.resume());
    }

    /// Resuming ends an active pause, and a new pause replaces the previous deadline.
    #[tokio::test(start_paused = true)]
    async fn resume_and_repause() {
        let pause = BlockingPause::default();
        pause.pause(Duration::from_secs(600));
        pause.pause(Duration::from_secs(60));
        assert_eq!(pause.remaining(), Some(Duration::from_secs(60)));
        assert!(pause.resume());
        assert_eq!(pause.enforcement(), Enforcement::Enforced);
        assert!(!pause.resume());
    }
}
