//! The atomically published policy read by every request handler.

use super::BlockingPause;
use crate::policy::{Enforcement, Policy, RuleSet};
use arc_swap::{ArcSwap, Guard};
use std::sync::Arc;

/// Lock-free storage for the active policy snapshot and the blocking pause.
pub struct PolicyStore {
    /// The current snapshot.
    current: ArcSwap<Policy>,
    /// A temporary pause of blocking, kept across policy reloads.
    pause: BlockingPause,
}

impl PolicyStore {
    /// Publish an initial policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            current: ArcSwap::from_pointee(policy),
            pause: BlockingPause::default(),
        }
    }

    /// The temporary pause of blocking.
    pub fn pause(&self) -> &BlockingPause {
        &self.pause
    }

    /// Whether requests no rule allows are currently denied.
    pub fn enforcement(&self) -> Enforcement {
        self.pause.enforcement()
    }

    /// Borrow the current snapshot cheaply for one request.
    pub fn load(&self) -> Guard<Arc<Policy>> {
        self.current.load()
    }

    /// Return an owned reference to the current snapshot.
    pub fn snapshot(&self) -> Arc<Policy> {
        self.current.load_full()
    }

    /// Replace only the rules, atomically preserving the current runtime settings.
    pub fn replace_rules(&self, rules: RuleSet) {
        let rules = Arc::new(rules);
        self.current.rcu(|current| Policy {
            runtime: current.runtime,
            rules: rules.clone(),
        });
    }

    /// Replace both runtime settings and rules.
    pub fn replace(&self, policy: Policy) {
        self.current.store(Arc::new(policy));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::RuntimeSettings, policy::Host};

    /// Rule-only updates keep settings published by a concurrent full reload.
    #[test]
    fn rule_updates_preserve_runtime_settings() {
        let store = PolicyStore::new(Policy::new(RuntimeSettings::default(), RuleSet::default()));
        let settings = RuntimeSettings {
            block_dns: false,
            watch_rules: false,
        };
        store.replace(Policy::new(settings, RuleSet::default()));
        store.replace_rules(RuleSet::parse("[[allow]]\ndomain = 'new.test'\n", "t").unwrap());
        let policy = store.snapshot();
        assert_eq!(policy.runtime, settings);
        assert!(policy.rules.dns_rule(&Host::new("new.test")).is_some());
    }
}
