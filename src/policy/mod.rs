//! Pure policy: hostnames, allow rules, and typed authorization decisions.

mod decision;
mod host;
mod loader;
mod methods;
pub mod path_safety;
pub mod pathname;
mod rules;

pub use decision::{Decision, DnsDecision, Enforcement, LocalHostname, MatchSource};
pub use host::Host;
pub use loader::{LoadError, MissingDirectory, load_rules};
pub use methods::MethodSet;
pub use rules::{Rule, RuleError, RuleFileError, RuleId, RuleSet};

use crate::config::RuntimeSettings;
use std::sync::Arc;

/// One atomic snapshot of reloadable settings and compiled allow rules.
#[derive(Clone)]
pub struct Policy {
    /// Settings republished on SIGHUP.
    pub runtime: RuntimeSettings,
    /// The complete ruleset from every rule file.
    pub rules: Arc<RuleSet>,
}

impl Policy {
    /// Combine settings and rules into a publishable snapshot.
    pub fn new(runtime: RuntimeSettings, rules: RuleSet) -> Self {
        Self {
            runtime,
            rules: Arc::new(rules),
        }
    }

    /// Authorize each DNS question by hostname, ignoring HTTP method and path constraints.
    ///
    /// While blocking is paused, questions that nothing else authorizes are allowed as
    /// [`MatchSource::Paused`].
    pub fn dns_decision(
        &self,
        questions: &[Host],
        local: &LocalHostname,
        enforcement: Enforcement,
    ) -> DnsDecision {
        let matches = questions
            .iter()
            .map(|host| {
                if !self.runtime.block_dns {
                    Some(MatchSource::DnsBypass)
                } else if let Some(rule) = self.rules.dns_rule(host) {
                    Some(MatchSource::Rule(rule.id().clone()))
                } else if local.matches(host) {
                    Some(MatchSource::LocalHostname)
                } else if enforcement == Enforcement::Paused {
                    Some(MatchSource::Paused)
                } else {
                    None
                }
            })
            .collect();
        DnsDecision {
            matches,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a policy from rule text and the DNS enforcement flag.
    fn policy(text: &str, block_dns: bool) -> Policy {
        let runtime = RuntimeSettings {
            block_dns,
            ..RuntimeSettings::default()
        };
        Policy::new(runtime, RuleSet::parse(text, "test").unwrap())
    }

    /// DNS uses hostname-only rules, checks every question, and honours exceptions.
    #[test]
    fn dns_decisions_cover_rules_exceptions_and_bypass() {
        let enforced = policy(
            "[[allow]]\ndomain='allowed.test'\nmethods=['POST']\npathname_pattern='/only'",
            true,
        );
        let local = LocalHostname::new(Host::new("box"));
        let questions = [Host::new("allowed.test"), Host::new("denied.test"), Host::new("BOX.")];
        let decision = enforced.dns_decision(&questions, &local, Enforcement::Enforced);
        assert_eq!(
            decision.matches,
            vec![
                Some(MatchSource::Rule(RuleId::new("test", 1))),
                None,
                Some(MatchSource::LocalHostname),
            ]
        );
        assert!(!decision.allowed());
        assert!(enforced.dns_decision(&questions[..1], &local, Enforcement::Enforced).allowed());
        let bypass = policy("", false);
        let decision = bypass.dns_decision(&questions, &local, Enforcement::Paused);
        assert!(decision.allowed());
        assert!(decision.matches.iter().all(|m| m == &Some(MatchSource::DnsBypass)));
    }

    /// A pause allows only the questions that rules and exceptions would deny.
    #[test]
    fn paused_dns_allows_unmatched_questions() {
        let enforced = policy("[[allow]]\ndomain='allowed.test'", true);
        let local = LocalHostname::new(Host::new("box"));
        let questions = [Host::new("allowed.test"), Host::new("denied.test"), Host::new("box")];
        let decision = enforced.dns_decision(&questions, &local, Enforcement::Paused);
        assert!(decision.allowed());
        assert_eq!(
            decision.matches,
            vec![
                Some(MatchSource::Rule(RuleId::new("test", 1))),
                Some(MatchSource::Paused),
                Some(MatchSource::LocalHostname),
            ]
        );
    }
}
