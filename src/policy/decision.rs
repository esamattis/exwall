//! Typed policy decisions shared by request handlers and telemetry.

use super::{host::Host, rules::RuleId};
use std::fmt;

/// The policy outcome, independent of the response or subsequent processing failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// A matching rule or configured exception authorizes the request.
    Allow,
    /// The policy rejects the request.
    Deny,
    /// The request was not evaluated against policy.
    Unevaluated,
}

impl Decision {
    /// Convert a boolean authorization result.
    pub fn from_allowed(allowed: bool) -> Self {
        if allowed {
            Self::Allow
        } else {
            Self::Deny
        }
    }
}

/// What authorized a request or one DNS question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchSource {
    /// A configured allow rule.
    Rule(RuleId),
    /// `block_dns = false` lets every DNS question through.
    DnsBypass,
    /// The host's own name is always resolvable.
    LocalHostname,
}

impl fmt::Display for MatchSource {
    /// Render the access-log rule label.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule(id) => id.fmt(formatter),
            Self::DnsBypass => formatter.write_str("@dns-bypass"),
            Self::LocalHostname => formatter.write_str("@local-hostname"),
        }
    }
}

/// The authorization of every question in one DNS query message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsDecision {
    /// What matched each question, in question order; `None` marks a denied question.
    pub matches: Vec<Option<MatchSource>>,
}

impl DnsDecision {
    /// A message is answered only when every question is authorized.
    pub fn allowed(&self) -> bool {
        !self.matches.is_empty() && self.matches.iter().all(Option::is_some)
    }
}

/// The local hostname exception used by DNS decisions, captured once at startup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalHostname(Option<Host>);

impl LocalHostname {
    /// Use a known hostname; an empty name disables the exception.
    pub fn new(host: Host) -> Self {
        if host.is_empty() {
            Self(None)
        } else {
            Self(Some(host))
        }
    }

    /// Read the kernel hostname, disabling the exception if it is unavailable.
    pub fn from_system() -> Self {
        match std::fs::read_to_string("/proc/sys/kernel/hostname") {
            Ok(name) => Self::new(Host::new(&name)),
            Err(error) => {
                tracing::warn!(%error, "cannot read the local hostname; its DNS exception is disabled");
                Self(None)
            }
        }
    }

    /// Report whether `host` is the local hostname.
    pub fn matches(&self, host: &Host) -> bool {
        self.0.as_ref() == Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Labels match the access-log vocabulary.
    #[test]
    fn renders_match_labels() {
        assert_eq!(MatchSource::Rule(RuleId::new("a.toml", 3)).to_string(), "a.toml:allow#3");
        assert_eq!(MatchSource::DnsBypass.to_string(), "@dns-bypass");
        assert_eq!(MatchSource::LocalHostname.to_string(), "@local-hostname");
    }

    /// An empty hostname never authorizes root or empty queries.
    #[test]
    fn empty_local_hostname_matches_nothing() {
        let local = LocalHostname::new(Host::new(""));
        assert!(!local.matches(&Host::new(".")));
        let local = LocalHostname::new(Host::new("Box."));
        assert!(local.matches(&Host::new("box")));
    }

    /// Messages without questions or with any denied question are denied.
    #[test]
    fn dns_decision_requires_every_question() {
        assert!(
            !DnsDecision {
                matches: vec![]
            }
            .allowed()
        );
        assert!(
            !DnsDecision {
                matches: vec![Some(MatchSource::DnsBypass), None]
            }
            .allowed()
        );
        assert!(
            DnsDecision {
                matches: vec![Some(MatchSource::DnsBypass)]
            }
            .allowed()
        );
    }
}
