//! Bounded domain counters and a bounded, process-local list of HTTP denials.

use super::event::{Protocol, RequestEvent};
use crate::policy::{Decision, Host};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

/// The number of HTTP denials retained for the UI.
const DENIAL_CAPACITY: usize = 100;
/// The number of domains tracked; the least recently updated is evicted first.
const DOMAIN_CAPACITY: usize = 1000;

/// Totals for evaluated requests in one application protocol.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    /// Allowed requests.
    pub allow: u64,
    /// Denied requests.
    pub block: u64,
}

/// The latest aggregate state for one normalized domain.
#[derive(Clone, Debug, Serialize)]
pub struct DomainSummary {
    /// The normalized domain or IP literal.
    pub domain: String,
    /// DNS totals.
    pub dns: Counts,
    /// HTTP and HTTPS totals.
    pub http: Counts,
    /// The latest allow, if any.
    #[serde(serialize_with = "serialize_optional_timestamp")]
    pub last_allowed: Option<jiff::Timestamp>,
    /// The latest denial, if any.
    #[serde(serialize_with = "serialize_optional_timestamp")]
    pub last_denied: Option<jiff::Timestamp>,
    /// The latest outcome of either kind.
    #[serde(serialize_with = "serialize_timestamp")]
    pub last_updated: jiff::Timestamp,
}

/// One denied HTTP or HTTPS request, excluding query strings and CONNECT setup.
#[derive(Clone, Debug, Serialize)]
pub struct HttpDenial {
    /// The normalized request host.
    pub domain: String,
    /// The request method.
    pub method: String,
    /// The query-free pathname.
    pub pathname: String,
    /// When the denial was recorded.
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: jiff::Timestamp,
}

/// A domain summary with its position in update order.
struct TrackedDomain {
    /// The value of [`Domains::next_update`] when this domain last changed.
    updated: u64,
    /// The counters reported to the UI.
    summary: DomainSummary,
}

/// Per-domain summaries limited to the most recently updated domains.
#[derive(Default)]
struct Domains {
    /// Summaries keyed by normalized domain.
    entries: BTreeMap<Host, TrackedDomain>,
    /// Update sequence keys, oldest first, pointing back into `entries`.
    order: BTreeMap<u64, Host>,
    /// The sequence number assigned to the next update.
    next_update: u64,
}

impl Domains {
    /// Return a domain's summary marked as just updated, evicting the stalest domain if full.
    fn touch(&mut self, host: &Host, timestamp: jiff::Timestamp) -> &mut DomainSummary {
        let updated = self.next_update;
        self.next_update += 1;
        if let Some(tracked) = self.entries.get_mut(host) {
            self.order.remove(&tracked.updated);
            tracked.updated = updated;
        } else {
            if self.entries.len() >= DOMAIN_CAPACITY
                && let Some((_, stalest)) = self.order.pop_first()
            {
                self.entries.remove(&stalest);
            }
            self.entries.insert(
                host.clone(),
                TrackedDomain {
                    updated,
                    summary: DomainSummary {
                        domain: host.to_string(),
                        dns: Counts::default(),
                        http: Counts::default(),
                        last_allowed: None,
                        last_denied: None,
                        last_updated: timestamp,
                    },
                },
            );
        }
        self.order.insert(updated, host.clone());
        let tracked = self.entries.get_mut(host).expect("domain was just inserted");
        &mut tracked.summary
    }
}

/// Shared process-lifetime counters and bounded denials, independent of log retention.
#[derive(Clone, Default)]
pub struct DomainStats {
    /// Summaries of the most recently updated domains.
    domains: Arc<Mutex<Domains>>,
    /// The newest HTTP denials, oldest first.
    denials: Arc<Mutex<VecDeque<HttpDenial>>>,
}

impl DomainStats {
    /// Update counters and denial history from an evaluated request event.
    pub fn record_event(&self, event: &RequestEvent) {
        let allowed = match event.decision {
            Decision::Allow => true,
            Decision::Deny => false,
            Decision::Unevaluated => return,
        };
        for host in &event.subjects {
            self.record(host, event.protocol, allowed);
        }
        if allowed || event.protocol == Protocol::Dns {
            return;
        }
        if let (Some(host), Some(method), Some(pathname)) =
            (event.subjects.first(), &event.method, &event.pathname)
        {
            self.record_denial(host, method, pathname);
        }
    }

    /// Increment a policy outcome and update its timestamp independently of the other outcome.
    pub fn record(&self, host: &Host, protocol: Protocol, allowed: bool) {
        if host.is_empty() {
            return;
        }
        let timestamp = jiff::Timestamp::now();
        let mut domains = self.domains.lock().expect("domain counter lock poisoned");
        let summary = domains.touch(host, timestamp);
        let counts = match protocol {
            Protocol::Dns => &mut summary.dns,
            Protocol::Http | Protocol::Https => &mut summary.http,
        };
        if allowed {
            counts.allow += 1;
            summary.last_allowed = Some(timestamp);
        } else {
            counts.block += 1;
            summary.last_denied = Some(timestamp);
        }
        summary.last_updated = timestamp;
    }

    /// Retain the latest denied requests without writing request history to disk.
    pub fn record_denial(&self, host: &Host, method: &str, pathname: &str) {
        let mut denials = self.denials.lock().expect("HTTP denial lock poisoned");
        if denials.len() == DENIAL_CAPACITY {
            denials.pop_front();
        }
        denials.push_back(HttpDenial {
            domain: host.to_string(),
            method: method.to_owned(),
            pathname: pathname.to_owned(),
            timestamp: jiff::Timestamp::now(),
        });
    }

    /// Return denied HTTP requests newest first, including repeated requests.
    pub fn denials_snapshot(&self) -> Vec<HttpDenial> {
        let denials = self.denials.lock().expect("HTTP denial lock poisoned");
        denials.iter().rev().cloned().collect()
    }

    /// Return independent snapshots with the most recently updated domain first.
    pub fn snapshot(&self) -> Vec<DomainSummary> {
        let mut domains: Vec<_> = self
            .domains
            .lock()
            .expect("domain counter lock poisoned")
            .entries
            .values()
            .map(|tracked| tracked.summary.clone())
            .collect();
        domains.sort_by(|left, right| {
            right.last_updated.cmp(&left.last_updated).then_with(|| left.domain.cmp(&right.domain))
        });
        domains
    }
}

/// Encode a timestamp as RFC 3339 for API consumers.
fn serialize_timestamp<S: serde::Serializer>(
    timestamp: &jiff::Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(timestamp)
}

/// Encode an optional timestamp as RFC 3339, or null when the outcome never occurred.
fn serialize_optional_timestamp<S: serde::Serializer>(
    timestamp: &Option<jiff::Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    timestamp.map(|value| value.to_string()).serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy::{MatchSource, RuleId},
        telemetry::event::RequestEvent,
    };

    /// Shorthand for a normalized host.
    fn host(name: &str) -> Host {
        Host::new(name)
    }

    /// Keep allow and denial timestamps independent across normalized hosts and protocols.
    #[test]
    fn tracks_outcomes_independently() {
        let stats = DomainStats::default();
        stats.record(&host("Example.COM."), Protocol::Dns, true);
        let allowed = stats.snapshot().remove(0);
        assert_eq!(allowed.last_allowed, Some(allowed.last_updated));
        assert_eq!(allowed.last_denied, None);
        let serialized = serde_json::to_value(&allowed).unwrap();
        assert_eq!(serialized["last_allowed"], allowed.last_updated.to_string());
        assert!(serialized["last_denied"].is_null());

        stats.record(&host("example.com"), Protocol::Https, false);
        let denied = stats.snapshot().remove(0);
        assert_eq!(denied.last_allowed, allowed.last_allowed);
        assert_eq!(denied.last_denied, Some(denied.last_updated));
        stats.record(&host("EXAMPLE.COM"), Protocol::Http, true);
        let latest = stats.snapshot().remove(0);
        assert_eq!(latest.last_denied, denied.last_denied);
        assert_eq!(latest.last_allowed, Some(latest.last_updated));
        assert_eq!(
            latest.dns,
            Counts {
                allow: 1,
                block: 0
            }
        );
        assert_eq!(
            latest.http,
            Counts {
                allow: 1,
                block: 1
            }
        );

        stats.record(&host("denied.test"), Protocol::Dns, false);
        let only_denied = stats.snapshot().remove(0);
        assert_eq!(only_denied.last_allowed, None);
        assert_eq!(only_denied.last_denied, Some(only_denied.last_updated));
    }

    /// Evict only the oldest denials while retaining repeats and immutable snapshots.
    #[test]
    fn retains_only_the_latest_hundred_http_denials() {
        let stats = DomainStats::default();
        for index in 0..105 {
            stats.record_denial(&host("Example.COM."), "POST", &format!("/request/{index}"));
        }
        let snapshot = stats.denials_snapshot();
        assert_eq!(snapshot.len(), 100);
        assert_eq!(snapshot[0].pathname, "/request/104");
        assert_eq!(snapshot[99].pathname, "/request/5");
        assert_eq!(snapshot[0].domain, "example.com");
        stats.record_denial(&host("example.com"), "POST", "/request/104");
        let latest = stats.denials_snapshot();
        assert_eq!(latest.len(), 100);
        assert_eq!(latest[0].pathname, latest[1].pathname);
        assert_eq!(snapshot[99].pathname, "/request/5");
    }

    /// Aggregate normalized hosts, combine HTTP/TLS, and retain only the latest state.
    #[test]
    fn aggregates_protocols_and_orders_latest_updates() {
        let stats = DomainStats::default();
        stats.record(&host("Example.COM."), Protocol::Dns, false);
        stats.record(&host("example.com"), Protocol::Http, true);
        stats.record(&host("example.com"), Protocol::Https, false);
        let first = stats.snapshot();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].dns.block, 1);
        assert_eq!(
            first[0].http,
            Counts {
                allow: 1,
                block: 1
            }
        );
        stats.record(&host("other.test"), Protocol::Dns, true);
        let latest = stats.snapshot();
        assert_eq!(latest[0].domain, "other.test");
        assert_eq!(latest[1].last_updated, first[0].last_updated);
    }

    /// Evict the least recently updated domain once the limit is reached.
    #[test]
    fn evicts_the_stalest_domain_beyond_the_limit() {
        let stats = DomainStats::default();
        for index in 0..DOMAIN_CAPACITY {
            stats.record(&host(&format!("d{index}.test")), Protocol::Dns, true);
        }
        // Refreshing the oldest domain moves it to the back of the eviction order.
        stats.record(&host("d0.test"), Protocol::Http, false);
        stats.record(&host("new.test"), Protocol::Dns, false);
        let domains: std::collections::HashSet<_> =
            stats.snapshot().into_iter().map(|summary| summary.domain).collect();
        assert_eq!(domains.len(), DOMAIN_CAPACITY);
        assert!(domains.contains("d0.test"));
        assert!(domains.contains("new.test"));
        assert!(!domains.contains("d1.test"));
        assert!(domains.contains("d2.test"));
        let inner = stats.domains.lock().unwrap();
        assert_eq!(inner.order.len(), DOMAIN_CAPACITY);
    }

    /// Retain only evaluated HTTP denials, with normalized hosts and query-free pathnames.
    #[test]
    fn tracks_http_denials_without_dns_connect_or_unevaluated_requests() {
        let stats = DomainStats::default();
        let cases = [
            (Protocol::Dns, None, "denied.test", None, Decision::Deny),
            (Protocol::Http, Some("GET"), "test", Some("/allowed"), Decision::Allow),
            (Protocol::Https, Some("POST"), "Test", Some("/a"), Decision::Deny),
            (Protocol::Https, Some("CONNECT"), "test", None, Decision::Deny),
            (Protocol::Http, Some("GET"), "test", Some("/invalid"), Decision::Unevaluated),
            (Protocol::Http, Some("GET"), "[::1]", Some("/denied"), Decision::Deny),
        ];
        for (protocol, method, subject, pathname, decision) in cases {
            let mut event = match method {
                Some(method) => RequestEvent::http(protocol, method, "-"),
                None => RequestEvent::dns(),
            };
            event.subjects = vec![host(subject)];
            event.pathname = pathname.map(str::to_owned);
            event.decide(decision);
            if decision == Decision::Allow {
                event.matched(MatchSource::Rule(RuleId::new("t", 1)));
            }
            stats.record_event(&event);
        }
        let denials = stats.denials_snapshot();
        assert_eq!(denials.len(), 2);
        assert_eq!(denials[0].domain, "::1");
        assert_eq!(denials[0].pathname, "/denied");
        assert_eq!(denials[1].domain, "test");
        assert_eq!(denials[1].method, "POST");
        assert_eq!(denials[1].pathname, "/a");
        let test = stats.snapshot().into_iter().find(|summary| summary.domain == "test").unwrap();
        assert_eq!(
            test.http,
            Counts {
                allow: 1,
                block: 2
            }
        );
    }
}
