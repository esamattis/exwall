//! Bounded domain counters, transfer totals, and bounded, process-local lists of HTTP requests.

use super::event::{Protocol, RequestEvent};
use crate::policy::{Decision, Host};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

/// The number of HTTP requests of each outcome retained for the UI.
const REQUEST_CAPACITY: usize = 200;
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

/// Which way forwarded body bytes travelled through the proxy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// From the client to the upstream: request bodies.
    Up,
    /// From the upstream to the client: response bodies.
    Down,
}

/// Body bytes forwarded for allowed HTTP and HTTPS requests.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Transferred {
    /// Request body bytes sent upstream.
    pub up: u64,
    /// Response body bytes returned to clients.
    pub down: u64,
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
    /// Forwarded HTTP and HTTPS body bytes.
    pub bytes: Transferred,
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

/// Repeats of one allowed or denied HTTP or HTTPS request, excluding query strings and
/// CONNECT setup.
///
/// Requests are grouped by domain, method, and pathname.
#[derive(Clone, Debug, Serialize)]
pub struct HttpRequest {
    /// The normalized request host.
    pub domain: String,
    /// The request method.
    pub method: String,
    /// The query-free pathname.
    pub pathname: String,
    /// What allowed the latest repeat, as its access-log label; absent for denials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// How many times the request was seen since it was first retained.
    pub count: u64,
    /// When the latest repeat was recorded.
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: jiff::Timestamp,
}

impl HttpRequest {
    /// Report whether `other` is a repeat of this request.
    fn same_request(&self, other: &HttpRequest) -> bool {
        self.domain == other.domain
            && self.method == other.method
            && self.pathname == other.pathname
    }
}

/// The most recently seen unique HTTP requests with one outcome, least recent first.
#[derive(Clone, Default)]
struct RecentRequests(Arc<Mutex<VecDeque<HttpRequest>>>);

impl RecentRequests {
    /// Record one occurrence of a request.
    ///
    /// A repeat updates and moves its existing entry to the newest position; a new
    /// request evicts the least recently seen one when the list is full.
    fn push(&self, mut request: HttpRequest) {
        let mut requests = self.0.lock().expect("HTTP request lock poisoned");
        let existing = requests.iter().position(|retained| retained.same_request(&request));
        if let Some(index) = existing {
            let previous = requests.remove(index).expect("position is in bounds");
            request.count = previous.count.saturating_add(1);
        } else if requests.len() == REQUEST_CAPACITY {
            requests.pop_front();
        }
        requests.push_back(request);
    }

    /// Return the retained requests with the most recently seen first.
    fn snapshot(&self) -> Vec<HttpRequest> {
        let requests = self.0.lock().expect("HTTP request lock poisoned");
        requests.iter().rev().cloned().collect()
    }

    /// Forget every retained request.
    fn clear(&self) {
        self.0.lock().expect("HTTP request lock poisoned").clear();
    }
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
                        bytes: Transferred::default(),
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

/// Shared process-lifetime counters and bounded request lists, independent of log retention.
#[derive(Clone, Default)]
pub struct DomainStats {
    /// Summaries of the most recently updated domains.
    domains: Arc<Mutex<Domains>>,
    /// The newest HTTP denials.
    denials: RecentRequests,
    /// The newest allowed HTTP requests.
    allowances: RecentRequests,
}

impl DomainStats {
    /// Update counters and request history from an evaluated request event.
    pub fn record_event(&self, event: &RequestEvent) {
        let allowed = match event.decision {
            Decision::Allow => true,
            Decision::Deny => false,
            Decision::Unevaluated => return,
        };
        for host in &event.subjects {
            self.record(host, event.protocol, allowed);
        }
        if event.protocol == Protocol::Dns {
            return;
        }
        let (Some(host), Some(method), Some(pathname)) =
            (event.subjects.first(), &event.method, &event.pathname)
        else {
            return;
        };
        if allowed {
            let rule = event.matches.first().and_then(Option::as_ref).map(ToString::to_string);
            self.record_allowance(host, method, pathname, rule);
        } else {
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

    /// Add forwarded body bytes to a domain without changing its outcome timestamps.
    ///
    /// The domain is created if needed because request bodies are forwarded before
    /// the request's policy outcome is recorded.
    pub fn record_transfer(&self, host: &Host, direction: Direction, bytes: u64) {
        if host.is_empty() || bytes == 0 {
            return;
        }
        let mut domains = self.domains.lock().expect("domain counter lock poisoned");
        let summary = domains.touch(host, jiff::Timestamp::now());
        let total = match direction {
            Direction::Up => &mut summary.bytes.up,
            Direction::Down => &mut summary.bytes.down,
        };
        *total = total.saturating_add(bytes);
    }

    /// Forget every domain summary and retained request.
    ///
    /// Transfers still in flight continue to count toward fresh summaries.
    pub fn reset(&self) {
        *self.domains.lock().expect("domain counter lock poisoned") = Domains::default();
        self.denials.clear();
        self.allowances.clear();
    }

    /// Retain the latest denied requests without writing request history to disk.
    pub fn record_denial(&self, host: &Host, method: &str, pathname: &str) {
        self.denials.push(http_request(host, method, pathname, None));
    }

    /// Retain the latest allowed requests and what allowed them, without writing to disk.
    pub fn record_allowance(
        &self,
        host: &Host,
        method: &str,
        pathname: &str,
        rule: Option<String>,
    ) {
        self.allowances.push(http_request(host, method, pathname, rule));
    }

    /// Return unique denied HTTP requests with the most recently seen first.
    pub fn denials_snapshot(&self) -> Vec<HttpRequest> {
        self.denials.snapshot()
    }

    /// Return unique allowed HTTP requests with the most recently seen first.
    pub fn allowances_snapshot(&self) -> Vec<HttpRequest> {
        self.allowances.snapshot()
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

/// Describe a single occurrence of a request whose outcome is being recorded now.
fn http_request(host: &Host, method: &str, pathname: &str, rule: Option<String>) -> HttpRequest {
    HttpRequest {
        domain: host.to_string(),
        method: method.to_owned(),
        pathname: pathname.to_owned(),
        rule,
        count: 1,
        timestamp: jiff::Timestamp::now(),
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

    /// Group repeats and evict only the least recently seen unique requests.
    #[test]
    fn retains_only_the_latest_unique_http_requests() {
        let stats = DomainStats::default();
        let extra = 5;
        for index in 0..REQUEST_CAPACITY + extra {
            stats.record_denial(&host("Example.COM."), "POST", &format!("/request/{index}"));
        }
        let newest = format!("/request/{}", REQUEST_CAPACITY + extra - 1);
        let oldest = format!("/request/{extra}");
        let snapshot = stats.denials_snapshot();
        assert_eq!(snapshot.len(), REQUEST_CAPACITY);
        assert_eq!(snapshot[0].pathname, newest);
        assert_eq!(snapshot[REQUEST_CAPACITY - 1].pathname, oldest);
        assert_eq!(snapshot[0].domain, "example.com");
        assert_eq!(snapshot[0].count, 1);

        // A repeat of the oldest request moves it to the front instead of evicting it.
        stats.record_denial(&host("example.com"), "POST", &oldest);
        stats.record_denial(&host("example.com"), "POST", &oldest);
        stats.record_denial(&host("example.com"), "GET", &oldest);
        let latest = stats.denials_snapshot();
        assert_eq!(latest.len(), REQUEST_CAPACITY);
        assert_eq!((latest[0].method.as_str(), latest[0].count), ("GET", 1));
        assert_eq!((latest[1].pathname.as_str(), latest[1].count), (oldest.as_str(), 3));
        assert_eq!(latest[2].pathname, newest);
        assert!(latest.iter().all(|request| request.pathname != format!("/request/{}", extra + 1)));
        assert_eq!(snapshot[REQUEST_CAPACITY - 1].count, 1);
        let serialized = serde_json::to_value(&latest[1]).unwrap();
        assert_eq!(serialized["count"], 3);
        assert!(serialized.get("rule").is_none());
    }

    /// Keep allowed requests separate from denials and report the latest allowing rule.
    #[test]
    fn tracks_allowed_requests_with_their_latest_rule() {
        let stats = DomainStats::default();
        let rule = MatchSource::Rule(RuleId::new("t.toml", 1));
        stats.record_allowance(&host("example.com"), "GET", "/", Some(rule.to_string()));
        stats.record_allowance(&host("example.com"), "GET", "/", Some("@paused".into()));
        stats.record_denial(&host("example.com"), "GET", "/");
        let allowances = stats.allowances_snapshot();
        assert_eq!(allowances.len(), 1);
        assert_eq!(allowances[0].count, 2);
        assert_eq!(allowances[0].rule.as_deref(), Some("@paused"));
        assert_eq!(serde_json::to_value(&allowances[0]).unwrap()["rule"], "@paused");
        assert_eq!(stats.denials_snapshot()[0].count, 1);
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

    /// Accumulate transfers per direction without touching outcome timestamps.
    #[test]
    fn tracks_transferred_bytes_per_domain() {
        let stats = DomainStats::default();
        stats.record_transfer(&host("Example.COM."), Direction::Up, 10);
        stats.record_transfer(&host("example.com"), Direction::Down, 0);
        let pending = stats.snapshot().remove(0);
        assert_eq!(
            pending.bytes,
            Transferred {
                up: 10,
                down: 0
            }
        );
        assert_eq!(pending.last_allowed, None);
        assert_eq!(pending.last_denied, None);
        stats.record(&host("example.com"), Protocol::Https, true);
        stats.record_transfer(&host("example.com"), Direction::Down, 1500);
        stats.record_transfer(&host("example.com"), Direction::Up, 5);
        let latest = stats.snapshot().remove(0);
        assert_eq!(
            latest.bytes,
            Transferred {
                up: 15,
                down: 1500
            }
        );
        assert_eq!(latest.last_allowed, Some(latest.last_updated));
        let serialized = serde_json::to_value(&latest).unwrap();
        assert_eq!(serialized["bytes"], serde_json::json!({ "up": 15, "down": 1500 }));
    }

    /// Clear domains and requests while continuing to accept new traffic.
    #[test]
    fn reset_clears_domains_and_requests() {
        let stats = DomainStats::default();
        stats.record(&host("example.com"), Protocol::Dns, true);
        stats.record_transfer(&host("example.com"), Direction::Down, 100);
        stats.record_denial(&host("example.com"), "GET", "/denied");
        stats.record_allowance(&host("example.com"), "GET", "/allowed", None);
        stats.reset();
        assert!(stats.snapshot().is_empty());
        assert!(stats.denials_snapshot().is_empty());
        assert!(stats.allowances_snapshot().is_empty());
        assert!(stats.domains.lock().unwrap().order.is_empty());
        stats.record_transfer(&host("example.com"), Direction::Up, 1);
        let fresh = stats.snapshot().remove(0);
        assert_eq!(fresh.dns, Counts::default());
        assert_eq!(
            fresh.bytes,
            Transferred {
                up: 1,
                down: 0
            }
        );
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

    /// Retain only evaluated HTTP requests, with normalized hosts and query-free pathnames.
    #[test]
    fn tracks_http_requests_without_dns_connect_or_unevaluated_requests() {
        let stats = DomainStats::default();
        let cases = [
            (Protocol::Dns, None, "denied.test", None, Decision::Deny),
            (Protocol::Dns, None, "allowed.test", None, Decision::Allow),
            (Protocol::Http, Some("GET"), "test", Some("/allowed"), Decision::Allow),
            (Protocol::Https, Some("CONNECT"), "test", None, Decision::Allow),
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
        let allowances = stats.allowances_snapshot();
        assert_eq!(allowances.len(), 1);
        assert_eq!(allowances[0].pathname, "/allowed");
        assert_eq!(allowances[0].rule.as_deref(), Some("t:allow#1"));
        let test = stats.snapshot().into_iter().find(|summary| summary.domain == "test").unwrap();
        assert_eq!(
            test.http,
            Counts {
                allow: 2,
                block: 2
            }
        );
    }
}
