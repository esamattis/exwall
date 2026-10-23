//! Bounded domain counters, transfer totals, and bounded, process-local lists of HTTP requests
//! with their optional captures.

use super::{
    capture::{Capture, CaptureSettings},
    event::{Protocol, RequestEvent},
};
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

/// Repeats of one allowed or denied HTTP or HTTPS request, excluding CONNECT setup.
///
/// Requests are grouped by scheme, domain, port, method, pathname, and query string.
#[derive(Clone, Debug, Serialize)]
pub struct HttpRequest {
    /// The URL scheme, `http` or `https`.
    pub scheme: &'static str,
    /// The normalized request host.
    pub domain: String,
    /// The destination port; absent when it is the scheme's default or unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The request method.
    pub method: String,
    /// The query-free pathname.
    pub pathname: String,
    /// The raw query string without `?`; absent when the request had none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// What allowed the latest repeat, as its access-log label; absent for denials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The latest captured repeat, serialized as its identifier.
    ///
    /// A repeat seen while capturing is off keeps the earlier capture.
    #[serde(
        rename = "capture_id",
        serialize_with = "serialize_capture_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub capture: Option<Capture>,
    /// How many times the request was seen since it was first retained.
    pub count: u64,
    /// When the latest repeat was recorded.
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: jiff::Timestamp,
}

impl HttpRequest {
    /// Describe a single occurrence of a request whose outcome is being recorded now.
    ///
    /// A port equal to the scheme's default is dropped, so the request groups with
    /// repeats that omit it. The allowing rule starts empty;
    /// `DomainStats::record_allowance` sets it.
    pub fn new(
        protocol: Protocol,
        host: &Host,
        port: Option<u16>,
        method: &str,
        pathname: &str,
        query: Option<&str>,
        capture: Option<Capture>,
    ) -> Self {
        let default_port = if protocol == Protocol::Https {
            443
        } else {
            80
        };
        Self {
            scheme: protocol.name(),
            domain: host.to_string(),
            port: port.filter(|port| *port != default_port),
            method: method.to_owned(),
            pathname: pathname.to_owned(),
            query: query.map(str::to_owned),
            rule: None,
            capture,
            count: 1,
            timestamp: jiff::Timestamp::now(),
        }
    }

    /// Report whether `other` is a repeat of this request.
    fn same_request(&self, other: &HttpRequest) -> bool {
        self.scheme == other.scheme
            && self.domain == other.domain
            && self.port == other.port
            && self.method == other.method
            && self.pathname == other.pathname
            && self.query == other.query
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
            if request.capture.is_none() {
                request.capture = previous.capture;
            }
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

    /// Find the capture with identifier `id` among the retained requests.
    fn capture(&self, id: u64) -> Option<Capture> {
        let requests = self.0.lock().expect("HTTP request lock poisoned");
        requests
            .iter()
            .filter_map(|request| request.capture.as_ref())
            .find(|capture| capture.id() == id)
            .cloned()
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
    /// Whether new HTTP requests capture headers and bodies.
    capture: CaptureSettings,
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
        let request = HttpRequest::new(
            event.protocol,
            host,
            event.port,
            method,
            pathname,
            event.query.as_deref(),
            event.capture.clone(),
        );
        if allowed {
            let rule = event.matches.first().and_then(Option::as_ref).map(ToString::to_string);
            self.record_allowance(request, rule);
        } else {
            self.record_denial(request);
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

    /// Forget every domain summary and retained request, including their captures.
    ///
    /// Transfers still in flight continue to count toward fresh summaries, and the
    /// capture settings are kept.
    pub fn reset(&self) {
        *self.domains.lock().expect("domain counter lock poisoned") = Domains::default();
        self.denials.clear();
        self.allowances.clear();
    }

    /// Retain the latest denied requests without writing request history to disk.
    pub fn record_denial(&self, request: HttpRequest) {
        self.denials.push(request);
    }

    /// Retain the latest allowed requests and what allowed them, without writing to disk.
    pub fn record_allowance(&self, mut request: HttpRequest, rule: Option<String>) {
        request.rule = rule;
        self.allowances.push(request);
    }

    /// Return the switch and body size limit for capturing HTTP headers and bodies.
    pub fn capture_settings(&self) -> &CaptureSettings {
        &self.capture
    }

    /// Find a capture held by a retained request, denied or allowed.
    pub fn capture(&self, id: u64) -> Option<Capture> {
        self.denials.capture(id).or_else(|| self.allowances.capture(id))
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

/// Encode a retained capture as the identifier the UI fetches it by.
fn serialize_capture_id<S: serde::Serializer>(
    capture: &Option<Capture>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_some(&capture.as_ref().map(Capture::id))
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
            stats.record_denial(HttpRequest::new(
                Protocol::Https,
                &host("Example.COM."),
                None,
                "POST",
                &format!("/request/{index}"),
                None,
                None,
            ));
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
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host("example.com"),
            None,
            "POST",
            &oldest,
            None,
            None,
        ));
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host("example.com"),
            None,
            "POST",
            &oldest,
            None,
            None,
        ));
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host("example.com"),
            None,
            "GET",
            &oldest,
            None,
            None,
        ));
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

    /// Group repeats only when the query string matches too, and record it from events.
    #[test]
    fn groups_requests_by_query_string() {
        let stats = DomainStats::default();
        let host = host("example.com");
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host,
            None,
            "GET",
            "/search",
            Some("q=a"),
            None,
        ));
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host,
            None,
            "GET",
            "/search",
            Some("q=b"),
            None,
        ));
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host,
            None,
            "GET",
            "/search",
            Some("q=a"),
            None,
        ));
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host,
            None,
            "GET",
            "/search",
            None,
            None,
        ));
        let denials = stats.denials_snapshot();
        let summary: Vec<_> =
            denials.iter().map(|request| (request.query.as_deref(), request.count)).collect();
        assert_eq!(summary, [(None, 1), (Some("q=a"), 2), (Some("q=b"), 1)]);
        assert!(serde_json::to_value(&denials[0]).unwrap().get("query").is_none());
        assert_eq!(serde_json::to_value(&denials[1]).unwrap()["query"], "q=a");

        let mut event = RequestEvent::http(Protocol::Https, "POST", "-");
        event.subjects = vec![host.clone()];
        event.pathname = Some("/submit".into());
        event.query = Some("token=x".into());
        event.decide(Decision::Allow);
        event.matched(MatchSource::Paused);
        stats.record_event(&event);
        let allowance = stats.allowances_snapshot().remove(0);
        assert_eq!(allowance.scheme, "https");
        assert_eq!(allowance.pathname, "/submit");
        assert_eq!(allowance.query.as_deref(), Some("token=x"));
        assert_eq!(allowance.rule.as_deref(), Some("@paused"));
    }

    /// Group repeats only when the scheme matches too, and report it to the UI.
    #[test]
    fn groups_requests_by_scheme() {
        let stats = DomainStats::default();
        let host = host("example.com");
        stats.record_denial(HttpRequest::new(Protocol::Http, &host, None, "GET", "/", None, None));
        stats.record_denial(HttpRequest::new(Protocol::Https, &host, None, "GET", "/", None, None));
        stats.record_denial(HttpRequest::new(Protocol::Http, &host, None, "GET", "/", None, None));
        let denials = stats.denials_snapshot();
        let summary: Vec<_> =
            denials.iter().map(|request| (request.scheme, request.count)).collect();
        assert_eq!(summary, [("http", 2), ("https", 1)]);
        assert_eq!(serde_json::to_value(&denials[0]).unwrap()["scheme"], "http");
    }

    /// Group repeats by port, treating the scheme's default port as no port.
    #[test]
    fn groups_requests_by_non_default_port() {
        let stats = DomainStats::default();
        let host = host("example.com");
        for (protocol, port) in [
            (Protocol::Https, Some(443)),
            (Protocol::Https, None),
            (Protocol::Https, Some(8443)),
            (Protocol::Http, Some(80)),
        ] {
            stats.record_denial(HttpRequest::new(protocol, &host, port, "GET", "/", None, None));
        }
        let denials = stats.denials_snapshot();
        let summary: Vec<_> =
            denials.iter().map(|request| (request.scheme, request.port, request.count)).collect();
        assert_eq!(summary, [("http", None, 1), ("https", Some(8443), 1), ("https", None, 2)]);
        assert_eq!(serde_json::to_value(&denials[1]).unwrap()["port"], 8443);
        assert!(serde_json::to_value(&denials[0]).unwrap().get("port").is_none());
    }

    /// Repeats keep the latest capture, or the earlier one when the repeat was not captured.
    #[test]
    fn retains_captures_across_repeats() {
        let stats = DomainStats::default();
        let host = host("example.com");
        stats.capture_settings().set(true, 1);
        let first = stats.capture_settings().begin(&rama::http::HeaderMap::new()).unwrap();
        let second = stats.capture_settings().begin(&rama::http::HeaderMap::new()).unwrap();
        stats.record_allowance(
            HttpRequest::new(Protocol::Https, &host, None, "POST", "/", None, Some(first.clone())),
            None,
        );
        assert!(stats.capture(first.id()).is_some());
        stats.record_allowance(
            HttpRequest::new(Protocol::Https, &host, None, "POST", "/", None, Some(second.clone())),
            None,
        );
        assert!(stats.capture(first.id()).is_none());
        stats.record_allowance(
            HttpRequest::new(Protocol::Https, &host, None, "POST", "/", None, None),
            None,
        );
        let allowance = stats.allowances_snapshot().remove(0);
        assert_eq!(allowance.capture.as_ref().map(Capture::id), Some(second.id()));
        assert_eq!(serde_json::to_value(&allowance).unwrap()["capture_id"], second.id());
        stats.reset();
        assert!(stats.capture(second.id()).is_none());
        assert!(stats.capture_settings().enabled());
    }

    /// Keep allowed requests separate from denials and report the latest allowing rule.
    #[test]
    fn tracks_allowed_requests_with_their_latest_rule() {
        let stats = DomainStats::default();
        let rule = MatchSource::Rule(RuleId::new("t.toml", 1));
        stats.record_allowance(
            HttpRequest::new(Protocol::Https, &host("example.com"), None, "GET", "/", None, None),
            Some(rule.to_string()),
        );
        stats.record_allowance(
            HttpRequest::new(Protocol::Https, &host("example.com"), None, "GET", "/", None, None),
            Some("@paused".into()),
        );
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host("example.com"),
            None,
            "GET",
            "/",
            None,
            None,
        ));
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
        stats.record_denial(HttpRequest::new(
            Protocol::Https,
            &host("example.com"),
            None,
            "GET",
            "/denied",
            None,
            None,
        ));
        stats.record_allowance(
            HttpRequest::new(
                Protocol::Https,
                &host("example.com"),
                None,
                "GET",
                "/allowed",
                None,
                None,
            ),
            None,
        );
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

    /// Retain only evaluated HTTP requests, with normalized hosts and pathnames.
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
