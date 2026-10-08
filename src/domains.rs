//! Current domain counters and a bounded, process-local list of HTTP denials.
use crate::{access_log::Protocol, rules::normalize_host};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
};

/// Totals for evaluated requests in one application protocol.
#[derive(Clone, Default, Serialize)]
pub struct Counts {
    pub allow: u64,
    pub block: u64,
}

/// The latest aggregate state for one normalized domain.
#[derive(Clone, Serialize)]
pub struct Domain {
    pub domain: String,
    pub dns: Counts,
    pub http: Counts,
    #[serde(serialize_with = "serialize_optional_timestamp")]
    pub last_allowed: Option<jiff::Timestamp>,
    #[serde(serialize_with = "serialize_optional_timestamp")]
    pub last_denied: Option<jiff::Timestamp>,
    #[serde(serialize_with = "serialize_timestamp")]
    pub last_updated: jiff::Timestamp,
}

/// One denied HTTP or HTTPS request, excluding query strings and CONNECT setup.
#[derive(Clone, Serialize)]
pub struct HttpDenial {
    pub domain: String,
    pub method: String,
    pub pathname: String,
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: jiff::Timestamp,
}

/// Shared process-lifetime counters and bounded denials, independent of log retention.
#[derive(Clone, Default)]
pub struct Domains {
    entries: Arc<Mutex<BTreeMap<String, Domain>>>,
    denials: Arc<Mutex<VecDeque<HttpDenial>>>,
}

impl Domains {
    /// Increment a policy outcome and update its timestamp independently of the other outcome.
    pub fn record(&self, host: &str, protocol: Protocol, allowed: bool) {
        let host = normalize_host(host.trim_matches(['[', ']']));
        if host.is_empty() {
            return;
        }
        let mut entries = self.entries.lock().expect("domain counter lock poisoned");
        let entry = entries.entry(host.clone()).or_insert_with(|| Domain {
            domain: host,
            dns: Counts::default(),
            http: Counts::default(),
            last_allowed: None,
            last_denied: None,
            last_updated: jiff::Timestamp::now(),
        });
        let counts = match protocol {
            Protocol::Dns => &mut entry.dns,
            Protocol::Http | Protocol::Https => &mut entry.http,
        };
        let timestamp = jiff::Timestamp::now();
        if allowed {
            counts.allow += 1;
            entry.last_allowed = Some(timestamp);
        } else {
            counts.block += 1;
            entry.last_denied = Some(timestamp);
        }
        entry.last_updated = timestamp;
    }

    /// Retain the latest 100 denied requests without writing request history to disk.
    pub fn record_denial(&self, host: &str, method: &str, pathname: &str) {
        let mut denials = self.denials.lock().expect("HTTP denial lock poisoned");
        if denials.len() == 100 {
            denials.pop_front();
        }
        denials.push_back(HttpDenial {
            domain: normalize_host(host.trim_matches(['[', ']'])),
            method: method.to_owned(),
            pathname: pathname.to_owned(),
            timestamp: jiff::Timestamp::now(),
        });
    }

    /// Return denied HTTP requests newest first, including repeated requests.
    pub fn denials_snapshot(&self) -> Vec<HttpDenial> {
        self.denials.lock().expect("HTTP denial lock poisoned").iter().rev().cloned().collect()
    }

    /// Return independent snapshots with the most recently updated domain first.
    pub fn snapshot(&self) -> Vec<Domain> {
        let mut domains: Vec<_> =
            self.entries.lock().expect("domain counter lock poisoned").values().cloned().collect();
        domains.sort_by(|left, right| {
            right.last_updated.cmp(&left.last_updated).then_with(|| left.domain.cmp(&right.domain))
        });
        domains
    }
}

/// Encode the latest update as an RFC 3339 timestamp for API consumers.
fn serialize_timestamp<S: serde::Serializer>(
    timestamp: &jiff::Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(timestamp)
}

/// Encode an outcome's latest timestamp as RFC 3339, or null when it has never occurred.
fn serialize_optional_timestamp<S: serde::Serializer>(
    timestamp: &Option<jiff::Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    timestamp.map(|value| value.to_string()).serialize(serializer)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keep allow and denial timestamps independent across normalized hosts and protocols.
    #[test]
    fn tracks_outcomes_independently() {
        let domains = Domains::default();
        domains.record("Example.COM.", Protocol::Dns, true);
        let allowed = domains.snapshot().remove(0);
        assert_eq!(allowed.last_allowed, Some(allowed.last_updated));
        assert_eq!(allowed.last_denied, None);
        let serialized = serde_json::to_value(&allowed).unwrap();
        assert_eq!(serialized["last_allowed"], allowed.last_updated.to_string());
        assert!(serialized["last_denied"].is_null());

        domains.record("example.com", Protocol::Https, false);
        let denied = domains.snapshot().remove(0);
        assert_eq!(denied.last_allowed, allowed.last_allowed);
        assert_eq!(denied.last_denied, Some(denied.last_updated));
        domains.record("EXAMPLE.COM", Protocol::Http, true);
        let latest = domains.snapshot().remove(0);
        assert_eq!(latest.last_denied, denied.last_denied);
        assert_eq!(latest.last_allowed, Some(latest.last_updated));
        assert_eq!(latest.dns.allow, 1);
        assert_eq!(latest.dns.block, 0);
        assert_eq!(latest.http.allow, 1);
        assert_eq!(latest.http.block, 1);

        domains.record("denied.test", Protocol::Dns, false);
        let only_denied = domains.snapshot().remove(0);
        assert_eq!(only_denied.last_allowed, None);
        assert_eq!(only_denied.last_denied, Some(only_denied.last_updated));
    }

    /// Evict only the oldest denials while retaining repeats and immutable snapshots.
    #[test]
    fn retains_only_the_latest_hundred_http_denials() {
        let domains = Domains::default();
        for index in 0..105 {
            domains.record_denial("Example.COM.", "POST", &format!("/request/{index}"));
        }
        let snapshot = domains.denials_snapshot();
        assert_eq!(snapshot.len(), 100);
        assert_eq!(snapshot[0].pathname, "/request/104");
        assert_eq!(snapshot[99].pathname, "/request/5");
        assert_eq!(snapshot[0].domain, "example.com");
        domains.record_denial("example.com", "POST", "/request/104");
        let latest = domains.denials_snapshot();
        assert_eq!(latest.len(), 100);
        assert_eq!(latest[0].pathname, latest[1].pathname);
        assert_eq!(snapshot[99].pathname, "/request/5");
    }

    /// Aggregate normalized hosts, combine HTTP/TLS, and retain only the latest state.
    #[test]
    fn aggregates_protocols_and_orders_latest_updates() {
        let domains = Domains::default();
        domains.record("Example.COM.", Protocol::Dns, false);
        domains.record("example.com", Protocol::Http, true);
        domains.record("example.com", Protocol::Https, false);
        let first = domains.snapshot();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].dns.block, 1);
        assert_eq!(first[0].http.allow, 1);
        assert_eq!(first[0].http.block, 1);
        domains.record("other.test", Protocol::Dns, true);
        let latest = domains.snapshot();
        assert_eq!(latest[0].domain, "other.test");
        assert_eq!(latest[1].last_updated, first[0].last_updated);
    }
}
