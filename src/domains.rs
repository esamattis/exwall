//! Current per-domain policy counters, without retaining individual requests.
use crate::{access_log::Protocol, rules::normalize_host};
use serde::Serialize;
use std::{
    collections::BTreeMap,
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
    #[serde(serialize_with = "serialize_timestamp")]
    pub last_updated: jiff::Timestamp,
}

/// Shared process-lifetime counters independent of rule reloads and log retention.
#[derive(Clone, Default)]
pub struct Domains {
    entries: Arc<Mutex<BTreeMap<String, Domain>>>,
}

impl Domains {
    /// Increment a policy outcome and replace only the latest update timestamp.
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
            last_updated: jiff::Timestamp::now(),
        });
        let counts = match protocol {
            Protocol::Dns => &mut entry.dns,
            Protocol::Http | Protocol::Https => &mut entry.http,
        };
        if allowed {
            counts.allow += 1;
        } else {
            counts.block += 1;
        }
        entry.last_updated = jiff::Timestamp::now();
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

#[cfg(test)]
mod tests {
    use super::*;

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
