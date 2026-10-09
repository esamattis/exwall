//! Pure, clock-driven batching and deduplication of access-log events.

use super::{event::RequestEvent, format};
use std::{collections::HashMap, time::Duration};
use tokio::time::Instant;

/// Collects events for a fixed window after the first arrival, counting duplicates.
pub struct Batcher {
    /// How long a batch stays open after its first event.
    window: Duration,
    /// When the open batch must be flushed.
    deadline: Option<Instant>,
    /// Distinct events in first-received order with their occurrence counts.
    entries: Vec<(RequestEvent, usize)>,
    /// Position of each distinct message in `entries`.
    positions: HashMap<String, usize>,
}

impl Batcher {
    /// Create an empty batcher with the given window.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            deadline: None,
            entries: Vec::new(),
            positions: HashMap::new(),
        }
    }

    /// Add an event received at `now`; the first event of a batch starts its window.
    ///
    /// Matching messages keep the first occurrence's position and timestamp.
    pub fn push(&mut self, event: RequestEvent, now: Instant) {
        if self.deadline.is_none() {
            self.deadline = Some(now + self.window);
        }
        let message = format::message(&event);
        if let Some(&position) = self.positions.get(&message) {
            self.entries[position].1 += 1;
        } else {
            self.positions.insert(message, self.entries.len());
            self.entries.push((event, 1));
        }
    }

    /// Return when the open batch must be flushed, if one is open.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Report whether the open batch's window has elapsed at `now`.
    pub fn is_due(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    /// Close the batch, returning its counted events and resetting the window.
    pub fn take(&mut self) -> Vec<(RequestEvent, usize)> {
        self.deadline = None;
        self.positions.clear();
        std::mem::take(&mut self.entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy::{Decision, MatchSource, RuleId},
        telemetry::{
            event::{Failure, Protocol},
            format::{line, tests::event},
        },
    };
    use hickory_proto::op::ResponseCode;

    /// Flush at one second despite later arrivals, preserving first occurrence order and time.
    #[test]
    fn batches_for_one_second_in_first_received_order() {
        let start = Instant::now();
        let mut batcher = Batcher::new(Duration::from_secs(1));
        assert_eq!(batcher.deadline(), None);
        batcher.push(event(2), start);
        batcher.push(event(1), start);
        let mut duplicate = event(2);
        duplicate.timestamp = "2026-10-07T12:34:57Z".parse().unwrap();
        batcher.push(duplicate, start + Duration::from_millis(900));
        batcher.push(event(2), start + Duration::from_millis(900));
        assert!(!batcher.is_due(start + Duration::from_millis(999)));
        assert!(batcher.is_due(start + Duration::from_secs(1)));
        let lines: Vec<_> =
            batcher.take().iter().map(|(event, count)| line(event, *count)).collect();
        assert_eq!(
            lines,
            [
                "2026-10-07T12:34:56Z http ALLOW test:allow#1 GET http://test/2 200 - - x3\n"
                    .to_string(),
                line(&event(1), 1),
            ]
        );
        assert_eq!(batcher.deadline(), None);
        let later = start + Duration::from_secs(5);
        batcher.push(event(2), later);
        assert_eq!(batcher.deadline(), Some(later + Duration::from_secs(1)));
        assert_eq!(batcher.take().len(), 1);
    }

    /// Keep messages distinct when any field other than their timestamp differs.
    #[test]
    fn deduplication_compares_every_message_field() {
        let now = Instant::now();
        let mut batcher = Batcher::new(Duration::from_secs(1));
        batcher.push(event(0), now);
        for index in 0..8 {
            let mut changed = event(0);
            match index {
                0 => changed.protocol = Protocol::Https,
                1 => changed.decide(Decision::Deny),
                2 => changed.matched(MatchSource::Rule(RuleId::new("other", 1))),
                3 => changed.method = Some("POST".into()),
                4 => changed.url = "http://test/other".into(),
                5 => changed.respond_http(201),
                6 => changed.respond_dns(ResponseCode::Refused),
                7 => changed.fail(Failure::Upstream),
                _ => unreachable!(),
            }
            batcher.push(changed, now);
        }
        let entries = batcher.take();
        assert_eq!(entries.len(), 9);
        assert!(entries.iter().all(|(_, count)| *count == 1));
    }
}
