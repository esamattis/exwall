//! The handler-facing mailbox for request events and the cancellation guard.

use super::{event::RequestEvent, stats::DomainStats};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc::{self, error::TrySendError};

/// A cloneable mailbox used by handlers without awaiting filesystem operations.
#[derive(Clone)]
pub struct EventSink {
    /// The access-log actor's bounded queue.
    sender: mpsc::Sender<RequestEvent>,
    /// Domain counters updated synchronously from every event.
    stats: DomainStats,
    /// Events discarded because the queue was full.
    dropped: Arc<AtomicU64>,
}

/// The receiving end of an [`EventSink`].
pub struct EventReceiver {
    /// Submitted events in arrival order.
    pub events: mpsc::Receiver<RequestEvent>,
    /// Events discarded because the queue was full.
    pub dropped: Arc<AtomicU64>,
}

impl EventSink {
    /// Create a sink with a bounded queue of `capacity` events.
    pub fn channel(capacity: usize) -> (Self, EventReceiver) {
        let (sender, events) = mpsc::channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let sink = Self {
            sender,
            stats: DomainStats::default(),
            dropped: dropped.clone(),
        };
        (
            sink,
            EventReceiver {
                events,
                dropped,
            },
        )
    }

    /// Return the domain statistics fed by this sink.
    pub fn stats(&self) -> &DomainStats {
        &self.stats
    }

    /// Update domain statistics and queue the event without blocking.
    ///
    /// A full queue drops the event and counts it so the actor can report the loss.
    pub fn submit(&self, event: RequestEvent) {
        self.stats.record_event(&event);
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Closed(_)) => {
                tracing::warn!("access log is closed; request event discarded");
            }
        }
    }

    /// Ensure a parsed request is logged even if its asynchronous handler is cancelled.
    pub fn track(&self, event: RequestEvent) -> PendingEvent {
        PendingEvent {
            sink: self.clone(),
            event: Some(event),
        }
    }
}

/// Request-scoped guard that submits an outcome when its handler exits or is cancelled.
pub struct PendingEvent {
    /// Where the event is submitted.
    sink: EventSink,
    /// The event, present until the guard is dropped.
    event: Option<RequestEvent>,
}

impl PendingEvent {
    /// Update policy metadata and the eventual response outcome before submission.
    pub fn event(&mut self) -> &mut RequestEvent {
        self.event.as_mut().expect("pending event exists until the guard is dropped")
    }
}

impl Drop for PendingEvent {
    /// Submit exactly one event, including requests interrupted before a response exists.
    fn drop(&mut self) {
        if let Some(event) = self.event.take() {
            self.sink.submit(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event::{Failure, Protocol};

    /// Dropping a guard submits its event once, presumed cancelled unless answered.
    #[tokio::test]
    async fn guards_submit_on_drop() {
        let (sink, mut receiver) = EventSink::channel(4);
        let guard = sink.track(RequestEvent::http(Protocol::Http, "GET", "http://test/"));
        drop(guard);
        let mut answered = sink.track(RequestEvent::http(Protocol::Http, "GET", "http://test/"));
        answered.event().respond_http(200);
        drop(answered);
        assert_eq!(receiver.events.recv().await.unwrap().failure, Some(Failure::Cancelled));
        assert_eq!(receiver.events.recv().await.unwrap().failure, None);
    }

    /// A full queue never blocks handlers; losses are counted for reporting.
    #[tokio::test]
    async fn full_queue_counts_drops() {
        let (sink, receiver) = EventSink::channel(1);
        for _ in 0..3 {
            sink.submit(RequestEvent::dns());
        }
        assert_eq!(receiver.dropped.load(Ordering::Relaxed), 2);
    }
}
