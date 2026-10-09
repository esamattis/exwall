//! The handler-facing mailbox for request events and the cancellation guard.

use super::{event::RequestEvent, stats::DomainStats};
use tokio::sync::mpsc;

/// A cloneable mailbox used by handlers without awaiting filesystem operations.
///
/// The queue is deliberately unbounded: every handled request is logged and
/// handlers never wait for the access-log actor. Dropping entries under load
/// would let a flood of requests hide others from the audit trail.
#[derive(Clone)]
pub struct EventSink {
    /// The access-log actor's queue.
    sender: mpsc::UnboundedSender<RequestEvent>,
    /// Domain counters updated synchronously from every event.
    stats: DomainStats,
}

/// The receiving end of an [`EventSink`].
pub struct EventReceiver {
    /// Submitted events in arrival order.
    pub events: mpsc::UnboundedReceiver<RequestEvent>,
}

impl EventSink {
    /// Create a sink and the receiver that the access-log actor drains.
    pub fn channel() -> (Self, EventReceiver) {
        let (sender, events) = mpsc::unbounded_channel();
        let sink = Self {
            sender,
            stats: DomainStats::default(),
        };
        (
            sink,
            EventReceiver {
                events,
            },
        )
    }

    /// Return the domain statistics fed by this sink.
    pub fn stats(&self) -> &DomainStats {
        &self.stats
    }

    /// Update domain statistics and queue the event without blocking or capacity drops.
    pub fn submit(&self, event: RequestEvent) {
        self.stats.record_event(&event);
        if self.sender.send(event).is_err() {
            tracing::error!("access-log actor is unavailable");
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
        let (sink, mut receiver) = EventSink::channel();
        let guard = sink.track(RequestEvent::http(Protocol::Http, "GET", "http://test/"));
        drop(guard);
        let mut answered = sink.track(RequestEvent::http(Protocol::Http, "GET", "http://test/"));
        answered.event().respond_http(200);
        drop(answered);
        assert_eq!(receiver.events.recv().await.unwrap().failure, Some(Failure::Cancelled));
        assert_eq!(receiver.events.recv().await.unwrap().failure, None);
    }

    /// Bursts far beyond any batch size are queued without blocking or losing events.
    #[tokio::test]
    async fn bursts_are_never_dropped() {
        let (sink, mut receiver) = EventSink::channel();
        for _ in 0..100_000 {
            sink.submit(RequestEvent::dns());
        }
        drop(sink);
        let mut received = 0;
        while receiver.events.recv().await.is_some() {
            received += 1;
        }
        assert_eq!(received, 100_000);
    }
}
