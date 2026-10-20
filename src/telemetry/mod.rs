//! Request telemetry: typed events, the access log, and in-memory domain and transfer statistics.
//!
//! Handlers submit [`RequestEvent`]s through an [`EventSink`]. Formatting and
//! batching are pure; only the writer actor touches the filesystem.

mod batcher;
mod event;
pub mod format;
mod sink;
mod stats;
mod writer;

pub use batcher::Batcher;
pub use event::{Failure, Protocol, RequestEvent};
pub use sink::{EventReceiver, EventSink, PendingEvent};
pub use stats::{Counts, Direction, DomainStats, DomainSummary, HttpDenial, Transferred};
pub use writer::{
    AccessLog, AccessLogCloser, AccessLogError, AccessLogTask, AccessLogWriter, start,
};
