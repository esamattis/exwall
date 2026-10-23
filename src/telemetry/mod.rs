//! Request telemetry: typed events, the access log, in-memory domain and transfer statistics,
//! and opt-in captures of HTTP headers and bodies.
//!
//! Handlers submit [`RequestEvent`]s through an [`EventSink`]. Formatting and
//! batching are pure; only the writer actor touches the filesystem.

mod batcher;
mod capture;
mod event;
pub mod format;
mod sink;
mod stats;
mod writer;

pub use batcher::Batcher;
pub use capture::{
    BodyRecorder, Capture, CaptureDetails, CaptureSettings, DEFAULT_BODY_LIMIT_KB,
    MAX_BODY_LIMIT_KB, Side,
};
pub use event::{Failure, Protocol, RequestEvent};
pub use sink::{EventReceiver, EventSink, PendingEvent};
pub use stats::{Counts, Direction, DomainStats, DomainSummary, HttpRequest, Transferred};
pub use writer::{
    AccessLog, AccessLogCloser, AccessLogError, AccessLogTask, AccessLogWriter, start,
};
