//! A body wrapper that counts forwarded bytes toward a domain's transfer totals,
//! optionally captures the leading bytes for the web UI, and optionally ends the
//! request's clock when the body ends.

use crate::{
    policy::Host,
    telemetry::{BodyRecorder, Direction, DomainStats, RequestClock},
};
use rama::{
    bytes::Bytes,
    error::BoxError,
    http::{
        Body,
        body::{Frame, SizeHint, StreamingBody},
    },
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Publish pending counts once this many bytes accumulate, so long transfers show progress.
const FLUSH_BYTES: u64 = 64 * 1024;

/// A streaming body that adds its data frame sizes to one domain's totals.
///
/// Counts are batched to keep the shared statistics lock off the per-frame path,
/// and flushed at the end of the stream or when the body is dropped early. Frames
/// are forwarded unchanged and immediately, whether or not they are also captured.
pub struct MeteredBody {
    /// The forwarded body.
    inner: Body,
    /// Where transferred bytes are recorded.
    stats: DomainStats,
    /// The authorized host the bytes are attributed to.
    host: Host,
    /// Which way the body travels.
    direction: Direction,
    /// Bytes counted but not yet recorded.
    pending: u64,
    /// Captures the body's leading bytes while request capturing is enabled.
    recorder: Option<BodyRecorder>,
    /// The request's clock, ended with the body when it is a response body.
    clock: Option<RequestClock>,
}

impl MeteredBody {
    /// Wrap `inner` so its data bytes count toward `host` in `direction`, are
    /// captured by `recorder` if one is given, and end `clock`, if given, when the
    /// body ends or is abandoned.
    pub fn wrap(
        inner: Body,
        stats: DomainStats,
        host: Host,
        direction: Direction,
        recorder: Option<BodyRecorder>,
        clock: Option<RequestClock>,
    ) -> Body {
        Body::new(Self {
            inner,
            stats,
            host,
            direction,
            pending: 0,
            recorder,
            clock,
        })
    }

    /// Record pending bytes and start a new batch.
    fn flush(&mut self) {
        let bytes = std::mem::take(&mut self.pending);
        self.stats.record_transfer(&self.host, self.direction, bytes);
    }

    /// Record pending bytes, store the captured body, if any, and end the clock, if any.
    fn finish(&mut self, complete: bool) {
        self.flush();
        if let Some(recorder) = &mut self.recorder {
            recorder.finish(complete);
        }
        if let Some(clock) = &self.clock {
            clock.finish();
        }
    }
}

impl StreamingBody for MeteredBody {
    type Data = Bytes;
    type Error = BoxError;

    /// Forward the next frame, counting data frames and flushing at the end of the stream.
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.pending += data.len() as u64;
                    if let Some(recorder) = &mut self.recorder {
                        recorder.observe(data);
                    }
                    if self.pending >= FLUSH_BYTES {
                        self.flush();
                    }
                }
            }
            Poll::Ready(Some(Err(_))) => self.finish(false),
            Poll::Ready(None) => self.finish(true),
            Poll::Pending => {}
        }
        polled
    }

    /// Report the wrapped body's size hint.
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    /// Report whether the wrapped body has ended.
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

impl Drop for MeteredBody {
    /// Record bytes forwarded before the body was completed or abandoned.
    ///
    /// An empty body may be dropped without being polled, so it still counts as complete.
    fn drop(&mut self) {
        let complete = self.inner.is_end_stream();
        self.finish(complete);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::body::util::BodyExt;

    /// Return the transfer totals recorded for the test host.
    fn transferred(stats: &DomainStats) -> (u64, u64) {
        let summary = stats.snapshot().remove(0);
        (summary.bytes.up, summary.bytes.down)
    }

    /// Count every data byte of a fully read body exactly once.
    #[tokio::test]
    async fn counts_complete_bodies() {
        let stats = DomainStats::default();
        let chunks = vec![Ok::<_, BoxError>(Bytes::from("hello")), Ok(Bytes::from(" world"))];
        let body = Body::from_stream(rama::stream::iter(chunks));
        let metered = MeteredBody::wrap(
            body,
            stats.clone(),
            Host::new("example.com"),
            Direction::Down,
            None,
            None,
        );
        let bytes = metered.collect().await.unwrap().to_bytes();
        assert_eq!(bytes, "hello world");
        assert_eq!(transferred(&stats), (0, 11));
    }

    /// Flush large transfers while streaming and count partial bodies when dropped.
    #[tokio::test]
    async fn flushes_large_and_abandoned_bodies() {
        let stats = DomainStats::default();
        let large = Bytes::from(vec![0; FLUSH_BYTES as usize]);
        let chunks = vec![Ok::<_, BoxError>(large), Ok(Bytes::from("tail"))];
        let body = Body::from_stream(rama::stream::iter(chunks));
        let mut metered = MeteredBody::wrap(
            body,
            stats.clone(),
            Host::new("example.com"),
            Direction::Up,
            None,
            None,
        );
        metered.frame().await.unwrap().unwrap();
        assert_eq!(transferred(&stats), (FLUSH_BYTES, 0));
        metered.frame().await.unwrap().unwrap();
        assert_eq!(transferred(&stats), (FLUSH_BYTES, 0));
        drop(metered);
        assert_eq!(transferred(&stats), (FLUSH_BYTES + 4, 0));
    }

    /// Capture the leading bytes of a forwarded body without changing what is forwarded.
    #[tokio::test]
    async fn captures_forwarded_bodies() {
        let stats = DomainStats::default();
        stats.capture_settings().set(true, 1);
        let capture = stats.capture_settings().begin(&rama::http::HeaderMap::new()).unwrap();
        let chunks = vec![
            Ok::<_, BoxError>(Bytes::from(vec![b'a'; 1000])),
            Ok(Bytes::from(vec![b'b'; 100])),
        ];
        let body = Body::from_stream(rama::stream::iter(chunks));
        let recorder = capture.recorder(crate::telemetry::Side::Request);
        let metered = MeteredBody::wrap(
            body,
            stats.clone(),
            Host::new("example.com"),
            Direction::Up,
            Some(recorder),
            None,
        );
        let bytes = metered.collect().await.unwrap().to_bytes();
        assert_eq!(bytes.len(), 1100);
        let body = capture.details().request.body.unwrap();
        assert_eq!((body.size, body.captured), (1100, 1024));
        assert!(body.truncated && body.complete);

        let empty = MeteredBody::wrap(
            Body::empty(),
            stats.clone(),
            Host::new("example.com"),
            Direction::Up,
            Some(capture.recorder(crate::telemetry::Side::Request)),
            None,
        );
        drop(empty);
        let body = capture.details().request.body.unwrap();
        assert_eq!(body.size, 0);
        assert!(body.complete);
    }

    /// A response body ends its request's clock when it is read to the end or abandoned.
    #[tokio::test]
    async fn ends_the_clock_with_the_body() {
        let stats = DomainStats::default();
        let read = RequestClock::start();
        let body = MeteredBody::wrap(
            Body::from("done"),
            stats.clone(),
            Host::new("example.com"),
            Direction::Down,
            None,
            Some(read.clone()),
        );
        assert!(!read.is_finished());
        body.collect().await.unwrap();
        assert!(read.is_finished());

        let abandoned = RequestClock::start();
        let chunks = vec![Ok::<_, BoxError>(Bytes::from("partial"))];
        let mut body = MeteredBody::wrap(
            Body::from_stream(rama::stream::iter(chunks)),
            stats,
            Host::new("example.com"),
            Direction::Down,
            None,
            Some(abandoned.clone()),
        );
        body.frame().await.unwrap().unwrap();
        assert!(!abandoned.is_finished());
        drop(body);
        assert!(abandoned.is_finished());
    }
}
