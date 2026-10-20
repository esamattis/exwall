//! A body wrapper that counts forwarded bytes toward a domain's transfer totals.

use crate::{
    policy::Host,
    telemetry::{Direction, DomainStats},
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
/// and flushed at the end of the stream or when the body is dropped early.
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
}

impl MeteredBody {
    /// Wrap `inner` so its data bytes count toward `host` in `direction`.
    pub fn wrap(inner: Body, stats: DomainStats, host: Host, direction: Direction) -> Body {
        Body::new(Self {
            inner,
            stats,
            host,
            direction,
            pending: 0,
        })
    }

    /// Record pending bytes and start a new batch.
    fn flush(&mut self) {
        let bytes = std::mem::take(&mut self.pending);
        self.stats.record_transfer(&self.host, self.direction, bytes);
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
                    if self.pending >= FLUSH_BYTES {
                        self.flush();
                    }
                }
            }
            Poll::Ready(Some(Err(_)) | None) => self.flush(),
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
    fn drop(&mut self) {
        self.flush();
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
        let metered =
            MeteredBody::wrap(body, stats.clone(), Host::new("example.com"), Direction::Down);
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
        let mut metered =
            MeteredBody::wrap(body, stats.clone(), Host::new("example.com"), Direction::Up);
        metered.frame().await.unwrap().unwrap();
        assert_eq!(transferred(&stats), (FLUSH_BYTES, 0));
        metered.frame().await.unwrap().unwrap();
        assert_eq!(transferred(&stats), (FLUSH_BYTES, 0));
        drop(metered);
        assert_eq!(transferred(&stats), (FLUSH_BYTES + 4, 0));
    }
}
