//! The access-log file writer and the actor task that batches events into it.

use super::{
    batcher::Batcher,
    event::RequestEvent,
    format,
    sink::{EventReceiver, EventSink},
};
use crate::config::AccessLogConfig;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::{task::JoinHandle, time::Instant};

/// How long events are batched after the first arrival.
const BATCH_WINDOW: Duration = Duration::from_secs(1);
/// Events received from the queue per wakeup.
const RECEIVE_CHUNK: usize = 256;

/// Access-log failures, which stop the service rather than silently losing logs.
#[derive(Debug, Error)]
pub enum AccessLogError {
    /// The log file could not be opened.
    #[error("open access log {}", path.display())]
    Open {
        /// The configured access-log path.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// A row could not be written or the file could not be trimmed.
    #[error("write access log {}", path.display())]
    Write {
        /// The configured access-log path.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// Buffered rows could not be flushed at shutdown.
    #[error("flush access log {}", path.display())]
    Flush {
        /// The configured access-log path.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// A blocking file task panicked or was cancelled.
    #[error("access-log file task failed")]
    Task(#[from] tokio::task::JoinError),
}

/// The running access-log actor.
pub type AccessLogTask = JoinHandle<Result<(), AccessLogError>>;

/// Open the log before serving requests, then start the actor that owns it.
///
/// The actor exits after every [`EventSink`] clone has been dropped and the
/// final batch has been written.
pub async fn start(config: AccessLogConfig) -> Result<(EventSink, AccessLogTask), AccessLogError> {
    let writer = tokio::task::spawn_blocking(move || AccessLogWriter::open(config)).await??;
    let (sink, receiver) = EventSink::channel();
    let task = tokio::spawn(run(writer, receiver));
    Ok((sink, task))
}

/// Batch events for one second, write each batch off the async runtime, and drain on close.
async fn run(writer: AccessLogWriter, mut receiver: EventReceiver) -> Result<(), AccessLogError> {
    let mut writer = writer;
    let mut batcher = Batcher::new(BATCH_WINDOW);
    let mut received = Vec::with_capacity(RECEIVE_CHUNK);
    loop {
        let deadline = batcher.deadline();
        let closed = tokio::select! {
            // A busy queue must not postpone the flush deadline.
            biased;
            () = sleep_until(deadline) => false,
            count = receiver.events.recv_many(&mut received, RECEIVE_CHUNK) => {
                if count > 0 {
                    let now = Instant::now();
                    for event in received.drain(..) {
                        batcher.push(event, now);
                    }
                    continue;
                }
                true
            }
        };
        writer = write_batch(writer, batcher.take()).await?;
        if closed {
            break;
        }
    }
    tokio::task::spawn_blocking(move || writer.flush()).await?
}

/// Sleep until a batch deadline, or forever when no batch is open.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Write a batch on the blocking pool, returning the writer for reuse.
async fn write_batch(
    mut writer: AccessLogWriter,
    batch: Vec<(RequestEvent, usize)>,
) -> Result<AccessLogWriter, AccessLogError> {
    if batch.is_empty() {
        return Ok(writer);
    }
    let (writer, result) = tokio::task::spawn_blocking(move || {
        let result = writer.write_batch(&batch);
        (writer, result)
    })
    .await?;
    result?;
    Ok(writer)
}

/// The file and retention counter owned exclusively by the access-log actor.
pub struct AccessLogWriter {
    /// Destination and retention settings.
    config: AccessLogConfig,
    /// The append-only file.
    file: File,
    /// Rows written since the last size check.
    since_check: u64,
}

impl AccessLogWriter {
    /// Open a private append-only log; its parent directory must already exist.
    pub fn open(config: AccessLogConfig) -> Result<Self, AccessLogError> {
        let file = open_append(&config.path).map_err(|source| AccessLogError::Open {
            path: config.path.clone(),
            source,
        })?;
        Ok(Self {
            config,
            file,
            since_check: 0,
        })
    }

    /// Append every counted row of a batch in order.
    pub fn write_batch(&mut self, batch: &[(RequestEvent, usize)]) -> Result<(), AccessLogError> {
        for (event, count) in batch {
            self.append(event, *count).map_err(|source| AccessLogError::Write {
                path: self.config.path.clone(),
                source,
            })?;
        }
        Ok(())
    }

    /// Flush buffered data to the file.
    pub fn flush(&mut self) -> Result<(), AccessLogError> {
        self.file.flush().map_err(|source| AccessLogError::Flush {
            path: self.config.path.clone(),
            source,
        })
    }

    /// Append a counted row and inspect the file size after the configured row interval.
    fn append(&mut self, event: &RequestEvent, count: usize) -> io::Result<()> {
        self.file.write_all(format::line(event, count).as_bytes())?;
        self.since_check += 1;
        if self.since_check == self.config.check_interval {
            self.since_check = 0;
            if self.file.metadata()?.len() > self.config.max_size_bytes {
                self.retain_tail()?;
            }
        }
        Ok(())
    }

    /// Atomically replace an oversized log with its newest complete rows in order.
    fn retain_tail(&mut self) -> io::Result<()> {
        let mut reader = BufReader::new(File::open(&self.config.path)?);
        let mut tail = VecDeque::new();
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            // An interrupted write is not a complete access-log row.
            if line.last() == Some(&b'\n') {
                tail.push_back(line);
                if tail.len() > self.config.keep_entries {
                    tail.pop_front();
                }
            }
        }
        let parent = self
            .config
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut replacement = tempfile::NamedTempFile::new_in(parent)?;
        replacement.as_file().set_permissions(self.file.metadata()?.permissions())?;
        for line in tail {
            replacement.write_all(&line)?;
        }
        replacement.flush()?;
        replacement.persist(&self.config.path).map_err(|error| error.error)?;
        self.file = open_append(&self.config.path)?;
        Ok(())
    }
}

/// Open or create a service-private access log without truncating existing rows.
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).mode(0o600).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{
        event::Protocol,
        format::{line, tests::event},
    };
    use std::os::unix::fs::PermissionsExt;

    /// Build a writer configuration for a temporary file.
    fn config(path: &Path) -> AccessLogConfig {
        AccessLogConfig {
            path: path.to_owned(),
            ..AccessLogConfig::default()
        }
    }

    /// Drain multiple queue reads on shutdown and write duplicates in stable order.
    #[tokio::test]
    async fn actor_flushes_counted_rows_on_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (sink, task) = start(config(&path)).await.unwrap();
        for _ in 0..300 {
            sink.submit(event(2));
            sink.submit(event(1));
        }
        drop(sink);
        task.await.unwrap().unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            line(&event(2), 300) + &line(&event(1), 300)
        );
    }

    /// Check retention only at the interval, preserve newest rows, and continue appending.
    #[test]
    fn retains_tail_at_configured_size_checks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        std::fs::write(&path, line(&event(0), 1)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mut writer = AccessLogWriter::open(AccessLogConfig {
            path: path.clone(),
            check_interval: 3,
            max_size_bytes: 1,
            keep_entries: 2,
        })
        .unwrap();
        writer.append(&event(1), 1).unwrap();
        writer.append(&event(2), 1).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        writer.append(&event(3), 1).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            line(&event(2), 1) + &line(&event(3), 1)
        );
        writer.append(&event(4), 1).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            line(&event(2), 1) + &line(&event(3), 1) + &line(&event(4), 1)
        );
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o640);
    }

    /// Keep every row when a size inspection finds the log below the threshold.
    #[test]
    fn leaves_small_logs_intact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let mut writer = AccessLogWriter::open(AccessLogConfig {
            path: path.clone(),
            check_interval: 1,
            max_size_bytes: 4096,
            keep_entries: 1,
        })
        .unwrap();
        writer.append(&event(0), 1).unwrap();
        writer.append(&event(1), 1).unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            line(&event(0), 1) + &line(&event(1), 1)
        );
    }

    /// Concurrent producers enqueue without waiting for disk and shutdown drains all rows.
    #[tokio::test]
    async fn actor_drains_concurrent_producers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (sink, task) = start(config(&path)).await.unwrap();
        let mut producers = tokio::task::JoinSet::new();
        for producer in 0..4 {
            let sink = sink.clone();
            producers.spawn(async move {
                for index in 0..100 {
                    sink.submit(event(producer * 100 + index));
                }
            });
        }
        while let Some(result) = producers.join_next().await {
            result.unwrap();
        }
        drop(sink);
        task.await.unwrap().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        let urls: std::collections::HashSet<_> =
            contents.lines().map(|line| line.split_whitespace().nth(5).unwrap()).collect();
        assert_eq!(contents.lines().count(), 400);
        assert_eq!(urls.len(), 400);
    }

    /// Reject an unusable destination before starting request listeners.
    #[tokio::test]
    async fn reports_open_failure() {
        let directory = tempfile::tempdir().unwrap();
        let result = start(config(&directory.path().join("missing/access.log"))).await;
        assert!(matches!(result, Err(AccessLogError::Open { .. })));
    }

    /// Cancellation guards submit once, and the actor waits for the final active handler.
    #[tokio::test]
    async fn logs_cancelled_requests_before_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (sink, task) = start(config(&path)).await.unwrap();
        let guard = sink.track(RequestEvent::http(Protocol::Http, "GET", "http://test/cancelled"));
        drop(sink);
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        drop(guard);
        task.await.unwrap().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("http - - GET http://test/cancelled - - CANCELLED"));
    }

    /// Batches stay open for the window and flush without waiting for shutdown.
    #[tokio::test(start_paused = true)]
    async fn actor_flushes_after_the_batch_window() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (sink, task) = start(config(&path)).await.unwrap();
        sink.submit(event(1));
        sink.submit(event(1));
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        tokio::time::sleep(Duration::from_millis(600)).await;
        // The write runs on the blocking pool, outside the paused clock.
        for _ in 0..500 {
            if !std::fs::read_to_string(&path).unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), line(&event(1), 2));
        drop(sink);
        task.await.unwrap().unwrap();
    }

    /// Surface write failures from the actor with the underlying filesystem error preserved.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reports_actor_write_failure() {
        let (sink, task) = start(config(Path::new("/dev/full"))).await.unwrap();
        sink.submit(event(0));
        drop(sink);
        let error = task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("write access log /dev/full"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
