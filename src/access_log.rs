//! Batched, deduplicated access logging, independent of application tracing.
use crate::{
    config::AccessLogConfig,
    error::{Context, Result},
};
use std::{
    collections::{HashMap, VecDeque},
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};

/// The application protocol inspected by a request handler.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    /// A DNS message transported over UDP or TCP.
    Dns,
    /// Plaintext HTTP proxy traffic.
    Http,
    /// HTTP over TLS, including explicit CONNECT setup.
    Https,
}

impl Protocol {
    /// Return the lowercase protocol column written to the access log.
    fn name(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// The rule decision, independent of the response or subsequent processing failures.
#[derive(Debug)]
enum Decision {
    /// A matching rule or configured exception authorizes the request.
    Allow,
    /// The policy rejects the request.
    Deny,
    /// The request was not evaluated against policy.
    Unevaluated,
}

impl Decision {
    /// Render a policy decision without incorporating response codes or error categories.
    fn name(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
            Self::Unevaluated => "-",
        }
    }
}

/// A processing failure recorded separately from policy and protocol response codes.
#[derive(Debug)]
pub enum Failure {
    /// Communication with an upstream failed before a valid response arrived.
    Upstream,
    /// Waiting for an upstream exceeded the request deadline.
    UpstreamTimeout,
    /// A DNS upstream returned an invalid or mismatched response.
    InvalidDnsReply,
    /// An incoming DNS packet could not be parsed.
    MalformedDns,
    /// HTTP request metadata or an unsupported operation prevented processing.
    InvalidRequest,
    /// The local HTTP CONNECT reply service failed to establish a tunnel.
    ConnectSetup,
    /// Request processing was cancelled before producing a response.
    Cancelled,
    /// The DNS concurrency limit prevented request processing.
    Overloaded,
}

impl Failure {
    /// Return a stable error token that never contains an HTTP status or DNS response code.
    fn name(&self) -> &'static str {
        match self {
            Self::Upstream => "UPSTREAM_FAILURE",
            Self::UpstreamTimeout => "UPSTREAM_TIMEOUT",
            Self::InvalidDnsReply => "INVALID_DNS_REPLY",
            Self::MalformedDns => "MALFORMED_DNS",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ConnectSetup => "CONNECT_SETUP",
            Self::Cancelled => "CANCELLED",
            Self::Overloaded => "OVERLOADED",
        }
    }
}

/// One request's arrival time, policy match, and response outcome.
#[derive(Debug)]
pub struct Entry {
    timestamp: jiff::Timestamp,
    protocol: Protocol,
    decision: Decision,
    pub rule: String,
    method: String,
    pub url: String,
    http_status: Option<u16>,
    dns_response: Option<String>,
    error: Option<Failure>,
}

impl Entry {
    /// Capture request metadata before filtering or waiting for an upstream.
    pub fn new(protocol: Protocol, method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            timestamp: jiff::Timestamp::now(),
            protocol,
            decision: Decision::Unevaluated,
            rule: "-".into(),
            method: method.into(),
            url: url.into(),
            http_status: None,
            dns_response: None,
            error: Some(Failure::Cancelled),
        }
    }

    /// Record the rule decision even if subsequent forwarding fails or is interrupted.
    pub fn decision(&mut self, allowed: bool) {
        self.decision = if allowed {
            Decision::Allow
        } else {
            Decision::Deny
        };
    }

    /// Record the HTTP status returned to the client without inferring a processing error.
    pub fn http_response(&mut self, status: u16) {
        self.http_status = Some(status);
        self.error = None;
    }

    /// Record the DNS response code returned to the client without inferring a processing error.
    pub fn dns_response(&mut self, code: impl std::fmt::Display) {
        self.dns_response = Some(code.to_string());
        self.error = None;
    }

    /// Record why processing failed while preserving policy and any client response code.
    pub fn fail(&mut self, error: Failure) {
        self.error = Some(error);
    }

    /// Render all message fields except the timestamp for duplicate detection.
    fn message(&self) -> String {
        format!(
            "{} {} {} {} {} {} {} {}",
            self.protocol.name(),
            self.decision.name(),
            field(&self.rule),
            field(&self.method),
            field(&self.url),
            self.http_status.map(|status| status.to_string()).unwrap_or_else(|| "-".into()),
            self.dns_response.as_deref().unwrap_or("-"),
            self.error.as_ref().map(Failure::name).unwrap_or("-"),
        )
    }

    /// Produce nine columns and an optional suffix counting occurrences in the batch.
    fn line(&self, count: usize) -> String {
        let suffix = if count > 1 {
            format!(" x{count}")
        } else {
            String::new()
        };
        format!("{} {}{suffix}\n", self.timestamp, self.message())
    }
}

/// One second of messages in first-received order, with counts indexed by message text.
#[derive(Default)]
struct Batch {
    entries: Vec<(Entry, usize)>,
    indices: HashMap<String, usize>,
}

impl Batch {
    /// Collect until one second after the first receive, or flush early on channel closure.
    async fn receive(receiver: &mut mpsc::UnboundedReceiver<Entry>) -> Self {
        let mut batch = Self::default();
        let mut received = Vec::with_capacity(256);
        if receiver.recv_many(&mut received, 256).await == 0 {
            return batch;
        }
        let deadline = tokio::time::sleep(Duration::from_secs(1));
        tokio::pin!(deadline);
        loop {
            for entry in received.drain(..) {
                batch.record(entry);
            }
            tokio::select! {
                // A busy channel must not postpone the flush deadline.
                biased;
                _ = &mut deadline => break,
                count = receiver.recv_many(&mut received, 256) => {
                    if count == 0 {
                        break;
                    }
                }
            }
        }
        batch
    }

    /// Count matching messages without moving the first occurrence or changing its timestamp.
    fn record(&mut self, entry: Entry) {
        let message = entry.message();
        if let Some(&index) = self.indices.get(&message) {
            self.entries[index].1 += 1;
        } else {
            self.indices.insert(message, self.entries.len());
            self.entries.push((entry, 1));
        }
    }
}

/// Escape whitespace, controls, and percent signs to keep request data on one line.
fn field(value: &str) -> String {
    if value.is_empty() {
        return "-".into();
    }
    let mut output = String::new();
    for character in value.chars() {
        if character.is_whitespace() || character.is_control() || character == '%' {
            let mut bytes = [0; 4];
            for byte in character.encode_utf8(&mut bytes).bytes() {
                use std::fmt::Write;
                write!(output, "%{byte:02X}").expect("writing to a String cannot fail");
            }
        } else {
            output.push(character);
        }
    }
    output
}

/// Cloneable mailbox used by handlers without awaiting filesystem operations.
#[derive(Clone)]
pub struct AccessLog {
    pub domains: crate::domains::Domains,
    sender: mpsc::UnboundedSender<Entry>,
}

impl AccessLog {
    /// Open the destination before serving requests, then start its blocking actor.
    pub async fn start(config: AccessLogConfig) -> Result<(Self, JoinHandle<Result<()>>)> {
        let writer = tokio::task::spawn_blocking(move || Writer::open(config)).await??;
        let (sender, receiver) = mpsc::unbounded_channel();
        let task = tokio::task::spawn_blocking(move || writer.run(receiver));
        Ok((
            Self {
                domains: crate::domains::Domains::default(),
                sender,
            },
            task,
        ))
    }

    /// Update domain totals and queue every entry without disk access or capacity drops.
    pub fn record(&self, entry: Entry) {
        if !matches!(entry.decision, Decision::Unevaluated) {
            let allowed = matches!(entry.decision, Decision::Allow);
            let urls: Vec<_> = match entry.protocol {
                Protocol::Dns => entry.url.split(',').collect(),
                Protocol::Http | Protocol::Https => vec![entry.url.as_str()],
            };
            for url in urls {
                if let Ok(uri) = rama::net::uri::Uri::parse(url)
                    && let Some(authority) = uri.authority()
                {
                    let host = authority.host().to_string();
                    self.domains.record(&host, entry.protocol, allowed);
                    if !allowed
                        && matches!(entry.protocol, Protocol::Http | Protocol::Https)
                        && entry.method != "CONNECT"
                    {
                        self.domains.record_denial(&host, &entry.method, &uri.path_or_root());
                    }
                }
            }
        }
        if self.sender.send(entry).is_err() {
            tracing::error!("access-log actor is unavailable");
        }
    }

    /// Ensure a parsed request is logged even if its asynchronous handler is cancelled.
    pub fn track(&self, entry: Entry) -> PendingEntry {
        PendingEntry {
            log: self.clone(),
            entry: Some(entry),
        }
    }
}

/// Request-scoped guard that submits an outcome when its handler exits or is cancelled.
pub struct PendingEntry {
    log: AccessLog,
    entry: Option<Entry>,
}

impl PendingEntry {
    /// Update policy metadata and the eventual response outcome before submission.
    pub fn entry(&mut self) -> &mut Entry {
        self.entry.as_mut().expect("pending entry exists until the guard is dropped")
    }
}

impl Drop for PendingEntry {
    /// Submit exactly one entry, including requests interrupted before a response exists.
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.log.record(entry);
        }
    }
}

/// File and retention counter owned exclusively by the blocking log actor.
struct Writer {
    config: AccessLogConfig,
    file: File,
    since_check: u64,
}

impl Writer {
    /// Open a private append-only log; its parent directory must already exist.
    fn open(config: AccessLogConfig) -> Result<Self> {
        let file = open_append(&config.path)
            .with_context(|| format!("open access log {}", config.path.display()))?;
        Ok(Self {
            config,
            file,
            since_check: 0,
        })
    }

    /// Write ordered one-second batches and drain the final batch when the mailbox closes.
    fn run(mut self, mut receiver: mpsc::UnboundedReceiver<Entry>) -> Result<()> {
        let runtime = tokio::runtime::Handle::current();
        loop {
            let batch = runtime.block_on(Batch::receive(&mut receiver));
            if batch.entries.is_empty() {
                break;
            }
            for (entry, count) in batch.entries {
                self.append(&entry, count)
                    .with_context(|| format!("write access log {}", self.config.path.display()))?;
            }
        }
        self.file.flush().context("flush access log")
    }

    /// Append a counted row and inspect the file size after the configured row interval.
    fn append(&mut self, entry: &Entry, count: usize) -> Result<()> {
        self.file.write_all(entry.line(count).as_bytes())?;
        self.since_check += 1;
        if self.since_check == self.config.check_interval {
            self.since_check = 0;
            if self.file.metadata()?.len() > self.config.max_size_bytes {
                self.retain_tail()?;
            }
        }
        Ok(())
    }

    /// Atomically replace an oversized log with its newest complete entries in order.
    fn retain_tail(&mut self) -> Result<()> {
        let mut reader = BufReader::new(File::open(&self.config.path)?);
        let mut tail = VecDeque::new();
        loop {
            let mut line = Vec::new();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            // An interrupted write is not a complete access-log item.
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
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut replacement = tempfile::NamedTempFile::new_in(parent)?;
        replacement.as_file().set_permissions(self.file.metadata()?.permissions())?;
        for line in tail {
            replacement.write_all(&line)?;
        }
        replacement.flush()?;
        replacement.persist(&self.config.path)?;
        self.file = open_append(&self.config.path)?;
        Ok(())
    }
}

/// Open or create a service-private access log without truncating existing entries.
fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).mode(0o600).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Retain only evaluated HTTP denials, with normalized hosts and query-free pathnames.
    #[tokio::test]
    async fn tracks_http_denials_without_dns_connect_or_upstream_errors() {
        let directory = tempfile::tempdir().unwrap();
        let (log, task) = AccessLog::start(AccessLogConfig {
            path: directory.path().join("access.log"),
            ..AccessLogConfig::default()
        })
        .await
        .unwrap();
        for (protocol, method, url, decision) in [
            (Protocol::Dns, "-", "dns://denied.test/A", Some(false)),
            (Protocol::Http, "GET", "http://test/allowed", Some(true)),
            (Protocol::Https, "POST", "https://Test:443/a?secret=value", Some(false)),
            (Protocol::Https, "CONNECT", "https://test/", Some(false)),
            (Protocol::Http, "GET", "http://test/invalid", None),
            (Protocol::Http, "GET", "http://[::1]:80/denied", Some(false)),
        ] {
            let mut entry = Entry::new(protocol, method, url);
            if let Some(allowed) = decision {
                entry.decision(allowed);
            }
            entry.http_response(403);
            log.record(entry);
        }
        let denials = log.domains.denials_snapshot();
        assert_eq!(denials.len(), 2);
        assert_eq!(denials[0].domain, "::1");
        assert_eq!(denials[0].pathname, "/denied");
        assert_eq!(denials[1].domain, "test");
        assert_eq!(denials[1].method, "POST");
        assert_eq!(denials[1].pathname, "/a");
        drop(log);
        task.await.unwrap().unwrap();
    }

    /// Build a log item with deterministic contents for format and retention assertions.
    fn entry(index: usize) -> Entry {
        let mut entry = Entry::new(Protocol::Http, "GET", format!("http://test/{index}"));
        entry.timestamp = "2026-10-07T12:34:56Z".parse().unwrap();
        entry.rule = "test:allow#1".into();
        entry.decision(true);
        entry.http_response(200);
        entry
    }

    /// Flush at one second despite later arrivals, preserving first occurrence order and time.
    #[tokio::test(start_paused = true)]
    async fn batches_for_one_second_in_first_received_order() {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        sender.send(entry(2)).unwrap();
        sender.send(entry(1)).unwrap();
        let task = tokio::spawn(async move {
            let batch = Batch::receive(&mut receiver).await;
            (batch, receiver)
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(900)).await;
        let mut duplicate = entry(2);
        duplicate.timestamp = "2026-10-07T12:34:57Z".parse().unwrap();
        sender.send(duplicate).unwrap();
        sender.send(entry(2)).unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        let (batch, mut receiver) = task.await.unwrap();
        let lines: Vec<_> = batch.entries.iter().map(|(entry, count)| entry.line(*count)).collect();
        assert_eq!(
            lines,
            [
                "2026-10-07T12:34:56Z http ALLOW test:allow#1 GET http://test/2 200 - - x3\n"
                    .to_string(),
                entry(1).line(1),
            ]
        );

        sender.send(entry(2)).unwrap();
        drop(sender);
        let before = tokio::time::Instant::now();
        let batch = Batch::receive(&mut receiver).await;
        assert_eq!(tokio::time::Instant::now(), before);
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.entries[0].0.line(batch.entries[0].1), entry(2).line(1));
        assert!(Batch::receive(&mut receiver).await.entries.is_empty());
    }

    /// Keep messages distinct when any field other than their timestamp differs.
    #[test]
    fn deduplication_compares_every_message_field() {
        let mut batch = Batch::default();
        batch.record(entry(0));
        for index in 0..8 {
            let mut changed = entry(0);
            match index {
                0 => changed.protocol = Protocol::Https,
                1 => changed.decision(false),
                2 => changed.rule = "other:allow#1".into(),
                3 => changed.method = "POST".into(),
                4 => changed.url = "http://test/other".into(),
                5 => changed.http_response(201),
                6 => changed.dns_response("REFUSED"),
                7 => changed.fail(Failure::Upstream),
                _ => unreachable!(),
            }
            batch.record(changed);
        }
        assert_eq!(batch.entries.len(), 9);
        assert!(batch.entries.iter().all(|(_, count)| *count == 1));
    }

    /// Drain multiple channel reads on shutdown and write duplicates in stable order.
    #[tokio::test]
    async fn actor_flushes_counted_rows_on_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (log, task) = AccessLog::start(AccessLogConfig {
            path: path.clone(),
            ..AccessLogConfig::default()
        })
        .await
        .unwrap();
        for _ in 0..300 {
            log.record(entry(2));
            log.record(entry(1));
        }
        drop(log);
        task.await.unwrap().unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            entry(2).line(300) + &entry(1).line(300)
        );
    }

    /// Verify that attacker-controlled fields cannot inject rows or extra columns.
    #[test]
    fn formats_separate_columns_without_log_injection() {
        let mut entry = entry(0);
        entry.rule = "file name\nforged".into();
        entry.url = "http://test/?q=%20\r\n\t\u{2003}".into();
        assert_eq!(
            entry.line(1),
            "2026-10-07T12:34:56Z http ALLOW file%20name%0Aforged GET http://test/?q=%2520%0D%0A%09%E2%80%83 200 - -\n"
        );
        assert_eq!(entry.line(1).split_whitespace().count(), 9);
    }

    /// Check retention only at the interval, preserve newest rows, and continue appending.
    #[test]
    fn retains_tail_at_configured_size_checks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        std::fs::write(&path, entry(0).line(1)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mut writer = Writer::open(AccessLogConfig {
            path: path.clone(),
            check_interval: 3,
            max_size_bytes: 1,
            keep_entries: 2,
        })
        .unwrap();
        writer.append(&entry(1), 1).unwrap();
        writer.append(&entry(2), 1).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        writer.append(&entry(3), 1).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), entry(2).line(1) + &entry(3).line(1));
        writer.append(&entry(4), 1).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            entry(2).line(1) + &entry(3).line(1) + &entry(4).line(1)
        );
        assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o640);
    }

    /// Keep every item when a size inspection finds the log below the threshold.
    #[test]
    fn leaves_small_logs_intact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let mut writer = Writer::open(AccessLogConfig {
            path: path.clone(),
            check_interval: 1,
            max_size_bytes: 4096,
            keep_entries: 1,
        })
        .unwrap();
        writer.append(&entry(0), 1).unwrap();
        writer.append(&entry(1), 1).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), entry(0).line(1) + &entry(1).line(1));
    }

    /// Concurrent producers enqueue without waiting for disk and shutdown drains all rows.
    #[tokio::test]
    async fn actor_drains_concurrent_producers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (log, task) = AccessLog::start(AccessLogConfig {
            path: path.clone(),
            ..AccessLogConfig::default()
        })
        .await
        .unwrap();
        let mut producers = tokio::task::JoinSet::new();
        for producer in 0..4 {
            let log = log.clone();
            producers.spawn(async move {
                for index in 0..100 {
                    log.record(entry(producer * 100 + index));
                }
            });
        }
        while let Some(result) = producers.join_next().await {
            result.unwrap();
        }
        drop(log);
        task.await.unwrap().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        let urls: std::collections::HashSet<_> =
            contents.lines().map(|line| line.split_whitespace().nth(5).unwrap()).collect();
        assert_eq!(contents.lines().count(), 400);
        assert_eq!(urls.len(), 400);
    }

    /// Preserve the same client status while distinguishing upstream responses from proxy failures.
    #[test]
    fn separates_http_status_from_processing_error() {
        let mut upstream_response = entry(0);
        upstream_response.http_response(502);
        assert!(
            upstream_response
                .line(1)
                .contains(" http ALLOW test:allow#1 GET http://test/0 502 - -\n")
        );
        upstream_response.fail(Failure::Upstream);
        assert!(
            upstream_response
                .line(1)
                .contains(" http ALLOW test:allow#1 GET http://test/0 502 - UPSTREAM_FAILURE\n")
        );
        upstream_response.fail(Failure::UpstreamTimeout);
        assert!(upstream_response.line(1).ends_with(" 502 - UPSTREAM_TIMEOUT\n"));
    }

    /// Reject an unusable destination before starting request listeners.
    #[tokio::test]
    async fn reports_open_failure() {
        let directory = tempfile::tempdir().unwrap();
        let result = AccessLog::start(AccessLogConfig {
            path: directory.path().join("missing/access.log"),
            ..AccessLogConfig::default()
        })
        .await;
        assert!(result.is_err());
    }

    /// Cancellation guards submit once, and the actor waits for the final active handler.
    #[tokio::test]
    async fn logs_cancelled_requests_before_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("access.log");
        let (log, task) = AccessLog::start(AccessLogConfig {
            path: path.clone(),
            ..AccessLogConfig::default()
        })
        .await
        .unwrap();
        let guard = log.track(Entry::new(Protocol::Http, "GET", "http://test/cancelled"));
        drop(log);
        assert!(!task.is_finished());
        drop(guard);
        task.await.unwrap().unwrap();
        let contents = std::fs::read_to_string(path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("http - - GET http://test/cancelled - - CANCELLED"));
    }

    /// Surface write failures from the actor with the underlying filesystem error preserved.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reports_actor_write_failure() {
        let (log, task) = AccessLog::start(AccessLogConfig {
            path: "/dev/full".into(),
            ..AccessLogConfig::default()
        })
        .await
        .unwrap();
        log.record(entry(0));
        drop(log);
        let error = task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("write access log /dev/full"));
        assert!(std::error::Error::source(&error).is_some());
    }
}
