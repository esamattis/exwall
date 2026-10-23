//! Opt-in capture of HTTP request and response headers and bodies for the web UI.
//!
//! Capturing is off by default and lives only in memory. While it is on, each HTTP
//! request records its client headers, the response headers, and up to a size limit of
//! each body. Bodies are captured while they stream: the proxy forwards every frame as
//! soon as it arrives and only keeps cheap references to the captured prefix until the
//! body ends, when the prefix is copied into one buffer.
//!
//! A WebSocket handshake captures its headers the same way, and then the first
//! [`WEBSOCKET_MESSAGE_LIMIT`] messages in each direction instead of bodies.

use super::{event::Failure, stats::Direction};
use rama::{
    bytes::{Bytes, BytesMut},
    http::HeaderMap,
};
use serde::Serialize;
use std::{
    fmt,
    io::Read,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// The body size limit used until the UI chooses another one, in KiB.
pub const DEFAULT_BODY_LIMIT_KB: u32 = 32;
/// The largest body size limit the UI may choose, in KiB.
pub const MAX_BODY_LIMIT_KB: u32 = 1024;
/// The most decompressed bytes shown for one captured body.
const DECODED_LIMIT: usize = 4 * 1024 * 1024;
/// The most WebSocket messages kept in each direction; later ones are only counted.
pub const WEBSOCKET_MESSAGE_LIMIT: usize = 50;

/// The runtime capture switch and body size limit shared by the proxy and the UI API.
#[derive(Clone)]
pub struct CaptureSettings(Arc<SettingsState>);

/// The shared state behind [`CaptureSettings`].
struct SettingsState {
    /// Whether new requests are captured.
    enabled: AtomicBool,
    /// The most bytes kept from each body, in KiB.
    body_limit_kb: AtomicU32,
    /// The identifier assigned to the next capture.
    next_id: AtomicU64,
}

impl Default for CaptureSettings {
    /// Start with capturing off and the default body size limit.
    fn default() -> Self {
        Self(Arc::new(SettingsState {
            enabled: AtomicBool::new(false),
            body_limit_kb: AtomicU32::new(DEFAULT_BODY_LIMIT_KB),
            next_id: AtomicU64::new(1),
        }))
    }
}

impl CaptureSettings {
    /// Report whether new requests are captured.
    pub fn enabled(&self) -> bool {
        self.0.enabled.load(Ordering::Relaxed)
    }

    /// Return the most bytes kept from each body, in KiB.
    pub fn body_limit_kb(&self) -> u32 {
        self.0.body_limit_kb.load(Ordering::Relaxed)
    }

    /// Turn capturing on or off with a body size limit, clamped to the supported range.
    ///
    /// Requests already in flight keep the settings they started with.
    pub fn set(&self, enabled: bool, body_limit_kb: u32) {
        let limit = body_limit_kb.clamp(1, MAX_BODY_LIMIT_KB);
        self.0.body_limit_kb.store(limit, Ordering::Relaxed);
        self.0.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Start capturing a request with the client's `headers`, if capturing is on.
    pub fn begin(&self, headers: &HeaderMap) -> Option<Capture> {
        if !self.enabled() {
            return None;
        }
        let limit_kb = self.body_limit_kb();
        Some(Capture(Arc::new(CaptureState {
            id: self.0.next_id.fetch_add(1, Ordering::Relaxed),
            timestamp: jiff::Timestamp::now(),
            body_limit: limit_kb as usize * 1024,
            exchange: Mutex::new(Exchange {
                request: Message {
                    status: None,
                    headers: header_list(headers),
                    body: None,
                },
                response: None,
                websocket: None,
            }),
        })))
    }
}

/// One header as received, with its value decoded leniently as UTF-8.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CapturedHeader {
    /// The header name, with the case the client or upstream sent where it is known.
    pub name: String,
    /// The header value; invalid UTF-8 is replaced.
    pub value: String,
}

/// Copy a header map in order, keeping repeated headers as separate entries.
fn header_list(headers: &HeaderMap) -> Vec<CapturedHeader> {
    headers
        .iter()
        .map(|(name, value)| CapturedHeader {
            name: name.as_str().to_owned(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

/// The captured prefix of one body and how much of the body was seen.
#[derive(Clone, Debug)]
struct CapturedBody {
    /// Up to the capture's body limit of leading bytes.
    bytes: Bytes,
    /// Every data byte seen, including bytes beyond the limit.
    size: u64,
    /// Whether the body was read to its end.
    complete: bool,
}

/// The headers and body of a request or response.
#[derive(Clone, Debug)]
struct Message {
    /// The response status; `None` for requests.
    status: Option<u16>,
    /// The headers in received order.
    headers: Vec<CapturedHeader>,
    /// The body, once it has ended or been abandoned.
    body: Option<CapturedBody>,
}

/// A captured request and, once one exists, its response.
#[derive(Clone, Debug)]
struct Exchange {
    /// The request as the client sent it, before any header injection.
    request: Message,
    /// The response returned to the client.
    response: Option<Message>,
    /// The messages of a WebSocket, once its handshake succeeded.
    websocket: Option<WebSocketLog>,
}

/// What a captured WebSocket message carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageKind {
    /// A UTF-8 text message.
    Text,
    /// A binary message.
    Binary,
    /// A close message; its payload is the close reason.
    Close,
}

/// One WebSocket message kept in a capture.
#[derive(Clone, Debug)]
struct CapturedFrame {
    /// Which way the message travelled.
    direction: Direction,
    /// What the message carried.
    kind: MessageKind,
    /// The decoded payload size, including bytes that were not kept.
    size: u64,
    /// The leading payload bytes kept within the direction's byte budget.
    bytes: Bytes,
    /// The close status code of a close message, if it had one.
    code: Option<u16>,
    /// How long after the WebSocket opened the message arrived.
    at: Duration,
}

/// Message and byte totals for one direction of a WebSocket.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct MessageTally {
    /// Text and binary messages seen, including those not kept.
    pub messages: u64,
    /// Decoded text and binary payload bytes seen.
    pub bytes: u64,
    /// Messages of any kind kept in the capture.
    #[serde(skip)]
    kept: usize,
    /// Payload bytes kept in the capture.
    #[serde(skip)]
    captured: usize,
}

/// How a captured WebSocket ended.
#[derive(Clone, Copy, Debug)]
struct WebSocketEnd {
    /// How long the WebSocket stayed open.
    duration: Duration,
    /// Which side sent the first close message, if any did.
    closed_by: Option<Direction>,
    /// Why the WebSocket ended abnormally, if it did.
    failure: Option<Failure>,
}

/// The messages of a captured WebSocket.
#[derive(Clone, Debug)]
struct WebSocketLog {
    /// When the handshake completed.
    opened: Instant,
    /// The kept messages in arrival order.
    messages: Vec<CapturedFrame>,
    /// Totals from the client to the upstream.
    up: MessageTally,
    /// Totals from the upstream to the client.
    down: MessageTally,
    /// How the WebSocket ended, once it has.
    ended: Option<WebSocketEnd>,
}

/// Which message of an exchange a body belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The client's request.
    Request,
    /// The response returned to the client.
    Response,
}

/// The shared state behind [`Capture`].
struct CaptureState {
    /// A process-unique identifier the UI uses to fetch the capture.
    id: u64,
    /// When the request arrived.
    timestamp: jiff::Timestamp,
    /// The most bytes kept from each body.
    body_limit: usize,
    /// The captured messages, filled in as the request progresses.
    exchange: Mutex<Exchange>,
}

/// A request's captured headers and bodies, shared by the proxy and request history.
///
/// Bodies finish streaming after the request is recorded, so the proxy keeps filling
/// in the same capture that the request history already holds.
#[derive(Clone)]
pub struct Capture(Arc<CaptureState>);

impl fmt::Debug for Capture {
    /// Identify the capture without printing headers or bodies, which may hold secrets.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Capture").field(&self.0.id).finish()
    }
}

impl Capture {
    /// Return the identifier the UI uses to fetch this capture.
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// Lock the captured messages.
    fn exchange(&self) -> std::sync::MutexGuard<'_, Exchange> {
        self.0.exchange.lock().expect("capture lock poisoned")
    }

    /// Record the status and headers of the response returned to the client.
    pub fn record_response(&self, status: u16, headers: &HeaderMap) {
        self.exchange().response = Some(Message {
            status: Some(status),
            headers: header_list(headers),
            body: None,
        });
    }

    /// Mark the exchange as an open WebSocket whose messages are captured from now on.
    pub fn start_websocket(&self) {
        self.exchange().websocket = Some(WebSocketLog {
            opened: Instant::now(),
            messages: Vec::new(),
            up: MessageTally::default(),
            down: MessageTally::default(),
            ended: None,
        });
    }

    /// Record one decoded WebSocket message travelling in `direction`.
    ///
    /// Text and binary messages count toward the direction's totals. Messages are kept
    /// up to [`WEBSOCKET_MESSAGE_LIMIT`] per direction, and their payloads share the
    /// capture's body limit as one byte budget per direction; close reasons are
    /// always kept.
    pub fn record_websocket_message(
        &self,
        direction: Direction,
        kind: MessageKind,
        payload: &[u8],
        code: Option<u16>,
    ) {
        let body_limit = self.0.body_limit;
        let mut exchange = self.exchange();
        let Some(log) = &mut exchange.websocket else {
            return;
        };
        let at = log.opened.elapsed();
        let tally = match direction {
            Direction::Up => &mut log.up,
            Direction::Down => &mut log.down,
        };
        if kind != MessageKind::Close {
            tally.messages += 1;
            tally.bytes = tally.bytes.saturating_add(payload.len() as u64);
        }
        if tally.kept >= WEBSOCKET_MESSAGE_LIMIT {
            return;
        }
        // A close reason is at most 123 bytes and explains the close, so it is always kept.
        let room = if kind == MessageKind::Close {
            payload.len()
        } else {
            body_limit.saturating_sub(tally.captured)
        };
        let bytes = &payload[..room.min(payload.len())];
        tally.kept += 1;
        if kind != MessageKind::Close {
            tally.captured += bytes.len();
        }
        log.messages.push(CapturedFrame {
            direction,
            kind,
            size: payload.len() as u64,
            bytes: Bytes::copy_from_slice(bytes),
            code,
            at,
        });
    }

    /// Record how a WebSocket ended: which side closed it first, and any failure.
    pub fn finish_websocket(&self, closed_by: Option<Direction>, failure: Option<Failure>) {
        let mut exchange = self.exchange();
        if let Some(log) = &mut exchange.websocket {
            log.ended = Some(WebSocketEnd {
                duration: log.opened.elapsed(),
                closed_by,
                failure,
            });
        }
    }

    /// Record a complete response generated by the proxy itself.
    pub fn record_local_response(&self, status: u16, headers: &HeaderMap, body: &'static str) {
        self.record_response(status, headers);
        let mut recorder = self.recorder(Side::Response);
        recorder.observe(&Bytes::from_static(body.as_bytes()));
        recorder.finish(true);
    }

    /// Start recording the body of one side of the exchange.
    pub fn recorder(&self, side: Side) -> BodyRecorder {
        BodyRecorder {
            capture: self.clone(),
            side,
            chunks: Vec::new(),
            captured: 0,
            size: 0,
            finished: false,
        }
    }

    /// Describe the capture for the UI, decoding compressed bodies.
    pub fn details(&self) -> CaptureDetails {
        let exchange = self.exchange().clone();
        CaptureDetails {
            id: self.0.id,
            timestamp: self.0.timestamp,
            body_limit: self.0.body_limit,
            request: MessageDetails::of(&exchange.request),
            response: exchange.response.as_ref().map(MessageDetails::of),
            websocket: exchange.websocket.as_ref().map(WebSocketDetails::of),
        }
    }
}

/// Collects the leading bytes of a streaming body and stores them in a capture when it ends.
///
/// Frames are kept as reference-counted slices, so observing a frame never copies it.
pub struct BodyRecorder {
    /// Where the body is stored.
    capture: Capture,
    /// Which message the body belongs to.
    side: Side,
    /// Slices of the frames seen so far, up to the body limit.
    chunks: Vec<Bytes>,
    /// The bytes held in `chunks`.
    captured: usize,
    /// Every data byte seen.
    size: u64,
    /// Whether the body has already been stored.
    finished: bool,
}

impl BodyRecorder {
    /// Count a data frame and keep the part of it that fits within the body limit.
    pub fn observe(&mut self, data: &Bytes) {
        self.size = self.size.saturating_add(data.len() as u64);
        let room = self.capture.0.body_limit.saturating_sub(self.captured);
        if room == 0 || data.is_empty() {
            return;
        }
        let kept = data.slice(..room.min(data.len()));
        self.captured += kept.len();
        self.chunks.push(kept);
    }

    /// Report whether more bytes were seen than the body limit keeps.
    pub fn is_truncated(&self) -> bool {
        self.size > self.capture.0.body_limit as u64
    }

    /// Store the captured prefix once, noting whether the body was read to its end.
    pub fn finish(&mut self, complete: bool) {
        if std::mem::replace(&mut self.finished, true) {
            return;
        }
        let mut bytes = BytesMut::with_capacity(self.captured);
        for chunk in self.chunks.drain(..) {
            bytes.extend_from_slice(&chunk);
        }
        let body = CapturedBody {
            bytes: bytes.freeze(),
            size: self.size,
            complete,
        };
        let mut exchange = self.capture.exchange();
        match self.side {
            Side::Request => exchange.request.body = Some(body),
            Side::Response => {
                if let Some(response) = &mut exchange.response {
                    response.body = Some(body);
                }
            }
        }
    }
}

impl Drop for BodyRecorder {
    /// Store bodies that were abandoned without being explicitly finished.
    fn drop(&mut self) {
        self.finish(false);
    }
}

/// A capture as reported to the UI.
#[derive(Debug, Serialize)]
pub struct CaptureDetails {
    /// The capture identifier.
    pub id: u64,
    /// When the request arrived.
    #[serde(serialize_with = "serialize_timestamp")]
    pub timestamp: jiff::Timestamp,
    /// The most bytes kept from each body.
    pub body_limit: usize,
    /// The request as the client sent it.
    pub request: MessageDetails,
    /// The response returned to the client, once its headers exist.
    pub response: Option<MessageDetails>,
    /// The messages of a WebSocket; absent for other requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub websocket: Option<WebSocketDetails>,
}

/// The captured messages of a WebSocket as reported to the UI.
#[derive(Debug, Serialize)]
pub struct WebSocketDetails {
    /// The most messages kept in each direction.
    pub message_limit: usize,
    /// The kept messages in arrival order.
    pub messages: Vec<WebSocketMessageDetails>,
    /// Totals from the client to the upstream.
    pub up: MessageTally,
    /// Totals from the upstream to the client.
    pub down: MessageTally,
    /// How the WebSocket ended; absent while it is open.
    pub ended: Option<WebSocketEndDetails>,
}

impl WebSocketDetails {
    /// Describe a captured WebSocket.
    fn of(log: &WebSocketLog) -> Self {
        Self {
            message_limit: WEBSOCKET_MESSAGE_LIMIT,
            messages: log.messages.iter().map(WebSocketMessageDetails::of).collect(),
            up: log.up,
            down: log.down,
            ended: log.ended.map(|ended| WebSocketEndDetails {
                duration_ms: duration_ms(ended.duration),
                closed_by: ended.closed_by.map(peer_name),
                failure: ended.failure.map(Failure::name),
            }),
        }
    }
}

/// One captured WebSocket message as reported to the UI.
#[derive(Debug, Serialize)]
pub struct WebSocketMessageDetails {
    /// `up` from the client to the upstream, or `down` back to the client.
    pub direction: &'static str,
    /// What the message carried.
    pub kind: MessageKind,
    /// The decoded payload size.
    pub size: u64,
    /// The payload bytes kept.
    pub captured: usize,
    /// Milliseconds after the WebSocket opened.
    pub at_ms: u64,
    /// The close status code of a close message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    /// The kept payload as text, when it is valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The kept payload in hexadecimal, when it is not text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

impl WebSocketMessageDetails {
    /// Describe a kept message, as text when possible and in hexadecimal otherwise.
    fn of(frame: &CapturedFrame) -> Self {
        let cut = frame.size > frame.bytes.len() as u64;
        let text = text(&frame.bytes, cut);
        let hex = if text.is_none() {
            Some(frame.bytes.iter().map(|byte| format!("{byte:02x}")).collect())
        } else {
            None
        };
        Self {
            direction: match frame.direction {
                Direction::Up => "up",
                Direction::Down => "down",
            },
            kind: frame.kind,
            size: frame.size,
            captured: frame.bytes.len(),
            at_ms: duration_ms(frame.at),
            code: frame.code,
            text,
            hex,
        }
    }
}

/// How a WebSocket ended, as reported to the UI.
#[derive(Debug, Serialize)]
pub struct WebSocketEndDetails {
    /// How long the WebSocket stayed open, in milliseconds.
    pub duration_ms: u64,
    /// `client` or `server`, whichever sent the first close message; absent when neither did.
    pub closed_by: Option<&'static str>,
    /// The access-log error token for an abnormal end; absent after a close handshake.
    pub failure: Option<&'static str>,
}

/// Name the peer that sends messages travelling in `direction`.
fn peer_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Up => "client",
        Direction::Down => "server",
    }
}

/// Convert a duration to whole milliseconds, saturating.
pub(super) fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// A request or response as reported to the UI.
#[derive(Debug, Serialize)]
pub struct MessageDetails {
    /// The response status; absent for requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The headers in received order.
    pub headers: Vec<CapturedHeader>,
    /// The body; absent while it is still streaming.
    pub body: Option<BodyDetails>,
}

impl MessageDetails {
    /// Describe a captured message, decoding its body according to its headers.
    fn of(message: &Message) -> Self {
        let encoding = message
            .headers
            .iter()
            .find(|header| header.name == "content-encoding")
            .map(|header| header.value.trim().to_ascii_lowercase())
            .filter(|encoding| !encoding.is_empty() && encoding != "identity");
        Self {
            status: message.status,
            headers: message.headers.clone(),
            body: message.body.as_ref().map(|body| BodyDetails::of(body, encoding)),
        }
    }
}

/// A captured body as reported to the UI.
#[derive(Debug, Serialize)]
pub struct BodyDetails {
    /// Every data byte seen, including bytes beyond the limit.
    pub size: u64,
    /// The bytes kept.
    pub captured: usize,
    /// Whether bytes beyond the limit were not kept.
    pub truncated: bool,
    /// Whether the body was read to its end.
    pub complete: bool,
    /// The body's `Content-Encoding`, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// Whether `text` was decompressed from `encoding`.
    pub decoded: bool,
    /// The body as text, or absent when it is not valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl BodyDetails {
    /// Describe a body, decompressing it first when its encoding is supported.
    fn of(body: &CapturedBody, encoding: Option<String>) -> Self {
        let decompressed = encoding.as_deref().and_then(|encoding| decode(encoding, &body.bytes));
        let decoded = decompressed.is_some();
        let bytes = decompressed.as_deref().unwrap_or(&body.bytes);
        Self {
            size: body.size,
            captured: body.bytes.len(),
            truncated: body.size > body.bytes.len() as u64,
            complete: body.complete,
            encoding,
            decoded,
            // Truncation and decompression limits can both cut a body short.
            text: text(bytes, true),
        }
    }
}

/// Decompress a possibly truncated body, keeping whatever decodes before an error.
///
/// Returns `None` for unsupported encodings and when nothing could be decoded.
fn decode(encoding: &str, bytes: &[u8]) -> Option<Vec<u8>> {
    let reader: Box<dyn Read + '_> = match encoding {
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(bytes)),
        "deflate" if has_zlib_header(bytes) => Box::new(flate2::read::ZlibDecoder::new(bytes)),
        "deflate" => Box::new(flate2::read::DeflateDecoder::new(bytes)),
        "br" => Box::new(brotli::Decompressor::new(bytes, 4096)),
        "zstd" => Box::new(zstd::stream::read::Decoder::new(bytes).ok()?),
        _ => return None,
    };
    let mut decoded = Vec::new();
    // A truncated body ends with a decoding error after its complete blocks.
    let _ = reader.take(DECODED_LIMIT as u64).read_to_end(&mut decoded);
    (!decoded.is_empty() || bytes.is_empty()).then_some(decoded)
}

/// Report whether a `deflate` body starts with a zlib header, as the HTTP standard requires.
///
/// Some servers send raw deflate data instead, which has no such header.
fn has_zlib_header(bytes: &[u8]) -> bool {
    match bytes {
        [method, flags, ..] => {
            method & 0x0f == 8 && (u16::from(*method) << 8 | u16::from(*flags)) % 31 == 0
        }
        _ => false,
    }
}

/// Return the bytes as text, or `None` when they are not valid UTF-8.
///
/// When `cut` says the bytes may have been cut short, a multi-byte character
/// cut off at the end is dropped instead of making the bytes invalid.
fn text(bytes: &[u8], cut: bool) -> Option<String> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text.to_owned()),
        Err(error) if cut && error.error_len().is_none() => {
            let valid = &bytes[..error.valid_up_to()];
            Some(String::from_utf8_lossy(valid).into_owned())
        }
        Err(_) => None,
    }
}

/// Encode a timestamp as RFC 3339 for API consumers.
fn serialize_timestamp<S: serde::Serializer>(
    timestamp: &jiff::Timestamp,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::HeaderValue;
    use std::io::Write;

    /// Build enabled settings with a body limit of `limit_kb` KiB.
    fn settings(limit_kb: u32) -> CaptureSettings {
        let settings = CaptureSettings::default();
        settings.set(true, limit_kb);
        settings
    }

    /// Build a header map from name and value pairs.
    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    /// Capturing is off by default and creates nothing until enabled.
    #[test]
    fn starts_disabled_with_the_default_limit() {
        let settings = CaptureSettings::default();
        assert!(!settings.enabled());
        assert_eq!(settings.body_limit_kb(), DEFAULT_BODY_LIMIT_KB);
        assert!(settings.begin(&HeaderMap::new()).is_none());
        settings.set(true, 0);
        assert_eq!(settings.body_limit_kb(), 1);
        settings.set(true, MAX_BODY_LIMIT_KB + 1);
        assert_eq!(settings.body_limit_kb(), MAX_BODY_LIMIT_KB);
        let first = settings.begin(&HeaderMap::new()).unwrap();
        let second = settings.begin(&HeaderMap::new()).unwrap();
        assert_ne!(first.id(), second.id());
    }

    /// Bodies keep only the leading bytes within the limit but count every byte.
    #[test]
    fn truncates_bodies_at_the_limit() {
        let capture = settings(1).begin(&headers(&[("x-test", "a"), ("x-test", "b")])).unwrap();
        let mut recorder = capture.recorder(Side::Request);
        recorder.observe(&Bytes::from(vec![b'a'; 1000]));
        assert!(!recorder.is_truncated());
        recorder.observe(&Bytes::from(vec![b'b'; 1000]));
        assert!(recorder.is_truncated());
        recorder.finish(true);
        let details = capture.details();
        assert_eq!(details.request.headers.len(), 2);
        assert_eq!(details.request.headers[1].value, "b");
        let body = details.request.body.unwrap();
        assert_eq!((body.size, body.captured), (2000, 1024));
        assert!(body.truncated && body.complete);
        let text = body.text.unwrap();
        assert!(text.starts_with(&"a".repeat(1000)) && text.ends_with(&"b".repeat(24)));
        assert!(details.response.is_none());
    }

    /// Abandoned bodies are stored when their recorder is dropped and marked incomplete.
    #[test]
    fn stores_abandoned_bodies() {
        let capture = settings(1).begin(&HeaderMap::new()).unwrap();
        capture.record_response(200, &headers(&[("content-type", "text/plain")]));
        let mut recorder = capture.recorder(Side::Response);
        recorder.observe(&Bytes::from_static(b"partial"));
        assert!(capture.details().response.unwrap().body.is_none());
        drop(recorder);
        let response = capture.details().response.unwrap();
        assert_eq!(response.status, Some(200));
        let body = response.body.unwrap();
        assert!(!body.complete && !body.truncated);
        assert_eq!(body.text.as_deref(), Some("partial"));
    }

    /// Compressed bodies are decoded, even when truncated, and binary bodies have no text.
    #[test]
    fn decodes_compressed_and_detects_binary_bodies() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all("é".repeat(5000).as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let capture = settings(1).begin(&HeaderMap::new()).unwrap();
        capture.record_response(200, &headers(&[("content-encoding", "GZIP")]));
        let mut recorder = capture.recorder(Side::Response);
        recorder.observe(&Bytes::from(compressed));
        recorder.finish(true);
        let body = capture.details().response.unwrap().body.unwrap();
        assert!(body.decoded);
        assert_eq!(body.encoding.as_deref(), Some("gzip"));
        assert_eq!(body.text.as_deref(), Some("é".repeat(5000).as_str()));

        let capture = settings(1).begin(&HeaderMap::new()).unwrap();
        let mut recorder = capture.recorder(Side::Request);
        recorder.observe(&Bytes::from_static(&[0xff, 0xfe, 0x00]));
        recorder.finish(true);
        assert_eq!(capture.details().request.body.unwrap().text, None);
    }

    /// Text cut inside a multi-byte character keeps the complete characters before it.
    #[test]
    fn trims_characters_split_by_truncation() {
        assert_eq!(text("aé".as_bytes(), true).as_deref(), Some("aé"));
        assert_eq!(text(&"aé".as_bytes()[..2], true).as_deref(), Some("a"));
        assert_eq!(text(&"aé".as_bytes()[..2], false), None);
        assert_eq!(text(&[b'a', 0xff, b'b'], true), None);
    }

    /// WebSocket captures keep the first messages per direction within the byte budget.
    #[test]
    fn records_websocket_messages_within_limits() {
        let capture = settings(1).begin(&HeaderMap::new()).unwrap();
        capture.record_websocket_message(Direction::Up, MessageKind::Text, b"ignored", None);
        assert!(capture.details().websocket.is_none());
        capture.record_response(101, &HeaderMap::new());
        capture.start_websocket();
        capture.record_websocket_message(Direction::Up, MessageKind::Text, b"hello", None);
        capture.record_websocket_message(Direction::Down, MessageKind::Binary, &[0xff; 2000], None);
        for _ in 0..WEBSOCKET_MESSAGE_LIMIT {
            capture.record_websocket_message(Direction::Up, MessageKind::Binary, b"x", None);
        }
        capture.record_websocket_message(Direction::Down, MessageKind::Close, b"bye", Some(1000));
        capture.finish_websocket(Some(Direction::Down), None);
        let websocket = capture.details().websocket.unwrap();
        assert_eq!(websocket.messages.len(), WEBSOCKET_MESSAGE_LIMIT + 2);
        assert_eq!((websocket.up.messages, websocket.up.bytes), (51, 55));
        assert_eq!((websocket.down.messages, websocket.down.bytes), (1, 2000));
        let first = &websocket.messages[0];
        assert_eq!((first.direction, first.kind), ("up", MessageKind::Text));
        assert_eq!(first.text.as_deref(), Some("hello"));
        let binary = &websocket.messages[1];
        assert_eq!((binary.size, binary.captured), (2000, 1024));
        assert_eq!(binary.text, None);
        assert_eq!(binary.hex.as_deref().map(str::len), Some(2048));
        let close = websocket.messages.last().unwrap();
        assert_eq!((close.kind, close.code), (MessageKind::Close, Some(1000)));
        assert_eq!(close.text.as_deref(), Some("bye"));
        let ended = websocket.ended.unwrap();
        assert_eq!((ended.closed_by, ended.failure), (Some("server"), None));
        let serialized = serde_json::to_value(capture.details()).unwrap();
        assert_eq!(serialized["websocket"]["messages"][0]["kind"], "text");
        assert_eq!(serialized["websocket"]["up"]["messages"], 51);
    }

    /// Local responses are recorded complete with their status, headers, and body.
    #[test]
    fn records_local_responses() {
        let capture = settings(1).begin(&HeaderMap::new()).unwrap();
        capture.record_local_response(403, &HeaderMap::new(), "denied\n");
        let response = capture.details().response.unwrap();
        assert_eq!(response.status, Some(403));
        let body = response.body.unwrap();
        assert!(body.complete);
        assert_eq!(body.text.as_deref(), Some("denied\n"));
        let serialized = serde_json::to_value(capture.details()).unwrap();
        assert_eq!(serialized["request"]["body"], serde_json::Value::Null);
        assert!(serialized["request"].get("status").is_none());
    }
}
