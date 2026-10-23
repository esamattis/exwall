//! HTTP/1.1 WebSockets: recognizing and forwarding handshakes, and relaying the
//! upgraded connections message by message.
//!
//! Both upgraded connections are decoded into WebSocket messages by Rama's relay,
//! so permessage-deflate is decompressed and recompressed with the parameters the
//! upstream accepted, and captures show decoded messages rather than raw frames.

use crate::{
    policy::Host,
    telemetry::{Capture, Direction, DomainStats, Failure, MessageKind},
};
use rama::{
    Service,
    extensions::{Extensions, ExtensionsRef},
    futures::{Sink, Stream},
    http::{
        Body, HeaderMap, HeaderValue, Method, Request, Response, Version,
        header::{self, HeaderName},
        io::upgrade::Upgraded,
        ws::{
            AsyncWebSocket, Message, ProtocolError,
            handshake::{
                client::apply_response_data_to_base_websocket_config,
                mitm::{WebSocketBridge, WebSocketRelayService},
            },
            protocol::{Role, WebSocketConfig},
        },
    },
    service::MirrorService,
};
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use thiserror::Error;
use tokio::time::{Instant, sleep_until};

/// How long an open WebSocket may carry no messages in either direction before it is dropped.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Publish pending byte counts once this many bytes accumulate.
const FLUSH_BYTES: u64 = 64 * 1024;
/// The longest a quiet WebSocket's byte counts wait before they are published.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// The only WebSocket extension the relay can decode.
const PERMESSAGE_DEFLATE: &str = "permessage-deflate";
/// The largest message, after decompression, the relay assembles in either direction.
///
/// The relay holds whole messages in memory, so this bounds the memory one
/// WebSocket can use. Rama's default is 64 MiB.
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;
/// The largest single frame payload the relay accepts in either direction.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;
/// The deflate window sizes, in bits, the relay's compression library supports.
///
/// RFC 7692 also allows 8, but zlib cannot compress with a window that small.
const WINDOW_BITS: std::ops::RangeInclusive<u8> = 9..=15;

/// Why an upstream's `101 Switching Protocols` response cannot be relayed.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The upstream switched to something other than a WebSocket.
    #[error("upstream switched protocols without Upgrade: websocket")]
    NotWebSocket,
    /// The upstream accepted an extension the relay cannot decode.
    #[error("upstream accepted unsupported WebSocket extensions: {0}")]
    UnsupportedExtensions(String),
    /// The upstream accepted permessage-deflate with parameters the relay cannot use.
    #[error("upstream accepted unsupported permessage-deflate parameters: {0}")]
    UnsupportedDeflate(String),
}

/// Report whether a comma-separated header contains `token`, ignoring ASCII case.
fn has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| item.trim().eq_ignore_ascii_case(token))
}

/// Report whether a request declares a body through `Content-Length` or `Transfer-Encoding`.
///
/// A `Content-Length` of zero is not a body.
fn declares_body(request: &Request) -> bool {
    if request.headers().contains_key(header::TRANSFER_ENCODING) {
        return true;
    }
    request
        .headers()
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .any(|value| value.to_str().map_or(true, |length| length.trim() != "0"))
}

/// Report whether a request is an HTTP/1.1 WebSocket opening handshake: a `GET` with
/// `Upgrade: websocket`, an `upgrade` token in `Connection`, and no body.
///
/// A request with a body is not relayed as a WebSocket, because the body would
/// precede the client's first frames. It is forwarded as a plain request instead.
pub fn is_websocket_handshake(request: &Request) -> bool {
    request.version() == Version::HTTP_11
        && request.method() == Method::GET
        && has_token(request.headers(), header::UPGRADE, "websocket")
        && has_token(request.headers(), header::CONNECTION, "upgrade")
        && !declares_body(request)
}

/// Return the extension names in a `Sec-WebSocket-Extensions` header, in order.
fn extension_offers(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SEC_WEBSOCKET_EXTENSIONS)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|offer| !offer.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Return the name of one extension offer, before its parameters.
fn extension_name(offer: &str) -> &str {
    offer.split(';').next().unwrap_or_default().trim()
}

/// Build the handshake sent upstream from a client handshake whose plan was applied.
///
/// Applying the plan removed the client's hop-by-hop headers, so the upgrade headers
/// are restored here. Only `permessage-deflate` extension offers are kept, because
/// the relay cannot decode messages of other extensions. The request is rebuilt
/// without the client connection's extensions and body, and without headers that
/// would announce a body.
pub fn upstream_handshake(request: &Request) -> Request {
    let mut headers = request.headers().clone();
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    let offers: Vec<String> = extension_offers(&headers)
        .into_iter()
        .filter(|offer| extension_name(offer).eq_ignore_ascii_case(PERMESSAGE_DEFLATE))
        .collect();
    headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);
    if !offers.is_empty()
        && let Ok(value) = HeaderValue::from_str(&offers.join(", "))
    {
        headers.insert(header::SEC_WEBSOCKET_EXTENSIONS, value);
    }
    let mut handshake = Request::new(Body::empty());
    *handshake.method_mut() = Method::GET;
    *handshake.uri_mut() = request.uri().clone();
    *handshake.version_mut() = Version::HTTP_11;
    *handshake.headers_mut() = headers;
    handshake
}

/// Return the relay's configuration before any extension is negotiated: Rama's
/// defaults with the message and frame size limits lowered.
fn base_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .with_max_message_size(MAX_MESSAGE_SIZE)
        .with_max_frame_size(MAX_FRAME_SIZE)
}

/// Check an upstream's `101` response and return the WebSocket configuration it negotiated.
///
/// The response may accept at most one extension, `permessage-deflate`, whose
/// parameters then apply to both relayed connections. Its parameters must parse,
/// and any window sizes must be ones the compression library supports, so that
/// both connections decode the messages the client was told to expect.
pub fn negotiated_config(response: &mut Response) -> Result<WebSocketConfig, HandshakeError> {
    if !has_token(response.headers(), header::UPGRADE, "websocket") {
        return Err(HandshakeError::NotWebSocket);
    }
    let accepted = extension_offers(response.headers());
    let supported = match accepted.as_slice() {
        [] => true,
        [only] => extension_name(only).eq_ignore_ascii_case(PERMESSAGE_DEFLATE),
        _ => false,
    };
    if !supported {
        return Err(HandshakeError::UnsupportedExtensions(accepted.join(", ")));
    }
    let config = apply_response_data_to_base_websocket_config(Some(base_config()), response)
        .unwrap_or_else(base_config);
    if let [deflate] = accepted.as_slice() {
        let usable = config.per_message_deflate.is_some_and(|parameters| {
            [parameters.client_max_window_bits, parameters.server_max_window_bits]
                .into_iter()
                .flatten()
                .all(|bits| WINDOW_BITS.contains(&bits))
        });
        if !usable {
            return Err(HandshakeError::UnsupportedDeflate(deflate.clone()));
        }
    }
    Ok(config)
}

/// How a WebSocket started to end, as first observed on either connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// The peer sending in this direction sent a close message.
    Closed(Direction),
    /// The peer sending in this direction disconnected or broke the protocol
    /// without a close message.
    Disconnected(Direction),
}

/// Mutable bookkeeping for one open WebSocket.
struct SessionState {
    /// When either peer last sent a message, including pings and pongs.
    last_activity: Instant,
    /// Client-to-upstream payload bytes not yet published.
    pending_up: u64,
    /// Upstream-to-client payload bytes not yet published.
    pending_down: u64,
    /// The first sign that the WebSocket is ending.
    ending: Option<Ending>,
}

/// Counts, captures, and watches the messages of one open WebSocket.
pub struct Session {
    /// Where transferred bytes are recorded.
    stats: DomainStats,
    /// The authorized host the bytes are attributed to.
    host: Host,
    /// The handshake's capture, while capturing was on when it arrived.
    capture: Option<Capture>,
    /// Activity, pending byte counts, and how the WebSocket is ending.
    state: Mutex<SessionState>,
}

impl Session {
    /// Start tracking a WebSocket whose bytes count toward `host`.
    pub fn new(stats: DomainStats, host: Host, capture: Option<Capture>) -> Arc<Self> {
        Arc::new(Self {
            stats,
            host,
            capture,
            state: Mutex::new(SessionState {
                last_activity: Instant::now(),
                pending_up: 0,
                pending_down: 0,
                ending: None,
            }),
        })
    }

    /// Lock the mutable bookkeeping.
    fn state(&self) -> std::sync::MutexGuard<'_, SessionState> {
        self.state.lock().expect("WebSocket session lock poisoned")
    }

    /// Record one item read from the peer sending in `direction`.
    ///
    /// `None` and errors mean the connection ended; the first close message or
    /// connection end decides how the WebSocket is reported to have ended.
    fn observe(&self, direction: Direction, item: Option<&Result<Message, ProtocolError>>) {
        let mut state = self.state();
        let message = match item {
            Some(Ok(message)) => message,
            Some(Err(_)) | None => {
                state.ending.get_or_insert(Ending::Disconnected(direction));
                return;
            }
        };
        if state.ending.is_some() {
            // The relay discards what arrives once the WebSocket is ending.
            return;
        }
        state.last_activity = Instant::now();
        let (kind, payload, code): (MessageKind, &[u8], Option<u16>) = match message {
            Message::Text(text) => (MessageKind::Text, text.as_ref(), None),
            Message::Binary(bytes) => (MessageKind::Binary, bytes, None),
            Message::Close(frame) => {
                state.ending.get_or_insert(Ending::Closed(direction));
                match frame {
                    Some(frame) => {
                        (MessageKind::Close, frame.reason.as_ref(), Some(frame.code.into()))
                    }
                    None => (MessageKind::Close, &[], None),
                }
            }
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => return,
        };
        if kind != MessageKind::Close {
            let pending = match direction {
                Direction::Up => &mut state.pending_up,
                Direction::Down => &mut state.pending_down,
            };
            *pending += payload.len() as u64;
            if *pending >= FLUSH_BYTES {
                let bytes = std::mem::take(pending);
                self.stats.record_transfer(&self.host, direction, bytes);
            }
        }
        drop(state);
        if let Some(capture) = &self.capture {
            capture.record_websocket_message(direction, kind, payload, code);
        }
    }

    /// Publish pending byte counts to the domain statistics.
    fn flush(&self) {
        let (up, down) = {
            let mut state = self.state();
            (std::mem::take(&mut state.pending_up), std::mem::take(&mut state.pending_down))
        };
        self.stats.record_transfer(&self.host, Direction::Up, up);
        self.stats.record_transfer(&self.host, Direction::Down, down);
    }

    /// Wait until neither peer has sent a message for `timeout`, publishing byte
    /// counts every [`FLUSH_INTERVAL`] meanwhile.
    async fn idle(&self, timeout: Duration) {
        loop {
            let deadline = self.state().last_activity + timeout;
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            sleep_until(deadline.min(now + FLUSH_INTERVAL)).await;
            self.flush();
        }
    }

    /// Return which peer sent the first close message, if one did before any disconnect.
    pub fn closed_by(&self) -> Option<Direction> {
        match self.state().ending {
            Some(Ending::Closed(direction)) => Some(direction),
            _ => None,
        }
    }

    /// Classify how the WebSocket ended once the relay has stopped.
    ///
    /// A close handshake started by either peer is a normal end. A client that
    /// disconnects without one is reported as such; an upstream that does is an
    /// upstream failure. A relay that stopped before either peer closed or
    /// disconnected failed to write to one of them, so the WebSocket broke.
    fn failure(&self) -> Option<Failure> {
        match self.state().ending {
            Some(Ending::Disconnected(Direction::Up)) => Some(Failure::ClientDisconnected),
            Some(Ending::Disconnected(Direction::Down)) => Some(Failure::Upstream),
            Some(Ending::Closed(_)) => None,
            None => Some(Failure::Disconnected),
        }
    }
}

/// A WebSocket connection whose received messages are reported to a [`Session`].
struct ObservedSocket<S> {
    /// The decoded connection.
    inner: S,
    /// The direction of the messages this connection receives.
    direction: Direction,
    /// Where received messages are reported.
    session: Arc<Session>,
}

impl<S> Stream for ObservedSocket<S>
where
    S: Stream<Item = Result<Message, ProtocolError>> + Unpin,
{
    type Item = Result<Message, ProtocolError>;

    /// Receive the next message and report it, or the end of the connection.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = Pin::new(&mut self.inner).poll_next(cx);
        if let Poll::Ready(item) = &polled {
            self.session.observe(self.direction, item.as_ref());
        }
        polled
    }
}

impl<S> Sink<Message> for ObservedSocket<S>
where
    S: Sink<Message, Error = ProtocolError> + Unpin,
{
    type Error = ProtocolError;

    /// Wait until the connection can accept a message.
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    /// Queue a message on the connection.
    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(message)
    }

    /// Write queued messages to the connection.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    /// Flush and close the connection.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl<S: ExtensionsRef> ExtensionsRef for ObservedSocket<S> {
    /// Expose the wrapped connection's extensions.
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

/// Relay messages between an upgraded client connection and its upstream until
/// either side closes, the WebSocket stays idle for `idle_timeout`, or `shutdown`
/// completes, and return why it ended abnormally, if it did.
///
/// Rama's relay answers pings itself and forwards close handshakes. An idle or
/// shut down WebSocket is dropped without a close message.
pub async fn relay(
    client: Upgraded,
    upstream: Upgraded,
    config: WebSocketConfig,
    session: Arc<Session>,
    idle_timeout: Duration,
    shutdown: impl Future<Output = ()>,
) -> Option<Failure> {
    let ingress = ObservedSocket {
        inner: AsyncWebSocket::from_raw_socket(client, Role::Server, Some(config)).await,
        direction: Direction::Up,
        session: session.clone(),
    };
    let egress = ObservedSocket {
        inner: AsyncWebSocket::from_raw_socket(upstream, Role::Client, Some(config)).await,
        direction: Direction::Down,
        session: session.clone(),
    };
    let relay = WebSocketRelayService::new(MirrorService::new());
    let failure = tokio::select! {
        _ = relay.serve(WebSocketBridge { ingress, egress }) => session.failure(),
        () = session.idle(idle_timeout) => Some(Failure::IdleTimeout),
        () = shutdown => Some(Failure::Cancelled),
    };
    session.flush();
    failure
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use rama::{
        bytes::Bytes,
        futures::{SinkExt, StreamExt},
        http::StatusCode,
    };
    use tokio::net::{TcpListener, TcpStream};

    /// Connect two loopback TCP sockets and return both ends as upgraded connections.
    pub(in crate::proxy) async fn socket_pair() -> (Upgraded, Upgraded) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (connected, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let wrap = |stream| Upgraded::new(rama::tcp::TcpStream::new(stream), Bytes::new());
        (wrap(connected.unwrap()), wrap(accepted.unwrap().0))
    }

    /// Relay compressed messages both ways with negotiated permessage-deflate, and
    /// count and capture their decoded payloads.
    #[tokio::test]
    async fn relays_permessage_deflate() {
        let mut accepted = Response::builder()
            .header("upgrade", "websocket")
            .header("sec-websocket-extensions", "permessage-deflate; client_no_context_takeover")
            .body(Body::empty())
            .unwrap();
        let config = negotiated_config(&mut accepted).unwrap();
        assert!(config.per_message_deflate.is_some());
        let (client_end, proxy_client) = socket_pair().await;
        let (proxy_upstream, server_end) = socket_pair().await;
        let stats = DomainStats::default();
        stats.capture_settings().set(true, 1);
        let capture = stats.capture_settings().begin(&HeaderMap::new()).unwrap();
        capture.start_websocket();
        let session = Session::new(stats.clone(), Host::new("ws.test"), Some(capture.clone()));
        let relay = tokio::spawn(relay(
            proxy_client,
            proxy_upstream,
            config,
            session,
            Duration::from_secs(60),
            std::future::pending(),
        ));
        let mut client =
            AsyncWebSocket::from_raw_socket(client_end, Role::Client, Some(config)).await;
        let mut server =
            AsyncWebSocket::from_raw_socket(server_end, Role::Server, Some(config)).await;
        let text = "compressible ".repeat(100);
        client.send(Message::text(text.clone())).await.unwrap();
        let Some(Ok(Message::Text(received))) = server.next().await else {
            panic!("the server did not receive the text message");
        };
        assert_eq!(received.as_str(), text);
        server.send(Message::binary(vec![7; 300])).await.unwrap();
        let Some(Ok(Message::Binary(received))) = client.next().await else {
            panic!("the client did not receive the binary message");
        };
        assert_eq!(received.len(), 300);
        server.close(None).await.unwrap();
        while client.next().await.is_some() {}
        assert_eq!(relay.await.unwrap(), None);
        let summary = stats.snapshot().remove(0);
        assert_eq!((summary.bytes.up, summary.bytes.down), (1300, 300));
        let websocket = capture.details().websocket.unwrap();
        assert_eq!(websocket.messages[0].size, 1300);
        assert_eq!(websocket.messages[1].kind, MessageKind::Binary);
    }

    /// Messages read after the WebSocket started ending are discarded by the relay,
    /// so they are neither counted nor captured, and a relay that stops with no
    /// close or disconnect seen is reported as broken.
    #[test]
    fn ignores_messages_after_ending_and_reports_unexplained_ends() {
        let stats = DomainStats::default();
        stats.capture_settings().set(true, 1);
        let capture = stats.capture_settings().begin(&HeaderMap::new()).unwrap();
        capture.start_websocket();
        let session = Session::new(stats.clone(), Host::new("ws.test"), Some(capture.clone()));
        assert_eq!(session.failure(), Some(Failure::Disconnected));
        session.observe(Direction::Down, Some(&Ok(Message::text("kept"))));
        session.observe(Direction::Up, Some(&Ok(Message::Close(None))));
        session.observe(Direction::Down, Some(&Ok(Message::text("discarded"))));
        session.observe(Direction::Down, Some(&Ok(Message::Close(None))));
        session.flush();
        let summary = stats.snapshot().remove(0);
        assert_eq!((summary.bytes.up, summary.bytes.down), (0, 4));
        assert_eq!(capture.details().websocket.unwrap().messages.len(), 2);
        assert_eq!(session.closed_by(), Some(Direction::Up));
        assert_eq!(session.failure(), None);
    }

    /// Build a request with the given method, version, and headers.
    fn request(method: Method, version: Version, headers: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder().method(method).version(version).uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// Only HTTP/1.1 GET requests with both upgrade tokens are WebSocket handshakes.
    #[test]
    fn recognizes_websocket_handshakes() {
        let headers = [("Upgrade", "WebSocket"), ("Connection", "keep-alive, Upgrade")];
        assert!(is_websocket_handshake(&request(Method::GET, Version::HTTP_11, &headers)));
        assert!(!is_websocket_handshake(&request(Method::POST, Version::HTTP_11, &headers)));
        assert!(!is_websocket_handshake(&request(Method::GET, Version::HTTP_2, &headers)));
        for partial in [
            [("Upgrade", "websocket"), ("Connection", "keep-alive")],
            [("Upgrade", "h2c"), ("Connection", "upgrade")],
        ] {
            assert!(!is_websocket_handshake(&request(Method::GET, Version::HTTP_11, &partial)));
        }
    }

    /// The upstream handshake restores the upgrade headers and keeps only deflate offers.
    #[test]
    fn builds_upstream_handshakes() {
        let client = request(
            Method::GET,
            Version::HTTP_11,
            &[
                ("Sec-WebSocket-Key", "key"),
                ("Sec-WebSocket-Extensions", "x-webkit-deflate-frame"),
                ("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits, foo"),
            ],
        );
        let handshake = upstream_handshake(&client);
        assert_eq!(handshake.headers()["connection"], "upgrade");
        assert_eq!(handshake.headers()["upgrade"], "websocket");
        assert_eq!(handshake.headers()["sec-websocket-key"], "key");
        assert_eq!(
            handshake.headers()["sec-websocket-extensions"],
            "permessage-deflate; client_max_window_bits"
        );
        let plain = upstream_handshake(&request(
            Method::GET,
            Version::HTTP_11,
            &[("Sec-WebSocket-Extensions", "foo")],
        ));
        assert!(!plain.headers().contains_key("sec-websocket-extensions"));
    }

    /// A 101 response must switch to WebSocket and accept at most permessage-deflate.
    #[test]
    fn validates_upstream_switches() {
        let response = |headers: &[(&str, &str)]| {
            let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            builder.body(Body::empty()).unwrap()
        };
        let plain = negotiated_config(&mut response(&[("Upgrade", "websocket")])).unwrap();
        assert!(plain.per_message_deflate.is_none());
        assert_eq!(plain.max_message_size, Some(MAX_MESSAGE_SIZE));
        let deflate = negotiated_config(&mut response(&[
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover"),
        ]))
        .unwrap();
        assert_eq!(deflate.max_frame_size, Some(MAX_FRAME_SIZE));
        assert!(deflate.per_message_deflate.unwrap().server_no_context_takeover);
        assert!(matches!(
            negotiated_config(&mut response(&[("Upgrade", "h2c")])),
            Err(HandshakeError::NotWebSocket)
        ));
        assert!(matches!(
            negotiated_config(&mut response(&[
                ("Upgrade", "websocket"),
                ("Sec-WebSocket-Extensions", "x-webkit-deflate-frame"),
            ])),
            Err(HandshakeError::UnsupportedExtensions(_))
        ));
        for unusable in [
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; server_max_window_bits=8",
            "permessage-deflate; client_max_window_bits=16",
            "permessage-deflate; foo",
        ] {
            assert!(
                matches!(
                    negotiated_config(&mut response(&[
                        ("Upgrade", "websocket"),
                        ("Sec-WebSocket-Extensions", unusable),
                    ])),
                    Err(HandshakeError::UnsupportedDeflate(_))
                ),
                "{unusable}"
            );
        }
        let narrow = negotiated_config(&mut response(&[
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits=10"),
        ]))
        .unwrap();
        assert_eq!(narrow.per_message_deflate.unwrap().client_max_window_bits, Some(10));
    }

    /// Requests that declare a body are not WebSocket handshakes, and the upstream
    /// handshake never announces one.
    #[test]
    fn handshakes_carry_no_body() {
        let upgrade = [("Upgrade", "websocket"), ("Connection", "Upgrade")];
        let with = |extra: (&'static str, &'static str)| {
            let mut headers = upgrade.to_vec();
            headers.push(extra);
            request(Method::GET, Version::HTTP_11, &headers)
        };
        assert!(is_websocket_handshake(&with(("Content-Length", "0"))));
        assert!(!is_websocket_handshake(&with(("Content-Length", "100"))));
        assert!(!is_websocket_handshake(&with(("Transfer-Encoding", "chunked"))));
        let handshake = upstream_handshake(&with(("Content-Length", "0")));
        assert!(!handshake.headers().contains_key("content-length"));
    }
}
