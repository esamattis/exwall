//! Rama HTTP server and rustls interception for REDIRECT and explicit proxy traffic.

use super::{
    authorize::{Target, apply_plan, authorize, authorize_connect, initial_event, record_plan},
    metered::MeteredBody,
    original_dst::redirected_destination,
    upstream::Upstream,
    websocket::{self, Session, is_websocket_handshake},
};
use crate::{
    BoxFuture,
    ca::{Authority, Resolver},
    error::ErrorChain,
    policy::{Decision, Host},
    runtime::PolicyStore,
    telemetry::{Capture, Direction, EventSink, Failure, PendingEvent, Side},
};
use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Body, Method, Request, Response, StatusCode,
        body::{StreamingBody, util::BodyExt},
        io::upgrade::handle_upgrade,
        layer::upgrade::{
            LazyHttpProxyConnectReplyService, UpgradeLayer, UpgradeResponse, Upgraded,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        ws::protocol::WebSocketConfig,
    },
    rt::Executor,
    service::service_fn,
    tls::{
        rustls::server::{RustlsServerConfigExt, TlsAcceptorLayer},
        server::TlsServerConfig,
    },
};
use std::{
    convert::Infallible,
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};

/// Concurrent client connections.
const CONNECTION_LIMIT: usize = 1024;
/// The deadline for an upstream response's headers.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a new connection may stay silent before its protocol is detected.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(10);
/// The first byte of a TLS handshake record.
const TLS_HANDSHAKE: u8 = 0x16;
/// How long a denied request's body is read for capture before the rejection is sent.
const CAPTURE_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Proxy listener and connection failures.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// The listener failed to accept a connection.
    #[error("accept proxy connection")]
    Accept(#[source] io::Error),
    /// The client sent nothing before the deadline.
    #[error("no request bytes before the deadline")]
    FirstByteTimeout,
    /// The client closed the connection without sending anything.
    #[error("empty connection")]
    Empty,
    /// The connection failed while detecting its protocol.
    #[error("read first byte")]
    Peek(#[source] io::Error),
    /// Rama failed while serving the connection.
    #[error("serve HTTP connection")]
    Serve(#[source] BoxError),
}

/// The CONNECT authority and connection slot carried into the upgraded TLS connection.
#[derive(Debug, Clone, rama::extensions::Extension)]
struct Tunnel {
    /// The CONNECT target.
    authority: rama::net::address::Authority,
    /// The client connection's slot under the connection limit.
    slot: Option<Arc<OwnedSemaphorePermit>>,
}

/// Shared HTTP policy, certificate authority, upstream client, and Rama task executor.
#[derive(Clone)]
pub struct Proxy {
    /// Access-log and statistics mailbox.
    sink: EventSink,
    /// The active policy.
    policy: Arc<PolicyStore>,
    /// Issues interception certificates.
    authority: Arc<Authority>,
    /// Forwards authorized requests.
    upstream: Arc<dyn Upstream>,
    /// Spawns Rama connection tasks under graceful shutdown.
    exec: Executor,
    /// The deadline for an upstream response, including a WebSocket handshake.
    upstream_timeout: Duration,
    /// How long an open WebSocket may stay silent before it is dropped.
    idle_timeout: Duration,
}

/// Create a local HTTP response with a short plaintext explanation.
fn response(status: StatusCode, message: &'static str) -> Response {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = status;
    response
}

/// Create a local HTTP response and record it in the request's capture, if any.
fn captured_response(
    status: StatusCode,
    message: &'static str,
    capture: Option<&Capture>,
) -> Response {
    let reply = response(status, message);
    if let Some(capture) = capture {
        capture.record_local_response(status.as_u16(), reply.headers(), message);
    }
    reply
}

/// Record an upstream failure and answer the client with `502 Bad Gateway`.
fn bad_gateway(event: &mut PendingEvent, failure: Failure, capture: Option<&Capture>) -> Response {
    event.event().respond_http(StatusCode::BAD_GATEWAY.as_u16());
    event.event().fail(failure);
    captured_response(StatusCode::BAD_GATEWAY, "upstream request failed\n", capture)
}

/// Wait for both sides of a WebSocket handshake to hand over their connections.
///
/// The client's connection is handed over once the `101` response is written to it.
async fn connect_upgrades(
    client: impl Future<Output = Result<Upgraded, BoxError>>,
    upstream: impl Future<Output = Result<Upgraded, BoxError>>,
) -> Result<(Upgraded, Upgraded), Failure> {
    let (client, upstream) = tokio::join!(client, upstream);
    let client = client.map_err(|error| {
        tracing::debug!(error = %ErrorChain(&*error), "client WebSocket upgrade failed");
        Failure::ClientDisconnected
    })?;
    let upstream = upstream.map_err(|error| {
        tracing::warn!(error = %ErrorChain(&*error), "upstream WebSocket upgrade failed");
        Failure::Upstream
    })?;
    Ok((client, upstream))
}

/// A WebSocket handshake the upstream accepted, ready to be relayed.
struct OpenWebSocket {
    /// The upstream's `101` response, carrying its pending upgrade.
    upstream: Response,
    /// The negotiated WebSocket settings, such as permessage-deflate.
    config: WebSocketConfig,
    /// The client's pending upgrade.
    client_upgrade: BoxFuture<'static, Result<Upgraded, BoxError>>,
    /// The handshake's event, logged when the WebSocket closes.
    event: PendingEvent,
    /// The handshake's capture, if capturing was on.
    capture: Option<Capture>,
    /// The authorized host that transferred bytes count toward.
    host: Host,
    /// The client connection's slot under the connection limit.
    slot: Option<Arc<OwnedSemaphorePermit>>,
}

/// Read a denied request's body up to the capture limit so the UI can show it.
///
/// The body is never forwarded. Reading stops just past the limit, at the end of the
/// body, or after [`CAPTURE_READ_TIMEOUT`], so a slow client cannot hold back its
/// rejection for long.
async fn capture_rejected_body(capture: &Capture, mut body: Body) {
    let mut recorder = capture.recorder(Side::Request);
    let read = async {
        while !recorder.is_truncated() {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        recorder.observe(data);
                    }
                }
                Some(Err(_)) => return false,
                None => return true,
            }
        }
        body.is_end_stream()
    };
    let complete = timeout(CAPTURE_READ_TIMEOUT, read).await.unwrap_or(false);
    recorder.finish(complete);
}

impl Proxy {
    /// Assemble a proxy from its shared services.
    pub fn new(
        sink: EventSink,
        policy: Arc<PolicyStore>,
        authority: Arc<Authority>,
        upstream: Arc<dyn Upstream>,
        exec: Executor,
    ) -> Self {
        Self {
            sink,
            policy,
            authority,
            upstream,
            exec,
            upstream_timeout: UPSTREAM_TIMEOUT,
            idle_timeout: websocket::IDLE_TIMEOUT,
        }
    }

    /// Build a rustls interception configuration using the persistent CA.
    fn tls_config(&self, fallback: String) -> TlsServerConfig {
        let resolver = Arc::new(Resolver {
            authority: self.authority.clone(),
            fallback,
        });
        TlsServerConfig::new().with_alpn_http_auto().with_modify_rustls_config(move |mut config| {
            config.cert_resolver = resolver.clone();
            Ok(config)
        })
    }

    /// Apply policy and relay an allowed request as a streaming HTTP response.
    ///
    /// Forwarded request and response body bytes count toward the authorized host.
    /// While capturing is enabled, the client's headers, the response headers, and the
    /// leading bytes of both bodies are recorded, including for denied requests.
    ///
    /// An authorized WebSocket handshake is forwarded by [`Self::websocket`]. Every
    /// other upgrade offer was stripped by [`apply_plan`], so the request is answered
    /// with an ordinary response and the client stays on filtered HTTP/1.1.
    pub async fn http(&self, mut request: Request, target: Target) -> Result<Response, Infallible> {
        let capture = if request.method() == Method::CONNECT {
            None
        } else {
            self.sink.stats().capture_settings().begin(request.headers())
        };
        let websocket = is_websocket_handshake(&request);
        let mut initial = initial_event(&request, &target);
        initial.capture = capture.clone();
        let mut event = self.sink.track(initial);
        let decision = {
            let policy = self.policy.load();
            authorize(&request, &target, &policy.rules, self.policy.enforcement())
        };
        let plan = match decision {
            Ok(plan) => plan,
            Err(rejection) => {
                rejection.record(event.event());
                if let Some(capture) = &capture {
                    capture_rejected_body(capture, request.into_body()).await;
                }
                return Ok(captured_response(
                    rejection.status(),
                    rejection.message(),
                    capture.as_ref(),
                ));
            }
        };
        record_plan(event.event(), &plan);
        apply_plan(&mut request, &plan);
        if websocket {
            return Ok(self.websocket(request, event, capture, plan.host, target.slot).await);
        }
        let stats = self.sink.stats().clone();
        let host = plan.host;
        let request = request.map(|body| {
            let recorder = capture.as_ref().map(|capture| capture.recorder(Side::Request));
            MeteredBody::wrap(body, stats.clone(), host.clone(), Direction::Up, recorder)
        });
        let failure = match timeout(self.upstream_timeout, self.upstream.send(request)).await {
            Ok(Ok(upstream)) if upstream.status() == StatusCode::SWITCHING_PROTOCOLS => {
                tracing::warn!("upstream switched protocols without an upgrade offer");
                Failure::Upstream
            }
            Ok(Ok(upstream)) => {
                return Ok(self.forward_response(upstream, &mut event, capture.as_ref(), host));
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %ErrorChain(&*error), "upstream HTTP request failed");
                Failure::Upstream
            }
            Err(_) => {
                tracing::warn!("upstream HTTP request timed out");
                Failure::UpstreamTimeout
            }
        };
        Ok(bad_gateway(&mut event, failure, capture.as_ref()))
    }

    /// Return an upstream response to the client, metering and capturing its body.
    fn forward_response(
        &self,
        upstream: Response,
        event: &mut PendingEvent,
        capture: Option<&Capture>,
        host: Host,
    ) -> Response {
        let status = upstream.status().as_u16();
        event.event().respond_http(status);
        let recorder = capture.map(|capture| {
            capture.record_response(status, upstream.headers());
            capture.recorder(Side::Response)
        });
        let stats = self.sink.stats().clone();
        upstream.map(|body| MeteredBody::wrap(body, stats, host, Direction::Down, recorder))
    }

    /// Forward an authorized WebSocket handshake over HTTP/1.1.
    ///
    /// When the upstream switches protocols, its `101` response is returned to the
    /// client and the WebSocket is relayed by a background task until it closes; see
    /// [`Self::open_websocket`]. Any other upstream response is returned as usual.
    /// The upstream timeout applies to the handshake only.
    async fn websocket(
        &self,
        request: Request,
        mut event: PendingEvent,
        capture: Option<Capture>,
        host: Host,
        slot: Option<Arc<OwnedSemaphorePermit>>,
    ) -> Response {
        let client_upgrade: BoxFuture<'static, _> = Box::pin(handle_upgrade(&request));
        let handshake = websocket::upstream_handshake(&request);
        drop(request);
        if let Some(capture) = &capture {
            capture.recorder(Side::Request).finish(true);
        }
        let failure = match timeout(self.upstream_timeout, self.upstream.websocket(handshake)).await
        {
            Ok(Ok(mut upstream)) if upstream.status() == StatusCode::SWITCHING_PROTOCOLS => {
                match websocket::negotiated_config(&mut upstream) {
                    Ok(config) => {
                        return self.open_websocket(OpenWebSocket {
                            upstream,
                            config,
                            client_upgrade,
                            event,
                            capture,
                            host,
                            slot,
                        });
                    }
                    Err(error) => {
                        tracing::warn!(error = %ErrorChain(&error), "upstream WebSocket handshake failed");
                        Failure::Upstream
                    }
                }
            }
            Ok(Ok(upstream)) => {
                return self.forward_response(upstream, &mut event, capture.as_ref(), host);
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %ErrorChain(&*error), "upstream WebSocket handshake failed");
                Failure::Upstream
            }
            Err(_) => {
                tracing::warn!("upstream WebSocket handshake timed out");
                Failure::UpstreamTimeout
            }
        };
        bad_gateway(&mut event, failure, capture.as_ref())
    }

    /// Return the upstream's `101` response to the client and relay the WebSocket in
    /// a background task.
    ///
    /// The WebSocket appears in statistics and request history now, while its
    /// access-log row is written when it closes, reporting how it ended. Until then
    /// it is presumed cancelled, so a relay cut short by a shutdown is logged as such.
    fn open_websocket(&self, open: OpenWebSocket) -> Response {
        let OpenWebSocket {
            upstream,
            config,
            client_upgrade,
            mut event,
            capture,
            host,
            slot,
        } = open;
        let upstream_upgrade = handle_upgrade(&upstream);
        let mut reply = Response::new(Body::empty());
        *reply.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        *reply.headers_mut() = upstream.into_parts().0.headers;
        let status = StatusCode::SWITCHING_PROTOCOLS.as_u16();
        event.event().respond_http(status);
        event.event().fail(Failure::Cancelled);
        event.record_now();
        if let Some(capture) = &capture {
            capture.record_response(status, reply.headers());
            capture.start_websocket();
        }
        let session = Session::new(self.sink.stats().clone(), host, capture.clone());
        let guard = self.exec.guard().cloned();
        let idle_timeout = self.idle_timeout;
        self.exec.spawn_task(async move {
            let _slot = slot;
            let opened = Instant::now();
            let shutdown = async move {
                match guard {
                    Some(guard) => guard.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            let failure = match connect_upgrades(client_upgrade, upstream_upgrade).await {
                Ok((client, upstream)) => {
                    websocket::relay(
                        client,
                        upstream,
                        config,
                        session.clone(),
                        idle_timeout,
                        shutdown,
                    )
                    .await
                }
                Err(failure) => Some(failure),
            };
            if let Some(capture) = &capture {
                capture.finish_websocket(session.closed_by(), failure);
            }
            let pending = event.event();
            pending.failure = failure;
            tracing::debug!(
                url = %pending.url,
                duration = ?opened.elapsed(),
                failure = failure.map(Failure::name),
                "WebSocket closed"
            );
        });
        reply
    }

    /// Authorize an explicit CONNECT and reply so the client can start TLS.
    async fn connect(
        &self,
        request: Request,
        slot: Arc<OwnedSemaphorePermit>,
    ) -> Result<UpgradeResponse<Request, Response>, Response> {
        let target = Target {
            tls: true,
            ..Target::default()
        };
        let mut event = self.sink.track(initial_event(&request, &target));
        let decision = {
            let policy = self.policy.load();
            authorize_connect(&request, &policy.rules, self.policy.enforcement())
        };
        let plan = match decision {
            Ok(plan) => plan,
            Err(rejection) => {
                rejection.record(event.event());
                return Err(response(rejection.status(), rejection.message()));
            }
        };
        let pending = event.event();
        pending.decide(Decision::Allow);
        pending.matched(plan.source);
        pending.subjects = vec![plan.host];
        request.extensions().insert(Tunnel {
            authority: plan.authority,
            slot: Some(slot),
        });
        let result = LazyHttpProxyConnectReplyService::new().serve(request).await;
        match &result {
            Ok(_) => event.event().respond_http(StatusCode::OK.as_u16()),
            Err(reply) => {
                event.event().respond_http(reply.status().as_u16());
                event.event().fail(Failure::ConnectSetup);
            }
        }
        result
    }

    /// Detect plaintext/TLS ingress and dispatch it through Rama HTTP services.
    ///
    /// `slot` is the connection's place under the connection limit; WebSockets and
    /// CONNECT tunnels that outlive the HTTP connection keep it.
    async fn connection(
        &self,
        stream: TcpStream,
        slot: Arc<OwnedSemaphorePermit>,
    ) -> Result<(), ProxyError> {
        let original = redirected_destination(&stream);
        let mut first = [0; 1];
        let peeked = timeout(FIRST_BYTE_TIMEOUT, stream.peek(&mut first))
            .await
            .map_err(|_| ProxyError::FirstByteTimeout)?
            .map_err(ProxyError::Peek)?;
        if peeked == 0 {
            return Err(ProxyError::Empty);
        }
        let tls = first[0] == TLS_HANDSHAKE;
        let target = Target {
            original,
            tls,
            tunnel: None,
            slot: Some(slot.clone()),
        };
        let stream = rama::tcp::TcpStream::new(stream);
        if tls {
            let fallback = original
                .map(|address| address.ip().to_string())
                .unwrap_or_else(|| "localhost".into());
            let http = HttpServer::auto(self.exec.clone()).service(self.http_service(target));
            TlsAcceptorLayer::new(self.tls_config(fallback))
                .with_store_client_hello(true)
                .into_layer(http)
                .serve(stream)
                .await
                .map_err(ProxyError::Serve)?;
        } else {
            let accept = self.clone();
            let tunnel = self.clone();
            let upgrades = UpgradeLayer::new_with_services(
                self.exec.clone(),
                MethodMatcher::CONNECT,
                service_fn(move |request: Request| {
                    let proxy = accept.clone();
                    let slot = slot.clone();
                    async move { proxy.connect(request, slot).await }
                }),
                service_fn(move |upgraded: Upgraded| {
                    let proxy = tunnel.clone();
                    async move { proxy.tunnel(upgraded).await }
                }),
            );
            let http = HttpServer::auto(self.exec.clone())
                .service(upgrades.into_layer(self.http_service(target)));
            http.serve(stream).await.map_err(ProxyError::Serve)?;
        }
        Ok(())
    }

    /// Wrap the HTTP handler as a Rama service bound to one connection's target.
    fn http_service(
        &self,
        target: Target,
    ) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
        let proxy = self.clone();
        service_fn(move |request| {
            let proxy = proxy.clone();
            let target = target.clone();
            async move { proxy.http(request, target).await }
        })
    }

    /// Terminate TLS inside CONNECT and inspect every tunneled HTTP request.
    async fn tunnel(&self, upgraded: Upgraded) -> Result<(), BoxError> {
        let tunnel = upgraded.extensions().get_ref::<Tunnel>().cloned();
        let (authority, slot) = match tunnel {
            Some(tunnel) => (Some(tunnel.authority), tunnel.slot),
            None => (None, None),
        };
        let fallback = authority
            .as_ref()
            .map(|authority| {
                crate::policy::Host::new(&authority.address.host.to_string()).to_string()
            })
            .unwrap_or_else(|| "localhost".into());
        let target = Target {
            original: None,
            tunnel: authority,
            tls: true,
            slot,
        };
        let http = HttpServer::auto(self.exec.clone()).service(self.http_service(target));
        TlsAcceptorLayer::new(self.tls_config(fallback))
            .with_store_client_hello(true)
            .into_layer(http)
            .serve(upgraded)
            .await
    }

    /// Accept TCP sessions with a fixed concurrent-connection limit.
    pub async fn serve(self, listener: TcpListener) -> Result<(), ProxyError> {
        let limit = Arc::new(Semaphore::new(CONNECTION_LIMIT));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(ProxyError::Accept)?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        continue;
                    };
                    let proxy = self.clone();
                    tasks.spawn(async move {
                        if let Err(error) = proxy.connection(stream, Arc::new(permit)).await {
                            tracing::debug!(%peer, error = %ErrorChain(&error), "proxy connection ended");
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::RuntimeSettings,
        policy::{Policy, RuleSet},
        telemetry::{EventReceiver, Transferred, format},
    };
    use rama::{
        futures::{SinkExt, StreamExt},
        http::{
            HeaderMap,
            body::util::BodyExt,
            io::upgrade::{Pending, pending},
            ws::{AsyncWebSocket, Message, protocol::Role},
        },
    };
    use std::sync::Mutex;
    use websocket::tests::socket_pair;

    /// How the fake upstream responds.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Respond with this status.
        Status(u16),
        /// Fail before a response.
        Fail,
        /// Never respond.
        Hang,
    }

    /// An in-memory upstream recording the requests it receives.
    struct FakeUpstream {
        /// The configured behaviour.
        behaviour: Behaviour,
        /// Received request URIs and Authorization headers.
        received: Mutex<Vec<(String, Option<String>)>>,
        /// The headers of every received request, in order.
        headers: Mutex<Vec<HeaderMap>>,
    }

    impl FakeUpstream {
        /// Record a request's URI, Authorization header, and all of its headers.
        fn record(&self, request: &Request) {
            let authorization = request
                .headers()
                .get("authorization")
                .map(|value| value.to_str().unwrap().to_owned());
            self.received.lock().unwrap().push((request.uri().to_string(), authorization));
            self.headers.lock().unwrap().push(request.headers().clone());
        }
    }

    /// Serve one WebSocket as the upstream: echo text messages with an `echo:` prefix,
    /// drop the connection on `drop`, and answer a close handshake.
    async fn echo_server(io: Upgraded) {
        let mut socket = AsyncWebSocket::from_raw_socket(io, Role::Server, None).await;
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Text(text) if text.as_str() == "drop" => return,
                Message::Text(text) => {
                    let reply = Message::text(format!("echo:{}", text.as_str()));
                    if socket.send(reply).await.is_err() {
                        return;
                    }
                }
                Message::Close(_) => {
                    let _ = socket.close(None).await;
                    return;
                }
                _ => {}
            }
        }
    }

    impl Upstream for FakeUpstream {
        /// Record the request, read its body, and respond according to the behaviour.
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
            self.record(&request);
            Box::pin(async move {
                request.into_body().collect().await?;
                match self.behaviour {
                    Behaviour::Status(status) => {
                        let mut reply = Response::new(Body::from("upstream"));
                        *reply.status_mut() = StatusCode::from_u16(status).unwrap();
                        Ok(reply)
                    }
                    Behaviour::Fail => Err(BoxError::from("connection refused")),
                    Behaviour::Hang => std::future::pending().await,
                }
            })
        }

        /// Record the handshake and, for status 101, switch to an echoing WebSocket.
        fn websocket(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
            self.record(&request);
            Box::pin(async move {
                match self.behaviour {
                    Behaviour::Status(101) => {
                        let (proxy_end, server_end) = socket_pair().await;
                        tokio::spawn(echo_server(server_end));
                        let (upgrade, on_upgrade) = pending();
                        upgrade.fulfill(proxy_end);
                        let reply = Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header("upgrade", "websocket")
                            .header("connection", "upgrade")
                            .header("sec-websocket-accept", "accepted")
                            .body(Body::empty())
                            .unwrap();
                        reply.extensions().insert(on_upgrade);
                        Ok(reply)
                    }
                    Behaviour::Status(status) => {
                        let mut reply = Response::new(Body::from("no socket"));
                        *reply.status_mut() = StatusCode::from_u16(status).unwrap();
                        Ok(reply)
                    }
                    Behaviour::Fail => Err(BoxError::from("connection refused")),
                    Behaviour::Hang => std::future::pending().await,
                }
            })
        }
    }

    /// Build a proxy over test rules with a fake upstream and an inspectable sink.
    fn proxy(behaviour: Behaviour) -> (tempfile::TempDir, Proxy, EventReceiver, Arc<FakeUpstream>) {
        let directory = tempfile::tempdir().unwrap();
        crate::ca::init(directory.path()).unwrap();
        let rules = RuleSet::parse(
            "[[allow]]\ndomain = 'allowed.test'\npathname_pattern = '/secure'\ninject_headers = [{ name = 'Authorization', value = 'replacement' }]\n[[allow]]\ndomain = 'allowed.test'\npathname_pattern = '/allowed'\n",
            "test",
        )
        .unwrap();
        let store = Arc::new(PolicyStore::new(Policy::new(RuntimeSettings::default(), rules)));
        let (sink, receiver) = EventSink::channel(16);
        let upstream = Arc::new(FakeUpstream {
            behaviour,
            received: Mutex::new(Vec::new()),
            headers: Mutex::new(Vec::new()),
        });
        let mut proxy = Proxy::new(
            sink,
            store,
            Arc::new(Authority::load(directory.path()).unwrap()),
            upstream.clone(),
            Executor::default(),
        );
        proxy.upstream_timeout = Duration::from_millis(50);
        (directory, proxy, receiver, upstream)
    }

    /// Send a request for `uri` through the handler and return its status and log row.
    async fn send(
        proxy: &Proxy,
        receiver: &mut EventReceiver,
        uri: &str,
        tls: bool,
    ) -> (u16, String) {
        let request = Request::builder()
            .uri(uri)
            .header("Authorization", "client-secret")
            .body(Body::from("payload"))
            .unwrap();
        let target = Target {
            tls,
            ..Target::default()
        };
        let reply = proxy.http(request, target).await.unwrap();
        let status = reply.status().as_u16();
        reply.into_body().collect().await.unwrap();
        (status, format::message(&receiver.events.recv().await.unwrap()))
    }

    /// Allowed requests are forwarded to the authorized URI with injected credentials.
    #[tokio::test]
    async fn forwards_allowed_requests_and_logs_them() {
        let (_directory, proxy, mut receiver, upstream) = proxy(Behaviour::Status(201));
        let (status, row) =
            send(&proxy, &mut receiver, "https://allowed.test/secure?q=1", false).await;
        assert_eq!(status, 201);
        assert_eq!(row, "https ALLOW test:allow#1 GET https://allowed.test:443/secure?q=1 201 - -");
        let received = upstream.received.lock().unwrap().clone();
        assert_eq!(
            received,
            vec![("https://allowed.test:443/secure?q=1".into(), Some("replacement".into()))]
        );
        let (status, row) = send(&proxy, &mut receiver, "http://allowed.test/denied", false).await;
        assert_eq!(status, 403);
        assert_eq!(row, "http DENY - GET http://allowed.test/denied 403 - -");
        assert_eq!(upstream.received.lock().unwrap().len(), 1);
        let denials = proxy.sink.stats().denials_snapshot();
        assert_eq!(denials[0].pathname, "/denied");
        let summary = proxy.sink.stats().snapshot().remove(0);
        assert_eq!(summary.domain, "allowed.test");
        assert_eq!(
            summary.bytes,
            Transferred {
                up: "payload".len() as u64,
                down: "upstream".len() as u64
            }
        );
    }

    /// Captures record client headers before injection, both bodies, and local rejections.
    #[tokio::test]
    async fn captures_allowed_and_denied_requests() {
        let (_directory, proxy, mut receiver, _upstream) = proxy(Behaviour::Status(201));
        send(&proxy, &mut receiver, "https://allowed.test/secure", false).await;
        assert!(proxy.sink.stats().allowances_snapshot()[0].capture.is_none());
        proxy.sink.stats().capture_settings().set(true, 1);

        send(&proxy, &mut receiver, "https://allowed.test/secure", false).await;
        let allowance = proxy.sink.stats().allowances_snapshot().remove(0);
        let details = allowance.capture.unwrap().details();
        let authorization = details.request.headers.iter().find(|h| h.name == "authorization");
        assert_eq!(authorization.unwrap().value, "client-secret");
        let request_body = details.request.body.unwrap();
        assert!(request_body.complete);
        assert_eq!(request_body.text.as_deref(), Some("payload"));
        let response = details.response.unwrap();
        assert_eq!(response.status, Some(201));
        assert_eq!(response.body.unwrap().text.as_deref(), Some("upstream"));

        send(&proxy, &mut receiver, "http://allowed.test/denied", false).await;
        let denial = proxy.sink.stats().denials_snapshot().remove(0);
        let details = denial.capture.unwrap().details();
        assert_eq!(details.request.body.unwrap().text.as_deref(), Some("payload"));
        let response = details.response.unwrap();
        assert_eq!(response.status, Some(403));
        let body = response.body.unwrap();
        assert!(body.complete);
        assert_eq!(body.text.as_deref(), Some("exwall: no allow rule matched\n"));
    }

    /// While blocking is paused, denied requests are forwarded and logged as `@paused`.
    #[tokio::test]
    async fn forwards_denied_requests_while_paused() {
        let (_directory, proxy, mut receiver, upstream) = proxy(Behaviour::Status(200));
        proxy.policy.pause().pause(Duration::from_secs(60));
        let (status, row) = send(&proxy, &mut receiver, "http://denied.test/x", false).await;
        assert_eq!(status, 200);
        assert_eq!(row, "http ALLOW @paused GET http://denied.test:80/x 200 - -");
        let received = upstream.received.lock().unwrap().clone();
        assert_eq!(
            received,
            vec![("http://denied.test:80/x".into(), Some("client-secret".into()))]
        );
        assert!(proxy.sink.stats().denials_snapshot().is_empty());
        proxy.policy.pause().resume();
        let (status, _row) = send(&proxy, &mut receiver, "http://denied.test/x", false).await;
        assert_eq!(status, 403);
    }

    /// Upstream failures and timeouts become 502 with a failure category.
    #[tokio::test]
    async fn maps_upstream_failures_to_bad_gateway() {
        for (behaviour, failure) in
            [(Behaviour::Fail, "UPSTREAM_FAILURE"), (Behaviour::Hang, "UPSTREAM_TIMEOUT")]
        {
            let (_directory, proxy, mut receiver, _upstream) = proxy(behaviour);
            let (status, row) =
                send(&proxy, &mut receiver, "http://allowed.test/allowed", false).await;
            assert_eq!(status, 502);
            assert!(row.ends_with(&format!(" 502 - {failure}")), "{row}");
        }
    }

    /// Upstream error statuses pass through without a processing failure.
    #[tokio::test]
    async fn passes_upstream_error_statuses_through() {
        let (_directory, proxy, mut receiver, _upstream) = proxy(Behaviour::Status(502));
        let (status, row) = send(&proxy, &mut receiver, "http://allowed.test/allowed", false).await;
        assert_eq!(status, 502);
        assert!(row.ends_with(" 502 - -"), "{row}");
    }

    /// Non-WebSocket upgrade offers such as h2c are forwarded without their upgrade
    /// headers, and the client gets the upstream's ordinary response.
    #[tokio::test]
    async fn strips_h2c_upgrades() {
        let (_directory, proxy, mut receiver, upstream) = proxy(Behaviour::Status(200));
        let request = Request::builder()
            .uri("http://allowed.test/allowed")
            .header("Upgrade", "h2c")
            .header("Connection", "Upgrade, HTTP2-Settings")
            .header("HTTP2-Settings", "AAMAAABkAAQAAP__")
            .body(Body::empty())
            .unwrap();
        let reply = proxy.http(request, Target::default()).await.unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(reply.into_body().collect().await.unwrap().to_bytes(), "upstream");
        let row = format::message(&receiver.events.recv().await.unwrap());
        assert_eq!(row, "http ALLOW test:allow#2 GET http://allowed.test:80/allowed 200 - -");
        let headers = upstream.headers.lock().unwrap().remove(0);
        for name in ["upgrade", "connection", "http2-settings"] {
            assert!(!headers.contains_key(name), "{name}");
        }
    }

    /// An upstream switching protocols without an upgrade offer is a gateway failure.
    #[tokio::test]
    async fn refuses_unrequested_protocol_switches() {
        let (_directory, proxy, mut receiver, _upstream) = proxy(Behaviour::Status(101));
        let (status, row) = send(&proxy, &mut receiver, "http://allowed.test/allowed", false).await;
        assert_eq!(status, 502);
        assert!(row.ends_with(" 502 - UPSTREAM_FAILURE"), "{row}");
    }

    /// Send a WebSocket handshake for `uri` through the handler over TLS.
    ///
    /// Returns the response and the client's pending upgrade, which the test fulfils
    /// once the response is 101, as the HTTP server would after writing it.
    async fn handshake(proxy: &Proxy, uri: &str) -> (Response, Pending) {
        let (upgrade, on_upgrade) = pending();
        let request = Request::builder()
            .uri(uri)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Extensions", "permessage-deflate, x-unknown")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(on_upgrade);
        let target = Target {
            tls: true,
            ..Target::default()
        };
        (proxy.http(request, target).await.unwrap(), upgrade)
    }

    /// Complete the client side of an accepted handshake and return the client's socket.
    async fn open_client(upgrade: Pending) -> AsyncWebSocket<Upgraded> {
        let (proxy_end, client_end) = socket_pair().await;
        upgrade.fulfill(proxy_end);
        AsyncWebSocket::from_raw_socket(client_end, Role::Client, None).await
    }

    /// Receive the next text message from a test client.
    async fn next_text(client: &mut AsyncWebSocket<Upgraded>) -> String {
        match client.next().await.unwrap().unwrap() {
            Message::Text(text) => text.as_str().to_owned(),
            other => panic!("expected text, got {other:?}"),
        }
    }

    /// An allowed WebSocket is relayed until it closes, shown in the UI as soon as
    /// it opens, counted toward its host, captured, and logged once when it closes.
    #[tokio::test]
    async fn relays_websockets_and_logs_them_on_close() {
        let (_directory, proxy, mut receiver, upstream) = proxy(Behaviour::Status(101));
        proxy.sink.stats().capture_settings().set(true, 1);
        let (reply, upgrade) = handshake(&proxy, "https://allowed.test/secure").await;
        assert_eq!(reply.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(reply.headers()["upgrade"], "websocket");
        assert_eq!(reply.headers()["sec-websocket-accept"], "accepted");
        let sent = upstream.headers.lock().unwrap().remove(0);
        assert_eq!(sent["authorization"], "replacement");
        assert_eq!(sent["connection"], "upgrade");
        assert_eq!(sent["sec-websocket-extensions"], "permessage-deflate");
        let allowance = proxy.sink.stats().allowances_snapshot().remove(0);
        assert_eq!((allowance.scheme, allowance.rule.as_deref()), ("wss", Some("test:allow#1")));

        let mut client = open_client(upgrade).await;
        client.send(Message::text("hello")).await.unwrap();
        assert_eq!(next_text(&mut client).await, "echo:hello");
        assert!(receiver.events.try_recv().is_err());
        client.close(None).await.unwrap();
        while client.next().await.is_some() {}

        let event = receiver.events.recv().await.unwrap();
        assert_eq!(
            format::message(&event),
            "wss ALLOW test:allow#1 GET wss://allowed.test:443/secure 101 - -"
        );
        let summary = proxy.sink.stats().snapshot().remove(0);
        assert_eq!(summary.http.allow, 1);
        assert_eq!(
            summary.bytes,
            Transferred {
                up: 5,
                down: 10
            }
        );
        let details = allowance.capture.unwrap().details();
        assert_eq!(details.response.unwrap().status, Some(101));
        let websocket = details.websocket.unwrap();
        let texts: Vec<_> = websocket
            .messages
            .iter()
            .map(|message| (message.direction, message.text.clone().unwrap_or_default()))
            .collect();
        assert_eq!(texts[..2], [("up", "hello".to_owned()), ("down", "echo:hello".to_owned())]);
        let ended = websocket.ended.unwrap();
        assert_eq!((ended.closed_by, ended.failure), (Some("client"), None));
    }

    /// Idle WebSockets and upstream disconnects end with a failure in the log row.
    #[tokio::test]
    async fn reports_idle_and_upstream_failures() {
        let (_directory, mut proxy, mut receiver, _upstream) = proxy(Behaviour::Status(101));
        proxy.idle_timeout = Duration::from_millis(50);
        let (_reply, upgrade) = handshake(&proxy, "https://allowed.test/allowed").await;
        let _client = open_client(upgrade).await;
        let row = format::message(&receiver.events.recv().await.unwrap());
        assert!(row.ends_with(" 101 - IDLE_TIMEOUT"), "{row}");

        proxy.idle_timeout = Duration::from_secs(60);
        let (_reply, upgrade) = handshake(&proxy, "https://allowed.test/allowed").await;
        let mut client = open_client(upgrade).await;
        client.send(Message::text("drop")).await.unwrap();
        let row = format::message(&receiver.events.recv().await.unwrap());
        assert!(row.ends_with(" 101 - UPSTREAM_FAILURE"), "{row}");
    }

    /// Denied handshakes are refused, and handshakes the upstream declines get its response.
    #[tokio::test]
    async fn refuses_denied_and_declined_websockets() {
        let (_directory, proxy, mut receiver, upstream) = proxy(Behaviour::Status(403));
        let (reply, _upgrade) = handshake(&proxy, "https://allowed.test/denied").await;
        assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        let row = format::message(&receiver.events.recv().await.unwrap());
        assert_eq!(row, "wss DENY - GET wss://allowed.test/denied 403 - -");
        assert!(upstream.headers.lock().unwrap().is_empty());
        assert_eq!(proxy.sink.stats().denials_snapshot()[0].scheme, "wss");

        let (reply, _upgrade) = handshake(&proxy, "https://allowed.test/allowed").await;
        assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        assert_eq!(reply.into_body().collect().await.unwrap().to_bytes(), "no socket");
        let row = format::message(&receiver.events.recv().await.unwrap());
        assert_eq!(row, "wss ALLOW test:allow#2 GET wss://allowed.test:443/allowed 403 - -");
    }
}
