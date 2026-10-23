//! Rama HTTP server and rustls interception for REDIRECT and explicit proxy traffic.

use super::{
    authorize::{Target, apply_plan, authorize, authorize_connect, initial_event, record_plan},
    metered::MeteredBody,
    original_dst::redirected_destination,
    upstream::Upstream,
};
use crate::{
    ca::{Authority, Resolver},
    error::ErrorChain,
    policy::Decision,
    runtime::PolicyStore,
    telemetry::{Capture, Direction, EventSink, Failure, Side},
};
use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Body, Method, Request, Response, StatusCode,
        body::{StreamingBody, util::BodyExt},
        layer::upgrade::{
            LazyHttpProxyConnectReplyService, UpgradeLayer, UpgradeResponse, Upgraded,
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    rt::Executor,
    service::service_fn,
    tls::{
        rustls::server::{RustlsServerConfigExt, TlsAcceptorLayer},
        server::TlsServerConfig,
    },
};
use std::{convert::Infallible, io, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
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

/// The CONNECT authority carried into the upgraded TLS connection.
#[derive(Debug, Clone, rama::extensions::Extension)]
struct Tunnel(rama::net::address::Authority);

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
    /// The deadline for an upstream response.
    upstream_timeout: Duration,
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
    pub async fn http(&self, mut request: Request, target: Target) -> Result<Response, Infallible> {
        let capture = if request.method() == Method::CONNECT {
            None
        } else {
            self.sink.stats().capture_settings().begin(request.headers())
        };
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
        let stats = self.sink.stats().clone();
        let host = plan.host;
        let request = request.map(|body| {
            let recorder = capture.as_ref().map(|capture| capture.recorder(Side::Request));
            MeteredBody::wrap(body, stats.clone(), host.clone(), Direction::Up, recorder)
        });
        let failure = match timeout(self.upstream_timeout, self.upstream.send(request)).await {
            Ok(Ok(upstream)) => {
                let status = upstream.status().as_u16();
                event.event().respond_http(status);
                let recorder = capture.as_ref().map(|capture| {
                    capture.record_response(status, upstream.headers());
                    capture.recorder(Side::Response)
                });
                return Ok(upstream
                    .map(|body| MeteredBody::wrap(body, stats, host, Direction::Down, recorder)));
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
        event.event().respond_http(StatusCode::BAD_GATEWAY.as_u16());
        event.event().fail(failure);
        Ok(captured_response(
            StatusCode::BAD_GATEWAY,
            "upstream request failed\n",
            capture.as_ref(),
        ))
    }

    /// Authorize an explicit CONNECT and reply so the client can start TLS.
    async fn connect(
        &self,
        request: Request,
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
        request.extensions().insert(Tunnel(plan.authority));
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
    async fn connection(&self, stream: TcpStream) -> Result<(), ProxyError> {
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
                    async move { proxy.connect(request).await }
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
        let authority = upgraded.extensions().get_ref::<Tunnel>().map(|tunnel| tunnel.0.clone());
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
                        let _permit = permit;
                        if let Err(error) = proxy.connection(stream).await {
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
        BoxFuture,
        config::RuntimeSettings,
        policy::{Policy, RuleSet},
        telemetry::{EventReceiver, Transferred, format},
    };
    use rama::http::body::util::BodyExt;
    use std::sync::Mutex;

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
    }

    impl Upstream for FakeUpstream {
        /// Record the request, read its body, and respond according to the behaviour.
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
            let authorization = request
                .headers()
                .get("authorization")
                .map(|value| value.to_str().unwrap().to_owned());
            self.received.lock().unwrap().push((request.uri().to_string(), authorization));
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
}
