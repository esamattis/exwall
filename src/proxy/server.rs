//! Rama HTTP server and rustls interception for REDIRECT and explicit proxy traffic.

use super::{
    authorize::{Target, apply_plan, authorize, authorize_connect, initial_event, record_plan},
    original_dst::redirected_destination,
    upstream::Upstream,
};
use crate::{
    ca::{Authority, Resolver},
    policy::{Decision, MatchSource},
    runtime::PolicyStore,
    telemetry::{EventSink, Failure},
};
use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Body, Request, Response, StatusCode,
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
    pub async fn http(&self, mut request: Request, target: Target) -> Result<Response, Infallible> {
        let mut event = self.sink.track(initial_event(&request, &target));
        let decision = {
            let policy = self.policy.load();
            authorize(&request, &target, &policy.rules)
        };
        let plan = match decision {
            Ok(plan) => plan,
            Err(rejection) => {
                rejection.record(event.event());
                return Ok(response(rejection.status(), rejection.message()));
            }
        };
        record_plan(event.event(), &plan);
        apply_plan(&mut request, &plan);
        let failure = match timeout(self.upstream_timeout, self.upstream.send(request)).await {
            Ok(Ok(upstream)) => {
                event.event().respond_http(upstream.status().as_u16());
                return Ok(upstream);
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "upstream HTTP request failed");
                Failure::Upstream
            }
            Err(_) => {
                tracing::warn!("upstream HTTP request timed out");
                Failure::UpstreamTimeout
            }
        };
        event.event().respond_http(StatusCode::BAD_GATEWAY.as_u16());
        event.event().fail(failure);
        Ok(response(StatusCode::BAD_GATEWAY, "upstream request failed\n"))
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
            authorize_connect(&request, &policy.rules)
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
        pending.matched(MatchSource::Rule(plan.rule));
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
                            tracing::debug!(%peer, error = %crate::error::ErrorChain(&error), "proxy connection ended");
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
        telemetry::{EventReceiver, format},
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
        /// Record the request and respond according to the behaviour.
        fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
            let authorization = request
                .headers()
                .get("authorization")
                .map(|value| value.to_str().unwrap().to_owned());
            self.received.lock().unwrap().push((request.uri().to_string(), authorization));
            Box::pin(async move {
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
            .body(Body::empty())
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
