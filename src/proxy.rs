//! Rama HTTP server/client and rustls interception for REDIRECT and explicit proxy traffic.
use crate::error::{Context, Result, ensure};
use crate::{
    access_log::{AccessLog, Entry, Failure, Protocol},
    ca::{Authority, Resolver},
    rules::normalize_host,
    state::SharedPolicy,
};
use rama::{
    Layer, Service,
    error::BoxError,
    extensions::ExtensionsRef,
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            remove_header::RemoveResponseHeaderLayer,
            required_header::AddRequiredRequestHeadersLayer,
            upgrade::{LazyHttpProxyConnectReplyService, UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    rt::Executor,
    service::service_fn,
    tls::{
        SecureTransport,
        client::TlsClientConfig,
        rustls::server::{RustlsServerConfigExt, TlsAcceptorLayer},
        server::TlsServerConfig,
    },
};
use std::{convert::Infallible, net::SocketAddr, os::fd::AsRawFd, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

/// Shared HTTP policy, certificate authority, and Rama task executor.
#[derive(Clone)]
pub struct Proxy {
    pub access_log: AccessLog,
    pub policy: SharedPolicy,
    pub authority: Arc<Authority>,
    pub exec: Executor,
}

/// Connection routing information retained while filtering HTTP requests.
#[derive(Clone, Default)]
struct Target {
    original: Option<SocketAddr>,
    tunnel: Option<rama::net::address::Authority>,
    tls: bool,
}

/// The CONNECT authority carried into the upgraded TLS connection.
#[derive(Debug, Clone, rama::extensions::Extension)]
struct Tunnel(rama::net::address::Authority);

impl Proxy {
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
    async fn http(&self, mut request: Request, target: Target) -> Result<Response, Infallible> {
        let mut access = self.access_log.track(access_entry(&request, &target));
        match self.prepare(&mut request, &target, access.entry()) {
            Ok(()) => (),
            Err((code, message)) => {
                access.entry().http_response(code.as_u16());
                if code != StatusCode::FORBIDDEN {
                    access.entry().fail(Failure::InvalidRequest);
                }
                return Ok(response(code, message));
            }
        }
        // No automatic redirects or upstream proxy environment: every request is independently filtered.
        // Upstream certificates are verified by rustls' default verifier.
        let client = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_dns_address_resolver(rama::dns::client::TokioDnsResolver::default())
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_rustls_and_default_http_version(
                TlsClientConfig::new().with_alpn_http_auto(),
                Version::HTTP_11,
            )
            .with_default_http_connector(self.exec.clone())
            .without_connection_pool()
            .build_client();
        let client = (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            RemoveResponseHeaderLayer::hop_by_hop(),
            AddRequiredRequestHeadersLayer::new(),
        )
            .into_layer(client);
        match timeout(Duration::from_secs(60), client.serve(request)).await {
            Ok(Ok(response)) => {
                access.entry().http_response(response.status().as_u16());
                Ok(response)
            }
            error => {
                tracing::warn!(?error, "upstream HTTP request failed");
                access.entry().http_response(502);
                access.entry().fail(if error.is_err() {
                    Failure::UpstreamTimeout
                } else {
                    Failure::Upstream
                });
                Ok(response(StatusCode::BAD_GATEWAY, "upstream request failed\n"))
            }
        }
    }

    /// Authorize request metadata, fix its destination, and inject configured headers.
    fn prepare(
        &self,
        request: &mut Request,
        target: &Target,
        access: &mut Entry,
    ) -> std::result::Result<(), (StatusCode, &'static str)> {
        if request.method() == Method::CONNECT {
            return Err((StatusCode::METHOD_NOT_ALLOWED, "nested CONNECT is not allowed\n"));
        }
        if request.headers().contains_key("upgrade") {
            return Err((StatusCode::NOT_IMPLEMENTED, "protocol upgrades are not supported\n"));
        }
        let authority = request
            .uri()
            .authority()
            .map(|a| a.into_owned())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| h.parse().ok())
            })
            .or_else(|| target.tunnel.clone())
            .or_else(|| target.original.and_then(|a| a.to_string().parse().ok()));
        let Some(authority) = authority else {
            return Err((StatusCode::BAD_REQUEST, "missing or invalid authority\n"));
        };
        let host = normalize_host(authority.address.host.to_string().trim_matches(['[', ']']));
        if let Some(header) = request.headers().get("host") {
            let header_authority = header
                .to_str()
                .ok()
                .and_then(|value| value.parse::<rama::net::address::Authority>().ok());

            let Some(header_authority) = header_authority else {
                return Err((StatusCode::BAD_REQUEST, "invalid Host header\n"));
            };

            let header_host =
                normalize_host(header_authority.address.host.to_string().trim_matches(['[', ']']));
            if header_host != host {
                return Err((
                    StatusCode::MISDIRECTED_REQUEST,
                    "Host differs from request authority\n",
                ));
            }
        }
        if let Some(tunnel) = &target.tunnel
            && normalize_host(tunnel.address.host.to_string().trim_matches(['[', ']'])) != host
        {
            return Err((
                StatusCode::MISDIRECTED_REQUEST,
                "authority differs from CONNECT target\n",
            ));
        }
        if let Some(transport) = request.extensions().get_ref::<SecureTransport>()
            && let Some(sni) = transport.client_hello().and_then(|hello| hello.ext_server_name())
            && normalize_host(sni.as_str()) != host
        {
            return Err((
                StatusCode::MISDIRECTED_REQUEST,
                "authority differs from TLS server name\n",
            ));
        }
        let mut path = request.uri().path_or_root().into_owned();
        if let Some(query) = request.uri().query() {
            path.push('?');
            path.push_str(&query.to_string());
        }
        let policy = self.policy.load();
        let Some(rule) = policy.rules.request(&host, request.method().as_str(), &path) else {
            access.decision(false);
            return Err((StatusCode::FORBIDDEN, "exwall: no allow rule matched\n"));
        };
        access.decision(true);
        access.rule.clone_from(&rule.name);
        // Fix the route before injecting headers; credentials can never change the selected destination.
        let scheme = if target.tls {
            "https"
        } else {
            request.uri().scheme_str().unwrap_or("http")
        };
        if !matches!(scheme, "http" | "https") {
            return Err((StatusCode::BAD_REQUEST, "unsupported scheme\n"));
        }
        // Resolve the authorized URI through the proxy's resolver. The client-selected
        // original IP supplies only a port; it must never override hostname routing.
        if !rule.inject_headers.is_empty() && scheme != "https" {
            access.decision(false);
            return Err((StatusCode::FORBIDDEN, "exwall: header injection requires HTTPS\n"));
        }
        let port = authority
            .port_u16()
            .or_else(|| target.tunnel.as_ref().and_then(|a| a.port_u16()))
            .or_else(|| target.original.map(|a| a.port()))
            .unwrap_or(if scheme == "https" {
                443
            } else {
                80
            });
        let routed_host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        };
        let uri = rama::net::uri::Uri::parse(format!("{scheme}://{routed_host}:{port}{path}"))
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid destination URI\n"))?;
        *request.uri_mut() = uri;
        access.url = request.uri().to_string();
        // TE: trailers is legal on HTTP/2 and advertises support for gRPC trailers.
        let accepts_trailers = request
            .headers()
            .get_all("te")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("trailers"));
        rama::http::layer::remove_header::remove_hop_by_hop_request_headers(request.headers_mut());
        if accepts_trailers {
            request.headers_mut().insert("te", "trailers".parse().expect("static header"));
        }
        for (name, value) in &rule.inject_headers {
            request.headers_mut().insert(name.clone(), value.clone());
        }
        Ok(())
    }

    /// Detect plaintext/TLS ingress and dispatch it through Rama HTTP services.
    async fn connection(&self, stream: TcpStream) -> Result<()> {
        let original = original_destination(&stream)
            .ok()
            .map(normalize_socket_address)
            .filter(|a| stream.local_addr().ok().map(normalize_socket_address) != Some(*a));
        let mut first = [0; 1];
        ensure!(
            timeout(Duration::from_secs(10), stream.peek(&mut first)).await?? > 0,
            "empty connection"
        );
        let tls = first[0] == 0x16;
        let target = Target {
            original,
            tls,
            tunnel: None,
        };
        let stream = rama::tcp::TcpStream::new(stream);
        let proxy = self.clone();
        if tls {
            let fallback =
                original.map(|a| a.ip().to_string()).unwrap_or_else(|| "localhost".into());
            let http = HttpServer::auto(self.exec.clone()).service(service_fn(move |request| {
                let proxy = proxy.clone();
                let target = target.clone();
                async move { proxy.http(request, target).await }
            }));
            TlsAcceptorLayer::new(self.tls_config(fallback))
                .with_store_client_hello(true)
                .into_layer(http)
                .serve(stream)
                .await
                .context("serve HTTP connection")?;
        } else {
            let accept_proxy = self.clone();
            let tunnel_proxy = self.clone();
            let upgrades = UpgradeLayer::new_with_services(
                self.exec.clone(),
                MethodMatcher::CONNECT,
                service_fn(move |request: Request| {
                    let proxy = accept_proxy.clone();
                    async move {
                        let mut access = proxy.access_log.track(access_entry(
                            &request,
                            &Target {
                                tls: true,
                                ..Target::default()
                            },
                        ));
                        let Some(authority) = request.uri().authority() else {
                            access.entry().http_response(400);
                            access.entry().fail(Failure::InvalidRequest);
                            return Err(response(StatusCode::BAD_REQUEST, "invalid CONNECT\n"));
                        };
                        let policy = proxy.policy.load();
                        let Some(rule) = policy
                            .rules
                            .dns_rule(authority.host().to_string().trim_matches(['[', ']']))
                        else {
                            access.entry().decision(false);
                            access.entry().http_response(403);
                            return Err(response(
                                StatusCode::FORBIDDEN,
                                "exwall: CONNECT hostname denied\n",
                            ));
                        };
                        access.entry().decision(true);
                        access.entry().rule.clone_from(&rule.name);
                        request.extensions().insert(Tunnel(authority.into_owned()));
                        let result = LazyHttpProxyConnectReplyService::new().serve(request).await;
                        match &result {
                            Ok(_) => access.entry().http_response(200),
                            Err(response) => {
                                access.entry().http_response(response.status().as_u16());
                                access.entry().fail(Failure::ConnectSetup);
                            }
                        }
                        result
                    }
                }),
                service_fn(move |upgraded: Upgraded| {
                    let proxy = tunnel_proxy.clone();
                    async move { proxy.tunnel(upgraded).await }
                }),
            );
            let http = HttpServer::auto(self.exec.clone()).service(upgrades.into_layer(
                service_fn(move |request| {
                    let proxy = proxy.clone();
                    let target = target.clone();
                    async move { proxy.http(request, target).await }
                }),
            ));
            http.serve(stream).await.context("serve HTTP connection")?;
        }
        Ok(())
    }

    /// Terminate TLS inside CONNECT and inspect every tunneled HTTP request.
    async fn tunnel(&self, upgraded: Upgraded) -> std::result::Result<(), BoxError> {
        let authority = upgraded.extensions().get_ref::<Tunnel>().map(|t| t.0.clone());
        let fallback = authority
            .as_ref()
            .map(|a| a.address.host.to_string().trim_matches(['[', ']']).to_owned())
            .unwrap_or_else(|| "localhost".into());
        let target = Target {
            original: None,
            tunnel: authority,
            tls: true,
        };
        let proxy = self.clone();
        let http = HttpServer::auto(self.exec.clone()).service(service_fn(move |request| {
            let proxy = proxy.clone();
            let target = target.clone();
            async move { proxy.http(request, target).await }
        }));
        TlsAcceptorLayer::new(self.tls_config(fallback))
            .with_store_client_hello(true)
            .into_layer(http)
            .serve(upgraded)
            .await
    }

    /// Accept TCP sessions with a fixed concurrent-connection limit.
    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        let limit = Arc::new(Semaphore::new(1024));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        continue;
                    };
                    let proxy = self.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = proxy.connection(stream).await {
                            tracing::debug!(%peer, %error, "proxy connection ended");
                        }
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

/// Capture a full URL for both absolute proxy requests and origin-form TLS traffic.
fn access_entry(request: &Request, target: &Target) -> Entry {
    let scheme = if target.tls {
        "https"
    } else {
        request.uri().scheme_str().unwrap_or("http")
    };
    let protocol = if scheme == "https" {
        Protocol::Https
    } else {
        Protocol::Http
    };
    let authority = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| request.headers().get("host").and_then(|h| h.to_str().ok()).map(str::to_owned))
        .or_else(|| target.tunnel.as_ref().map(ToString::to_string))
        .or_else(|| target.original.map(|a| a.to_string()));
    let url = match authority {
        Some(authority) if request.method() == Method::CONNECT => format!("https://{authority}/"),
        Some(authority) => {
            let mut url = format!("{scheme}://{authority}{}", request.uri().path_or_root());
            if let Some(query) = request.uri().query() {
                url.push('?');
                url.push_str(&query.to_string());
            }
            url
        }
        None => request.uri().to_string(),
    };
    Entry::new(protocol, request.method().as_str(), url)
}

/// Create a local HTTP error response with a short plaintext explanation.
fn response(code: StatusCode, message: &'static str) -> Response {
    let mut response = Response::new(Body::from(message));
    *response.status_mut() = code;
    response
}

/// Linux netfilter REDIRECT preserves the original destination in conntrack.
fn original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    // A dual-stack socket can carry an IPv4 REDIRECT connection. Try both
    // conntrack families rather than inferring them from the listener's family.
    let levels = if stream.local_addr()?.is_ipv6() {
        [libc::SOL_IPV6, libc::SOL_IP]
    } else {
        [libc::SOL_IP, libc::SOL_IPV6]
    };

    read_original_destination(stream, levels[0])
        .or_else(|_| read_original_destination(stream, levels[1]))
}

/// Read and decode one family's netfilter original-destination socket option.
fn read_original_destination(stream: &TcpStream, level: i32) -> Result<SocketAddr> {
    // SAFETY: zeroed sockaddr_storage is a valid getsockopt output buffer.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&storage) as libc::socklen_t;
    // SAFETY: storage is valid and writable for `length`; the live socket fd is borrowed.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            level,
            80,
            &mut storage as *mut _ as *mut libc::c_void,
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_ORIGINAL_DST");
    }
    match storage.ss_family as i32 {
        libc::AF_INET if length as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: kernel returned AF_INET with enough bytes, and storage has sufficient alignment.
            let address = unsafe { *(&storage as *const _ as *const libc::sockaddr_in) };
            Ok(SocketAddr::new(
                std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                u16::from_be(address.sin_port),
            ))
        }
        libc::AF_INET6 if length as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: kernel returned AF_INET6 with enough bytes, and storage has sufficient alignment.
            let address = unsafe { *(&storage as *const _ as *const libc::sockaddr_in6) };
            Ok(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )
            .into())
        }
        _ => crate::error::bail!("invalid original destination address"),
    }
}

/// Normalize mapped addresses before comparing local and original destinations.
fn normalize_socket_address(address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(ipv6) = address
        && let Some(ipv4) = ipv6.ip().to_ipv4_mapped()
    {
        return SocketAddr::new(ipv4.into(), address.port());
    }

    address
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, rules::RuleSet, state::Policy};

    /// Build isolated proxy policy and CA material for request-validation tests.
    async fn test_proxy() -> (tempfile::TempDir, Proxy, tokio::task::JoinHandle<Result<()>>) {
        let directory = tempfile::tempdir().unwrap();
        crate::ca::init(directory.path()).unwrap();
        let rules = RuleSet::parse(
            r#"
[[allow]]
domain = 'allowed.test'
pathname_pattern = '/allowed'
inject_headers = [{ name = 'Authorization', value = 'replacement' }]
"#,
            "test",
        )
        .unwrap();
        let (access_log, task) = AccessLog::start(crate::config::AccessLogConfig {
            path: directory.path().join("access.log"),
            ..crate::config::AccessLogConfig::default()
        })
        .await
        .unwrap();
        let proxy = Proxy {
            access_log,
            policy: Arc::new(arc_swap::ArcSwap::from_pointee(Policy {
                config: Config::default(),
                rules,
            })),
            authority: Arc::new(Authority::load(directory.path()).unwrap()),
            exec: Executor::default(),
        };
        (directory, proxy, task)
    }

    /// Verify injections survive client hop-by-hop directives while proxy credentials are removed.
    #[tokio::test]
    async fn fixes_route_before_injection_and_cleans_client_headers() {
        let (_directory, proxy, task) = test_proxy().await;
        let mut request = Request::builder()
            .uri("https://allowed.test/allowed?x=1")
            .header("Host", "allowed.test")
            .header("Authorization", "client-supplied")
            .header("Proxy-Authorization", "proxy-secret")
            .header("Connection", "Authorization")
            .body(Body::empty())
            .unwrap();

        let mut entry = access_entry(&request, &Target::default());
        proxy.prepare(&mut request, &Target::default(), &mut entry).unwrap();

        assert_eq!(request.headers()["authorization"], "replacement");
        assert!(!request.headers().contains_key("proxy-authorization"));
        assert!(!request.headers().contains_key("connection"));
        assert_eq!(request.uri().host_str().unwrap(), "allowed.test");
        assert_eq!(request.uri().query_or_empty(), "x=1");
        assert_eq!(entry.rule, "test:allow#1");
        assert_eq!(entry.url, "https://allowed.test:443/allowed?x=1");
        drop(proxy);
        task.await.unwrap().unwrap();
    }

    /// Reject plaintext injections and keep transparent routing bound to the authorized URI.
    #[tokio::test]
    async fn rejects_plaintext_secrets_and_original_destination_override() {
        let (_directory, proxy, task) = test_proxy().await;
        let target = Target {
            original: Some("127.0.0.1:8443".parse().unwrap()),
            ..Target::default()
        };
        let mut request =
            Request::builder().uri("http://allowed.test/allowed").body(Body::empty()).unwrap();
        let mut entry = access_entry(&request, &target);
        assert_eq!(
            proxy.prepare(&mut request, &target, &mut entry).unwrap_err().0,
            StatusCode::FORBIDDEN
        );
        assert!(!request.headers().contains_key("authorization"));

        *request.uri_mut() = "https://allowed.test/allowed".parse().unwrap();
        request.headers_mut().insert("te", "gzip, trailers".parse().unwrap());
        proxy.prepare(&mut request, &target, &mut entry).unwrap();
        assert_eq!(request.uri().to_string(), "https://allowed.test:8443/allowed");
        assert!(request.extensions().get_ref::<rama::net::client::ConnectorTarget>().is_none());
        assert_eq!(request.headers()["te"], "trailers");
        drop(proxy);
        task.await.unwrap().unwrap();
    }

    /// Reject conflicting authority metadata and unsupported upgrades before forwarding.
    #[tokio::test]
    async fn rejects_conflicting_hosts_and_raw_upgrades() {
        let (_directory, proxy, task) = test_proxy().await;
        let mut request = Request::builder()
            .uri("http://allowed.test/allowed")
            .header("Host", "denied.test")
            .body(Body::empty())
            .unwrap();
        let mut entry = access_entry(&request, &Target::default());
        assert_eq!(
            proxy.prepare(&mut request, &Target::default(), &mut entry).unwrap_err().0,
            StatusCode::MISDIRECTED_REQUEST
        );

        request.headers_mut().insert("host", "allowed.test".parse().unwrap());
        request.headers_mut().insert("upgrade", "websocket".parse().unwrap());
        assert_eq!(
            proxy.prepare(&mut request, &Target::default(), &mut entry).unwrap_err().0,
            StatusCode::NOT_IMPLEMENTED
        );
        drop(proxy);
        task.await.unwrap().unwrap();
    }
}
