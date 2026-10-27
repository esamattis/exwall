//! The outbound HTTP clients, built once and shared by every connection.

use crate::BoxFuture;
use rama::{
    Layer, Service,
    error::BoxError,
    http::{
        Request, Response, Version,
        client::{EasyHttpWebClient, HttpPooledConnectorConfig},
        layer::{
            map_response_body::MapResponseBodyLayer, remove_header::RemoveResponseHeaderLayer,
            required_header::AddRequiredRequestHeadersLayer,
        },
    },
    rt::Executor,
    service::BoxService,
    tls::client::TlsClientConfig,
};
use std::time::Duration;

/// The most upstream connections the pool keeps, open or idle, across all origins.
///
/// When every slot is in use, a request waits for a connection to its origin to
/// free up or for an idle connection to evict. The limit is far above the
/// client connection limit so that the pool only bounds runaway growth.
const POOL_MAX_CONNECTIONS: usize = 4096;

/// How long an idle pooled connection may be reused.
///
/// This stays below common server keep-alive timeouts, such as Apache's five
/// seconds, so a request is rarely sent on a connection the server is closing.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(4);

/// Sends authorized requests to their destinations.
pub trait Upstream: Send + Sync {
    /// Forward one request and return the upstream response with a streaming body.
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>>;

    /// Forward a WebSocket handshake over HTTP/1.1, keeping its upgrade headers.
    ///
    /// A `101 Switching Protocols` response carries the pending upgraded connection
    /// in its extensions, ready for `rama::http::io::upgrade::handle_upgrade`.
    fn websocket(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>>;
}

/// The production clients: direct connections, verified TLS, and pooled connections.
pub struct HttpUpstream {
    /// The layered Rama client for ordinary requests.
    client: BoxService<Request, Response, BoxError>,
    /// The HTTP/1.1-only client for WebSocket handshakes.
    websocket: BoxService<Request, Response, BoxError>,
}

impl HttpUpstream {
    /// Build the clients once, spawning connection tasks on `exec`.
    ///
    /// There are no automatic redirects or upstream proxies: every request is
    /// independently filtered. Upstream certificates are verified by rustls'
    /// default verifier.
    ///
    /// Ordinary requests share pooled connections per scheme, host, and port, and
    /// HTTP/2 connections carry concurrent requests. Reuse avoids a new TCP and TLS
    /// handshake for every request, which made bursts of small requests, such as
    /// package manager metadata lookups, several times slower than direct access.
    /// Pooling happens after authorization, so it does not change which requests
    /// are allowed.
    ///
    /// The WebSocket client offers only `http/1.1` over TLS, because an HTTP/1.1
    /// upgrade cannot happen on HTTP/2, and it keeps the response's `Upgrade` and
    /// `Connection` headers, which the client needs to accept the handshake. It
    /// never pools, because an upgraded connection cannot serve another request.
    pub fn new(exec: Executor) -> Self {
        let client = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_dns_address_resolver(rama::dns::client::TokioDnsResolver::default())
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_rustls_and_default_http_version(
                TlsClientConfig::new().with_alpn_http_auto(),
                Version::HTTP_11,
            )
            .with_default_http_connector(exec.clone())
            // Box the connector so its deeply nested TLS and HTTP connection
            // futures live on the heap. Polling them inline under the pool
            // overflows the worker thread stack in debug builds.
            .map_connector(|connector| connector.boxed())
            .try_with_connection_pool(HttpPooledConnectorConfig {
                max_total: POOL_MAX_CONNECTIONS,
                idle_timeout: Some(POOL_IDLE_TIMEOUT),
                ..HttpPooledConnectorConfig::default()
            })
            .expect("the connection pool limits are non-zero")
            .build_client();
        let client = (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            RemoveResponseHeaderLayer::hop_by_hop(),
            AddRequiredRequestHeadersLayer::new(),
        )
            .into_layer(client);
        // The same connector, except that TLS offers only HTTP/1.1.
        let websocket = EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_dns_address_resolver(rama::dns::client::TokioDnsResolver::default())
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_rustls_and_default_http_version(
                TlsClientConfig::new().with_alpn_http_1(),
                Version::HTTP_11,
            )
            .with_default_http_connector(exec)
            .without_connection_pool()
            .build_client();
        let websocket = (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            AddRequiredRequestHeadersLayer::new(),
        )
            .into_layer(websocket);
        Self {
            client: client.boxed(),
            websocket: websocket.boxed(),
        }
    }
}

impl Upstream for HttpUpstream {
    /// Send the request through the shared client.
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
        Box::pin(self.client.serve(request))
    }

    /// Send the handshake through the HTTP/1.1-only client.
    fn websocket(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
        Box::pin(self.websocket.serve(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::{Body, StatusCode, body::util::BodyExt, server::HttpServer};
    use rama::service::service_fn;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::net::TcpListener;

    /// Serve plain HTTP on loopback and count the TCP connections it accepts.
    async fn counting_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let http = HttpServer::auto(Executor::default()).service(service_fn(
                        |_request: Request| async {
                            Ok::<_, Infallible>(Response::new(Body::from("ok")))
                        },
                    ));
                    let _ = http.serve(rama::tcp::TcpStream::new(stream)).await;
                });
            }
        });
        (format!("http://{address}/"), accepted)
    }

    /// Sequential requests to one origin reuse a single upstream connection.
    #[tokio::test]
    async fn requests_to_one_origin_share_a_connection() {
        let (url, accepted) = counting_server().await;
        let upstream = HttpUpstream::new(Executor::default());
        for _ in 0..3 {
            let request = Request::builder().uri(url.as_str()).body(Body::empty()).unwrap();
            let response = upstream.send(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"ok");
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }
}
