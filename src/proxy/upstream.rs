//! The outbound HTTP clients, built once and shared by every connection.

use crate::BoxFuture;
use rama::{
    Layer, Service,
    error::BoxError,
    http::{
        Request, Response, Version,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer, remove_header::RemoveResponseHeaderLayer,
            required_header::AddRequiredRequestHeadersLayer,
        },
    },
    rt::Executor,
    service::BoxService,
    tls::client::TlsClientConfig,
};

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

/// The production clients: direct connections, verified TLS, and no connection reuse.
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
    /// default verifier, and connections are never pooled.
    ///
    /// The WebSocket client offers only `http/1.1` over TLS, because an HTTP/1.1
    /// upgrade cannot happen on HTTP/2, and it keeps the response's `Upgrade` and
    /// `Connection` headers, which the client needs to accept the handshake.
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
            .without_connection_pool()
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
