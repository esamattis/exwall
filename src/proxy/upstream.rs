//! The outbound HTTP client, built once and shared by every connection.

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
}

/// The production client: direct connections, verified TLS, and no connection reuse.
pub struct HttpUpstream {
    /// The layered Rama client.
    client: BoxService<Request, Response, BoxError>,
}

impl HttpUpstream {
    /// Build the client once, spawning connection tasks on `exec`.
    ///
    /// There are no automatic redirects or upstream proxies: every request is
    /// independently filtered. Upstream certificates are verified by rustls'
    /// default verifier, and connections are never pooled.
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
            .with_default_http_connector(exec)
            .without_connection_pool()
            .build_client();
        let client = (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            RemoveResponseHeaderLayer::hop_by_hop(),
            AddRequiredRequestHeadersLayer::new(),
        )
            .into_layer(client);
        Self {
            client: client.boxed(),
        }
    }
}

impl Upstream for HttpUpstream {
    /// Send the request through the shared client.
    fn send(&self, request: Request) -> BoxFuture<'_, Result<Response, BoxError>> {
        Box::pin(self.client.serve(request))
    }
}
