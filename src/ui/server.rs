//! UI listeners and request routing between the API and embedded assets.

use super::{api::Api, assets};
use crate::{config::UiConfig, error::ErrorChain, net};
use rama::{
    Service,
    http::{Request, Response, server::HttpServer},
    rt::Executor,
    service::service_fn,
};
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc};
use thiserror::Error;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

/// Concurrent UI connections per listener.
const CONNECTION_LIMIT: usize = 128;
/// The UI listen backlog.
const BACKLOG: i32 = 128;

/// UI listener failures.
#[derive(Debug, Error)]
pub enum UiError {
    /// A configured address could not be bound.
    #[error("bind UI {address}")]
    Bind {
        /// The configured address.
        address: SocketAddr,
        /// The socket error.
        #[source]
        source: io::Error,
    },
    /// A listener failed to accept connections.
    #[error("accept UI connection")]
    Accept(#[source] io::Error),
    /// A listener task panicked.
    #[error("UI listener task failed")]
    Task(#[from] tokio::task::JoinError),
}

/// Bind every configured interface before launching any listener tasks.
///
/// Each IPv4/IPv6 address owns its own socket, so IPv6 sockets are v6-only.
pub fn bind(config: &UiConfig) -> Result<Vec<TcpListener>, UiError> {
    let mut listeners = Vec::new();
    for host in &config.hosts {
        let address = SocketAddr::new(*host, config.port);
        let listener =
            net::tcp_listener(address, net::Stack::Separate, BACKLOG).map_err(|source| {
                UiError::Bind {
                    address,
                    source,
                }
            })?;
        listeners.push(listener);
    }
    Ok(listeners)
}

/// Send `/api/` requests to the API and everything else to the embedded assets.
pub async fn route(api: &Api, request: Request) -> Response {
    if request.uri().path_or_root().starts_with("/api/") {
        api.response(request).await
    } else {
        assets::response(&request)
    }
}

/// Serve every listener; a listener failure fails the whole UI.
pub async fn serve(
    listeners: Vec<TcpListener>,
    exec: Executor,
    api: Arc<Api>,
) -> Result<(), UiError> {
    let mut tasks = JoinSet::new();
    for listener in listeners {
        tasks.spawn(serve_listener(listener, exec.clone(), api.clone()));
    }
    match tasks.join_next().await {
        Some(result) => result?,
        None => std::future::pending().await,
    }
}

/// Accept bounded HTTP connections and cancel them when the listener shuts down.
async fn serve_listener(
    listener: TcpListener,
    exec: Executor,
    api: Arc<Api>,
) -> Result<(), UiError> {
    let limit = Arc::new(Semaphore::new(CONNECTION_LIMIT));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(UiError::Accept)?;
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    continue;
                };
                let api = api.clone();
                let server = HttpServer::auto(exec.clone()).service(service_fn(move |request: Request| {
                    let api = api.clone();
                    async move { Ok::<_, Infallible>(route(&api, request).await) }
                }));
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = server.serve(rama::tcp::TcpStream::new(stream)).await {
                        tracing::debug!(%peer, error = %ErrorChain(&*error), "UI connection ended");
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Permit disabling the UI and report an occupied listener as a startup error.
    #[test]
    fn listener_binding() {
        let disabled = UiConfig {
            hosts: Vec::new(),
            ..UiConfig::default()
        };
        assert!(bind(&disabled).unwrap().is_empty());
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = UiConfig {
            port: occupied.local_addr().unwrap().port(),
            ..UiConfig::default()
        };
        let error = bind(&config).unwrap_err();
        assert!(error.to_string().starts_with("bind UI 127.0.0.1:"));
    }
}
