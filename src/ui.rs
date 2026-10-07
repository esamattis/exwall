//! Serve the compiled React application using the existing Rama HTTP stack.
use crate::{
    config::UiConfig,
    error::{Context, Result},
};
use rama::{
    Service,
    http::{Body, Method, Request, Response, StatusCode, header, server::HttpServer},
    rt::Executor,
    service::service_fn,
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};

include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

/// Bind every configured interface before launching any listener tasks.
pub fn bind(config: &UiConfig) -> Result<Vec<TcpListener>> {
    let mut listeners = Vec::new();
    for host in &config.hosts {
        let address = SocketAddr::new(*host, config.port);
        let socket = socket2::Socket::new(
            if host.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_reuse_address(true)?;
        if host.is_ipv6() {
            // Each configured IPv4/IPv6 interface owns its own socket.
            socket.set_only_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into()).with_context(|| format!("bind UI {address}"))?;
        socket.listen(128)?;
        listeners.push(TcpListener::from_std(socket.into())?);
    }
    Ok(listeners)
}

/// Supervise UI listeners together so a listener failure fails the service.
pub async fn serve(
    listeners: Vec<TcpListener>,
    exec: Executor,
    api: Arc<crate::ui_api::Api>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    for listener in listeners {
        tasks.spawn(serve_listener(listener, exec.clone(), api.clone()));
    }
    match tasks.join_next().await {
        Some(result) => result.context("UI listener task failed")?,
        None => std::future::pending().await,
    }
}

/// Accept bounded HTTP connections and cancel them when the listener shuts down.
async fn serve_listener(
    listener: TcpListener,
    exec: Executor,
    api: Arc<crate::ui_api::Api>,
) -> Result<()> {
    let limit = Arc::new(Semaphore::new(128));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    continue;
                };
                let api = api.clone();
                let server = HttpServer::auto(exec.clone()).service(service_fn(move |request: Request| {
                    let api = api.clone();
                    async move {
                        if request.uri().path_or_root().starts_with("/api/") {
                            Ok::<_, Infallible>(api.response(request).await)
                        } else {
                            response(request).await
                        }
                    }
                }));
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = server.serve(rama::tcp::TcpStream::new(stream)).await {
                        tracing::debug!(%peer, %error, "UI connection ended");
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Serve GET/HEAD assets and HTML navigation fallbacks without touching disk.
async fn response(request: Request) -> Result<Response, Infallible> {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(header::ALLOW, "GET, HEAD".parse().unwrap());
        return Ok(response);
    }
    let request_path = request.uri().path_or_root();
    let path = request_path.trim_start_matches('/');
    let asset = ASSETS.iter().find(|(name, _)| *name == path);
    // Missing assets/API paths must remain 404; only HTML navigation gets SPA fallback.
    let navigation = !path.starts_with("assets/")
        && path != "api"
        && !path.starts_with("api/")
        && !path.rsplit('/').next().unwrap_or_default().contains('.');
    let asset = asset.or_else(|| {
        if path.is_empty() || navigation {
            ASSETS.iter().find(|(name, _)| *name == "index.html")
        } else {
            None
        }
    });
    let Some((name, bytes)) = asset else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    };
    let body = if request.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from(*bytes)
    };
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, content_type(name).parse().unwrap());
    headers.insert(header::CONTENT_LENGTH, bytes.len().into());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    headers.insert(header::CACHE_CONTROL, cache.parse().unwrap());
    Ok(response)
}

/// Assign browser MIME types for common Vite output files.
fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::http::body::util::BodyExt;

    /// Build an HTTP request for direct embedded-asset response tests.
    fn request(method: Method, path: &str) -> Request {
        Request::builder().method(method).uri(path).body(Body::empty()).unwrap()
    }

    /// Verify HTML navigation, hashed assets, MIME types, caching, and HEAD behavior.
    #[tokio::test]
    async fn embedded_assets_and_navigation() {
        let index = response(request(Method::GET, "/")).await.unwrap();
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(index.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(index.headers()[header::CACHE_CONTROL], "no-cache");
        let bytes = index.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("<title>exwall</title>"));
        let navigation = response(request(Method::GET, "/future/page?query=value")).await.unwrap();
        assert_eq!(navigation.into_body().collect().await.unwrap().to_bytes(), bytes);
        let (name, expected) = ASSETS.iter().find(|(name, _)| name.ends_with(".js")).unwrap();
        let asset = response(request(Method::GET, &format!("/{name}"))).await.unwrap();
        assert_eq!(asset.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        assert_eq!(asset.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        assert_eq!(asset.into_body().collect().await.unwrap().to_bytes().as_ref(), *expected);
        let head = response(request(Method::HEAD, &format!("/{name}"))).await.unwrap();
        assert_eq!(head.headers()[header::CONTENT_LENGTH], expected.len().to_string());
        assert!(head.into_body().collect().await.unwrap().to_bytes().is_empty());
    }

    /// Reject unsupported methods and missing assets instead of returning the SPA.
    #[tokio::test]
    async fn invalid_asset_requests() {
        for path in ["/assets/missing.js", "/missing.css", "/api", "/api/rules"] {
            assert_eq!(
                response(request(Method::GET, path)).await.unwrap().status(),
                StatusCode::NOT_FOUND
            );
        }
        let response = response(request(Method::POST, "/")).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
    }

    /// Permit disabling the UI and report an occupied listener as a startup error.
    #[tokio::test]
    async fn listener_binding() {
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
        assert!(bind(&config).is_err());
    }
}
