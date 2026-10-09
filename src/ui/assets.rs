//! The compiled React application embedded at build time.

use rama::http::{Body, Method, Request, Response, StatusCode, header};

include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

/// Look up an embedded asset by its path relative to the bundle root.
fn find(name: &str) -> Option<&'static (&'static str, &'static [u8])> {
    ASSETS.iter().find(|(asset, _)| *asset == name)
}

/// Report whether a missing path is an HTML navigation that should receive the SPA.
///
/// Missing assets and API paths must stay 404; only extensionless routes fall back.
fn is_navigation(path: &str) -> bool {
    !path.starts_with("assets/")
        && path != "api"
        && !path.starts_with("api/")
        && !path.rsplit('/').next().unwrap_or_default().contains('.')
}

/// Serve GET/HEAD assets and HTML navigation fallbacks without touching disk.
pub fn response(request: &Request) -> Response {
    if request.method() != Method::GET && request.method() != Method::HEAD {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        response.headers_mut().insert(header::ALLOW, header::HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let request_path = request.uri().path_or_root();
    let path = request_path.trim_start_matches('/');
    let asset = find(path).or_else(|| {
        if path.is_empty() || is_navigation(path) {
            find("index.html")
        } else {
            None
        }
    });
    let Some((name, bytes)) = asset else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    };
    let body = if request.method() == Method::HEAD {
        Body::empty()
    } else {
        Body::from(*bytes)
    };
    let mut response = Response::new(body);
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(content_type(name)));
    headers.insert(header::CONTENT_LENGTH, bytes.len().into());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static(cache));
    response
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
        let index = response(&request(Method::GET, "/"));
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(index.headers()[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(index.headers()[header::CACHE_CONTROL], "no-cache");
        let bytes = index.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("<title>exwall</title>"));
        let navigation = response(&request(Method::GET, "/future/page?query=value"));
        assert_eq!(navigation.into_body().collect().await.unwrap().to_bytes(), bytes);
        let (name, expected) = ASSETS.iter().find(|(name, _)| name.ends_with(".js")).unwrap();
        let asset = response(&request(Method::GET, &format!("/{name}")));
        assert_eq!(asset.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        assert_eq!(asset.headers()[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
        assert_eq!(asset.into_body().collect().await.unwrap().to_bytes().as_ref(), *expected);
        let head = response(&request(Method::HEAD, &format!("/{name}")));
        assert_eq!(head.headers()[header::CONTENT_LENGTH], expected.len().to_string());
        assert!(head.into_body().collect().await.unwrap().to_bytes().is_empty());
    }

    /// Reject unsupported methods and missing assets instead of returning the SPA.
    #[test]
    fn invalid_asset_requests() {
        for path in ["/assets/missing.js", "/missing.css", "/api", "/api/rules"] {
            assert_eq!(response(&request(Method::GET, path)).status(), StatusCode::NOT_FOUND);
        }
        let response = response(&request(Method::POST, "/"));
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
    }
}
