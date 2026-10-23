//! Pure HTTP authorization: request metadata and policy in, a forwarding plan or rejection out.

use crate::{
    policy::{
        Decision, Enforcement, Host, MatchSource, RuleId, RuleSet,
        path_safety::{is_clean_pathname, is_unambiguous_pathname},
    },
    proxy::websocket::is_websocket_handshake,
    telemetry::{Failure, Protocol, RequestEvent},
};
use rama::{
    extensions::ExtensionsRef,
    http::{HeaderName, HeaderValue, Method, Request, StatusCode, header},
    net::{address::Authority, uri::Uri},
    tls::SecureTransport,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::OwnedSemaphorePermit;

/// The request header carrying HTTP/2 settings in an h2c upgrade offer.
const HTTP2_SETTINGS: HeaderName = HeaderName::from_static("http2-settings");

/// Connection routing information retained while filtering HTTP requests.
#[derive(Clone, Debug, Default)]
pub struct Target {
    /// The pre-REDIRECT destination of a transparent connection.
    pub original: Option<SocketAddr>,
    /// The CONNECT authority of a tunnelled connection.
    pub tunnel: Option<Authority>,
    /// Whether the connection was TLS-terminated by the proxy.
    pub tls: bool,
    /// The client connection's slot under the proxy's connection limit.
    ///
    /// Tasks that outlive the HTTP connection, such as an open WebSocket or a
    /// CONNECT tunnel, keep a clone so the connection keeps counting toward the limit.
    pub slot: Option<Arc<OwnedSemaphorePermit>>,
}

/// An authorized request's fixed destination and header injections.
#[derive(Clone, Debug)]
pub struct ForwardPlan {
    /// The authorizing rule, or a blocking pause.
    pub source: MatchSource,
    /// The authorized, normalized host.
    pub host: Host,
    /// The absolute URI the request is forwarded to.
    pub destination: Uri,
    /// Headers replacing any client-supplied values.
    pub inject_headers: Vec<(HeaderName, HeaderValue)>,
}

/// An authorized CONNECT tunnel.
#[derive(Clone, Debug)]
pub struct ConnectPlan {
    /// The authorizing rule, or a blocking pause.
    pub source: MatchSource,
    /// The normalized tunnel host.
    pub host: Host,
    /// The CONNECT target carried into the tunnel.
    pub authority: Authority,
}

/// Why the proxy answered a request itself instead of forwarding it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// CONNECT inside an intercepted connection.
    NestedConnect,
    /// No URI authority, Host header, tunnel, or original destination.
    MissingAuthority,
    /// The Host header cannot be parsed.
    InvalidHostHeader,
    /// The Host header names a different host than the request authority.
    HostMismatch,
    /// The request authority differs from the CONNECT target.
    TunnelMismatch,
    /// The request authority differs from the TLS server name.
    SniMismatch,
    /// The pathname contains control characters or a literal backslash, or it
    /// contains traversal or encoded separators while the matching rule cannot
    /// authorize ambiguous routes.
    AmbiguousPathname {
        /// The request host.
        host: Host,
        /// The request pathname.
        pathname: String,
        /// The first rule matching the literal pathname.
        rule: RuleId,
    },
    /// No rule authorizes the host, method, and pathname.
    NoRuleMatched {
        /// The request host.
        host: Host,
        /// The request pathname.
        pathname: String,
    },
    /// The request scheme is neither HTTP nor HTTPS.
    UnsupportedScheme {
        /// The request host.
        host: Host,
        /// The rule that authorized the request.
        rule: RuleId,
    },
    /// The authorizing rule injects headers, which plaintext would expose.
    InjectionRequiresHttps {
        /// The request host.
        host: Host,
        /// The request pathname.
        pathname: String,
        /// The rule that would inject headers.
        rule: RuleId,
    },
    /// The authorized destination does not form a valid URI.
    InvalidDestination {
        /// The request host.
        host: Host,
        /// The rule that authorized the request.
        rule: RuleId,
    },
    /// A CONNECT request without an authority.
    InvalidConnect,
    /// No HTTP-capable rule authorizes the CONNECT host.
    ConnectDenied {
        /// The tunnel host.
        host: Host,
    },
}

impl Rejection {
    /// The HTTP status returned to the client.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::NestedConnect => StatusCode::METHOD_NOT_ALLOWED,
            Self::MissingAuthority
            | Self::InvalidHostHeader
            | Self::UnsupportedScheme {
                ..
            }
            | Self::InvalidDestination {
                ..
            }
            | Self::InvalidConnect => StatusCode::BAD_REQUEST,
            Self::HostMismatch | Self::TunnelMismatch | Self::SniMismatch => {
                StatusCode::MISDIRECTED_REQUEST
            }
            Self::AmbiguousPathname {
                ..
            }
            | Self::NoRuleMatched {
                ..
            }
            | Self::InjectionRequiresHttps {
                ..
            }
            | Self::ConnectDenied {
                ..
            } => StatusCode::FORBIDDEN,
        }
    }

    /// The plaintext explanation returned to the client.
    pub fn message(&self) -> &'static str {
        match self {
            Self::NestedConnect => "nested CONNECT is not allowed\n",
            Self::MissingAuthority => "missing or invalid authority\n",
            Self::InvalidHostHeader => "invalid Host header\n",
            Self::HostMismatch => "Host differs from request authority\n",
            Self::TunnelMismatch => "authority differs from CONNECT target\n",
            Self::SniMismatch => "authority differs from TLS server name\n",
            Self::AmbiguousPathname {
                ..
            } => "exwall: ambiguous pathname denied\n",
            Self::NoRuleMatched {
                ..
            } => "exwall: no allow rule matched\n",
            Self::UnsupportedScheme {
                ..
            } => "unsupported scheme\n",
            Self::InjectionRequiresHttps {
                ..
            } => "exwall: header injection requires HTTPS\n",
            Self::InvalidDestination {
                ..
            } => "invalid destination URI\n",
            Self::InvalidConnect => "invalid CONNECT\n",
            Self::ConnectDenied {
                ..
            } => "exwall: CONNECT hostname denied\n",
        }
    }

    /// The policy decision recorded for the request.
    ///
    /// Policy refusals are DENY, including a matched rule refusing an ambiguous
    /// pathname or plaintext injection. Other failures after a rule matched
    /// keep the ALLOW decision; checks that ran before policy evaluation are
    /// unevaluated.
    pub fn decision(&self) -> Decision {
        match self {
            Self::AmbiguousPathname {
                ..
            }
            | Self::NoRuleMatched {
                ..
            }
            | Self::InjectionRequiresHttps {
                ..
            }
            | Self::ConnectDenied {
                ..
            } => Decision::Deny,
            Self::UnsupportedScheme {
                ..
            }
            | Self::InvalidDestination {
                ..
            } => Decision::Allow,
            _ => Decision::Unevaluated,
        }
    }

    /// The processing failure recorded for the request; policy denials have none.
    pub fn failure(&self) -> Option<Failure> {
        (self.status() != StatusCode::FORBIDDEN).then_some(Failure::InvalidRequest)
    }

    /// The rule that matched before the rejection, if any.
    pub fn rule(&self) -> Option<&RuleId> {
        match self {
            Self::AmbiguousPathname {
                rule,
                ..
            }
            | Self::UnsupportedScheme {
                rule,
                ..
            }
            | Self::InjectionRequiresHttps {
                rule,
                ..
            }
            | Self::InvalidDestination {
                rule,
                ..
            } => Some(rule),
            _ => None,
        }
    }

    /// The host the decision applies to, if policy was evaluated.
    pub fn host(&self) -> Option<&Host> {
        match self {
            Self::AmbiguousPathname {
                host,
                ..
            }
            | Self::NoRuleMatched {
                host,
                ..
            }
            | Self::UnsupportedScheme {
                host,
                ..
            }
            | Self::InjectionRequiresHttps {
                host,
                ..
            }
            | Self::InvalidDestination {
                host,
                ..
            }
            | Self::ConnectDenied {
                host,
            } => Some(host),
            _ => None,
        }
    }

    /// Record this rejection's decision, rule, subject, status, and failure on an event.
    pub fn record(&self, event: &mut RequestEvent) {
        event.decide(self.decision());
        if let Some(rule) = self.rule() {
            event.matched(crate::policy::MatchSource::Rule(rule.clone()));
        }
        if let Some(host) = self.host() {
            event.subjects = vec![host.clone()];
        }
        event.respond_http(self.status().as_u16());
        if let Some(failure) = self.failure() {
            event.fail(failure);
        }
    }
}

/// Normalize the host of a URI authority.
fn authority_host(authority: &Authority) -> Host {
    Host::new(&authority.address.host.to_string())
}

/// Select the request authority from the URI, Host header, tunnel, or original destination.
fn request_authority(request: &Request, target: &Target) -> Option<Authority> {
    request
        .uri()
        .authority()
        .map(|authority| authority.into_owned())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
        })
        .or_else(|| target.tunnel.clone())
        .or_else(|| target.original.and_then(|address| address.to_string().parse().ok()))
}

/// The scheme of a request: HTTPS when TLS was terminated, else the URI scheme or HTTP.
fn request_scheme<'a>(request: &'a Request, target: &Target) -> &'a str {
    if target.tls {
        "https"
    } else {
        request.uri().scheme_str().unwrap_or("http")
    }
}

/// The TLS server name sent by the client, if the connection was TLS-terminated.
fn client_server_name(request: &Request) -> Option<Host> {
    let transport = request.extensions().get_ref::<SecureTransport>()?;
    let name = transport.client_hello()?.ext_server_name()?;
    Some(Host::new(name.as_str()))
}

/// Authorize request metadata and fix its destination before any header is injected.
///
/// While blocking is paused, a request the rules deny is still forwarded, but
/// without injected headers; see [`paused_plan`].
pub fn authorize(
    request: &Request,
    target: &Target,
    rules: &RuleSet,
    enforcement: Enforcement,
) -> Result<ForwardPlan, Rejection> {
    let rejection = match authorize_by_rules(request, target, rules) {
        Ok(plan) => return Ok(plan),
        Err(rejection) => rejection,
    };
    if enforcement == Enforcement::Paused
        && rejection.decision() == Decision::Deny
        && let Some(plan) = paused_plan(request, target)
    {
        return Ok(plan);
    }
    Err(rejection)
}

/// Forward a request the rules deny while blocking is paused.
///
/// A pause lifts only policy: it never injects headers, and requests with an
/// unclean pathname or an unsupported scheme keep their original rejection.
/// The authority checks already passed when the rules were evaluated.
fn paused_plan(request: &Request, target: &Target) -> Option<ForwardPlan> {
    let authority = request_authority(request, target)?;
    let host = authority_host(&authority);
    let (pathname, path) = request_path(request);
    if !is_clean_pathname(&pathname) {
        return None;
    }
    let scheme = request_scheme(request, target);
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let destination = destination_uri(scheme, &authority, target, &host, &path)?;
    Some(ForwardPlan {
        source: MatchSource::Paused,
        host,
        destination,
        inject_headers: Vec::new(),
    })
}

/// The pathname of a request, and the pathname with its query string.
fn request_path(request: &Request) -> (String, String) {
    let pathname = request.uri().path_or_root().into_owned();
    let mut path = pathname.clone();
    if let Some(query) = request.uri().query() {
        path.push('?');
        path.push_str(&query.to_string());
    }
    (pathname, path)
}

/// Build the absolute URI that forwards a request to `host`, or `None` if it is invalid.
///
/// The port is chosen by [`destination_port`].
fn destination_uri(
    scheme: &str,
    authority: &Authority,
    target: &Target,
    host: &Host,
    path: &str,
) -> Option<Uri> {
    let port = destination_port(scheme, authority, target);
    Uri::parse(format!("{scheme}://{}:{port}{path}", host.uri_host())).ok()
}

/// Select the port a request is forwarded to.
///
/// The port comes from the request authority, the CONNECT target, or the
/// original destination, defaulting to the scheme's port.
fn destination_port(scheme: &str, authority: &Authority, target: &Target) -> u16 {
    let default_port = if scheme == "https" {
        443
    } else {
        80
    };
    authority
        .port_u16()
        .or_else(|| target.tunnel.as_ref().and_then(Authority::port_u16))
        .or_else(|| target.original.map(|address| address.port()))
        .unwrap_or(default_port)
}

/// Authorize a request strictly by the allow rules.
///
/// The client-selected original IP supplies only a port; it can never override
/// hostname routing, so credentials always reach the authorized host.
///
/// Every pathname must be clean. Traversal and encoded separators are refused
/// only when the first matching rule cannot authorize every route they might
/// decode to (see [`RuleSet::admits_ambiguous_pathname`]), so domain-wide
/// rules allow paths such as `/@scope%2Fname`. An unclean or ambiguous path
/// that no rule matches is reported as unmatched, since no rule allows it at all.
fn authorize_by_rules(
    request: &Request,
    target: &Target,
    rules: &RuleSet,
) -> Result<ForwardPlan, Rejection> {
    if request.method() == Method::CONNECT {
        return Err(Rejection::NestedConnect);
    }
    let authority = request_authority(request, target).ok_or(Rejection::MissingAuthority)?;
    let host = authority_host(&authority);
    if let Some(value) = request.headers().get(header::HOST) {
        let header_authority = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<Authority>().ok())
            .ok_or(Rejection::InvalidHostHeader)?;
        if authority_host(&header_authority) != host {
            return Err(Rejection::HostMismatch);
        }
    }
    if let Some(tunnel) = &target.tunnel
        && authority_host(tunnel) != host
    {
        return Err(Rejection::TunnelMismatch);
    }
    if let Some(server_name) = client_server_name(request)
        && server_name != host
    {
        return Err(Rejection::SniMismatch);
    }
    let (pathname, path) = request_path(request);
    let method = request.method().as_str();
    let Some(rule) = rules.http_rule(&host, method, &path) else {
        return Err(Rejection::NoRuleMatched {
            host,
            pathname,
        });
    };
    let rule_id = rule.id().clone();
    let admitted = is_clean_pathname(&pathname)
        && (is_unambiguous_pathname(&pathname)
            || rules.admits_ambiguous_pathname(rule, &host, method));
    if !admitted {
        return Err(Rejection::AmbiguousPathname {
            host,
            pathname,
            rule: rule_id,
        });
    }
    let scheme = request_scheme(request, target);
    if !matches!(scheme, "http" | "https") {
        return Err(Rejection::UnsupportedScheme {
            host,
            rule: rule_id,
        });
    }
    if !rule.inject_headers().is_empty() && scheme != "https" {
        return Err(Rejection::InjectionRequiresHttps {
            host,
            pathname,
            rule: rule_id,
        });
    }
    let Some(destination) = destination_uri(scheme, &authority, target, &host, &path) else {
        return Err(Rejection::InvalidDestination {
            host,
            rule: rule_id,
        });
    };
    Ok(ForwardPlan {
        source: MatchSource::Rule(rule_id),
        host,
        destination,
        inject_headers: rule.inject_headers().to_vec(),
    })
}

/// Authorize a CONNECT hostname using HTTP-capable rules, ignoring method and path filters.
///
/// While blocking is paused, every CONNECT host is let through; the tunneled
/// requests are still authorized one by one.
pub fn authorize_connect(
    request: &Request,
    rules: &RuleSet,
    enforcement: Enforcement,
) -> Result<ConnectPlan, Rejection> {
    let authority = request.uri().authority().ok_or(Rejection::InvalidConnect)?.into_owned();
    let host = authority_host(&authority);
    let source = match rules.connect_rule(&host) {
        Some(rule) => MatchSource::Rule(rule.id().clone()),
        None if enforcement == Enforcement::Paused => MatchSource::Paused,
        None => {
            return Err(Rejection::ConnectDenied {
                host,
            });
        }
    };
    Ok(ConnectPlan {
        source,
        host,
        authority,
    })
}

/// Route the request to its authorized destination and replace client hop-by-hop headers.
///
/// Removing the hop-by-hop headers also strips every protocol upgrade offer:
/// `Upgrade`, `Connection` with the headers it names, and `HTTP2-Settings`. A
/// client offering h2c or any other upgrade is answered with an ordinary
/// response and stays on HTTP/1.1, where its later requests are still filtered.
/// WebSocket handshakes restore their own upgrade headers afterwards.
pub fn apply_plan(request: &mut Request, plan: &ForwardPlan) {
    *request.uri_mut() = plan.destination.clone();
    // TE: trailers is legal on HTTP/2 and advertises support for gRPC trailers.
    let accepts_trailers = request
        .headers()
        .get_all(header::TE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case("trailers"));
    rama::http::layer::remove_header::remove_hop_by_hop_request_headers(request.headers_mut());
    request.headers_mut().remove(HTTP2_SETTINGS);
    if accepts_trailers {
        request.headers_mut().insert(header::TE, HeaderValue::from_static("trailers"));
    }
    for (name, value) in &plan.inject_headers {
        request.headers_mut().insert(name.clone(), value.clone());
    }
}

/// Capture the protocol, method, and full URL before filtering, for absolute and origin-form requests.
///
/// A WebSocket handshake is described with the `ws` or `wss` protocol and URL scheme.
pub fn initial_event(request: &Request, target: &Target) -> RequestEvent {
    let scheme = request_scheme(request, target);
    let websocket = is_websocket_handshake(request);
    let protocol = match (scheme == "https", websocket) {
        (true, true) => Protocol::Wss,
        (true, false) => Protocol::Https,
        (false, true) => Protocol::Ws,
        (false, false) => Protocol::Http,
    };
    let authority = request
        .uri()
        .authority()
        .map(|authority| authority.to_string())
        .or_else(|| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .or_else(|| target.tunnel.as_ref().map(ToString::to_string))
        .or_else(|| target.original.map(|address| address.to_string()));
    let is_connect = request.method() == Method::CONNECT;
    let url = match authority {
        Some(authority) if is_connect => format!("https://{authority}/"),
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
    let url = if websocket {
        websocket_url(url)
    } else {
        url
    };
    let mut event = RequestEvent::http(protocol, request.method().as_str(), url);
    if !is_connect {
        event.pathname = Some(request.uri().path_or_root().into_owned());
        event.query = request.uri().query().map(|query| query.to_string());
        event.port = request_authority(request, target)
            .map(|authority| destination_port(scheme, &authority, target));
    }
    event
}

/// Record an authorized forwarding plan on an event.
pub fn record_plan(event: &mut RequestEvent, plan: &ForwardPlan) {
    event.decide(Decision::Allow);
    event.matched(plan.source.clone());
    event.subjects = vec![plan.host.clone()];
    let url = plan.destination.to_string();
    event.url = if matches!(event.protocol, Protocol::Ws | Protocol::Wss) {
        websocket_url(url)
    } else {
        url
    };
}

/// Replace an `http` or `https` URL scheme with `ws` or `wss`.
fn websocket_url(url: String) -> String {
    if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::format;
    use rama::http::Body;

    /// Compile test rules.
    fn rules(text: &str) -> RuleSet {
        RuleSet::parse(text, "test").unwrap()
    }

    /// The rules used by most authorization tests.
    fn injecting_rules() -> RuleSet {
        rules(
            r#"
[[allow]]
domain = 'allowed.test'
pathname_pattern = '/allowed'
inject_headers = [{ name = 'Authorization', value = 'replacement' }]
"#,
        )
    }

    /// Build a request for `uri` with extra headers.
    fn request(uri: &str, headers: &[(&str, &str)]) -> Request {
        let mut builder = Request::builder().uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// Build an authority-form CONNECT request.
    fn connect_request(authority: &str) -> Request {
        let mut request = Request::builder().method(Method::CONNECT).body(Body::empty()).unwrap();
        *request.uri_mut() = Uri::parse_authority_form(authority).unwrap();
        request
    }

    /// Authorize and apply in one step, as the handler does.
    fn prepare(
        request: &mut Request,
        target: &Target,
        rules: &RuleSet,
    ) -> Result<ForwardPlan, Rejection> {
        let plan = authorize(request, target, rules, Enforcement::Enforced)?;
        apply_plan(request, &plan);
        Ok(plan)
    }

    /// Refuse traversal through an otherwise matching wildcard before injecting credentials.
    #[test]
    fn rejects_traversal_before_authorization_and_injection() {
        let rules = rules(
            "[[allow]]\ndomain = 'allowed.test'\npathname_pattern = '/allowed/*'\ninject_headers = [{name = 'Authorization', value = 'secret'}]",
        );
        for path in
            ["/allowed/../private", "/allowed/%2e%2e/private", "/allowed/%252e%252e/private"]
        {
            let mut request = request(&format!("https://allowed.test{path}"), &[]);
            let rejection = prepare(&mut request, &Target::default(), &rules).unwrap_err();
            assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
            assert_eq!(rejection.decision(), Decision::Deny);
            assert!(!request.headers().contains_key("authorization"));
        }
        let mut request = request("https://allowed.test/allowed/file.txt?next=/../private", &[]);
        prepare(&mut request, &Target::default(), &rules).unwrap();
        assert_eq!(request.headers()["authorization"], "secret");
    }

    /// Assert that `uri` is refused as an ambiguous pathname by rule `number` without injection.
    fn assert_ambiguous(rules: &RuleSet, uri: &str, number: usize) {
        let mut refused = request(uri, &[]);
        let rejection = prepare(&mut refused, &Target::default(), rules).unwrap_err();
        let Rejection::AmbiguousPathname {
            rule,
            ..
        } = &rejection
        else {
            panic!("{uri}: expected an ambiguous pathname, got {rejection:?}");
        };
        assert_eq!(rule, &RuleId::new("test", number), "{uri}");
        assert_eq!(rejection.decision(), Decision::Deny, "{uri}");
        assert!(!refused.headers().contains_key("authorization"), "{uri}");
    }

    /// Rules without path constraints allow encoded separators and dot segments verbatim.
    #[test]
    fn domain_wide_rules_allow_ambiguous_pathnames() {
        let rules = rules("[[allow]]\ndomain = 'registry.test'");
        for path in [
            "/@uiw%2Freact-codemirror",
            "/api/v4/projects/group%2frepo",
            "/a/%2e%2e/b",
            "/a/%252e%252e/b",
            "/bucket/key%5Cname",
        ] {
            let mut forwarded = request(&format!("https://registry.test{path}?x=1"), &[]);
            let plan = prepare(&mut forwarded, &Target::default(), &rules).unwrap();
            assert_eq!(plan.source.to_string(), "test:allow#1");
            assert_eq!(forwarded.uri().path_or_root(), path);
            assert_eq!(forwarded.uri().query_or_empty(), "x=1");
        }
    }

    /// Control characters are refused even when the matching rule allows every path.
    #[test]
    fn domain_wide_rules_refuse_control_characters() {
        let rules = rules("[[allow]]\ndomain = 'registry.test'");
        for path in ["/a%00b", "/a%0d%0aHost:%20evil.test", "/a%2500b"] {
            assert_ambiguous(&rules, &format!("https://registry.test{path}"), 1);
        }
    }

    /// A path-constrained rule refuses ambiguous paths it matches literally, and
    /// unclean paths no rule matches are reported as unmatched.
    #[test]
    fn path_constrained_rules_refuse_ambiguous_pathnames() {
        let rules = rules("[[allow]]\ndomain = 'allowed.test'\npathname_pattern = '/allowed/*'");
        for path in ["/allowed/%2f../private", "/allowed/%2e%2e/private", "/allowed/a%2fb"] {
            assert_ambiguous(&rules, &format!("https://allowed.test{path}"), 1);
        }
        for path in ["/other/%2f../private", "/other/%00"] {
            let rejection = authorize(
                &request(&format!("https://allowed.test{path}"), &[]),
                &Target::default(),
                &rules,
                Enforcement::Enforced,
            )
            .unwrap_err();
            assert_eq!(
                rejection,
                Rejection::NoRuleMatched {
                    host: Host::new("allowed.test"),
                    pathname: path.into(),
                }
            );
        }
    }

    /// An ambiguous path missing a path-constrained rule falls through to a later
    /// domain-wide rule, which authorizes every route and supplies its own headers.
    #[test]
    fn ambiguous_pathnames_fall_through_to_domain_wide_rules() {
        let rules = rules(
            r#"
[[allow]]
domain = 'registry.test'
pathname_pattern = '/@private/*'
inject_headers = [{ name = 'Authorization', value = 'private-token' }]
[[allow]]
domain = 'registry.test'
"#,
        );
        let mut encoded = request("https://registry.test/@private%2fpackage", &[]);
        let plan = prepare(&mut encoded, &Target::default(), &rules).unwrap();
        assert_eq!(plan.source.to_string(), "test:allow#2");
        assert!(!encoded.headers().contains_key("authorization"));
        assert_ambiguous(&rules, "https://registry.test/@private/%2e%2e/other", 1);
        let mut literal = request("https://registry.test/@private/package", &[]);
        prepare(&mut literal, &Target::default(), &rules).unwrap();
        assert_eq!(literal.headers()["authorization"], "private-token");
    }

    /// A later injecting rule cannot authorize an ambiguous path when an earlier
    /// path-constrained rule for the same host and method chose other headers,
    /// because the upstream might decode the path into that carved-out route.
    #[test]
    fn ambiguous_pathnames_cannot_escape_header_carve_outs() {
        let rules = rules(
            r#"
[[allow]]
domain = 'api.test'
pathname_pattern = '/echo/*'
[[allow]]
domain = 'api.test'
methods = ['POST']
pathname_pattern = '/other/*'
inject_headers = [{ name = 'Authorization', value = 'other' }]
[[allow]]
domain = 'api.test'
methods = 'ANY'
inject_headers = [{ name = 'Authorization', value = 'secret' }]
"#,
        );
        assert_ambiguous(&rules, "https://api.test/echo%2fheaders", 3);
        assert_ambiguous(&rules, "https://api.test/x/%2e%2e/echo/headers", 3);
        let mut plain = request("https://api.test/plain/path", &[]);
        prepare(&mut plain, &Target::default(), &rules).unwrap();
        assert_eq!(plain.headers()["authorization"], "secret");
        let mut post = request("https://api.test/other%2fx", &[]);
        *post.method_mut() = Method::POST;
        let rejection =
            authorize(&post, &Target::default(), &rules, Enforcement::Enforced).unwrap_err();
        assert_eq!(rejection.rule().unwrap().to_string(), "test:allow#3");
        // Neither carve-out applies to DELETE (rule 1 is GET and HEAD only, rule 2
        // is POST only), so the domain-wide rule already covers every DELETE route.
        let mut delete = request("https://api.test/echo%2fheaders", &[]);
        *delete.method_mut() = Method::DELETE;
        prepare(&mut delete, &Target::default(), &rules).unwrap();
        assert_eq!(delete.headers()["authorization"], "secret");
    }

    /// Verify injections survive client hop-by-hop directives while proxy credentials are removed.
    #[test]
    fn fixes_route_before_injection_and_cleans_client_headers() {
        let mut request = request(
            "https://allowed.test/allowed?x=1",
            &[
                ("Host", "allowed.test"),
                ("Authorization", "client-supplied"),
                ("Proxy-Authorization", "proxy-secret"),
                ("Connection", "Authorization"),
            ],
        );
        let target = Target::default();
        let mut event = initial_event(&request, &target);
        let plan = prepare(&mut request, &target, &injecting_rules()).unwrap();
        record_plan(&mut event, &plan);
        assert_eq!(request.headers()["authorization"], "replacement");
        assert!(!request.headers().contains_key("proxy-authorization"));
        assert!(!request.headers().contains_key("connection"));
        assert_eq!(request.uri().host_str().unwrap(), "allowed.test");
        assert_eq!(request.uri().query_or_empty(), "x=1");
        assert_eq!(plan.source.to_string(), "test:allow#1");
        assert_eq!(event.url, "https://allowed.test:443/allowed?x=1");
        assert_eq!(event.subjects, vec![Host::new("allowed.test")]);
    }

    /// Reject plaintext secrets and keep transparent routing bound to the authorized URI.
    #[test]
    fn rejects_plaintext_secrets_and_original_destination_override() {
        let target = Target {
            original: Some("127.0.0.1:8443".parse().unwrap()),
            ..Target::default()
        };
        let mut request = request("http://allowed.test/allowed", &[]);
        let rejection = prepare(&mut request, &target, &injecting_rules()).unwrap_err();
        assert_eq!(rejection.status(), StatusCode::FORBIDDEN);
        assert_eq!(rejection.rule().unwrap().to_string(), "test:allow#1");
        assert!(!request.headers().contains_key("authorization"));

        *request.uri_mut() = "https://allowed.test/allowed".parse().unwrap();
        request.headers_mut().insert("te", "gzip, trailers".parse().unwrap());
        prepare(&mut request, &target, &injecting_rules()).unwrap();
        assert_eq!(request.uri().to_string(), "https://allowed.test:8443/allowed");
        assert!(request.extensions().get_ref::<rama::net::client::ConnectorTarget>().is_none());
        assert_eq!(request.headers()["te"], "trailers");
    }

    /// Reject conflicting authority metadata before forwarding.
    #[test]
    fn rejects_conflicting_hosts() {
        let rules = injecting_rules();
        let request = request("http://allowed.test/allowed", &[("Host", "denied.test")]);
        let rejection =
            authorize(&request, &Target::default(), &rules, Enforcement::Enforced).unwrap_err();
        assert_eq!(rejection, Rejection::HostMismatch);
        assert_eq!(rejection.status(), StatusCode::MISDIRECTED_REQUEST);
    }

    /// Non-WebSocket upgrade offers such as h2c are authorized like any request and
    /// forwarded without their upgrade negotiation, so the client stays on HTTP/1.1.
    #[test]
    fn strips_non_websocket_upgrade_offers() {
        let rules = rules("[[allow]]\ndomain = 'allowed.test'");
        for (upgrade, connection) in
            [("h2c", "Upgrade, HTTP2-Settings"), ("websocket", "Upgrade"), ("TLS/1.0", "upgrade")]
        {
            let mut forwarded = request(
                "http://allowed.test/x",
                &[
                    ("Upgrade", upgrade),
                    ("Connection", connection),
                    ("HTTP2-Settings", "AAMAAABkAAQAAP__"),
                ],
            );
            if upgrade == "websocket" {
                // Only a GET can open a WebSocket.
                *forwarded.method_mut() = Method::HEAD;
            }
            assert!(!is_websocket_handshake(&forwarded), "{upgrade}");
            let event = initial_event(&forwarded, &Target::default());
            assert_eq!(event.protocol, Protocol::Http, "{upgrade}");
            let plan = prepare(&mut forwarded, &Target::default(), &rules).unwrap();
            assert_eq!(plan.source.to_string(), "test:allow#1");
            for name in ["upgrade", "connection", "http2-settings"] {
                assert!(!forwarded.headers().contains_key(name), "{upgrade}: {name}");
            }
        }
    }

    /// WebSocket handshakes follow the normal rules and are described as `ws` or `wss`.
    #[test]
    fn authorizes_websocket_handshakes_like_other_requests() {
        let handshake = |uri: &str| {
            request(
                uri,
                &[
                    ("Upgrade", "WebSocket"),
                    ("Connection", "keep-alive, Upgrade"),
                    ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                    ("Sec-WebSocket-Version", "13"),
                ],
            )
        };
        let rules = rules(
            "[[allow]]\ndomain = 'allowed.test'\npathname = '/socket'\ninject_headers = [{ name = 'Authorization', value = 'secret' }]",
        );
        let mut allowed = handshake("https://allowed.test/socket?x=1");
        assert!(is_websocket_handshake(&allowed));
        let mut event = initial_event(&allowed, &Target::default());
        assert_eq!(event.protocol, Protocol::Wss);
        assert_eq!(event.url, "wss://allowed.test/socket?x=1");
        let plan = prepare(&mut allowed, &Target::default(), &rules).unwrap();
        record_plan(&mut event, &plan);
        assert_eq!(event.url, "wss://allowed.test:443/socket?x=1");
        assert_eq!(allowed.headers()["authorization"], "secret");
        assert_eq!(allowed.headers()["sec-websocket-key"], "dGhlIHNhbXBsZSBub25jZQ==");

        let plaintext = handshake("http://allowed.test/socket");
        let rejection =
            authorize(&plaintext, &Target::default(), &rules, Enforcement::Enforced).unwrap_err();
        assert!(matches!(rejection, Rejection::InjectionRequiresHttps { .. }));
        let event = initial_event(&plaintext, &Target::default());
        assert_eq!(
            (event.protocol, event.url.as_str()),
            (Protocol::Ws, "ws://allowed.test/socket")
        );

        let denied = handshake("https://allowed.test/other");
        let rejection =
            authorize(&denied, &Target::default(), &rules, Enforcement::Enforced).unwrap_err();
        assert_eq!(rejection.decision(), Decision::Deny);
        let plan = authorize(&denied, &Target::default(), &rules, Enforcement::Paused).unwrap();
        assert_eq!(plan.source, MatchSource::Paused);
        assert!(plan.inject_headers.is_empty());
    }

    /// Origin-form requests use the Host header, then the tunnel or original destination.
    #[test]
    fn selects_authority_and_port_from_connection_metadata() {
        let rules = rules("[[allow]]\ndomain = ['allowed.test', '::1']\npathname_pattern = '/a'");
        let tunnel = Target {
            tunnel: Some("allowed.test:8443".parse().unwrap()),
            tls: true,
            ..Target::default()
        };
        let plan = authorize(&request("/a", &[]), &tunnel, &rules, Enforcement::Enforced).unwrap();
        assert_eq!(plan.destination.to_string(), "https://allowed.test:8443/a");
        let mismatch = authorize(
            &request("/a", &[("Host", "other.test")]),
            &tunnel,
            &rules,
            Enforcement::Enforced,
        );
        assert_eq!(mismatch.unwrap_err(), Rejection::TunnelMismatch);
        let transparent = Target {
            original: Some("[::1]:8080".parse().unwrap()),
            ..Target::default()
        };
        let plan =
            authorize(&request("/a", &[]), &transparent, &rules, Enforcement::Enforced).unwrap();
        assert_eq!(plan.destination.to_string(), "http://[::1]:8080/a");
        let missing =
            authorize(&request("/a", &[]), &Target::default(), &rules, Enforcement::Enforced);
        assert_eq!(missing.unwrap_err(), Rejection::MissingAuthority);
        let unusable = authorize(
            &request("/a", &[("Host", "bad host")]),
            &Target::default(),
            &rules,
            Enforcement::Enforced,
        );
        assert_eq!(unusable.unwrap_err(), Rejection::MissingAuthority);
        let invalid = request("http://allowed.test/a", &[("Host", "bad host")]);
        let invalid = authorize(&invalid, &Target::default(), &rules, Enforcement::Enforced);
        assert_eq!(invalid.unwrap_err(), Rejection::InvalidHostHeader);
    }

    /// Every rejection maps to one status, message, decision, and failure category.
    #[test]
    fn rejection_mapping_is_consistent() {
        let host = Host::new("h.test");
        let rule = RuleId::new("r", 1);
        let cases = [
            (Rejection::NestedConnect, 405, "-", "INVALID_REQUEST"),
            (Rejection::MissingAuthority, 400, "-", "INVALID_REQUEST"),
            (Rejection::InvalidHostHeader, 400, "-", "INVALID_REQUEST"),
            (Rejection::HostMismatch, 421, "-", "INVALID_REQUEST"),
            (Rejection::TunnelMismatch, 421, "-", "INVALID_REQUEST"),
            (Rejection::SniMismatch, 421, "-", "INVALID_REQUEST"),
            (
                Rejection::AmbiguousPathname {
                    host: host.clone(),
                    pathname: "/".into(),
                    rule: rule.clone(),
                },
                403,
                "DENY",
                "-",
            ),
            (
                Rejection::NoRuleMatched {
                    host: host.clone(),
                    pathname: "/".into(),
                },
                403,
                "DENY",
                "-",
            ),
            (
                Rejection::UnsupportedScheme {
                    host: host.clone(),
                    rule: rule.clone(),
                },
                400,
                "ALLOW",
                "INVALID_REQUEST",
            ),
            (
                Rejection::InjectionRequiresHttps {
                    host: host.clone(),
                    pathname: "/".into(),
                    rule: rule.clone(),
                },
                403,
                "DENY",
                "-",
            ),
            (
                Rejection::InvalidDestination {
                    host: host.clone(),
                    rule,
                },
                400,
                "ALLOW",
                "INVALID_REQUEST",
            ),
            (Rejection::InvalidConnect, 400, "-", "INVALID_REQUEST"),
            (
                Rejection::ConnectDenied {
                    host,
                },
                403,
                "DENY",
                "-",
            ),
        ];
        for (rejection, status, decision, failure) in cases {
            let mut event = RequestEvent::http(Protocol::Http, "GET", "http://h.test/");
            rejection.record(&mut event);
            let row = format::message(&event);
            let columns: Vec<_> = row.split(' ').collect();
            assert_eq!(rejection.status().as_u16(), status, "{rejection:?}");
            assert_eq!(columns[1], decision, "{rejection:?}");
            assert_eq!(columns[5], status.to_string(), "{rejection:?}");
            assert_eq!(columns[7], failure, "{rejection:?}");
            assert!(rejection.message().ends_with('\n'));
        }
    }

    /// CONNECT uses HTTP-capable rules and needs an authority.
    #[test]
    fn authorizes_connect_hosts() {
        let rules = rules(
            "[[allow]]\ndomain='dns.test'\ndns_only=true\n[[allow]]\ndomain='web.test'\npathname_pattern='/x'",
        );
        let connect = |authority: &str| {
            authorize_connect(&connect_request(authority), &rules, Enforcement::Enforced)
        };
        let plan = connect("WEB.test:443").unwrap();
        assert_eq!(plan.host, Host::new("web.test"));
        assert_eq!(plan.source.to_string(), "test:allow#2");
        assert_eq!(
            connect("dns.test:443").unwrap_err(),
            Rejection::ConnectDenied {
                host: Host::new("dns.test")
            }
        );
    }

    /// A pause forwards denied requests and CONNECT hosts without injecting headers.
    #[test]
    fn paused_blocking_forwards_denied_requests_without_injection() {
        let rules = injecting_rules();
        let paused = |uri: &str, target: &Target| {
            let mut forwarded = request(uri, &[("Authorization", "client")]);
            let plan = authorize(&forwarded, target, &rules, Enforcement::Paused)?;
            apply_plan(&mut forwarded, &plan);
            Ok::<_, Rejection>((plan, forwarded))
        };
        let (plan, forwarded) =
            paused("https://denied.test:8443/x?q=1", &Target::default()).unwrap();
        assert_eq!(plan.source, MatchSource::Paused);
        assert_eq!(plan.destination.to_string(), "https://denied.test:8443/x?q=1");
        assert_eq!(forwarded.headers()["authorization"], "client");

        let (plan, forwarded) = paused("https://allowed.test/allowed", &Target::default()).unwrap();
        assert_eq!(plan.source.to_string(), "test:allow#1");
        assert_eq!(forwarded.headers()["authorization"], "replacement");

        let (plan, forwarded) = paused("http://allowed.test/allowed", &Target::default()).unwrap();
        assert_eq!(plan.source, MatchSource::Paused);
        assert_eq!(forwarded.headers()["authorization"], "client");

        let rejection = paused("https://denied.test/a%00b", &Target::default()).unwrap_err();
        assert!(matches!(rejection, Rejection::NoRuleMatched { .. }));
        let mismatch = paused(
            "https://denied.test/x",
            &Target {
                tunnel: Some("other.test:443".parse().unwrap()),
                ..Target::default()
            },
        );
        assert_eq!(mismatch.unwrap_err(), Rejection::TunnelMismatch);

        let plan =
            authorize_connect(&connect_request("denied.test:443"), &rules, Enforcement::Paused)
                .unwrap();
        assert_eq!(plan.source, MatchSource::Paused);
    }

    /// Initial events capture full URLs, pathnames, query strings, and destination ports, but
    /// no path or port for CONNECT.
    #[test]
    fn initial_events_describe_requests() {
        let event = initial_event(
            &request("/p?q=1", &[("Host", "h.test:8080")]),
            &Target {
                tls: true,
                ..Target::default()
            },
        );
        assert_eq!(event.protocol, Protocol::Https);
        assert_eq!(event.url, "https://h.test:8080/p?q=1");
        assert_eq!(event.pathname.as_deref(), Some("/p"));
        assert_eq!(event.query.as_deref(), Some("q=1"));
        assert_eq!(event.port, Some(8080));
        let event = initial_event(&request("/p", &[("Host", "h.test")]), &Target::default());
        assert_eq!(event.query, None);
        assert_eq!(event.port, Some(80));
        let event = initial_event(
            &request("/p", &[("Host", "h.test")]),
            &Target {
                original: Some("192.0.2.1:8443".parse().unwrap()),
                tls: true,
                ..Target::default()
            },
        );
        assert_eq!(event.port, Some(8443));
        let event = initial_event(
            &connect_request("h.test:443"),
            &Target {
                tls: true,
                ..Target::default()
            },
        );
        assert_eq!(event.url, "https://h.test:443/");
        assert_eq!(event.pathname, None);
        assert_eq!(event.query, None);
        assert_eq!(event.port, None);
    }
}
