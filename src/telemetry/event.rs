//! Typed request events, recorded once per HTTP request, CONNECT, or DNS message.

use super::capture::Capture;
use crate::policy::{Decision, Host, MatchSource};
use hickory_proto::op::ResponseCode;

/// The application protocol inspected by a request handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// A DNS message transported over UDP or TCP.
    Dns,
    /// Plaintext HTTP proxy traffic.
    Http,
    /// HTTP over TLS, including explicit CONNECT setup.
    Https,
}

impl Protocol {
    /// Return the lowercase protocol column written to the access log.
    pub fn name(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// A processing failure recorded separately from policy and protocol response codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Communication with an upstream failed before a valid response arrived.
    Upstream,
    /// Waiting for an upstream exceeded the request deadline.
    UpstreamTimeout,
    /// A DNS upstream returned an invalid or mismatched response.
    InvalidDnsReply,
    /// An incoming DNS packet could not be parsed.
    MalformedDns,
    /// HTTP request metadata or an unsupported operation prevented processing.
    InvalidRequest,
    /// The local HTTP CONNECT reply service failed to establish a tunnel.
    ConnectSetup,
    /// Request processing was cancelled before producing a response.
    Cancelled,
    /// The DNS concurrency limit prevented request processing.
    Overloaded,
}

impl Failure {
    /// Return a stable error token that never contains an HTTP status or DNS response code.
    pub fn name(self) -> &'static str {
        match self {
            Self::Upstream => "UPSTREAM_FAILURE",
            Self::UpstreamTimeout => "UPSTREAM_TIMEOUT",
            Self::InvalidDnsReply => "INVALID_DNS_REPLY",
            Self::MalformedDns => "MALFORMED_DNS",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::ConnectSetup => "CONNECT_SETUP",
            Self::Cancelled => "CANCELLED",
            Self::Overloaded => "OVERLOADED",
        }
    }
}

/// One request's arrival time, policy match, and response outcome.
#[derive(Clone, Debug)]
pub struct RequestEvent {
    /// Request arrival time.
    pub timestamp: jiff::Timestamp,
    /// The inspected protocol.
    pub protocol: Protocol,
    /// The policy decision.
    pub decision: Decision,
    /// What authorized the request, or each DNS question; empty when nothing matched.
    pub matches: Vec<Option<MatchSource>>,
    /// The HTTP method; `None` for DNS.
    pub method: Option<String>,
    /// The request URL, or comma-separated `dns://host/TYPE` questions.
    pub url: String,
    /// Normalized hosts the decision applies to, for domain statistics.
    pub subjects: Vec<Host>,
    /// The query-free HTTP pathname, retained for request history; `None` for CONNECT and DNS.
    pub pathname: Option<String>,
    /// The raw HTTP query string without `?`, retained for request history; `None` when the
    /// request has no query, and for CONNECT and DNS.
    pub query: Option<String>,
    /// Captured headers and bodies, while capturing is enabled; never written to the access log.
    pub capture: Option<Capture>,
    /// The HTTP status returned to the client.
    pub http_status: Option<u16>,
    /// The DNS response code returned to the client.
    pub dns_rcode: Option<ResponseCode>,
    /// A processing failure; new events assume cancellation until a response is recorded.
    pub failure: Option<Failure>,
}

impl RequestEvent {
    /// Capture HTTP request metadata before filtering or waiting for an upstream.
    pub fn http(protocol: Protocol, method: impl Into<String>, url: impl Into<String>) -> Self {
        Self::new(protocol, Some(method.into()), url.into())
    }

    /// Capture a DNS message whose questions are not yet parsed.
    pub fn dns() -> Self {
        Self::new(Protocol::Dns, None, String::new())
    }

    /// Build an unevaluated event that is cancelled unless a response is recorded.
    fn new(protocol: Protocol, method: Option<String>, url: String) -> Self {
        Self {
            timestamp: jiff::Timestamp::now(),
            protocol,
            decision: Decision::Unevaluated,
            matches: Vec::new(),
            method,
            url,
            subjects: Vec::new(),
            pathname: None,
            query: None,
            capture: None,
            http_status: None,
            dns_rcode: None,
            failure: Some(Failure::Cancelled),
        }
    }

    /// Record the policy decision even if subsequent forwarding fails or is interrupted.
    pub fn decide(&mut self, decision: Decision) {
        self.decision = decision;
    }

    /// Record the rule or exception that authorized an HTTP request.
    pub fn matched(&mut self, source: MatchSource) {
        self.matches = vec![Some(source)];
    }

    /// Record the HTTP status returned to the client, clearing the presumed cancellation.
    pub fn respond_http(&mut self, status: u16) {
        self.http_status = Some(status);
        self.failure = None;
    }

    /// Record the DNS response code returned to the client, clearing the presumed cancellation.
    pub fn respond_dns(&mut self, code: ResponseCode) {
        self.dns_rcode = Some(code);
        self.failure = None;
    }

    /// Record why processing failed while preserving policy and any client response code.
    pub fn fail(&mut self, failure: Failure) {
        self.failure = Some(failure);
    }
}
