//! Compiled allow rules and first-match lookups for HTTP, CONNECT, and DNS.

use super::{
    host::Host,
    methods::MethodSet,
    pathname::{self, PathnameError},
};
use fancy_regex::Regex;
use rama::http::{HeaderName, HeaderValue};
use serde::Deserialize;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use thiserror::Error;

/// The backtracking budget for each regex evaluation.
const BACKTRACK_LIMIT: usize = 100_000;

/// Identifies one allow table by its source file and 1-based position.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RuleId {
    /// The rule file path or label.
    file: Arc<str>,
    /// The 1-based `[[allow]]` table number within the file.
    number: usize,
}

impl RuleId {
    /// Identify the `number`th (1-based) allow table in `file`.
    pub fn new(file: impl Into<Arc<str>>, number: usize) -> Self {
        Self {
            file: file.into(),
            number,
        }
    }
}

impl fmt::Display for RuleId {
    /// Render the stable `path:allow#N` identifier used in logs.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:allow#{}", self.file, self.number)
    }
}

/// A TOML value accepting either one string or a list of strings.
#[derive(Deserialize)]
#[serde(untagged)]
enum Strings {
    /// One hostname, method marker, or pathname matcher.
    One(String),
    /// Multiple alternatives supplied in a TOML array.
    Many(Vec<String>),
}

impl Strings {
    /// Normalize scalar/list syntax and reject empty rule values.
    fn items(self) -> Result<Vec<String>, RuleError> {
        let items = match self {
            Self::One(item) => vec![item],
            Self::Many(items) => items,
        };
        if items.is_empty() || items.iter().any(|item| item.trim().is_empty()) {
            return Err(RuleError::EmptyStrings);
        }
        Ok(items)
    }
}

/// A strictly validated TOML document containing allow tables.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuleFile {
    /// The `[[allow]]` tables in document order.
    allow: Vec<RawRule>,
}

/// Uncompiled rule fields deserialized from one allow table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    /// Exact domains.
    domain: Option<Strings>,
    /// Case-insensitive domain regexes.
    domain_regex: Option<Strings>,
    /// Whether exact domains also cover subdomains.
    include_subdomains: Option<bool>,
    /// Whether the rule authorizes only DNS.
    dns_only: Option<bool>,
    /// Method constraint: `"ANY"` or a list.
    methods: Option<Strings>,
    /// URLPattern-style pathname constraints.
    pathname_pattern: Option<Strings>,
    /// Pathname regex constraints.
    pathname_regex: Option<Strings>,
    /// Headers injected into authorized HTTPS requests.
    inject_headers: Option<Vec<RawHeader>>,
    /// Accept the legacy streaming option; all proxy responses already stream.
    #[serde(default, rename = "stream")]
    _stream: bool,
}

/// A configured upstream header name and value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeader {
    /// Header name.
    name: String,
    /// Header value.
    value: String,
}

/// A semantically invalid allow table.
#[derive(Debug, Error)]
pub enum RuleError {
    /// Neither or both of `domain` and `domain_regex` were given.
    #[error("exactly one of domain and domain_regex is required")]
    DomainChoice,
    /// `include_subdomains` was combined with `domain_regex`.
    #[error("include_subdomains is only valid with domain")]
    SubdomainsWithRegex,
    /// A string or list value is empty.
    #[error("expected a nonempty string or list of nonempty strings")]
    EmptyStrings,
    /// A scalar `methods` value other than ANY.
    #[error("string methods must be ANY")]
    ScalarMethod,
    /// ANY was listed among other methods.
    #[error("use methods = 'ANY', not ANY in a list")]
    AnyInList,
    /// `inject_headers` is an empty list.
    #[error("inject_headers must be a nonempty list")]
    EmptyHeaders,
    /// An injected header name is invalid.
    #[error("invalid injected header name")]
    HeaderName(#[source] rama::http::header::InvalidHeaderName),
    /// An injected header value is invalid.
    #[error("invalid injected header value")]
    HeaderValue(#[source] rama::http::header::InvalidHeaderValue),
    /// A domain or pathname regex failed to compile.
    #[error("invalid regex")]
    Regex(#[source] Box<fancy_regex::Error>),
    /// A pathname pattern is malformed.
    #[error(transparent)]
    Pathname(#[from] PathnameError),
}

/// A rule document that cannot be compiled.
#[derive(Debug, Error)]
pub enum RuleFileError {
    /// The TOML could not be deserialized into allow tables.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    /// One allow table is invalid.
    #[error("{id}")]
    Rule {
        /// The invalid table.
        id: RuleId,
        /// What is wrong with it.
        #[source]
        source: RuleError,
    },
}

/// A compiled regex that reports its first evaluation failure.
pub struct Matcher {
    /// The compiled expression.
    regex: Regex,
    /// Whether an evaluation failure has already been reported.
    reported: AtomicBool,
}

impl Matcher {
    /// Compile a bounded Python-compatible regex, optionally ignoring case.
    fn compile(source: &str, insensitive: bool) -> Result<Self, RuleError> {
        // Python's end-of-string escape predates Rust's spelling.
        let source = source.replace("\\Z", "\\z");
        let source = if insensitive {
            format!("(?i:{source})")
        } else {
            source
        };
        Self::build(&source)
    }

    /// Build a matcher from final regex source with the backtracking budget.
    fn build(source: &str) -> Result<Self, RuleError> {
        let regex = fancy_regex::RegexBuilder::new(source)
            .backtrack_limit(BACKTRACK_LIMIT)
            .build()
            .map_err(|error| RuleError::Regex(Box::new(error)))?;
        Ok(Self {
            regex,
            reported: AtomicBool::new(false),
        })
    }

    /// Evaluate the regex; an evaluation failure (such as an exhausted
    /// backtracking budget) is treated as no match and reported once per pattern.
    fn is_match(&self, value: &str, rule: &RuleId) -> bool {
        match self.regex.is_match(value) {
            Ok(matched) => matched,
            Err(error) => {
                if !self.reported.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        %rule,
                        pattern = self.regex.as_str(),
                        %error,
                        "rule regex could not be evaluated; treating it as not matching"
                    );
                }
                false
            }
        }
    }
}

/// A compiled allow rule with HTTP constraints and header injections.
pub struct Rule {
    /// Where the rule was defined.
    id: RuleId,
    /// Exact normalized domains.
    domains: Vec<Host>,
    /// Case-insensitive domain regexes.
    domain_regexes: Vec<Matcher>,
    /// Whether exact domains cover their subdomains.
    include_subdomains: bool,
    /// Whether the rule authorizes DNS only.
    dns_only: bool,
    /// Authorized HTTP methods.
    methods: MethodSet,
    /// Pathname constraints; empty means every path.
    paths: Vec<Matcher>,
    /// Headers injected into authorized HTTPS requests.
    inject_headers: Vec<(HeaderName, HeaderValue)>,
}

impl Rule {
    /// Return the rule's file and position.
    pub fn id(&self) -> &RuleId {
        &self.id
    }

    /// Return the headers this rule injects into forwarded requests.
    pub fn inject_headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.inject_headers
    }

    /// Report whether the rule authorizes only DNS.
    pub fn is_dns_only(&self) -> bool {
        self.dns_only
    }

    /// Check exact, subdomain, or regex hostname authorization.
    pub fn matches_host(&self, host: &Host) -> bool {
        let exact = self.domains.iter().any(|domain| {
            host == domain || (self.include_subdomains && host.is_subdomain_of(domain))
        });
        exact || self.domain_regexes.iter().any(|regex| regex.is_match(host.as_str(), &self.id))
    }

    /// Report whether the rule restricts pathnames with patterns or regexes.
    pub fn has_path_constraint(&self) -> bool {
        !self.paths.is_empty()
    }

    /// Check that the rule authorizes HTTP for the hostname and method, ignoring pathnames.
    fn matches_endpoint(&self, host: &Host, method: &str) -> bool {
        !self.dns_only && self.methods.allows(method) && self.matches_host(host)
    }

    /// Check the hostname, method, and pathname filters together.
    fn matches_request(&self, host: &Host, method: &str, path: &str) -> bool {
        self.matches_endpoint(host, method)
            && (self.paths.is_empty()
                || self.paths.iter().any(|regex| regex.is_match(path, &self.id)))
    }

    /// Compile one raw allow table.
    fn compile(id: RuleId, raw: RawRule) -> Result<Self, RuleError> {
        if raw.domain.is_some() == raw.domain_regex.is_some() {
            return Err(RuleError::DomainChoice);
        }
        if raw.domain_regex.is_some() && raw.include_subdomains.is_some() {
            return Err(RuleError::SubdomainsWithRegex);
        }
        let domains = match raw.domain {
            Some(domains) => domains.items()?.iter().map(|domain| Host::new(domain)).collect(),
            None => Vec::new(),
        };
        let mut domain_regexes = Vec::new();
        if let Some(regexes) = raw.domain_regex {
            for source in regexes.items()? {
                domain_regexes.push(Matcher::compile(&source, true)?);
            }
        }
        let methods = compile_methods(raw.methods)?;
        let mut paths = Vec::new();
        if let Some(regexes) = raw.pathname_regex {
            for source in regexes.items()? {
                paths.push(Matcher::compile(&source, false)?);
            }
        }
        if let Some(patterns) = raw.pathname_pattern {
            for pattern in patterns.items()? {
                paths.push(Matcher::build(&pathname::compile_source(&pattern)?)?);
            }
        }
        let inject_headers = compile_headers(raw.inject_headers)?;
        Ok(Self {
            id,
            domains,
            domain_regexes,
            include_subdomains: raw.include_subdomains.unwrap_or(false),
            dns_only: raw.dns_only.unwrap_or(false),
            methods,
            paths,
            inject_headers,
        })
    }
}

/// Interpret the `methods` field: absent, `"ANY"`, or a list without ANY.
fn compile_methods(methods: Option<Strings>) -> Result<MethodSet, RuleError> {
    match methods {
        None => Ok(MethodSet::default()),
        Some(Strings::One(method)) => {
            if method.trim().eq_ignore_ascii_case("ANY") {
                Ok(MethodSet::Any)
            } else {
                Err(RuleError::ScalarMethod)
            }
        }
        Some(list) => {
            let items = list.items()?;
            if items.iter().any(|item| item.trim().eq_ignore_ascii_case("ANY")) {
                return Err(RuleError::AnyInList);
            }
            Ok(MethodSet::only(items.iter().map(String::as_str)))
        }
    }
}

/// Validate injected header names and values.
fn compile_headers(
    headers: Option<Vec<RawHeader>>,
) -> Result<Vec<(HeaderName, HeaderValue)>, RuleError> {
    let Some(headers) = headers else {
        return Ok(Vec::new());
    };
    if headers.is_empty() {
        return Err(RuleError::EmptyHeaders);
    }
    let mut compiled = Vec::new();
    for header in headers {
        let name =
            HeaderName::from_bytes(header.name.trim().as_bytes()).map_err(RuleError::HeaderName)?;
        let value = HeaderValue::from_str(&header.value).map_err(RuleError::HeaderValue)?;
        compiled.push((name, value));
    }
    Ok(compiled)
}

/// Rules in deterministic filename and table order.
#[derive(Default)]
pub struct RuleSet {
    /// Every compiled rule, in precedence order.
    rules: Vec<Rule>,
}

impl fmt::Debug for RuleSet {
    /// Summarize the ruleset by its rule identifiers.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_list().entries(self.rules.iter().map(|rule| rule.id.to_string())).finish()
    }
}

impl RuleSet {
    /// Validate a TOML rule document and compile its matchers, labelling rules with `file`.
    pub fn parse(text: &str, file: &str) -> Result<Self, RuleFileError> {
        let raw: RuleFile = toml::from_str(text)?;
        let file: Arc<str> = Arc::from(file);
        let mut rules = Vec::new();
        for (index, raw) in raw.allow.into_iter().enumerate() {
            let id = RuleId::new(file.clone(), index + 1);
            let rule = Rule::compile(id.clone(), raw).map_err(|source| RuleFileError::Rule {
                id,
                source,
            })?;
            rules.push(rule);
        }
        Ok(Self {
            rules,
        })
    }

    /// Append another set's rules after this set's rules.
    pub fn extend(&mut self, other: RuleSet) {
        self.rules.extend(other.rules);
    }

    /// Return the number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Report whether there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate rules in precedence order.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    /// Return the first matching HTTP rule; `path` may carry a query or fragment, which is ignored.
    pub fn http_rule(&self, host: &Host, method: &str, path: &str) -> Option<&Rule> {
        let path = path.split(['?', '#']).next().filter(|path| !path.is_empty()).unwrap_or("/");
        self.rules.iter().find(|rule| rule.matches_request(host, method, path))
    }

    /// Report whether `matched`, the first HTTP rule for a request, may authorize
    /// a pathname that upstreams could decode into a different route.
    ///
    /// A rule that constrains paths may not: its matchers saw only the literal
    /// path, so an encoded separator or dot segment could reach a route the
    /// rule never allowed. A rule without path constraints already authorizes
    /// every route on the host, so whichever route the upstream decodes is
    /// authorized too.
    ///
    /// One case remains. An earlier rule for the same host and method can
    /// constrain paths in order to give those routes different injected
    /// headers, or none. An ambiguous path can miss that rule literally yet
    /// reach one of its routes upstream carrying `matched`'s headers instead,
    /// which could expose credentials to an endpoint deliberately carved out
    /// of them. Such paths are refused whenever `matched` injects headers that
    /// an earlier path-constrained rule would not. When `matched` injects
    /// nothing the request carries only client-supplied headers, which the
    /// client could send anywhere on the host already.
    pub fn admits_ambiguous_pathname(&self, matched: &Rule, host: &Host, method: &str) -> bool {
        if matched.has_path_constraint() {
            return false;
        }
        if matched.inject_headers.is_empty() {
            return true;
        }
        self.rules
            .iter()
            .take_while(|rule| !std::ptr::eq(*rule, matched))
            .filter(|rule| rule.has_path_constraint() && rule.matches_endpoint(host, method))
            .all(|rule| rule.inject_headers == matched.inject_headers)
    }

    /// Return the first hostname match for DNS, ignoring HTTP constraints.
    pub fn dns_rule(&self, host: &Host) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches_host(host))
    }

    /// Authorize CONNECT hostnames using HTTP-capable rules, ignoring method and path filters.
    pub fn connect_rule(&self, host: &Host) -> Option<&Rule> {
        self.rules.iter().find(|rule| !rule.dns_only && rule.matches_host(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared request inputs and expected decisions produced by the original Python implementation.
    #[derive(Deserialize)]
    struct ParityFixture {
        /// Hostnames tried against every suite.
        hosts: Vec<String>,
        /// Methods tried for every host.
        methods: Vec<String>,
        /// Paths tried for every host and method.
        paths: Vec<String>,
        /// Rule documents with their recorded decisions.
        suites: Vec<ParitySuite>,
    }

    /// One source TOML document and its Python HTTP/DNS decisions.
    #[derive(Deserialize)]
    struct ParitySuite {
        /// The rule document.
        rules: String,
        /// HTTP decisions in host, method, path order.
        expected: Vec<bool>,
        /// DNS decisions per host.
        dns: Vec<bool>,
    }

    /// Compile rules from a test document.
    fn rules(text: &str) -> RuleSet {
        RuleSet::parse(text, "test").unwrap()
    }

    /// Look up an HTTP rule's identifier from raw request parts.
    fn http(rules: &RuleSet, host: &str, method: &str, path: &str) -> Option<String> {
        rules.http_rule(&Host::new(host), method, path).map(|rule| rule.id().to_string())
    }

    /// Compare compiled Rust rules against the original implementation's recorded decisions.
    #[test]
    fn matches_original_python_decisions() {
        let fixture: ParityFixture =
            serde_json::from_str(include_str!("../../tests/fixtures/mitmwall-parity.json"))
                .unwrap();
        for suite in fixture.suites {
            let rules = RuleSet::parse(&suite.rules, "parity").unwrap();
            let mut decisions = suite.expected.into_iter();
            for (host, dns_allowed) in fixture.hosts.iter().zip(suite.dns) {
                let normalized = Host::new(host);
                assert_eq!(
                    rules.dns_rule(&normalized).is_some(),
                    dns_allowed,
                    "{}: {host}",
                    suite.rules
                );
                for method in &fixture.methods {
                    for path in &fixture.paths {
                        assert_eq!(
                            rules.http_rule(&normalized, method, path).is_some(),
                            decisions.next().unwrap(),
                            "{}: {host} {method} {path}",
                            suite.rules
                        );
                    }
                }
            }
            assert!(decisions.next().is_none());
        }
    }

    /// Verify normalization, filtering, DNS authorization, and rule precedence.
    #[test]
    fn matching_and_precedence() {
        let rules = rules(
            r#"
[[allow]]
domain = ['Example.COM.', 'other.test']
include_subdomains = true
pathname_pattern = '/api/:id'
[[allow]]
domain_regex = '(^|\.)example\.com$'
methods = 'ANY'
pathname_regex = '(?<=/)upload(?=/|$)'
inject_headers = [{ name = 'Authorization', value = 'secret' }]
[[allow]]
domain = 'example.com'
methods = 'ANY'
"#,
        );
        assert_eq!(
            http(&rules, " Sub.Example.COM.. ", " get ", "/api/42?x=1").as_deref(),
            Some("test:allow#1")
        );
        assert!(http(&rules, "badexample.com", "GET", "/api/42").is_none());
        assert!(http(&rules, "sub.example.com", "POST", "/api/42").is_none());
        let upload = rules.http_rule(&Host::new("example.com"), "POST", "/upload/1").unwrap();
        assert_eq!(upload.inject_headers().len(), 1);
        let api = rules.http_rule(&Host::new("example.com"), "GET", "/api/42").unwrap();
        assert!(api.inject_headers().is_empty());
        assert!(rules.dns_rule(&Host::new("sub.example.com")).is_some());
        assert!(rules.dns_rule(&Host::new("example.com.evil.test")).is_none());
    }

    /// Keep DNS-only rules out of HTTP and CONNECT without masking later HTTP rules.
    #[test]
    fn dns_only_rules_do_not_authorize_http_or_connect() {
        let rules = rules(
            "[[allow]]\ndomain='dns.test'\ndns_only=true\nmethods='ANY'\n\
             [[allow]]\ndomain='both.test'\ndns_only=true\n\
             [[allow]]\ndomain='both.test'\nmethods=['POST']\npathname_pattern='/api'",
        );
        assert!(rules.dns_rule(&Host::new("DNS.TEST.")).is_some());
        assert!(rules.connect_rule(&Host::new("dns.test")).is_none());
        for method in ["GET", "HEAD", "POST", "DELETE"] {
            assert!(http(&rules, "dns.test", method, "/").is_none());
        }
        let both = Host::new("both.test");
        assert_eq!(rules.dns_rule(&both).unwrap().id().to_string(), "test:allow#2");
        assert_eq!(rules.connect_rule(&both).unwrap().id().to_string(), "test:allow#3");
        assert_eq!(http(&rules, "both.test", "POST", "/api").as_deref(), Some("test:allow#3"));
        assert!(http(&rules, "both.test", "GET", "/api").is_none());
    }

    /// Reject malformed rule formats and accept the shipped example rules.
    #[test]
    fn rejects_invalid_rules() {
        for body in [
            "domain = 'x'\ndomain_regex = 'x'",
            "domain_regex = 'x'\ninclude_subdomains = false",
            "domain = []",
            "domain = 'x'\nmethods = ['ANY']",
            "domain = 'x'\nmethods = 'GET'",
            "domain = 'x'\ninject_headers = []",
            "domain = 'x'\nstream = 1",
            "domain = 'x'\ndns_only = 'true'",
            "domain = 'x'\nunknown = true",
            "domain_regex = '['",
            "domain = 'x'\ninject_headers = [{name='Bad Name', value='x'}]",
        ] {
            assert!(RuleSet::parse(&format!("[[allow]]\n{body}"), "test").is_err(), "{body}");
        }
        RuleSet::parse(include_str!("../../example-rules.toml"), "examples").unwrap();
    }

    /// Invalid tables are reported with their file and table number.
    #[test]
    fn errors_identify_the_failing_table() {
        let error = RuleSet::parse("[[allow]]\ndomain='ok'\n[[allow]]\ndomain=''", "file.toml")
            .unwrap_err();
        assert_eq!(
            crate::error::ErrorChain(&error).to_string(),
            "file.toml:allow#2: expected a nonempty string or list of nonempty strings"
        );
    }

    /// A pathname regex exhausting its backtracking budget is treated as not matching.
    #[test]
    fn regex_evaluation_failures_do_not_match() {
        let rules = rules("[[allow]]\ndomain = 'x.test'\npathname_regex = '(a+)+\\1b'\n");
        let path = format!("/{}", "a".repeat(64));
        assert!(http(&rules, "x.test", "GET", &path).is_none());
        assert!(http(&rules, "x.test", "GET", &path).is_none());
    }
}
