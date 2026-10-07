use crate::error::{Context, Result, ensure};
use fancy_regex::Regex;
use rama::http::{HeaderName, HeaderValue};
use serde::Deserialize;
use std::{fs, path::Path};

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
    fn items(self) -> Result<Vec<String>> {
        let items = match self {
            Self::One(s) => vec![s],
            Self::Many(v) => v,
        };
        ensure!(
            !items.is_empty() && items.iter().all(|s| !s.trim().is_empty()),
            "expected a nonempty string or list of nonempty strings"
        );
        Ok(items)
    }
}

/// A strictly validated TOML document containing allow tables.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuleFile {
    allow: Vec<RawRule>,
}

/// Uncompiled rule fields deserialized from one allow table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    domain: Option<Strings>,
    domain_regex: Option<Strings>,
    include_subdomains: Option<bool>,
    methods: Option<Strings>,
    pathname_pattern: Option<Strings>,
    pathname_regex: Option<Strings>,
    inject_headers: Option<Vec<RawHeader>>,
    #[serde(default)]
    stream: bool,
}

/// A configured upstream header name and value.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHeader {
    name: String,
    value: String,
}

/// A compiled allow rule with HTTP constraints and header injections.
pub struct Rule {
    pub name: String,
    domains: Vec<String>,
    domain_regexes: Vec<Regex>,
    include_subdomains: bool,
    methods: Vec<String>,
    paths: Vec<Regex>,
    pub inject_headers: Vec<(HeaderName, HeaderValue)>,
    pub stream: bool,
}

/// Rules in deterministic filename and table order.
#[derive(Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

/// Trim whitespace and trailing dots, then lowercase the hostname.
pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_lowercase()
}

/// Compile a bounded Python-compatible regex, optionally ignoring case.
fn compile_regex(source: &str, insensitive: bool) -> Result<Regex> {
    // Python's end-of-string escape predates Rust's spelling.
    let source = source.replace("\\Z", "\\z");
    let source = if insensitive {
        format!("(?i:{source})")
    } else {
        source
    };
    Ok(fancy_regex::RegexBuilder::new(&source).backtrack_limit(100_000).build()?)
}

/// Evaluate a regex and deny matches when evaluation exceeds its limits.
fn matches(re: &Regex, value: &str) -> bool {
    match re.is_match(value) {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "rule regex evaluation failed; treating as no match");
            false
        }
    }
}

impl Rule {
    /// Check exact, subdomain, or regex hostname authorization.
    pub fn matches_host(&self, host: &str) -> bool {
        let host = normalize_host(host);
        self.domains.iter().any(|domain| {
            host == *domain || (self.include_subdomains && host.ends_with(&format!(".{domain}")))
        }) || self.domain_regexes.iter().any(|re| matches(re, &host))
    }

    /// Check the hostname, normalized method, and pathname filters together.
    fn matches_request(&self, host: &str, method: &str, path: &str) -> bool {
        (self.methods.is_empty() || self.methods.iter().any(|m| m == &method.trim().to_uppercase()))
            && self.matches_host(host)
            && (self.paths.is_empty() || self.paths.iter().any(|re| matches(re, path)))
    }
}
impl RuleSet {
    /// Validate a TOML rule document and compile its matchers.
    pub fn parse(text: &str, filename: &str) -> Result<Self> {
        let raw: RuleFile = toml::from_str(text)?;
        let mut rules = Vec::new();
        for (i, raw) in raw.allow.into_iter().enumerate() {
            let name = format!("{filename}:allow#{}", i + 1);
            let rule = (|| -> Result<Rule> {
                ensure!(
                    raw.domain.is_some() != raw.domain_regex.is_some(),
                    "exactly one of domain and domain_regex is required"
                );
                ensure!(
                    raw.domain_regex.is_none() || raw.include_subdomains.is_none(),
                    "include_subdomains is only valid with domain"
                );
                let domains = raw
                    .domain
                    .map(Strings::items)
                    .transpose()?
                    .unwrap_or_default()
                    .iter()
                    .map(|s| normalize_host(s))
                    .collect();
                let domain_regexes = raw
                    .domain_regex
                    .map(Strings::items)
                    .transpose()?
                    .unwrap_or_default()
                    .iter()
                    .map(|s| compile_regex(s, true))
                    .collect::<Result<_>>()?;
                let methods = match raw.methods {
                    None => vec!["GET".into(), "HEAD".into()],
                    Some(Strings::One(s)) => {
                        ensure!(s.trim().eq_ignore_ascii_case("ANY"), "string methods must be ANY");
                        Vec::new()
                    }
                    Some(s) => {
                        let methods: Vec<_> =
                            s.items()?.iter().map(|s| s.trim().to_uppercase()).collect();
                        ensure!(
                            !methods.iter().any(|s| s == "ANY"),
                            "use methods = 'ANY', not ANY in a list"
                        );
                        methods
                    }
                };
                let mut paths = Vec::new();
                if let Some(s) = raw.pathname_regex {
                    for s in s.items()? {
                        paths.push(compile_regex(&s, false)?);
                    }
                }
                if let Some(s) = raw.pathname_pattern {
                    for s in s.items()? {
                        paths.push(crate::pathname::compile(&s)?);
                    }
                }
                let mut inject_headers = Vec::new();
                if let Some(headers) = raw.inject_headers {
                    ensure!(!headers.is_empty(), "inject_headers must be a nonempty list");
                    for h in headers {
                        let header_name = HeaderName::from_bytes(h.name.trim().as_bytes())
                            .context("invalid injected header name")?;
                        let header_value = HeaderValue::from_str(&h.value)
                            .context("invalid injected header value")?;
                        inject_headers.push((header_name, header_value));
                    }
                }
                Ok(Rule {
                    name: name.clone(),
                    domains,
                    domain_regexes,
                    include_subdomains: raw.include_subdomains.unwrap_or(false),
                    methods,
                    paths,
                    inject_headers,
                    stream: raw.stream,
                })
            })()
            .with_context(|| name)?;
            rules.push(rule);
        }
        Ok(Self {
            rules,
        })
    }

    /// Load all TOML rule files in alphabetical filename order.
    pub fn load(directory: &Path) -> Result<Self> {
        let mut files = match fs::read_dir(directory) {
            Ok(files) => files.collect::<std::io::Result<Vec<_>>>()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        files.sort_by_key(|f| f.file_name());
        let mut rules = Vec::new();
        for file in files {
            let path = file.path();
            if path.extension().is_some_and(|s| s == "toml") && path.is_file() {
                rules.extend(
                    Self::parse(&fs::read_to_string(&path)?, &path.display().to_string())?.rules,
                );
            }
        }
        Ok(Self {
            rules,
        })
    }

    /// Return the first matching HTTP rule, excluding query and fragment.
    pub fn request(&self, host: &str, method: &str, path: &str) -> Option<&Rule> {
        let path = path.split(['?', '#']).next().filter(|s| !s.is_empty()).unwrap_or("/");
        self.rules.iter().find(|rule| rule.matches_request(host, method, path))
    }

    /// Return the first hostname match for DNS and CONNECT, ignoring HTTP constraints.
    pub fn dns_rule(&self, host: &str) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches_host(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared request inputs and expected decisions produced by the original Python implementation.
    #[derive(Deserialize)]
    struct ParityFixture {
        hosts: Vec<String>,
        methods: Vec<String>,
        paths: Vec<String>,
        suites: Vec<ParitySuite>,
    }

    /// One source TOML document and its Python HTTP/DNS decisions.
    #[derive(Deserialize)]
    struct ParitySuite {
        rules: String,
        expected: Vec<bool>,
        dns: Vec<bool>,
    }

    /// Compare compiled Rust rules against the original implementation's recorded decisions.
    #[test]
    fn matches_original_python_decisions() {
        let fixture: ParityFixture =
            serde_json::from_str(include_str!("../tests/fixtures/mitmwall-parity.json")).unwrap();

        for suite in fixture.suites {
            let rules = RuleSet::parse(&suite.rules, "parity").unwrap();
            let mut decisions = suite.expected.into_iter();

            for (host, dns_allowed) in fixture.hosts.iter().zip(suite.dns) {
                assert_eq!(rules.dns_rule(host).is_some(), dns_allowed, "{}: {host}", suite.rules);

                for method in &fixture.methods {
                    for path in &fixture.paths {
                        assert_eq!(
                            rules.request(host, method, path).is_some(),
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
        let rules = RuleSet::parse(
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
            "test",
        )
        .unwrap();
        assert!(rules.request(" Sub.Example.COM.. ", " get ", "/api/42?x=1").is_some());
        assert!(rules.request("badexample.com", "GET", "/api/42").is_none());
        assert!(rules.request("sub.example.com", "POST", "/api/42").is_none());
        assert_eq!(
            rules.request("example.com", "POST", "/upload/1").unwrap().inject_headers.len(),
            1
        );
        assert!(rules.request("example.com", "GET", "/api/42").unwrap().inject_headers.is_empty());
        assert!(rules.dns_rule("sub.example.com").is_some());
        assert!(rules.dns_rule("example.com.evil.test").is_none());
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
            "domain = 'x'\nunknown = true",
            "domain_regex = '['",
            "domain = 'x'\ninject_headers = [{name='Bad Name', value='x'}]",
        ] {
            assert!(RuleSet::parse(&format!("[[allow]]\n{body}"), "test").is_err(), "{body}");
        }
        RuleSet::parse(include_str!("../example-rules.toml"), "examples").unwrap();
    }
}
