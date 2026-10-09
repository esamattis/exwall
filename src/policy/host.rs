//! Hostnames normalized once at the boundary where they enter the policy.

use std::fmt;

/// A lowercase hostname or IP literal without surrounding whitespace, IPv6
/// brackets, or trailing dots.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Host(String);

impl Host {
    /// Normalize a hostname from a URI authority, Host header, SNI, DNS question, or rule.
    pub fn new(raw: &str) -> Self {
        let trimmed = raw.trim().trim_matches(['[', ']']).trim_end_matches('.');
        Self(trimmed.to_lowercase())
    }

    /// Return the normalized text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Report whether normalization left no hostname at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Report whether this is an IPv6 literal, which needs brackets inside URIs.
    pub fn is_ipv6_literal(&self) -> bool {
        self.0.contains(':')
    }

    /// Render the host for use inside a URI authority.
    pub fn uri_host(&self) -> String {
        if self.is_ipv6_literal() {
            format!("[{}]", self.0)
        } else {
            self.0.clone()
        }
    }

    /// Report whether this host is a strict subdomain of `domain`.
    pub fn is_subdomain_of(&self, domain: &Host) -> bool {
        self.0.len() > domain.0.len()
            && self.0.ends_with(&domain.0)
            && self.0.as_bytes()[self.0.len() - domain.0.len() - 1] == b'.'
    }
}

impl fmt::Display for Host {
    /// Display the normalized hostname.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Normalize case, whitespace, trailing dots, and IPv6 brackets.
    #[test]
    fn normalizes_every_input_form() {
        assert_eq!(Host::new(" Sub.Example.COM.. ").as_str(), "sub.example.com");
        assert_eq!(Host::new("[FD00::2]").as_str(), "fd00::2");
        assert_eq!(Host::new("LOCALHOST.").as_str(), "localhost");
        assert!(Host::new(".").is_empty());
        assert_eq!(Host::new("::1").uri_host(), "[::1]");
        assert_eq!(Host::new("example.com").uri_host(), "example.com");
    }

    /// Subdomain checks require a label boundary.
    #[test]
    fn subdomains_require_a_dot_boundary() {
        let domain = Host::new("example.com");
        assert!(Host::new("api.example.com").is_subdomain_of(&domain));
        assert!(!Host::new("badexample.com").is_subdomain_of(&domain));
        assert!(!Host::new("example.com").is_subdomain_of(&domain));
    }
}
