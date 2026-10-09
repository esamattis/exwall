//! HTTP method constraints of an allow rule.

/// The HTTP methods an allow rule authorizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodSet {
    /// Every method, written `methods = "ANY"`.
    Any,
    /// Only the listed uppercase methods.
    Only(Vec<String>),
}

impl Default for MethodSet {
    /// Rules without `methods` allow only GET and HEAD.
    fn default() -> Self {
        Self::Only(vec!["GET".into(), "HEAD".into()])
    }
}

impl MethodSet {
    /// Build a list of methods normalized to trimmed uppercase.
    pub fn only<'a>(methods: impl IntoIterator<Item = &'a str>) -> Self {
        Self::Only(methods.into_iter().map(normalize).collect())
    }

    /// Check a request method, tolerating surrounding whitespace and lowercase.
    pub fn allows(&self, method: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Only(methods) => {
                let method = normalize(method);
                methods.contains(&method)
            }
        }
    }
}

/// Normalize a method name to trimmed uppercase.
fn normalize(method: &str) -> String {
    method.trim().to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Defaults, ANY, and normalized lists behave like mitmwall.
    #[test]
    fn matches_methods_case_insensitively() {
        assert!(MethodSet::default().allows(" get "));
        assert!(MethodSet::default().allows("HEAD"));
        assert!(!MethodSet::default().allows("POST"));
        assert!(MethodSet::Any.allows("PATCH"));
        let post = MethodSet::only([" post "]);
        assert!(post.allows("POST"));
        assert!(!post.allows("GET"));
    }
}
