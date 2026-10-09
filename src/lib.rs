//! TOML-driven transparent HTTP(S) and DNS egress filtering for Linux.
//!
//! The crate is layered so that policy decisions, access-log formatting, firewall
//! plans, and rule-document editing are pure and unit-testable, while sockets,
//! files, signals, and subprocesses are confined to thin adapters.

pub mod app;
pub mod ca;
pub mod cli;
pub mod config;
pub mod dns;
pub mod error;
pub mod host;
pub mod net;
pub mod policy;
pub mod proxy;
pub mod runtime;
pub mod telemetry;
pub mod ui;

/// A boxed, sendable future used at dynamic trait boundaries.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    /// Collect every Rust source file below `directory`.
    fn rust_sources(directory: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_sources(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    /// Report whether a trimmed line declares a function, struct, enum, or trait.
    fn declares_item(line: &str) -> bool {
        let mut rest = line;
        for prefix in ["pub(crate) ", "pub(super) ", "pub ", "const ", "async ", "unsafe "] {
            rest = rest.strip_prefix(prefix).unwrap_or(rest);
        }
        ["fn ", "struct ", "enum ", "trait "].iter().any(|keyword| rest.starts_with(keyword))
    }

    /// Every function, struct, enum, and trait has a doc comment, including test code.
    ///
    /// Clippy's `missing_docs_in_private_items` covers non-test items, fields,
    /// and variants; it skips `#[cfg(test)]` code, which this check covers.
    #[test]
    fn every_item_has_a_doc_comment() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = vec![root.join("build.rs")];
        rust_sources(&root.join("src"), &mut files);
        let mut undocumented = Vec::new();
        for file in files {
            let text = fs::read_to_string(&file).unwrap();
            let lines: Vec<&str> = text.lines().map(str::trim).collect();
            for (index, line) in lines.iter().enumerate() {
                if !declares_item(line) {
                    continue;
                }
                let documented = lines[..index]
                    .iter()
                    .rev()
                    .find(|previous| !previous.starts_with("#["))
                    .is_some_and(|previous| previous.starts_with("///"));
                if !documented {
                    undocumented.push(format!("{}:{}", file.display(), index + 1));
                }
            }
        }
        assert!(undocumented.is_empty(), "undocumented items: {undocumented:#?}");
    }
}
