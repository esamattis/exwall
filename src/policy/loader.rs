//! Loading every `*.toml` rule file in a directory as one ruleset.

use super::rules::{RuleFileError, RuleSet};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// How to treat a rules directory that does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingDirectory {
    /// Treat an absent directory as an empty ruleset (startup and validation).
    Empty,
    /// Reject an absent directory so a reload keeps the previous policy.
    Reject,
}

/// A rules directory that could not be loaded completely.
#[derive(Debug, Error)]
pub enum LoadError {
    /// The directory could not be listed.
    #[error("read rules directory {}", path.display())]
    ReadDirectory {
        /// The rules directory.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// A rule file could not be read.
    #[error("read rules file {}", path.display())]
    ReadFile {
        /// The rule file.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// A rule file is invalid.
    #[error("rules file {}", path.display())]
    Invalid {
        /// The rule file.
        path: PathBuf,
        /// The parse or validation failure.
        #[source]
        source: RuleFileError,
    },
}

/// Load all regular `*.toml` rule files in alphabetical filename order.
pub fn load_rules(directory: &Path, missing: MissingDirectory) -> Result<RuleSet, LoadError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound && missing == MissingDirectory::Empty =>
        {
            return Ok(RuleSet::default());
        }
        Err(source) => {
            return Err(LoadError::ReadDirectory {
                path: directory.to_owned(),
                source,
            });
        }
    };
    let mut files =
        entries.collect::<io::Result<Vec<_>>>().map_err(|source| LoadError::ReadDirectory {
            path: directory.to_owned(),
            source,
        })?;
    files.sort_by_key(|file| file.file_name());
    let mut rules = RuleSet::default();
    for file in files {
        let path = file.path();
        if path.extension().is_none_or(|extension| extension != "toml") {
            continue;
        }
        let metadata = fs::metadata(&path).map_err(|source| LoadError::ReadFile {
            path: path.clone(),
            source,
        })?;
        if !metadata.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|source| LoadError::ReadFile {
            path: path.clone(),
            source,
        })?;
        let parsed = RuleSet::parse(&text, &path.display().to_string()).map_err(|source| {
            LoadError::Invalid {
                path: path.clone(),
                source,
            }
        })?;
        rules.extend(parsed);
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Host;

    /// Files load in filename order, non-TOML files are ignored, and rule IDs carry paths.
    #[test]
    fn loads_toml_files_in_order() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("20-b.toml"), "[[allow]]\ndomain = 'b.test'\n").unwrap();
        fs::write(directory.path().join("10-a.toml"), "[[allow]]\ndomain = 'b.test'\n").unwrap();
        fs::write(directory.path().join("notes.txt"), "not rules").unwrap();
        fs::create_dir(directory.path().join("dir.toml")).unwrap();
        let rules = load_rules(directory.path(), MissingDirectory::Reject).unwrap();
        assert_eq!(rules.len(), 2);
        let first = rules.dns_rule(&Host::new("b.test")).unwrap().id().to_string();
        assert!(first.ends_with("10-a.toml:allow#1"), "{first}");
    }

    /// A missing directory is empty at startup but rejected during reloads.
    #[test]
    fn missing_directory_behaviour_is_explicit() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent");
        assert!(load_rules(&missing, MissingDirectory::Empty).unwrap().is_empty());
        assert!(matches!(
            load_rules(&missing, MissingDirectory::Reject),
            Err(LoadError::ReadDirectory { .. })
        ));
    }

    /// An invalid file rejects the entire ruleset and names the file.
    #[test]
    fn invalid_files_reject_the_whole_set() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("a.toml"), "[[allow]]\ndomain = 'ok.test'\n").unwrap();
        fs::write(directory.path().join("b.toml"), "[[allow]]\nunknown = true\n").unwrap();
        let error = load_rules(directory.path(), MissingDirectory::Empty).unwrap_err();
        assert!(error.to_string().contains("b.toml"));
    }
}
