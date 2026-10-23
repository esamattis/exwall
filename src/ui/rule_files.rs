//! The rule files in the rules directory that the UI lists and edits.

use std::{
    fs, io,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// The rule file the start hook always creates and the UI's traffic actions extend.
pub const WEB_RULES_FILE: &str = "05-web.toml";

/// The outcome of a revision-checked write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The new contents were written.
    Written,
    /// The file changed since the expected revision was read.
    Conflict,
}

/// The `*.toml` rule files directly inside the rules directory.
#[derive(Clone, Debug)]
pub struct RuleFiles {
    /// The rules directory.
    directory: PathBuf,
}

impl RuleFiles {
    /// Manage the rule files inside `directory`.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
        }
    }

    /// List editable rule file names in the loader's filename order.
    ///
    /// Only regular files are listed: symlinks and other entries cannot be
    /// edited in place. A missing directory has no files.
    pub fn list(&self) -> io::Result<Vec<String>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if is_rule_file_name(&name) && entry.file_type()?.is_file() {
                names.push(name);
            }
        }
        names.sort();
        Ok(names)
    }

    /// The absolute path of the rules directory, for display.
    ///
    /// The path is made absolute without touching the filesystem, like [`Self::path`].
    pub fn directory(&self) -> PathBuf {
        std::path::absolute(&self.directory).unwrap_or_else(|_| self.directory.clone())
    }

    /// The absolute path of the rule file `name`, for display.
    ///
    /// The path is made absolute without touching the filesystem; a relative
    /// path is returned unchanged if the working directory is unavailable.
    pub fn path(&self, name: &str) -> PathBuf {
        let path = self.directory.join(name);
        std::path::absolute(&path).unwrap_or(path)
    }

    /// Read the contents of the rule file `name`.
    pub fn read(&self, name: &str) -> io::Result<String> {
        let mut file = self.open(name, false)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        Ok(text)
    }

    /// Replace the contents of the rule file `name` only if they still equal `expected`.
    ///
    /// The root-owned rules directory permits edits only to existing files, so
    /// the existing inode is rewritten in place instead of renaming a
    /// replacement.
    pub fn replace_if_unchanged(
        &self,
        name: &str,
        expected: &str,
        contents: &str,
    ) -> io::Result<WriteOutcome> {
        let mut file = self.open(name, true)?;
        let mut latest = String::new();
        file.read_to_string(&mut latest)?;
        if latest != expected {
            return Ok(WriteOutcome::Conflict);
        }
        file.seek(SeekFrom::Start(0))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
        file.set_len(contents.len() as u64)?;
        file.sync_all()?;
        Ok(WriteOutcome::Written)
    }

    /// Open an existing regular rule file without following symlinks.
    ///
    /// Invalid names, symlinks, and non-regular files are reported as not found.
    fn open(&self, name: &str, write: bool) -> io::Result<fs::File> {
        if !is_rule_file_name(name) {
            return Err(not_found());
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.directory.join(name))
            .map_err(|error| {
                if error.raw_os_error() == Some(libc::ELOOP) {
                    not_found()
                } else {
                    error
                }
            })?;
        if !file.metadata()?.is_file() {
            return Err(not_found());
        }
        Ok(file)
    }
}

/// Whether `name` names a `*.toml` file directly inside the directory, as the loader accepts.
fn is_rule_file_name(name: &str) -> bool {
    !name.contains(['/', '\0']) && Path::new(name).extension().is_some_and(|ext| ext == "toml")
}

/// The error for a name that is not an editable rule file.
fn not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no such editable rule file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Only regular `*.toml` files are listed, in filename order.
    #[test]
    fn lists_regular_rule_files_in_order() {
        let directory = tempfile::tempdir().unwrap();
        let files = RuleFiles::new(directory.path().to_owned());
        fs::write(directory.path().join("20-b.toml"), "").unwrap();
        fs::write(directory.path().join("05-web.toml"), "").unwrap();
        fs::write(directory.path().join("notes.txt"), "").unwrap();
        fs::create_dir(directory.path().join("dir.toml")).unwrap();
        symlink(directory.path().join("20-b.toml"), directory.path().join("30-link.toml")).unwrap();
        assert_eq!(files.list().unwrap(), ["05-web.toml", "20-b.toml"]);
        assert!(RuleFiles::new(directory.path().join("absent")).list().unwrap().is_empty());
    }

    /// Display paths are absolute even for a relative rules directory.
    #[test]
    fn paths_are_absolute() {
        let files = RuleFiles::new("rules".into());
        let path = files.path("05-web.toml");
        assert!(path.is_absolute());
        assert!(path.ends_with("rules/05-web.toml"));
    }

    /// Writes require the expected revision, shrink files correctly, and never create files.
    #[test]
    fn writes_only_matching_revisions() {
        let directory = tempfile::tempdir().unwrap();
        let files = RuleFiles::new(directory.path().to_owned());
        let missing = files.replace_if_unchanged("05-web.toml", "", "x").unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        let path = directory.path().join("05-web.toml");
        fs::write(&path, "").unwrap();
        assert_eq!(files.read("05-web.toml").unwrap(), "");
        let replace =
            |expected, contents| files.replace_if_unchanged("05-web.toml", expected, contents);
        assert_eq!(replace("", "long contents").unwrap(), WriteOutcome::Written);
        assert_eq!(replace("", "other").unwrap(), WriteOutcome::Conflict);
        assert_eq!(replace("long contents", "short").unwrap(), WriteOutcome::Written);
        assert_eq!(files.read("05-web.toml").unwrap(), "short");
        assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// Symlinks, non-rule names, and paths outside the directory are never opened.
    #[test]
    fn refuses_symlinks_and_other_names() {
        let directory = tempfile::tempdir().unwrap();
        let rules = directory.path().join("rules");
        fs::create_dir(&rules).unwrap();
        let target = directory.path().join("target.toml");
        fs::write(&target, "").unwrap();
        fs::write(rules.join("notes.txt"), "").unwrap();
        symlink(&target, rules.join("link.toml")).unwrap();
        let files = RuleFiles::new(rules);
        for name in ["link.toml", "notes.txt", "../target.toml", "", "missing.toml"] {
            assert_eq!(files.read(name).unwrap_err().kind(), io::ErrorKind::NotFound, "{name}");
            let error = files.replace_if_unchanged(name, "", "x").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::NotFound, "{name}");
        }
        assert_eq!(fs::read_to_string(target).unwrap(), "");
    }
}
