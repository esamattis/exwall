//! The service-owned `05-web.toml` file edited by the UI.

use std::{
    fs, io,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// The UI-managed rule file name inside the rules directory.
pub const WEB_RULES_FILE: &str = "05-web.toml";

/// The outcome of a revision-checked write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The new contents were written.
    Written,
    /// The file changed since the expected revision was read.
    Conflict,
}

/// The UI rules file inside the rules directory.
#[derive(Clone, Debug)]
pub struct WebRulesFile {
    /// The rules directory.
    directory: PathBuf,
}

impl WebRulesFile {
    /// Manage `05-web.toml` inside `directory`.
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
        }
    }

    /// The file path.
    pub fn path(&self) -> PathBuf {
        self.directory.join(WEB_RULES_FILE)
    }

    /// Read the current contents; a missing file is an empty revision.
    pub fn read(&self) -> io::Result<String> {
        match fs::read_to_string(self.path()) {
            Ok(text) => Ok(text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(error),
        }
    }

    /// Replace the contents only if they still equal `expected`.
    ///
    /// The root-owned rules directory deliberately permits edits only to this
    /// file, so the existing inode is rewritten in place instead of renaming a
    /// replacement; symlinks are refused.
    pub fn replace_if_unchanged(&self, expected: &str, contents: &str) -> io::Result<WriteOutcome> {
        fs::create_dir_all(&self.directory)?;
        let mut file = open_private(&self.path())?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("web rules must be a regular file"));
        }
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
}

/// Open or create the file read-write with mode 0600, refusing symlinks.
fn open_private(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Writes require the expected revision and shrink files correctly.
    #[test]
    fn writes_only_matching_revisions() {
        let directory = tempfile::tempdir().unwrap();
        let file = WebRulesFile::new(directory.path().join("rules"));
        assert_eq!(file.read().unwrap(), "");
        assert_eq!(file.replace_if_unchanged("", "long contents").unwrap(), WriteOutcome::Written);
        assert_eq!(file.replace_if_unchanged("", "other").unwrap(), WriteOutcome::Conflict);
        assert_eq!(
            file.replace_if_unchanged("long contents", "short").unwrap(),
            WriteOutcome::Written
        );
        assert_eq!(file.read().unwrap(), "short");
        assert_eq!(fs::metadata(file.path()).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// A symlink in place of the file is never followed.
    #[test]
    fn refuses_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, "").unwrap();
        let file = WebRulesFile::new(directory.path().to_owned());
        symlink(&target, file.path()).unwrap();
        assert!(file.replace_if_unchanged("", "x").is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "");
    }
}
