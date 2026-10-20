//! Web UI credentials: password generation, in-place `config.toml` updates,
//! and the browser URLs where the configured UI can be reached.
//!
//! Editing goes through `toml_edit`, so comments, ordering, and formatting of
//! the operator's configuration survive credential rotation.

use crate::config::{Config, InvalidConfig, UiConfig};
use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    os::unix::fs::{MetadataExt, PermissionsExt, fchown},
    path::{Path, PathBuf},
};
use thiserror::Error;
use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

/// Username written when neither the command line nor the file names one.
pub const DEFAULT_USERNAME: &str = "admin";
/// Number of characters in a generated password.
const PASSWORD_LENGTH: usize = 24;
/// Characters a generated password is drawn from; none need quoting in a shell or URL.
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Mode of a configuration file created by this module; the service group may read it.
const NEW_FILE_MODE: u32 = 0o640;
/// A TEST-NET-1 address used only to ask the kernel which source address it routes from.
const ROUTE_PROBE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);

/// A complete web UI login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiCredentials {
    /// The login name.
    pub username: String,
    /// The login password.
    pub password: String,
}

impl UiCredentials {
    /// Return the configured login, or `None` when either part is empty and login is disabled.
    pub fn configured(ui: &UiConfig) -> Option<Self> {
        if ui.username.is_empty() || ui.password.is_empty() {
            return None;
        }
        Some(Self {
            username: ui.username.clone(),
            password: ui.password.clone(),
        })
    }
}

/// Whether existing complete credentials are replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rotation {
    /// Always generate a new password.
    Replace,
    /// Generate a password only when the configuration lacks complete credentials.
    IfMissing,
}

/// The credentials in effect after [`update`] and the UI settings they apply to.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The credentials now stored in the configuration file.
    pub credentials: UiCredentials,
    /// Whether the file was rewritten with new credentials.
    pub changed: bool,
    /// The UI listener settings from the configuration file.
    pub ui: UiConfig,
}

/// Failures editing a configuration document in memory.
#[derive(Debug, Error)]
pub enum EditError {
    /// The document is not valid TOML.
    #[error("parse TOML")]
    Syntax(#[from] toml_edit::TomlError),
    /// The document has a `ui` key that is not a table.
    #[error("`ui` must be a table")]
    UiNotTable,
    /// The document is not a valid exwall configuration.
    #[error(transparent)]
    Invalid(#[from] InvalidConfig),
}

/// Failures reading, updating, or writing UI credentials in the configuration file.
#[derive(Debug, Error)]
pub enum CredentialsError {
    /// The configuration file exists but could not be read.
    #[error("read config {}", path.display())]
    Read {
        /// The configuration path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// The configuration file could not be parsed or edited.
    #[error("config {}", path.display())]
    Edit {
        /// The configuration path.
        path: PathBuf,
        /// The parsing or validation failure.
        #[source]
        source: EditError,
    },
    /// Random bytes for the password could not be read.
    #[error("generate password")]
    Random(#[source] io::Error),
    /// The updated configuration file could not be written.
    #[error("write config {}", path.display())]
    Write {
        /// The configuration path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: io::Error,
    },
}

/// Generate a uniformly distributed alphanumeric password from `random` bytes.
pub fn generate_password(random: &mut impl Read) -> io::Result<String> {
    // Rejecting bytes at or above the largest multiple of the alphabet size
    // keeps every character equally likely.
    let limit = 256 - 256 % PASSWORD_ALPHABET.len();
    let mut password = String::with_capacity(PASSWORD_LENGTH);
    let mut byte = [0u8; 1];
    while password.len() < PASSWORD_LENGTH {
        random.read_exact(&mut byte)?;
        let index = usize::from(byte[0]);
        if index < limit {
            password.push(char::from(PASSWORD_ALPHABET[index % PASSWORD_ALPHABET.len()]));
        }
    }
    Ok(password)
}

/// Return `text` with the `[ui]` username and password replaced, keeping all other content.
///
/// The `[ui]` table is appended when absent, and the result is validated as a
/// complete configuration before it is returned.
pub fn set_credentials(text: &str, credentials: &UiCredentials) -> Result<String, EditError> {
    let mut document = text.parse::<DocumentMut>()?;
    let ui = document
        .entry("ui")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or(EditError::UiNotTable)?;
    set_string(ui, "username", &credentials.username);
    set_string(ui, "password", &credentials.password);
    let rendered = document.to_string();
    Config::parse(&rendered)?;
    Ok(rendered)
}

/// Set a string value, keeping the key's comments and the old value's surrounding whitespace.
fn set_string(table: &mut dyn TableLike, key: &str, text: &str) {
    let mut value = Value::from(text);
    // Replacing the item in place, rather than inserting, keeps the key and
    // the comments attached to it.
    match table.get_mut(key) {
        Some(item) => {
            if let Some(old) = item.as_value() {
                *value.decor_mut() = old.decor().clone();
            }
            *item = Item::Value(value);
        }
        None => {
            table.insert(key, Item::Value(value));
        }
    }
}

/// Ensure the configuration at `path` holds UI credentials and return them.
///
/// The username comes from `username`, then the existing configuration, then
/// [`DEFAULT_USERNAME`]. A missing file is created, readable by the group of
/// its directory.
pub fn update(
    path: &Path,
    username: Option<&str>,
    rotation: Rotation,
    random: &mut impl Read,
) -> Result<Outcome, CredentialsError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(CredentialsError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    let edit_error = |source: EditError| CredentialsError::Edit {
        path: path.to_owned(),
        source,
    };
    let ui = Config::parse(&text).map_err(|source| edit_error(source.into()))?.startup.ui;
    if rotation == Rotation::IfMissing
        && let Some(credentials) = UiCredentials::configured(&ui)
    {
        return Ok(Outcome {
            credentials,
            changed: false,
            ui,
        });
    }
    let username = match username {
        Some(username) => username.to_owned(),
        None if !ui.username.is_empty() => ui.username.clone(),
        None => DEFAULT_USERNAME.to_owned(),
    };
    let credentials = UiCredentials {
        username,
        password: generate_password(random).map_err(CredentialsError::Random)?,
    };
    let updated = set_credentials(&text, &credentials).map_err(edit_error)?;
    replace_file(path, &updated).map_err(|source| CredentialsError::Write {
        path: path.to_owned(),
        source,
    })?;
    Ok(Outcome {
        credentials,
        changed: true,
        ui,
    })
}

/// Atomically replace `path` with `text`, keeping the mode and ownership of an existing file.
fn replace_file(path: &Path, text: &str) -> io::Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let (mode, owner, group) = match fs::metadata(path) {
        Ok(metadata) => (metadata.mode() & 0o7777, Some(metadata.uid()), metadata.gid()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            (NEW_FILE_MODE, None, fs::metadata(directory)?.gid())
        }
        Err(error) => return Err(error),
    };
    let mut file = tempfile::NamedTempFile::new_in(directory)?;
    // Restrict ownership before widening the mode so the password is never exposed.
    fchown(file.as_file(), owner, Some(group))?;
    file.as_file().set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(text.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// A browser URL for the web UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UiUrl {
    /// The URL to open.
    pub url: String,
    /// The IPv4 address the URL connects to.
    pub address: Ipv4Addr,
    /// Whether a configured listener accepts connections to the address.
    pub listening: bool,
}

/// Return the localhost URL and, when known, the URL for this machine's IPv4 address.
///
/// Only IPv4 URLs are listed; IPv6 listeners are not reported.
pub fn ui_urls(ui: &UiConfig, machine: Option<Ipv4Addr>) -> Vec<UiUrl> {
    let accepts = |address: Ipv4Addr| {
        ui.hosts.contains(&IpAddr::V4(address))
            || ui.hosts.contains(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    };
    let mut urls = vec![UiUrl {
        url: format!("http://localhost:{}", ui.port),
        address: Ipv4Addr::LOCALHOST,
        listening: accepts(Ipv4Addr::LOCALHOST),
    }];
    if let Some(address) = machine {
        urls.push(UiUrl {
            url: format!("http://{address}:{}", ui.port),
            address,
            listening: accepts(address),
        });
    }
    urls
}

/// Return the IPv4 source address of this machine's default route, if it has one.
///
/// Connecting a UDP socket only selects a route; no packet is sent.
pub fn machine_address() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(ROUTE_PROBE).ok()?;
    let IpAddr::V4(address) = socket.local_addr().ok()?.ip() else {
        return None;
    };
    (!address.is_unspecified() && !address.is_loopback()).then_some(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Endless pseudo-random bytes for deterministic password generation.
    struct Counter(u8);

    impl Read for Counter {
        /// Fill the buffer with consecutive byte values.
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            for byte in buffer.iter_mut() {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(buffer.len())
        }
    }

    /// Build credentials from string literals.
    fn credentials(username: &str, password: &str) -> UiCredentials {
        UiCredentials {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    /// Passwords use the full length and alphabet, and biased bytes are rejected.
    #[test]
    fn generates_alphanumeric_passwords() {
        let password = generate_password(&mut Counter(0)).unwrap();
        assert_eq!(password, "ABCDEFGHIJKLMNOPQRSTUVWX");
        let mut biased = io::Cursor::new([255u8, 254, 248, 0].repeat(PASSWORD_LENGTH));
        assert_eq!(generate_password(&mut biased).unwrap(), "A".repeat(PASSWORD_LENGTH));
        assert!(generate_password(&mut io::Cursor::new([0u8; 3])).is_err());
    }

    /// Replacing credentials keeps comments, other keys, and value whitespace.
    #[test]
    fn replaces_credentials_preserving_document() {
        let text = include_str!("../config-default.toml");
        let updated = set_credentials(text, &credentials("admin", "secret")).unwrap();
        let ui = Config::parse(&updated).unwrap().startup.ui;
        assert_eq!(UiCredentials::configured(&ui), Some(credentials("admin", "secret")));
        assert!(updated.contains("username = \"admin\"\npassword = \"secret\"\n"));
        let removed: Vec<&str> = text.lines().filter(|line| !updated.contains(line)).collect();
        assert_eq!(removed, ["username = \"\"", "password = \"\""]);
    }

    /// A missing `[ui]` table is appended; inline tables and dotted keys are edited in place.
    #[test]
    fn edits_any_ui_table_form() {
        let expected = Some(credentials("a", "b"));
        for text in ["", "log_level = 'info'\n", "ui = { port = 8080 }\n", "ui.port = 8080\n"] {
            let updated = set_credentials(text, &credentials("a", "b")).unwrap();
            let ui = Config::parse(&updated).unwrap().startup.ui;
            assert_eq!(UiCredentials::configured(&ui), expected, "{text}");
        }
        assert!(matches!(
            set_credentials("ui = 1", &credentials("a", "b")),
            Err(EditError::UiNotTable)
        ));
        assert!(matches!(
            set_credentials("typo = 1", &credentials("a", "b")),
            Err(EditError::Invalid(_))
        ));
        assert!(matches!(
            set_credentials("[ui", &credentials("a", "b")),
            Err(EditError::Syntax(_))
        ));
    }

    /// The file keeps its mode, is only rewritten when needed, and keeps the configured name.
    #[test]
    fn updates_configuration_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(&path, "# keep me\n[ui]\nport = 8080\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let first = update(&path, None, Rotation::IfMissing, &mut Counter(0)).unwrap();
        assert!(first.changed);
        assert_eq!(first.credentials.username, DEFAULT_USERNAME);
        assert_eq!(first.ui.port, 8080);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# keep me\n"));
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);

        let kept = update(&path, Some("other"), Rotation::IfMissing, &mut Counter(0)).unwrap();
        assert!(!kept.changed);
        assert_eq!(kept.credentials, first.credentials);
        assert_eq!(fs::read_to_string(&path).unwrap(), text);

        let rotated = update(&path, None, Rotation::Replace, &mut Counter(100)).unwrap();
        assert!(rotated.changed);
        assert_eq!(rotated.credentials.username, DEFAULT_USERNAME);
        assert_ne!(rotated.credentials.password, first.credentials.password);

        let renamed = update(&path, Some("root"), Rotation::Replace, &mut Counter(0)).unwrap();
        let ui = Config::load(&path).unwrap().startup.ui;
        assert_eq!(UiCredentials::configured(&ui), Some(renamed.credentials));
    }

    /// A missing file is created group-readable, and invalid files are left untouched.
    #[test]
    fn creates_missing_and_rejects_invalid_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let created = update(&path, Some("ops"), Rotation::IfMissing, &mut Counter(0)).unwrap();
        assert!(created.changed);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, NEW_FILE_MODE);
        assert_eq!(created.credentials.username, "ops");

        fs::write(&path, "typo = 1\n").unwrap();
        let error = update(&path, None, Rotation::Replace, &mut Counter(0)).unwrap_err();
        assert!(matches!(error, CredentialsError::Edit { .. }));
        assert_eq!(fs::read_to_string(&path).unwrap(), "typo = 1\n");
    }

    /// URLs report whether a listener, including a family wildcard, accepts the address.
    #[test]
    fn reports_reachable_urls() {
        let machine = Ipv4Addr::new(192, 168, 1, 5);
        let mut ui = UiConfig::default();
        let urls = ui_urls(&ui, Some(machine));
        assert_eq!(urls[0].url, "http://localhost:58000");
        assert_eq!(urls[1].url, "http://192.168.1.5:58000");
        assert!(urls.iter().all(|url| url.listening));

        ui.hosts = vec!["127.0.0.1".parse().unwrap()];
        let urls = ui_urls(&ui, Some(machine));
        assert!(urls[0].listening);
        assert!(!urls[1].listening);

        ui.hosts = vec!["::1".parse().unwrap(), "0.0.0.0".parse().unwrap()];
        let urls = ui_urls(&ui, Some(machine));
        assert!(urls.iter().all(|url| url.listening));

        ui.hosts = vec!["::".parse().unwrap(), "192.168.1.5".parse().unwrap()];
        let urls = ui_urls(&ui, Some(machine));
        assert!(!urls[0].listening);
        assert!(urls[1].listening);

        ui.hosts.clear();
        assert!(ui_urls(&ui, None).iter().all(|url| !url.listening));
    }
}
