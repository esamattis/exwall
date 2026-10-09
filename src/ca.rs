//! Persistent private CA and bounded, on-demand leaf certificate generation.

use rama::{
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    tls::rustls::dep::rustls::{self, server::ResolvesServerCert, sign::CertifiedKey},
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::{
    collections::HashMap,
    fs, io,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use thiserror::Error;

/// CA certificate filename inside the CA directory.
pub const CERT_FILE: &str = "exwall-ca-cert.pem";
/// CA private key filename inside the CA directory.
pub const KEY_FILE: &str = "exwall-ca-key.pem";
/// Leaf certificates cached before the cache is cleared.
const CACHE_LIMIT: usize = 1024;

/// CA creation, loading, or leaf issuance failures.
#[derive(Debug, Error)]
pub enum CaError {
    /// A CA file or directory operation failed.
    #[error("{operation} {}", path.display())]
    Io {
        /// What was being done.
        operation: &'static str,
        /// The affected path.
        path: PathBuf,
        /// The filesystem error.
        #[source]
        source: io::Error,
    },
    /// Only one of the certificate and key exists.
    #[error("incomplete CA; restore the missing file instead of rotating the CA")]
    Incomplete,
    /// The key file is not a private regular file.
    #[error("CA key must be a private regular file (0600)")]
    ExposedKey,
    /// Certificate generation or parsing failed.
    #[error("certificate generation failed")]
    Certificate(#[from] rcgen::Error),
    /// PEM material could not be decoded.
    #[error("decode PEM")]
    Pem(#[from] rama::crypto::pki_types::pem::Error),
    /// The certificate and key do not belong together, or a leaf is invalid.
    #[error("CA certificate/key mismatch")]
    Mismatch(#[source] rustls::Error),
    /// A generated leaf key could not be encoded.
    #[error("encode leaf key: {0}")]
    LeafKey(&'static str),
}

/// Build a filesystem error for `path`.
fn io_error(operation: &'static str, path: &Path) -> impl FnOnce(io::Error) -> CaError {
    let path = path.to_owned();
    move |source| CaError::Io {
        operation,
        path,
        source,
    }
}

/// Create CA material once and validate existing material without rotating it.
pub fn init(directory: &Path) -> Result<(), CaError> {
    fs::create_dir_all(directory).map_err(io_error("create CA directory", directory))?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .map_err(io_error("restrict CA directory", directory))?;
    let cert_path = directory.join(CERT_FILE);
    let key_path = directory.join(KEY_FILE);
    if cert_path.exists() || key_path.exists() {
        if !(cert_path.exists() && key_path.exists()) {
            return Err(CaError::Incomplete);
        }
        Authority::load(directory)?;
        return Ok(());
    }
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, "exwall local CA");
    params.distinguished_name.push(DnType::OrganizationName, "exwall");
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    for (path, contents) in [(key_path, key.serialize_pem()), (cert_path, cert.pem())] {
        write_new_private(&path, contents.as_bytes()).map_err(io_error("write CA file", &path))?;
    }
    Ok(())
}

/// Create a new 0600 file and durably write its contents.
fn write_new_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// A private persistent issuer with a bounded leaf-certificate cache.
pub struct Authority {
    /// The CA used to sign leaves.
    issuer: Issuer<'static, KeyPair>,
    /// The CA certificate appended to every leaf chain.
    cert: CertificateDer<'static>,
    /// Leaf certificates by hostname.
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for Authority {
    /// Describe the authority without exposing its private key.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Authority { private_material: <redacted> }")
    }
}

impl Authority {
    /// Read private CA material and verify certificate/key consistency.
    pub fn load(directory: &Path) -> Result<Self, CaError> {
        let key_path = directory.join(KEY_FILE);
        let cert_path = directory.join(CERT_FILE);
        let metadata =
            fs::symlink_metadata(&key_path).map_err(io_error("inspect CA key", &key_path))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(CaError::ExposedKey);
        }
        let key_pem = fs::read_to_string(&key_path).map_err(io_error("read CA key", &key_path))?;
        let pem =
            fs::read_to_string(&cert_path).map_err(io_error("read CA certificate", &cert_path))?;
        let key = KeyPair::from_pem(&key_pem)?;
        let cert = CertificateDer::from_pem_slice(pem.as_bytes())?;
        let issuer = Issuer::from_ca_cert_pem(&pem, key)?;
        // Detect a mismatched certificate/key pair before accepting any clients.
        let provider = rustls::crypto::ring::default_provider();
        let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;
        CertifiedKey::from_der(vec![cert.clone()], private_key, &provider)
            .map_err(CaError::Mismatch)?;
        Ok(Self {
            issuer,
            cert,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Generate or reuse a CA-signed certificate for one hostname or IP.
    pub fn issue(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let mut cache = self.cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cert) = cache.get(host) {
            return Ok(cert.clone());
        }
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![host.into()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        // Strict TLS clients require a leaf to identify the CA that signed it.
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer)?;
        let private_key = PrivateKeyDer::try_from(key.serialize_der()).map_err(CaError::LeafKey)?;
        let certified = Arc::new(
            CertifiedKey::from_der(
                vec![cert.der().clone(), self.cert.clone()],
                private_key,
                &rustls::crypto::ring::default_provider(),
            )
            .map_err(CaError::Mismatch)?,
        );
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        cache.insert(host.into(), certified.clone());
        Ok(certified)
    }
}

/// Select a certificate for TLS SNI or the connection fallback hostname.
#[derive(Debug)]
pub struct Resolver {
    /// The issuing authority.
    pub authority: Arc<Authority>,
    /// The name used when the client sends no SNI.
    pub fallback: String,
}

impl ResolvesServerCert for Resolver {
    /// Resolve the TLS certificate without leaking generation errors to clients.
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name().unwrap_or(&self.fallback);
        match self.authority.issue(host) {
            Ok(cert) => Some(cert),
            Err(error) => {
                tracing::warn!(
                    error = %crate::error::ErrorChain(&error),
                    %host,
                    "cannot issue interception certificate"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify CA reuse, leaf generation, and private-key permission checks.
    #[test]
    fn persists_ca_and_rejects_exposed_key() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path()).unwrap();
        let before = fs::read(dir.path().join(CERT_FILE)).unwrap();
        init(dir.path()).unwrap();
        assert_eq!(before, fs::read(dir.path().join(CERT_FILE)).unwrap());
        let authority = Authority::load(dir.path()).unwrap();
        assert!(authority.issue("example.com").is_ok());
        assert!(authority.issue("127.0.0.1").is_ok());
        let cached = authority.issue("example.com").unwrap();
        assert!(Arc::ptr_eq(&cached, &authority.issue("example.com").unwrap()));
        fs::set_permissions(dir.path().join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Authority::load(dir.path()), Err(CaError::ExposedKey)));
    }

    /// A lone certificate or key is never silently replaced.
    #[test]
    fn refuses_to_rotate_an_incomplete_ca() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(CERT_FILE), "certificate").unwrap();
        assert!(matches!(init(dir.path()), Err(CaError::Incomplete)));
        assert_eq!(fs::read_to_string(dir.path().join(CERT_FILE)).unwrap(), "certificate");
    }
}
