//! Persistent private CA and bounded, on-demand leaf certificate generation.
use crate::error::{Context, Result, ensure};
use rama::{
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    tls::rustls::dep::rustls::{self, server::ResolvesServerCert, sign::CertifiedKey},
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Arc, Mutex},
};

pub const CERT_FILE: &str = "ramawall-ca-cert.pem";
pub const KEY_FILE: &str = "ramawall-ca-key.pem";

/// Create CA material once and validate existing material without rotating it.
pub fn init(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    let cert_path = directory.join(CERT_FILE);
    let key_path = directory.join(KEY_FILE);
    if cert_path.exists() || key_path.exists() {
        ensure!(
            cert_path.exists() && key_path.exists(),
            "incomplete CA; restore the missing file instead of rotating the CA"
        );
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
    params.distinguished_name.push(DnType::CommonName, "ramawall local CA");
    params.distinguished_name.push(DnType::OrganizationName, "ramawall");
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    for (path, contents) in [(key_path, key.serialize_pem()), (cert_path, cert.pem())] {
        let mut file =
            fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
    }
    Ok(())
}

/// A private persistent issuer with a bounded leaf-certificate cache.
pub struct Authority {
    issuer: Issuer<'static, KeyPair>,
    cert: CertificateDer<'static>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}
impl std::fmt::Debug for Authority {
    /// Describe the authority without exposing its private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Authority { private_material: <redacted> }")
    }
}
impl Authority {
    /// Read private CA material and verify certificate/key consistency.
    pub fn load(directory: &Path) -> Result<Self> {
        let key_path = directory.join(KEY_FILE);
        let metadata = fs::symlink_metadata(&key_path)?;
        ensure!(
            metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
            "CA key must be a private regular file (0600)"
        );
        let key = KeyPair::from_pem(&fs::read_to_string(&key_path)?)?;
        let pem = fs::read_to_string(directory.join(CERT_FILE))?;
        let cert = CertificateDer::from_pem_slice(pem.as_bytes())?;
        let issuer = Issuer::from_ca_cert_pem(&pem, key)?;
        // Detect a mismatched certificate/key pair before accepting any clients.
        let provider = rustls::crypto::ring::default_provider();
        let key = PrivateKeyDer::from_pem_slice(fs::read_to_string(key_path)?.as_bytes())?;
        CertifiedKey::from_der(vec![cert.clone()], key, &provider)
            .context("CA certificate/key mismatch")?;
        Ok(Self {
            issuer,
            cert,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Generate or reuse a CA-signed certificate for one hostname or IP.
    fn issue(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| crate::error::Error::message("certificate cache poisoned".to_string()))?;
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
        let private_key =
            PrivateKeyDer::try_from(key.serialize_der()).map_err(crate::error::Error::msg)?;
        let certified = Arc::new(CertifiedKey::from_der(
            vec![cert.der().clone(), self.cert.clone()],
            private_key,
            &rustls::crypto::ring::default_provider(),
        )?);
        if cache.len() >= 1024 {
            cache.clear();
        }
        cache.insert(host.into(), certified.clone());
        Ok(certified)
    }
}

/// Select a certificate for TLS SNI or the connection fallback hostname.
#[derive(Debug)]
pub struct Resolver {
    pub authority: Arc<Authority>,
    pub fallback: String,
}
impl ResolvesServerCert for Resolver {
    /// Resolve the TLS certificate without leaking generation errors to clients.
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name().unwrap_or(&self.fallback);
        match self.authority.issue(host) {
            Ok(cert) => Some(cert),
            Err(error) => {
                tracing::warn!(%error, %host, "cannot issue interception certificate");
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
        fs::set_permissions(dir.path().join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Authority::load(dir.path()).is_err());
    }
}
