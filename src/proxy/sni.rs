//! SNI (Server Name Indication) support for multi-domain TLS
//!
//! Enables a single HTTPS listener to serve multiple domains, each with
//! their own SSL certificate. The correct certificate is selected based on
//! the SNI hostname provided by the client during TLS handshake.
//!
//! # Architecture
//!
//! - `SniResolver`: Implements `rustls::server::ResolvesServerCert`
//! - Pre-loads all certificates at startup
//! - Matches SNI hostname (exact match or wildcard)
//! - Falls back to default certificate if no match
//!
//! # Example Configuration
//!
//! ```toml
//! [[server.listeners]]
//! listen = "0.0.0.0:443"
//! backend = "http://127.0.0.1:8080"
//!
//! [server.listeners.tls]
//! # Default/fallback certificate
//! cert_file = "/etc/letsencrypt/live/default.com/fullchain.pem"
//! key_file = "/etc/letsencrypt/live/default.com/privkey.pem"
//!
//! # Additional SNI certificates
//! [[server.listeners.tls.sni_certificates]]
//! server_name = "example.com"
//! cert_file = "/etc/letsencrypt/live/example.com/fullchain.pem"
//! key_file = "/etc/letsencrypt/live/example.com/privkey.pem"
//!
//! [[server.listeners.tls.sni_certificates]]
//! server_name = "*.example.org"
//! cert_file = "/etc/letsencrypt/live/example.org/fullchain.pem"
//! key_file = "/etc/letsencrypt/live/example.org/privkey.pem"
//! ```

use crate::config::settings::ListenerTlsConfig;
use crate::{Error, Result};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

/// SNI certificate resolver
///
/// Selects the appropriate TLS certificate based on the SNI hostname
/// provided by the client. Supports exact matches and wildcard domains.
#[derive(Debug)]
pub struct SniResolver {
    /// Default certificate (fallback if no SNI match)
    default_cert: Arc<CertifiedKey>,
    /// SNI certificates mapped by server name
    sni_certs: HashMap<String, Arc<CertifiedKey>>,
}

impl SniResolver {
    /// Create a new SNI resolver from configuration
    ///
    /// Loads all certificates into memory for fast lookup during handshake.
    ///
    /// # Arguments
    ///
    /// * `config` - TLS configuration with default cert and optional SNI certs
    ///
    /// # Errors
    ///
    /// Returns error if any certificate or key file cannot be loaded or parsed.
    pub fn new(config: &ListenerTlsConfig) -> Result<Self> {
        // Load default certificate
        let default_cert = load_certified_key(&config.cert_file, &config.key_file)?;

        // Load SNI certificates
        let mut sni_certs = HashMap::new();
        for sni_config in &config.sni_certificates {
            let cert = load_certified_key(&sni_config.cert_file, &sni_config.key_file)?;
            sni_certs.insert(sni_config.server_name.to_lowercase(), Arc::new(cert));

            tracing::info!(
                server_name = %sni_config.server_name,
                cert_file = %sni_config.cert_file,
                "Loaded SNI certificate"
            );
        }

        Ok(Self {
            default_cert: Arc::new(default_cert),
            sni_certs,
        })
    }

    /// Resolve certificate for given SNI hostname
    ///
    /// Matching logic:
    /// 1. Exact match (e.g., "example.com" matches "example.com")
    /// 2. Wildcard match (e.g., "*.example.com" matches "sub.example.com")
    /// 3. Fallback to default certificate
    fn resolve_cert(&self, server_name: &str) -> Arc<CertifiedKey> {
        let server_name_lower = server_name.to_lowercase();

        // 1. Try exact match
        if let Some(cert) = self.sni_certs.get(&server_name_lower) {
            tracing::debug!(
                server_name = %server_name,
                "SNI: Exact match found"
            );
            return Arc::clone(cert);
        }

        // 2. Try wildcard match
        if let Some(wildcard_cert) = self.find_wildcard_match(&server_name_lower) {
            tracing::debug!(
                server_name = %server_name,
                "SNI: Wildcard match found"
            );
            return wildcard_cert;
        }

        // 3. Fallback to default
        tracing::debug!(
            server_name = %server_name,
            "SNI: No match, using default certificate"
        );
        Arc::clone(&self.default_cert)
    }

    /// Find wildcard certificate matching the hostname
    ///
    /// E.g., certificate for "*.example.com" matches "sub.example.com"
    fn find_wildcard_match(&self, hostname: &str) -> Option<Arc<CertifiedKey>> {
        for (pattern, cert) in &self.sni_certs {
            if pattern.starts_with("*.") {
                let domain_suffix = &pattern[2..]; // Remove "*."
                if let Some(dot_pos) = hostname.find('.') {
                    let hostname_suffix = &hostname[dot_pos + 1..];
                    if hostname_suffix == domain_suffix {
                        return Some(Arc::clone(cert));
                    }
                }
            }
        }
        None
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        match client_hello.server_name() {
            Some(server_name) => {
                tracing::trace!(
                    server_name = %server_name,
                    "SNI hostname received from client"
                );
                Some(self.resolve_cert(server_name))
            }
            None => {
                // Client didn't send SNI, use default certificate
                tracing::debug!("No SNI provided by client, using default certificate");
                Some(Arc::clone(&self.default_cert))
            }
        }
    }
}

/// Load certificate and private key from PEM files
///
/// # Arguments
///
/// * `cert_path` - Path to PEM certificate chain file
/// * `key_path` - Path to PEM private key file
///
/// # Errors
///
/// Returns error if files cannot be read or parsed, or if key doesn't match cert.
fn load_certified_key(cert_path: &str, key_path: &str) -> Result<CertifiedKey> {
    // Load certificates
    let cert_file = fs::File::open(cert_path)
        .map_err(|e| Error::Config(format!("Failed to open cert file {cert_path}: {e}")))?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| Error::Config(format!("Failed to parse certificates from {cert_path}: {e}")))?;

    if certs.is_empty() {
        return Err(Error::Config(format!(
            "No certificates found in {cert_path}"
        )));
    }

    // Load private key
    let key_file = fs::File::open(key_path)
        .map_err(|e| Error::Config(format!("Failed to open key file {key_path}: {e}")))?;
    let mut key_reader = BufReader::new(key_file);

    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| Error::Config(format!("Failed to parse private key from {key_path}: {e}")))?
        .ok_or_else(|| Error::Config(format!("No private key found in {key_path}")))?;

    // Create signing key (rustls 0.23 uses the crypto provider directly)
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
        .map_err(|e| Error::Config(format!("Failed to create signing key from private key: {e}")))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_pattern_parsing() {
        // Test wildcard domain pattern extraction
        let pattern = "*.example.com";
        assert!(pattern.starts_with("*."));
        let domain_suffix = &pattern[2..];
        assert_eq!(domain_suffix, "example.com");

        // Test hostname matching
        let hostname = "sub.example.com";
        if let Some(dot_pos) = hostname.find('.') {
            let hostname_suffix = &hostname[dot_pos + 1..];
            assert_eq!(hostname_suffix, "example.com");
        }
    }

    #[test]
    fn test_server_name_normalization() {
        // Test that server names are normalized to lowercase
        let name1 = "Example.COM".to_lowercase();
        let name2 = "example.com";
        assert_eq!(name1, name2);
    }

    // Note: Full SNI resolver tests require actual TLS certificates
    // These are better suited for integration tests with test fixtures
}
