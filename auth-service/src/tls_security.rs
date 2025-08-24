//! TLS and network security configuration
//! 
//! This module provides secure TLS configuration, certificate management,
//! and network security policies following industry best practices.

use rustls::{
    ClientConfig, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{
    fs::File,
    io::BufReader,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{error, info, warn};
use crate::error_handling::{SecurityError, SecurityResult};

/// TLS security configuration
#[derive(Debug, Clone)]
pub struct TlsSecurityConfig {
    /// Minimum TLS version
    pub min_tls_version: TlsVersion,
    /// Preferred TLS version
    pub preferred_tls_version: TlsVersion,
    /// Allowed cipher suites
    pub cipher_suites: Vec<TlsCipherSuite>,
    /// Certificate validation mode
    pub cert_validation: CertValidationMode,
    /// OCSP stapling enabled
    pub ocsp_stapling: bool,
    /// SNI enabled
    pub sni_enabled: bool,
    /// Session resumption enabled
    pub session_resumption: bool,
    /// Client certificate required
    pub require_client_cert: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy)]
pub enum TlsCipherSuite {
    // TLS 1.3
    Tls13Aes256GcmSha384,
    Tls13Chacha20Poly1305Sha256,
    Tls13Aes128GcmSha256,
    
    // TLS 1.2 (for compatibility)
    Tls12EcdheEcdsaWithAes256GcmSha384,
    Tls12EcdheRsaWithAes256GcmSha384,
}

#[derive(Debug, Clone, Copy)]
pub enum CertValidationMode {
    /// Full certificate validation including hostname
    Full,
    /// Skip hostname verification (for internal services)
    SkipHostname,
    /// Custom validation
    Custom,
}

impl Default for TlsSecurityConfig {
    fn default() -> Self {
        Self {
            min_tls_version: TlsVersion::Tls12,
            preferred_tls_version: TlsVersion::Tls13,
            cipher_suites: vec![
                TlsCipherSuite::Tls13Aes256GcmSha384,
                TlsCipherSuite::Tls13Chacha20Poly1305Sha256,
                TlsCipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384,
                TlsCipherSuite::Tls12EcdheRsaWithAes256GcmSha384,
            ],
            cert_validation: CertValidationMode::Full,
            ocsp_stapling: true,
            sni_enabled: true,
            session_resumption: true,
            require_client_cert: false,
        }
    }
}

/// TLS configuration builder
pub struct TlsConfigBuilder {
    config: TlsSecurityConfig,
}

impl TlsConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: TlsSecurityConfig::default(),
        }
    }
    
    pub fn min_tls_version(mut self, version: TlsVersion) -> Self {
        self.config.min_tls_version = version;
        self
    }
    
    pub fn preferred_tls_version(mut self, version: TlsVersion) -> Self {
        self.config.preferred_tls_version = version;
        self
    }
    
    pub fn cipher_suites(mut self, suites: Vec<TlsCipherSuite>) -> Self {
        self.config.cipher_suites = suites;
        self
    }
    
    pub fn cert_validation(mut self, mode: CertValidationMode) -> Self {
        self.config.cert_validation = mode;
        self
    }
    
    pub fn require_client_cert(mut self, required: bool) -> Self {
        self.config.require_client_cert = required;
        self
    }
    
    pub fn build(self) -> TlsSecurityConfig {
        self.config
    }
}

/// Secure TLS client configuration
pub fn create_secure_client_config(
    config: &TlsSecurityConfig,
    ca_cert_path: Option<&str>,
) -> SecurityResult<Arc<ClientConfig>> {
    info!("Creating secure TLS client configuration");
    
    let mut client_config = ClientConfig::builder()
        .with_cipher_suites(&convert_cipher_suites(&config.cipher_suites))
        .with_safe_default_kx_groups()
        .with_protocol_versions(&convert_protocol_versions(config))?
        .with_root_certificates(load_ca_certificates(ca_cert_path)?)
        .with_no_client_auth();
    
    // Configure SNI
    if config.sni_enabled {
        client_config.enable_sni = true;
    }
    
    // Configure session resumption
    if !config.session_resumption {
        client_config.resumption = rustls::client::Resumption::disabled();
    }
    
    info!("TLS client configuration created successfully");
    Ok(Arc::new(client_config))
}

/// Secure TLS server configuration
pub fn create_secure_server_config(
    config: &TlsSecurityConfig,
    cert_chain_path: &str,
    private_key_path: &str,
    ca_cert_path: Option<&str>,
) -> SecurityResult<Arc<ServerConfig>> {
    info!("Creating secure TLS server configuration");
    
    let cert_chain = load_certificate_chain(cert_chain_path)?;
    let private_key = load_private_key(private_key_path)?;
    
    let server_config = if config.require_client_cert {
        let client_cert_verifier = load_client_cert_verifier(ca_cert_path)?;
        ServerConfig::builder()
            .with_cipher_suites(&convert_cipher_suites(&config.cipher_suites))
            .with_safe_default_kx_groups()
            .with_protocol_versions(&convert_protocol_versions(config))?
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(cert_chain, private_key)?
    } else {
        ServerConfig::builder()
            .with_cipher_suites(&convert_cipher_suites(&config.cipher_suites))
            .with_safe_default_kx_groups()
            .with_protocol_versions(&convert_protocol_versions(config))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?
    };
    
    info!("TLS server configuration created successfully");
    Ok(Arc::new(server_config))
}

/// Certificate management and validation
pub struct CertificateManager {
    cert_path: String,
    key_path: String,
    ca_path: Option<String>,
    config: TlsSecurityConfig,
}

impl CertificateManager {
    pub fn new(
        cert_path: String,
        key_path: String,
        ca_path: Option<String>,
        config: TlsSecurityConfig,
    ) -> Self {
        Self {
            cert_path,
            key_path,
            ca_path,
            config,
        }
    }
    
    /// Validate certificate chain
    pub fn validate_certificate_chain(&self) -> SecurityResult<()> {
        info!("Validating certificate chain");
        
        let cert_chain = load_certificate_chain(&self.cert_path)?;
        
        // Check certificate expiration
        for (i, cert) in cert_chain.iter().enumerate() {
            self.validate_certificate_expiration(cert, i)?;
        }
        
        // Validate certificate chain integrity
        self.validate_chain_integrity(&cert_chain)?;
        
        info!("Certificate chain validation completed successfully");
        Ok(())
    }
    
    /// Check certificate expiration
    fn validate_certificate_expiration(&self, cert: &CertificateDer, index: usize) -> SecurityResult<()> {
        let parsed_cert = x509_parser::parse_x509_certificate(cert.as_ref())
            .map_err(|_| SecurityError::CryptographicFailure)?
            .1;
        
        let not_after = parsed_cert.validity().not_after;
        let current_time = SystemTime::now();
        
        // Convert ASN.1 time to SystemTime
        let expiration_time = asn1_time_to_system_time(not_after)
            .ok_or(SecurityError::CryptographicFailure)?;
        
        if current_time > expiration_time {
            error!("Certificate {} has expired", index);
            return Err(SecurityError::CryptographicFailure);
        }
        
        // Warn if certificate expires within 30 days
        let thirty_days = Duration::from_secs(30 * 24 * 60 * 60);
        if current_time + thirty_days > expiration_time {
            warn!("Certificate {} expires within 30 days", index);
        }
        
        Ok(())
    }
    
    /// Validate certificate chain integrity
    fn validate_chain_integrity(&self, _cert_chain: &[CertificateDer]) -> SecurityResult<()> {
        // TODO: Implement full chain validation
        // This would include:
        // - Verifying signatures
        // - Checking certificate extensions
        // - Validating key usage
        // - Checking revocation status
        Ok(())
    }
    
    /// Reload certificates when they change
    pub async fn watch_for_certificate_changes(&self) -> SecurityResult<()> {
        info!("Starting certificate monitoring");
        
        // In a real implementation, you would use a file watcher
        // to detect changes to certificate files and reload them
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await; // Check hourly
            
            if let Err(e) = self.validate_certificate_chain() {
                error!("Certificate validation failed: {}", e);
                // Trigger alert or certificate renewal
            }
        }
    }
}

/// Network security policies
#[derive(Debug, Clone)]
pub struct NetworkSecurityPolicy {
    /// Allowed IP ranges for client connections
    pub allowed_ip_ranges: Vec<ipnetwork::IpNetwork>,
    /// Blocked IP addresses
    pub blocked_ips: Vec<std::net::IpAddr>,
    /// Rate limiting per IP
    pub rate_limit_per_ip: u32,
    /// Maximum concurrent connections per IP
    pub max_connections_per_ip: u32,
    /// DDoS protection enabled
    pub ddos_protection: bool,
    /// Geo-blocking enabled
    pub geo_blocking: bool,
    /// Allowed countries (ISO 3166-1 alpha-2)
    pub allowed_countries: Vec<String>,
}

impl Default for NetworkSecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_ip_ranges: vec![
                // Allow all private networks by default
                "10.0.0.0/8".parse().unwrap(),
                "172.16.0.0/12".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                // Allow localhost
                "127.0.0.0/8".parse().unwrap(),
                "::1/128".parse().unwrap(),
            ],
            blocked_ips: Vec::new(),
            rate_limit_per_ip: 100, // requests per minute
            max_connections_per_ip: 10,
            ddos_protection: true,
            geo_blocking: false,
            allowed_countries: Vec::new(),
        }
    }
}

impl NetworkSecurityPolicy {
    /// Check if an IP address is allowed
    pub fn is_ip_allowed(&self, ip: &std::net::IpAddr) -> bool {
        // Check if IP is explicitly blocked
        if self.blocked_ips.contains(ip) {
            return false;
        }
        
        // Check if IP is in allowed ranges
        for range in &self.allowed_ip_ranges {
            if range.contains(*ip) {
                return true;
            }
        }
        
        false
    }
    
    /// Add IP to block list
    pub fn block_ip(&mut self, ip: std::net::IpAddr) {
        if !self.blocked_ips.contains(&ip) {
            self.blocked_ips.push(ip);
            warn!("IP address {} added to block list", ip);
        }
    }
    
    /// Remove IP from block list
    pub fn unblock_ip(&mut self, ip: &std::net::IpAddr) {
        self.blocked_ips.retain(|blocked_ip| blocked_ip != ip);
        info!("IP address {} removed from block list", ip);
    }
}

/// HTTP security headers
pub fn security_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        // Prevent MIME type sniffing
        ("X-Content-Type-Options", "nosniff"),
        
        // XSS protection
        ("X-XSS-Protection", "1; mode=block"),
        
        // Frame options to prevent clickjacking
        ("X-Frame-Options", "DENY"),
        
        // Content Security Policy
        ("Content-Security-Policy", 
         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'"),
        
        // HSTS for HTTPS enforcement
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
        
        // Referrer policy
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        
        // Permissions policy
        ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        
        // Remove server identification
        ("Server", ""),
    ]
}

// Helper functions

fn convert_cipher_suites(suites: &[TlsCipherSuite]) -> Vec<SupportedCipherSuite> {
    suites.iter().map(|suite| match suite {
        TlsCipherSuite::Tls13Aes256GcmSha384 => rustls::TLS13_AES_256_GCM_SHA384,
        TlsCipherSuite::Tls13Chacha20Poly1305Sha256 => rustls::TLS13_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite::Tls13Aes128GcmSha256 => rustls::TLS13_AES_128_GCM_SHA256,
        TlsCipherSuite::Tls12EcdheEcdsaWithAes256GcmSha384 => rustls::TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite::Tls12EcdheRsaWithAes256GcmSha384 => rustls::TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    }).collect()
}

fn convert_protocol_versions(config: &TlsSecurityConfig) -> SecurityResult<&'static [&'static SupportedProtocolVersion]> {
    match (config.min_tls_version, config.preferred_tls_version) {
        (TlsVersion::Tls13, TlsVersion::Tls13) => Ok(&[&TLS13]),
        (TlsVersion::Tls12, TlsVersion::Tls13) => Ok(&[&TLS13, &TLS12]),
        (TlsVersion::Tls12, TlsVersion::Tls12) => Ok(&[&TLS12]),
        _ => Err(SecurityError::Configuration),
    }
}

fn load_ca_certificates(ca_cert_path: Option<&str>) -> SecurityResult<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    
    if let Some(path) = ca_cert_path {
        let ca_file = File::open(path)
            .map_err(|_| SecurityError::Configuration)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs = certs(&mut ca_reader)
            .map_err(|_| SecurityError::CryptographicFailure)?;
        
        for cert in ca_certs {
            root_store.add(cert)
                .map_err(|_| SecurityError::CryptographicFailure)?;
        }
    } else {
        // Use system root certificates
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    
    Ok(root_store)
}

fn load_certificate_chain(cert_path: &str) -> SecurityResult<Vec<CertificateDer>> {
    let cert_file = File::open(cert_path)
        .map_err(|_| SecurityError::Configuration)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain = certs(&mut cert_reader)
        .map_err(|_| SecurityError::CryptographicFailure)?
        .into_iter()
        .collect();
    
    Ok(cert_chain)
}

fn load_private_key(key_path: &str) -> SecurityResult<PrivateKeyDer> {
    let key_file = File::open(key_path)
        .map_err(|_| SecurityError::Configuration)?;
    let mut key_reader = BufReader::new(key_file);
    let keys = pkcs8_private_keys(&mut key_reader)
        .map_err(|_| SecurityError::CryptographicFailure)?;
    
    keys.into_iter()
        .next()
        .map(PrivateKeyDer::from)
        .ok_or(SecurityError::CryptographicFailure)
}

fn load_client_cert_verifier(ca_cert_path: Option<&str>) -> SecurityResult<Arc<dyn rustls::server::ClientCertVerifier>> {
    let root_store = load_ca_certificates(ca_cert_path)?;
    Ok(rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build().map_err(|_| SecurityError::CryptographicFailure)?)
}

fn asn1_time_to_system_time(asn1_time: x509_parser::time::ASN1Time) -> Option<SystemTime> {
    match asn1_time {
        x509_parser::time::ASN1Time::UTCTime(utc) => {
            let timestamp = utc.timestamp();
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        }
        x509_parser::time::ASN1Time::GeneralizedTime(gt) => {
            let timestamp = gt.timestamp();
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp as u64))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_network_policy_ip_allowed() {
        let policy = NetworkSecurityPolicy::default();
        
        // Test localhost
        assert!(policy.is_ip_allowed(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        
        // Test private network
        assert!(policy.is_ip_allowed(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        
        // Test public IP (should be blocked by default with restrictive config)
        // This depends on your default policy configuration
    }
    
    #[test]
    fn test_network_policy_block_ip() {
        let mut policy = NetworkSecurityPolicy::default();
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        // Initially should be allowed (private network)
        assert!(policy.is_ip_allowed(&test_ip));
        
        // Block the IP
        policy.block_ip(test_ip);
        assert!(!policy.is_ip_allowed(&test_ip));
        
        // Unblock the IP
        policy.unblock_ip(&test_ip);
        assert!(policy.is_ip_allowed(&test_ip));
    }
    
    #[test]
    fn test_tls_config_builder() {
        let config = TlsConfigBuilder::new()
            .min_tls_version(TlsVersion::Tls13)
            .require_client_cert(true)
            .build();
        
        assert!(matches!(config.min_tls_version, TlsVersion::Tls13));
        assert!(config.require_client_cert);
    }
    
    #[test]
    fn test_security_headers() {
        let headers = security_headers();
        
        // Check that essential security headers are present
        assert!(headers.iter().any(|(name, _)| *name == "X-Content-Type-Options"));
        assert!(headers.iter().any(|(name, _)| *name == "Strict-Transport-Security"));
        assert!(headers.iter().any(|(name, _)| *name == "Content-Security-Policy"));
    }
}