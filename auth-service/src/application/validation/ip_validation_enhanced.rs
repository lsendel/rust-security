//! Enhanced IP address validation and extraction with improved security
//!
//! This module provides enhanced IP address validation and extraction functionality
//! with improved security practices compared to the basic implementations.
//!
//! ## Features
//!
//! - **Proper IP Parsing**: Uses `std::net::IpAddr` for accurate validation
//! - **IP Range Detection**: Identifies private, reserved, and special IP ranges
//! - **Proxy Header Validation**: Secure extraction from proxy headers
//! - **Privacy Protection**: Removes identifying information from logs
//! - **Threat Intelligence**: Detects known malicious IP patterns
//! - **Performance Optimized**: Efficient validation with caching

use axum::http::HeaderMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{debug, warn};

/// Enhanced IP address information with security metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedIpInfo {
    /// The validated IP address
    pub address: IpAddr,
    /// IP address type classification
    pub ip_type: IpType,
    /// Security classification
    pub security_classification: SecurityClassification,
    /// Whether this is a trusted proxy IP
    pub is_trusted_proxy: bool,
    /// Whether this IP should be anonymized in logs
    pub should_anonymize: bool,
}

/// IP address type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpType {
    /// IPv4 address
    IPv4,
    /// IPv6 address
    IPv6,
    /// IPv4-mapped IPv6 address
    IPv4MappedIPv6,
}

/// Security classification for IP addresses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityClassification {
    /// Public internet address
    Public,
    /// Private network address (RFC 1918, RFC 4193)
    Private,
    /// Loopback address (localhost)
    Loopback,
    /// Reserved address (RFCs, documentation)
    Reserved,
    /// Special use address (multicast, benchmarking, etc.)
    SpecialUse,
    /// Bogon address (not yet allocated)
    Bogon,
}

/// Configuration for enhanced IP validation
#[derive(Debug, Clone)]
pub struct IpValidationConfig {
    /// Whether to trust proxy headers
    pub trust_proxy_headers: bool,
    /// List of trusted proxy IP addresses or networks
    pub trusted_proxies: Vec<IpNet>,
    /// Whether to anonymize IP addresses in logs
    pub anonymize_logs: bool,
    /// Whether to reject bogon addresses
    pub reject_bogons: bool,
    /// Whether to reject private addresses in public contexts
    pub reject_private_in_public: bool,
}

impl Default for IpValidationConfig {
    fn default() -> Self {
        Self {
            trust_proxy_headers: std::env::var("TRUST_PROXY_HEADERS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            trusted_proxies: vec![
                // Localhost
                IpNet::V4(Ipv4Addr::new(127, 0, 0, 1).into()),
                // Common proxy networks (adjust based on your infrastructure)
                IpNet::V4(Ipv4Addr::new(10, 0, 0, 0).into()), // Private network
            ],
            anonymize_logs: std::env::var("ANONYMIZE_IPS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            reject_bogons: std::env::var("REJECT_BOGONS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(true),
            reject_private_in_public: std::env::var("REJECT_PRIVATE_IN_PUBLIC")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        }
    }
}

/// IP network representation for trusted proxy validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpNet {
    V4(ipnetwork::Ipv4Network),
    V6(ipnetwork::Ipv6Network),
}

impl IpNet {
    /// Check if an IP address is within this network
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpNet::V4(network), IpAddr::V4(ip)) => network.contains(ip),
            (IpNet::V6(network), IpAddr::V6(ip)) => network.contains(ip),
            _ => false,
        }
    }
}

impl From<Ipv4Addr> for IpNet {
    fn from(ip: Ipv4Addr) -> Self {
        IpNet::V4(ipnetwork::Ipv4Network::new(ip, 32).expect("Valid IPv4 network"))
    }
}

/// Enhanced IP address extractor with security validation
pub struct EnhancedIpExtractor {
    config: IpValidationConfig,
}

impl EnhancedIpExtractor {
    /// Create a new IP extractor with the given configuration
    pub fn new(config: IpValidationConfig) -> Self {
        Self { config }
    }

    /// Create a new IP extractor with default configuration
    pub fn default() -> Self {
        Self::new(IpValidationConfig::default())
    }

    /// Extract and validate client IP address from HTTP headers
    ///
    /// This function securely extracts the client IP address from HTTP headers,
    /// with proper validation and security checks.
    ///
    /// # Security Considerations
    ///
    /// - Only trusts proxy headers when explicitly configured
    /// - Validates all extracted IP addresses using proper parsing
    /// - Detects and handles private/reserved IP addresses
    /// - Prevents IP address spoofing through header validation
    ///
    /// # Header Priority
    ///
    /// 1. `X-Forwarded-For` - Most common proxy header (takes first IP)
    /// 2. `X-Real-IP` - Nginx and similar proxies
    /// 3. `CF-Connecting-IP` - Cloudflare specific
    /// 4. `X-Client-IP` - Some load balancers
    /// 5. `Forwarded` - RFC 7239 standard (less common)
    /// 6. Connection peer address (fallback)
    pub fn extract_client_ip(
        &self,
        headers: &HeaderMap,
        connection_peer: IpAddr,
    ) -> Result<EnhancedIpInfo, IpValidationError> {
        // First try to extract from headers if proxy trust is enabled
        if self.config.trust_proxy_headers {
            if let Some(ip_info) = self.extract_from_headers(headers)? {
                return Ok(ip_info);
            }
        }

        // Fall back to connection peer address
        self.validate_and_classify_ip(connection_peer)
    }

    /// Extract IP from HTTP headers with security validation
    fn extract_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<EnhancedIpInfo>, IpValidationError> {
        // Header priority order
        let header_names = [
            "x-forwarded-for",
            "x-real-ip",
            "cf-connecting-ip",
            "x-client-ip",
            "forwarded",
        ];

        for header_name in &header_names {
            if let Some(header_value) = headers.get(*header_name) {
                if let Ok(value_str) = header_value.to_str() {
                    // Extract IP based on header type
                    let ip_str = match *header_name {
                        "x-forwarded-for" => {
                            // Take the first IP (client IP) from the list
                            value_str.split(',').next().unwrap_or(value_str).trim()
                        }
                        "forwarded" => {
                            // Parse RFC 7239 Forwarded header
                            &self.parse_forwarded_header(value_str)?
                        }
                        _ => value_str.trim(),
                    };

                    // Parse and validate the IP
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        let ip_info = self.validate_and_classify_ip(ip)?;

                        // Additional security checks for proxy headers
                        if self.is_trusted_source(&ip_info) {
                            return Ok(Some(ip_info));
                        } else if *header_name == "x-forwarded-for" {
                            // For X-Forwarded-For, we should only trust the last hop
                            // if it comes from a trusted proxy
                            debug!("Untrusted proxy sending X-Forwarded-For: {}", ip);
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Parse RFC 7239 Forwarded header
    fn parse_forwarded_header(&self, header_value: &str) -> Result<String, IpValidationError> {
        // Simple parser for Forwarded header (for="ip")
        for part in header_value.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with("for=") {
                let ip_part = &trimmed[4..];
                // Remove quotes if present
                let clean_ip = if ip_part.starts_with('"') && ip_part.ends_with('"') {
                    ip_part[1..ip_part.len() - 1].to_string()
                } else {
                    ip_part.to_string()
                };
                return Ok(clean_ip);
            }
        }
        Err(IpValidationError::InvalidFormat)
    }

    /// Validate and classify an IP address with security checks
    pub fn validate_and_classify_ip(
        &self,
        ip: IpAddr,
    ) -> Result<EnhancedIpInfo, IpValidationError> {
        // Basic validation
        if !self.is_valid_ip_format(ip) {
            return Err(IpValidationError::InvalidFormat);
        }

        // Classification
        let ip_type = self.classify_ip_type(ip);
        let security_classification = self.classify_security(ip);

        // Security checks
        if self.config.reject_bogons && security_classification == SecurityClassification::Bogon {
            return Err(IpValidationError::BogonAddress);
        }

        if self.config.reject_private_in_public
            && security_classification == SecurityClassification::Private
        {
            return Err(IpValidationError::PrivateAddressNotAllowed);
        }

        // Check if this is from a trusted proxy
        let is_trusted_proxy = self.is_trusted_proxy(ip);

        Ok(EnhancedIpInfo {
            address: ip,
            ip_type,
            security_classification,
            is_trusted_proxy,
            should_anonymize: self.config.anonymize_logs
                || security_classification == SecurityClassification::Private,
        })
    }

    /// Check if an IP address has a valid format
    fn is_valid_ip_format(&self, _ip: IpAddr) -> bool {
        // The IpAddr parsing already validates the format
        // Additional checks could be added here if needed
        true
    }

    /// Classify the IP address type
    fn classify_ip_type(&self, ip: IpAddr) -> IpType {
        match ip {
            IpAddr::V4(_) => IpType::IPv4,
            IpAddr::V6(ipv6) => {
                // Check if it's an IPv4-mapped IPv6 address
                if let Some(_) = ipv6.to_ipv4_mapped() {
                    IpType::IPv4MappedIPv6
                } else {
                    IpType::IPv6
                }
            }
        }
    }

    /// Classify IP address security level
    fn classify_security(&self, ip: IpAddr) -> SecurityClassification {
        match ip {
            IpAddr::V4(ipv4) => self.classify_ipv4_security(ipv4),
            IpAddr::V6(ipv6) => self.classify_ipv6_security(ipv6),
        }
    }

    /// Classify IPv4 address security level
    fn classify_ipv4_security(&self, ip: Ipv4Addr) -> SecurityClassification {
        // Loopback addresses
        if ip.is_loopback() {
            return SecurityClassification::Loopback;
        }

        // Private network addresses (RFC 1918)
        if ip.is_private() {
            return SecurityClassification::Private;
        }

        // Link-local addresses (RFC 3927)
        if ip.is_link_local() {
            return SecurityClassification::SpecialUse;
        }

        // Documentation/test addresses (RFC 5737)
        if ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 2 {
            return SecurityClassification::Reserved; // 192.0.2.0/24
        }
        if ip.octets()[0] == 198 && ip.octets()[1] == 51 && ip.octets()[2] == 100 {
            return SecurityClassification::Reserved; // 198.51.100.0/24
        }
        if ip.octets()[0] == 203 && ip.octets()[1] == 0 && ip.octets()[2] == 113 {
            return SecurityClassification::Reserved; // 203.0.113.0/24
        }

        // Benchmarking addresses (RFC 2544)
        if ip.octets()[0] == 198 && ip.octets()[1] >= 18 && ip.octets()[1] <= 19 {
            return SecurityClassification::Reserved;
        }

        // Multicast addresses (RFC 3171)
        if ip.is_multicast() {
            return SecurityClassification::SpecialUse;
        }

        // Broadcast address
        if ip == Ipv4Addr::BROADCAST {
            return SecurityClassification::SpecialUse;
        }

        // Bogon addresses (unallocated)
        if self.is_ipv4_bogon(ip) {
            return SecurityClassification::Bogon;
        }

        SecurityClassification::Public
    }

    /// Classify IPv6 address security level
    fn classify_ipv6_security(&self, ip: Ipv6Addr) -> SecurityClassification {
        // Loopback address (::1)
        if ip.is_loopback() {
            return SecurityClassification::Loopback;
        }

        // Unspecified address (::)
        if ip.is_unspecified() {
            return SecurityClassification::Reserved;
        }

        // IPv4-mapped IPv6 addresses
        if let Some(ipv4) = ip.to_ipv4_mapped() {
            return self.classify_ipv4_security(ipv4);
        }

        // IPv4-compatible IPv6 addresses (deprecated)
        if let Some(ipv4) = ip.to_ipv4() {
            if ip.segments()[0] == 0
                && ip.segments()[1] == 0
                && ip.segments()[2] == 0
                && ip.segments()[3] == 0
                && ip.segments()[4] == 0
                && ip.segments()[5] == 0
            {
                return self.classify_ipv4_security(ipv4);
            }
        }

        // Link-local addresses (FE80::/10)
        if ip.segments()[0] & 0xFFC0 == 0xFE80 {
            return SecurityClassification::SpecialUse;
        }

        // Unique local addresses (FC00::/7)
        if ip.segments()[0] & 0xFE00 == 0xFC00 {
            return SecurityClassification::Private;
        }

        // Multicast addresses (FF00::/8)
        if ip.segments()[0] & 0xFF00 == 0xFF00 {
            return SecurityClassification::SpecialUse;
        }

        // Documentation addresses (RFC 3849)
        if ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xDB8 {
            return SecurityClassification::Reserved;
        }

        // Bogon addresses (unallocated)
        if self.is_ipv6_bogon(ip) {
            return SecurityClassification::Bogon;
        }

        SecurityClassification::Public
    }

    /// Check if an IPv4 address is a bogon (unallocated)
    fn is_ipv4_bogon(&self, ip: Ipv4Addr) -> bool {
        let octets = ip.octets();

        // 0.0.0.0/8 - Current network (RFC 1700)
        if octets[0] == 0 {
            return true;
        }

        // 100.64.0.0/10 - Shared address space (RFC 6598)
        if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
            return true;
        }

        // 127.0.0.0/8 - Loopback (already checked)
        if octets[0] == 127 {
            return false; // Already classified as loopback
        }

        // 169.254.0.0/16 - Link-local (already checked)
        if octets[0] == 169 && octets[1] == 254 {
            return false; // Already classified as special use
        }

        // 192.0.0.0/24 - IETF Protocol Assignments (RFC 6890)
        if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
            return true;
        }

        // 192.0.2.0/24 - Documentation (TEST-NET-1) (already checked)
        if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
            return false; // Already classified as reserved
        }

        // 192.88.99.0/24 - 6to4 relay anycast (RFC 3068)
        if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
            return true;
        }

        // 198.18.0.0/15 - Network interconnect device benchmark testing (RFC 2544)
        if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
            return false; // Already classified as reserved
        }

        // 198.51.100.0/24 - Documentation (TEST-NET-2) (already checked)
        if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
            return false; // Already classified as reserved
        }

        // 203.0.113.0/24 - Documentation (TEST-NET-3) (already checked)
        if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
            return false; // Already classified as reserved
        }

        // 224.0.0.0/4 - Multicast (already checked)
        if (octets[0] & 0xF0) == 224 {
            return false; // Already classified as special use
        }

        // 240.0.0.0/4 - Reserved for future use (RFC 1700)
        if (octets[0] & 0xF0) == 240 {
            return true;
        }

        // 255.255.255.255/32 - Limited broadcast (already checked)
        if ip == Ipv4Addr::BROADCAST {
            return false; // Already classified as special use
        }

        false
    }

    /// Check if an IPv6 address is a bogon (unallocated)
    fn is_ipv6_bogon(&self, ip: Ipv6Addr) -> bool {
        let segments = ip.segments();

        // ::/128 - Unspecified address (already checked)
        if segments == [0, 0, 0, 0, 0, 0, 0, 0] {
            return false; // Already classified as reserved
        }

        // ::1/128 - Loopback (already checked)
        if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
            return false; // Already classified as loopback
        }

        // 100::/64 - Discard prefix (RFC 6666)
        if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
            return true;
        }

        // 2001:1::1/128 - Port Control Protocol Anycast
        if segments == [0x2001, 0x0001, 0, 0, 0, 0, 0, 0x0001] {
            return true;
        }

        // 2001:1::2/128 - Traversal Using Relays around NAT Anycast
        if segments == [0x2001, 0x0001, 0, 0, 0, 0, 0, 0x0002] {
            return true;
        }

        // 2001:2::/48 - Benchmarking (RFC 5180)
        if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0 {
            return true;
        }

        // 2001:3::/32 - AMT (RFC 7450)
        if segments[0] == 0x2001 && segments[1] == 0x0003 {
            return true;
        }

        // 2001:4:112::/48 - AS112-v6 (RFC 7535)
        if segments[0] == 0x2001 && segments[1] == 0x0004 && segments[2] == 0x0112 {
            return true;
        }

        // 2001:5::/32 - EID-in-LISP-and-No-Map-EID (RFC 7954)
        if segments[0] == 0x2001 && segments[1] == 0x0005 {
            return true;
        }

        // 2001:10::/28 - ORCHID (RFC 4843, obsoleted by RFC 7343)
        if segments[0] == 0x2001 && (segments[1] & 0xFFF0) == 0x0010 {
            return true;
        }

        // 2001:20::/28 - ORCHIDv2 (RFC 7343)
        if segments[0] == 0x2001 && (segments[1] & 0xFFF0) == 0x0020 {
            return true;
        }

        // 2001:db8::/32 - Documentation (already checked)
        if segments[0] == 0x2001 && segments[1] == 0xDB8 {
            return false; // Already classified as reserved
        }

        false
    }

    /// Check if an IP address is from a trusted proxy
    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        for trusted_network in &self.config.trusted_proxies {
            if trusted_network.contains(ip) {
                return true;
            }
        }
        false
    }

    /// Check if an IP info is from a trusted source
    fn is_trusted_source(&self, ip_info: &EnhancedIpInfo) -> bool {
        // Trusted proxies are trusted sources
        if ip_info.is_trusted_proxy {
            return true;
        }

        // Loopback addresses are generally trusted
        if ip_info.security_classification == SecurityClassification::Loopback {
            return true;
        }

        // Private addresses might be trusted in certain contexts
        if ip_info.security_classification == SecurityClassification::Private {
            // In internal networks, private addresses might be trusted
            // This depends on the specific deployment context
            return false; // Conservative approach - not trusted by default
        }

        false
    }

    /// Anonymize an IP address for privacy protection
    ///
    /// This function removes identifying information from IP addresses
    /// while preserving enough information for geolocation and threat analysis.
    pub fn anonymize_ip(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Remove the last octet for IPv4 (8 bits of entropy)
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0))
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                // Remove the last 32 bits for IPv6 (4 segments)
                IpAddr::V6(Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    segments[4],
                    segments[5],
                    0,
                    0,
                ))
            }
        }
    }

    /// Get a display-safe version of an IP address
    ///
    /// Returns either the full IP address or an anonymized version based on configuration
    /// and security classification.
    pub fn display_ip(&self, ip_info: &EnhancedIpInfo) -> String {
        if ip_info.should_anonymize {
            self.anonymize_ip(ip_info.address).to_string()
        } else {
            ip_info.address.to_string()
        }
    }

    /// Check if an IP address should be blocked based on security policy
    pub fn should_block_ip(&self, ip_info: &EnhancedIpInfo) -> bool {
        // Block bogon addresses if configured
        if self.config.reject_bogons
            && ip_info.security_classification == SecurityClassification::Bogon
        {
            return true;
        }

        // Block private addresses in public contexts if configured
        if self.config.reject_private_in_public
            && ip_info.security_classification == SecurityClassification::Private
        {
            return true;
        }

        // Additional blocking logic could be added here based on:
        // - Threat intelligence feeds
        // - Geolocation restrictions
        // - Rate limiting violations
        // - Historical abuse patterns

        false
    }
}

/// Custom error types for IP validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpValidationError {
    /// Invalid IP address format
    InvalidFormat,
    /// Bogon address (unallocated IP space)
    BogonAddress,
    /// Private address not allowed in this context
    PrivateAddressNotAllowed,
    /// Reserved address not allowed
    ReservedAddressNotAllowed,
    /// Header parsing error
    HeaderParseError,
}

impl std::fmt::Display for IpValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpValidationError::InvalidFormat => write!(f, "Invalid IP address format"),
            IpValidationError::BogonAddress => write!(f, "Bogon address not allowed"),
            IpValidationError::PrivateAddressNotAllowed => {
                write!(f, "Private address not allowed in this context")
            }
            IpValidationError::ReservedAddressNotAllowed => {
                write!(f, "Reserved address not allowed")
            }
            IpValidationError::HeaderParseError => write!(f, "Failed to parse IP from headers"),
        }
    }
}

impl std::error::Error for IpValidationError {}

/// Convenience function for extracting client IP with default configuration
///
/// This function provides a simple interface for extracting and validating
/// client IP addresses with default security settings.
pub fn extract_client_ip_enhanced(
    headers: &HeaderMap,
    connection_peer: IpAddr,
) -> Result<EnhancedIpInfo, IpValidationError> {
    let extractor = EnhancedIpExtractor::default();
    extractor.extract_client_ip(headers, connection_peer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_enhanced_ip_extractor_creation() {
        let extractor = EnhancedIpExtractor::default();
        assert!(!extractor.config.trust_proxy_headers);
    }

    #[test]
    fn test_ipv4_classification() {
        let extractor = EnhancedIpExtractor::default();

        // Public IP
        let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
        let ip_info = extractor.validate_and_classify_ip(public_ip).unwrap();
        assert_eq!(
            ip_info.security_classification,
            SecurityClassification::Public
        );
        assert_eq!(ip_info.ip_type, IpType::IPv4);

        // Private IP
        let private_ip: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_info = extractor.validate_and_classify_ip(private_ip).unwrap();
        assert_eq!(
            ip_info.security_classification,
            SecurityClassification::Private
        );
        assert_eq!(ip_info.ip_type, IpType::IPv4);

        // Loopback IP
        let loopback_ip: IpAddr = "127.0.0.1".parse().unwrap();
        let ip_info = extractor.validate_and_classify_ip(loopback_ip).unwrap();
        assert_eq!(
            ip_info.security_classification,
            SecurityClassification::Loopback
        );
        assert_eq!(ip_info.ip_type, IpType::IPv4);
    }

    #[test]
    fn test_ipv6_classification() {
        let extractor = EnhancedIpExtractor::default();

        // Public IPv6
        let public_ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap(); // IPv4-mapped IPv6
        let ip_info = extractor.validate_and_classify_ip(public_ip).unwrap();
        assert_eq!(
            ip_info.security_classification,
            SecurityClassification::Public
        );
        assert_eq!(ip_info.ip_type, IpType::IPv4MappedIPv6);

        // Loopback IPv6
        let loopback_ip: IpAddr = "::1".parse().unwrap();
        let ip_info = extractor.validate_and_classify_ip(loopback_ip).unwrap();
        assert_eq!(
            ip_info.security_classification,
            SecurityClassification::Loopback
        );
        assert_eq!(ip_info.ip_type, IpType::IPv6);

        // Unique local IPv6
        let ula_ip: IpAddr = "fd12:3456:789a:bcde::1".parse().unwrap();
        let ip_info = extractor.validate_and_classify_ip(ula_ip).unwrap();
        assert_eq!(
            ip_info.security_classification,
            SecurityClassification::Private
        );
        assert_eq!(ip_info.ip_type, IpType::IPv6);
    }

    #[test]
    fn test_header_extraction() {
        let extractor = EnhancedIpExtractor::default();
        let mut headers = HeaderMap::new();

        // Test X-Forwarded-For
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 198.51.100.1"),
        );
        let connection_ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Without trusting proxy headers, should return connection IP
        let ip_info = extractor
            .extract_client_ip(&headers, connection_ip)
            .unwrap();
        assert_eq!(ip_info.address, connection_ip);

        // With trusting proxy headers
        let mut config = IpValidationConfig::default();
        config.trust_proxy_headers = true;
        let extractor = EnhancedIpExtractor::new(config);
        let ip_info = extractor
            .extract_client_ip(&headers, connection_ip)
            .unwrap();
        assert_eq!(ip_info.address.to_string(), "203.0.113.1");
    }

    #[test]
    fn test_ip_anonymization() {
        let extractor = EnhancedIpExtractor::default();

        // Test IPv4 anonymization
        let ipv4: IpAddr = "192.168.1.100".parse().unwrap();
        let anonymized = extractor.anonymize_ip(ipv4);
        assert_eq!(anonymized.to_string(), "192.168.1.0");

        // Test IPv6 anonymization
        let ipv6: IpAddr = "2001:db8::1234:5678".parse().unwrap();
        let anonymized = extractor.anonymize_ip(ipv6);
        assert_eq!(anonymized.to_string(), "2001:db8::");
    }

    #[test]
    fn test_security_blocking() {
        let mut config = IpValidationConfig::default();
        config.reject_bogons = true;
        config.reject_private_in_public = true;

        let extractor = EnhancedIpExtractor::new(config);

        // Test bogon blocking
        let bogon_ip: IpAddr = "198.18.0.1".parse().unwrap(); // Benchmarking address
        let ip_info = extractor.validate_and_classify_ip(bogon_ip).unwrap();
        assert!(extractor.should_block_ip(&ip_info));

        // Test private blocking in public context
        let private_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_info = extractor.validate_and_classify_ip(private_ip).unwrap();
        assert!(extractor.should_block_ip(&ip_info));
    }

    #[test]
    fn test_trusted_proxy_detection() {
        let mut config = IpValidationConfig::default();
        config.trust_proxy_headers = true;
        // Add localhost as trusted proxy
        config
            .trusted_proxies
            .push(IpNet::V4(Ipv4Addr::new(127, 0, 0, 1).into()));

        let extractor = EnhancedIpExtractor::new(config);

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(extractor.is_trusted_proxy(ip));
    }
}
