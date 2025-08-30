//! `OAuth` Client Registration Security Policies
//!
//! Security-focused policies for `OAuth` 2.0 dynamic client registration
//! including cryptographic requirements, network security, and geolocation controls.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security policy set for `OAuth` client registration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityPolicySet {
    /// URI validation policy
    pub uri_policy: UriValidationPolicy,

    /// Content validation policy
    pub content_policy: ContentValidationPolicy,

    /// Cryptographic policy
    pub crypto_policy: CryptographicPolicy,

    /// Network security policy
    pub network_policy: NetworkSecurityPolicy,

    /// Geolocation policy
    pub geolocation_policy: GeolocationPolicy,
}

/// URI validation policy for redirect URIs and other URIs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriValidationPolicy {
    /// Allowed URI schemes
    pub allowed_schemes: Vec<String>,

    /// Blocked URI patterns (regex)
    pub blocked_patterns: Vec<String>,

    /// Require HTTPS for production
    pub require_https: bool,

    /// Maximum URI length
    pub max_length: usize,

    /// Allow localhost for development
    pub allow_localhost: bool,

    /// Allow private IP addresses
    pub allow_private_ips: bool,

    /// Custom URI validation rules
    pub custom_rules: Vec<UriValidationRule>,
}

/// Custom URI validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriValidationRule {
    /// Rule name
    pub name: String,

    /// URI pattern to match (regex)
    pub pattern: String,

    /// Whether this rule allows or blocks
    pub action: ValidationAction,

    /// Priority (higher numbers processed first)
    pub priority: i32,
}

/// Content validation policy for client metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentValidationPolicy {
    /// Maximum client name length
    pub max_client_name_length: usize,

    /// Maximum description length
    pub max_description_length: usize,

    /// Maximum logo URI length
    pub max_logo_uri_length: usize,

    /// Maximum policy URI length
    pub max_policy_uri_length: usize,

    /// Maximum terms of service URI length
    pub max_tos_uri_length: usize,

    /// Maximum contacts array size
    pub max_contacts_count: usize,

    /// Allowed characters in client names (regex)
    pub allowed_client_name_chars: Option<String>,

    /// Blocked words in client names
    pub blocked_client_name_words: Vec<String>,

    /// Require client URI for certain grant types
    pub require_client_uri_for_grant_types: Vec<String>,
}

/// Cryptographic policy for client registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicPolicy {
    /// Minimum RSA key size
    pub min_rsa_key_size: usize,

    /// Minimum ECDSA curve strength
    pub min_ecdsa_curve: String,

    /// Allowed signature algorithms
    pub allowed_algorithms: Vec<String>,

    /// Require key rotation
    pub require_key_rotation: bool,

    /// Maximum key age in days
    pub max_key_age_days: usize,

    /// Require certificate validation
    pub require_certificate_validation: bool,

    /// Allowed certificate authorities
    pub allowed_certificate_authorities: Vec<String>,
}

/// Network security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityPolicy {
    /// Allowed IP ranges for client registration
    pub allowed_ip_ranges: Vec<String>,

    /// Blocked IP ranges
    pub blocked_ip_ranges: Vec<String>,

    /// Require rate limiting
    pub require_rate_limiting: bool,

    /// Maximum requests per hour per IP
    pub max_requests_per_hour: usize,

    /// Maximum concurrent connections per IP
    pub max_concurrent_connections: usize,

    /// Require `DDoS` protection
    pub require_ddos_protection: bool,

    /// Trusted proxy headers
    pub trusted_proxy_headers: Vec<String>,
}

/// Geolocation policy for client registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationPolicy {
    /// Allowed countries (ISO 3166-1 alpha-2)
    pub allowed_countries: Vec<String>,

    /// Blocked countries
    pub blocked_countries: Vec<String>,

    /// Require geolocation verification
    pub require_geolocation: bool,

    /// Maximum allowed distance from registered location
    pub max_distance_km: Option<f64>,

    /// Require VPN detection and blocking
    pub block_vpn: bool,

    /// Require TOR detection and blocking
    pub block_tor: bool,

    /// Custom geolocation rules
    pub custom_rules: Vec<GeolocationRule>,
}

/// Custom geolocation validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationRule {
    /// Rule name
    pub name: String,

    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: String,

    /// Action to take
    pub action: ValidationAction,

    /// Additional conditions
    pub conditions: HashMap<String, String>,
}

/// Validation action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationAction {
    /// Allow the request
    Allow,

    /// Block the request
    Block,

    /// Require additional verification
    RequireVerification,
}

impl Default for UriValidationPolicy {
    fn default() -> Self {
        Self {
            allowed_schemes: vec!["https".to_string(), "http".to_string()],
            blocked_patterns: vec![
                r"^https?://.*\.local$".to_string(),
                r"^https?://localhost".to_string(),
            ],
            require_https: true,
            max_length: 2048,
            allow_localhost: false,
            allow_private_ips: false,
            custom_rules: Vec::new(),
        }
    }
}

impl Default for ContentValidationPolicy {
    fn default() -> Self {
        Self {
            max_client_name_length: 256,
            max_description_length: 1024,
            max_logo_uri_length: 2048,
            max_policy_uri_length: 2048,
            max_tos_uri_length: 2048,
            max_contacts_count: 10,
            allowed_client_name_chars: Some(r"^[a-zA-Z0-9\s\-_\.]+$".to_string()),
            blocked_client_name_words: vec![
                "admin".to_string(),
                "root".to_string(),
                "system".to_string(),
            ],
            require_client_uri_for_grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
        }
    }
}

impl Default for CryptographicPolicy {
    fn default() -> Self {
        Self {
            min_rsa_key_size: 2048,
            min_ecdsa_curve: "P-256".to_string(),
            allowed_algorithms: vec![
                "RS256".to_string(),
                "ES256".to_string(),
                "PS256".to_string(),
            ],
            require_key_rotation: true,
            max_key_age_days: 365,
            require_certificate_validation: true,
            allowed_certificate_authorities: Vec::new(),
        }
    }
}

impl Default for NetworkSecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_ip_ranges: Vec::new(),
            blocked_ip_ranges: Vec::new(),
            require_rate_limiting: true,
            max_requests_per_hour: 100,
            max_concurrent_connections: 10,
            require_ddos_protection: true,
            trusted_proxy_headers: vec!["X-Forwarded-For".to_string(), "X-Real-IP".to_string()],
        }
    }
}

impl Default for GeolocationPolicy {
    fn default() -> Self {
        Self {
            allowed_countries: Vec::new(),
            blocked_countries: Vec::new(),
            require_geolocation: false,
            max_distance_km: None,
            block_vpn: true,
            block_tor: true,
            custom_rules: Vec::new(),
        }
    }
}
