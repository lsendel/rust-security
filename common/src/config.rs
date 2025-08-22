//! Platform configuration for rust-security services

use serde::{Deserialize, Serialize};

/// Platform-wide configuration for all services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfiguration {
    /// Environment (development, staging, production)
    pub environment: String,
    /// Service name
    pub service_name: String,
    /// Log level
    pub log_level: String,
    /// Security settings
    pub security: SecurityConfig,
}

/// Security configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable security headers
    pub enable_security_headers: bool,
    /// Rate limiting settings
    pub rate_limit: RateLimitConfig,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per minute
    pub requests_per_minute: u64,
    /// Enable rate limiting
    pub enabled: bool,
}

impl Default for PlatformConfiguration {
    fn default() -> Self {
        Self {
            environment: "development".to_string(),
            service_name: "auth-service".to_string(),
            log_level: "info".to_string(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_security_headers: true,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            enabled: true,
        }
    }
}