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

impl PlatformConfiguration {
    /// Basic validation to ensure sane configuration; returns Err with reason when invalid
    pub fn validate(&self) -> Result<(), String> {
        // environment should be one of known values
        let env = self.environment.to_lowercase();
        let valid_env = matches!(
            env.as_str(),
            "development" | "staging" | "production" | "test"
        );
        if !valid_env {
            return Err(format!("invalid environment: {}", self.environment));
        }
        if self.service_name.trim().is_empty() {
            return Err("service_name must not be empty".to_string());
        }
        if !matches!(
            self.log_level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            return Err(format!("invalid log_level: {}", self.log_level));
        }
        self.security.validate()
    }
}

impl SecurityConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.rate_limit.validate()
    }
}

impl RateLimitConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && (self.requests_per_minute == 0 || self.requests_per_minute > 1_000_000) {
            return Err("requests_per_minute must be in 1..=1_000_000 when enabled".to_string());
        }
        Ok(())
    }
}
