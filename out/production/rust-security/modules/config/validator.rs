//! Configuration Validator
//!
//! Validates configuration values and provides detailed error reporting.

use std::collections::HashSet;
use regex::Regex;
use validator::{Validate, ValidationError, ValidationErrors};
use crate::shared::error::AppError;
use super::loader::{ServiceConfig, ServerConfig, DatabaseConfig, RedisConfig, SecurityConfig, JwtConfig, OAuthConfig, RateLimitingConfig, SessionConfig, MonitoringConfig, FeaturesConfig};

/// Configuration validator with comprehensive validation rules
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate entire configuration
    pub fn validate_config(config: &ServiceConfig) -> Result<(), AppError> {
        let mut errors = Vec::new();

        // Validate each section
        if let Err(e) = Self::validate_server_config(&config.server) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_database_config(&config.database) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_redis_config(&config.redis) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_security_config(&config.security) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_jwt_config(&config.jwt) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_oauth_config(&config.oauth) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_rate_limiting_config(&config.rate_limiting) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_session_config(&config.session) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_monitoring_config(&config.monitoring) {
            errors.extend(e);
        }

        if let Err(e) = Self::validate_features_config(&config.features) {
            errors.extend(e);
        }

        // Validate cross-section dependencies
        if let Err(e) = Self::validate_config_dependencies(config) {
            errors.extend(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(AppError::Validation(format!("Configuration validation failed: {}", errors.join(", "))))
        }
    }

    /// Validate server configuration
    fn validate_server_config(config: &ServerConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate port
        if config.port == 0 || config.port > 65535 {
            errors.push("Server port must be between 1 and 65535".to_string());
        }

        // Validate host
        if config.host.is_empty() {
            errors.push("Server host cannot be empty".to_string());
        }

        // Validate bind address
        if config.bind_addr.is_empty() {
            errors.push("Server bind address cannot be empty".to_string());
        } else if config.bind_addr.parse::<std::net::SocketAddr>().is_err() {
            errors.push("Server bind address must be a valid socket address".to_string());
        }

        // Validate timeouts
        if let Err(_) = Self::parse_duration(&config.request_timeout) {
            errors.push("Invalid request timeout format".to_string());
        }

        if let Err(_) = Self::parse_duration(&config.shutdown_timeout) {
            errors.push("Invalid shutdown timeout format".to_string());
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate database configuration
    fn validate_database_config(config: &DatabaseConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate URL
        if config.url.is_empty() {
            errors.push("Database URL cannot be empty".to_string());
        } else if !config.url.starts_with("sqlite:") &&
                  !config.url.starts_with("postgresql:") &&
                  !config.url.starts_with("mysql:") {
            errors.push("Database URL must be a valid database connection string".to_string());
        }

        // Validate connection pool settings
        if let Some(max_conn) = config.max_connections {
            if max_conn == 0 {
                errors.push("Database max connections cannot be 0".to_string());
            }
        }

        if let Some(min_conn) = config.min_connections {
            if let Some(max_conn) = config.max_connections {
                if min_conn > max_conn {
                    errors.push("Database min connections cannot be greater than max connections".to_string());
                }
            }
        }

        // Validate timeouts
        if let Some(ref timeout) = config.connect_timeout {
            if Self::parse_duration(timeout).is_err() {
                errors.push("Invalid database connect timeout format".to_string());
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate Redis configuration
    fn validate_redis_config(config: &RedisConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate URL
        if config.url.is_empty() {
            errors.push("Redis URL cannot be empty".to_string());
        } else if !config.url.starts_with("redis://") && !config.url.starts_with("rediss://") {
            errors.push("Redis URL must start with redis:// or rediss://".to_string());
        }

        // Validate timeouts
        if Self::parse_duration(&config.connection_timeout).is_err() {
            errors.push("Invalid Redis connection timeout format".to_string());
        }

        if Self::parse_duration(&config.command_timeout).is_err() {
            errors.push("Invalid Redis command timeout format".to_string());
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate security configuration
    fn validate_security_config(config: &SecurityConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate password requirements
        if let Some(min_length) = config.password_min_length {
            if min_length < 8 {
                errors.push("Minimum password length must be at least 8".to_string());
            }
        }

        if let Some(cost) = config.bcrypt_cost {
            if cost < 4 || cost > 31 {
                errors.push("Bcrypt cost must be between 4 and 31".to_string());
            }
        }

        if let Some(attempts) = config.max_login_attempts {
            if attempts == 0 {
                errors.push("Maximum login attempts cannot be 0".to_string());
            }
        }

        // Validate lockout duration
        if let Some(ref duration) = config.lockout_duration {
            if Self::parse_duration(duration).is_err() {
                errors.push("Invalid lockout duration format".to_string());
            }
        }

        // Validate CORS configuration
        if let Some(ref cors) = config.cors {
            for origin in &cors.allowed_origins {
                if !Self::is_valid_url(origin) && !Self::is_valid_origin_pattern(origin) {
                    errors.push(format!("Invalid CORS origin: {}", origin));
                }
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate JWT configuration
    fn validate_jwt_config(config: &JwtConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate secret
        if let Some(ref secret) = config.secret {
            if secret.len() < 32 {
                errors.push("JWT secret must be at least 32 characters long".to_string());
            }
        }

        // Validate algorithm
        let valid_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"];
        if !valid_algorithms.contains(&config.algorithm.as_str()) {
            errors.push(format!("Invalid JWT algorithm: {}", config.algorithm));
        }

        // Validate TTL formats
        if Self::parse_duration(&config.access_token_ttl).is_err() {
            errors.push("Invalid JWT access token TTL format".to_string());
        }

        if Self::parse_duration(&config.refresh_token_ttl).is_err() {
            errors.push("Invalid JWT refresh token TTL format".to_string());
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate OAuth configuration
    fn validate_oauth_config(config: &OAuthConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate providers
        if let Some(ref providers) = config.providers {
            for (name, provider) in providers {
                if provider.client_id.is_empty() {
                    errors.push(format!("OAuth provider {}: client_id cannot be empty", name));
                }
                if provider.client_secret.is_empty() {
                    errors.push(format!("OAuth provider {}: client_secret cannot be empty", name));
                }
                if !Self::is_valid_url(&provider.authorization_url) {
                    errors.push(format!("OAuth provider {}: invalid authorization URL", name));
                }
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate rate limiting configuration
    fn validate_rate_limiting_config(config: &RateLimitingConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate limits
        if config.global_limit == 0 {
            errors.push("Global rate limit cannot be 0".to_string());
        }

        if config.per_ip_limit == 0 {
            errors.push("Per-IP rate limit cannot be 0".to_string());
        }

        // Validate windows
        if Self::parse_duration(&config.global_window).is_err() {
            errors.push("Invalid global rate limit window format".to_string());
        }

        if Self::parse_duration(&config.per_ip_window).is_err() {
            errors.push("Invalid per-IP rate limit window format".to_string());
        }

        if Self::parse_duration(&config.per_user_window).is_err() {
            errors.push("Invalid per-user rate limit window format".to_string());
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate session configuration
    fn validate_session_config(config: &SessionConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate TTL
        if Self::parse_duration(&config.ttl).is_err() {
            errors.push("Invalid session TTL format".to_string());
        }

        // Validate cookie name
        if config.cookie_name.is_empty() {
            errors.push("Session cookie name cannot be empty".to_string());
        }

        // Validate same-site
        let valid_same_site = ["Strict", "Lax", "None"];
        if !valid_same_site.contains(&config.cookie_same_site.as_str()) {
            errors.push(format!("Invalid cookie same-site value: {}", config.cookie_same_site));
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate monitoring configuration
    fn validate_monitoring_config(config: &MonitoringConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate tracing level
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&config.tracing_level.as_str()) {
            errors.push(format!("Invalid tracing level: {}", config.tracing_level));
        }

        // Validate log format
        let valid_formats = ["json", "text", "compact"];
        if !valid_formats.contains(&config.log_format.as_str()) {
            errors.push(format!("Invalid log format: {}", config.log_format));
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Validate features configuration
    fn validate_features_config(_config: &FeaturesConfig) -> Result<(), Vec<String>> {
        // Features config is mostly boolean flags, minimal validation needed
        Ok(())
    }

    /// Validate cross-section dependencies
    fn validate_config_dependencies(config: &ServiceConfig) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Check if Redis is required for certain features
        if config.features.oauth_enabled && config.redis.url.is_empty() {
            errors.push("OAuth requires Redis for session management".to_string());
        }

        // Check if monitoring is enabled but no endpoints configured
        if config.monitoring.metrics_enabled && config.monitoring.metrics_path.is_empty() {
            errors.push("Metrics enabled but no metrics path configured".to_string());
        }

        // Check JWT configuration consistency
        if config.jwt.secret.is_none() && config.features.oauth_enabled {
            errors.push("OAuth enabled but no JWT secret configured".to_string());
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Parse duration string (e.g., "30s", "5m", "1h", "24h")
    fn parse_duration(duration: &str) -> Result<std::time::Duration, ()> {
        let re = Regex::new(r"^(\d+)([smhd])$").map_err(|_| ())?;
        let caps = re.captures(duration).ok_or(())?;

        let value: u64 = caps[1].parse().map_err(|_| ())?;
        let unit = &caps[2];

        let seconds = match unit {
            "s" => value,
            "m" => value * 60,
            "h" => value * 3600,
            "d" => value * 86400,
            _ => return Err(()),
        };

        Ok(std::time::Duration::from_secs(seconds))
    }

    /// Validate URL format
    fn is_valid_url(url: &str) -> bool {
        url.starts_with("http://") || url.starts_with("https://")
    }

    /// Validate CORS origin pattern
    fn is_valid_origin_pattern(pattern: &str) -> bool {
        // Simple pattern validation for CORS origins
        pattern.contains("*") || Self::is_valid_url(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert!(ConfigValidator::parse_duration("30s").is_ok());
        assert!(ConfigValidator::parse_duration("5m").is_ok());
        assert!(ConfigValidator::parse_duration("1h").is_ok());
        assert!(ConfigValidator::parse_duration("24h").is_ok());
        assert!(ConfigValidator::parse_duration("invalid").is_err());
        assert!(ConfigValidator::parse_duration("30x").is_err());
    }

    #[test]
    fn test_validate_server_config() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8080,
            bind_addr: "127.0.0.1:8080".to_string(),
            max_connections: 1000,
            request_timeout: "30s".to_string(),
            shutdown_timeout: "30s".to_string(),
        };

        assert!(ConfigValidator::validate_server_config(&config).is_ok());
    }

    #[test]
    fn test_validate_invalid_server_config() {
        let config = ServerConfig {
            host: "".to_string(),
            port: 0,
            bind_addr: "invalid".to_string(),
            max_connections: 1000,
            request_timeout: "30s".to_string(),
            shutdown_timeout: "30s".to_string(),
        };

        assert!(ConfigValidator::validate_server_config(&config).is_err());
    }
}
