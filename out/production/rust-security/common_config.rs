//! Common configuration structures to eliminate duplication across modules
//!
//! This module provides shared configuration types that are used throughout
//! the codebase to ensure consistency and reduce code duplication.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Common timeout configuration used across multiple services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    pub connection_timeout: Duration,
    pub request_timeout: Duration,
    pub operation_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(60),
        }
    }
}

/// Common retry configuration used across multiple services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
        }
    }
}

/// Common rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_window: u32,
    pub window_duration: Duration,
    pub burst_capacity: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_window: 100,
            window_duration: Duration::from_secs(60),
            burst_capacity: 150,
        }
    }
}

/// Common security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enforce_https: bool,
    pub require_auth: bool,
    pub allowed_origins: Vec<String>,
    pub session_timeout: Duration,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enforce_https: true,
            require_auth: true,
            allowed_origins: vec!["https://localhost:3000".to_string()],
            session_timeout: Duration::from_secs(3600),
        }
    }
}

/// Unified service configuration combining common patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfig {
    pub timeouts: TimeoutConfig,
    pub retry: RetryConfig,
    pub rate_limit: RateLimitConfig,
    pub security: SecurityConfig,
}

/// Common validation utilities to prevent duplication
pub mod validation {
    use regex::Regex;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::LazyLock;

    static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Email regex should compile")
    });

    static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            .expect("UUID regex should compile")
    });

    /// Validate email address format
    pub fn is_valid_email(email: &str) -> bool {
        EMAIL_REGEX.is_match(email)
    }

    /// Validate UUID format
    pub fn is_valid_uuid(uuid: &str) -> bool {
        UUID_REGEX.is_match(uuid)
    }

    /// Validate IP address
    #[must_use]
    pub fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<IpAddr>().is_ok()
    }

    /// Check if IP is localhost
    #[must_use]
    pub fn is_localhost(ip: &str) -> bool {
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(ipv4)) => {
                ipv4 == Ipv4Addr::LOCALHOST || ipv4.is_loopback() || ipv4.is_private()
            }
            Ok(IpAddr::V6(ipv6)) => ipv6 == Ipv6Addr::LOCALHOST || ipv6.is_loopback(),
            Err(_) => {
                // Try hostname patterns
                matches!(ip, "localhost" | "127.0.0.1" | "::1")
            }
        }
    }

    /// Validate port number
    #[must_use]
    pub const fn is_valid_port(port: u16) -> bool {
        port > 0
    }

    /// Common password strength validation
    pub fn validate_password_strength(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        let has_uppercase = password.chars().any(char::is_uppercase);
        let has_lowercase = password.chars().any(char::is_lowercase);
        let has_digit = password.chars().any(char::is_numeric);
        let has_special = password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        if !has_uppercase {
            return Err("Password must contain at least one uppercase letter".to_string());
        }
        if !has_lowercase {
            return Err("Password must contain at least one lowercase letter".to_string());
        }
        if !has_digit {
            return Err("Password must contain at least one digit".to_string());
        }
        if !has_special {
            return Err("Password must contain at least one special character".to_string());
        }

        Ok(())
    }
}

/// Common error handling utilities
pub mod error_handling {
    use std::fmt::Display;
    use tracing::{error, warn};

    /// Log and convert an error with context
    pub fn log_and_convert<E: Display, T>(result: Result<T, E>, context: &str) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(e) => {
                error!("Error in {}: {}", context, e);
                None
            }
        }
    }

    /// Log a warning and return a default value
    pub fn warn_and_default<T: Default>(message: &str) -> T {
        warn!("{}", message);
        T::default()
    }

    /// Retry operation with exponential backoff
    pub async fn retry_with_backoff<F, T, E>(
        mut operation: F,
        max_attempts: u32,
        base_delay: std::time::Duration,
        backoff_multiplier: f64,
    ) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
        E: Display,
    {
        let mut attempts = 0;
        let mut delay = base_delay;

        loop {
            attempts += 1;

            match operation() {
                Ok(result) => return Ok(result),
                Err(e) if attempts >= max_attempts => return Err(e),
                Err(e) => {
                    warn!(
                        "Operation failed (attempt {}/{}): {}",
                        attempts, max_attempts, e
                    );
                    tokio::time::sleep(delay).await;
                    delay = std::time::Duration::from_millis(
                        (delay.as_millis() as f64 * backoff_multiplier) as u64,
                    );
                }
            }
        }
    }
}
