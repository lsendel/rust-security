//! Production logging configuration for the authentication service
//!
//! This module provides structured logging configuration optimized for production
//! environments with proper log levels, formatting, and security considerations.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tracing::{info, Level};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Logging configuration for different environments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Log format (json, compact, pretty)
    pub format: LogFormat,
    /// Whether to log to file
    pub log_to_file: bool,
    /// Log file path (if logging to file)
    pub file_path: Option<String>,
    /// Maximum log file size in MB
    pub max_file_size_mb: u64,
    /// Number of log files to retain
    pub max_files: u32,
    /// Enable structured logging for production
    pub structured: bool,
    /// Enable request/response logging
    pub log_requests: bool,
    /// Mask sensitive data in logs
    pub mask_sensitive_data: bool,
    /// Include source location in logs
    pub include_location: bool,
    /// Enable distributed tracing
    pub enable_tracing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    /// JSON format for production
    Json,
    /// Compact format for development
    Compact,
    /// Pretty format for local development
    Pretty,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
            log_to_file: false,
            file_path: Some("/var/log/auth-service/auth-service.log".to_string()),
            max_file_size_mb: 100,
            max_files: 10,
            structured: true,
            log_requests: true,
            mask_sensitive_data: true,
            include_location: false,
            enable_tracing: true,
        }
    }
}

impl LoggingConfig {
    /// Create production logging configuration
    #[must_use]
    pub fn production() -> Self {
        Self {
            level: "info".to_string(),
            format: LogFormat::Json,
            log_to_file: true,
            file_path: Some("/var/log/auth-service/auth-service.log".to_string()),
            max_file_size_mb: 100,
            max_files: 10,
            structured: true,
            log_requests: true,
            mask_sensitive_data: true,
            include_location: false,
            enable_tracing: true,
        }
    }

    /// Create development logging configuration
    #[must_use]
    pub fn development() -> Self {
        Self {
            level: "debug".to_string(),
            format: LogFormat::Pretty,
            log_to_file: false,
            file_path: None,
            max_file_size_mb: 50,
            max_files: 5,
            structured: false,
            log_requests: true,
            mask_sensitive_data: false,
            include_location: true,
            enable_tracing: false,
        }
    }

    /// Create testing logging configuration
    #[must_use]
    pub fn testing() -> Self {
        Self {
            level: "warn".to_string(),
            format: LogFormat::Compact,
            log_to_file: false,
            file_path: None,
            max_file_size_mb: 10,
            max_files: 2,
            structured: false,
            log_requests: false,
            mask_sensitive_data: true,
            include_location: false,
            enable_tracing: false,
        }
    }
}

/// Initialize logging based on configuration
pub fn initialize_logging(config: &LoggingConfig) -> Result<()> {
    // Parse log level
    let log_level = Level::from_str(&config.level)
        .map_err(|e| anyhow::anyhow!("Invalid log level '{}': {}", config.level, e))?;

    // Create environment filter
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("auth_service={log_level}"))
            .add_directive("tower_http=info".parse().unwrap())
            .add_directive("hyper=warn".parse().unwrap())
            .add_directive("reqwest=info".parse().unwrap())
    });

    // Create formatter based on configuration
    let registry = tracing_subscriber::registry().with(env_filter);

    match config.format {
        LogFormat::Json => {
            let layer = fmt::layer()
                .json()
                .with_span_events(if config.log_requests {
                    FmtSpan::NEW | FmtSpan::CLOSE
                } else {
                    FmtSpan::NONE
                })
                .with_current_span(config.include_location)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true);

            if config.log_to_file && config.file_path.is_some() {
                // File logging with rotation
                let file_appender = tracing_appender::rolling::daily(
                    std::path::Path::new(config.file_path.as_ref().unwrap())
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new(".")),
                    "auth-service.log",
                );
                let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

                registry.with(layer.with_writer(file_writer)).init();
            } else {
                registry.with(layer).init();
            }
        }
        LogFormat::Compact => {
            let layer = fmt::layer()
                .compact()
                .with_span_events(if config.log_requests {
                    FmtSpan::NEW | FmtSpan::CLOSE
                } else {
                    FmtSpan::NONE
                })
                .with_target(config.include_location);

            registry.with(layer).init();
        }
        LogFormat::Pretty => {
            let layer = fmt::layer()
                .pretty()
                .with_span_events(if config.log_requests {
                    FmtSpan::NEW | FmtSpan::CLOSE
                } else {
                    FmtSpan::NONE
                })
                .with_target(config.include_location)
                .with_file(config.include_location)
                .with_line_number(config.include_location);

            registry.with(layer).init();
        }
    }

    info!(
        level = %config.level,
        format = ?config.format,
        log_to_file = config.log_to_file,
        "Logging initialized"
    );

    Ok(())
}

/// Sensitive data masking utilities
pub mod masking {
    use regex::Regex;
    use std::collections::HashMap;

    lazy_static::lazy_static! {
        static ref SENSITIVE_PATTERNS: HashMap<&'static str, Regex> = {
            let mut patterns = HashMap::new();

            // Common sensitive patterns
            patterns.insert("password", Regex::new(r#""password":\s*"[^"]*""#).unwrap());
            patterns.insert("secret", Regex::new(r#""secret":\s*"[^"]*""#).unwrap());
            patterns.insert("token", Regex::new(r#""token":\s*"[^"]*""#).unwrap());
            patterns.insert("authorization", Regex::new(r#""authorization":\s*"[^"]*""#).unwrap());
            patterns.insert("api_key", Regex::new(r#""api_key":\s*"[^"]*""#).unwrap());
            patterns.insert("client_secret", Regex::new(r#""client_secret":\s*"[^"]*""#).unwrap());

            // Credit card patterns
            patterns.insert("credit_card", Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap());

            // SSN patterns
            patterns.insert("ssn", Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

            // Email addresses (partial masking)
            patterns.insert("email", Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap());

            patterns
        };
    }

    /// Mask sensitive data in a log message
    #[must_use]
    pub fn mask_sensitive_data(input: &str) -> String {
        let mut result = input.to_string();

        for (name, pattern) in SENSITIVE_PATTERNS.iter() {
            result = match *name {
                "email" => {
                    // Partially mask emails: u***@example.com
                    pattern
                        .replace_all(&result, |caps: &regex::Captures| {
                            let email = caps.get(0).unwrap().as_str();
                            if let Some(at_pos) = email.find('@') {
                                let username = &email[..at_pos];
                                let domain = &email[at_pos..];
                                if username.len() > 1 {
                                    format!("{}***{}", &username[..1], domain)
                                } else {
                                    format!("***{domain}")
                                }
                            } else {
                                "***@***.***".to_string()
                            }
                        })
                        .to_string()
                }
                "credit_card" => {
                    // Mask credit card: ****-****-****-1234
                    pattern
                        .replace_all(&result, |caps: &regex::Captures| {
                            let card = caps.get(0).unwrap().as_str();
                            if card.len() >= 4 {
                                format!("****-****-****-{}", &card[card.len() - 4..])
                            } else {
                                "****-****-****-****".to_string()
                            }
                        })
                        .to_string()
                }
                "ssn" => {
                    // Mask SSN: ***-**-1234
                    pattern
                        .replace_all(&result, |caps: &regex::Captures| {
                            let ssn = caps.get(0).unwrap().as_str();
                            if ssn.len() >= 4 {
                                format!("***-**-{}", &ssn[ssn.len() - 4..])
                            } else {
                                "***-**-****".to_string()
                            }
                        })
                        .to_string()
                }
                _ => {
                    // Complete masking for other sensitive fields
                    pattern
                        .replace_all(&result, |caps: &regex::Captures| {
                            let full_match = caps.get(0).unwrap().as_str();
                            if let Some(colon_pos) = full_match.find(':') {
                                format!("{}:\"[REDACTED]\"", &full_match[..colon_pos])
                            } else {
                                "[REDACTED]".to_string()
                            }
                        })
                        .to_string()
                }
            };
        }

        result
    }
}

/// Request/Response logging middleware configuration
#[derive(Debug, Clone)]
pub struct RequestLoggingConfig {
    /// Log request headers
    pub log_headers: bool,
    /// Log request body (be careful with sensitive data)
    pub log_request_body: bool,
    /// Log response body
    pub log_response_body: bool,
    /// Maximum body size to log (in bytes)
    pub max_body_size: usize,
    /// Paths to exclude from logging
    pub exclude_paths: Vec<String>,
    /// Headers to exclude from logging
    pub exclude_headers: Vec<String>,
}

impl Default for RequestLoggingConfig {
    fn default() -> Self {
        Self {
            log_headers: true,
            log_request_body: false, // Disabled by default for security
            log_response_body: false,
            max_body_size: 1024,
            exclude_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/ready".to_string(),
                "/live".to_string(),
            ],
            exclude_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "set-cookie".to_string(),
                "x-api-key".to_string(),
                "x-auth-token".to_string(),
            ],
        }
    }
}

impl RequestLoggingConfig {
    /// Create production-safe request logging configuration
    #[must_use]
    pub fn production() -> Self {
        Self {
            log_headers: false, // Disabled in production for security
            log_request_body: false,
            log_response_body: false,
            max_body_size: 512,
            exclude_paths: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/ready".to_string(),
                "/live".to_string(),
                "/favicon.ico".to_string(),
            ],
            exclude_headers: vec![
                "authorization".to_string(),
                "cookie".to_string(),
                "set-cookie".to_string(),
                "x-api-key".to_string(),
                "x-auth-token".to_string(),
                "x-forwarded-for".to_string(),
                "x-real-ip".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_config_defaults() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert!(matches!(config.format, LogFormat::Json));
        assert!(config.mask_sensitive_data);
    }

    #[test]
    fn test_production_config() {
        let config = LoggingConfig::production();
        assert_eq!(config.level, "info");
        assert!(matches!(config.format, LogFormat::Json));
        assert!(config.log_to_file);
        assert!(config.mask_sensitive_data);
        assert!(!config.include_location); // No source location in production
    }

    #[test]
    fn test_development_config() {
        let config = LoggingConfig::development();
        assert_eq!(config.level, "debug");
        assert!(matches!(config.format, LogFormat::Pretty));
        assert!(!config.log_to_file);
        assert!(!config.mask_sensitive_data); // Allow sensitive data in dev
        assert!(config.include_location);
    }

    #[test]
    fn test_sensitive_data_masking() {
        let input = r#"{"password":"secret123","email":"user@example.com","credit_card":"1234-5678-9012-3456"}"#;
        let masked = masking::mask_sensitive_data(input);

        assert!(!masked.contains("secret123"));
        assert!(masked.contains("[REDACTED]"));
        assert!(masked.contains("u***@example.com"));
        assert!(masked.contains("****-****-****-3456"));
    }

    #[test]
    fn test_request_logging_config() {
        let config = RequestLoggingConfig::production();
        assert!(!config.log_headers); // Disabled in production
        assert!(!config.log_request_body);
        assert!(config
            .exclude_headers
            .contains(&"authorization".to_string()));
        assert!(config.exclude_paths.contains(&"/health".to_string()));
    }
}
