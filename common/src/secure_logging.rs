//! Secure logging utilities with secret protection
//!
//! This module provides logging utilities that automatically sanitize
//! sensitive information and prevent secret leakage in logs.

use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashSet;
use tracing::{info, warn};

/// Patterns that indicate potentially sensitive information
static SECRET_PATTERNS: Lazy<Vec<regex::Regex>> = Lazy::new(|| {
    let patterns = vec![
        // Common secret field names
        r"(?i)(password|passwd|pwd)[\s]*[:=][\s]*[^\s,}]+",
        r"(?i)(secret|token|key)[\s]*[:=][\s]*[^\s,}]+",
        r"(?i)(api_key|apikey)[\s]*[:=][\s]*[^\s,}]+",
        r"(?i)(private_key|private-key)[\s]*[:=][\s]*[^\s,}]+",
        r"(?i)(jwt_secret|jwt-secret)[\s]*[:=][\s]*[^\s,}]+",
        r"(?i)(oauth_secret|oauth-secret)[\s]*[:=][\s]*[^\s,}]+",
        r"(?i)(client_secret|client-secret)[\s]*[:=][\s]*[^\s,}]+",
        // Common patterns for secrets
        r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", // JWT tokens
        r"sk_[a-zA-Z0-9]{32,}",                                        // API keys starting with sk_
        r"[A-Za-z0-9]{32,}", // Long alphanumeric strings (potential secrets)
        // Database connection strings
        r"(?i)(postgresql|mysql|redis)://[^@]+:[^@]+@", // Connection strings with credentials
        // Environment variable patterns
        r"(?i)[A-Z_]+_SECRET[A-Z_]*[\s]*=[\s]*[^\s]+",
        r"(?i)[A-Z_]+_KEY[A-Z_]*[\s]*=[\s]*[^\s]+",
        r"(?i)[A-Z_]+_TOKEN[A-Z_]*[\s]*=[\s]*[^\s]+",
    ];

    patterns
        .into_iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
});

/// Fields that should always be redacted in logs
static SENSITIVE_FIELD_NAMES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "key",
        "api_key",
        "apikey",
        "api-key",
        "private_key",
        "private-key",
        "jwt_secret",
        "jwt-secret",
        "oauth_secret",
        "oauth-secret",
        "client_secret",
        "client-secret",
        "refresh_token",
        "refresh-token",
        "access_token",
        "access-token",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "session_id",
        "session-id",
    ]
    .into_iter()
    .collect()
});

/// Sanitize a string by redacting potentially sensitive information
///
/// # Panics
/// Panics if a regex capture group is expected but not found (this should not happen with valid patterns)
pub fn sanitize_for_logging(input: &str) -> String {
    let mut sanitized = input.to_string();

    // Apply regex-based sanitization
    for pattern in SECRET_PATTERNS.iter() {
        sanitized = pattern
            .replace_all(&sanitized, |caps: &regex::Captures<'_>| {
                let full_match = caps.get(0).unwrap().as_str();

                // Find the value part (after = or :)
                full_match.find([':', '=']).map_or_else(
                    || "[REDACTED]".to_string(),
                    |pos| {
                        let key_part = &full_match[..=pos];
                        format!("{key_part}[REDACTED]")
                    },
                )
            })
            .to_string();
    }

    // Additional sanitization for common patterns
    sanitized = sanitize_bearer_tokens(&sanitized);
    sanitized = sanitize_connection_strings(&sanitized);
    sanitized = sanitize_json_fields(&sanitized);

    sanitized
}

/// Sanitize Bearer tokens in Authorization headers
fn sanitize_bearer_tokens(input: &str) -> String {
    let bearer_regex = regex::Regex::new(r"(?i)bearer\s+[^\s]+").unwrap();
    bearer_regex
        .replace_all(input, "Bearer [REDACTED]")
        .to_string()
}

/// Sanitize connection strings with credentials
fn sanitize_connection_strings(input: &str) -> String {
    let conn_regex = regex::Regex::new(r"(?i)(postgresql|mysql|redis)://([^:]+):([^@]+)@").unwrap();
    conn_regex
        .replace_all(input, "$1://[REDACTED]:[REDACTED]@")
        .to_string()
}

/// Sanitize JSON-like fields
fn sanitize_json_fields(input: &str) -> String {
    let json_regex =
        regex::Regex::new(r#""([^"]*(?:password|secret|token|key)[^"]*)"\s*:\s*"([^"]*)""#)
            .unwrap();
    json_regex
        .replace_all(input, r#""$1":"[REDACTED]""#)
        .to_string()
}

/// Secure logging macros that automatically sanitize input
#[macro_export]
macro_rules! secure_info {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let sanitized = $crate::secure_logging::sanitize_for_logging(&message);
        tracing::info!("{}", sanitized);
    };
}

#[macro_export]
macro_rules! secure_warn {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let sanitized = $crate::secure_logging::sanitize_for_logging(&message);
        tracing::warn!("{}", sanitized);
    };
}

#[macro_export]
macro_rules! secure_error {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let sanitized = $crate::secure_logging::sanitize_for_logging(&message);
        tracing::error!("{}", sanitized);
    };
}

#[macro_export]
macro_rules! secure_debug {
    ($($arg:tt)*) => {
        let message = format!($($arg)*);
        let sanitized = $crate::secure_logging::sanitize_for_logging(&message);
        tracing::debug!("{}", sanitized);
    };
}

/// Trait for types that can be safely logged
pub trait SafeForLogging {
    fn safe_to_log(&self) -> String;
}

/// Implement `SafeForLogging` for common types
impl SafeForLogging for String {
    fn safe_to_log(&self) -> String {
        sanitize_for_logging(self)
    }
}

impl SafeForLogging for &str {
    fn safe_to_log(&self) -> String {
        sanitize_for_logging(self)
    }
}

/// A wrapper type that ensures values are sanitized when logged
#[derive(Debug, Clone)]
pub struct SanitizedValue<T: std::fmt::Display> {
    inner: T,
}

impl<T: std::fmt::Display> SanitizedValue<T> {
    pub const fn new(value: T) -> Self {
        Self { inner: value }
    }
}

impl<T: std::fmt::Display> std::fmt::Display for SanitizedValue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sanitized = sanitize_for_logging(&self.inner.to_string());
        write!(f, "{sanitized}")
    }
}

/// Secure structured logging for request/response data
#[derive(Debug, Serialize)]
pub struct SecureRequestLog {
    pub method: String,
    pub path: String,
    pub user_id: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub status_code: u16,
    pub duration_ms: u64,
    pub error: Option<String>,
}

impl SecureRequestLog {
    pub fn log(&self) {
        // Ensure all fields are sanitized before logging
        let sanitized_path = sanitize_for_logging(&self.path);
        let sanitized_user_agent = self.user_agent.as_ref().map(|ua| sanitize_for_logging(ua));
        let sanitized_error = self.error.as_ref().map(|e| sanitize_for_logging(e));

        info!(
            method = %self.method,
            path = %sanitized_path,
            user_id = ?self.user_id,
            ip_address = %self.ip_address,
            user_agent = ?sanitized_user_agent,
            status_code = self.status_code,
            duration_ms = self.duration_ms,
            error = ?sanitized_error,
            "HTTP request processed"
        );
    }
}

/// Audit logging with automatic sanitization
pub struct AuditLogger;

impl AuditLogger {
    pub fn log_authentication_attempt(
        user_id: Option<&str>,
        ip_address: &str,
        success: bool,
        reason: Option<&str>,
    ) {
        let sanitized_reason = reason.map(sanitize_for_logging);

        info!(
            event_type = "authentication_attempt",
            user_id = ?user_id,
            ip_address = %ip_address,
            success = success,
            reason = ?sanitized_reason,
            "Authentication attempt logged"
        );
    }

    pub fn log_privilege_escalation(
        user_id: &str,
        from_role: &str,
        to_role: &str,
        granted_by: &str,
    ) {
        info!(
            event_type = "privilege_escalation",
            user_id = %user_id,
            from_role = %from_role,
            to_role = %to_role,
            granted_by = %granted_by,
            "Privilege escalation logged"
        );
    }

    pub fn log_sensitive_operation(
        operation: &str,
        user_id: &str,
        resource: &str,
        details: Option<&str>,
    ) {
        let sanitized_details = details.map(sanitize_for_logging);

        warn!(
            event_type = "sensitive_operation",
            operation = %operation,
            user_id = %user_id,
            resource = %resource,
            details = ?sanitized_details,
            "Sensitive operation performed"
        );
    }
}

/// Configuration for logging behavior
#[derive(Debug, Clone)]
pub struct SecureLoggingConfig {
    /// Whether to enable paranoid mode (extra sanitization)
    pub paranoid_mode: bool,
    /// Custom patterns to redact
    pub custom_redaction_patterns: Vec<String>,
    /// Whether to log to external systems (requires extra care)
    pub external_logging: bool,
}

impl Default for SecureLoggingConfig {
    fn default() -> Self {
        Self {
            paranoid_mode: true, // Default to paranoid for security
            custom_redaction_patterns: Vec::new(),
            external_logging: false,
        }
    }
}

/// Validate that a string is safe to log (for development/testing)
///
/// # Errors
/// Returns a vector of validation violations if the input contains potentially sensitive information
/// that should not be logged, such as passwords, API keys, or other secrets
pub fn validate_safe_to_log(input: &str) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();

    // Check for common secret patterns
    for pattern in SECRET_PATTERNS.iter() {
        if pattern.is_match(input) {
            violations.push(format!("Matches secret pattern: {}", pattern.as_str()));
        }
    }

    // Check for sensitive field names
    for field_name in SENSITIVE_FIELD_NAMES.iter() {
        if input.to_lowercase().contains(field_name) {
            violations.push(format!("Contains sensitive field name: {field_name}"));
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_redaction() {
        let input = "user logged in with password=secretpass123";
        let sanitized = sanitize_for_logging(input);
        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("secretpass123"));
    }

    #[test]
    fn test_jwt_token_redaction() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let sanitized = sanitize_for_logging(input);
        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("eyJhbGciOiJIUzI1NiI"));
    }

    #[test]
    fn test_api_key_redaction() {
        let input = "using api_key=sk_1234567890abcdef1234567890abcdef for request";
        let sanitized = sanitize_for_logging(input);
        assert!(sanitized.contains("[REDACTED]"));
        assert!(!sanitized.contains("sk_1234567890"));
    }

    #[test]
    fn test_connection_string_redaction() {
        let input = "connecting to postgresql://user:password@localhost:5432/db";
        let sanitized = sanitize_for_logging(input);
        assert!(sanitized.contains("postgresql://[REDACTED]:[REDACTED]@"));
        assert!(!sanitized.contains("user:password"));
    }

    #[test]
    fn test_json_field_redaction() {
        let input = r#"{"username": "john", "password": "secret123", "email": "john@example.com"}"#;
        let sanitized = sanitize_for_logging(input);
        assert!(sanitized.contains(r#""password":"[REDACTED]""#));
        assert!(!sanitized.contains("secret123"));
        assert!(sanitized.contains("john@example.com")); // Non-sensitive data preserved
    }

    #[test]
    fn test_safe_logging_validation() {
        assert!(validate_safe_to_log("User logged in successfully").is_ok());
        assert!(validate_safe_to_log("Request processed in 150ms").is_ok());

        assert!(validate_safe_to_log("password=secret").is_err());
        assert!(validate_safe_to_log("api_key=abc123").is_err());
    }

    #[test]
    fn test_sanitized_value_wrapper() {
        let secret = "password=secret123";
        let sanitized = SanitizedValue::new(secret);
        let output = format!("{}", sanitized);

        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("secret123"));
    }

    #[test]
    fn test_audit_logging_sanitization() {
        // This test verifies that audit logging doesn't leak secrets
        let user_details = "user logged in with token=secret123";

        // In real code, this would go through our sanitization
        let sanitized = sanitize_for_logging(user_details);
        assert!(!sanitized.contains("secret123"));

        // The audit log should be clean
        AuditLogger::log_authentication_attempt(
            Some("user123"),
            "192.168.1.1",
            true,
            Some(&sanitized),
        );
    }
}
