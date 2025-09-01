//! Security Logging Module - MVP Version
//!
//! Simple security event logging for basic authentication monitoring.
//!
//! # Security Considerations
//!
//! This module provides secure logging practices:
//! - Structured logging with tracing
//! - Sensitive data redaction
//! - PII protection
//! - Audit trail generation

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Security patterns for detecting sensitive data
static SENSITIVE_DATA_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"(?i)password|passwd|pwd").unwrap(),
        Regex::new(r"(?i)token|bearer|jwt").unwrap(),
        Regex::new(r"(?i)secret|key|apikey").unwrap(),
        Regex::new(r"(?i)ssn|social|credit").unwrap(),
        Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap(), // Credit card pattern
        Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap(),           // SSN pattern
    ]
});

/// Security guardrail for logging sensitive data
pub struct SecurityLoggingGuard;

impl SecurityLoggingGuard {
    /// Check if a string contains potentially sensitive data
    pub fn contains_sensitive_data(text: &str) -> bool {
        SENSITIVE_DATA_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(text))
    }

    /// Redact sensitive data from a string
    pub fn redact_sensitive_data(text: &str) -> String {
        let mut result = text.to_string();
        for pattern in SENSITIVE_DATA_PATTERNS.iter() {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }
        result
    }

    /// Validate that a log message is safe to log
    pub fn validate_log_safety(text: &str) -> Result<(), String> {
        if Self::contains_sensitive_data(text) {
            return Err(format!(
                "Log message contains potentially sensitive data: {}",
                Self::redact_sensitive_data(text)
            ));
        }
        Ok(())
    }
}

/// Basic security event severity levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
    Info,
    Warning,
}

/// Basic security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    AuthenticationAttempt,
    AuthenticationFailure,
    AuthenticationSuccess,
    TokenIssued,
    TokenRevoked,
    TokenOperation,
    RateLimitExceeded,
    AccessDenied,
    SystemEvent,
    SecurityViolation,
    Authentication,
    Authorization,
    RateLimitViolation,
    SuspiciousActivity,
    UnauthorizedAccess,
    AdminAction,
    AdminAccess,
    InputValidationFailure,
    ValidationFailure,
    RequestSignatureFailure,
    WorkflowTriggered,
    WorkflowCompleted,
    KeyManagement,
}

/// Simple security event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub source: String,
    pub description: String,
    pub ip_address: Option<String>,
    pub user_id: Option<String>,
    pub details: HashMap<String, Value>,
    pub metadata: HashMap<String, Value>,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub correlation_id: Option<String>,
    pub user_agent: Option<String>,
    pub client_id: Option<String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
    pub resource: Option<String>,
    pub risk_score: Option<u8>,
    pub location: Option<String>,
    pub device_fingerprint: Option<String>,
    pub http_method: Option<String>,
    pub http_status: Option<u16>,
    pub request_path: Option<String>,
    pub response_time_ms: Option<u64>,
}

impl SecurityEvent {
    #[must_use]
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        source: String,
        description: String,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity,
            source,
            description,
            ip_address: None,
            user_id: None,
            details: HashMap::new(),
            metadata: HashMap::new(),
            actor: None,
            action: None,
            target: None,
            outcome: "pending".to_string(),
            reason: None,
            correlation_id: None,
            user_agent: None,
            client_id: None,
            request_id: None,
            session_id: None,
            resource: None,
            risk_score: None,
            location: None,
            device_fingerprint: None,
            http_method: None,
            http_status: None,
            request_path: None,
            response_time_ms: None,
        }
    }

    #[must_use]
    pub fn with_ip(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    #[must_use]
    pub fn with_ip_address(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    #[must_use]
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    #[must_use]
    pub fn with_detail(mut self, key: String, value: Value) -> Self {
        self.details.insert(key, value);
        self
    }

    #[must_use]
    pub fn with_detail_string(mut self, key: String, value: String) -> Self {
        self.details.insert(key, Value::String(value));
        self
    }

    #[must_use]
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    #[must_use]
    pub fn with_action(mut self, action: String) -> Self {
        self.action = Some(action);
        self
    }

    #[must_use]
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    #[must_use]
    pub fn with_outcome(mut self, outcome: String) -> Self {
        self.outcome = outcome;
        self
    }

    #[must_use]
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    #[must_use]
    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    #[must_use]
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    #[must_use]
    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    #[must_use]
    pub const fn with_risk_score(mut self, risk_score: u8) -> Self {
        self.risk_score = Some(risk_score);
        self
    }

    #[must_use]
    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    #[must_use]
    pub fn with_device_fingerprint(mut self, device_fingerprint: String) -> Self {
        self.device_fingerprint = Some(device_fingerprint);
        self
    }

    #[must_use]
    pub fn with_http_method(mut self, http_method: String) -> Self {
        self.http_method = Some(http_method);
        self
    }

    #[must_use]
    pub const fn with_http_status(mut self, http_status: u16) -> Self {
        self.http_status = Some(http_status);
        self
    }

    #[must_use]
    pub fn with_request_path(mut self, request_path: String) -> Self {
        self.request_path = Some(request_path);
        self
    }

    #[must_use]
    pub const fn with_response_time_ms(mut self, response_time_ms: u64) -> Self {
        self.response_time_ms = Some(response_time_ms);
        self
    }

    /// Basic PII redaction for MVP
    fn redact_basic_pii(&self, text: &str) -> String {
        // Simple email redaction
        let email_regex =
            regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        let text = email_regex.replace_all(text, "[EMAIL_REDACTED]");

        // Simple phone number redaction
        let phone_regex =
            regex::Regex::new(r"\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s?\d{3}-\d{4}\b").unwrap();
        let text = phone_regex.replace_all(&text, "[PHONE_REDACTED]");

        text.to_string()
    }

    /// Apply basic PII protection
    pub fn apply_pii_protection(&mut self) {
        self.description = self.redact_basic_pii(&self.description);
    }
}

/// Simple security logger
#[derive(Debug, Clone)]
pub struct SecurityLogger {
    pub config: SecurityLoggerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityLoggerConfig {
    pub enabled: bool,
    pub max_events: usize,
}

impl Default for SecurityLoggerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_events: 10000,
        }
    }
}

impl SecurityLogger {
    #[must_use]
    pub const fn new(config: SecurityLoggerConfig) -> Self {
        Self { config }
    }

    pub fn log_event(&self, event: SecurityEvent) {
        if self.config.enabled {
            // Apply security guardrails before logging
            let safe_description = SecurityLoggingGuard::redact_sensitive_data(&event.description);
            let safe_source = SecurityLoggingGuard::redact_sensitive_data(&event.source);

            // Validate log safety in debug mode
            #[cfg(debug_assertions)]
            if let Err(e) = SecurityLoggingGuard::validate_log_safety(&safe_description) {
                tracing::warn!("Security logging guardrail triggered: {}", e);
            }

            tracing::info!(
                event_type = ?event.event_type,
                severity = ?event.severity,
                source = safe_source,
                description = safe_description,
                ip_address = event.ip_address,
                user_id = event.user_id,
                correlation_id = event.correlation_id,
                "Security event logged"
            );
        }
    }

    /// Static method for backwards compatibility
    pub fn log_event_static(event: &SecurityEvent) {
        let logger = Self::default();
        logger.log_event(event.clone());
    }
}

impl Default for SecurityLogger {
    fn default() -> Self {
        Self::new(SecurityLoggerConfig::default())
    }
}

/// Global function for logging security events (backwards compatibility)
pub fn log_event(event: &SecurityEvent) {
    SecurityLogger::log_event_static(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensitive_data_detection() {
        assert!(SecurityLoggingGuard::contains_sensitive_data(
            "User password is: secret123"
        ));
        assert!(SecurityLoggingGuard::contains_sensitive_data(
            "Token: Bearer abc123"
        ));
        assert!(SecurityLoggingGuard::contains_sensitive_data(
            "API Key: sk-123456"
        ));
        assert!(!SecurityLoggingGuard::contains_sensitive_data(
            "Normal log message"
        ));
    }

    #[test]
    fn test_sensitive_data_redaction() {
        let input = "User password is: secret123 and token is: Bearer abc123";
        let redacted = SecurityLoggingGuard::redact_sensitive_data(input);
        assert!(!redacted.contains("secret123"));
        assert!(!redacted.contains("Bearer"));
        assert!(redacted.contains("[REDACTED]"));
    }

    #[test]
    fn test_log_validation() {
        assert!(SecurityLoggingGuard::validate_log_safety("Normal message").is_ok());
        assert!(SecurityLoggingGuard::validate_log_safety("Password: secret123").is_err());
    }
}
