use crate::pii_protection::{redact_log, DataClassification, PiiSpiRedactor};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Warning,
}

/// Security event types for categorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    AuthenticationAttempt,
    AuthenticationFailure,
    AuthenticationSuccess,
    TokenIssued,
    TokenRevoked,
    TokenBindingViolation,
    InputValidationFailure,
    RateLimitExceeded,
    RequestSignatureFailure,
    Authentication,
    Authorization,
    RateLimitViolation,
    SuspiciousActivity,
    MfaAttempt,
    MfaFailure,
    ConfigurationChange,
    SystemError,
    AccessDenied,
    PrivilegeEscalation,
    DataAccess,
    AdminAction,
    AdminAccess,
    UnauthorizedAccess,
    SessionEvent,
    SecurityViolation,
    KeyManagement,
}

/// Structured security event for audit logging with comprehensive fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier
    pub event_id: String,

    /// Event timestamp in UTC
    pub timestamp: DateTime<Utc>,

    /// Event type for categorization
    pub event_type: SecurityEventType,

    /// Severity level
    pub severity: SecuritySeverity,

    /// Source service or component
    pub source: String,

    /// Actor who initiated the action (user, client, system)
    pub actor: Option<String>,

    /// Action performed (create, read, update, delete, authenticate, etc.)
    pub action: Option<String>,

    /// Target resource or object affected
    pub target: Option<String>,

    /// Outcome of the event (success, failure, blocked, etc.)
    pub outcome: String,

    /// Reason for the outcome (error message, policy violation, etc.)
    pub reason: Option<String>,

    /// Correlation ID for tracing across services
    pub correlation_id: Option<String>,

    /// Client IP address (potentially redacted)
    pub ip_address: Option<String>,

    /// User agent string (potentially redacted)
    pub user_agent: Option<String>,

    /// Client identifier (if applicable)
    pub client_id: Option<String>,

    /// User identifier (if applicable) - always redacted in logs
    pub user_id: Option<String>,

    /// Request ID for correlation
    pub request_id: Option<String>,

    /// Session ID for correlation
    pub session_id: Option<String>,

    /// Event description
    pub description: String,

    /// Additional event details (PII-safe)
    pub details: HashMap<String, Value>,

    /// Resource accessed or affected (legacy field, use target instead)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    /// Risk score (0-100)
    pub risk_score: Option<u8>,

    /// Geographic location (if available)
    pub location: Option<String>,

    /// Device fingerprint
    pub device_fingerprint: Option<String>,

    /// HTTP method (for web requests)
    pub http_method: Option<String>,

    /// HTTP status code (for web responses)
    pub http_status: Option<u16>,

    /// Request path (potentially redacted)
    pub request_path: Option<String>,

    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        source: String,
        description: String,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity,
            source,
            actor: None,
            action: None,
            target: None,
            outcome: "unknown".to_string(),
            reason: None,
            correlation_id: None,
            ip_address: None,
            user_agent: None,
            client_id: None,
            user_id: None,
            request_id: None,
            session_id: None,
            description,
            details: HashMap::new(),
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

    /// Builder pattern methods for setting optional fields
    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_outcome(mut self, outcome: String) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn with_action(mut self, action: String) -> Self {
        self.action = Some(action);
        self
    }

    pub fn with_risk_score(mut self, risk_score: u8) -> Self {
        self.risk_score = Some(risk_score.min(100));
        self
    }

    pub fn with_detail<T: Serialize>(mut self, key: String, value: T) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.details.insert(key, json_value);
        }
        self
    }

    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    pub fn with_device_fingerprint(mut self, fingerprint: String) -> Self {
        self.device_fingerprint = Some(fingerprint);
        self
    }

    /// Set the actor (who initiated the action)
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(PiiRedactor::redact_actor(&actor));
        self
    }

    /// Set the target (resource or object affected)
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the reason for the outcome
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(PiiRedactor::redact_reason(&reason));
        self
    }

    /// Set the correlation ID for tracing
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set HTTP method
    pub fn with_http_method(mut self, method: String) -> Self {
        self.http_method = Some(method);
        self
    }

    /// Set HTTP status code
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    /// Set request path with PII redaction
    pub fn with_request_path(mut self, path: String) -> Self {
        self.request_path = Some(PiiRedactor::redact_path(&path));
        self
    }

    /// Set response time in milliseconds
    pub fn with_response_time_ms(mut self, time_ms: u64) -> Self {
        self.response_time_ms = Some(time_ms);
        self
    }

    /// Override user_id with PII redaction
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(PiiRedactor::redact_user_id(&user_id));
        self
    }

    /// Override ip_address with optional PII redaction
    pub fn with_ip_address(mut self, ip_address: String) -> Self {
        self.ip_address = Some(PiiRedactor::redact_ip_address(&ip_address));
        self
    }

    /// Override user_agent with PII redaction
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(PiiRedactor::redact_user_agent(&user_agent));
        self
    }

    /// Apply comprehensive PII/SPI protection to the entire event
    pub fn apply_pii_protection(&mut self) {
        let redactor = PiiSpiRedactor::new();

        // Protect description field
        self.description = redactor.redact_log_message(&self.description);

        // Protect reason field if present
        if let Some(ref reason) = self.reason {
            self.reason = Some(redactor.redact_log_message(reason));
        }

        // Protect request path if present
        if let Some(ref path) = self.request_path {
            self.request_path = Some(PiiRedactor::redact_path(path));
        }

        // Protect details map values
        for (key, value) in self.details.iter_mut() {
            if let Value::String(ref s) = value {
                let redacted = redactor.redact_log_message(s);
                *value = Value::String(redacted);
            }
        }

        // Additional protection for location data if present
        if let Some(ref location) = self.location {
            // Redact precise location data but keep general region
            self.location = Some(redactor.redact_text(location, DataClassification::Internal));
        }
    }
}

/// PII redaction utility for security logging
pub struct PiiRedactor;

impl PiiRedactor {
    /// Redact user ID to prevent PII leakage (show only first/last chars)
    pub fn redact_user_id(user_id: &str) -> String {
        if user_id.len() <= 4 {
            return "*".repeat(user_id.len());
        }

        let first = &user_id[0..2];
        let last = &user_id[user_id.len() - 2..];
        let middle = "*".repeat(4); // Fixed length for consistency
        format!("{}{}{}", first, middle, last)
    }

    /// Redact IP address (keep first 3 octets for IPv4, first 4 groups for IPv6)
    pub fn redact_ip_address(ip: &str) -> String {
        if ip.contains(':') {
            // IPv6 - keep first 4 groups
            let parts: Vec<&str> = ip.split(':').collect();
            if parts.len() >= 4 {
                format!("{}:{}:{}:{}::***", parts[0], parts[1], parts[2], parts[3])
            } else {
                "***".to_string()
            }
        } else if ip.contains('.') {
            // IPv4 - keep first 3 octets
            let parts: Vec<&str> = ip.split('.').collect();
            if parts.len() == 4 {
                format!("{}.{}.{}.***", parts[0], parts[1], parts[2])
            } else {
                "***".to_string()
            }
        } else {
            "***".to_string()
        }
    }

    /// Redact sensitive parts of user agent
    pub fn redact_user_agent(user_agent: &str) -> String {
        // Remove potential email addresses and phone numbers
        let email_pattern =
            regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        let phone_pattern = regex::Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();

        let redacted = email_pattern.replace_all(user_agent, "[EMAIL_REDACTED]");
        let redacted = phone_pattern.replace_all(&redacted, "[PHONE_REDACTED]");

        // Truncate if too long
        if redacted.len() > 200 {
            format!("{}...[TRUNCATED]", &redacted[0..197])
        } else {
            redacted.to_string()
        }
    }

    /// Redact sensitive information from request paths
    pub fn redact_path(path: &str) -> String {
        // Common patterns that might contain sensitive info
        let patterns = [
            (
                regex::Regex::new(r"/users/[^/]+").unwrap(),
                "/users/[USER_ID]",
            ),
            (
                regex::Regex::new(r"[?&]token=[^&]*").unwrap(),
                "&token=[REDACTED]",
            ),
            (
                regex::Regex::new(r"[?&]secret=[^&]*").unwrap(),
                "&secret=[REDACTED]",
            ),
            (
                regex::Regex::new(r"[?&]password=[^&]*").unwrap(),
                "&password=[REDACTED]",
            ),
            (
                regex::Regex::new(r"[?&]email=[^&]*").unwrap(),
                "&email=[REDACTED]",
            ),
        ];

        let mut redacted = path.to_string();
        for (pattern, replacement) in &patterns {
            redacted = pattern.replace_all(&redacted, *replacement).to_string();
        }

        redacted
    }

    /// Redact sensitive information from actor field
    pub fn redact_actor(actor: &str) -> String {
        // Check if it looks like an email and redact
        if actor.contains('@') && actor.contains('.') {
            let parts: Vec<&str> = actor.split('@').collect();
            if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                let username = if parts[0].len() <= 2 {
                    "*".repeat(parts[0].len())
                } else {
                    format!("{}*", &parts[0][0..1])
                };
                return format!("{}@{}", username, parts[1]);
            }
        }

        // For non-email actors, limit length but don't redact
        if actor.len() > 50 {
            format!("{}...[TRUNCATED]", &actor[0..47])
        } else {
            actor.to_string()
        }
    }

    /// Redact sensitive information from reason field
    pub fn redact_reason(reason: &str) -> String {
        // Remove tokens, secrets, and other sensitive data from error messages
        let patterns = [
            (
                regex::Regex::new(r"token:\s*[A-Za-z0-9._-]+").unwrap(),
                "token: [REDACTED]",
            ),
            (
                regex::Regex::new(r"secret:\s*[A-Za-z0-9._-]+").unwrap(),
                "secret: [REDACTED]",
            ),
            (
                regex::Regex::new(r"password:\s*[^\s]+").unwrap(),
                "password: [REDACTED]",
            ),
            (
                regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap(),
                "[EMAIL_REDACTED]",
            ),
        ];

        let mut redacted = reason.to_string();
        for (pattern, replacement) in &patterns {
            redacted = pattern.replace_all(&redacted, *replacement).to_string();
        }

        redacted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_redaction_user_id() {
        assert_eq!(PiiRedactor::redact_user_id("u123"), "****");
        assert_eq!(PiiRedactor::redact_user_id("user123456"), "us****56");
        assert_eq!(PiiRedactor::redact_user_id("a"), "*");
        assert_eq!(PiiRedactor::redact_user_id("ab"), "**");
    }

    #[test]
    fn test_pii_redaction_ip_address() {
        assert_eq!(
            PiiRedactor::redact_ip_address("192.168.1.100"),
            "192.168.1.***"
        );
        assert_eq!(
            PiiRedactor::redact_ip_address("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
            "2001:db8:85a3:8d3::***"
        );
        assert_eq!(PiiRedactor::redact_ip_address("invalid"), "***");
    }

    #[test]
    fn test_pii_redaction_email() {
        assert_eq!(
            PiiRedactor::redact_actor("user@example.com"),
            "u*@example.com"
        );
        assert_eq!(
            PiiRedactor::redact_actor("ab@example.com"),
            "**@example.com"
        );
        assert_eq!(PiiRedactor::redact_actor("system_user"), "system_user");

        let long_actor = "a".repeat(60);
        let redacted = PiiRedactor::redact_actor(&long_actor);
        // 47 chars + "..." + "[TRUNCATED]" = 47 + 3 + 11 = 61 characters
        assert_eq!(redacted.len(), 61);
        assert!(redacted.contains("[TRUNCATED]"));
        assert!(redacted.starts_with(&"a".repeat(47)));
        assert!(redacted.ends_with("...[TRUNCATED]"));
    }

    #[test]
    fn test_pii_redaction_user_agent() {
        let ua_with_email = "Mozilla/5.0 user@example.com Chrome";
        let redacted = PiiRedactor::redact_user_agent(ua_with_email);
        assert!(redacted.contains("[EMAIL_REDACTED]"));
        assert!(!redacted.contains("user@example.com"));

        let ua_with_phone = "Mozilla/5.0 555-123-4567 Chrome";
        let redacted = PiiRedactor::redact_user_agent(ua_with_phone);
        assert!(redacted.contains("[PHONE_REDACTED]"));
        assert!(!redacted.contains("555-123-4567"));
    }

    #[test]
    fn test_pii_redaction_path() {
        assert_eq!(
            PiiRedactor::redact_path("/users/12345/profile"),
            "/users/[USER_ID]/profile"
        );
        assert_eq!(
            PiiRedactor::redact_path("/api?token=secret123"),
            "/api&token=[REDACTED]"
        );
        assert_eq!(
            PiiRedactor::redact_path("/login?password=mypass"),
            "/login&password=[REDACTED]"
        );
    }

    #[test]
    fn test_pii_redaction_reason() {
        let reason = "Authentication failed for token: abc123 with secret: xyz789";
        let redacted = PiiRedactor::redact_reason(reason);
        assert!(redacted.contains("token: [REDACTED]"));
        assert!(redacted.contains("secret: [REDACTED]"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("xyz789"));
    }

    #[test]
    fn test_security_event_builder() {
        let event = SecurityEvent::new(
            SecurityEventType::AuthenticationAttempt,
            SecuritySeverity::Medium,
            "auth-service".to_string(),
            "User login attempt".to_string(),
        )
        .with_actor("user@example.com".to_string())
        .with_action("authenticate".to_string())
        .with_target("/api/login".to_string())
        .with_outcome("success".to_string())
        .with_reason("Valid credentials provided".to_string())
        .with_correlation_id("req-123".to_string())
        .with_ip_address("192.168.1.100".to_string())
        .with_user_agent("Mozilla/5.0".to_string())
        .with_http_method("POST".to_string())
        .with_http_status(200)
        .with_response_time_ms(150);

        assert_eq!(event.event_type, SecurityEventType::AuthenticationAttempt);
        assert_eq!(event.severity, SecuritySeverity::Medium);
        assert_eq!(event.source, "auth-service");
        assert!(event.actor.is_some());
        assert_eq!(event.action, Some("authenticate".to_string()));
        assert_eq!(event.target, Some("/api/login".to_string()));
        assert_eq!(event.outcome, "success");
        assert!(event.reason.is_some());
        assert_eq!(event.correlation_id, Some("req-123".to_string()));
        assert_eq!(event.ip_address, Some("192.168.1.***".to_string())); // Redacted
        assert_eq!(event.http_method, Some("POST".to_string()));
        assert_eq!(event.http_status, Some(200));
        assert_eq!(event.response_time_ms, Some(150));
    }
}

/// Security logger for structured audit logging
pub struct SecurityLogger;

impl SecurityLogger {
    /// Create a new security logger instance
    pub fn new() -> Self {
        Self
    }

    /// Log a security event with appropriate level and PII protection
    pub fn log_event(event: &SecurityEvent) {
        // Clone and apply PII redaction to avoid mutating caller state
        let mut event = event.clone();
        event.apply_pii_protection();

        let event_json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize security event: {}", e);
                return;
            }
        };

        // Additional protection for the JSON string itself
        let protected_json = redact_log(&event_json);

        match event.severity {
            SecuritySeverity::Critical => {
                error!(
                    target: "security_audit",
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    client_id = ?event.client_id,
                    ip_address = ?event.ip_address,
                    "SECURITY_EVENT: {}",
                    protected_json
                );
            }
            SecuritySeverity::High => {
                error!(
                    target: "security_audit",
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    client_id = ?event.client_id,
                    ip_address = ?event.ip_address,
                    "SECURITY_EVENT: {}",
                    protected_json
                );
            }
            SecuritySeverity::Medium => {
                warn!(
                    target: "security_audit",
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    client_id = ?event.client_id,
                    ip_address = ?event.ip_address,
                    "SECURITY_EVENT: {}",
                    protected_json
                );
            }
            SecuritySeverity::Low => {
                info!(
                    target: "security_audit",
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    client_id = ?event.client_id,
                    ip_address = ?event.ip_address,
                    "SECURITY_EVENT: {}",
                    protected_json
                );
            }
            SecuritySeverity::Info => {
                info!(
                    target: "security_audit",
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    client_id = ?event.client_id,
                    ip_address = ?event.ip_address,
                    "SECURITY_EVENT: {}",
                    protected_json
                );
            }
            SecuritySeverity::Warning => {
                warn!(
                    target: "security_audit",
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    severity = ?event.severity,
                    client_id = ?event.client_id,
                    ip_address = ?event.ip_address,
                    "SECURITY_EVENT: {}",
                    protected_json
                );
            }
        }
    }

    /// Log authentication attempt
    pub fn log_auth_attempt(
        client_id: &str,
        ip_address: &str,
        user_agent: Option<&str>,
        outcome: &str,
        details: Option<HashMap<String, Value>>,
    ) {
        let mut event = SecurityEvent::new(
            SecurityEventType::AuthenticationAttempt,
            if outcome == "success" {
                SecuritySeverity::Low
            } else {
                SecuritySeverity::Medium
            },
            "auth-service".to_string(),
            format!("Authentication attempt by client {}", client_id),
        )
        .with_client_id(client_id.to_string())
        .with_ip_address(ip_address.to_string())
        .with_outcome(outcome.to_string());

        if let Some(ua) = user_agent {
            event = event.with_user_agent(ua.to_string());
        }

        if let Some(details) = details {
            for (key, value) in details {
                event.details.insert(key, value);
            }
        }

        SecurityLogger::log_event(&event);
    }

    /// Log token operation
    pub fn log_token_operation(
        operation: &str,
        token_type: &str,
        client_id: &str,
        ip_address: &str,
        outcome: &str,
        details: Option<HashMap<String, Value>>,
    ) {
        let event_type = match operation {
            "issue" => SecurityEventType::TokenIssued,
            "revoke" => SecurityEventType::TokenRevoked,
            _ => SecurityEventType::SystemError,
        };

        let mut event = SecurityEvent::new(
            event_type,
            SecuritySeverity::Low,
            "auth-service".to_string(),
            format!("Token {} operation for {}", operation, token_type),
        )
        .with_client_id(client_id.to_string())
        .with_ip_address(ip_address.to_string())
        .with_outcome(outcome.to_string())
        .with_detail("token_type".to_string(), token_type)
        .with_detail("operation".to_string(), operation);

        if let Some(details) = details {
            for (key, value) in details {
                event.details.insert(key, value);
            }
        }

        SecurityLogger::log_event(&event);
    }

    /// Log security violation
    pub fn log_security_violation(
        violation_type: &str,
        client_id: Option<&str>,
        ip_address: &str,
        description: &str,
        risk_score: u8,
        details: Option<HashMap<String, Value>>,
    ) {
        let mut event = SecurityEvent::new(
            SecurityEventType::SuspiciousActivity,
            match risk_score {
                0..=25 => SecuritySeverity::Low,
                26..=50 => SecuritySeverity::Medium,
                51..=75 => SecuritySeverity::High,
                _ => SecuritySeverity::Critical, // 76-100 and any invalid values
            },
            "auth-service".to_string(),
            description.to_string(),
        )
        .with_ip_address(ip_address.to_string())
        .with_outcome("violation_detected".to_string())
        .with_risk_score(risk_score)
        .with_detail("violation_type".to_string(), violation_type);

        if let Some(client_id) = client_id {
            event = event.with_client_id(client_id.to_string());
        }

        if let Some(details) = details {
            for (key, value) in details {
                event.details.insert(key, value);
            }
        }

        SecurityLogger::log_event(&event);
    }

    /// Log input validation failure
    pub fn log_validation_failure(
        endpoint: &str,
        validation_type: &str,
        client_id: Option<&str>,
        ip_address: &str,
        details: Option<HashMap<String, Value>>,
    ) {
        let mut event = SecurityEvent::new(
            SecurityEventType::InputValidationFailure,
            SecuritySeverity::Medium,
            "auth-service".to_string(),
            format!("Input validation failure at {}", endpoint),
        )
        .with_ip_address(ip_address.to_string())
        .with_outcome("validation_failed".to_string())
        .with_resource(endpoint.to_string())
        .with_detail("validation_type".to_string(), validation_type);

        if let Some(client_id) = client_id {
            event = event.with_client_id(client_id.to_string());
        }

        if let Some(details) = details {
            for (key, value) in details {
                event.details.insert(key, value);
            }
        }

        SecurityLogger::log_event(&event);
    }

    /// Log rate limit exceeded
    pub fn log_rate_limit_exceeded(
        client_id: &str,
        ip_address: &str,
        endpoint: &str,
        current_rate: u32,
        limit: u32,
    ) {
        let event = SecurityEvent::new(
            SecurityEventType::RateLimitExceeded,
            SecuritySeverity::Medium,
            "auth-service".to_string(),
            format!(
                "Rate limit exceeded for client {} at {}",
                client_id, endpoint
            ),
        )
        .with_client_id(client_id.to_string())
        .with_ip_address(ip_address.to_string())
        .with_outcome("rate_limited".to_string())
        .with_resource(endpoint.to_string())
        .with_detail("current_rate".to_string(), current_rate)
        .with_detail("rate_limit".to_string(), limit);

        SecurityLogger::log_event(&event);
    }
}

/// Convenience macros for security logging
#[macro_export]
macro_rules! log_security_event {
    ($event:expr) => {
        $crate::security_logging::SecurityLogger::log_event(&$event);
    };
}

#[macro_export]
macro_rules! log_auth_attempt {
    ($client_id:expr, $ip:expr, $outcome:expr) => {
        $crate::security_logging::SecurityLogger::log_auth_attempt(
            $client_id, $ip, None, $outcome, None,
        );
    };
    ($client_id:expr, $ip:expr, $user_agent:expr, $outcome:expr) => {
        $crate::security_logging::SecurityLogger::log_auth_attempt(
            $client_id,
            $ip,
            Some($user_agent),
            $outcome,
            None,
        );
    };
}

#[macro_export]
macro_rules! log_security_violation {
    ($violation_type:expr, $client_id:expr, $ip:expr, $description:expr, $risk_score:expr) => {
        $crate::security_logging::SecurityLogger::log_security_violation(
            $violation_type,
            Some($client_id),
            $ip,
            $description,
            $risk_score,
            None,
        );
    };
}
