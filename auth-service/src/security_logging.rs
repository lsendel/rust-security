//! Security Logging Module - MVP Version
//!
//! Simple security event logging for basic authentication monitoring.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

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
            tracing::info!(
                event_type = ?event.event_type,
                severity = ?event.severity,
                source = event.source,
                description = event.description,
                ip_address = event.ip_address,
                user_id = event.user_id,
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
