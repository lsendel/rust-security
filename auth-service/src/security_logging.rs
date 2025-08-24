//! Security Logging Module
//!
//! Re-exports from the enhanced security logging implementation.
//! This module provides a clean API for security event logging with:
//! - PII protection and redaction
//! - Threat intelligence integration
//! - Structured JSON logging
//! - SIEM forwarding capabilities
//! - Privacy-safe user identification using hashes
//! - Comprehensive security event types and severity levels

// Enhanced features from enhanced security logging
pub use crate::security_logging_enhanced::{
    SecuritySeverity,
    SecurityLoggerConfig,
    SecurityEventBuilder,
    SecurityEventStats,
    SecurityMetadata,
    ThreatIntelligence,
    IpReputation,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid;

/// Legacy Security event types for categorization
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LegacySecurityEventType {
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
    SystemEvent,
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

/// Legacy structured security event for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyLegacySecurityEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: LegacySecurityEventType,
    pub severity: SecuritySeverity,
    pub source: String,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub correlation_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
    pub description: String,
    pub details: HashMap<String, Value>,
    pub resource: Option<String>,
    pub risk_score: Option<u8>,
    pub location: Option<String>,
    pub device_fingerprint: Option<String>,
    pub http_method: Option<String>,
    pub http_status: Option<u16>,
    pub request_path: Option<String>,
    pub response_time_ms: Option<u64>,
}

impl LegacyLegacySecurityEvent {
    pub fn new(
        event_type: LegacySecurityEventType,
        severity: SecuritySeverity,
        source: String,
        description: String,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
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

    // Builder pattern methods
    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn with_action(mut self, action: String) -> Self {
        self.action = Some(action);
        self
    }

    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    pub fn with_outcome(mut self, outcome: String) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn with_ip_address(mut self, ip_address: String) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
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

    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
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

    pub fn with_http_method(mut self, method: String) -> Self {
        self.http_method = Some(method);
        self
    }

    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    pub fn with_request_path(mut self, path: String) -> Self {
        self.request_path = Some(path);
        self
    }

    pub fn with_response_time_ms(mut self, time_ms: u64) -> Self {
        self.response_time_ms = Some(time_ms);
        self
    }

    /// Apply PII protection to sensitive fields
    pub fn apply_pii_protection(&mut self) {
        // Use the enhanced PII detector for protection
        use crate::security_logging_enhanced::PiiDetector;
        let detector = PiiDetector::new();
        
        // Redact PII in description
        self.description = detector.redact_pii(&self.description);
        
        // Redact PII in optional string fields
        if let Some(ref mut actor) = self.actor {
            *actor = detector.redact_pii(actor);
        }
        if let Some(ref mut reason) = self.reason {
            *reason = detector.redact_pii(reason);
        }
        
        // Hash user_id instead of storing it directly
        if let Some(ref user_id) = self.user_id {
            self.user_id = Some(detector.hash_identifier(user_id));
        }
    }
}

// Main types from legacy API for backward compatibility
pub type SecurityEvent = LegacyLegacySecurityEvent;
pub type SecurityEventType = LegacySecurityEventType;

// Main SecurityLogger for static method compatibility
pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log_event(event: &SecurityEvent) {
        // Implementation using tracing directly for simplicity
        match event.severity {
            SecuritySeverity::Critical | SecuritySeverity::High => {
                tracing::error!(target: "security_audit", event = ?event, "Security event");
            }
            SecuritySeverity::Medium | SecuritySeverity::Warning => {
                tracing::warn!(target: "security_audit", event = ?event, "Security event");
            }
            SecuritySeverity::Low | SecuritySeverity::Info => {
                tracing::info!(target: "security_audit", event = ?event, "Security event");
            }
        }
    }
}

// Convenience macro for quick security event logging
#[macro_export]
macro_rules! log_security_event {
    ($logger:expr, $event_type:expr, $severity:expr, $ip:expr, $description:expr) => {
        {
            let event = $logger.event_builder()
                .event_type($event_type)
                .severity($severity)
                .source_ip($ip)
                .description($description.to_string())
                .build();
            $logger.log_event(event).await;
        }
    };
}

// Convenience macro for authentication events
#[macro_export]
macro_rules! log_auth_event {
    (success, $logger:expr, $user_id:expr, $ip:expr, $correlation_id:expr) => {
        $logger.log_auth_success($user_id, $ip, $correlation_id).await;
    };
    (failure, $logger:expr, $user_id:expr, $ip:expr, $correlation_id:expr, $reason:expr) => {
        $logger.log_auth_failure($user_id, $ip, $correlation_id, $reason).await;
    };
}

// Convenience macro for rate limiting events
#[macro_export]
macro_rules! log_rate_limit {
    ($logger:expr, $ip:expr, $endpoint:expr, $correlation_id:expr) => {
        $logger.log_rate_limit_exceeded($ip, $endpoint, $correlation_id).await;
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_security_logging_api() {
        let config = crate::security_logging_enhanced::SecurityLoggerConfig::default();
        let logger = crate::security_logging_enhanced::SecurityLogger::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        
        // Test authentication success
        logger.log_auth_success("test_user", ip, "corr-123").await;
        
        // Test authentication failure  
        logger.log_auth_failure("test_user", ip, "corr-124", "invalid_password").await;
        
        // Test rate limiting
        logger.log_rate_limit_exceeded(ip, "/api/login", "corr-125").await;
        
        // Test CSRF violation
        logger.log_csrf_violation(ip, "/api/transfer", "corr-126").await;
        
        // Test suspicious activity
        logger.log_suspicious_activity(ip, "Multiple failed login attempts", "corr-127").await;
        
        // Verify events were logged
        let stats = logger.get_event_stats().await;
        assert!(stats.total_events > 0);
    }
    
    #[test] 
    fn test_event_builder() {
        use crate::security_logging_enhanced::{SecurityEventType, SecurityEvent};
        
        let event = SecurityEventBuilder::new()
            .event_type(SecurityEventType::AuthenticationSuccess)
            .severity(SecuritySeverity::Info)
            .user_id("test_user")
            .description("Test authentication success".to_string())
            .build();
            
        assert_eq!(event.event_type, SecurityEventType::AuthenticationSuccess);
        assert_eq!(event.severity, SecuritySeverity::Info);
        assert!(event.user_id_hash.is_some());
        assert!(!event.description.is_empty());
    }
}