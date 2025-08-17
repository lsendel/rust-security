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
    UnauthorizedAccess,
    SessionEvent,
    SecurityViolation,
}

/// Structured security event for audit logging
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
    
    /// Client identifier (if applicable)
    pub client_id: Option<String>,
    
    /// User identifier (if applicable)
    pub user_id: Option<String>,
    
    /// Client IP address
    pub ip_address: Option<String>,
    
    /// User agent string
    pub user_agent: Option<String>,
    
    /// Request ID for correlation
    pub request_id: Option<String>,
    
    /// Session ID for correlation
    pub session_id: Option<String>,
    
    /// Event description
    pub description: String,
    
    /// Additional event details
    pub details: HashMap<String, Value>,
    
    /// Outcome of the event (success, failure, etc.)
    pub outcome: String,
    
    /// Resource accessed or affected
    pub resource: Option<String>,
    
    /// Action performed
    pub action: Option<String>,
    
    /// Risk score (0-100)
    pub risk_score: Option<u8>,
    
    /// Geographic location (if available)
    pub location: Option<String>,
    
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
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
            client_id: None,
            user_id: None,
            ip_address: None,
            user_agent: None,
            request_id: None,
            session_id: None,
            description,
            details: HashMap::new(),
            outcome: "unknown".to_string(),
            resource: None,
            action: None,
            risk_score: None,
            location: None,
            device_fingerprint: None,
        }
    }
    
    /// Builder pattern methods for setting optional fields
    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }
    
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
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
}

/// Security logger for structured audit logging
pub struct SecurityLogger;

impl SecurityLogger {
    /// Log a security event with appropriate level
    pub fn log_event(event: &SecurityEvent) {
        let event_json = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(e) => {
                error!("Failed to serialize security event: {}", e);
                return;
            }
        };
        
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
                    event_json
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
                    event_json
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
                    event_json
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
                    event_json
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
                    event_json
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
                    event_json
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
        
        Self::log_event(&event);
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
        
        Self::log_event(&event);
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
        
        Self::log_event(&event);
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
        
        Self::log_event(&event);
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
            format!("Rate limit exceeded for client {} at {}", client_id, endpoint),
        )
        .with_client_id(client_id.to_string())
        .with_ip_address(ip_address.to_string())
        .with_outcome("rate_limited".to_string())
        .with_resource(endpoint.to_string())
        .with_detail("current_rate".to_string(), current_rate)
        .with_detail("rate_limit".to_string(), limit);
        
        Self::log_event(&event);
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
            $client_id,
            $ip,
            None,
            $outcome,
            None,
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
