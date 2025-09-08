//! # Security Event Audit Logging
//!
//! Structured security event logging for compliance and security monitoring.
//! Supports SIEM integration and audit trail requirements.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Security event severity levels aligned with NIST standards
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Informational security events
    Info = 1,
    /// Low impact security events
    Low = 2,
    /// Medium impact security events requiring attention
    Medium = 3,
    /// High impact security events requiring immediate attention
    High = 4,
    /// Critical security events requiring urgent response
    Critical = 5,
}

impl fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecuritySeverity::Info => write!(f, "INFO"),
            SecuritySeverity::Low => write!(f, "LOW"),
            SecuritySeverity::Medium => write!(f, "MEDIUM"),
            SecuritySeverity::High => write!(f, "HIGH"),
            SecuritySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Security event categories for classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityEventType {
    Authentication,
    Authorization,
    RateLimiting,
    Cryptography,
    Configuration,
    NetworkSecurity,
    DataAccess,
    SystemSecurity,
    ComplianceViolation,
    ThreatDetection,
}

impl fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityEventType::Authentication => write!(f, "AUTHENTICATION"),
            SecurityEventType::Authorization => write!(f, "AUTHORIZATION"),
            SecurityEventType::RateLimiting => write!(f, "RATE_LIMITING"),
            SecurityEventType::Cryptography => write!(f, "CRYPTOGRAPHY"),
            SecurityEventType::Configuration => write!(f, "CONFIGURATION"),
            SecurityEventType::NetworkSecurity => write!(f, "NETWORK_SECURITY"),
            SecurityEventType::DataAccess => write!(f, "DATA_ACCESS"),
            SecurityEventType::SystemSecurity => write!(f, "SYSTEM_SECURITY"),
            SecurityEventType::ComplianceViolation => write!(f, "COMPLIANCE_VIOLATION"),
            SecurityEventType::ThreatDetection => write!(f, "THREAT_DETECTION"),
        }
    }
}

/// Structured security event for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier
    pub event_id: String,
    /// Event timestamp (ISO 8601)
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event severity level
    pub severity: SecuritySeverity,
    /// Event category
    pub event_type: SecurityEventType,
    /// Human-readable event description
    pub message: String,
    /// Source IP address if applicable
    pub source_ip: Option<IpAddr>,
    /// User ID if applicable
    pub user_id: Option<String>,
    /// Session ID if applicable
    pub session_id: Option<String>,
    /// Resource being accessed
    pub resource: Option<String>,
    /// Action attempted or performed
    pub action: Option<String>,
    /// Event outcome (success/failure/blocked)
    pub outcome: SecurityOutcome,
    /// Additional structured metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Compliance tags for filtering
    pub compliance_tags: Vec<String>,
}

/// Security event outcome classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityOutcome {
    Success,
    Failure,
    Blocked,
    Warning,
    Error,
}

impl fmt::Display for SecurityOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityOutcome::Success => write!(f, "SUCCESS"),
            SecurityOutcome::Failure => write!(f, "FAILURE"),
            SecurityOutcome::Blocked => write!(f, "BLOCKED"),
            SecurityOutcome::Warning => write!(f, "WARNING"),
            SecurityOutcome::Error => write!(f, "ERROR"),
        }
    }
}

/// Security audit logger configuration
#[derive(Debug, Clone)]
pub struct AuditLoggerConfig {
    /// Enable structured JSON logging
    pub enable_json_format: bool,
    /// Enable SIEM integration
    pub enable_siem_integration: bool,
    /// Minimum severity level to log
    pub min_severity: SecuritySeverity,
    /// Enable real-time alerting for critical events
    pub enable_real_time_alerts: bool,
    /// Log retention period in days
    pub retention_days: u32,
    /// Enable event correlation
    pub enable_correlation: bool,
    /// Maximum events per minute (rate limiting)
    pub max_events_per_minute: u32,
}

impl Default for AuditLoggerConfig {
    fn default() -> Self {
        Self {
            enable_json_format: true,
            enable_siem_integration: false,
            min_severity: SecuritySeverity::Info,
            enable_real_time_alerts: true,
            retention_days: 90,
            enable_correlation: true,
            max_events_per_minute: 1000,
        }
    }
}

impl AuditLoggerConfig {
    /// Production configuration with strict security
    pub fn production() -> Self {
        Self {
            enable_json_format: true,
            enable_siem_integration: true,
            min_severity: SecuritySeverity::Low,
            enable_real_time_alerts: true,
            retention_days: 365,
            enable_correlation: true,
            max_events_per_minute: 500,
        }
    }

    /// Development configuration with verbose logging
    pub fn development() -> Self {
        Self {
            enable_json_format: false,
            enable_siem_integration: false,
            min_severity: SecuritySeverity::Info,
            enable_real_time_alerts: false,
            retention_days: 30,
            enable_correlation: false,
            max_events_per_minute: 2000,
        }
    }
}

/// Security audit logger with correlation and compliance features
#[derive(Debug)]
pub struct SecurityAuditLogger {
    config: AuditLoggerConfig,
    event_correlation: Arc<RwLock<HashMap<String, Vec<SecurityEvent>>>>,
    rate_limiter: Arc<RwLock<tokio_util::time::DelayQueue<()>>>,
}

impl SecurityAuditLogger {
    /// Create a new audit logger with configuration
    pub fn new(config: AuditLoggerConfig) -> Self {
        Self {
            config,
            event_correlation: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(tokio_util::time::DelayQueue::new())),
        }
    }

    /// Log a security event
    pub async fn log_event(&self, mut event: SecurityEvent) {
        // Check severity threshold
        if event.severity < self.config.min_severity {
            return;
        }

        // Add correlation ID if enabled
        if self.config.enable_correlation {
            if let Some(correlation_id) = self.correlate_event(&event).await {
                event.metadata.insert(
                    "correlation_id".to_string(),
                    serde_json::Value::String(correlation_id),
                );
            }
        }

        // Format and log event
        if self.config.enable_json_format {
            self.log_json_event(&event).await;
        } else {
            self.log_text_event(&event).await;
        }

        // Handle real-time alerts for critical events
        if self.config.enable_real_time_alerts && event.severity >= SecuritySeverity::High {
            self.send_real_time_alert(&event).await;
        }

        // Store for correlation if enabled
        if self.config.enable_correlation {
            self.store_for_correlation(event).await;
        }
    }

    /// Log structured JSON event
    async fn log_json_event(&self, event: &SecurityEvent) {
        let json_event = serde_json::to_string(event).unwrap_or_else(|_| {
            format!("{{\"error\":\"Failed to serialize event\",\"event_id\":\"{}\"}}", event.event_id)
        });

        match event.severity {
            SecuritySeverity::Critical => error!(target: "security_audit", "{}", json_event),
            SecuritySeverity::High => warn!(target: "security_audit", "{}", json_event),
            _ => info!(target: "security_audit", "{}", json_event),
        }
    }

    /// Log human-readable text event
    async fn log_text_event(&self, event: &SecurityEvent) {
        let log_line = format!(
            "[{}] [{}] [{}] {} - {} (Event ID: {})",
            event.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            event.severity,
            event.event_type,
            event.outcome,
            event.message,
            event.event_id
        );

        match event.severity {
            SecuritySeverity::Critical => error!(target: "security_audit", "{}", log_line),
            SecuritySeverity::High => warn!(target: "security_audit", "{}", log_line),
            _ => info!(target: "security_audit", "{}", log_line),
        }
    }

    /// Correlate events to detect patterns
    async fn correlate_event(&self, event: &SecurityEvent) -> Option<String> {
        if !self.config.enable_correlation {
            return None;
        }

        // Generate correlation key based on source IP and event type
        let correlation_key = match &event.source_ip {
            Some(ip) => format!("{}:{}", ip, event.event_type),
            None => format!("unknown:{}", event.event_type),
        };

        let correlation_guard = self.event_correlation.read().await;
        if correlation_guard.contains_key(&correlation_key) {
            Some(correlation_key)
        } else {
            None
        }
    }

    /// Store event for correlation analysis
    async fn store_for_correlation(&self, event: SecurityEvent) {
        let correlation_key = match &event.source_ip {
            Some(ip) => format!("{}:{}", ip, event.event_type),
            None => format!("unknown:{}", event.event_type),
        };

        let mut correlation_guard = self.event_correlation.write().await;
        correlation_guard
            .entry(correlation_key)
            .or_insert_with(Vec::new)
            .push(event);
    }

    /// Send real-time alert for critical events
    async fn send_real_time_alert(&self, event: &SecurityEvent) {
        // In a real implementation, this would integrate with alerting systems
        warn!(
            target: "security_alerts",
            "CRITICAL SECURITY EVENT: {} - {} (Event ID: {})",
            event.event_type,
            event.message,
            event.event_id
        );
    }
}

/// Convenience functions for common security events
impl SecurityAuditLogger {
    /// Log authentication event
    pub async fn log_authentication(&self, user_id: Option<String>, source_ip: Option<IpAddr>, 
                                   outcome: SecurityOutcome, message: String) {
        let severity = match outcome {
            SecurityOutcome::Failure => SecuritySeverity::Medium,
            SecurityOutcome::Blocked => SecuritySeverity::High,
            SecurityOutcome::Success => SecuritySeverity::Info,
            _ => SecuritySeverity::Low,
        };

        let event = SecurityEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            severity,
            event_type: SecurityEventType::Authentication,
            message,
            source_ip,
            user_id,
            session_id: None,
            resource: Some("authentication".to_string()),
            action: Some("login".to_string()),
            outcome,
            metadata: HashMap::new(),
            compliance_tags: vec!["authentication".to_string(), "access_control".to_string()],
        };

        self.log_event(event).await;
    }

    /// Log rate limiting violation
    pub async fn log_rate_limit_violation(&self, source_ip: IpAddr, limit_type: String, 
                                        current_count: u32, limit: u32) {
        let mut metadata = HashMap::new();
        metadata.insert("limit_type".to_string(), serde_json::Value::String(limit_type.clone()));
        metadata.insert("current_count".to_string(), serde_json::Value::Number(current_count.into()));
        metadata.insert("limit".to_string(), serde_json::Value::Number(limit.into()));

        let event = SecurityEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            severity: SecuritySeverity::Medium,
            event_type: SecurityEventType::RateLimiting,
            message: format!("Rate limit exceeded: {} ({}/{})", limit_type, current_count, limit),
            source_ip: Some(source_ip),
            user_id: None,
            session_id: None,
            resource: Some("rate_limiter".to_string()),
            action: Some("block".to_string()),
            outcome: SecurityOutcome::Blocked,
            metadata,
            compliance_tags: vec!["rate_limiting".to_string(), "dos_protection".to_string()],
        };

        self.log_event(event).await;
    }

    /// Log cryptographic operation
    pub async fn log_crypto_operation(&self, operation: String, outcome: SecurityOutcome, 
                                    algorithm: Option<String>) {
        let severity = match outcome {
            SecurityOutcome::Failure | SecurityOutcome::Error => SecuritySeverity::High,
            SecurityOutcome::Warning => SecuritySeverity::Medium,
            _ => SecuritySeverity::Low,
        };

        let mut metadata = HashMap::new();
        if let Some(algo) = algorithm {
            metadata.insert("algorithm".to_string(), serde_json::Value::String(algo));
        }

        let event = SecurityEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            severity,
            event_type: SecurityEventType::Cryptography,
            message: format!("Cryptographic operation: {}", operation),
            source_ip: None,
            user_id: None,
            session_id: None,
            resource: Some("crypto_service".to_string()),
            action: Some(operation),
            outcome,
            metadata,
            compliance_tags: vec!["cryptography".to_string(), "data_protection".to_string()],
        };

        self.log_event(event).await;
    }

    /// Log configuration security violation
    pub async fn log_config_violation(&self, parameter: String, severity: SecuritySeverity, 
                                    current_value: String, recommended_value: String) {
        let mut metadata = HashMap::new();
        metadata.insert("parameter".to_string(), serde_json::Value::String(parameter.clone()));
        metadata.insert("current_value".to_string(), serde_json::Value::String(current_value));
        metadata.insert("recommended_value".to_string(), serde_json::Value::String(recommended_value));

        let event = SecurityEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            severity,
            event_type: SecurityEventType::Configuration,
            message: format!("Configuration security violation: {}", parameter),
            source_ip: None,
            user_id: None,
            session_id: None,
            resource: Some("configuration".to_string()),
            action: Some("validate".to_string()),
            outcome: SecurityOutcome::Warning,
            metadata,
            compliance_tags: vec!["configuration".to_string(), "security_policy".to_string()],
        };

        self.log_event(event).await;
    }
}

use once_cell::sync::OnceCell;

/// Global audit logger instance
static GLOBAL_AUDIT_LOGGER: OnceCell<SecurityAuditLogger> = OnceCell::new();

/// Initialize the global audit logger
pub fn initialize_audit_logger(config: AuditLoggerConfig) {
    GLOBAL_AUDIT_LOGGER.set(SecurityAuditLogger::new(config))
        .expect("GLOBAL_AUDIT_LOGGER already initialized");
}

/// Get the global audit logger instance
pub fn get_audit_logger() -> Option<&'static SecurityAuditLogger> {
    GLOBAL_AUDIT_LOGGER.get()
}

/// Convenience macro for logging security events
#[macro_export]
macro_rules! log_security_event {
    ($severity:expr, $event_type:expr, $message:expr) => {
        if let Some(logger) = $crate::security::audit_logging::get_audit_logger() {
            let event = $crate::security::audit_logging::SecurityEvent {
                event_id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                severity: $severity,
                event_type: $event_type,
                message: $message.to_string(),
                source_ip: None,
                user_id: None,
                session_id: None,
                resource: None,
                action: None,
                outcome: $crate::security::audit_logging::SecurityOutcome::Success,
                metadata: std::collections::HashMap::new(),
                compliance_tags: vec![],
            };
            tokio::spawn(async move {
                logger.log_event(event).await;
            });
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_logger_creation() {
        let config = AuditLoggerConfig::default();
        let logger = SecurityAuditLogger::new(config);
        
        // Test that logger can be created
        assert_eq!(logger.config.min_severity, SecuritySeverity::Info);
    }

    #[tokio::test]
    async fn test_security_event_serialization() {
        let event = SecurityEvent {
            event_id: "test-123".to_string(),
            timestamp: chrono::Utc::now(),
            severity: SecuritySeverity::High,
            event_type: SecurityEventType::Authentication,
            message: "Test authentication event".to_string(),
            source_ip: Some("127.0.0.1".parse().unwrap()),
            user_id: Some("user123".to_string()),
            session_id: Some("session456".to_string()),
            resource: Some("api".to_string()),
            action: Some("login".to_string()),
            outcome: SecurityOutcome::Success,
            metadata: HashMap::new(),
            compliance_tags: vec!["test".to_string()],
        };

        let json = serde_json::to_string(&event);
        assert!(json.is_ok());
        
        let parsed: SecurityEvent = serde_json::from_str(&json.unwrap()).unwrap();
        assert_eq!(parsed.event_id, "test-123");
        assert_eq!(parsed.severity, SecuritySeverity::High);
    }

    #[tokio::test]
    async fn test_authentication_logging() {
        let config = AuditLoggerConfig::development();
        let logger = SecurityAuditLogger::new(config);
        
        logger.log_authentication(
            Some("user123".to_string()),
            Some("127.0.0.1".parse().unwrap()),
            SecurityOutcome::Success,
            "User logged in successfully".to_string(),
        ).await;
        
        // Test passes if no panic occurs
    }

    #[tokio::test]
    async fn test_rate_limit_logging() {
        let config = AuditLoggerConfig::development();
        let logger = SecurityAuditLogger::new(config);
        
        logger.log_rate_limit_violation(
            "127.0.0.1".parse().unwrap(),
            "requests_per_minute".to_string(),
            150,
            100,
        ).await;
        
        // Test passes if no panic occurs
    }
}