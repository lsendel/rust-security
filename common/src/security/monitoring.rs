//! Security monitoring and threat detection module
//!
//! Provides real-time security monitoring, threat detection, and alerting
//! capabilities for comprehensive security observability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security event types for monitoring
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityEventType {
    // Authentication events
    LoginSuccess,
    LoginFailure,
    LoginSuspicious,
    PasswordChange,
    MfaEnabled,
    MfaDisabled,

    // Authorization events
    AccessGranted,
    AccessDenied,
    PrivilegeEscalation,
    PolicyViolation,

    // Session events
    SessionCreated,
    SessionExpired,
    SessionTerminated,
    ConcurrentSessionLimit,

    // API security events
    RateLimitExceeded,
    InvalidApiKey,
    RequestSizeExceeded,
    SuspiciousApiUsage,

    // System security events
    ConfigurationChanged,
    SecurityPolicyUpdated,
    CryptoKeyRotated,
    BackupCreated,

    // Threat detection
    BruteForceAttempt,
    AnomalousActivity,
    DataExfiltrationAttempt,
    InjectionAttempt,
    MaliciousPayload,

    // Compliance events
    AuditLogAccess,
    DataDeletion,
    PersonalDataAccess,
    ComplianceViolation,
}

/// Security event severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl SecuritySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Security event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event ID
    pub id: String,

    /// Event type
    pub event_type: SecurityEventType,

    /// Event severity
    pub severity: SecuritySeverity,

    /// Timestamp when event occurred
    pub timestamp: DateTime<Utc>,

    /// User ID associated with event (if applicable)
    pub user_id: Option<String>,

    /// Session ID associated with event (if applicable)
    pub session_id: Option<String>,

    /// Source IP address
    pub source_ip: Option<String>,

    /// User agent string
    pub user_agent: Option<String>,

    /// Event details
    pub details: HashMap<String, String>,

    /// Request ID for correlation
    pub request_id: Option<String>,

    /// Geographic location information
    pub geo_location: Option<GeoLocation>,

    /// Risk score (0-100)
    pub risk_score: u8,

    /// Whether this event requires immediate attention
    pub requires_attention: bool,

    /// Tags for categorization
    pub tags: Vec<String>,
}

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country_code: String,
    pub country_name: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub is_tor_exit: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
}

/// Security metrics for monitoring dashboards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Authentication metrics
    pub authentication: AuthenticationMetrics,

    /// API security metrics
    pub api_security: ApiSecurityMetrics,

    /// Threat detection metrics
    pub threat_detection: ThreatDetectionMetrics,

    /// System security metrics
    pub system_security: SystemSecurityMetrics,

    /// Performance impact metrics
    pub performance: PerformanceMetrics,
}

/// Authentication-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationMetrics {
    pub successful_logins_last_hour: u64,
    pub failed_logins_last_hour: u64,
    pub blocked_ips_count: u64,
    pub active_sessions_count: u64,
    pub mfa_enabled_users_percentage: f64,
    pub password_strength_score: f64,
    pub average_session_duration: f64,
    pub concurrent_session_violations: u64,
}

/// API security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityMetrics {
    pub rate_limit_violations_last_hour: u64,
    pub requests_processed_last_hour: u64,
    pub average_request_size: f64,
    pub api_error_rate: f64,
    pub suspicious_requests_count: u64,
    pub blocked_requests_count: u64,
    pub authenticated_requests_percentage: f64,
}

/// Threat detection metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionMetrics {
    pub threats_detected_last_hour: u64,
    pub brute_force_attempts: u64,
    pub injection_attempts: u64,
    pub anomalous_activities: u64,
    pub high_risk_events: u64,
    pub false_positive_rate: f64,
    pub mean_time_to_detection: f64,
}

/// System security metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSecurityMetrics {
    pub security_policy_violations: u64,
    pub configuration_changes_last_24h: u64,
    pub crypto_key_rotations_last_24h: u64,
    pub backup_completion_rate: f64,
    pub audit_log_integrity_score: f64,
    pub compliance_score: f64,
}

/// Performance impact metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub security_overhead_percentage: f64,
    pub authentication_latency_p95: f64,
    pub authorization_latency_p95: f64,
    pub encryption_overhead_percentage: f64,
    pub monitoring_overhead_percentage: f64,
}

/// Real-time security monitor
pub struct SecurityMonitor {
    /// Event buffer for batching
    event_buffer: Vec<SecurityEvent>,

    /// Configuration
    config: MonitoringConfig,

    /// Metrics collection
    metrics: SecurityMetrics,

    /// Alert handlers
    alert_handlers: Vec<Box<dyn AlertHandler + Send + Sync>>,

    /// Threat detection rules
    detection_rules: Vec<Box<dyn ThreatDetectionRule + Send + Sync>>,
}

/// Monitoring configuration
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Buffer size for batching events
    pub buffer_size: usize,

    /// Flush interval for events (seconds)
    pub flush_interval_seconds: u64,

    /// Enable real-time alerting
    pub enable_real_time_alerts: bool,

    /// Minimum severity level for alerts
    pub min_alert_severity: SecuritySeverity,

    /// Enable metrics collection
    pub enable_metrics_collection: bool,

    /// Metrics collection interval (seconds)
    pub metrics_collection_interval: u64,

    /// Enable geolocation lookups
    pub enable_geolocation: bool,

    /// Enable threat intelligence feeds
    pub enable_threat_intelligence: bool,
}

/// Alert handler trait
#[async_trait::async_trait]
pub trait AlertHandler {
    async fn handle_alert(&self, event: &SecurityEvent) -> Result<(), String>;
    fn name(&self) -> &str;
    fn min_severity(&self) -> SecuritySeverity;
}

/// Threat detection rule trait
pub trait ThreatDetectionRule {
    fn evaluate(
        &self,
        event: &SecurityEvent,
        historical_events: &[SecurityEvent],
    ) -> Option<SecurityEvent>;
    fn name(&self) -> &str;
    fn priority(&self) -> u8;
}

impl SecurityMonitor {
    /// Create a new security monitor
    pub fn new(config: MonitoringConfig) -> Self {
        Self {
            event_buffer: Vec::with_capacity(config.buffer_size),
            config,
            metrics: SecurityMetrics::default(),
            alert_handlers: Vec::new(),
            detection_rules: Vec::new(),
        }
    }

    /// Record a security event
    pub async fn record_event(&mut self, mut event: SecurityEvent) {
        // Apply threat detection rules
        self.apply_threat_detection(&mut event).await;

        // Check for immediate alerts
        if event.severity >= self.config.min_alert_severity || event.requires_attention {
            self.send_alerts(&event).await;
        }

        // Buffer the event
        self.event_buffer.push(event);

        // Flush if buffer is full
        if self.event_buffer.len() >= self.config.buffer_size {
            self.flush_events().await;
        }
    }

    /// Apply threat detection rules to an event
    async fn apply_threat_detection(&self, event: &mut SecurityEvent) {
        for rule in &self.detection_rules {
            if let Some(threat_event) = rule.evaluate(event, &[]) {
                // Upgrade the event severity if threat detected
                if threat_event.severity > event.severity {
                    event.severity = threat_event.severity;
                    event.requires_attention = true;
                    event.tags.push(format!("threat_detected_{}", rule.name()));
                }
            }
        }
    }

    /// Send alerts for high-severity events
    async fn send_alerts(&self, event: &SecurityEvent) {
        for handler in &self.alert_handlers {
            if event.severity >= handler.min_severity() {
                if let Err(e) = handler.handle_alert(event).await {
                    tracing::error!("Alert handler {} failed: {}", handler.name(), e);
                }
            }
        }
    }

    /// Flush buffered events to storage
    async fn flush_events(&mut self) {
        if self.event_buffer.is_empty() {
            return;
        }

        // Log all events
        for event in &self.event_buffer {
            tracing::info!(
                target = "security_monitor",
                event_id = %event.id,
                event_type = ?event.event_type,
                severity = %event.severity.as_str(),
                user_id = ?event.user_id,
                source_ip = ?event.source_ip,
                risk_score = %event.risk_score,
                "Security event recorded"
            );
        }

        // Update metrics
        let events = self.event_buffer.clone();
        self.update_metrics(&events);

        // Clear buffer
        self.event_buffer.clear();
    }

    /// Update security metrics based on events
    fn update_metrics(&mut self, events: &[SecurityEvent]) {
        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);

        for event in events {
            if event.timestamp >= one_hour_ago {
                match event.event_type {
                    SecurityEventType::LoginSuccess => {
                        self.metrics.authentication.successful_logins_last_hour += 1;
                    }
                    SecurityEventType::LoginFailure => {
                        self.metrics.authentication.failed_logins_last_hour += 1;
                    }
                    SecurityEventType::RateLimitExceeded => {
                        self.metrics.api_security.rate_limit_violations_last_hour += 1;
                    }
                    SecurityEventType::BruteForceAttempt => {
                        self.metrics.threat_detection.brute_force_attempts += 1;
                    }
                    SecurityEventType::AnomalousActivity => {
                        self.metrics.threat_detection.anomalous_activities += 1;
                    }
                    _ => {}
                }

                if event.severity >= SecuritySeverity::High {
                    self.metrics.threat_detection.high_risk_events += 1;
                }
            }
        }
    }

    /// Add an alert handler
    pub fn add_alert_handler(&mut self, handler: Box<dyn AlertHandler + Send + Sync>) {
        self.alert_handlers.push(handler);
    }

    /// Add a threat detection rule
    pub fn add_detection_rule(&mut self, rule: Box<dyn ThreatDetectionRule + Send + Sync>) {
        self.detection_rules.push(rule);
    }

    /// Get current security metrics
    pub fn get_metrics(&self) -> &SecurityMetrics {
        &self.metrics
    }

    /// Perform health check
    pub async fn health_check(&self) -> Result<(), String> {
        // Check alert handlers
        for _handler in &self.alert_handlers {
            // Basic connectivity check would go here
        }
        Ok(())
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self {
            authentication: AuthenticationMetrics {
                successful_logins_last_hour: 0,
                failed_logins_last_hour: 0,
                blocked_ips_count: 0,
                active_sessions_count: 0,
                mfa_enabled_users_percentage: 0.0,
                password_strength_score: 0.0,
                average_session_duration: 0.0,
                concurrent_session_violations: 0,
            },
            api_security: ApiSecurityMetrics {
                rate_limit_violations_last_hour: 0,
                requests_processed_last_hour: 0,
                average_request_size: 0.0,
                api_error_rate: 0.0,
                suspicious_requests_count: 0,
                blocked_requests_count: 0,
                authenticated_requests_percentage: 0.0,
            },
            threat_detection: ThreatDetectionMetrics {
                threats_detected_last_hour: 0,
                brute_force_attempts: 0,
                injection_attempts: 0,
                anomalous_activities: 0,
                high_risk_events: 0,
                false_positive_rate: 0.0,
                mean_time_to_detection: 0.0,
            },
            system_security: SystemSecurityMetrics {
                security_policy_violations: 0,
                configuration_changes_last_24h: 0,
                crypto_key_rotations_last_24h: 0,
                backup_completion_rate: 0.0,
                audit_log_integrity_score: 0.0,
                compliance_score: 0.0,
            },
            performance: PerformanceMetrics {
                security_overhead_percentage: 0.0,
                authentication_latency_p95: 0.0,
                authorization_latency_p95: 0.0,
                encryption_overhead_percentage: 0.0,
                monitoring_overhead_percentage: 0.0,
            },
        }
    }
}

/// Simple email alert handler
pub struct EmailAlertHandler {
    pub smtp_server: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub min_severity: SecuritySeverity,
}

#[async_trait::async_trait]
impl AlertHandler for EmailAlertHandler {
    async fn handle_alert(&self, event: &SecurityEvent) -> Result<(), String> {
        // Email sending logic would be implemented here
        tracing::info!(
            "Email alert sent for event {} to {:?}",
            event.id,
            self.to_addresses
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "email"
    }

    fn min_severity(&self) -> SecuritySeverity {
        self.min_severity
    }
}

/// Brute force detection rule
pub struct BruteForceDetectionRule {
    pub max_failed_attempts: u32,
    pub time_window_minutes: u32,
}

impl ThreatDetectionRule for BruteForceDetectionRule {
    fn evaluate(
        &self,
        event: &SecurityEvent,
        _historical_events: &[SecurityEvent],
    ) -> Option<SecurityEvent> {
        if matches!(event.event_type, SecurityEventType::LoginFailure) {
            // In a real implementation, we would check historical events
            // For now, just mark as potential brute force
            let mut threat_event = event.clone();
            threat_event.event_type = SecurityEventType::BruteForceAttempt;
            threat_event.severity = SecuritySeverity::High;
            threat_event.requires_attention = true;
            threat_event.tags.push("brute_force_detected".to_string());
            Some(threat_event)
        } else {
            None
        }
    }

    fn name(&self) -> &str {
        "brute_force_detection"
    }

    fn priority(&self) -> u8 {
        90
    }
}

/// Helper function to create a security event
pub fn create_security_event(
    event_type: SecurityEventType,
    severity: SecuritySeverity,
    user_id: Option<String>,
    source_ip: Option<String>,
    details: HashMap<String, String>,
) -> SecurityEvent {
    SecurityEvent {
        id: uuid::Uuid::new_v4().to_string(),
        event_type,
        severity,
        timestamp: Utc::now(),
        user_id,
        session_id: None,
        source_ip,
        user_agent: None,
        details,
        request_id: None,
        geo_location: None,
        risk_score: match severity {
            SecuritySeverity::Info => 10,
            SecuritySeverity::Low => 25,
            SecuritySeverity::Medium => 50,
            SecuritySeverity::High => 75,
            SecuritySeverity::Critical => 95,
        },
        requires_attention: severity >= SecuritySeverity::High,
        tags: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_monitor_event_recording() {
        let config = MonitoringConfig {
            buffer_size: 10,
            flush_interval_seconds: 60,
            enable_real_time_alerts: true,
            min_alert_severity: SecuritySeverity::Medium,
            enable_metrics_collection: true,
            metrics_collection_interval: 300,
            enable_geolocation: false,
            enable_threat_intelligence: false,
        };

        let mut monitor = SecurityMonitor::new(config);

        let event = create_security_event(
            SecurityEventType::LoginSuccess,
            SecuritySeverity::Info,
            Some("user123".to_string()),
            Some("192.168.1.1".to_string()),
            HashMap::new(),
        );

        monitor.record_event(event).await;

        assert_eq!(monitor.event_buffer.len(), 1);
    }

    #[test]
    fn test_brute_force_detection_rule() {
        let rule = BruteForceDetectionRule {
            max_failed_attempts: 5,
            time_window_minutes: 15,
        };

        let event = create_security_event(
            SecurityEventType::LoginFailure,
            SecuritySeverity::Low,
            Some("user123".to_string()),
            Some("192.168.1.1".to_string()),
            HashMap::new(),
        );

        let result = rule.evaluate(&event, &[]);
        assert!(result.is_some());

        let threat_event = result.unwrap();
        assert_eq!(
            threat_event.event_type,
            SecurityEventType::BruteForceAttempt
        );
        assert_eq!(threat_event.severity, SecuritySeverity::High);
    }

    #[test]
    fn test_security_severity_ordering() {
        assert!(SecuritySeverity::Critical > SecuritySeverity::High);
        assert!(SecuritySeverity::High > SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium > SecuritySeverity::Low);
        assert!(SecuritySeverity::Low > SecuritySeverity::Info);
    }
}
