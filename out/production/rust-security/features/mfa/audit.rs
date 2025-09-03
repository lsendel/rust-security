use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{event, Level};

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Channel send error")]
    ChannelSendError,
    #[error("Invalid event data: {0}")]
    InvalidEventData(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaEventType {
    Registration,
    RegistrationCompleted,
    Verification,
    VerificationSuccess,
    VerificationFailure,
    BackupCodeGeneration,
    BackupCodeUsed,
    SecretRotation,
    RateLimitExceeded,
    ReplayAttempt,
    SuspiciousActivity,
    ConfigurationChange,
    UserMfaDisabled,
    UserMfaEnabled,
    SecurityAlert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaMethod {
    TOTP,
    SMS,
    Email,
    BackupCode,
    WebAuthn,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MfaResult {
    Success,
    Failure,
    RateLimited,
    Blocked,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaAuditEvent {
    pub event_id: String,
    pub event_type: MfaEventType,
    pub user_id: String,
    pub timestamp: u64,
    pub method: MfaMethod,
    pub result: MfaResult,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub device_fingerprint: Option<String>,
    pub geolocation: Option<GeoLocation>,
    pub additional_context: HashMap<String, serde_json::Value>,
    pub risk_score: Option<f64>,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl MfaAuditEvent {
    pub fn new(
        event_type: MfaEventType,
        user_id: String,
        method: MfaMethod,
        result: MfaResult,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            user_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            method,
            result,
            ip_address: None,
            user_agent: None,
            session_id: None,
            device_fingerprint: None,
            geolocation: None,
            additional_context: HashMap::new(),
            risk_score: None,
            security_level: SecurityLevel::Low,
        }
    }

    pub fn with_ip_address(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn with_device_fingerprint(mut self, fingerprint: String) -> Self {
        self.device_fingerprint = Some(fingerprint);
        self
    }

    pub fn with_geolocation(mut self, geo: GeoLocation) -> Self {
        self.geolocation = Some(geo);
        self
    }

    pub fn with_context(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_context.insert(key, value);
        self
    }

    pub fn with_risk_score(mut self, score: f64) -> Self {
        self.risk_score = Some(score);
        self.security_level = match score {
            s if s >= 0.8 => SecurityLevel::Critical,
            s if s >= 0.6 => SecurityLevel::High,
            s if s >= 0.3 => SecurityLevel::Medium,
            _ => SecurityLevel::Low,
        };
        self
    }

    pub fn is_security_alert(&self) -> bool {
        matches!(
            self.event_type,
            MfaEventType::RateLimitExceeded
                | MfaEventType::ReplayAttempt
                | MfaEventType::SuspiciousActivity
                | MfaEventType::SecurityAlert
        ) || matches!(self.security_level, SecurityLevel::High | SecurityLevel::Critical)
    }

    pub fn should_trigger_notification(&self) -> bool {
        self.is_security_alert() || matches!(self.result, MfaResult::Blocked)
    }
}

pub trait AuditSink: Send + Sync {
    fn log_event(&self, event: &MfaAuditEvent) -> Result<(), AuditError>;
}

pub struct StructuredLogger;

impl AuditSink for StructuredLogger {
    fn log_event(&self, event: &MfaAuditEvent) -> Result<(), AuditError> {
        let level = match event.security_level {
            SecurityLevel::Critical => Level::ERROR,
            SecurityLevel::High => Level::WARN,
            SecurityLevel::Medium => Level::INFO,
            SecurityLevel::Low => Level::DEBUG,
        };

        event!(
            target: "mfa_audit",
            level,
            event_id = %event.event_id,
            event_type = ?event.event_type,
            user_id = %event.user_id,
            method = ?event.method,
            result = ?event.result,
            ip_address = ?event.ip_address,
            risk_score = ?event.risk_score,
            security_level = ?event.security_level,
            additional_context = ?event.additional_context,
            "MFA audit event"
        );

        Ok(())
    }
}

pub struct JsonFileLogger {
    file_path: String,
}

impl JsonFileLogger {
    pub fn new(file_path: String) -> Self {
        Self { file_path }
    }
}

impl AuditSink for JsonFileLogger {
    fn log_event(&self, event: &MfaAuditEvent) -> Result<(), AuditError> {
        let json_line = serde_json::to_string(event)?;

        // In a real implementation, you'd want to use a proper async file writer
        // with rotation, buffering, etc. This is a simplified version.
        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .and_then(|mut file| {
                use std::io::Write;
                writeln!(file, "{}", json_line)
            })
        {
            tracing::error!("Failed to write audit log: {}", e);
        }

        Ok(())
    }
}

pub struct SyslogSink {
    facility: String,
}

impl SyslogSink {
    pub fn new(facility: String) -> Self {
        Self { facility }
    }
}

impl AuditSink for SyslogSink {
    fn log_event(&self, event: &MfaAuditEvent) -> Result<(), AuditError> {
        let message = format!(
            "MFA_AUDIT: event_type={:?} user_id={} method={:?} result={:?} ip={:?} risk_score={:?}",
            event.event_type,
            event.user_id,
            event.method,
            event.result,
            event.ip_address,
            event.risk_score
        );

        // In a real implementation, you'd use a proper syslog library
        tracing::info!(target: "syslog", facility = %self.facility, "{}", message);
        Ok(())
    }
}

pub struct SecurityIncidentManager {
    incident_threshold: u32,
    time_window_secs: u64,
    recent_events: Arc<tokio::sync::Mutex<Vec<MfaAuditEvent>>>,
}

impl SecurityIncidentManager {
    pub fn new(incident_threshold: u32, time_window_secs: u64) -> Self {
        Self {
            incident_threshold,
            time_window_secs,
            recent_events: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn process_event(&self, event: &MfaAuditEvent) -> bool {
        if !event.is_security_alert() {
            return false;
        }

        let mut events = self.recent_events.lock().await;
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Remove old events outside the time window
        events.retain(|e| current_time - e.timestamp <= self.time_window_secs);

        // Add current event
        events.push(event.clone());

        // Check if we've exceeded the threshold
        let security_events_count = events
            .iter()
            .filter(|e| e.is_security_alert())
            .count() as u32;

        if security_events_count >= self.incident_threshold {
            tracing::error!(
                "Security incident detected: {} security events in {} seconds for user {}",
                security_events_count,
                self.time_window_secs,
                event.user_id
            );
            true
        } else {
            false
        }
    }
}

pub struct MfaAuditor {
    sinks: Vec<Arc<dyn AuditSink>>,
    event_sender: Option<mpsc::UnboundedSender<MfaAuditEvent>>,
    incident_manager: SecurityIncidentManager,
    metrics_collector: MfaMetricsCollector,
}

impl MfaAuditor {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        let mut auditor = Self {
            sinks: vec![Arc::new(StructuredLogger)],
            event_sender: Some(tx),
            incident_manager: SecurityIncidentManager::new(5, 300), // 5 events in 5 minutes
            metrics_collector: MfaMetricsCollector::new(),
        };

        // Spawn async event processor
        auditor.spawn_event_processor(rx);
        auditor
    }

    pub fn add_sink(&mut self, sink: Arc<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    pub fn add_json_file_sink(&mut self, file_path: String) {
        self.add_sink(Arc::new(JsonFileLogger::new(file_path)));
    }

    pub fn add_syslog_sink(&mut self, facility: String) {
        self.add_sink(Arc::new(SyslogSink::new(facility)));
    }

    pub async fn log_mfa_event(&self, event: MfaAuditEvent) -> Result<(), AuditError> {
        // Send event for async processing
        if let Some(sender) = &self.event_sender {
            sender.send(event).map_err(|_| AuditError::ChannelSendError)?;
        }
        Ok(())
    }

    fn spawn_event_processor(&self, mut rx: mpsc::UnboundedReceiver<MfaAuditEvent>) {
        let sinks = self.sinks.clone();
        let incident_manager = self.incident_manager.clone();
        let metrics_collector = self.metrics_collector.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                // Process through all sinks
                for sink in &sinks {
                    if let Err(e) = sink.log_event(&event) {
                        tracing::error!("Audit sink error: {}", e);
                    }
                }

                // Check for security incidents
                if incident_manager.process_event(&event).await {
                    // Trigger additional alerting mechanisms
                    Self::trigger_security_alert(&event).await;
                }

                // Update metrics
                metrics_collector.record_event(&event).await;
            }
        });
    }

    async fn trigger_security_alert(event: &MfaAuditEvent) {
        tracing::error!(
            target: "security_alert",
            event_id = %event.event_id,
            user_id = %event.user_id,
            event_type = ?event.event_type,
            "MFA security incident detected - immediate attention required"
        );

        // Here you would integrate with your alerting system:
        // - Send to SIEM
        // - Trigger PagerDuty/OpsGenie
        // - Send to security team Slack channel
        // - Create incident ticket
    }

    pub async fn get_user_audit_summary(&self, user_id: &str, hours: u32) -> AuditSummary {
        // In a real implementation, this would query your audit store
        AuditSummary {
            user_id: user_id.to_string(),
            time_range_hours: hours,
            total_events: 0,
            successful_authentications: 0,
            failed_authentications: 0,
            security_alerts: 0,
            unique_ip_addresses: 0,
            methods_used: vec![],
        }
    }
}

impl Clone for SecurityIncidentManager {
    fn clone(&self) -> Self {
        Self {
            incident_threshold: self.incident_threshold,
            time_window_secs: self.time_window_secs,
            recent_events: self.recent_events.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MfaMetricsCollector {
    // In a real implementation, this would integrate with Prometheus/metrics
}

impl MfaMetricsCollector {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn record_event(&self, event: &MfaAuditEvent) {
        // Record metrics based on event
        match &event.result {
            MfaResult::Success => {
                tracing::debug!(target: "metrics", "mfa_verification_success_total");
            }
            MfaResult::Failure => {
                tracing::debug!(target: "metrics", "mfa_verification_failure_total");
            }
            MfaResult::RateLimited => {
                tracing::debug!(target: "metrics", "mfa_rate_limited_total");
            }
            _ => {}
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuditSummary {
    pub user_id: String,
    pub time_range_hours: u32,
    pub total_events: u32,
    pub successful_authentications: u32,
    pub failed_authentications: u32,
    pub security_alerts: u32,
    pub unique_ip_addresses: u32,
    pub methods_used: Vec<MfaMethod>,
}

// Helper functions for creating common audit events
impl MfaAuditEvent {
    pub fn totp_verification_success(user_id: String) -> Self {
        Self::new(
            MfaEventType::VerificationSuccess,
            user_id,
            MfaMethod::TOTP,
            MfaResult::Success,
        )
    }

    pub fn totp_verification_failure(user_id: String) -> Self {
        Self::new(
            MfaEventType::VerificationFailure,
            user_id,
            MfaMethod::TOTP,
            MfaResult::Failure,
        )
    }

    pub fn backup_code_used(user_id: String) -> Self {
        Self::new(
            MfaEventType::BackupCodeUsed,
            user_id,
            MfaMethod::BackupCode,
            MfaResult::Success,
        )
    }

    pub fn rate_limit_exceeded(user_id: String, method: MfaMethod) -> Self {
        Self::new(
            MfaEventType::RateLimitExceeded,
            user_id,
            method,
            MfaResult::RateLimited,
        )
        .with_context(
            "rate_limit_type".to_string(),
            serde_json::Value::String("verification_attempts".to_string()),
        )
    }

    pub fn replay_attempt_detected(user_id: String) -> Self {
        Self::new(
            MfaEventType::ReplayAttempt,
            user_id,
            MfaMethod::TOTP,
            MfaResult::Blocked,
        )
        .with_risk_score(0.8)
    }

    pub fn suspicious_activity(user_id: String, reason: String) -> Self {
        Self::new(
            MfaEventType::SuspiciousActivity,
            user_id,
            MfaMethod::Unknown,
            MfaResult::Blocked,
        )
        .with_context("reason".to_string(), serde_json::Value::String(reason))
        .with_risk_score(0.9)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestSink {
        call_count: Arc<AtomicUsize>,
    }

    impl TestSink {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let counter = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    call_count: counter.clone(),
                },
                counter,
            )
        }
    }

    impl AuditSink for TestSink {
        fn log_event(&self, _event: &MfaAuditEvent) -> Result<(), AuditError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_audit_event_creation() {
        let event = MfaAuditEvent::totp_verification_success("user123".to_string())
            .with_ip_address("192.168.1.1".parse().unwrap())
            .with_user_agent("Mozilla/5.0".to_string())
            .with_risk_score(0.2);

        assert_eq!(event.user_id, "user123");
        assert!(matches!(event.event_type, MfaEventType::VerificationSuccess));
        assert!(matches!(event.method, MfaMethod::TOTP));
        assert!(matches!(event.result, MfaResult::Success));
        assert!(event.ip_address.is_some());
        assert!(event.user_agent.is_some());
        assert_eq!(event.risk_score, Some(0.2));
        assert!(matches!(event.security_level, SecurityLevel::Low));
    }

    #[tokio::test]
    async fn test_auditor_with_multiple_sinks() {
        let mut auditor = MfaAuditor::new();
        let (test_sink, counter) = TestSink::new();
        auditor.add_sink(Arc::new(test_sink));

        let event = MfaAuditEvent::totp_verification_success("user123".to_string());
        auditor.log_mfa_event(event).await.unwrap();

        // Give some time for async processing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Should have called both the default structured logger and our test sink
        assert!(counter.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn test_security_incident_detection() {
        let incident_manager = SecurityIncidentManager::new(3, 60); // 3 events in 1 minute

        // First two events should not trigger incident
        let event1 = MfaAuditEvent::rate_limit_exceeded("user123".to_string(), MfaMethod::TOTP);
        let event2 = MfaAuditEvent::replay_attempt_detected("user123".to_string());

        assert!(!incident_manager.process_event(&event1).await);
        assert!(!incident_manager.process_event(&event2).await);

        // Third event should trigger incident
        let event3 = MfaAuditEvent::suspicious_activity("user123".to_string(), "Multiple failed attempts".to_string());
        assert!(incident_manager.process_event(&event3).await);
    }

    #[test]
    fn test_event_security_classification() {
        let normal_event = MfaAuditEvent::totp_verification_success("user123".to_string());
        assert!(!normal_event.is_security_alert());
        assert!(!normal_event.should_trigger_notification());

        let security_event = MfaAuditEvent::rate_limit_exceeded("user123".to_string(), MfaMethod::TOTP);
        assert!(security_event.is_security_alert());
        assert!(security_event.should_trigger_notification());

        let high_risk_event = MfaAuditEvent::totp_verification_success("user123".to_string())
            .with_risk_score(0.9);
        assert!(high_risk_event.is_security_alert());
        assert!(high_risk_event.should_trigger_notification());
    }
}