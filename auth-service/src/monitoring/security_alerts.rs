//! Advanced Security Monitoring and Alerting System
//!
//! Provides comprehensive security event monitoring, threat detection,
//! and automated alerting for production environments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Security alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Security event types for monitoring
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecurityEventType {
    // Authentication events
    AuthenticationFailure,
    AuthenticationSuccess,
    PasswordBruteForce,
    CredentialStuffing,
    
    // Authorization events
    AuthorizationFailure,
    PrivilegeEscalation,
    UnauthorizedAccess,
    
    // Rate limiting events
    RateLimitExceeded,
    IpAddressBanned,
    SuspiciousActivity,
    
    // System security events
    TestModeViolation,
    ConfigurationTampering,
    CryptographicFailure,
    JwksRotationFailure,
    
    // Application security events
    SqlInjectionAttempt,
    XssAttempt,
    CsrfAttempt,
    PathTraversalAttempt,
    
    // Compliance events
    DataExfiltration,
    PiiAccess,
    AuditLogTampering,
}

/// Security event details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: AlertSeverity,
    pub timestamp: u64,
    pub source_ip: Option<IpAddr>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub user_agent: Option<String>,
    pub endpoint: Option<String>,
    pub message: String,
    pub metadata: HashMap<String, String>,
    pub count: u32,
}

/// Alert thresholds and configuration
#[derive(Debug, Clone)]
pub struct AlertConfiguration {
    // Time windows for threshold calculations
    pub short_window: Duration,  // 5 minutes
    pub medium_window: Duration, // 1 hour
    pub long_window: Duration,   // 24 hours
    
    // Threshold configurations
    pub failed_auth_threshold: u32,
    pub rate_limit_threshold: u32,
    pub suspicious_activity_threshold: u32,
    pub ip_ban_threshold: u32,
    
    // Alert channels
    pub enable_email_alerts: bool,
    pub enable_slack_alerts: bool,
    pub enable_pagerduty_alerts: bool,
    pub enable_siem_integration: bool,
}

impl Default for AlertConfiguration {
    fn default() -> Self {
        Self {
            short_window: Duration::from_secs(300),    // 5 minutes
            medium_window: Duration::from_secs(3600),  // 1 hour
            long_window: Duration::from_secs(86400),   // 24 hours
            
            failed_auth_threshold: 10,
            rate_limit_threshold: 100,
            suspicious_activity_threshold: 50,
            ip_ban_threshold: 5,
            
            enable_email_alerts: true,
            enable_slack_alerts: true,
            enable_pagerduty_alerts: false,
            enable_siem_integration: true,
        }
    }
}

/// Comprehensive security monitoring system
pub struct SecurityMonitor {
    config: AlertConfiguration,
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    metrics: Arc<SecurityMetrics>,
    alert_handlers: Vec<Box<dyn AlertHandler + Send + Sync>>,
}

/// Security metrics tracking
#[derive(Debug, Default)]
pub struct SecurityMetrics {
    pub total_events: AtomicU64,
    pub failed_authentications: AtomicU64,
    pub rate_limit_violations: AtomicU64,
    pub banned_ips: AtomicU64,
    pub suspicious_activities: AtomicU64,
    pub system_violations: AtomicU64,
    pub compliance_events: AtomicU64,
}

/// Alert handler trait for different notification channels
pub trait AlertHandler {
    async fn send_alert(&self, event: &SecurityEvent) -> Result<(), AlertError>;
    fn get_name(&self) -> &str;
}

#[derive(Debug, thiserror::Error)]
pub enum AlertError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl SecurityMonitor {
    pub fn new(config: AlertConfiguration) -> Self {
        Self {
            config,
            events: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(SecurityMetrics::default()),
            alert_handlers: Vec::new(),
        }
    }

    /// Add an alert handler
    pub fn add_alert_handler(&mut self, handler: Box<dyn AlertHandler + Send + Sync>) {
        self.alert_handlers.push(handler);
    }

    /// Record a security event and trigger alerting if needed
    pub async fn record_event(&self, mut event: SecurityEvent) {
        // Update timestamp
        event.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Update metrics
        self.update_metrics(&event);

        // Check if this event should trigger an alert
        if self.should_trigger_alert(&event).await {
            self.trigger_alert(&event).await;
        }

        // Store event
        let mut events = self.events.write().await;
        events.push(event);

        // Cleanup old events to prevent memory bloat
        self.cleanup_old_events(&mut events).await;
    }

    /// Update security metrics
    fn update_metrics(&self, event: &SecurityEvent) {
        self.metrics.total_events.fetch_add(1, Ordering::Relaxed);
        
        match event.event_type {
            SecurityEventType::AuthenticationFailure => {
                self.metrics.failed_authentications.fetch_add(1, Ordering::Relaxed);
            }
            SecurityEventType::RateLimitExceeded => {
                self.metrics.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
            }
            SecurityEventType::IpAddressBanned => {
                self.metrics.banned_ips.fetch_add(1, Ordering::Relaxed);
            }
            SecurityEventType::SuspiciousActivity => {
                self.metrics.suspicious_activities.fetch_add(1, Ordering::Relaxed);
            }
            SecurityEventType::TestModeViolation |
            SecurityEventType::ConfigurationTampering |
            SecurityEventType::CryptographicFailure => {
                self.metrics.system_violations.fetch_add(1, Ordering::Relaxed);
            }
            SecurityEventType::DataExfiltration |
            SecurityEventType::PiiAccess |
            SecurityEventType::AuditLogTampering => {
                self.metrics.compliance_events.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Determine if an event should trigger an alert
    async fn should_trigger_alert(&self, event: &SecurityEvent) -> bool {
        match event.severity {
            AlertSeverity::Emergency => true,
            AlertSeverity::Critical => true,
            AlertSeverity::Warning => {
                // Check for patterns that warrant alerting
                self.check_warning_thresholds(event).await
            }
            AlertSeverity::Info => false,
        }
    }

    /// Check if warning-level events have crossed thresholds
    async fn check_warning_thresholds(&self, event: &SecurityEvent) -> bool {
        let events = self.events.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Count similar events in the short window
        let short_window_start = now.saturating_sub(self.config.short_window.as_secs());
        let similar_events_count = events
            .iter()
            .filter(|e| {
                e.timestamp > short_window_start &&
                e.event_type == event.event_type &&
                e.source_ip == event.source_ip
            })
            .count() as u32;

        match event.event_type {
            SecurityEventType::AuthenticationFailure => {
                similar_events_count >= self.config.failed_auth_threshold
            }
            SecurityEventType::RateLimitExceeded => {
                similar_events_count >= self.config.rate_limit_threshold
            }
            SecurityEventType::SuspiciousActivity => {
                similar_events_count >= self.config.suspicious_activity_threshold
            }
            _ => false,
        }
    }

    /// Trigger alerts for the event
    async fn trigger_alert(&self, event: &SecurityEvent) {
        warn!(
            event_type = ?event.event_type,
            severity = ?event.severity,
            source_ip = ?event.source_ip,
            message = %event.message,
            "Security alert triggered"
        );

        // Send alerts through all configured handlers
        for handler in &self.alert_handlers {
            if let Err(e) = handler.send_alert(event).await {
                error!(
                    handler = handler.get_name(),
                    error = %e,
                    "Failed to send security alert"
                );
            }
        }

        // Log to structured format for SIEM integration
        self.log_structured_alert(event).await;
    }

    /// Log structured alert data for SIEM integration
    async fn log_structured_alert(&self, event: &SecurityEvent) {
        info!(
            target: "security_alert",
            event_type = ?event.event_type,
            severity = ?event.severity,
            timestamp = event.timestamp,
            source_ip = ?event.source_ip,
            user_id = ?event.user_id,
            session_id = ?event.session_id,
            user_agent = ?event.user_agent,
            endpoint = ?event.endpoint,
            message = %event.message,
            metadata = ?event.metadata,
            count = event.count,
            "Security alert generated"
        );
    }

    /// Cleanup old events to prevent memory bloat
    async fn cleanup_old_events(&self, events: &mut Vec<SecurityEvent>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let cutoff = now.saturating_sub(self.config.long_window.as_secs());
        
        events.retain(|event| event.timestamp > cutoff);
        
        // Also limit total events to prevent unbounded growth
        const MAX_EVENTS: usize = 10_000;
        if events.len() > MAX_EVENTS {
            events.drain(0..events.len() - MAX_EVENTS);
        }
    }

    /// Get current security metrics
    pub fn get_metrics(&self) -> SecurityMetricsSnapshot {
        SecurityMetricsSnapshot {
            total_events: self.metrics.total_events.load(Ordering::Relaxed),
            failed_authentications: self.metrics.failed_authentications.load(Ordering::Relaxed),
            rate_limit_violations: self.metrics.rate_limit_violations.load(Ordering::Relaxed),
            banned_ips: self.metrics.banned_ips.load(Ordering::Relaxed),
            suspicious_activities: self.metrics.suspicious_activities.load(Ordering::Relaxed),
            system_violations: self.metrics.system_violations.load(Ordering::Relaxed),
            compliance_events: self.metrics.compliance_events.load(Ordering::Relaxed),
        }
    }

    /// Generate security report for the specified time period
    pub async fn generate_security_report(&self, hours: u32) -> SecurityReport {
        let events = self.events.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let cutoff = now.saturating_sub((hours as u64) * 3600);
        
        let recent_events: Vec<_> = events
            .iter()
            .filter(|e| e.timestamp > cutoff)
            .cloned()
            .collect();

        SecurityReport {
            time_period_hours: hours,
            total_events: recent_events.len() as u32,
            events_by_type: self.count_events_by_type(&recent_events),
            events_by_severity: self.count_events_by_severity(&recent_events),
            top_source_ips: self.get_top_source_ips(&recent_events, 10),
            recommendations: self.generate_recommendations(&recent_events),
        }
    }

    fn count_events_by_type(&self, events: &[SecurityEvent]) -> HashMap<SecurityEventType, u32> {
        let mut counts = HashMap::new();
        for event in events {
            *counts.entry(event.event_type.clone()).or_insert(0) += 1;
        }
        counts
    }

    fn count_events_by_severity(&self, events: &[SecurityEvent]) -> HashMap<AlertSeverity, u32> {
        let mut counts = HashMap::new();
        for event in events {
            *counts.entry(event.severity).or_insert(0) += 1;
        }
        counts
    }

    fn get_top_source_ips(&self, events: &[SecurityEvent], limit: usize) -> Vec<(IpAddr, u32)> {
        let mut ip_counts = HashMap::new();
        for event in events {
            if let Some(ip) = event.source_ip {
                *ip_counts.entry(ip).or_insert(0) += 1;
            }
        }
        
        let mut sorted: Vec<_> = ip_counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    fn generate_recommendations(&self, events: &[SecurityEvent]) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        let failed_auth_count = events.iter()
            .filter(|e| e.event_type == SecurityEventType::AuthenticationFailure)
            .count();
        
        if failed_auth_count > 100 {
            recommendations.push(
                "High number of authentication failures detected. Consider implementing account lockout policies.".to_string()
            );
        }
        
        let rate_limit_count = events.iter()
            .filter(|e| e.event_type == SecurityEventType::RateLimitExceeded)
            .count();
        
        if rate_limit_count > 50 {
            recommendations.push(
                "Frequent rate limiting violations. Consider adjusting rate limit thresholds or investigating potential DDoS attacks.".to_string()
            );
        }
        
        // Add more sophisticated recommendation logic here
        
        recommendations
    }
}

/// Security metrics snapshot
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityMetricsSnapshot {
    pub total_events: u64,
    pub failed_authentications: u64,
    pub rate_limit_violations: u64,
    pub banned_ips: u64,
    pub suspicious_activities: u64,
    pub system_violations: u64,
    pub compliance_events: u64,
}

/// Security report structure
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityReport {
    pub time_period_hours: u32,
    pub total_events: u32,
    pub events_by_type: HashMap<SecurityEventType, u32>,
    pub events_by_severity: HashMap<AlertSeverity, u32>,
    pub top_source_ips: Vec<(IpAddr, u32)>,
    pub recommendations: Vec<String>,
}

/// Convenience functions for creating security events
impl SecurityEvent {
    pub fn authentication_failure(ip: IpAddr, user_id: Option<String>, message: String) -> Self {
        Self {
            event_type: SecurityEventType::AuthenticationFailure,
            severity: AlertSeverity::Warning,
            timestamp: 0, // Will be set by SecurityMonitor
            source_ip: Some(ip),
            user_id,
            session_id: None,
            user_agent: None,
            endpoint: None,
            message,
            metadata: HashMap::new(),
            count: 1,
        }
    }

    pub fn test_mode_violation(message: String) -> Self {
        Self {
            event_type: SecurityEventType::TestModeViolation,
            severity: AlertSeverity::Emergency,
            timestamp: 0,
            source_ip: None,
            user_id: None,
            session_id: None,
            user_agent: None,
            endpoint: None,
            message,
            metadata: HashMap::new(),
            count: 1,
        }
    }

    pub fn rate_limit_exceeded(ip: IpAddr, endpoint: String) -> Self {
        Self {
            event_type: SecurityEventType::RateLimitExceeded,
            severity: AlertSeverity::Warning,
            timestamp: 0,
            source_ip: Some(ip),
            user_id: None,
            session_id: None,
            user_agent: None,
            endpoint: Some(endpoint),
            message: format!("Rate limit exceeded for IP {} on endpoint {}", ip, endpoint),
            metadata: HashMap::new(),
            count: 1,
        }
    }

    pub fn ip_banned(ip: IpAddr, reason: String) -> Self {
        Self {
            event_type: SecurityEventType::IpAddressBanned,
            severity: AlertSeverity::Critical,
            timestamp: 0,
            source_ip: Some(ip),
            user_id: None,
            session_id: None,
            user_agent: None,
            endpoint: None,
            message: format!("IP address {} banned: {}", ip, reason),
            metadata: HashMap::new(),
            count: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_security_monitor_creation() {
        let config = AlertConfiguration::default();
        let monitor = SecurityMonitor::new(config);
        
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_events, 0);
    }

    #[tokio::test]
    async fn test_event_recording() {
        let config = AlertConfiguration::default();
        let monitor = SecurityMonitor::new(config);
        
        let event = SecurityEvent::authentication_failure(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            Some("test_user".to_string()),
            "Invalid password".to_string(),
        );
        
        monitor.record_event(event).await;
        
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_events, 1);
        assert_eq!(metrics.failed_authentications, 1);
    }

    #[tokio::test]
    async fn test_security_report_generation() {
        let config = AlertConfiguration::default();
        let monitor = SecurityMonitor::new(config);
        
        // Record some events
        for i in 0..5 {
            let event = SecurityEvent::authentication_failure(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, i)),
                Some(format!("user_{}", i)),
                "Test failure".to_string(),
            );
            monitor.record_event(event).await;
        }
        
        let report = monitor.generate_security_report(1).await;
        assert_eq!(report.total_events, 5);
        assert!(report.events_by_type.contains_key(&SecurityEventType::AuthenticationFailure));
    }
}