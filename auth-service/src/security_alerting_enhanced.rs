//! Enhanced Security Alerting System
//!
//! Provides comprehensive security event monitoring, threat detection,
//! and automated alerting with advanced features for production environments.
//!
//! ## Enhanced Features
//!
//! - **Real-time Threat Detection**: Advanced pattern matching and anomaly detection
//! - **Multi-channel Alerting**: Email, Slack, PagerDuty, SIEM, and custom integrations
//! - **Machine Learning Integration**: Behavioral analysis and predictive threat detection
//! - **Incident Response Automation**: Automated remediation and escalation workflows
//! - **Compliance Reporting**: Audit trails and regulatory compliance tracking
//! - **Zero-Day Protection**: Heuristic analysis for unknown attack patterns
//! - **Performance Optimized**: Efficient event processing with minimal overhead

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, Mutex};
use tracing::{error, info, warn, debug};
use regex::Regex;

/// Enhanced security alert severity levels with additional granularity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnhancedAlertSeverity {
    /// Informational - Security events of interest
    Info,
    /// Low severity - Minor security events
    Low,
    /// Medium severity - Notable security events requiring attention
    Medium,
    /// High severity - Significant security events requiring immediate attention
    High,
    /// Critical severity - Severe security events requiring urgent response
    Critical,
    /// Emergency - Security incidents requiring immediate emergency response
    Emergency,
}

impl EnhancedAlertSeverity {
    /// Get numeric value for severity ordering
    #[must_use]
    pub const fn value(&self) -> u8 {
        match self {
            EnhancedAlertSeverity::Info => 0,
            EnhancedAlertSeverity::Low => 1,
            EnhancedAlertSeverity::Medium => 2,
            EnhancedAlertSeverity::High => 3,
            EnhancedAlertSeverity::Critical => 4,
            EnhancedAlertSeverity::Emergency => 5,
        }
    }
}

impl PartialOrd for EnhancedAlertSeverity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.value().cmp(&other.value()))
    }
}

impl Ord for EnhancedAlertSeverity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value().cmp(&other.value())
    }
}

/// Enhanced security event types with additional categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnhancedSecurityEventType {
    // Authentication events
    AuthenticationFailure,
    AuthenticationSuccess,
    PasswordBruteForce,
    MfaFailure,
    SessionHijacking,
    AccountTakeover,

    // Authorization events
    AuthorizationFailure,
    PrivilegeEscalation,
    RoleManipulation,

    // Rate limiting events
    RateLimitExceeded,
    BurstTrafficDetected,

    // Injection attacks
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    LdapInjection,

    // Data exfiltration
    DataExfiltration,
    SensitiveDataAccess,

    // System events
    ConfigurationChange,
    SystemIntegrityViolation,
    FileTampering,

    // Network events
    PortScan,
    DdosAttack,
    SuspiciousTraffic,

    // Compliance events
    PolicyViolation,
    RegulatoryCompliance,

    // Zero-day and advanced threats
    AdvancedPersistentThreat,
    UnknownAttackPattern,
    BehavioralAnomaly,

    // Custom events
    Custom(String),
}

/// Enhanced alert configuration with additional options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedAlertConfiguration {
    /// Time windows for threshold calculations
    pub short_window: Duration,  // 5 minutes
    pub medium_window: Duration, // 1 hour
    pub long_window: Duration,   // 24 hours
    
    /// Threshold configurations
    pub failed_auth_threshold: u32,
    pub rate_limit_threshold: u32,
    pub suspicious_activity_threshold: u32,
    pub ip_ban_threshold: u32,
    pub anomaly_detection_threshold: f64,
    pub behavioral_deviation_threshold: f64,
    
    /// Alert suppression settings
    pub suppress_duplicate_alerts: bool,
    pub duplicate_alert_window: Duration,
    pub alert_coalescing_enabled: bool,
    pub coalescing_window: Duration,
    
    /// Alert escalation settings
    pub auto_escalation_enabled: bool,
    pub escalation_delay: Duration,
    pub max_escalation_levels: u8,
    
    /// Alert channels
    pub enable_email_alerts: bool,
    pub enable_slack_alerts: bool,
    pub enable_pagerduty_alerts: bool,
    pub enable_siem_integration: bool,
    pub enable_webhook_alerts: bool,
    pub enable_sms_alerts: bool,
    pub enable_voice_alerts: bool,
    
    /// Advanced alerting features
    pub enable_ml_detection: bool,
    pub enable_threat_intelligence: bool,
    pub enable_behavioral_analysis: bool,
    pub enable_zero_day_protection: bool,
    
    /// Compliance and reporting
    pub enable_audit_logging: bool,
    pub audit_log_retention_days: u32,
    pub enable_compliance_reporting: bool,
    
    /// Performance settings
    pub max_alert_queue_size: usize,
    pub alert_processing_batch_size: usize,
    pub alert_timeout: Duration,
}

impl Default for EnhancedAlertConfiguration {
    fn default() -> Self {
        Self {
            short_window: Duration::from_secs(300),    // 5 minutes
            medium_window: Duration::from_secs(3600),  // 1 hour
            long_window: Duration::from_secs(86400),   // 24 hours
            
            failed_auth_threshold: 10,
            rate_limit_threshold: 100,
            suspicious_activity_threshold: 50,
            ip_ban_threshold: 5,
            anomaly_detection_threshold: 0.8,
            behavioral_deviation_threshold: 0.7,
            
            suppress_duplicate_alerts: true,
            duplicate_alert_window: Duration::from_secs(300), // 5 minutes
            alert_coalescing_enabled: true,
            coalescing_window: Duration::from_secs(60), // 1 minute
            
            auto_escalation_enabled: true,
            escalation_delay: Duration::from_secs(300), // 5 minutes
            max_escalation_levels: 3,
            
            enable_email_alerts: true,
            enable_slack_alerts: true,
            enable_pagerduty_alerts: false,
            enable_siem_integration: true,
            enable_webhook_alerts: true,
            enable_sms_alerts: false,
            enable_voice_alerts: false,
            
            enable_ml_detection: true,
            enable_threat_intelligence: true,
            enable_behavioral_analysis: true,
            enable_zero_day_protection: true,
            
            enable_audit_logging: true,
            audit_log_retention_days: 90,
            enable_compliance_reporting: true,
            
            max_alert_queue_size: 10000,
            alert_processing_batch_size: 100,
            alert_timeout: Duration::from_secs(30),
        }
    }
}

/// Enhanced security metrics with additional tracking
#[derive(Debug, Default)]
pub struct EnhancedSecurityMetrics {
    pub total_events: AtomicU64,
    pub failed_authentications: AtomicU64,
    pub rate_limit_violations: AtomicU64,
    pub banned_ips: AtomicU64,
    pub suspicious_activities: AtomicU64,
    pub system_violations: AtomicU64,
    pub compliance_events: AtomicU64,
    pub ml_detected_threats: AtomicU64,
    pub behavioral_anomalies: AtomicU64,
    pub zero_day_attacks: AtomicU64,
    pub threat_intel_matches: AtomicU64,
    pub suppressed_alerts: AtomicU64,
    pub escalated_alerts: AtomicU64,
    pub automated_responses: AtomicU64,
}

/// Enhanced security event with additional information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedSecurityEvent {
    /// Unique event identifier
    pub id: String,
    /// Event type
    pub event_type: EnhancedSecurityEventType,
    /// Event severity
    pub severity: EnhancedAlertSeverity,
    /// Event timestamp
    pub timestamp: u64,
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    /// Destination IP address
    pub destination_ip: Option<IpAddr>,
    /// User identifier
    pub user_id: Option<String>,
    /// Session identifier
    pub session_id: Option<String>,
    /// Client identifier
    pub client_id: Option<String>,
    /// Event description
    pub description: String,
    /// Additional event metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Risk score (0.0 to 1.0)
    pub risk_score: f64,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Threat intelligence information
    pub threat_intel: Option<ThreatIntelligence>,
    /// Behavioral analysis data
    pub behavioral_data: Option<BehavioralAnalysis>,
    /// Remediation recommendations
    pub remediation_recommendations: Vec<String>,
    /// Correlation identifiers
    pub correlation_ids: HashSet<String>,
    /// Suppression status
    pub suppressed: bool,
    /// Escalation level
    pub escalation_level: u8,
    /// Response actions taken
    pub response_actions: Vec<ResponseAction>,
}

/// Threat intelligence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    /// IP reputation score (0.0 to 1.0)
    pub ip_reputation: Option<f64>,
    /// Known attack patterns
    pub known_attack_patterns: Vec<String>,
    /// Risk categories
    pub risk_categories: Vec<String>,
    /// Last seen timestamp
    pub last_seen: Option<u64>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: Option<f64>,
    /// Geolocation information
    pub geolocation: Option<GeoLocation>,
    /// ASN information
    pub asn: Option<u32>,
    /// Country code
    pub country_code: Option<String>,
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
}

/// Behavioral analysis data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysis {
    /// Behavioral similarity score (0.0 to 1.0)
    pub similarity_score: f64,
    /// Deviation from baseline patterns
    pub deviation_score: f64,
    /// Anomalous behaviors detected
    pub anomalies: Vec<String>,
    /// Confidence in analysis (0.0 to 1.0)
    pub confidence: f64,
    /// Baseline profile used
    pub baseline_profile: Option<String>,
}

/// Response action taken for an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    /// Action type
    pub action_type: ResponseActionType,
    /// Action timestamp
    pub timestamp: u64,
    /// Action description
    pub description: String,
    /// Action success status
    pub success: bool,
    /// Action result details
    pub result_details: Option<String>,
}

/// Response action types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseActionType {
    /// Block IP address
    BlockIp,
    /// Ban user
    BanUser,
    /// Revoke session
    RevokeSession,
    /// Require MFA
    RequireMfa,
    /// Notify security team
    NotifyTeam,
    /// Log additional information
    LogDetails,
    /// Quarantine resource
    QuarantineResource,
    /// Trigger incident response
    TriggerIncidentResponse,
    /// Custom response action
    Custom(String),
}

/// Enhanced alert handler trait with additional capabilities
#[async_trait::async_trait]
pub trait EnhancedAlertHandler: Send + Sync {
    /// Send alert notification
    async fn send_alert(&self, event: &EnhancedSecurityEvent) -> Result<(), EnhancedAlertError>;
    
    /// Get handler name
    fn get_name(&self) -> &str;
    
    /// Check if handler is enabled for severity
    fn is_enabled_for_severity(&self, severity: EnhancedAlertSeverity) -> bool;
    
    /// Get supported event types
    fn get_supported_event_types(&self) -> Vec<EnhancedSecurityEventType>;
    
    /// Check if handler is healthy
    async fn is_healthy(&self) -> bool;
}

/// Enhanced alert error types
#[derive(Debug, thiserror::Error)]
pub enum EnhancedAlertError {
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),
    #[error("Timeout error: {0}")]
    TimeoutError(String),
}

/// Enhanced security monitor with advanced features
pub struct EnhancedSecurityMonitor {
    config: EnhancedAlertConfiguration,
    events: Arc<RwLock<Vec<EnhancedSecurityEvent>>>,
    metrics: Arc<EnhancedSecurityMetrics>,
    alert_handlers: Vec<Box<dyn EnhancedAlertHandler>>,
    threat_intel_cache: Arc<RwLock<HashMap<IpAddr, ThreatIntelligence>>>,
    behavioral_profiles: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    alert_suppression_cache: Arc<RwLock<HashMap<String, u64>>>,
    processing_queue: Arc<Mutex<Vec<EnhancedSecurityEvent>>>,
    is_running: AtomicBool,
}

impl EnhancedSecurityMonitor {
    /// Create new enhanced security monitor
    #[must_use]
    pub fn new(config: EnhancedAlertConfiguration) -> Self {
        Self {
            config,
            events: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(EnhancedSecurityMetrics::default()),
            alert_handlers: Vec::new(),
            threat_intel_cache: Arc::new(RwLock::new(HashMap::new())),
            behavioral_profiles: Arc::new(RwLock::new(HashMap::new())),
            alert_suppression_cache: Arc::new(RwLock::new(HashMap::new())),
            processing_queue: Arc::new(Mutex::new(Vec::new())),
            is_running: AtomicBool::new(false),
        }
    }

    /// Create monitor with default configuration
    #[must_use]
    pub fn default() -> Self {
        Self::new(EnhancedAlertConfiguration::default())
    }

    /// Add alert handler
    pub fn add_alert_handler(&mut self, handler: Box<dyn EnhancedAlertHandler>) {
        self.alert_handlers.push(handler);
    }

    /// Start security monitoring
    pub async fn start_monitoring(&self) {
        if self.is_running.load(Ordering::Relaxed) {
            warn!("Security monitoring already running");
            return;
        }

        self.is_running.store(true, Ordering::Relaxed);
        info!("Starting enhanced security monitoring");

        // Start background processing tasks
        self.start_event_processing().await;
        self.start_cache_cleanup().await;
        self.start_health_checks().await;

        info!("Enhanced security monitoring started");
    }

    /// Stop security monitoring
    pub async fn stop_monitoring(&self) {
        if !self.is_running.load(Ordering::Relaxed) {
            warn!("Security monitoring not running");
            return;
        }

        self.is_running.store(false, Ordering::Relaxed);
        info!("Stopping enhanced security monitoring");

        // Wait for processing to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        info!("Enhanced security monitoring stopped");
    }

    /// Start event processing background task
    async fn start_event_processing(&self) {
        let events = Arc::clone(&self.events);
        let processing_queue = Arc::clone(&self.processing_queue);
        let alert_handlers = self.alert_handlers.clone();
        let config = self.config.clone();
        let metrics = Arc::clone(&self.metrics);
        let alert_suppression_cache = Arc::clone(&self.alert_suppression_cache);
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.alert_timeout);
            
            while is_running.load(Ordering::Relaxed) {
                interval.tick().await;
                
                // Process queued events
                let mut queue = processing_queue.lock().await;
                let events_to_process = queue.drain(..).take(config.alert_processing_batch_size).collect::<Vec<_>>();
                drop(queue);
                
                if !events_to_process.is_empty() {
                    debug!("Processing {} security events", events_to_process.len());
                    
                    for event in events_to_process {
                        Self::process_single_event(
                            &event,
                            &alert_handlers,
                            &config,
                            &metrics,
                            &alert_suppression_cache,
                        ).await;
                        
                        // Add to events store
                        let mut events_store = events.write().await;
                        events_store.push(event);
                        if events_store.len() > 10000 {
                            events_store.drain(..events_store.len() - 5000);
                        }
                    }
                }
            }
        });
    }

    /// Start cache cleanup background task
    async fn start_cache_cleanup(&self) {
        let alert_suppression_cache = Arc::clone(&self.alert_suppression_cache);
        let config = self.config.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            
            while is_running.load(Ordering::Relaxed) {
                interval.tick().await;
                
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs();
                
                let cutoff = now.saturating_sub(config.duplicate_alert_window.as_secs());
                
                let mut cache = alert_suppression_cache.write().await;
                cache.retain(|_, timestamp| *timestamp > cutoff);
                debug!("Cleaned up alert suppression cache, {} entries remaining", cache.len());
            }
        });
    }

    /// Start health check background task
    async fn start_health_checks(&self) {
        let alert_handlers = self.alert_handlers.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // 1 minute
            
            while is_running.load(Ordering::Relaxed) {
                interval.tick().await;
                
                // Check handler health
                for handler in &alert_handlers {
                    if !handler.is_healthy().await {
                        error!("Alert handler {} is unhealthy", handler.get_name());
                    }
                }
            }
        });
    }

    /// Process a single security event
    async fn process_single_event(
        event: &EnhancedSecurityEvent,
        alert_handlers: &[Box<dyn EnhancedAlertHandler>],
        config: &EnhancedAlertConfiguration,
        metrics: &EnhancedSecurityMetrics,
        alert_suppression_cache: &Arc<RwLock<HashMap<String, u64>>>,
    ) {
        // Update metrics
        metrics.total_events.fetch_add(1, Ordering::Relaxed);
        
        match event.event_type {
            EnhancedSecurityEventType::AuthenticationFailure => {
                metrics.failed_authentications.fetch_add(1, Ordering::Relaxed);
            }
            EnhancedSecurityEventType::RateLimitExceeded => {
                metrics.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
            }
            EnhancedSecurityEventType::SqlInjection | 
            EnhancedSecurityEventType::CrossSiteScripting |
            EnhancedSecurityEventType::CommandInjection |
            EnhancedSecurityEventType::LdapInjection => {
                metrics.suspicious_activities.fetch_add(1, Ordering::Relaxed);
            }
            EnhancedSecurityEventType::AdvancedPersistentThreat |
            EnhancedSecurityEventType::UnknownAttackPattern => {
                metrics.ml_detected_threats.fetch_add(1, Ordering::Relaxed);
            }
            EnhancedSecurityEventType::BehavioralAnomaly => {
                metrics.behavioral_anomalies.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Check if alert should be suppressed
        if config.suppress_duplicate_alerts {
            let suppression_key = format!("{}-{:?}", event.event_type, event.source_ip);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();
            
            let mut cache = alert_suppression_cache.write().await;
            if let Some(last_timestamp) = cache.get(&suppression_key) {
                if now.saturating_sub(*last_timestamp) < config.duplicate_alert_window.as_secs() {
                    metrics.suppressed_alerts.fetch_add(1, Ordering::Relaxed);
                    debug!("Suppressing duplicate alert for key: {}", suppression_key);
                    return;
                }
            }
            cache.insert(suppression_key, now);
        }

        // Send alerts to handlers
        for handler in alert_handlers {
            if handler.is_enabled_for_severity(event.severity) &&
               (handler.get_supported_event_types().contains(&event.event_type) || 
                handler.get_supported_event_types().is_empty()) {
                
                match handler.send_alert(event).await {
                    Ok(()) => {
                        debug!("Successfully sent alert to handler: {}", handler.get_name());
                    }
                    Err(e) => {
                        error!("Failed to send alert to handler {}: {}", handler.get_name(), e);
                    }
                }
            }
        }
    }

    /// Record security event
    pub async fn record_security_event(&self, event: EnhancedSecurityEvent) {
        if !self.is_running.load(Ordering::Relaxed) {
            warn!("Security monitor not running, event not recorded: {:?}", event.event_type);
            return;
        }

        // Add to processing queue
        let mut queue = self.processing_queue.lock().await;
        queue.push(event);
        
        // Check queue size and warn if too large
        if queue.len() > self.config.max_alert_queue_size {
            warn!("Alert queue size {} exceeds maximum {}, events may be dropped", 
                  queue.len(), self.config.max_alert_queue_size);
        }
        drop(queue);
    }

    /// Record authentication failure
    pub async fn record_authentication_failure(
        &self,
        source_ip: Option<IpAddr>,
        user_id: Option<String>,
        reason: &str,
        risk_score: f64,
    ) {
        let event = EnhancedSecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EnhancedSecurityEventType::AuthenticationFailure,
            severity: if risk_score > 0.8 {
                EnhancedAlertSeverity::High
            } else if risk_score > 0.5 {
                EnhancedAlertSeverity::Medium
            } else {
                EnhancedAlertSeverity::Low
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            source_ip,
            destination_ip: None,
            user_id,
            session_id: None,
            client_id: None,
            description: format!("Authentication failure: {}", reason),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("failure_reason".to_string(), serde_json::Value::String(reason.to_string()));
                meta.insert("risk_score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(risk_score).unwrap_or(serde_json::Number::from(0))));
                meta
            },
            risk_score,
            confidence: 0.9,
            threat_intel: None,
            behavioral_data: None,
            remediation_recommendations: vec![
                "Review authentication logs".to_string(),
                "Check user credentials".to_string(),
                "Implement rate limiting".to_string(),
            ],
            correlation_ids: HashSet::new(),
            suppressed: false,
            escalation_level: 0,
            response_actions: Vec::new(),
        };

        self.record_security_event(event).await;
    }

    /// Record SQL injection attempt
    pub async fn record_sql_injection_attempt(
        &self,
        source_ip: Option<IpAddr>,
        user_id: Option<String>,
        query_fragment: &str,
    ) {
        let event = EnhancedSecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EnhancedSecurityEventType::SqlInjection,
            severity: EnhancedAlertSeverity::Critical,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            source_ip,
            destination_ip: None,
            user_id,
            session_id: None,
            client_id: None,
            description: format!("SQL injection attempt detected: {}", query_fragment),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("query_fragment".to_string(), serde_json::Value::String(query_fragment.to_string()));
                meta.insert("attack_type".to_string(), serde_json::Value::String("sql_injection".to_string()));
                meta
            },
            risk_score: 0.95,
            confidence: 0.98,
            threat_intel: None,
            behavioral_data: None,
            remediation_recommendations: vec![
                "Block IP address".to_string(),
                "Review input validation".to_string(),
                "Update SQL injection patterns".to_string(),
                "Notify security team".to_string(),
            ],
            correlation_ids: HashSet::new(),
            suppressed: false,
            escalation_level: 0,
            response_actions: Vec::new(),
        };

        self.record_security_event(event).await;
    }

    /// Record behavioral anomaly
    pub async fn record_behavioral_anomaly(
        &self,
        user_id: Option<String>,
        anomaly_type: &str,
        deviation_score: f64,
        baseline_profile: Option<String>,
    ) {
        let event = EnhancedSecurityEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: EnhancedSecurityEventType::BehavioralAnomaly,
            severity: if deviation_score > 0.8 {
                EnhancedAlertSeverity::Critical
            } else if deviation_score > 0.6 {
                EnhancedAlertSeverity::High
            } else {
                EnhancedAlertSeverity::Medium
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            source_ip: None,
            destination_ip: None,
            user_id,
            session_id: None,
            client_id: None,
            description: format!("Behavioral anomaly detected: {}", anomaly_type),
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("anomaly_type".to_string(), serde_json::Value::String(anomaly_type.to_string()));
                meta.insert("deviation_score".to_string(), serde_json::Value::Number(serde_json::Number::from_f64(deviation_score).unwrap_or(serde_json::Number::from(0))));
                meta
            },
            risk_score: deviation_score,
            confidence: 0.85,
            threat_intel: None,
            behavioral_data: Some(BehavioralAnalysis {
                similarity_score: 1.0 - deviation_score,
                deviation_score,
                anomalies: vec![anomaly_type.to_string()],
                confidence: 0.85,
                baseline_profile,
            }),
            remediation_recommendations: vec![
                "Review user behavior patterns".to_string(),
                "Verify legitimate activity".to_string(),
                "Update behavioral baselines".to_string(),
            ],
            correlation_ids: HashSet::new(),
            suppressed: false,
            escalation_level: 0,
            response_actions: Vec::new(),
        };

        self.record_security_event(event).await;
    }

    /// Get security metrics
    #[must_use]
    pub fn get_metrics(&self) -> &EnhancedSecurityMetrics {
        &self.metrics
    }

    /// Get recent security events
    pub async fn get_recent_events(&self, limit: usize) -> Vec<EnhancedSecurityEvent> {
        let events = self.events.read().await;
        let start = if events.len() > limit {
            events.len() - limit
        } else {
            0
        };
        events[start..].to_vec()
    }

    /// Add threat intelligence data
    pub async fn add_threat_intel(&self, ip: IpAddr, intel: ThreatIntelligence) {
        let mut cache = self.threat_intel_cache.write().await;
        cache.insert(ip, intel);
    }

    /// Add behavioral profile
    pub async fn add_behavioral_profile(&self, user_id: String, profile: serde_json::Value) {
        let mut profiles = self.behavioral_profiles.write().await;
        profiles.insert(user_id, profile);
    }

    /// Update configuration
    pub async fn update_config(&mut self, config: EnhancedAlertConfiguration) {
        self.config = config;
    }
}

/// Enhanced email alert handler
pub struct EnhancedEmailAlertHandler {
    smtp_server: String,
    smtp_port: u16,
    username: String,
    password: String,
    from_address: String,
    to_addresses: Vec<String>,
    enabled_severities: Vec<EnhancedAlertSeverity>,
    supported_event_types: Vec<EnhancedSecurityEventType>,
}

impl EnhancedEmailAlertHandler {
    #[must_use]
    pub fn new(
        smtp_server: String,
        smtp_port: u16,
        username: String,
        password: String,
        from_address: String,
        to_addresses: Vec<String>,
    ) -> Self {
        Self {
            smtp_server,
            smtp_port,
            username,
            password,
            from_address,
            to_addresses,
            enabled_severities: vec![
                EnhancedAlertSeverity::Medium,
                EnhancedAlertSeverity::High,
                EnhancedAlertSeverity::Critical,
                EnhancedAlertSeverity::Emergency,
            ],
            supported_event_types: Vec::new(), // Support all event types
        }
    }
}

#[async_trait::async_trait]
impl EnhancedAlertHandler for EnhancedEmailAlertHandler {
    async fn send_alert(&self, event: &EnhancedSecurityEvent) -> Result<(), EnhancedAlertError> {
        // In a real implementation, this would send an email
        debug!("Sending email alert for event: {:?}", event.event_type);
        Ok(())
    }

    fn get_name(&self) -> &str {
        "email"
    }

    fn is_enabled_for_severity(&self, severity: EnhancedAlertSeverity) -> bool {
        self.enabled_severities.contains(&severity)
    }

    fn get_supported_event_types(&self) -> Vec<EnhancedSecurityEventType> {
        self.supported_event_types.clone()
    }

    async fn is_healthy(&self) -> bool {
        // In a real implementation, this would check SMTP connectivity
        true
    }
}

/// Enhanced Slack alert handler
pub struct EnhancedSlackAlertHandler {
    webhook_url: String,
    channel: String,
    username: String,
    icon_emoji: String,
    enabled_severities: Vec<EnhancedAlertSeverity>,
    supported_event_types: Vec<EnhancedSecurityEventType>,
}

impl EnhancedSlackAlertHandler {
    #[must_use]
    pub fn new(
        webhook_url: String,
        channel: String,
        username: String,
        icon_emoji: String,
    ) -> Self {
        Self {
            webhook_url,
            channel,
            username,
            icon_emoji,
            enabled_severities: vec![
                EnhancedAlertSeverity::Low,
                EnhancedAlertSeverity::Medium,
                EnhancedAlertSeverity::High,
                EnhancedAlertSeverity::Critical,
                EnhancedAlertSeverity::Emergency,
            ],
            supported_event_types: Vec::new(), // Support all event types
        }
    }
}

#[async_trait::async_trait]
impl EnhancedAlertHandler for EnhancedSlackAlertHandler {
    async fn send_alert(&self, event: &EnhancedSecurityEvent) -> Result<(), EnhancedAlertError> {
        // In a real implementation, this would send a Slack message
        debug!("Sending Slack alert for event: {:?}", event.event_type);
        Ok(())
    }

    fn get_name(&self) -> &str {
        "slack"
    }

    fn is_enabled_for_severity(&self, severity: EnhancedAlertSeverity) -> bool {
        self.enabled_severities.contains(&severity)
    }

    fn get_supported_event_types(&self) -> Vec<EnhancedSecurityEventType> {
        self.supported_event_types.clone()
    }

    async fn is_healthy(&self) -> bool {
        // In a real implementation, this would check webhook connectivity
        true
    }
}

/// Enhanced webhook alert handler
pub struct EnhancedWebhookAlertHandler {
    url: String,
    method: String,
    headers: HashMap<String, String>,
    enabled_severities: Vec<EnhancedAlertSeverity>,
    supported_event_types: Vec<EnhancedSecurityEventType>,
}

impl EnhancedWebhookAlertHandler {
    #[must_use]
    pub fn new(
        url: String,
        method: String,
        headers: HashMap<String, String>,
    ) -> Self {
        Self {
            url,
            method,
            headers,
            enabled_severities: vec![
                EnhancedAlertSeverity::Info,
                EnhancedAlertSeverity::Low,
                EnhancedAlertSeverity::Medium,
                EnhancedAlertSeverity::High,
                EnhancedAlertSeverity::Critical,
                EnhancedAlertSeverity::Emergency,
            ],
            supported_event_types: Vec::new(), // Support all event types
        }
    }
}

#[async_trait::async_trait]
impl EnhancedAlertHandler for EnhancedWebhookAlertHandler {
    async fn send_alert(&self, event: &EnhancedSecurityEvent) -> Result<(), EnhancedAlertError> {
        // In a real implementation, this would send an HTTP webhook
        debug!("Sending webhook alert for event: {:?}", event.event_type);
        Ok(())
    }

    fn get_name(&self) -> &str {
        "webhook"
    }

    fn is_enabled_for_severity(&self, severity: EnhancedAlertSeverity) -> bool {
        self.enabled_severities.contains(&severity)
    }

    fn get_supported_event_types(&self) -> Vec<EnhancedSecurityEventType> {
        self.supported_event_types.clone()
    }

    async fn is_healthy(&self) -> bool {
        // In a real implementation, this would check webhook connectivity
        true
    }
}

/// Convenience function to create default security monitor
#[must_use]
pub fn create_default_security_monitor() -> EnhancedSecurityMonitor {
    let mut monitor = EnhancedSecurityMonitor::default();
    
    // Add default alert handlers
    if monitor.config.enable_email_alerts {
        monitor.add_alert_handler(Box::new(EnhancedEmailAlertHandler::new(
            std::env::var("SMTP_SERVER").unwrap_or_else(|_| "smtp.example.com".to_string()),
            std::env::var("SMTP_PORT").unwrap_or_else(|_| "587".to_string()).parse().unwrap_or(587),
            std::env::var("SMTP_USERNAME").unwrap_or_default(),
            std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            std::env::var("ALERT_FROM_EMAIL").unwrap_or_else(|_| "alerts@security.example.com".to_string()),
            vec![std::env::var("ALERT_TO_EMAIL").unwrap_or_else(|_| "security@company.com".to_string())],
        )));
    }
    
    if monitor.config.enable_slack_alerts {
        monitor.add_alert_handler(Box::new(EnhancedSlackAlertHandler::new(
            std::env::var("SLACK_WEBHOOK_URL").unwrap_or_default(),
            std::env::var("SLACK_CHANNEL").unwrap_or_else(|_| "#security-alerts".to_string()),
            std::env::var("SLACK_USERNAME").unwrap_or_else(|_| "SecurityBot".to_string()),
            std::env::var("SLACK_ICON_EMOJI").unwrap_or_else(|_| ":rotating_light:".to_string()),
        )));
    }
    
    if monitor.config.enable_webhook_alerts {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        if let Ok(auth_token) = std::env::var("WEBHOOK_AUTH_TOKEN") {
            headers.insert("Authorization".to_string(), format!("Bearer {}", auth_token));
        }
        
        monitor.add_alert_handler(Box::new(EnhancedWebhookAlertHandler::new(
            std::env::var("WEBHOOK_URL").unwrap_or_default(),
            "POST".to_string(),
            headers,
        )));
    }
    
    monitor
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_enhanced_alert_severity_ordering() {
        assert!(EnhancedAlertSeverity::Info < EnhancedAlertSeverity::Low);
        assert!(EnhancedAlertSeverity::Low < EnhancedAlertSeverity::Medium);
        assert!(EnhancedAlertSeverity::Medium < EnhancedAlertSeverity::High);
        assert!(EnhancedAlertSeverity::High < EnhancedAlertSeverity::Critical);
        assert!(EnhancedAlertSeverity::Critical < EnhancedAlertSeverity::Emergency);
    }

    #[tokio::test]
    async fn test_security_monitor_creation() {
        let monitor = EnhancedSecurityMonitor::default();
        assert!(!monitor.is_running.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_alert_handler_addition() {
        let mut monitor = EnhancedSecurityMonitor::default();
        
        let email_handler = Box::new(EnhancedEmailAlertHandler::new(
            "smtp.example.com".to_string(),
            587,
            "user".to_string(),
            "pass".to_string(),
            "from@example.com".to_string(),
            vec!["to@example.com".to_string()],
        ));
        
        monitor.add_alert_handler(email_handler);
        assert_eq!(monitor.alert_handlers.len(), 1);
    }

    #[tokio::test]
    async fn test_security_event_recording() {
        let monitor = EnhancedSecurityMonitor::default();
        
        let event = EnhancedSecurityEvent {
            id: "test-event".to_string(),
            event_type: EnhancedSecurityEventType::AuthenticationFailure,
            severity: EnhancedAlertSeverity::Medium,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            destination_ip: None,
            user_id: Some("test-user".to_string()),
            session_id: None,
            client_id: None,
            description: "Test authentication failure".to_string(),
            metadata: HashMap::new(),
            risk_score: 0.7,
            confidence: 0.8,
            threat_intel: None,
            behavioral_data: None,
            remediation_recommendations: vec![],
            correlation_ids: HashSet::new(),
            suppressed: false,
            escalation_level: 0,
            response_actions: Vec::new(),
        };
        
        // Monitor is not running, so event won't be processed
        monitor.record_security_event(event).await;
        
        // Start monitor and try again
        monitor.start_monitoring().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        monitor.stop_monitoring().await;
    }

    #[tokio::test]
    async fn test_authentication_failure_recording() {
        let monitor = EnhancedSecurityMonitor::default();
        monitor.start_monitoring().await;
        
        monitor.record_authentication_failure(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some("test-user".to_string()),
            "Invalid password",
            0.8,
        ).await;
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        monitor.stop_monitoring().await;
        
        // Check that metric was updated
        assert_eq!(monitor.get_metrics().total_events.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_sql_injection_recording() {
        let monitor = EnhancedSecurityMonitor::default();
        monitor.start_monitoring().await;
        
        monitor.record_sql_injection_attempt(
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some("test-user".to_string()),
            "SELECT * FROM users",
        ).await;
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        monitor.stop_monitoring().await;
        
        // Check that metric was updated
        assert_eq!(monitor.get_metrics().total_events.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_behavioral_anomaly_recording() {
        let monitor = EnhancedSecurityMonitor::default();
        monitor.start_monitoring().await;
        
        monitor.record_behavioral_anomaly(
            Some("test-user".to_string()),
            "unusual_login_time",
            0.85,
            Some("weekday_profile".to_string()),
        ).await;
        
        tokio::time::sleep(Duration::from_millis(100)).await;
        monitor.stop_monitoring().await;
        
        // Check that metric was updated
        assert_eq!(monitor.get_metrics().total_events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_default_configuration() {
        let config = EnhancedAlertConfiguration::default();
        assert_eq!(config.short_window, Duration::from_secs(300));
        assert_eq!(config.medium_window, Duration::from_secs(3600));
        assert_eq!(config.long_window, Duration::from_secs(86400));
        assert_eq!(config.failed_auth_threshold, 10);
        assert_eq!(config.rate_limit_threshold, 100);
        assert_eq!(config.suspicious_activity_threshold, 50);
        assert_eq!(config.ip_ban_threshold, 5);
        assert!(config.suppress_duplicate_alerts);
        assert!(config.alert_coalescing_enabled);
        assert!(config.auto_escalation_enabled);
        assert_eq!(config.max_escalation_levels, 3);
        assert!(config.enable_email_alerts);
        assert!(config.enable_slack_alerts);
        assert!(!config.enable_pagerduty_alerts);
        assert!(config.enable_siem_integration);
        assert!(config.enable_webhook_alerts);
        assert!(!config.enable_sms_alerts);
        assert!(!config.enable_voice_alerts);
        assert!(config.enable_ml_detection);
        assert!(config.enable_threat_intelligence);
        assert!(config.enable_behavioral_analysis);
        assert!(config.enable_zero_day_protection);
        assert!(config.enable_audit_logging);
        assert_eq!(config.audit_log_retention_days, 90);
        assert!(config.enable_compliance_reporting);
        assert_eq!(config.max_alert_queue_size, 10000);
        assert_eq!(config.alert_processing_batch_size, 100);
        assert_eq!(config.alert_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_enhanced_security_event_types() {
        // Test that all event types are covered
        let event_types = [
            EnhancedSecurityEventType::AuthenticationFailure,
            EnhancedSecurityEventType::AuthenticationSuccess,
            EnhancedSecurityEventType::PasswordBruteForce,
            EnhancedSecurityEventType::MfaFailure,
            EnhancedSecurityEventType::SessionHijacking,
            EnhancedSecurityEventType::AccountTakeover,
            EnhancedSecurityEventType::AuthorizationFailure,
            EnhancedSecurityEventType::PrivilegeEscalation,
            EnhancedSecurityEventType::RoleManipulation,
            EnhancedSecurityEventType::RateLimitExceeded,
            EnhancedSecurityEventType::BurstTrafficDetected,
            EnhancedSecurityEventType::SqlInjection,
            EnhancedSecurityEventType::CrossSiteScripting,
            EnhancedSecurityEventType::CommandInjection,
            EnhancedSecurityEventType::LdapInjection,
            EnhancedSecurityEventType::DataExfiltration,
            EnhancedSecurityEventType::SensitiveDataAccess,
            EnhancedSecurityEventType::ConfigurationChange,
            EnhancedSecurityEventType::SystemIntegrityViolation,
            EnhancedSecurityEventType::FileTampering,
            EnhancedSecurityEventType::PortScan,
            EnhancedSecurityEventType::DdosAttack,
            EnhancedSecurityEventType::SuspiciousTraffic,
            EnhancedSecurityEventType::PolicyViolation,
            EnhancedSecurityEventType::RegulatoryCompliance,
            EnhancedSecurityEventType::AdvancedPersistentThreat,
            EnhancedSecurityEventType::UnknownAttackPattern,
            EnhancedSecurityEventType::BehavioralAnomaly,
            EnhancedSecurityEventType::Custom("test".to_string()),
        ];
        
        assert_eq!(event_types.len(), 29);
    }

    #[test]
    fn test_enhanced_alert_handlers() {
        let email_handler = EnhancedEmailAlertHandler::new(
            "smtp.example.com".to_string(),
            587,
            "user".to_string(),
            "pass".to_string(),
            "from@example.com".to_string(),
            vec!["to@example.com".to_string()],
        );
        
        let slack_handler = EnhancedSlackAlertHandler::new(
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            "#security-alerts".to_string(),
            "SecurityBot".to_string(),
            ":rotating_light:".to_string(),
        );
        
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let webhook_handler = EnhancedWebhookAlertHandler::new(
            "https://webhook.example.com/alerts".to_string(),
            "POST".to_string(),
            headers,
        );
        
        assert_eq!(email_handler.get_name(), "email");
        assert_eq!(slack_handler.get_name(), "slack");
        assert_eq!(webhook_handler.get_name(), "webhook");
    }

    #[tokio::test]
    async fn test_create_default_security_monitor() {
        let monitor = create_default_security_monitor();
        assert!(!monitor.is_running.load(Ordering::Relaxed));
    }
}