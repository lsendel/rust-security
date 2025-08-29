//! Core types and data structures for the SOAR system
//!
//! This module contains all the fundamental data structures used throughout
//! the SOAR (Security Orchestration, Automation, and Response) system.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::security_monitoring::{AlertSeverity, SecurityAlert, SecurityAlertType};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::oneshot;
use uuid::Uuid;

// Re-export playbook types
pub mod playbook;
pub use playbook::*;

/// SOAR system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarConfig {
    /// Whether SOAR is enabled
    pub enabled: bool,

    /// Maximum concurrent workflows
    pub max_concurrent_workflows: usize,

    /// Default workflow timeout in minutes
    pub default_workflow_timeout_minutes: u32,

    /// Auto-response threshold configuration
    pub auto_response_config: AutoResponseConfig,

    /// Alert correlation configuration
    pub correlation_config: CorrelationConfig,

    /// Notification configuration
    pub notification_config: NotificationConfig,

    /// Integration configurations
    pub integrations: HashMap<String, IntegrationConfig>,

    /// Security playbook definitions
    pub playbooks: HashMap<String, SecurityPlaybook>,

    /// Escalation policies
    pub escalation_policies: Vec<EscalationPolicy>,

    /// Case management settings
    pub case_management: CaseManagementConfig,
}

/// Auto-response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponseConfig {
    /// Enable automatic response
    pub enabled: bool,

    /// Severity threshold for auto-response
    pub severity_threshold: AlertSeverity,

    /// Confidence threshold for auto-response (0-100)
    pub confidence_threshold: u8,

    /// Types of threats that can be auto-responded to
    pub allowed_threat_types: Vec<SecurityAlertType>,

    /// Maximum actions per auto-response
    pub max_actions_per_response: u8,

    /// Cooldown period between auto-responses in minutes
    pub cooldown_minutes: u32,
}

/// Alert correlation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Time window for correlation in minutes
    pub correlation_window_minutes: u32,

    /// Minimum events to trigger correlation
    pub min_events_for_correlation: u32,

    /// Maximum correlation cache size
    pub max_correlation_cache_size: usize,

    /// Correlation rules
    pub correlation_rules: Vec<CorrelationRule>,
}

/// Correlation rule for alert pattern matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Rule ID
    pub id: String,
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Alert types to correlate
    pub alert_types: Vec<SecurityAlertType>,
    /// Time window for correlation
    pub time_window_minutes: u32,
    /// Minimum events required
    pub min_events: u32,
    /// Rule severity
    pub severity: AlertSeverity,
    /// Whether the rule is enabled
    pub enabled: bool,
}

/// Result of alert correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Correlation ID
    pub id: String,
    /// Rule that triggered the correlation
    pub rule_id: String,
    /// Correlated alerts
    pub alerts: Vec<SecurityAlert>,
    /// Correlation timestamp
    pub timestamp: DateTime<Utc>,
    /// Correlation confidence score (0-100)
    pub confidence_score: u8,
    /// Correlation status
    pub status: CorrelationStatus,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Correlation processing status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationStatus {
    /// Correlation is active and being processed
    Active,
    /// Correlation has been resolved
    Resolved,
    /// Correlation has been dismissed as false positive
    Dismissed,
    /// Correlation requires manual review
    PendingReview,
}

/// Correlation metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CorrelationMetrics {
    /// Total correlations processed
    pub total_correlations: u64,
    /// Active correlations count
    pub active_correlations: u64,
    /// False positive correlations
    pub false_positives: u64,
    /// Processing time statistics
    pub avg_processing_time_ms: f64,
    /// Rule effectiveness metrics
    pub rule_metrics: HashMap<String, RuleMetrics>,
    /// Total alerts processed
    pub total_alerts_processed: u64,
    /// Correlations found
    pub correlations_found: u64,
}

/// Metrics for individual correlation rules
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleMetrics {
    /// Times the rule was triggered
    pub trigger_count: u64,
    /// Times the rule resulted in valid correlation
    pub success_count: u64,
    /// False positive rate
    pub false_positive_rate: f64,
    /// Average confidence score
    pub avg_confidence: f64,
}

/// Workflow execution metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct WorkflowMetrics {
    /// Workflow ID
    pub workflow_id: String,
    /// Total executions
    pub total_executions: u64,
    /// Successful executions
    pub successful_executions: u64,
    /// Failed executions
    pub failed_executions: u64,
    /// Average execution time in milliseconds
    pub avg_execution_time_ms: f64,
    /// Last execution timestamp
    pub last_execution: Option<DateTime<Utc>>,
    /// Last success timestamp
    pub last_success: Option<DateTime<Utc>>,
    /// Last failure timestamp
    pub last_failure: Option<DateTime<Utc>>,
}

/// Case management metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CaseMetrics {
    /// Total cases created
    pub total_cases: u64,
    /// Open cases count
    pub open_cases: u64,
    /// Closed cases count
    pub closed_cases: u64,
    /// Average resolution time in hours
    pub avg_resolution_time_hours: f64,
    /// SLA compliance rate
    pub sla_compliance_rate: f64,
    /// Cases by severity
    pub cases_by_severity: HashMap<AlertSeverity, u64>,
}

/// System performance metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Active connections count
    pub active_connections: u64,
    /// Total requests processed
    pub total_requests: u64,
    /// Requests per second
    pub requests_per_second: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
}

/// Case status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CaseStatus {
    /// Case is newly created
    New,
    /// Case is being investigated
    InProgress,
    /// Case is pending external input
    Pending,
    /// Case is resolved
    Resolved,
    /// Case is closed
    Closed,
    /// Case has been escalated
    Escalated,
}

/// Correlation error types
#[derive(Debug, thiserror::Error)]
pub enum CorrelationError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Processing error: {0}")]
    Processing(String),
    #[error("Rule error: {0}")]
    Rule(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Email settings
    pub email: Option<EmailConfig>,

    /// Slack integration
    pub slack: Option<SlackConfig>,

    /// PagerDuty integration
    pub pagerduty: Option<PagerDutyConfig>,

    /// Custom webhook configurations
    pub webhooks: Vec<WebhookConfig>,

    /// SMS configuration
    pub sms: Option<SmsConfig>,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub use_tls: bool,
}

/// Slack configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub webhook_url: String,
    pub channel: String,
    pub username: String,
    pub icon_emoji: Option<String>,
}

/// PagerDuty configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub integration_key: String,
    pub api_url: String,
    pub service_id: String,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub timeout_seconds: u64,
    pub retry_count: u32,
}

/// SMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    pub provider: String,
    pub api_key: String,
    pub from_number: String,
}

/// Integration configuration for external tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Unique identifier for the integration
    pub id: String,

    /// Integration type (SIEM, EDR, Firewall, etc.)
    pub integration_type: IntegrationType,

    /// Connection parameters
    pub connection_params: HashMap<String, String>,

    /// Authentication configuration
    pub auth_config: AuthConfig,

    /// Whether integration is enabled
    pub enabled: bool,

    /// Health check configuration
    pub health_check: HealthCheckConfig,
}

/// Types of integrations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationType {
    Siem,
    Edr,
    Firewall,
    IdentityProvider,
    TicketingSystem,
    ThreatIntelligence,
    Sandbox,
    NetworkMonitoring,
    Custom(String),
}

/// Authentication configuration for integrations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub auth_type: AuthType,
    pub credentials: HashMap<String, String>,
}

/// Authentication types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthType {
    ApiKey,
    BasicAuth,
    BearerToken,
    OAuth2,
    Certificate,
    Custom,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval_minutes: u32,
    pub timeout_seconds: u64,
    pub failure_threshold: u32,
}

/// Integration health status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationHealth {
    /// Integration is healthy and operational
    Healthy,
    /// Integration has degraded performance
    Degraded,
    /// Integration is unhealthy or unavailable
    Unhealthy,
    /// Integration health status is unknown
    Unknown,
}

/// Integration health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationHealthInfo {
    /// Integration ID
    pub integration_id: String,
    /// Current health status
    pub status: IntegrationHealth,
    /// Last health check timestamp
    pub last_check: DateTime<Utc>,
    /// Health check response time in milliseconds
    pub response_time_ms: u64,
    /// Error message if unhealthy
    pub error_message: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Integration metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationMetrics {
    /// Integration name/id
    pub integration_name: String,
    /// Total requests made
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Last request timestamp
    pub last_request: Option<DateTime<Utc>>,
    /// Error rate (0.0 to 1.0)
    pub error_rate: f64,
    /// Last success timestamp
    pub last_success: Option<DateTime<Utc>>,
    /// Last failure timestamp
    pub last_failure: Option<DateTime<Utc>>,
    /// Health status
    pub health_status: IntegrationHealth,
}

/// Integration error types
#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("Request error: {0}")]
    Request(String),
    #[error("Response error: {0}")]
    Response(String),
    #[error("Timeout error: {0}")]
    Timeout(String),
    #[error("Health check error: {0}")]
    HealthCheck(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Correlation condition for rule matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCondition {
    /// Field to check
    pub field: String,
    /// Operator for comparison
    pub operator: CorrelationOperator,
    /// Value to compare against
    pub value: serde_json::Value,
}

/// Correlation operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrelationOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
}

/// Types of correlation patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CorrelationType {
    /// Time-based correlation
    Temporal,
    /// IP address based correlation
    IpBased,
    /// User based correlation
    UserBased,
    /// Asset based correlation
    AssetBased,
    /// Pattern based correlation
    PatternBased,
    /// Custom correlation type
    Custom(String),
}

/// SOAR system events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: SoarEventType,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event data payload
    pub data: serde_json::Value,
    /// Event source
    pub source: String,
    /// Event metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of SOAR events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SoarEventType {
    /// Alert received from external system
    AlertReceived,
    /// Workflow started
    WorkflowStarted,
    /// Workflow completed successfully
    WorkflowCompleted,
    /// Workflow failed
    WorkflowFailed,
    /// Workflow paused for approval
    WorkflowPaused,
    /// Approval required for workflow step
    ApprovalRequired,
    /// Approval granted
    ApprovalGranted,
    /// Approval denied
    ApprovalDenied,
    /// Escalation triggered
    EscalationTriggered,
    /// Case created
    CaseCreated,
    /// Case updated
    CaseUpdated,
    /// Case closed
    CaseClosed,
    /// Integration health changed
    IntegrationHealthChanged,
    /// Configuration updated
    ConfigurationUpdated,
    /// Custom event type
    Custom(String),
}

/// Case management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseManagementConfig {
    /// Automatic case creation settings
    pub auto_create_cases: bool,

    /// Severity threshold for case creation
    pub case_creation_threshold: AlertSeverity,

    /// Default assignee for cases
    pub default_assignee: Option<String>,

    /// Case retention period in days
    pub retention_days: u32,

    /// SLA configurations
    pub sla_config: SlaConfig,
}

/// SLA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaConfig {
    /// Response time SLAs by severity
    pub response_time_minutes: HashMap<AlertSeverity, u32>,

    /// Resolution time SLAs by severity
    pub resolution_time_hours: HashMap<AlertSeverity, u32>,

    /// Escalation thresholds
    pub escalation_thresholds: HashMap<AlertSeverity, u32>,
}

// Default implementations for configuration types
impl Default for SoarConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_workflows: 100,
            default_workflow_timeout_minutes: 60,
            auto_response_config: AutoResponseConfig::default(),
            correlation_config: CorrelationConfig::default(),
            notification_config: NotificationConfig::default(),
            integrations: HashMap::new(),
            playbooks: HashMap::new(),
            escalation_policies: Vec::new(),
            case_management: CaseManagementConfig::default(),
        }
    }
}

impl Default for AutoResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            severity_threshold: AlertSeverity::High,
            confidence_threshold: 80,
            allowed_threat_types: Vec::new(),
            max_actions_per_response: 5,
            cooldown_minutes: 30,
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            correlation_window_minutes: 60,
            min_events_for_correlation: 3,
            max_correlation_cache_size: 10000,
            correlation_rules: Vec::new(),
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            email: None,
            slack: None,
            pagerduty: None,
            webhooks: Vec::new(),
            sms: None,
        }
    }
}

impl Default for CaseManagementConfig {
    fn default() -> Self {
        Self {
            auto_create_cases: true,
            case_creation_threshold: AlertSeverity::Medium,
            default_assignee: None,
            retention_days: 365,
            sla_config: SlaConfig::default(),
        }
    }
}

impl Default for SlaConfig {
    fn default() -> Self {
        let mut response_time_minutes = HashMap::new();
        response_time_minutes.insert(AlertSeverity::Critical, 15);
        response_time_minutes.insert(AlertSeverity::High, 60);
        response_time_minutes.insert(AlertSeverity::Medium, 240);
        response_time_minutes.insert(AlertSeverity::Low, 1440);

        let mut resolution_time_hours = HashMap::new();
        resolution_time_hours.insert(AlertSeverity::Critical, 4);
        resolution_time_hours.insert(AlertSeverity::High, 24);
        resolution_time_hours.insert(AlertSeverity::Medium, 72);
        resolution_time_hours.insert(AlertSeverity::Low, 168);

        let mut escalation_thresholds = HashMap::new();
        escalation_thresholds.insert(AlertSeverity::Critical, 30);
        escalation_thresholds.insert(AlertSeverity::High, 120);
        escalation_thresholds.insert(AlertSeverity::Medium, 480);
        escalation_thresholds.insert(AlertSeverity::Low, 2880);

        Self {
            response_time_minutes,
            resolution_time_hours,
            escalation_thresholds,
        }
    }
}
