//! SOAR Core Types
//!
//! Core data structures and types for the SOAR engine.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

impl Default for AutoResponseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            severity_threshold: AlertSeverity::High,
            confidence_threshold: 80,
            allowed_threat_types: Vec::new(),
            max_actions_per_response: 5,
            cooldown_minutes: 15,
        }
    }
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

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            correlation_window_minutes: 30,
            min_events_for_correlation: 3,
            max_correlation_cache_size: 10000,
            correlation_rules: Vec::new(),
        }
    }
}

/// Correlation rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Rule identifier
    pub id: String,
    
    /// Rule name
    pub name: String,
    
    /// Rule description
    pub description: String,
    
    /// Conditions for correlation
    pub conditions: Vec<CorrelationCondition>,
    
    /// Time window for correlation
    pub time_window_minutes: u32,
    
    /// Minimum events to trigger
    pub min_events: u32,
    
    /// Maximum events to consider
    pub max_events: u32,
    
    /// Rule priority
    pub priority: u8,
    
    /// Whether rule is enabled
    pub enabled: bool,
}

/// Correlation condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCondition {
    /// Field to correlate on
    pub field: String,
    
    /// Correlation type
    pub correlation_type: CorrelationType,
    
    /// Value threshold
    pub threshold: Option<serde_json::Value>,
}

/// Types of correlation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CorrelationType {
    /// Same value
    Exact,
    /// Similar values (fuzzy matching)
    Similar,
    /// Values within range
    Range,
    /// Pattern matching
    Pattern,
    /// Temporal correlation
    Temporal,
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

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: 5,
            timeout_seconds: 30,
            failure_threshold: 3,
        }
    }
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

impl Default for SlaConfig {
    fn default() -> Self {
        let mut response_times = HashMap::new();
        response_times.insert(AlertSeverity::Critical, 5);
        response_times.insert(AlertSeverity::High, 15);
        response_times.insert(AlertSeverity::Medium, 30);
        response_times.insert(AlertSeverity::Low, 60);

        let mut resolution_times = HashMap::new();
        resolution_times.insert(AlertSeverity::Critical, 2);
        resolution_times.insert(AlertSeverity::High, 8);
        resolution_times.insert(AlertSeverity::Medium, 24);
        resolution_times.insert(AlertSeverity::Low, 72);

        let mut escalation_thresholds = HashMap::new();
        escalation_thresholds.insert(AlertSeverity::Critical, 10);
        escalation_thresholds.insert(AlertSeverity::High, 30);
        escalation_thresholds.insert(AlertSeverity::Medium, 60);
        escalation_thresholds.insert(AlertSeverity::Low, 120);

        Self {
            response_time_minutes: response_times,
            resolution_time_hours: resolution_times,
            escalation_thresholds,
        }
    }
}

/// Escalation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    /// Policy identifier
    pub id: String,
    
    /// Policy name
    pub name: String,
    
    /// Escalation levels
    pub levels: Vec<EscalationLevel>,
    
    /// Whether policy is enabled
    pub enabled: bool,
}

/// Escalation level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLevel {
    /// Level number (1, 2, 3, etc.)
    pub level: u32,
    
    /// Time to wait before escalating (minutes)
    pub escalation_delay_minutes: u32,
    
    /// Recipients at this level
    pub recipients: Vec<String>,
    
    /// Notification methods
    pub notification_methods: Vec<NotificationMethod>,
}

/// Notification methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationMethod {
    Email,
    Sms,
    Slack,
    PagerDuty,
    Webhook,
    Phone,
}

/// SOAR event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarEvent {
    /// Event identifier
    pub id: String,
    
    /// Event type
    pub event_type: SoarEventType,
    
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Event source
    pub source: String,
    
    /// Event data
    pub data: serde_json::Value,
    
    /// Event severity
    pub severity: AlertSeverity,
    
    /// Event metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of SOAR events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SoarEventType {
    /// Security alert received
    AlertReceived,
    
    /// Workflow started
    WorkflowStarted,
    
    /// Workflow completed
    WorkflowCompleted,
    
    /// Workflow failed
    WorkflowFailed,
    
    /// Case created
    CaseCreated,
    
    /// Case updated
    CaseUpdated,
    
    /// Integration health check
    IntegrationHealthCheck,
    
    /// Policy violation
    PolicyViolation,
    
    /// Threat detected
    ThreatDetected,
    
    /// Response action executed
    ResponseActionExecuted,
}

/// Alert severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Security alert types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityAlertType {
    Malware,
    Phishing,
    DataExfiltration,
    UnauthorizedAccess,
    BruteForce,
    DenialOfService,
    InsiderThreat,
    PolicyViolation,
    AnomalousActivity,
    ThreatIntelligence,
    NetworkIntrusion,
    DataBreach,
    ComplianceViolation,
    Other(String),
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Low => write!(f, "Low"),
            AlertSeverity::Medium => write!(f, "Medium"),
            AlertSeverity::High => write!(f, "High"),
            AlertSeverity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::fmt::Display for SecurityAlertType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityAlertType::Malware => write!(f, "Malware"),
            SecurityAlertType::Phishing => write!(f, "Phishing"),
            SecurityAlertType::DataExfiltration => write!(f, "Data Exfiltration"),
            SecurityAlertType::UnauthorizedAccess => write!(f, "Unauthorized Access"),
            SecurityAlertType::BruteForce => write!(f, "Brute Force"),
            SecurityAlertType::DenialOfService => write!(f, "Denial of Service"),
            SecurityAlertType::InsiderThreat => write!(f, "Insider Threat"),
            SecurityAlertType::PolicyViolation => write!(f, "Policy Violation"),
            SecurityAlertType::AnomalousActivity => write!(f, "Anomalous Activity"),
            SecurityAlertType::ThreatIntelligence => write!(f, "Threat Intelligence"),
            SecurityAlertType::NetworkIntrusion => write!(f, "Network Intrusion"),
            SecurityAlertType::DataBreach => write!(f, "Data Breach"),
            SecurityAlertType::ComplianceViolation => write!(f, "Compliance Violation"),
            SecurityAlertType::Other(s) => write!(f, "{}", s),
        }
    }
}

impl std::fmt::Display for IntegrationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrationType::Siem => write!(f, "SIEM"),
            IntegrationType::Edr => write!(f, "EDR"),
            IntegrationType::Firewall => write!(f, "Firewall"),
            IntegrationType::IdentityProvider => write!(f, "Identity Provider"),
            IntegrationType::TicketingSystem => write!(f, "Ticketing System"),
            IntegrationType::ThreatIntelligence => write!(f, "Threat Intelligence"),
            IntegrationType::Sandbox => write!(f, "Sandbox"),
            IntegrationType::NetworkMonitoring => write!(f, "Network Monitoring"),
            IntegrationType::Custom(s) => write!(f, "{}", s),
        }
    }
}
