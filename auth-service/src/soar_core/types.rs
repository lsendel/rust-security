//! Core types and data structures for the SOAR system
//!
//! This module contains all the fundamental data structures used throughout
//! the SOAR (Security Orchestration, Automation, and Response) system.

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
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
