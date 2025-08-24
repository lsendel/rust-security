//! SOAR (Security Orchestration, Automation and Response) Module
//!
//! This module provides comprehensive SOAR capabilities including:
//! - Case management and lifecycle
//! - Evidence collection and chain of custody
//! - SLA tracking and escalation
//! - Collaboration and communication
//! - Quality assurance and metrics
//! - Template-based automation

pub mod case_types;
pub mod templates;
pub mod evidence;
pub mod sla;
pub mod collaboration;
pub mod quality;
pub mod case_manager;

// Re-export commonly used types
pub use case_types::*;
pub use templates::{TemplateManager, CaseTemplate, EnhancedCaseTemplate};
pub use case_manager::CaseManagementSystem;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// SOAR event for system integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarEvent {
    /// Event ID
    pub id: String,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: SoarEventType,

    /// Event data
    pub data: serde_json::Value,

    /// Event source
    pub source: String,

    /// Event priority
    pub priority: u32,
}

/// SOAR event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoarEventType {
    /// Case created
    CaseCreated,
    /// Case updated
    CaseUpdated,
    /// Case assigned
    CaseAssigned,
    /// Case escalated
    CaseEscalated,
    /// Case resolved
    CaseResolved,
    /// Case closed
    CaseClosed,
    /// Evidence added
    EvidenceAdded,
    /// Evidence verified
    EvidenceVerified,
    /// SLA breach
    SlaBreach,
    /// Workflow triggered
    WorkflowTriggered,
    /// Automation executed
    AutomationExecuted,
    /// Custom event
    Custom(String),
}

/// SOAR configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarConfig {
    /// Auto-create cases from alerts
    pub auto_create_cases: bool,

    /// Case creation threshold
    pub case_creation_threshold: crate::security_monitoring::AlertSeverity,

    /// Default SLA settings
    pub default_sla: SlaSettings,

    /// Automation settings
    pub automation: AutomationSettings,

    /// Notification settings
    pub notifications: NotificationSettings,

    /// Quality settings
    pub quality: QualitySettings,

    /// Integration settings
    pub integrations: IntegrationSettings,
}

/// SLA settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaSettings {
    /// Response time by severity (hours)
    pub response_time_hours: HashMap<String, u32>,

    /// Resolution time by severity (hours)
    pub resolution_time_hours: HashMap<String, u32>,

    /// Business hours only
    pub business_hours_only: bool,

    /// Timezone for SLA calculation
    pub timezone: String,
}

/// Automation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationSettings {
    /// Enable automation
    pub enabled: bool,

    /// Max automation actions per case
    pub max_actions_per_case: u32,

    /// Automation timeout (seconds)
    pub timeout_seconds: u64,

    /// Retry configuration
    pub retry_config: RetryConfig,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Delay between retries (seconds)
    pub delay_seconds: u64,

    /// Exponential backoff
    pub exponential_backoff: bool,
}

/// Notification settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Enable notifications
    pub enabled: bool,

    /// Default channels
    pub default_channels: Vec<String>,

    /// Rate limiting
    pub rate_limit: RateLimitConfig,

    /// Template settings
    pub templates: TemplateSettings,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Max notifications per hour
    pub max_per_hour: u32,

    /// Max notifications per day
    pub max_per_day: u32,

    /// Burst limit
    pub burst_limit: u32,
}

/// Template settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSettings {
    /// Default template language
    pub default_language: String,

    /// Template cache size
    pub cache_size: usize,

    /// Template validation
    pub validation_enabled: bool,
}

/// Quality settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualitySettings {
    /// Enable quality checks
    pub enabled: bool,

    /// Minimum quality score
    pub min_quality_score: f64,

    /// Quality check frequency
    pub check_frequency: QualityCheckFrequency,

    /// Auto-remediation
    pub auto_remediation: bool,
}

/// Quality check frequency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QualityCheckFrequency {
    /// On every case update
    OnUpdate,
    /// Periodic checks
    Periodic { interval_hours: u32 },
    /// Manual checks only
    Manual,
}

/// Integration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationSettings {
    /// External systems
    pub external_systems: HashMap<String, ExternalSystemConfig>,

    /// Webhook settings
    pub webhooks: WebhookSettings,

    /// API settings
    pub api: ApiSettings,
}

/// External system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSystemConfig {
    /// System name
    pub name: String,

    /// System type
    pub system_type: String,

    /// Connection settings
    pub connection: ConnectionSettings,

    /// Sync settings
    pub sync: SyncSettings,
}

/// Connection settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSettings {
    /// Base URL
    pub base_url: String,

    /// Authentication
    pub auth: AuthSettings,

    /// Timeout (seconds)
    pub timeout_seconds: u64,

    /// Retry configuration
    pub retry_config: RetryConfig,
}

/// Authentication settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthSettings {
    /// API key authentication
    ApiKey { key: String },
    /// Bearer token
    Bearer { token: String },
    /// Basic authentication
    Basic { username: String, password: String },
    /// OAuth 2.0
    OAuth2 { client_id: String, client_secret: String },
    /// Custom authentication
    Custom(HashMap<String, String>),
}

/// Sync settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSettings {
    /// Enable sync
    pub enabled: bool,

    /// Sync interval (seconds)
    pub interval_seconds: u64,

    /// Sync direction
    pub direction: SyncDirection,

    /// Field mappings
    pub field_mappings: HashMap<String, String>,
}

/// Sync direction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncDirection {
    /// Import only
    Import,
    /// Export only
    Export,
    /// Bidirectional
    Bidirectional,
}

/// Webhook settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSettings {
    /// Enable webhooks
    pub enabled: bool,

    /// Webhook endpoints
    pub endpoints: Vec<WebhookEndpoint>,

    /// Retry configuration
    pub retry_config: RetryConfig,
}

/// Webhook endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Endpoint name
    pub name: String,

    /// URL
    pub url: String,

    /// HTTP method
    pub method: String,

    /// Headers
    pub headers: HashMap<String, String>,

    /// Event filters
    pub event_filters: Vec<String>,
}

/// API settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSettings {
    /// Enable API
    pub enabled: bool,

    /// API version
    pub version: String,

    /// Rate limiting
    pub rate_limit: RateLimitConfig,

    /// Authentication required
    pub auth_required: bool,
}

/// SOAR operations trait
#[async_trait]
pub trait SoarOperations {
    /// Create a new case
    async fn create_case(&self, request: CreateCaseRequest) -> Result<String, SoarError>;

    /// Update case
    async fn update_case(&self, case_id: &str, update: CaseUpdate) -> Result<SecurityCase, SoarError>;

    /// Get case by ID
    async fn get_case(&self, case_id: &str) -> Result<Option<SecurityCase>, SoarError>;

    /// List cases with filters
    async fn list_cases(&self, filters: CaseFilters) -> Result<Vec<SecurityCase>, SoarError>;

    /// Add evidence to case
    async fn add_evidence(&self, case_id: &str, evidence: Evidence) -> Result<String, SoarError>;

    /// Assign case
    async fn assign_case(&self, case_id: &str, assignee: &str, actor: &str) -> Result<(), SoarError>;

    /// Close case
    async fn close_case(&self, case_id: &str, reason: CloseReason, actor: &str) -> Result<(), SoarError>;
}

/// Case filters for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseFilters {
    /// Filter by status
    pub status: Option<Vec<CaseStatus>>,

    /// Filter by severity
    pub severity: Option<Vec<crate::security_monitoring::AlertSeverity>>,

    /// Filter by assignee
    pub assignee: Option<String>,

    /// Filter by tags
    pub tags: Option<Vec<String>>,

    /// Filter by date range
    pub date_range: Option<DateRange>,

    /// Custom filters
    pub custom_filters: HashMap<String, serde_json::Value>,

    /// Pagination
    pub pagination: Option<Pagination>,
}

/// Date range filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    /// Start date
    pub start: DateTime<Utc>,

    /// End date
    pub end: DateTime<Utc>,
}

/// Pagination settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    /// Page number (0-based)
    pub page: u32,

    /// Page size
    pub size: u32,

    /// Sort field
    pub sort_by: Option<String>,

    /// Sort order
    pub sort_order: SortOrder,
}

/// Sort order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortOrder {
    /// Ascending
    Asc,
    /// Descending
    Desc,
}

/// SOAR errors
#[derive(Debug, Clone)]
pub enum SoarError {
    /// Case not found
    CaseNotFound(String),
    /// Invalid case data
    InvalidCaseData(String),
    /// Permission denied
    PermissionDenied(String),
    /// Database error
    DatabaseError(String),
    /// External system error
    ExternalSystemError(String),
    /// Configuration error
    ConfigurationError(String),
    /// Validation error
    ValidationError(String),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for SoarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SoarError::CaseNotFound(id) => write!(f, "Case not found: {}", id),
            SoarError::InvalidCaseData(msg) => write!(f, "Invalid case data: {}", msg),
            SoarError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            SoarError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            SoarError::ExternalSystemError(msg) => write!(f, "External system error: {}", msg),
            SoarError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            SoarError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            SoarError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for SoarError {}

/// Default SOAR configuration
impl Default for SoarConfig {
    fn default() -> Self {
        Self {
            auto_create_cases: true,
            case_creation_threshold: crate::security_monitoring::AlertSeverity::Medium,
            default_sla: SlaSettings {
                response_time_hours: {
                    let mut map = HashMap::new();
                    map.insert("Critical".to_string(), 1);
                    map.insert("High".to_string(), 4);
                    map.insert("Medium".to_string(), 8);
                    map.insert("Low".to_string(), 24);
                    map
                },
                resolution_time_hours: {
                    let mut map = HashMap::new();
                    map.insert("Critical".to_string(), 4);
                    map.insert("High".to_string(), 24);
                    map.insert("Medium".to_string(), 72);
                    map.insert("Low".to_string(), 168);
                    map
                },
                business_hours_only: false,
                timezone: "UTC".to_string(),
            },
            automation: AutomationSettings {
                enabled: true,
                max_actions_per_case: 10,
                timeout_seconds: 300,
                retry_config: RetryConfig {
                    max_attempts: 3,
                    delay_seconds: 5,
                    exponential_backoff: true,
                },
            },
            notifications: NotificationSettings {
                enabled: true,
                default_channels: vec!["email".to_string(), "slack".to_string()],
                rate_limit: RateLimitConfig {
                    max_per_hour: 100,
                    max_per_day: 1000,
                    burst_limit: 10,
                },
                templates: TemplateSettings {
                    default_language: "en".to_string(),
                    cache_size: 1000,
                    validation_enabled: true,
                },
            },
            quality: QualitySettings {
                enabled: true,
                min_quality_score: 0.8,
                check_frequency: QualityCheckFrequency::OnUpdate,
                auto_remediation: false,
            },
            integrations: IntegrationSettings {
                external_systems: HashMap::new(),
                webhooks: WebhookSettings {
                    enabled: true,
                    endpoints: vec![],
                    retry_config: RetryConfig {
                        max_attempts: 3,
                        delay_seconds: 5,
                        exponential_backoff: true,
                    },
                },
                api: ApiSettings {
                    enabled: true,
                    version: "v1".to_string(),
                    rate_limit: RateLimitConfig {
                        max_per_hour: 1000,
                        max_per_day: 10000,
                        burst_limit: 50,
                    },
                    auth_required: true,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soar_config_default() {
        let config = SoarConfig::default();
        assert!(config.auto_create_cases);
        assert!(config.automation.enabled);
        assert!(config.notifications.enabled);
        assert!(config.quality.enabled);
    }

    #[test]
    fn test_soar_event_creation() {
        let event = SoarEvent {
            id: "test-event".to_string(),
            timestamp: Utc::now(),
            event_type: SoarEventType::CaseCreated,
            data: serde_json::json!({"case_id": "test-case"}),
            source: "test".to_string(),
            priority: 1,
        };

        assert_eq!(event.id, "test-event");
        assert_eq!(event.priority, 1);
    }
}
