//! Rust-based compliance reporting and validation tools
//!
//! This library provides comprehensive compliance reporting capabilities
//! for security frameworks including SOC 2, ISO 27001, GDPR, and custom
//! security controls.

pub mod compliance;
pub mod metrics;
pub mod prometheus_client;
pub mod reporting;
pub mod templates;
pub mod validation;

pub use compliance::*;
pub use metrics::*;
pub use reporting::*;
pub use validation::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// Dependencies used by binaries but not directly by lib
use anyhow as _;
use clap as _;
use sha2 as _;
use uuid as _;

// Dependencies that might be used conditionally or in features
use calamine as _;
use config as _;
use csv as _;
use dotenvy as _;
use fastrand as _;
use handlebars as _;
use moka as _;
use pulldown_cmark as _;
use regex as _;
use serde_yaml as _;
use tempfile as _;
use tracing_subscriber as _;
use walkdir as _;

// Dependencies used in lib modules
use common as _;
use prometheus as _;

/// Common error types for compliance tools
#[derive(Error, Debug)]
pub enum ComplianceError {
    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Data collection error: {0}")]
    DataCollection(String),

    #[error("Report generation error: {0}")]
    ReportGeneration(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Template error: {0}")]
    Template(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for compliance operations
pub type ComplianceResult<T> = std::result::Result<T, ComplianceError>;

/// Shorter alias for compliance result
pub type Result<T> = std::result::Result<T, ComplianceError>;

/// Security metric data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetric {
    pub name: String,
    pub value: f64,
    pub threshold: f64,
    pub status: MetricStatus,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub tags: HashMap<String, String>,
}

/// Status of a security metric
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MetricStatus {
    Pass,
    Fail,
    Warning,
    Unknown,
}

/// Compliance control assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub control_id: String,
    pub framework: ComplianceFramework,
    pub title: String,
    pub description: String,
    pub implementation_status: ImplementationStatus,
    pub effectiveness: EffectivenessLevel,
    pub evidence: Vec<String>,
    pub last_tested: DateTime<Utc>,
    pub next_review: DateTime<Utc>,
    pub risk_level: RiskLevel,
    pub assigned_to: Option<String>,
    pub remediation_plan: Option<String>,
}

/// Supported compliance frameworks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ComplianceFramework {
    Soc2,
    Iso27001,
    Gdpr,
    Nist,
    Pci,
    Hipaa,
    Custom(String),
}

/// Implementation status of controls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    Implemented,
    Partial,
    NotImplemented,
    Planned,
}

/// Effectiveness level of controls
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectivenessLevel {
    Effective,
    NeedsImprovement,
    Ineffective,
    NotTested,
}

/// Risk level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Security incident record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub incident_id: String,
    pub severity: IncidentSeverity,
    pub category: IncidentCategory,
    pub title: String,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub impact: String,
    pub root_cause: Option<String>,
    pub remediation_actions: Vec<String>,
    pub affected_systems: Vec<String>,
    pub assigned_to: Option<String>,
    pub lessons_learned: Option<String>,
}

/// Incident severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Incident categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentCategory {
    AuthenticationFailure,
    UnauthorizedAccess,
    DataBreach,
    MalwareDetection,
    DenialOfService,
    PolicyViolation,
    SystemCompromise,
    Other(String),
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub result: AuditResult,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
}

/// Audit result types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
    Blocked,
    Warning,
}

/// Configuration for compliance reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    pub organization: OrganizationInfo,
    pub frameworks: Vec<ComplianceFramework>,
    pub report_settings: ReportSettings,
    pub data_sources: DataSourceConfig,
    pub notifications: NotificationConfig,
}

/// Organization information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationInfo {
    pub name: String,
    pub domain: String,
    pub contact_email: String,
    pub compliance_officer: String,
    pub assessment_period_days: u32,
}

/// Report generation settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSettings {
    pub output_formats: Vec<ReportFormat>,
    pub include_charts: bool,
    pub include_recommendations: bool,
    pub classification_level: ClassificationLevel,
    pub retention_days: u32,
}

/// Supported report formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    Html,
    Pdf,
    Json,
    Csv,
    Excel,
    Markdown,
}

/// Classification levels for reports
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ClassificationLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Data source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceConfig {
    pub prometheus_url: Option<String>,
    pub elasticsearch_url: Option<String>,
    pub audit_log_paths: Vec<String>,
    pub redis_url: Option<String>,
    pub custom_apis: HashMap<String, ApiConfig>,
}

/// API configuration for custom data sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub url: String,
    pub auth_type: AuthType,
    pub headers: HashMap<String, String>,
    pub timeout_seconds: u64,
}

/// Authentication types for APIs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    None,
    Bearer(String),
    Basic { username: String, password: String },
    ApiKey { key: String, header: String },
}

/// Notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub slack_webhook: Option<String>,
    pub email_recipients: Vec<String>,
    pub teams_webhook: Option<String>,
    pub custom_webhooks: Vec<WebhookConfig>,
}

/// Custom webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub payload_template: String,
}
