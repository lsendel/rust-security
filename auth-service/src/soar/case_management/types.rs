//! Case Management Types
//!
//! Core data structures for the SOAR case management system.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Security case status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaseStatus {
    /// Case has been created but not yet assigned
    New,
    /// Case is assigned and being investigated
    InProgress,
    /// Case is waiting for external input or resources
    Waiting,
    /// Case has been escalated to higher tier
    Escalated,
    /// Case has been resolved
    Resolved,
    /// Case has been closed
    Closed,
    /// Case has been reopened after closure
    Reopened,
}

/// Case priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CasePriority {
    /// Low priority - routine security events
    Low = 1,
    /// Medium priority - potential security issues
    Medium = 2,
    /// High priority - confirmed security incidents
    High = 3,
    /// Critical priority - active security breaches
    Critical = 4,
    /// Emergency priority - system-wide security compromise
    Emergency = 5,
}

/// Security case representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    /// Unique case identifier
    pub id: String,
    
    /// Case title
    pub title: String,
    
    /// Detailed case description
    pub description: String,
    
    /// Current case status
    pub status: CaseStatus,
    
    /// Case priority level
    pub priority: CasePriority,
    
    /// Case severity (different from priority)
    pub severity: CaseSeverity,
    
    /// Case category/type
    pub category: CaseCategory,
    
    /// Assigned analyst/team
    pub assignee: Option<String>,
    
    /// Case creator
    pub creator: String,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    
    /// Due date for resolution
    pub due_date: Option<DateTime<Utc>>,
    
    /// Case tags for categorization
    pub tags: Vec<String>,
    
    /// Custom fields for extensibility
    pub custom_fields: HashMap<String, serde_json::Value>,
    
    /// Associated alerts
    pub alerts: Vec<String>,
    
    /// Evidence items
    pub evidence: Vec<EvidenceItem>,
    
    /// Case timeline/activities
    pub timeline: Vec<CaseActivity>,
    
    /// SLA information
    pub sla: Option<CaseSla>,
    
    /// Metrics and statistics
    pub metrics: CaseMetrics,
}

/// Case severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaseSeverity {
    /// Informational - no immediate action required
    Info,
    /// Low severity - minor security concern
    Low,
    /// Medium severity - moderate security risk
    Medium,
    /// High severity - significant security threat
    High,
    /// Critical severity - immediate security risk
    Critical,
}

/// Case categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaseCategory {
    /// Malware detection and response
    Malware,
    /// Phishing attempts and email security
    Phishing,
    /// Data breach or exfiltration
    DataBreach,
    /// Unauthorized access attempts
    UnauthorizedAccess,
    /// Denial of service attacks
    DenialOfService,
    /// Insider threat activities
    InsiderThreat,
    /// Compliance violations
    Compliance,
    /// Vulnerability management
    Vulnerability,
    /// Fraud detection
    Fraud,
    /// General security incident
    General,
}

impl std::fmt::Display for CaseCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaseCategory::Malware => write!(f, "Malware"),
            CaseCategory::Phishing => write!(f, "Phishing"),
            CaseCategory::DataBreach => write!(f, "DataBreach"),
            CaseCategory::UnauthorizedAccess => write!(f, "UnauthorizedAccess"),
            CaseCategory::DenialOfService => write!(f, "DenialOfService"),
            CaseCategory::InsiderThreat => write!(f, "InsiderThreat"),
            CaseCategory::Compliance => write!(f, "Compliance"),
            CaseCategory::Vulnerability => write!(f, "Vulnerability"),
            CaseCategory::Fraud => write!(f, "Fraud"),
            CaseCategory::General => write!(f, "General"),
        }
    }
}

/// Evidence item in a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Evidence identifier
    pub id: String,
    
    /// Evidence type
    pub evidence_type: EvidenceType,
    
    /// Evidence description
    pub description: String,
    
    /// File path or reference
    pub file_path: Option<String>,
    
    /// Evidence hash for integrity
    pub hash: Option<String>,
    
    /// Collection timestamp
    pub collected_at: DateTime<Utc>,
    
    /// Collector information
    pub collected_by: String,
    
    /// Chain of custody information
    pub custody_chain: Vec<CustodyEntry>,
    
    /// Evidence metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of evidence
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    /// Log files
    LogFile,
    /// Network packet capture
    PacketCapture,
    /// Memory dump
    MemoryDump,
    /// Disk image
    DiskImage,
    /// Screenshot
    Screenshot,
    /// Document or file
    Document,
    /// Database export
    DatabaseExport,
    /// Configuration file
    Configuration,
    /// Other evidence type
    Other(String),
}

/// Chain of custody entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// Person handling the evidence
    pub handler: String,
    
    /// Action performed
    pub action: CustodyAction,
    
    /// Timestamp of action
    pub timestamp: DateTime<Utc>,
    
    /// Notes about the action
    pub notes: Option<String>,
}

/// Custody actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CustodyAction {
    /// Evidence collected
    Collected,
    /// Evidence transferred
    Transferred,
    /// Evidence analyzed
    Analyzed,
    /// Evidence stored
    Stored,
    /// Evidence disposed
    Disposed,
}

/// Case activity/timeline entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseActivity {
    /// Activity identifier
    pub id: String,
    
    /// Activity type
    pub activity_type: ActivityType,
    
    /// Activity description
    pub description: String,
    
    /// User who performed the activity
    pub user: String,
    
    /// Activity timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Additional activity data
    pub data: Option<serde_json::Value>,
}

/// Types of case activities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActivityType {
    /// Case created
    Created,
    /// Case updated
    Updated,
    /// Status changed
    StatusChanged,
    /// Priority changed
    PriorityChanged,
    /// Case assigned
    Assigned,
    /// Comment added
    CommentAdded,
    /// Evidence added
    EvidenceAdded,
    /// Case escalated
    Escalated,
    /// Case resolved
    Resolved,
    /// Case closed
    Closed,
    /// Case reopened
    Reopened,
    /// Custom activity
    Custom(String),
}

/// SLA (Service Level Agreement) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSla {
    /// SLA policy identifier
    pub policy_id: String,
    
    /// Response time SLA
    pub response_time: Duration,
    
    /// Resolution time SLA
    pub resolution_time: Duration,
    
    /// First response timestamp
    pub first_response_at: Option<DateTime<Utc>>,
    
    /// Resolution timestamp
    pub resolved_at: Option<DateTime<Utc>>,
    
    /// SLA breach indicators
    pub breaches: Vec<SlaBreach>,
    
    /// SLA status
    pub status: SlaStatus,
}

/// SLA breach information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaBreach {
    /// Breach type
    pub breach_type: SlaBreachType,
    
    /// Breach timestamp
    pub breached_at: DateTime<Utc>,
    
    /// Breach duration
    pub duration: Duration,
    
    /// Breach reason
    pub reason: Option<String>,
}

/// Types of SLA breaches
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlaBreachType {
    /// Response time exceeded
    ResponseTime,
    /// Resolution time exceeded
    ResolutionTime,
}

/// SLA status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlaStatus {
    /// SLA is being met
    Met,
    /// SLA is at risk of breach
    AtRisk,
    /// SLA has been breached
    Breached,
}

/// Case metrics and statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaseMetrics {
    /// Time to first response
    pub time_to_response: Option<Duration>,
    
    /// Time to resolution
    pub time_to_resolution: Option<Duration>,
    
    /// Number of escalations
    pub escalation_count: u32,
    
    /// Number of reassignments
    pub reassignment_count: u32,
    
    /// Number of comments/updates
    pub update_count: u32,
    
    /// Number of evidence items
    pub evidence_count: u32,
    
    /// Case complexity score
    pub complexity_score: Option<f64>,
}

/// Case template for automated case creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseTemplate {
    /// Template identifier
    pub id: String,
    
    /// Template name
    pub name: String,
    
    /// Template description
    pub description: String,
    
    /// Default case title pattern
    pub title_pattern: String,
    
    /// Default case description template
    pub description_template: String,
    
    /// Default priority
    pub default_priority: CasePriority,
    
    /// Default severity
    pub default_severity: CaseSeverity,
    
    /// Default category
    pub default_category: CaseCategory,
    
    /// Default assignee
    pub default_assignee: Option<String>,
    
    /// Default tags
    pub default_tags: Vec<String>,
    
    /// Custom fields template
    pub custom_fields_template: HashMap<String, serde_json::Value>,
    
    /// SLA policy
    pub sla_policy: Option<String>,
    
    /// Template is active
    pub active: bool,
}

impl Default for CaseStatus {
    fn default() -> Self {
        CaseStatus::New
    }
}

impl Default for CasePriority {
    fn default() -> Self {
        CasePriority::Medium
    }
}

impl Default for CaseSeverity {
    fn default() -> Self {
        CaseSeverity::Medium
    }
}

impl Default for CaseCategory {
    fn default() -> Self {
        CaseCategory::General
    }
}

impl std::fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaseStatus::New => write!(f, "New"),
            CaseStatus::InProgress => write!(f, "In Progress"),
            CaseStatus::Waiting => write!(f, "Waiting"),
            CaseStatus::Escalated => write!(f, "Escalated"),
            CaseStatus::Resolved => write!(f, "Resolved"),
            CaseStatus::Closed => write!(f, "Closed"),
            CaseStatus::Reopened => write!(f, "Reopened"),
        }
    }
}

impl std::fmt::Display for CasePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CasePriority::Low => write!(f, "Low"),
            CasePriority::Medium => write!(f, "Medium"),
            CasePriority::High => write!(f, "High"),
            CasePriority::Critical => write!(f, "Critical"),
            CasePriority::Emergency => write!(f, "Emergency"),
        }
    }
}

impl std::fmt::Display for CaseSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaseSeverity::Info => write!(f, "Info"),
            CaseSeverity::Low => write!(f, "Low"),
            CaseSeverity::Medium => write!(f, "Medium"),
            CaseSeverity::High => write!(f, "High"),
            CaseSeverity::Critical => write!(f, "Critical"),
        }
    }
}
