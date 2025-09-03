//! Case Management Data Models
//!
//! This module contains all the core data structures for case management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Case status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR")]
pub enum CaseStatus {
    /// Case is open and actively being worked on
    Open,
    /// Case is under investigation
    Investigating,
    /// Case requires escalation
    Escalated,
    /// Case is waiting for external input
    Pending,
    /// Case resolution is in progress
    Resolving,
    /// Case has been resolved
    Resolved,
    /// Case has been closed
    Closed,
}

/// Case priority levels
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "VARCHAR")]
pub enum CasePriority {
    /// Low priority - routine investigation
    Low = 1,
    /// Medium priority - standard timeline
    Medium = 2,
    /// High priority - expedited handling
    High = 3,
    /// Critical priority - immediate action required
    Critical = 4,
}

/// Security case structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCase {
    /// Unique case identifier
    pub id: String,
    /// Case title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Current status
    pub status: CaseStatus,
    /// Priority level
    pub priority: CasePriority,
    /// Assigned analyst
    pub assigned_to: Option<String>,
    /// Case creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Expected resolution time
    pub due_date: Option<DateTime<Utc>>,
    /// Associated alerts
    pub alerts: Vec<String>,
    /// Evidence files
    pub evidence: Vec<Evidence>,
    /// Case tags for categorization
    pub tags: Vec<String>,
    /// Custom metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Evidence structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence identifier
    pub id: String,
    /// Evidence type
    pub evidence_type: EvidenceType,
    /// Description
    pub description: String,
    /// File path or content
    pub content: String,
    /// Timestamp when evidence was collected
    pub collected_at: DateTime<Utc>,
    /// Collector information
    pub collected_by: String,
    /// Integrity hash
    pub integrity_hash: String,
}

/// Evidence types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Log files
    LogFile,
    /// Network packet capture
    PacketCapture,
    /// Memory dump
    MemoryDump,
    /// File system artifact
    FileArtifact,
    /// Screenshot or image
    Screenshot,
    /// User report
    UserReport,
    /// System configuration
    Configuration,
    /// Other evidence type
    Other(String),
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
    /// Default priority
    pub default_priority: CasePriority,
    /// Default tags
    pub default_tags: Vec<String>,
    /// Required fields
    pub required_fields: Vec<String>,
    /// SLA configuration
    pub sla_config: SlaConfig,
}

/// SLA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaConfig {
    /// Response time SLA (in minutes)
    pub response_time_minutes: u32,
    /// Resolution time SLA (in hours)
    pub resolution_time_hours: u32,
    /// Escalation time (in minutes)
    pub escalation_time_minutes: u32,
}

impl Default for SlaConfig {
    fn default() -> Self {
        Self {
            response_time_minutes: 30,
            resolution_time_hours: 24,
            escalation_time_minutes: 60,
        }
    }
}

impl SecurityCase {
    /// Create a new security case
    #[must_use]
    pub fn new(title: String, description: String, priority: CasePriority) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            description,
            status: CaseStatus::Open,
            priority,
            assigned_to: None,
            created_at: now,
            updated_at: now,
            due_date: None,
            alerts: Vec::new(),
            evidence: Vec::new(),
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Update the case status
    pub fn update_status(&mut self, status: CaseStatus) {
        self.status = status;
        self.updated_at = Utc::now();
    }

    /// Assign the case to an analyst
    pub fn assign_to(&mut self, analyst: String) {
        self.assigned_to = Some(analyst);
        self.updated_at = Utc::now();
    }

    /// Add evidence to the case
    pub fn add_evidence(&mut self, evidence: Evidence) {
        self.evidence.push(evidence);
        self.updated_at = Utc::now();
    }

    /// Add tags to the case
    pub fn add_tags(&mut self, tags: Vec<String>) {
        self.tags.extend(tags);
        self.updated_at = Utc::now();
    }
}
