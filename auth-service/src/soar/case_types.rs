//! Core SOAR case types and data structures
//!
//! This module contains the fundamental types used throughout the SOAR case management system.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::security_monitoring::AlertSeverity;
use crate::soar_core::*;

/// Security case representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityCase {
    /// Unique case identifier
    pub id: String,

    /// Case title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Case severity level
    pub severity: AlertSeverity,

    /// Current case status
    pub status: CaseStatus,

    /// Assigned user (if any)
    pub assignee: Option<String>,

    /// Case creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Case due date
    pub due_date: Option<DateTime<Utc>>,

    /// Related security alerts
    pub related_alerts: Vec<String>,

    /// Related workflow instances
    pub related_workflows: Vec<String>,

    /// Evidence attached to case
    pub evidence: Vec<Evidence>,

    /// Case timeline
    pub timeline: Vec<TimelineEntry>,

    /// Case tags
    pub tags: Vec<String>,

    /// Custom fields
    pub custom_fields: HashMap<String, serde_json::Value>,

    /// SLA information
    pub sla_info: SlaInfo,
}

/// Case status enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CaseStatus {
    /// Newly created case
    New,
    /// Case is being investigated
    InProgress,
    /// Case is on hold
    OnHold,
    /// Case has been resolved
    Resolved,
    /// Case has been closed
    Closed,
    /// Case has been escalated
    Escalated,
}

/// Case priority levels
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CasePriority {
    /// Critical priority
    Critical,
    /// High priority
    High,
    /// Medium priority
    Medium,
    /// Low priority
    Low,
}

/// Case phases for workflow management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CasePhase {
    /// Case creation phase
    Creation,
    /// Investigation phase
    Investigation,
    /// Resolution phase
    Resolution,
    /// Case closure phase
    Closure,
    /// Post-mortem phase
    PostMortem,
}

/// Timeline entry for case history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Entry ID
    pub id: String,

    /// Entry timestamp
    pub timestamp: DateTime<Utc>,

    /// Type of timeline entry
    pub entry_type: TimelineEntryType,

    /// Actor who performed the action
    pub actor: String,

    /// Description of the action
    pub description: String,

    /// Additional data (JSON)
    pub data: Option<serde_json::Value>,
}

/// Timeline entry types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimelineEntryType {
    /// Case was created
    CaseCreated,
    /// Case status changed
    CaseStatusChanged,
    /// Case was assigned
    CaseAssigned,
    /// Evidence was added
    EvidenceAdded,
    /// Comment was added
    CommentAdded,
    /// Workflow was executed
    WorkflowExecuted,
    /// Case was escalated
    CaseEscalated,
    /// Custom entry type
    Custom(String),
}

/// SLA information for a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaInfo {
    /// Response deadline
    pub response_deadline: Option<DateTime<Utc>>,

    /// Resolution deadline
    pub resolution_deadline: Option<DateTime<Utc>>,

    /// Time to first response
    pub time_to_response: Option<Duration>,

    /// Time to resolution
    pub time_to_resolution: Option<Duration>,

    /// SLA breach indicators
    pub breached: bool,

    /// Breach reasons
    pub breach_reasons: Vec<String>,
}

/// Evidence attached to a case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Evidence ID
    pub id: String,

    /// Evidence type
    pub evidence_type: EvidenceType,

    /// Evidence name
    pub name: String,

    /// Evidence description
    pub description: String,

    /// Evidence data
    pub data: EvidenceData,

    /// Collection timestamp
    pub collected_at: DateTime<Utc>,

    /// Collector information
    pub collected_by: String,

    /// Evidence hash for integrity
    pub hash: String,

    /// Chain of custody
    pub chain_of_custody: Vec<CustodyEntry>,

    /// Evidence metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Evidence types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Log file evidence
    LogFile,
    /// Network capture
    NetworkCapture,
    /// Memory dump
    MemoryDump,
    /// Disk image
    DiskImage,
    /// Screenshot
    Screenshot,
    /// Document
    Document,
    /// Custom evidence type
    Custom(String),
}

/// Evidence data storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceData {
    /// File path reference
    FilePath(String),
    /// Inline data (base64 encoded)
    Inline(String),
    /// External URL
    ExternalUrl(String),
}

/// Chain of custody entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyEntry {
    /// Entry ID
    pub id: String,

    /// Timestamp of custody action
    pub timestamp: DateTime<Utc>,

    /// Actor performing custody action
    pub actor: String,

    /// Action performed
    pub action: CustodyAction,

    /// Action description
    pub description: String,

    /// Digital signature (if available)
    pub signature: Option<String>,
}

/// Custody actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CustodyAction {
    /// Evidence collected
    Collected,
    /// Evidence transferred
    Transferred,
    /// Evidence accessed
    Accessed,
    /// Evidence modified
    Modified,
    /// Evidence verified
    Verified,
    /// Evidence archived
    Archived,
}

/// Case creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCaseRequest {
    /// Case title
    pub title: String,

    /// Case description
    pub description: String,

    /// Case severity
    pub severity: AlertSeverity,

    /// Related alerts
    pub related_alerts: Vec<String>,

    /// Initial assignee
    pub assignee: Option<String>,

    /// Case tags
    pub tags: Vec<String>,

    /// Custom fields
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Case update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseUpdate {
    /// New title
    pub title: Option<String>,

    /// New description
    pub description: Option<String>,

    /// New status
    pub status: Option<CaseStatus>,

    /// New assignee
    pub assignee: Option<String>,

    /// New tags
    pub tags: Option<Vec<String>>,

    /// Custom field updates
    pub custom_fields: Option<HashMap<String, serde_json::Value>>,
}

/// Case close reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloseReason {
    /// Resolved successfully
    Resolved,
    /// False positive
    FalsePositive,
    /// Duplicate case
    Duplicate,
    /// Insufficient information
    InsufficientInfo,
    /// Custom reason
    Custom(String),
}

impl Default for SlaInfo {
    fn default() -> Self {
        Self {
            response_deadline: None,
            resolution_deadline: None,
            time_to_response: None,
            time_to_resolution: None,
            breached: false,
            breach_reasons: Vec::new(),
        }
    }
}

impl SecurityCase {
    /// Create a new security case
    pub fn new(
        title: String,
        description: String,
        severity: AlertSeverity,
        related_alerts: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        let case_id = Uuid::new_v4().to_string();

        Self {
            id: case_id.clone(),
            title,
            description,
            severity,
            status: CaseStatus::New,
            assignee: None,
            created_at: now,
            updated_at: now,
            due_date: None,
            related_alerts,
            related_workflows: Vec::new(),
            evidence: Vec::new(),
            timeline: vec![TimelineEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: now,
                entry_type: TimelineEntryType::CaseCreated,
                actor: "system".to_string(),
                description: "Case created".to_string(),
                data: None,
            }],
            tags: Vec::new(),
            custom_fields: HashMap::new(),
            sla_info: SlaInfo::default(),
        }
    }

    /// Add a timeline entry
    pub fn add_timeline_entry(
        &mut self,
        entry_type: TimelineEntryType,
        actor: String,
        description: String,
        data: Option<serde_json::Value>,
    ) {
        let entry = TimelineEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            entry_type,
            actor,
            description,
            data,
        };
        self.timeline.push(entry);
        self.updated_at = Utc::now();
    }

    /// Check if case is overdue
    pub fn is_overdue(&self) -> bool {
        if let Some(due_date) = self.due_date {
            Utc::now() > due_date
        } else {
            false
        }
    }

    /// Get case age in hours
    pub fn age_hours(&self) -> f64 {
        let duration = Utc::now() - self.created_at;
        duration.num_seconds() as f64 / 3600.0
    }

    /// Check if case is in active status
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            CaseStatus::New | CaseStatus::InProgress | CaseStatus::Escalated
        )
    }
}

impl Evidence {
    /// Create new evidence entry
    pub fn new(
        evidence_type: EvidenceType,
        name: String,
        description: String,
        data: EvidenceData,
        collected_by: String,
        hash: String,
    ) -> Self {
        let now = Utc::now();
        let evidence_id = Uuid::new_v4().to_string();

        Self {
            id: evidence_id.clone(),
            evidence_type,
            name,
            description,
            data,
            collected_at: now,
            collected_by: collected_by.clone(),
            hash,
            chain_of_custody: vec![CustodyEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: now,
                actor: collected_by,
                action: CustodyAction::Collected,
                description: "Evidence collected".to_string(),
                signature: None,
            }],
            metadata: HashMap::new(),
        }
    }

    /// Add custody entry
    pub fn add_custody_entry(
        &mut self,
        actor: String,
        action: CustodyAction,
        description: String,
        signature: Option<String>,
    ) {
        let entry = CustodyEntry {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            actor,
            action,
            description,
            signature,
        };
        self.chain_of_custody.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_case_creation() {
        let case = SecurityCase::new(
            "Test Case".to_string(),
            "Test Description".to_string(),
            AlertSeverity::High,
            vec!["alert-1".to_string()],
        );

        assert_eq!(case.title, "Test Case");
        assert_eq!(case.status, CaseStatus::New);
        assert_eq!(case.timeline.len(), 1);
        assert!(case.is_active());
    }

    #[test]
    fn test_case_age_calculation() {
        let mut case = SecurityCase::new(
            "Test Case".to_string(),
            "Test Description".to_string(),
            AlertSeverity::Medium,
            vec![],
        );

        // Set created_at to 2 hours ago
        case.created_at = Utc::now() - Duration::hours(2);

        let age = case.age_hours();
        assert!(age >= 1.9 && age <= 2.1); // Allow for small timing differences
    }

    #[test]
    fn test_evidence_creation() {
        let evidence = Evidence::new(
            EvidenceType::LogFile,
            "test.log".to_string(),
            "Test log file".to_string(),
            EvidenceData::FilePath("/tmp/test.log".to_string()),
            "analyst1".to_string(),
            "abc123".to_string(),
        );

        assert_eq!(evidence.name, "test.log");
        assert_eq!(evidence.chain_of_custody.len(), 1);
        assert_eq!(evidence.chain_of_custody[0].action, CustodyAction::Collected);
    }
}
