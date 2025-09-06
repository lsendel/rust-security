//! Audit and Logging Components

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Audit entry for workflow execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub workflow_id: String,
    pub instance_id: String,
    pub step_id: Option<String>,
    pub user_id: Option<String>,
    pub action: String,
    pub resource: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, Value>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub correlation_id: Option<String>,
}

/// Audit outcomes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    Success,
    Failure,
    Blocked,
    Bypassed,
    Pending,
    Cancelled,
}

/// Audit trail for a workflow instance
#[derive(Debug, Clone, Default)]
pub struct AuditTrail {
    pub entries: Vec<AuditEntry>,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
}

impl AuditTrail {
    /// Create a new audit trail
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            entries: Vec::new(),
            created_at: now,
            last_updated: now,
        }
    }

    /// Add an entry to the audit trail
    pub fn add_entry(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
        self.last_updated = Utc::now();
    }

    /// Get entries for a specific step
    #[must_use]
    pub fn get_step_entries(&self, step_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.step_id.as_deref() == Some(step_id))
            .collect()
    }

    /// Get entries by action type
    #[must_use]
    pub fn get_entries_by_action(&self, action: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.action == action)
            .collect()
    }
}
