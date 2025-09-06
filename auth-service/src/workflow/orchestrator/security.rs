//! Security Components for Workflow Execution

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Security context for workflow execution
#[derive(Debug, Clone)]
pub struct SecurityContext {
    pub user_id: String,
    pub user_roles: HashSet<String>,
    pub permissions: HashSet<String>,
    pub security_level: SecurityLevel,
    pub constraints: Vec<SecurityConstraint>,
    pub audit_trail: Vec<AuditEntry>,
}

/// Security levels
#[derive(Debug, Clone)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Security constraint
#[derive(Debug, Clone)]
pub struct SecurityConstraint {
    pub constraint_type: ConstraintType,
    pub value: String,
    pub enforcement: EnforcementLevel,
}

/// Constraint types
#[derive(Debug, Clone)]
pub enum ConstraintType {
    IPAddress { allowed_ips: Vec<String> },
    TimeWindow { start: u32, end: u32 }, // hours
    MFARequired,
    ApprovalRequired { approvers: Vec<String> },
    DataClassification { max_level: DataClassification },
}

/// Enforcement levels
#[derive(Debug, Clone)]
pub enum EnforcementLevel {
    Advisory,
    Mandatory,
    Critical,
}

/// Data classification levels
#[derive(Debug, Clone)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
    HighlyRestricted,
}

/// Audit entry for security logging
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub outcome: AuditOutcome,
    pub details: HashMap<String, Value>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
}

/// Audit outcomes
#[derive(Debug, Clone)]
pub enum AuditOutcome {
    Success,
    Failure,
    Blocked,
    Bypassed,
}
