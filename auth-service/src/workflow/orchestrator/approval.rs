//! Workflow Approval Management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Approval manager for workflow steps requiring human approval
pub struct ApprovalManager {
    /// Active approval requests
    approval_requests: Arc<RwLock<HashMap<String, ApprovalRequest>>>,

    /// Approval policies by workflow type
    policies: Arc<RwLock<HashMap<String, ApprovalPolicy>>>,

    /// Approver groups
    approver_groups: Arc<RwLock<HashMap<String, ApproverGroup>>>,

    /// Escalation rules
    escalation_rules: Arc<RwLock<HashMap<String, ApprovalEscalationRule>>>,

    /// Auto-approval engine
    auto_approval_engine: Arc<AutoApprovalEngine>,
}

impl ApprovalManager {
    /// Create a new approval manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            approval_requests: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            approver_groups: Arc::new(RwLock::new(HashMap::new())),
            escalation_rules: Arc::new(RwLock::new(HashMap::new())),
            auto_approval_engine: Arc::new(AutoApprovalEngine::new()),
        }
    }

    /// Create a new approval request
    pub async fn create_approval_request(
        &self,
        workflow_id: String,
        step_id: String,
        approvers: Vec<String>,
        reason: String,
        priority: ApprovalPriority,
    ) -> Result<String, String> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let request = ApprovalRequest {
            id: request_id.clone(),
            workflow_id,
            step_id,
            approvers,
            reason,
            priority,
            status: ApprovalStatus::Pending,
            created_at: Utc::now(),
            expires_at: None,
            approved_by: None,
            approval_notes: None,
        };

        self.approval_requests
            .write()
            .await
            .insert(request_id.clone(), request);

        Ok(request_id)
    }

    /// Approve a request
    pub async fn approve_request(
        &self,
        request_id: &str,
        approver: String,
        notes: Option<String>,
    ) -> Result<(), String> {
        let mut requests = self.approval_requests.write().await;
        if let Some(request) = requests.get_mut(request_id) {
            request.status = ApprovalStatus::Approved;
            request.approved_by = Some(approver);
            request.approval_notes = notes;
            Ok(())
        } else {
            Err("Approval request not found".to_string())
        }
    }

    /// Reject a request
    pub async fn reject_request(
        &self,
        request_id: &str,
        rejector: String,
        reason: String,
    ) -> Result<(), String> {
        let mut requests = self.approval_requests.write().await;
        if let Some(request) = requests.get_mut(request_id) {
            request.status = ApprovalStatus::Rejected;
            request.approved_by = Some(rejector);
            request.approval_notes = Some(reason);
            Ok(())
        } else {
            Err("Approval request not found".to_string())
        }
    }
}

impl Default for ApprovalManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Approval request
#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: String,
    pub workflow_id: String,
    pub step_id: String,
    pub approvers: Vec<String>,
    pub reason: String,
    pub priority: ApprovalPriority,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub approved_by: Option<String>,
    pub approval_notes: Option<String>,
}

/// Approval priority levels
#[derive(Debug, Clone)]
pub enum ApprovalPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Approval status
#[derive(Debug, Clone)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Cancelled,
}

/// Approval policy for different workflow types
#[derive(Debug, Clone)]
pub struct ApprovalPolicy {
    pub workflow_type: String,
    pub required_approvers: Vec<String>,
    pub min_approvals: u32,
    pub auto_approval_rules: Vec<AutoApprovalRule>,
    pub escalation_rules: Vec<String>, // References to escalation rule IDs
    pub timeout_minutes: u32,
}

/// Group of approvers
#[derive(Debug, Clone)]
pub struct ApproverGroup {
    pub id: String,
    pub name: String,
    pub members: HashSet<String>,
    pub required_approvals: u32,
}

/// Escalation rule for approval timeouts
#[derive(Debug, Clone)]
pub struct ApprovalEscalationRule {
    pub id: String,
    pub name: String,
    pub condition: EscalationCondition,
    pub action: EscalationAction,
    pub delay_minutes: u32,
}

/// Escalation conditions
#[derive(Debug, Clone)]
pub enum EscalationCondition {
    Timeout { minutes: u32 },
    Rejection { count: u32 },
    NoResponse { count: u32 },
}

/// Escalation actions
#[derive(Debug, Clone)]
pub enum EscalationAction {
    Notify { recipients: Vec<String> },
    Reassign { new_approvers: Vec<String> },
    AutoApprove,
    CancelWorkflow,
}

/// Notification for approval requests
#[derive(Debug, Clone)]
pub struct ApprovalNotification {
    pub request_id: String,
    pub recipient: String,
    pub message: String,
    pub priority: ApprovalPriority,
    pub sent_at: DateTime<Utc>,
    pub delivery_status: NotificationDeliveryStatus,
}

/// Notification delivery status
#[derive(Debug, Clone)]
pub enum NotificationDeliveryStatus {
    Pending,
    Sent,
    Delivered,
    Failed,
}

/// Auto-approval engine for low-risk requests
pub struct AutoApprovalEngine {
    /// Rules for automatic approval
    rules: Arc<RwLock<Vec<AutoApprovalRule>>>,

    /// Risk assessor for evaluating requests
    risk_assessor: Arc<RiskAssessor>,
}

impl AutoApprovalEngine {
    /// Create a new auto-approval engine
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            risk_assessor: Arc::new(RiskAssessor::new()),
        }
    }

    /// Evaluate if a request can be auto-approved
    pub async fn can_auto_approve(&self, request: &ApprovalRequest) -> bool {
        // Check if any rules match and allow auto-approval
        let rules = self.rules.read().await;
        for rule in rules.iter() {
            if rule.matches(request) && rule.auto_approve {
                return true;
            }
        }
        false
    }
}

/// Auto-approval rule
#[derive(Debug, Clone)]
pub struct AutoApprovalRule {
    pub id: String,
    pub name: String,
    pub conditions: Vec<ApprovalCondition>,
    pub auto_approve: bool,
    pub risk_threshold: f64,
    pub enabled: bool,
}

/// Conditions for approval rules
#[derive(Debug, Clone)]
pub enum ApprovalCondition {
    WorkflowType { type_name: String },
    Requester { user_id: String },
    TimeWindow { start_hour: u32, end_hour: u32 },
    RiskScore { max_score: f64 },
    AmountThreshold { max_amount: f64 },
}

impl AutoApprovalRule {
    /// Check if this rule matches the given request
    #[must_use]
    pub fn matches(&self, _request: &ApprovalRequest) -> bool {
        // Simplified matching logic - in a real implementation, this would be more complex
        !self.conditions.is_empty() && self.enabled
    }
}

/// Risk assessor for approval requests
pub struct RiskAssessor {
    /// Risk factors to evaluate
    risk_factors: Arc<RwLock<Vec<RiskFactor>>>,

    /// Scoring rules
    scoring_rules: Arc<RwLock<Vec<ScoringRule>>>,
}

impl RiskAssessor {
    /// Create a new risk assessor
    #[must_use]
    pub fn new() -> Self {
        Self {
            risk_factors: Arc::new(RwLock::new(Vec::new())),
            scoring_rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Assess risk for an approval request
    pub async fn assess_risk(&self, _request: &ApprovalRequest) -> f64 {
        // Simplified risk assessment - in a real implementation, this would be more complex
        0.1 // Default low risk
    }
}

/// Risk factor for evaluation
#[derive(Debug, Clone)]
pub struct RiskFactor {
    pub id: String,
    pub name: String,
    pub description: String,
    pub weight: f64,
    pub category: RiskCategory,
}

/// Risk categories
#[derive(Debug, Clone)]
pub enum RiskCategory {
    Security,
    Compliance,
    Financial,
    Operational,
}

/// Scoring rule for risk assessment
#[derive(Debug, Clone)]
pub struct ScoringRule {
    pub id: String,
    pub name: String,
    pub condition: ScoringCondition,
    pub score: f64,
    pub explanation: String,
}

/// Conditions for scoring rules
#[derive(Debug, Clone)]
pub enum ScoringCondition {
    UserHistory { pattern: String },
    TimePattern { hour: u32 },
    RequestPattern { type_pattern: String },
    ExternalThreat { source: String, level: ThreatLevel },
}

/// Threat levels
#[derive(Debug, Clone)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}
