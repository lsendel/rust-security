//! Playbook and workflow type definitions
//!
//! This module contains all types related to security playbooks,
//! workflow definitions, and execution parameters.

use crate::infrastructure::security::security_monitoring::{AlertSeverity, SecurityAlertType};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Security playbook definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPlaybook {
    /// Unique playbook identifier
    pub id: String,

    /// Playbook name
    pub name: String,

    /// Description of the playbook
    pub description: String,

    /// Playbook version
    pub version: String,

    /// Triggers that activate this playbook
    pub triggers: Vec<PlaybookTrigger>,

    /// Workflow steps
    pub steps: Vec<WorkflowStep>,

    /// Input parameters
    pub inputs: Vec<ParameterDefinition>,

    /// Output definitions
    pub outputs: Vec<ParameterDefinition>,

    /// Timeout for the entire playbook
    pub timeout_minutes: u32,

    /// Whether the playbook can run automatically
    pub auto_executable: bool,

    /// Required approvals
    pub required_approvals: Vec<ApprovalRequirement>,

    /// Metadata
    pub metadata: PlaybookMetadata,
}

/// Playbook trigger conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    /// Trigger type
    pub trigger_type: TriggerType,

    /// Conditions that must be met
    pub conditions: Vec<TriggerCondition>,

    /// Priority of this trigger
    pub priority: u8,
}

/// Types of triggers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerType {
    AlertReceived,
    ThreatDetected,
    ScheduledExecution,
    ManualTrigger,
    ApiTrigger,
    EventPattern,
}

/// Trigger condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    /// Field to evaluate
    pub field: String,

    /// Operator for comparison
    pub operator: ConditionOperator,

    /// Expected value
    pub value: serde_json::Value,

    /// Whether this condition is required
    pub required: bool,
}

/// Condition operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Regex,
    In,
    NotIn,
}

/// Workflow step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Step identifier
    pub id: String,

    /// Step name
    pub name: String,

    /// Step type
    pub step_type: StepType,

    /// Action to perform
    pub action: StepAction,

    /// Input parameters for this step
    pub inputs: HashMap<String, serde_json::Value>,

    /// Output variable mappings
    pub outputs: HashMap<String, String>,

    /// Dependencies on other steps
    pub dependencies: Vec<String>,

    /// Conditions for step execution
    pub conditions: Vec<TriggerCondition>,

    /// Timeout for this step
    pub timeout_minutes: u32,

    /// Retry configuration
    pub retry_config: RetryConfig,

    /// Error handling
    pub error_handling: ErrorHandling,
}

/// Types of workflow steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepType {
    Action,
    Decision,
    Loop,
    Parallel,
    SubWorkflow,
    Approval,
    Notification,
    Wait,
}

/// Step actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepAction {
    /// Block an IP address
    BlockIp {
        ip_address: String,
        duration_minutes: u32,
        reason: String,
    },

    /// Lock a user account
    LockAccount {
        user_id: String,
        duration_minutes: u32,
        reason: String,
    },

    /// Revoke tokens
    RevokeTokens {
        user_id: Option<String>,
        token_type: Option<String>,
    },

    /// Send notification
    SendNotification {
        notification_type: String,
        recipients: Vec<String>,
        subject: String,
        message: String,
        priority: String,
    },

    /// Query SIEM
    QuerySiem {
        query: String,
        time_range: String,
        max_results: u32,
    },

    /// Create incident ticket
    CreateTicket {
        title: String,
        description: String,
        priority: String,
        assignee: Option<String>,
    },

    /// Execute script
    ExecuteScript {
        script_type: String,
        script_content: String,
        parameters: HashMap<String, String>,
    },

    /// HTTP request
    HttpRequest {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },

    /// Execute database query
    ExecuteQuery {
        query: String,
        parameters: Option<HashMap<String, String>>,
        timeout_seconds: u32,
    },

    /// Update case
    UpdateCase {
        case_id: String,
        fields: HashMap<String, serde_json::Value>,
        add_note: Option<String>,
    },

    /// Custom action
    CustomAction {
        action_type: String,
        parameters: HashMap<String, serde_json::Value>,
    },
}

/// Parameter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDefinition {
    /// Parameter name
    pub name: String,

    /// Parameter type
    pub param_type: ParameterType,

    /// Whether parameter is required
    pub required: bool,

    /// Default value
    pub default_value: Option<serde_json::Value>,

    /// Description
    pub description: String,

    /// Validation rules
    pub validation: Option<ParameterValidation>,
}

/// Parameter types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
    DateTime,
    IpAddress,
    Email,
    Url,
}

/// Parameter validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterValidation {
    /// Minimum value (for numbers)
    pub min: Option<f64>,

    /// Maximum value (for numbers)
    pub max: Option<f64>,

    /// Regular expression pattern
    pub pattern: Option<String>,

    /// Allowed values
    pub allowed_values: Option<Vec<serde_json::Value>>,

    /// Custom validation script
    pub custom_validator: Option<String>,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,

    /// Retry delay in seconds
    pub delay_seconds: u32,

    /// Backoff strategy
    pub backoff_strategy: BackoffStrategy,

    /// Conditions that trigger retries
    pub retry_conditions: Vec<RetryCondition>,
}

/// Backoff strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackoffStrategy {
    Fixed,
    Linear,
    Exponential,
    Custom(String),
}

/// Retry conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryCondition {
    /// Error type or code
    pub error_type: String,

    /// Whether to retry on this error
    pub should_retry: bool,
}

/// Error handling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandling {
    /// Action to take on error
    pub on_error: ErrorAction,

    /// Whether to continue workflow on error
    pub continue_on_error: bool,

    /// Error notification settings
    pub notify_on_error: bool,

    /// Custom error handlers
    pub custom_handlers: Vec<CustomErrorHandler>,
}

/// Error actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorAction {
    Stop,
    Continue,
    Retry,
    Escalate,
    Rollback,
    Custom(String),
}

/// Custom error handler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomErrorHandler {
    /// Error pattern to match
    pub pattern: String,

    /// Action to take
    pub action: ErrorAction,

    /// Custom parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Approval requirement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequirement {
    /// Type of approval required
    pub approval_type: ApprovalType,

    /// Required approvers
    pub approvers: Vec<String>,

    /// Number of approvals needed
    pub required_approvals: u32,

    /// Timeout for approval
    pub timeout_minutes: u32,

    /// Auto-approve conditions
    pub auto_approve_conditions: Vec<TriggerCondition>,
}

/// Types of approvals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalType {
    Manual,
    Automatic,
    Conditional,
    MultiLevel,
}

/// Playbook metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookMetadata {
    /// Author information
    pub author: String,

    /// Creation date
    pub created_at: DateTime<Utc>,

    /// Last modified date
    pub modified_at: DateTime<Utc>,

    /// Tags for categorization
    pub tags: Vec<String>,

    /// Category
    pub category: String,

    /// Severity levels this playbook handles
    pub severity_levels: Vec<AlertSeverity>,

    /// Threat types this playbook addresses
    pub threat_types: Vec<SecurityAlertType>,

    /// Compliance frameworks
    pub compliance_frameworks: Vec<String>,

    /// Documentation links
    pub documentation: Vec<DocumentationLink>,
}

/// Documentation link
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentationLink {
    /// Link title
    pub title: String,

    /// URL
    pub url: String,

    /// Link type
    pub link_type: String,
}

/// Workflow instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstance {
    /// Instance identifier
    pub id: String,

    /// Playbook being executed
    pub playbook_id: String,

    /// Current status
    pub status: WorkflowStatus,

    /// Start time
    pub started_at: DateTime<Utc>,

    /// End time
    pub ended_at: Option<DateTime<Utc>>,

    /// Current step index
    pub current_step: usize,

    /// Execution context
    pub context: HashMap<String, serde_json::Value>,

    /// Step execution results
    pub step_results: HashMap<String, StepResult>,

    /// Error information
    pub error: Option<WorkflowError>,

    /// Input parameters
    pub inputs: HashMap<String, serde_json::Value>,

    /// Output values
    pub outputs: HashMap<String, serde_json::Value>,

    /// Approval requests
    pub approval_requests: Vec<ApprovalRequest>,
}

/// Workflow status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Paused,
    WaitingApproval,
    Completed,
    Failed,
    Cancelled,
    Timeout,
}

/// Workflow execution request
#[derive(Debug)]
pub struct WorkflowExecutionRequest {
    /// Workflow instance ID
    pub instance_id: String,

    /// Playbook to execute
    pub playbook: SecurityPlaybook,

    /// Input parameters
    pub inputs: HashMap<String, serde_json::Value>,

    /// Execution context
    pub context: HashMap<String, serde_json::Value>,

    /// Response channel
    pub response_tx: oneshot::Sender<Result<WorkflowResult, WorkflowError>>,
}

/// Workflow execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowResult {
    /// Instance ID
    pub instance_id: String,

    /// Final status
    pub status: WorkflowStatus,

    /// Output values
    pub outputs: HashMap<String, serde_json::Value>,

    /// Execution duration
    pub duration_ms: u64,

    /// Step results
    pub step_results: HashMap<String, StepResult>,
}

/// Step execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Step ID
    pub step_id: String,

    /// Execution status
    pub status: StepStatus,

    /// Start time
    pub started_at: DateTime<Utc>,

    /// End time
    pub ended_at: Option<DateTime<Utc>>,

    /// Output data
    pub outputs: HashMap<String, serde_json::Value>,

    /// Error information
    pub error: Option<StepError>,

    /// Retry attempts
    pub retry_count: u32,
}

/// Step execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
    Retrying,
}

/// Step error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepError {
    /// Error code
    pub code: String,

    /// Error message
    pub message: String,

    /// Error details
    pub details: Option<serde_json::Value>,

    /// Whether the error is retryable
    pub retryable: bool,
}

impl From<serde_json::Error> for StepError {
    fn from(err: serde_json::Error) -> Self {
        Self {
            code: "SERIALIZATION_ERROR".to_string(),
            message: format!("JSON serialization error: {}", err),
            details: None,
            retryable: false,
        }
    }
}

/// Workflow error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowError {
    /// Error code
    pub code: String,

    /// Error message
    pub message: String,

    /// Error details
    pub details: Option<serde_json::Value>,

    /// Failed step ID
    pub failed_step: Option<String>,
}

/// Approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Request ID
    pub id: String,

    /// Workflow instance ID
    pub workflow_instance_id: String,

    /// Step ID requiring approval
    pub step_id: String,

    /// Approval type
    pub approval_type: ApprovalType,

    /// Required approvers
    pub required_approvers: Vec<String>,

    /// Number of approvals needed
    pub required_approvals: u32,

    /// Current approvals
    pub current_approvals: Vec<Approval>,

    /// Request timestamp
    pub requested_at: DateTime<Utc>,

    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,

    /// Status
    pub status: ApprovalStatus,

    /// Approval context
    pub context: HashMap<String, serde_json::Value>,
}

/// Individual approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Approver ID
    pub approver_id: String,

    /// Approval decision
    pub decision: ApprovalDecision,

    /// Approval timestamp
    pub approved_at: DateTime<Utc>,

    /// Comments
    pub comments: Option<String>,
}

/// Approval decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
    Abstain,
}

/// Approval status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

/// Execution context for workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Variables accessible to workflow steps
    pub variables: HashMap<String, serde_json::Value>,

    /// Metadata about the execution
    pub metadata: HashMap<String, serde_json::Value>,

    /// History of errors encountered
    pub error_history: Vec<StepError>,
}
