//! Workflow Types for the Orchestrator

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;

/// Workflow instance
#[derive(Debug, Clone)]
pub struct WorkflowInstance {
    pub id: String,
    pub definition: WorkflowDefinition,
    pub status: WorkflowStatus,
    pub context: HashMap<String, Value>,
    pub current_step: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, Value>,
}

/// Workflow status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    Paused,
}

/// Workflow definition
#[derive(Debug, Clone)]
pub struct WorkflowDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<WorkflowStep>,
    pub inputs: Vec<ParameterDefinition>,
    pub outputs: Vec<ParameterDefinition>,
    pub timeout_minutes: u32,
}

/// Workflow step
#[derive(Debug, Clone)]
pub struct WorkflowStep {
    pub id: String,
    pub name: String,
    pub step_type: StepType,
    pub parameters: HashMap<String, Value>,
    pub dependencies: Vec<String>,
    pub timeout_minutes: u32,
    pub retry_config: Option<RetryConfig>,
}

/// Step type
#[derive(Debug, Clone)]
pub enum StepType {
    Action,
    Decision,
    Parallel,
    SubWorkflow,
    Notification,
    Approval,
}

/// Parameter definition
#[derive(Debug, Clone)]
pub struct ParameterDefinition {
    pub name: String,
    pub parameter_type: ParameterType,
    pub required: bool,
    pub default_value: Option<Value>,
    pub description: String,
}

/// Parameter type
#[derive(Debug, Clone)]
pub enum ParameterType {
    String,
    Integer,
    Boolean,
    Object,
    Array,
    Secret,
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub delay_seconds: u64,
    pub backoff_multiplier: f64,
    pub max_delay_seconds: u64,
}

/// Workflow execution request
#[derive(Debug, Clone)]
pub struct WorkflowExecutionRequest {
    pub instance_id: String,
    pub workflow: WorkflowDefinition,
    pub context: HashMap<String, Value>,
    pub priority: Priority,
    pub submitted_at: DateTime<Utc>,
}

/// Priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Step executor trait
#[async_trait::async_trait]
pub trait StepExecutor: Send + Sync {
    /// Execute a workflow step
    async fn execute(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, String>;

    /// Get the step type this executor handles
    fn step_type(&self) -> StepType;
}

/// SOAR error types
#[derive(Debug, Clone)]
pub enum SoarError {
    WorkflowNotFound,
    ExecutionFailed(String),
    Timeout,
    ValidationError(String),
    ConfigurationError(String),
}

/// SOAR event
#[derive(Debug, Clone)]
pub struct SoarEvent {
    pub event_type: SoarEventType,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub data: HashMap<String, Value>,
}

/// SOAR event types
#[derive(Debug, Clone)]
pub enum SoarEventType {
    WorkflowStarted,
    WorkflowCompleted,
    WorkflowFailed,
    StepStarted,
    StepCompleted,
    StepFailed,
    AlertReceived,
    ResponseTriggered,
}
