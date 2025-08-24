//! SOAR Workflow Orchestration System
//!
//! This module provides a comprehensive workflow orchestration system for security playbooks,
//! including execution management, approval workflows, scheduling, and persistence.

pub mod engine;
pub mod execution;
pub mod approval;
pub mod scheduling;
pub mod persistence;
pub mod metrics;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

pub use engine::*;
pub use execution::*;
pub use approval::*;
pub use scheduling::*;
pub use persistence::*;
pub use metrics::*;

/// Main workflow orchestrator
pub struct WorkflowOrchestrator {
    /// Core workflow engine
    engine: Arc<WorkflowEngine>,
    
    /// Workflow scheduler
    scheduler: Arc<WorkflowScheduler>,
    
    /// Approval manager
    approval_manager: Arc<ApprovalManager>,
    
    /// Metrics collector
    metrics_collector: Arc<MetricsCollector>,
    
    /// Persistence layer
    persistence_layer: Arc<PersistenceLayer>,
    
    /// Configuration
    config: Arc<RwLock<WorkflowOrchestratorConfig>>,
    
    /// Event publisher
    event_publisher: mpsc::Sender<WorkflowEvent>,
}

/// Workflow orchestrator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowOrchestratorConfig {
    /// Maximum concurrent workflows
    pub max_concurrent_workflows: usize,
    
    /// Default workflow timeout
    pub default_timeout: Duration,
    
    /// Enable persistence
    pub persistence_enabled: bool,
    
    /// Enable metrics collection
    pub metrics_enabled: bool,
    
    /// Enable approval workflows
    pub approval_enabled: bool,
    
    /// Enable scheduling
    pub scheduling_enabled: bool,
    
    /// Component configurations
    pub engine_config: WorkflowEngineConfig,
    pub scheduler_config: SchedulerConfig,
    pub approval_config: ApprovalConfig,
    pub metrics_config: MetricsConfig,
    pub persistence_config: PersistenceConfig,
}

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    /// Workflow ID
    pub id: String,
    
    /// Workflow name
    pub name: String,
    
    /// Workflow description
    pub description: String,
    
    /// Workflow version
    pub version: String,
    
    /// Workflow steps
    pub steps: Vec<WorkflowStep>,
    
    /// Workflow variables
    pub variables: HashMap<String, WorkflowVariable>,
    
    /// Workflow triggers
    pub triggers: Vec<WorkflowTrigger>,
    
    /// Workflow metadata
    pub metadata: WorkflowMetadata,
    
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Workflow step definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Step ID
    pub id: String,
    
    /// Step name
    pub name: String,
    
    /// Step type
    pub step_type: StepType,
    
    /// Step configuration
    pub config: StepConfig,
    
    /// Step dependencies
    pub dependencies: Vec<String>,
    
    /// Step conditions
    pub conditions: Vec<StepCondition>,
    
    /// Step timeout
    pub timeout: Option<Duration>,
    
    /// Retry configuration
    pub retry_config: Option<RetryConfig>,
    
    /// Error handling
    pub error_handling: ErrorHandling,
    
    /// Step metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Step types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepType {
    /// Action step
    Action,
    /// Decision step
    Decision,
    /// Parallel execution
    Parallel,
    /// Sequential execution
    Sequential,
    /// Approval step
    Approval,
    /// Wait/delay step
    Wait,
    /// Notification step
    Notification,
    /// Data transformation
    Transform,
    /// External API call
    ApiCall,
    /// Script execution
    Script,
    /// Custom step type
    Custom(String),
}

/// Step configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepConfig {
    /// Executor type
    pub executor: String,
    
    /// Step parameters
    pub parameters: HashMap<String, serde_json::Value>,
    
    /// Input mappings
    pub inputs: HashMap<String, String>,
    
    /// Output mappings
    pub outputs: HashMap<String, String>,
    
    /// Environment variables
    pub environment: HashMap<String, String>,
}

/// Step condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepCondition {
    /// Condition expression
    pub expression: String,
    
    /// Condition type
    pub condition_type: ConditionType,
    
    /// Action on condition failure
    pub on_failure: ConditionFailureAction,
}

/// Condition types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionType {
    /// Pre-condition (evaluated before step)
    PreCondition,
    /// Post-condition (evaluated after step)
    PostCondition,
    /// Guard condition (evaluated during step)
    Guard,
}

/// Condition failure actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConditionFailureAction {
    /// Skip the step
    Skip,
    /// Fail the workflow
    Fail,
    /// Retry the step
    Retry,
    /// Jump to another step
    Jump(String),
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum retry attempts
    pub max_attempts: u32,
    
    /// Retry delay
    pub delay: Duration,
    
    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,
    
    /// Maximum delay
    pub max_delay: Duration,
    
    /// Retry conditions
    pub retry_conditions: Vec<RetryCondition>,
}

/// Retry condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryCondition {
    /// Error pattern to match
    pub error_pattern: String,
    
    /// Whether to retry on this error
    pub should_retry: bool,
}

/// Error handling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandling {
    /// Error handling strategy
    pub strategy: ErrorHandlingStrategy,
    
    /// Rollback steps
    pub rollback_steps: Vec<String>,
    
    /// Notification settings
    pub notifications: Vec<ErrorNotification>,
    
    /// Continue on error
    pub continue_on_error: bool,
}

/// Error handling strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorHandlingStrategy {
    /// Fail fast
    FailFast,
    /// Continue with warnings
    ContinueWithWarnings,
    /// Rollback and retry
    RollbackAndRetry,
    /// Manual intervention
    ManualIntervention,
    /// Custom strategy
    Custom(String),
}

/// Error notification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorNotification {
    /// Notification type
    pub notification_type: NotificationType,
    
    /// Recipients
    pub recipients: Vec<String>,
    
    /// Message template
    pub message_template: String,
    
    /// Severity level
    pub severity: NotificationSeverity,
}

/// Notification types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    /// Email notification
    Email,
    /// Slack notification
    Slack,
    /// SMS notification
    Sms,
    /// Webhook notification
    Webhook,
    /// In-app notification
    InApp,
}

/// Notification severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationSeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Workflow variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowVariable {
    /// Variable name
    pub name: String,
    
    /// Variable type
    pub variable_type: VariableType,
    
    /// Default value
    pub default_value: Option<serde_json::Value>,
    
    /// Variable description
    pub description: String,
    
    /// Whether variable is required
    pub required: bool,
    
    /// Variable validation rules
    pub validation: Vec<ValidationRule>,
}

/// Variable types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariableType {
    /// String variable
    String,
    /// Number variable
    Number,
    /// Boolean variable
    Boolean,
    /// Array variable
    Array,
    /// Object variable
    Object,
    /// Date variable
    Date,
    /// Duration variable
    Duration,
}

/// Validation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Rule type
    pub rule_type: ValidationType,
    
    /// Rule value
    pub value: serde_json::Value,
    
    /// Error message
    pub error_message: String,
}

/// Validation types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationType {
    /// Required validation
    Required,
    /// Minimum length
    MinLength,
    /// Maximum length
    MaxLength,
    /// Pattern matching
    Pattern,
    /// Range validation
    Range,
    /// Custom validation
    Custom(String),
}

/// Workflow trigger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTrigger {
    /// Trigger ID
    pub id: String,
    
    /// Trigger name
    pub name: String,
    
    /// Trigger type
    pub trigger_type: TriggerType,
    
    /// Trigger configuration
    pub config: TriggerConfig,
    
    /// Trigger conditions
    pub conditions: Vec<TriggerCondition>,
    
    /// Trigger enabled
    pub enabled: bool,
}

/// Trigger types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerType {
    /// Manual trigger
    Manual,
    /// Scheduled trigger
    Scheduled,
    /// Event-based trigger
    Event,
    /// API trigger
    Api,
    /// Webhook trigger
    Webhook,
    /// File system trigger
    FileSystem,
    /// Database trigger
    Database,
}

/// Trigger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerConfig {
    /// Trigger parameters
    pub parameters: HashMap<String, serde_json::Value>,
    
    /// Schedule expression (for scheduled triggers)
    pub schedule: Option<String>,
    
    /// Event filters (for event triggers)
    pub event_filters: Vec<EventFilter>,
    
    /// Webhook configuration
    pub webhook_config: Option<WebhookConfig>,
}

/// Event filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Field to filter on
    pub field: String,
    
    /// Filter operator
    pub operator: FilterOperator,
    
    /// Filter value
    pub value: serde_json::Value,
}

/// Filter operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterOperator {
    /// Equal to
    Equals,
    /// Not equal to
    NotEquals,
    /// Contains
    Contains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Greater than
    GreaterThan,
    /// Less than
    LessThan,
    /// In list
    In,
    /// Not in list
    NotIn,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    
    /// HTTP method
    pub method: String,
    
    /// Headers
    pub headers: HashMap<String, String>,
    
    /// Authentication
    pub auth: Option<WebhookAuth>,
    
    /// Timeout
    pub timeout: Duration,
}

/// Webhook authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebhookAuth {
    /// Basic authentication
    Basic { username: String, password: String },
    /// Bearer token
    Bearer { token: String },
    /// API key
    ApiKey { key: String, header: String },
    /// Custom authentication
    Custom(HashMap<String, String>),
}

/// Trigger condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    /// Condition expression
    pub expression: String,
    
    /// Condition description
    pub description: String,
}

/// Workflow metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMetadata {
    /// Workflow author
    pub author: String,
    
    /// Workflow category
    pub category: String,
    
    /// Workflow tags
    pub tags: Vec<String>,
    
    /// Workflow documentation
    pub documentation: Option<String>,
    
    /// Workflow icon
    pub icon: Option<String>,
    
    /// Workflow color
    pub color: Option<String>,
    
    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
}

/// Workflow instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowInstance {
    /// Instance ID
    pub id: String,
    
    /// Workflow definition ID
    pub workflow_id: String,
    
    /// Instance status
    pub status: WorkflowStatus,
    
    /// Current step
    pub current_step: Option<String>,
    
    /// Execution context
    pub context: ExecutionContext,
    
    /// Instance variables
    pub variables: HashMap<String, serde_json::Value>,
    
    /// Step results
    pub step_results: HashMap<String, StepResult>,
    
    /// Instance metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Start timestamp
    pub started_at: DateTime<Utc>,
    
    /// End timestamp
    pub ended_at: Option<DateTime<Utc>>,
    
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// Workflow status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowStatus {
    /// Workflow is pending
    Pending,
    /// Workflow is running
    Running,
    /// Workflow is paused
    Paused,
    /// Workflow completed successfully
    Completed,
    /// Workflow failed
    Failed,
    /// Workflow was cancelled
    Cancelled,
    /// Workflow is waiting for approval
    WaitingForApproval,
    /// Workflow is waiting for manual intervention
    WaitingForIntervention,
}

/// Execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Execution ID
    pub execution_id: String,
    
    /// Trigger information
    pub trigger: TriggerInfo,
    
    /// User context
    pub user: Option<UserContext>,
    
    /// Environment variables
    pub environment: HashMap<String, String>,
    
    /// Execution parameters
    pub parameters: HashMap<String, serde_json::Value>,
    
    /// Parent workflow (for sub-workflows)
    pub parent_workflow: Option<String>,
    
    /// Execution priority
    pub priority: ExecutionPriority,
}

/// Trigger information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerInfo {
    /// Trigger ID
    pub trigger_id: String,
    
    /// Trigger type
    pub trigger_type: TriggerType,
    
    /// Trigger timestamp
    pub triggered_at: DateTime<Utc>,
    
    /// Trigger data
    pub data: HashMap<String, serde_json::Value>,
}

/// User context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// User ID
    pub user_id: String,
    
    /// User name
    pub username: String,
    
    /// User roles
    pub roles: Vec<String>,
    
    /// User permissions
    pub permissions: Vec<String>,
    
    /// User metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Execution priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionPriority {
    /// Low priority
    Low = 1,
    /// Normal priority
    Normal = 2,
    /// High priority
    High = 3,
    /// Critical priority
    Critical = 4,
}

/// Step result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// Step ID
    pub step_id: String,
    
    /// Execution status
    pub status: StepStatus,
    
    /// Result data
    pub data: HashMap<String, serde_json::Value>,
    
    /// Error information
    pub error: Option<StepError>,
    
    /// Execution duration
    pub duration: Duration,
    
    /// Start timestamp
    pub started_at: DateTime<Utc>,
    
    /// End timestamp
    pub ended_at: Option<DateTime<Utc>>,
    
    /// Retry attempts
    pub retry_attempts: u32,
}

/// Step status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StepStatus {
    /// Step is pending
    Pending,
    /// Step is running
    Running,
    /// Step completed successfully
    Completed,
    /// Step failed
    Failed,
    /// Step was skipped
    Skipped,
    /// Step was cancelled
    Cancelled,
    /// Step is waiting for approval
    WaitingForApproval,
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
    
    /// Error timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Whether error is retryable
    pub retryable: bool,
}

/// Workflow event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEvent {
    /// Event ID
    pub id: String,
    
    /// Event type
    pub event_type: WorkflowEventType,
    
    /// Workflow instance ID
    pub workflow_instance_id: String,
    
    /// Step ID (if applicable)
    pub step_id: Option<String>,
    
    /// Event data
    pub data: HashMap<String, serde_json::Value>,
    
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
}

/// Workflow event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkflowEventType {
    /// Workflow started
    WorkflowStarted,
    /// Workflow completed
    WorkflowCompleted,
    /// Workflow failed
    WorkflowFailed,
    /// Workflow cancelled
    WorkflowCancelled,
    /// Workflow paused
    WorkflowPaused,
    /// Workflow resumed
    WorkflowResumed,
    /// Step started
    StepStarted,
    /// Step completed
    StepCompleted,
    /// Step failed
    StepFailed,
    /// Step skipped
    StepSkipped,
    /// Approval requested
    ApprovalRequested,
    /// Approval granted
    ApprovalGranted,
    /// Approval denied
    ApprovalDenied,
}

/// Component trait for workflow components
#[async_trait]
pub trait WorkflowComponent {
    /// Initialize the component
    async fn initialize(&mut self) -> Result<(), WorkflowError>;
    
    /// Start the component
    async fn start(&self) -> Result<(), WorkflowError>;
    
    /// Stop the component
    async fn stop(&self) -> Result<(), WorkflowError>;
    
    /// Get component health status
    fn get_health_status(&self) -> ComponentHealth;
    
    /// Get component metrics
    fn get_metrics(&self) -> ComponentMetrics;
}

/// Component health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub component: String,
    
    /// Health status
    pub status: HealthStatus,
    
    /// Health message
    pub message: String,
    
    /// Last check timestamp
    pub last_check: DateTime<Utc>,
    
    /// Health details
    pub details: HashMap<String, serde_json::Value>,
}

/// Health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Component is healthy
    Healthy,
    /// Component is degraded
    Degraded,
    /// Component is unhealthy
    Unhealthy,
    /// Component status is unknown
    Unknown,
}

/// Component metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentMetrics {
    /// Component name
    pub component: String,
    
    /// Metrics data
    pub metrics: HashMap<String, MetricValue>,
    
    /// Collection timestamp
    pub collected_at: DateTime<Utc>,
}

/// Metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Counter metric
    Counter(u64),
    /// Gauge metric
    Gauge(f64),
    /// Histogram metric
    Histogram(Vec<f64>),
    /// Summary metric
    Summary { count: u64, sum: f64 },
}

/// Workflow error
#[derive(Debug, Clone)]
pub struct WorkflowError {
    /// Error code
    pub code: String,
    
    /// Error message
    pub message: String,
    
    /// Error details
    pub details: Option<serde_json::Value>,
    
    /// Error source
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl std::fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for WorkflowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl Default for WorkflowOrchestratorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workflows: 100,
            default_timeout: Duration::from_secs(3600), // 1 hour
            persistence_enabled: true,
            metrics_enabled: true,
            approval_enabled: true,
            scheduling_enabled: true,
            engine_config: WorkflowEngineConfig::default(),
            scheduler_config: SchedulerConfig::default(),
            approval_config: ApprovalConfig::default(),
            metrics_config: MetricsConfig::default(),
            persistence_config: PersistenceConfig::default(),
        }
    }
}

impl WorkflowOrchestrator {
    /// Create new workflow orchestrator
    pub async fn new(
        config: WorkflowOrchestratorConfig,
        event_publisher: mpsc::Sender<WorkflowEvent>,
    ) -> Result<Self, WorkflowError> {
        let engine = Arc::new(WorkflowEngine::new(config.engine_config.clone()).await?);
        let scheduler = Arc::new(WorkflowScheduler::new(config.scheduler_config.clone()).await?);
        let approval_manager = Arc::new(ApprovalManager::new(config.approval_config.clone()).await?);
        let metrics_collector = Arc::new(MetricsCollector::new(config.metrics_config.clone()).await?);
        let persistence_layer = Arc::new(PersistenceLayer::new(config.persistence_config.clone()).await?);
        
        Ok(Self {
            engine,
            scheduler,
            approval_manager,
            metrics_collector,
            persistence_layer,
            config: Arc::new(RwLock::new(config)),
            event_publisher,
        })
    }
    
    /// Start the orchestrator
    pub async fn start(&self) -> Result<(), WorkflowError> {
        tracing::info!("Starting workflow orchestrator");
        
        // Start all components
        self.engine.start().await?;
        self.scheduler.start().await?;
        self.approval_manager.start().await?;
        self.metrics_collector.start().await?;
        self.persistence_layer.start().await?;
        
        tracing::info!("Workflow orchestrator started successfully");
        Ok(())
    }
    
    /// Stop the orchestrator
    pub async fn stop(&self) -> Result<(), WorkflowError> {
        tracing::info!("Stopping workflow orchestrator");
        
        // Stop all components
        self.engine.stop().await?;
        self.scheduler.stop().await?;
        self.approval_manager.stop().await?;
        self.metrics_collector.stop().await?;
        self.persistence_layer.stop().await?;
        
        tracing::info!("Workflow orchestrator stopped successfully");
        Ok(())
    }
    
    /// Execute a workflow
    pub async fn execute_workflow(
        &self,
        workflow_definition: WorkflowDefinition,
        context: ExecutionContext,
    ) -> Result<String, WorkflowError> {
        let instance_id = Uuid::new_v4().to_string();
        
        tracing::info!("Starting workflow execution: {}", instance_id);
        
        // Create workflow instance
        let instance = WorkflowInstance {
            id: instance_id.clone(),
            workflow_id: workflow_definition.id.clone(),
            status: WorkflowStatus::Pending,
            current_step: None,
            context,
            variables: HashMap::new(),
            step_results: HashMap::new(),
            metadata: HashMap::new(),
            started_at: Utc::now(),
            ended_at: None,
            updated_at: Utc::now(),
        };
        
        // Execute workflow through engine
        self.engine.execute_workflow(workflow_definition, instance).await?;
        
        Ok(instance_id)
    }
    
    /// Get workflow status
    pub async fn get_workflow_status(&self, instance_id: &str) -> Result<WorkflowStatus, WorkflowError> {
        self.engine.get_workflow_status(instance_id).await
    }
    
    /// Cancel workflow
    pub async fn cancel_workflow(&self, instance_id: &str) -> Result<(), WorkflowError> {
        self.engine.cancel_workflow(instance_id).await
    }
    
    /// Get orchestrator health
    pub async fn get_health(&self) -> HashMap<String, ComponentHealth> {
        let mut health = HashMap::new();
        
        health.insert("engine".to_string(), self.engine.get_health_status());
        health.insert("scheduler".to_string(), self.scheduler.get_health_status());
        health.insert("approval_manager".to_string(), self.approval_manager.get_health_status());
        health.insert("metrics_collector".to_string(), self.metrics_collector.get_health_status());
        health.insert("persistence_layer".to_string(), self.persistence_layer.get_health_status());
        
        health
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_definition_creation() {
        let workflow = WorkflowDefinition {
            id: "test_workflow".to_string(),
            name: "Test Workflow".to_string(),
            description: "A test workflow".to_string(),
            version: "1.0".to_string(),
            steps: vec![],
            variables: HashMap::new(),
            triggers: vec![],
            metadata: WorkflowMetadata {
                author: "test".to_string(),
                category: "test".to_string(),
                tags: vec![],
                documentation: None,
                icon: None,
                color: None,
                custom: HashMap::new(),
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        assert_eq!(workflow.id, "test_workflow");
        assert_eq!(workflow.name, "Test Workflow");
    }

    #[test]
    fn test_execution_priority_ordering() {
        assert!(ExecutionPriority::Critical > ExecutionPriority::High);
        assert!(ExecutionPriority::High > ExecutionPriority::Normal);
        assert!(ExecutionPriority::Normal > ExecutionPriority::Low);
    }

    #[test]
    fn test_workflow_status_equality() {
        assert_eq!(WorkflowStatus::Running, WorkflowStatus::Running);
        assert_ne!(WorkflowStatus::Running, WorkflowStatus::Completed);
    }
}
