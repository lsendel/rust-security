//! SOAR Workflow Orchestration Engine
//!
//! This module provides the workflow execution engine for security playbooks,
//! including step execution, dependency management, approval handling, and error recovery.

use async_trait::async_trait;

use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use crate::soar_core::*;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use futures::future::join_all;
#[cfg(feature = "soar")]
use handlebars::Handlebars;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock, Semaphore};
use tokio::time::{sleep, timeout, Duration as TokioDuration, Instant};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

/// Advanced workflow orchestration engine
pub struct WorkflowOrchestrator {
    /// Configuration
    config: Arc<RwLock<WorkflowConfig>>,

    /// Active workflow instances
    active_workflows: Arc<DashMap<String, WorkflowInstance>>,

    /// Execution queue with priority support
    execution_queue: Arc<RwLock<PriorityQueue<WorkflowExecutionRequest>>>,

    /// Step executors registry
    step_executors: Arc<DashMap<String, Arc<dyn StepExecutor + Send + Sync>>>,

    /// Template engine for dynamic content rendering
    template_engine: Arc<Handlebars<'static>>,

    /// Approval manager
    approval_manager: Arc<ApprovalManager>,

    /// Workflow scheduler
    scheduler: Arc<WorkflowScheduler>,

    /// Execution metrics
    metrics: Arc<Mutex<WorkflowMetrics>>,

    /// Concurrency control
    execution_semaphore: Arc<Semaphore>,

    /// Event publisher
    event_publisher: mpsc::Sender<SoarEvent>,

    /// Background task handles
    task_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

/// Workflow configuration
#[derive(Debug, Clone)]
pub struct WorkflowConfig {
    /// Maximum concurrent workflows
    pub max_concurrent_workflows: usize,

    /// Default timeout for workflows
    pub default_timeout_minutes: u32,

    /// Maximum retry attempts
    pub max_retry_attempts: u32,

    /// Step execution timeout
    pub step_timeout_minutes: u32,

    /// Enable parallel execution
    pub parallel_execution_enabled: bool,

    /// Workflow persistence settings
    pub persistence_config: PersistenceConfig,

    /// Error handling settings
    pub error_handling: GlobalErrorHandling,
}

/// Persistence configuration
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Enable workflow state persistence
    pub enabled: bool,

    /// Persistence backend
    pub backend: PersistenceBackend,

    /// Checkpoint frequency
    pub checkpoint_frequency: CheckpointFrequency,

    /// Retention policy
    pub retention_days: u32,
}

/// Persistence backend types
#[derive(Debug, Clone)]
pub enum PersistenceBackend {
    Redis,
    Database,
    FileSystem,
    Memory,
}

/// Checkpoint frequency
#[derive(Debug, Clone)]
pub enum CheckpointFrequency {
    AfterEachStep,
    EveryNSteps(u32),
    TimeInterval(u32), // minutes
    OnError,
}

/// Global error handling configuration
#[derive(Debug, Clone)]
pub struct GlobalErrorHandling {
    /// Default error action
    pub default_action: ErrorAction,

    /// Enable automatic retry
    pub auto_retry_enabled: bool,

    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,

    /// Dead letter queue for failed workflows
    pub dead_letter_queue_enabled: bool,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,

    /// Time window for failure counting
    pub time_window_minutes: u32,

    /// Recovery timeout
    pub recovery_timeout_minutes: u32,
}

/// Priority queue for workflow execution
pub struct PriorityQueue<T> {
    items: VecDeque<PriorityItem<T>>,
}

/// Priority queue item
#[derive(Debug, Clone)]
pub struct PriorityItem<T> {
    item: T,
    priority: u8,
    timestamp: DateTime<Utc>,
}

/// Enhanced step executor trait with lifecycle hooks
#[async_trait::async_trait]
pub trait AdvancedStepExecutor: StepExecutor {
    /// Pre-execution hook
    async fn pre_execute(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
    ) -> Result<(), StepError> {
        Ok(())
    }

    /// Post-execution hook
    async fn post_execute(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
        result: &Result<HashMap<String, Value>, StepError>,
    ) -> Result<(), StepError> {
        Ok(())
    }

    /// Health check for executor
    async fn health_check(&self) -> Result<bool, StepError>;

    /// Get executor capabilities
    fn get_capabilities(&self) -> Vec<String>;
}

/// Approval manager for handling workflow approvals
pub struct ApprovalManager {
    /// Pending approvals
    pending_approvals: Arc<DashMap<String, ApprovalRequest>>,

    /// Approval policies
    approval_policies: Arc<RwLock<Vec<ApprovalPolicy>>>,

    /// Notification sender for approval requests
    notification_sender: mpsc::Sender<ApprovalNotification>,

    /// Auto-approval engine
    auto_approval_engine: Arc<AutoApprovalEngine>,
}

/// Approval policy
#[derive(Debug, Clone)]
pub struct ApprovalPolicy {
    /// Policy ID
    pub id: String,

    /// Policy name
    pub name: String,

    /// Conditions that trigger this policy
    pub conditions: Vec<TriggerCondition>,

    /// Required approvers
    pub required_approvers: Vec<ApproverGroup>,

    /// Approval timeout
    pub timeout_minutes: u32,

    /// Auto-approve conditions
    pub auto_approve_conditions: Vec<TriggerCondition>,

    /// Escalation rules
    pub escalation_rules: Vec<ApprovalEscalationRule>,
}

/// Approver group
#[derive(Debug, Clone)]
pub struct ApproverGroup {
    /// Group ID
    pub id: String,

    /// Group name
    pub name: String,

    /// Members
    pub members: Vec<String>,

    /// Required approvals from this group
    pub required_approvals: u32,

    /// Group priority
    pub priority: u8,
}

/// Approval escalation rule
#[derive(Debug, Clone)]
pub struct ApprovalEscalationRule {
    /// Escalation delay
    pub delay_minutes: u32,

    /// Escalation target
    pub escalation_target: EscalationTarget,

    /// Maximum escalations
    pub max_escalations: u32,
}

/// Escalation target
#[derive(Debug, Clone)]
pub enum EscalationTarget {
    Manager,
    SecurityTeam,
    IncidentResponse,
    Custom(String),
}

/// Approval notification
#[derive(Debug, Clone)]
pub struct ApprovalNotification {
    /// Approval request ID
    pub approval_id: String,

    /// Workflow instance ID
    pub workflow_id: String,

    /// Approver ID
    pub approver_id: String,

    /// Notification type
    pub notification_type: NotificationTargetType,

    /// Message content
    pub message: String,

    /// Urgency level
    pub urgency: UrgencyLevel,
}

/// Urgency levels for notifications
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrgencyLevel {
    Low,
    Normal,
    High,
    Critical,
}

/// Auto-approval engine
pub struct AutoApprovalEngine {
    /// Auto-approval rules
    rules: Arc<RwLock<Vec<AutoApprovalRule>>>,

    /// Risk assessment engine
    risk_assessor: Arc<RiskAssessor>,
}

/// Auto-approval rule
#[derive(Debug, Clone)]
pub struct AutoApprovalRule {
    /// Rule ID
    pub id: String,

    /// Rule name
    pub name: String,

    /// Conditions for auto-approval
    pub conditions: Vec<TriggerCondition>,

    /// Maximum risk score for auto-approval
    pub max_risk_score: u8,

    /// Time constraints
    pub time_constraints: Option<TimeConstraints>,

    /// Rule priority
    pub priority: u8,
}

/// Time constraints for auto-approval
#[derive(Debug, Clone)]
pub struct TimeConstraints {
    /// Allowed days of week
    pub allowed_days: Vec<chrono::Weekday>,

    /// Allowed hours (24-hour format)
    pub allowed_hours: std::ops::Range<u8>,

    /// Timezone
    pub timezone: String,
}

/// Risk assessor for evaluating approval requests
pub struct RiskAssessor {
    /// Risk factors
    risk_factors: Arc<RwLock<Vec<RiskFactor>>>,

    /// Risk calculation model
    calculation_model: RiskCalculationModel,
}

/// Risk factor
#[derive(Debug, Clone)]
pub struct RiskFactor {
    /// Factor name
    pub name: String,

    /// Factor weight (0.0 - 1.0)
    pub weight: f64,

    /// Evaluation function
    pub evaluator: RiskEvaluator,
}

/// Risk evaluator types
#[derive(Debug, Clone)]
pub enum RiskEvaluator {
    /// Fixed score
    Fixed(u8),

    /// Field-based evaluation
    FieldBased {
        field: String,
        scoring_rules: Vec<ScoringRule>,
    },

    /// Custom evaluation logic
    Custom(String),
}

/// Scoring rule for field-based evaluation
#[derive(Debug, Clone)]
pub struct ScoringRule {
    /// Condition for this rule
    pub condition: TriggerCondition,

    /// Score to assign if condition matches
    pub score: u8,
}

/// Risk calculation model
#[derive(Debug, Clone)]
pub enum RiskCalculationModel {
    /// Weighted average
    WeightedAverage,

    /// Maximum score
    Maximum,

    /// Custom calculation
    Custom(String),
}

/// Workflow scheduler for time-based execution
pub struct WorkflowScheduler {
    /// Scheduled workflows
    scheduled_workflows: Arc<DashMap<String, ScheduledWorkflow>>,

    /// Recurring workflows
    recurring_workflows: Arc<DashMap<String, RecurringWorkflow>>,

    /// Scheduler configuration
    config: SchedulerConfig,
}

/// Scheduled workflow
#[derive(Debug, Clone)]
pub struct ScheduledWorkflow {
    /// Schedule ID
    pub id: String,

    /// Playbook ID to execute
    pub playbook_id: String,

    /// Scheduled execution time
    pub execution_time: DateTime<Utc>,

    /// Input parameters
    pub inputs: HashMap<String, Value>,

    /// Execution context
    pub context: HashMap<String, Value>,

    /// Priority
    pub priority: u8,

    /// Status
    pub status: ScheduleStatus,
}

/// Recurring workflow
#[derive(Debug, Clone)]
pub struct RecurringWorkflow {
    /// Recurring schedule ID
    pub id: String,

    /// Playbook ID to execute
    pub playbook_id: String,

    /// Cron expression for scheduling
    pub cron_expression: String,

    /// Input parameters
    pub inputs: HashMap<String, Value>,

    /// Execution context
    pub context: HashMap<String, Value>,

    /// Whether the schedule is active
    pub active: bool,

    /// Next execution time
    pub next_execution: DateTime<Utc>,

    /// Last execution time
    pub last_execution: Option<DateTime<Utc>>,
}

/// Schedule status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleStatus {
    Pending,
    Executing,
    Completed,
    Failed,
    Cancelled,
}

/// Scheduler configuration
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Check interval for scheduled workflows
    pub check_interval_seconds: u64,

    /// Maximum schedule lookahead
    pub max_lookahead_hours: u32,

    /// Enable recurring workflows
    pub recurring_enabled: bool,

    /// Maximum concurrent scheduled workflows
    pub max_concurrent_scheduled: usize,
}

/// Enhanced workflow execution context
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Basic context
    pub base_context: HashMap<String, Value>,

    /// Execution metadata
    pub metadata: ExecutionMetadata,

    /// Security context
    pub security_context: SecurityContext,

    /// Performance tracking
    pub performance: PerformanceTracker,
}

/// Execution metadata
#[derive(Debug, Clone)]
pub struct ExecutionMetadata {
    /// Execution ID
    pub execution_id: String,

    /// Parent workflow ID (for sub-workflows)
    pub parent_workflow_id: Option<String>,

    /// Execution trigger
    pub trigger: ExecutionTrigger,

    /// Execution priority
    pub priority: u8,

    /// Execution tags
    pub tags: Vec<String>,
}

/// Execution trigger information
#[derive(Debug, Clone)]
pub struct ExecutionTrigger {
    /// Trigger type
    pub trigger_type: TriggerType,

    /// Trigger source
    pub source: String,

    /// Trigger timestamp
    pub timestamp: DateTime<Utc>,

    /// Trigger data
    pub data: Value,
}

/// Security context for workflow execution
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Executing user/service
    pub executor: String,

    /// Authorization scopes
    pub scopes: Vec<String>,

    /// Security constraints
    pub constraints: Vec<SecurityConstraint>,

    /// Audit trail
    pub audit_trail: Vec<AuditEntry>,
}

/// Security constraint
#[derive(Debug, Clone)]
pub struct SecurityConstraint {
    /// Constraint type
    pub constraint_type: ConstraintType,

    /// Constraint value
    pub value: Value,

    /// Enforcement level
    pub enforcement: EnforcementLevel,
}

/// Constraint types
#[derive(Debug, Clone)]
pub enum ConstraintType {
    TimeWindow,
    IpRestriction,
    ActionLimit,
    ResourceAccess,
    Custom(String),
}

/// Enforcement levels
#[derive(Debug, Clone)]
pub enum EnforcementLevel {
    Advisory,
    Warning,
    Blocking,
}

/// Audit entry
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Action performed
    pub action: String,

    /// Actor
    pub actor: String,

    /// Result
    pub result: String,

    /// Additional data
    pub data: Value,
}

/// Performance tracker
#[derive(Debug, Clone)]
pub struct PerformanceTracker {
    /// Start time
    pub start_time: Instant,

    /// Step timings
    pub step_timings: HashMap<String, StepTiming>,

    /// Resource usage
    pub resource_usage: ResourceUsage,

    /// Performance metrics
    pub metrics: HashMap<String, f64>,
}

/// Step timing information
#[derive(Debug, Clone)]
pub struct StepTiming {
    /// Step start time
    pub start_time: Instant,

    /// Step end time
    pub end_time: Option<Instant>,

    /// Step duration
    pub duration: Option<TokioDuration>,

    /// Retry attempts
    pub retry_count: u32,
}

/// Resource usage tracking
#[derive(Debug, Clone)]
pub struct ResourceUsage {
    /// Memory usage in bytes
    pub memory_bytes: u64,

    /// CPU time in microseconds
    pub cpu_time_us: u64,

    /// Network I/O bytes
    pub network_io_bytes: u64,

    /// Disk I/O bytes
    pub disk_io_bytes: u64,
}

impl WorkflowOrchestrator {
    /// Create a new workflow orchestrator
    pub async fn new(
        config: WorkflowConfig,
        event_publisher: mpsc::Sender<SoarEvent>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let execution_semaphore = Arc::new(Semaphore::new(config.max_concurrent_workflows));

        let mut template_engine = Handlebars::new();
        template_engine.set_strict_mode(false);

        let (notification_sender, notification_receiver) = mpsc::channel(100);

        let orchestrator = Self {
            config: Arc::new(RwLock::new(config)),
            active_workflows: Arc::new(DashMap::new()),
            execution_queue: Arc::new(RwLock::new(PriorityQueue::new())),
            step_executors: Arc::new(DashMap::new()),
            template_engine: Arc::new(template_engine),
            approval_manager: Arc::new(
                ApprovalManager::new(notification_sender, notification_receiver).await?,
            ),
            scheduler: Arc::new(WorkflowScheduler::new().await?),
            metrics: Arc::new(Mutex::new(WorkflowMetrics::default())),
            execution_semaphore,
            event_publisher,
            task_handles: Arc::new(Mutex::new(Vec::new())),
        };

        // Register default step executors
        orchestrator.register_default_executors().await?;

        Ok(orchestrator)
    }

    /// Initialize the orchestrator
    #[instrument(skip(self))]
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing workflow orchestrator");

        // Start background processors
        self.start_execution_processor().await;
        self.start_approval_processor().await;
        self.start_scheduler_processor().await;
        self.start_metrics_collector().await;
        self.start_cleanup_processor().await;

        info!("Workflow orchestrator initialized successfully");
        Ok(())
    }

    /// Execute a workflow
    #[instrument(skip(self, playbook, inputs, context))]
    pub async fn execute_workflow(
        &self,
        playbook: SecurityPlaybook,
        inputs: HashMap<String, Value>,
        context: HashMap<String, Value>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let instance_id = Uuid::new_v4().to_string();

        // Create execution context
        let execution_context = ExecutionContext {
            base_context: context.clone(),
            metadata: ExecutionMetadata {
                execution_id: instance_id.clone(),
                parent_workflow_id: None,
                trigger: ExecutionTrigger {
                    trigger_type: TriggerType::ManualTrigger,
                    source: "api".to_string(),
                    timestamp: Utc::now(),
                    data: serde_json::to_value(&inputs)?,
                },
                priority: 5,
                tags: vec!["manual".to_string()],
            },
            security_context: SecurityContext {
                executor: "system".to_string(),
                scopes: vec!["workflow:execute".to_string()],
                constraints: Vec::new(),
                audit_trail: Vec::new(),
            },
            performance: PerformanceTracker {
                start_time: Instant::now(),
                step_timings: HashMap::new(),
                resource_usage: ResourceUsage {
                    memory_bytes: 0,
                    cpu_time_us: 0,
                    network_io_bytes: 0,
                    disk_io_bytes: 0,
                },
                metrics: HashMap::new(),
            },
        };

        // Create workflow instance
        let instance = WorkflowInstance {
            id: instance_id.clone(),
            playbook_id: playbook.id.clone(),
            status: WorkflowStatus::Pending,
            started_at: Utc::now(),
            ended_at: None,
            current_step: 0,
            context: context.clone(),
            step_results: HashMap::new(),
            error: None,
            inputs: inputs.clone(),
            outputs: HashMap::new(),
            approval_requests: Vec::new(),
        };

        self.active_workflows.insert(instance_id.clone(), instance);

        // Create execution request
        let (response_tx, response_rx) = oneshot::channel();
        let execution_request = WorkflowExecutionRequest {
            instance_id: instance_id.clone(),
            playbook,
            inputs,
            context,
            response_tx,
        };

        // Queue for execution
        {
            let mut queue = self.execution_queue.write().await;
            queue.push(execution_request, 5); // Default priority
        }

        // Publish workflow triggered event
        let event = SoarEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: SoarEventType::WorkflowTriggered,
            data: serde_json::json!({
                "instance_id": instance_id,
                "playbook_id": playbook.id,
                "trigger": "manual"
            }),
            source: "workflow_orchestrator".to_string(),
            priority: 3,
        };

        if let Err(e) = self.event_publisher.send(event).await {
            warn!("Failed to publish workflow triggered event: {}", e);
        }

        info!("Queued workflow execution: {}", instance_id);
        Ok(instance_id)
    }

    /// Schedule a workflow for future execution
    #[instrument(skip(self, playbook_id, inputs, context))]
    pub async fn schedule_workflow(
        &self,
        playbook_id: String,
        execution_time: DateTime<Utc>,
        inputs: HashMap<String, Value>,
        context: HashMap<String, Value>,
        priority: u8,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        self.scheduler
            .schedule_workflow(playbook_id, execution_time, inputs, context, priority)
            .await
    }

    /// Submit approval for a workflow
    #[instrument(skip(self))]
    pub async fn submit_approval(
        &self,
        approval_id: String,
        approver_id: String,
        decision: ApprovalDecision,
        comments: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.approval_manager
            .submit_approval(approval_id, approver_id, decision, comments)
            .await
    }

    /// Get workflow status
    pub async fn get_workflow_status(&self, instance_id: &str) -> Option<WorkflowInstance> {
        self.active_workflows
            .get(instance_id)
            .map(|entry| entry.clone())
    }

    /// Cancel a workflow
    #[instrument(skip(self))]
    pub async fn cancel_workflow(
        &self,
        instance_id: String,
        reason: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(mut instance) = self.active_workflows.get_mut(&instance_id) {
            instance.status = WorkflowStatus::Cancelled;
            instance.ended_at = Some(Utc::now());
            instance.error = Some(WorkflowError {
                code: "CANCELLED".to_string(),
                message: reason,
                details: None,
                failed_step: None,
            });

            info!("Cancelled workflow: {}", instance_id);

            // Publish workflow cancelled event
            let event = SoarEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: SoarEventType::WorkflowFailed,
                data: serde_json::json!({
                    "instance_id": instance_id,
                    "reason": "cancelled"
                }),
                source: "workflow_orchestrator".to_string(),
                priority: 3,
            };

            if let Err(e) = self.event_publisher.send(event).await {
                warn!("Failed to publish workflow cancelled event: {}", e);
            }
        }

        Ok(())
    }

    /// Register a step executor
    pub async fn register_step_executor(
        &self,
        executor: Arc<dyn StepExecutor + Send + Sync>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let step_type = executor.get_step_type();
        self.step_executors.insert(step_type.clone(), executor);
        info!("Registered step executor: {}", step_type);
        Ok(())
    }

    /// Start execution processor
    async fn start_execution_processor(&self) {
        let execution_queue = self.execution_queue.clone();
        let active_workflows = self.active_workflows.clone();
        let step_executors = self.step_executors.clone();
        let template_engine = self.template_engine.clone();
        let approval_manager = self.approval_manager.clone();
        let execution_semaphore = self.execution_semaphore.clone();
        let event_publisher = self.event_publisher.clone();
        let config = self.config.clone();

        let handle = tokio::spawn(async move {
            info!("Starting workflow execution processor");

            loop {
                // Get next execution request
                let request = {
                    let mut queue = execution_queue.write().await;
                    queue.pop()
                };

                if let Some(request) = request {
                    // Acquire semaphore permit for concurrency control
                    let permit = execution_semaphore.acquire().await.unwrap();

                    let active_workflows = active_workflows.clone();
                    let step_executors = step_executors.clone();
                    let template_engine = template_engine.clone();
                    let approval_manager = approval_manager.clone();
                    let event_publisher = event_publisher.clone();
                    let config = config.clone();

                    // Execute workflow in background
                    tokio::spawn(async move {
                        let _permit = permit; // Keep permit until workflow completes

                        let result = Self::execute_workflow_internal(
                            request,
                            active_workflows,
                            step_executors,
                            template_engine,
                            approval_manager,
                            event_publisher,
                            config,
                        )
                        .await;

                        if let Err(e) = result {
                            error!("Workflow execution failed: {}", e);
                        }
                    });
                } else {
                    // No requests in queue, sleep briefly
                    sleep(TokioDuration::from_millis(100)).await;
                }
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }

    /// Internal workflow execution logic
    async fn execute_workflow_internal(
        request: WorkflowExecutionRequest,
        active_workflows: Arc<DashMap<String, WorkflowInstance>>,
        step_executors: Arc<DashMap<String, Arc<dyn StepExecutor + Send + Sync>>>,
        template_engine: Arc<Handlebars<'static>>,
        approval_manager: Arc<ApprovalManager>,
        event_publisher: mpsc::Sender<SoarEvent>,
        config: Arc<RwLock<WorkflowConfig>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let instance_id = request.instance_id.clone();
        let playbook = request.playbook.clone();

        // Update workflow status to running
        if let Some(mut instance) = active_workflows.get_mut(&instance_id) {
            instance.status = WorkflowStatus::Running;
        }

        let mut execution_context = request.context;
        execution_context.insert(
            "workflow_id".to_string(),
            Value::String(instance_id.clone()),
        );
        execution_context.insert(
            "playbook_id".to_string(),
            Value::String(playbook.id.clone()),
        );

        let mut step_results = HashMap::new();
        let mut workflow_error = None;
        let start_time = std::time::Instant::now();

        // Execute steps in order
        for (step_index, step) in playbook.steps.iter().enumerate() {
            // Check if workflow was cancelled
            if let Some(instance) = active_workflows.get(&instance_id) {
                if instance.status == WorkflowStatus::Cancelled {
                    break;
                }
            }

            // Update current step
            if let Some(mut instance) = active_workflows.get_mut(&instance_id) {
                instance.current_step = step_index;
            }

            // Check step dependencies
            if !Self::check_dependencies(&step.dependencies, &step_results) {
                let error = StepError {
                    code: "DEPENDENCY_FAILED".to_string(),
                    message: format!("Dependencies not satisfied for step: {}", step.id),
                    details: None,
                    retryable: false,
                };

                step_results.insert(
                    step.id.clone(),
                    StepResult {
                        step_id: step.id.clone(),
                        status: StepStatus::Failed,
                        started_at: Utc::now(),
                        ended_at: Some(Utc::now()),
                        outputs: HashMap::new(),
                        error: Some(error.clone()),
                        retry_count: 0,
                    },
                );

                workflow_error = Some(WorkflowError {
                    code: "STEP_DEPENDENCY_FAILED".to_string(),
                    message: error.message,
                    details: None,
                    failed_step: Some(step.id.clone()),
                });
                break;
            }

            // Evaluate step conditions
            if !Self::evaluate_conditions(&step.conditions, &execution_context) {
                // Skip step if conditions not met
                step_results.insert(
                    step.id.clone(),
                    StepResult {
                        step_id: step.id.clone(),
                        status: StepStatus::Skipped,
                        started_at: Utc::now(),
                        ended_at: Some(Utc::now()),
                        outputs: HashMap::new(),
                        error: None,
                        retry_count: 0,
                    },
                );
                continue;
            }

            // Check if approval is required for this step
            if step.step_type == StepType::Approval {
                match Self::handle_approval_step(
                    &step,
                    &instance_id,
                    &execution_context,
                    &approval_manager,
                )
                .await
                {
                    Ok(approval_result) => {
                        if !approval_result {
                            // Approval denied
                            workflow_error = Some(WorkflowError {
                                code: "APPROVAL_DENIED".to_string(),
                                message: "Step approval was denied".to_string(),
                                details: None,
                                failed_step: Some(step.id.clone()),
                            });
                            break;
                        }
                    }
                    Err(e) => {
                        workflow_error = Some(WorkflowError {
                            code: "APPROVAL_FAILED".to_string(),
                            message: e.to_string(),
                            details: None,
                            failed_step: Some(step.id.clone()),
                        });
                        break;
                    }
                }
            }

            // Execute step
            let step_result =
                Self::execute_step(step, &execution_context, &step_executors, &template_engine)
                    .await;

            match step_result {
                Ok(result) => {
                    step_results.insert(step.id.clone(), operation_result.clone());

                    // Merge step outputs into execution context
                    for (key, value) in operation_result.outputs {
                        execution_context.insert(key, value);
                    }
                }
                Err(e) => {
                    let step_error = StepResult {
                        step_id: step.id.clone(),
                        status: StepStatus::Failed,
                        started_at: Utc::now(),
                        ended_at: Some(Utc::now()),
                        outputs: HashMap::new(),
                        error: Some(e.clone()),
                        retry_count: 0,
                    };

                    step_results.insert(step.id.clone(), step_error);

                    // Handle step error based on error handling configuration
                    if !step.error_handling.continue_on_error {
                        workflow_error = Some(WorkflowError {
                            code: "STEP_EXECUTION_FAILED".to_string(),
                            message: e.message,
                            details: e.details,
                            failed_step: Some(step.id.clone()),
                        });
                        break;
                    }
                }
            }
        }

        // Update final workflow status
        let final_status = if workflow_error.is_some() {
            WorkflowStatus::Failed
        } else {
            WorkflowStatus::Completed
        };

        if let Some(mut instance) = active_workflows.get_mut(&instance_id) {
            instance.status = final_status.clone();
            instance.ended_at = Some(Utc::now());
            instance.step_results = step_results.clone();
            instance.error = workflow_error.clone();

            // Extract outputs from final context
            for output_def in &playbook.outputs {
                if let Some(value) = execution_context.get(&output_def.name) {
                    instance
                        .outputs
                        .insert(output_def.name.clone(), value.clone());
                }
            }
        }

        // Publish workflow completion event
        let event_type = match final_status {
            WorkflowStatus::Completed => SoarEventType::WorkflowCompleted,
            _ => SoarEventType::WorkflowFailed,
        };

        let event = SoarEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            data: serde_json::json!({
                "instance_id": instance_id,
                "playbook_id": playbook.id,
                "status": final_status,
                "error": workflow_error
            }),
            source: "workflow_orchestrator".to_string(),
            priority: 2,
        };

        if let Err(e) = event_publisher.send(event).await {
            warn!("Failed to publish workflow completion event: {}", e);
        }

        // Send response if channel is still open
        let result = if let Some(error) = workflow_error {
            Err(error)
        } else {
            Ok(WorkflowResult {
                instance_id: instance_id.clone(),
                status: final_status,
                outputs: execution_context.clone(),
                duration_ms: start_time.elapsed().as_millis() as u64,
                step_results,
            })
        };

        let _ = request.response_tx.send(result);

        info!("Workflow execution completed: {}", instance_id);
        Ok(())
    }

    /// Execute a single step
    async fn execute_step(
        step: &WorkflowStep,
        context: &HashMap<String, Value>,
        step_executors: &Arc<DashMap<String, Arc<dyn StepExecutor + Send + Sync>>>,
        template_engine: &Arc<Handlebars<'static>>,
    ) -> Result<StepResult, StepError> {
        let start_time = Utc::now();

        // Get appropriate executor
        let executor = step_executors
            .get(&step.step_type.to_string())
            .ok_or_else(|| StepError {
                code: "EXECUTOR_NOT_FOUND".to_string(),
                message: format!("No executor found for step type: {:?}", step.step_type),
                details: None,
                retryable: false,
            })?;

        // Render dynamic content in step inputs
        let mut rendered_step = step.clone();
        Self::render_step_content(&mut rendered_step, context, template_engine)?;

        // Execute with timeout
        let timeout_duration = TokioDuration::from_secs((step.timeout_minutes * 60) as u64);

        let execution_result = timeout(
            timeout_duration,
            executor.execute_step(&rendered_step, context),
        )
        .await;

        match execution_result {
            Ok(Ok(outputs)) => Ok(StepResult {
                step_id: step.id.clone(),
                status: StepStatus::Completed,
                started_at: start_time,
                ended_at: Some(Utc::now()),
                outputs,
                error: None,
                retry_count: 0,
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(StepError {
                code: "STEP_TIMEOUT".to_string(),
                message: format!(
                    "Step execution timed out after {} minutes",
                    step.timeout_minutes
                ),
                details: None,
                retryable: true,
            }),
        }
    }

    /// Render dynamic content in step
    fn render_step_content(
        step: &mut WorkflowStep,
        context: &HashMap<String, Value>,
        template_engine: &Handlebars<'static>,
    ) -> Result<(), StepError> {
        // Render step action parameters
        match &mut step.action {
            StepAction::BlockIp {
                ip_address, reason, ..
            } => {
                *ip_address = Self::render_template(ip_address, context, template_engine)?;
                *reason = Self::render_template(reason, context, template_engine)?;
            }
            StepAction::LockAccount {
                user_id, reason, ..
            } => {
                *user_id = Self::render_template(user_id, context, template_engine)?;
                *reason = Self::render_template(reason, context, template_engine)?;
            }
            StepAction::SendNotification {
                subject, message, ..
            } => {
                *subject = Self::render_template(subject, context, template_engine)?;
                *message = Self::render_template(message, context, template_engine)?;
            }
            _ => {} // Other actions don't need rendering yet
        }

        Ok(())
    }

    /// Render a template string
    fn render_template(
        template: &str,
        context: &HashMap<String, Value>,
        template_engine: &Handlebars<'static>,
    ) -> Result<String, StepError> {
        template_engine
            .render_template(template, context)
            .map_err(|e| StepError {
                code: "TEMPLATE_RENDER_ERROR".to_string(),
                message: format!("Failed to render template: {}", e),
                details: Some(serde_json::json!({
                    "template": template,
                    "error": e.to_string()
                })),
                retryable: false,
            })
    }

    /// Check step dependencies
    fn check_dependencies(
        dependencies: &[String],
        step_results: &HashMap<String, StepResult>,
    ) -> bool {
        dependencies.iter().all(|dep| {
            step_results
                .get(dep)
                .map(|result| operation_result.status == StepStatus::Completed)
                .unwrap_or(false)
        })
    }

    /// Evaluate step conditions
    fn evaluate_conditions(
        conditions: &[TriggerCondition],
        context: &HashMap<String, Value>,
    ) -> bool {
        if conditions.is_empty() {
            return true;
        }

        conditions.iter().all(|condition| {
            let field_value = context.get(&condition.field);
            Self::evaluate_condition(condition, field_value)
        })
    }

    /// Evaluate a single condition
    fn evaluate_condition(condition: &TriggerCondition, field_value: Option<&Value>) -> bool {
        match (field_value, &condition.operator) {
            (Some(value), ConditionOperator::Equals) => value == &condition.value,
            (Some(value), ConditionOperator::NotEquals) => value != &condition.value,
            (Some(Value::String(s)), ConditionOperator::Contains) => {
                if let Value::String(pattern) = &condition.value {
                    s.contains(pattern)
                } else {
                    false
                }
            }
            (Some(Value::Number(n)), ConditionOperator::GreaterThan) => {
                if let Value::Number(threshold) = &condition.value {
                    n.as_f64().unwrap_or(0.0) > threshold.as_f64().unwrap_or(0.0)
                } else {
                    false
                }
            }
            (None, _) => !condition.required,
            _ => false,
        }
    }

    /// Handle approval step
    async fn handle_approval_step(
        step: &WorkflowStep,
        instance_id: &str,
        context: &HashMap<String, Value>,
        approval_manager: &ApprovalManager,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Create approval request
        let approval_request = ApprovalRequest {
            id: Uuid::new_v4().to_string(),
            workflow_instance_id: instance_id.to_string(),
            step_id: step.id.clone(),
            approval_type: ApprovalType::Manual,
            required_approvers: step
                .inputs
                .get("approvers")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_else(|| vec!["security-team".to_string()]),
            required_approvals: 1,
            current_approvals: Vec::new(),
            requested_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(step.timeout_minutes as i64),
            status: ApprovalStatus::Pending,
            context: context.clone(),
        };

        // Submit approval request
        approval_manager.request_approval(approval_request).await?;

        // TODO: Wait for approval response
        // For now, return true (auto-approve)
        Ok(true)
    }

    /// Register default step executors
    async fn register_default_executors(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::soar_executors::*;

        info!("Registering built-in step executors...");

        // Security action executors
        self.step_executors
            .insert("block_ip".to_string(), Arc::new(IpBlockExecutor::new()));

        self.step_executors.insert(
            "lock_account".to_string(),
            Arc::new(AccountLockExecutor::new()),
        );

        self.step_executors.insert(
            "revoke_tokens".to_string(),
            Arc::new(TokenRevokeExecutor::new()),
        );

        // Notification executors
        self.step_executors.insert(
            "email_notification".to_string(),
            Arc::new(EmailNotificationExecutor::new().await?),
        );

        self.step_executors.insert(
            "slack_notification".to_string(),
            Arc::new(SlackNotificationExecutor::new()),
        );

        self.step_executors.insert(
            "webhook_notification".to_string(),
            Arc::new(WebhookNotificationExecutor::new()),
        );

        // Query and data executors
        self.step_executors
            .insert("siem_query".to_string(), Arc::new(SiemQueryExecutor::new()));

        self.step_executors.insert(
            "database_query".to_string(),
            Arc::new(DatabaseQueryExecutor::new()),
        );

        // Case and ticket management
        self.step_executors.insert(
            "create_ticket".to_string(),
            Arc::new(TicketCreateExecutor::new()),
        );

        self.step_executors.insert(
            "update_case".to_string(),
            Arc::new(CaseUpdateExecutor::new()),
        );

        // Script and automation executors
        self.step_executors.insert(
            "execute_script".to_string(),
            Arc::new(ScriptExecutor::new()),
        );

        self.step_executors.insert(
            "http_request".to_string(),
            Arc::new(HttpRequestExecutor::new()),
        );

        // Control flow executors
        self.step_executors
            .insert("decision".to_string(), Arc::new(DecisionExecutor::new()));

        self.step_executors
            .insert("wait".to_string(), Arc::new(WaitExecutor::new()));

        let executor_count = self.step_executors.len();
        info!(
            "Successfully registered {} built-in step executors",
            executor_count
        );

        // Log all registered executors for debugging
        let executor_types: Vec<String> =
            self.step_executors.iter().map(|(k, _)| k.clone()).collect();
        debug!("Registered step executor types: {:?}", executor_types);

        Ok(())
    }

    /// Start approval processor
    async fn start_approval_processor(&self) {
        let approval_manager = self.approval_manager.clone();

        let handle = tokio::spawn(async move {
            approval_manager.start_processor().await;
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }

    /// Start scheduler processor
    async fn start_scheduler_processor(&self) {
        let scheduler = self.scheduler.clone();

        let handle = tokio::spawn(async move {
            scheduler.start_processor().await;
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }

    /// Start metrics collector
    async fn start_metrics_collector(&self) {
        let metrics = self.metrics.clone();
        let active_workflows = self.active_workflows.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TokioDuration::from_secs(60));

            loop {
                interval.tick().await;

                let mut metrics_guard = metrics.lock().await;
                metrics_guard.active_workflows = active_workflows.len() as u64;

                debug!("Updated workflow metrics");
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }

    /// Start cleanup processor
    async fn start_cleanup_processor(&self) {
        let active_workflows = self.active_workflows.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TokioDuration::from_secs(3600)); // 1 hour

            loop {
                interval.tick().await;

                let cutoff_time = Utc::now() - Duration::hours(24);
                let mut to_remove = Vec::new();

                for entry in active_workflows.iter() {
                    let instance = entry.value();
                    if let Some(ended_at) = instance.ended_at {
                        if ended_at < cutoff_time {
                            to_remove.push(entry.key().clone());
                        }
                    }
                }

                for id in to_remove {
                    active_workflows.remove(&id);
                }

                debug!("Cleaned up old workflow instances");
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }
}

// Implementation stubs for supporting components
impl<T> PriorityQueue<T> {
    fn new() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }

    fn push(&mut self, item: T, priority: u8) {
        let priority_item = PriorityItem {
            item,
            priority,
            timestamp: Utc::now(),
        };

        // Insert in priority order (higher priority first)
        let insert_pos = self
            .items
            .iter()
            .position(|existing| existing.priority < priority)
            .unwrap_or(self.items.len());

        self.items.insert(insert_pos, priority_item);
    }

    fn pop(&mut self) -> Option<T> {
        self.items.pop_front().map(|item| item.item)
    }
}

impl ApprovalManager {
    async fn new(
        _notification_sender: mpsc::Sender<ApprovalNotification>,
        _notification_receiver: mpsc::Receiver<ApprovalNotification>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            pending_approvals: Arc::new(DashMap::new()),
            approval_policies: Arc::new(RwLock::new(Vec::new())),
            notification_sender: _notification_sender,
            auto_approval_engine: Arc::new(AutoApprovalEngine::new()),
        })
    }

    async fn request_approval(
        &self,
        approval_request: ApprovalRequest,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.pending_approvals
            .insert(approval_request.id.clone(), approval_request);
        Ok(())
    }

    async fn submit_approval(
        &self,
        approval_id: String,
        approver_id: String,
        decision: ApprovalDecision,
        comments: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Processing approval submission: {} by {} with decision: {:?}",
            approval_id, approver_id, decision
        );

        // Find the pending approval
        let approval_request = self.pending_approvals.remove(&approval_id).ok_or_else(|| {
            error!(
                "Approval request {} not found in pending approvals",
                approval_id
            );
            format!("Approval request {} not found", approval_id)
        })?;

        // Validate that the approver is authorized
        if !self
            .validate_approver_authorization(&approval_request, &approver_id)
            .await?
        {
            error!(
                "Approver {} not authorized for approval {}",
                approver_id, approval_id
            );
            return Err(
                format!("Approver {} not authorized for this approval", approver_id).into(),
            );
        }

        // Create approval response
        let response = ApprovalResponse {
            approval_id: approval_id.clone(),
            approver_id: approver_id.clone(),
            decision: decision.clone(),
            comments: comments.clone(),
            timestamp: Utc::now(),
        };

        // Store the approval response
        self.approval_responses
            .insert(approval_id.clone(), response.clone());

        // Log the approval decision
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::AdminAction,
                SecuritySeverity::Medium,
                "soar_workflow".to_string(),
                format!(
                    "Approval {} {} by {}",
                    approval_id,
                    match decision {
                        ApprovalDecision::Approved => "approved",
                        ApprovalDecision::Rejected => "rejected",
                        ApprovalDecision::RequestMoreInfo => "requested more info for",
                    },
                    approver_id
                ),
            )
            .with_actor(approver_id.clone())
            .with_action("submit_approval".to_string())
            .with_target("soar_workflow".to_string())
            .with_outcome(
                match decision {
                    ApprovalDecision::Approved => "approved",
                    ApprovalDecision::Rejected => "rejected",
                    ApprovalDecision::RequestMoreInfo => "more_info_requested",
                }
                .to_string(),
            )
            .with_reason(format!("Manual approval decision: {:?}", decision))
            .with_detail("approval_id".to_string(), approval_id.clone())
            .with_detail(
                "workflow_id".to_string(),
                approval_request.workflow_id.clone(),
            )
            .with_detail(
                "comments".to_string(),
                comments.unwrap_or("None".to_string()),
            ),
        );

        // Handle the approval decision
        match decision {
            ApprovalDecision::Approved => {
                info!(
                    "Approval {} approved, resuming workflow {}",
                    approval_id, approval_request.workflow_id
                );
                self.resume_workflow_after_approval(&approval_request.workflow_id, true)
                    .await?;
            }
            ApprovalDecision::Rejected => {
                warn!(
                    "Approval {} rejected, stopping workflow {}",
                    approval_id, approval_request.workflow_id
                );
                self.resume_workflow_after_approval(&approval_request.workflow_id, false)
                    .await?;
            }
            ApprovalDecision::RequestMoreInfo => {
                info!("More information requested for approval {}", approval_id);
                // For now, treat as rejected. In a full implementation,
                // this would notify the requester to provide more information
                self.resume_workflow_after_approval(&approval_request.workflow_id, false)
                    .await?;
            }
        }

        // Send notifications about the approval decision
        self.send_approval_notification(&approval_request, &response)
            .await?;

        info!("Successfully processed approval submission {}", approval_id);
        Ok(())
    }

    /// Validate that the approver is authorized to make this approval decision
    async fn validate_approver_authorization(
        &self,
        approval_request: &ApprovalRequest,
        approver_id: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // Check if the approver is in the list of authorized approvers
        if let Some(authorized_approvers) = &approval_request.authorized_approvers {
            if !authorized_approvers.contains(&approver_id.to_string()) {
                return Ok(false);
            }
        }

        // Additional authorization checks could go here:
        // - Check if approver has the required role
        // - Check if approver is not the same as the requester
        // - Check organizational hierarchy

        // For now, if no specific approvers are listed, any authenticated user can approve
        Ok(true)
    }

    /// Resume workflow execution after approval decision
    async fn resume_workflow_after_approval(
        &self,
        workflow_id: &str,
        approved: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // This would integrate with the workflow engine to resume execution
        // For now, we'll just log the action
        if approved {
            info!("Workflow {} approved and ready to resume", workflow_id);
            // TODO: Send signal to workflow engine to resume execution
        } else {
            warn!("Workflow {} rejected and will be terminated", workflow_id);
            // TODO: Send signal to workflow engine to terminate execution
        }
        Ok(())
    }

    /// Send notifications about approval decisions
    async fn send_approval_notification(
        &self,
        approval_request: &ApprovalRequest,
        response: &ApprovalResponse,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let subject = format!(
            "Workflow Approval {}: {}",
            response.approval_id,
            match response.decision {
                ApprovalDecision::Approved => "Approved",
                ApprovalDecision::Rejected => "Rejected",
                ApprovalDecision::RequestMoreInfo => "More Information Requested",
            }
        );

        let message = format!(
            "Workflow approval {} has been {} by {}.\n\nWorkflow: {}\nStep: {}\nComments: {}\n\nTimestamp: {}",
            response.approval_id,
            match response.decision {
                ApprovalDecision::Approved => "approved",
                ApprovalDecision::Rejected => "rejected",
                ApprovalDecision::RequestMoreInfo => "sent back for more information",
            },
            response.approver_id,
            approval_request.workflow_id,
            approval_request.step_name,
            response.comments.as_deref().unwrap_or("None"),
            response.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        );

        // Send notification to the workflow requester if specified
        if let Some(requester) = &approval_request.requester_id {
            // TODO: Send email/notification to requester
            info!(
                "Would send notification to requester {}: {}",
                requester, subject
            );
        }

        // Send notification to configured approval notification channels
        // TODO: Integrate with notification system
        debug!("Approval notification sent: {}", subject);

        Ok(())
    }

    async fn start_processor(&self) {
        info!("Approval processor started");
    }
}

impl AutoApprovalEngine {
    fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            risk_assessor: Arc::new(RiskAssessor::new()),
        }
    }
}

impl RiskAssessor {
    fn new() -> Self {
        Self {
            risk_factors: Arc::new(RwLock::new(Vec::new())),
            calculation_model: RiskCalculationModel::WeightedAverage,
        }
    }
}

impl WorkflowScheduler {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            scheduled_workflows: Arc::new(DashMap::new()),
            recurring_workflows: Arc::new(DashMap::new()),
            config: SchedulerConfig {
                check_interval_seconds: 60,
                max_lookahead_hours: 24,
                recurring_enabled: true,
                max_concurrent_scheduled: 10,
            },
        })
    }

    async fn schedule_workflow(
        &self,
        playbook_id: String,
        execution_time: DateTime<Utc>,
        inputs: HashMap<String, Value>,
        context: HashMap<String, Value>,
        priority: u8,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let schedule_id = Uuid::new_v4().to_string();

        let scheduled_workflow = ScheduledWorkflow {
            id: schedule_id.clone(),
            playbook_id,
            execution_time,
            inputs,
            context,
            priority,
            status: ScheduleStatus::Pending,
        };

        self.scheduled_workflows
            .insert(schedule_id.clone(), scheduled_workflow);

        info!(
            "Scheduled workflow: {} for execution at {}",
            schedule_id, execution_time
        );
        Ok(schedule_id)
    }

    async fn start_processor(&self) {
        info!("Workflow scheduler processor started");
    }
}

impl Default for WorkflowMetrics {
    fn default() -> Self {
        Self {
            playbook_id: String::new(),
            total_executions: 0,
            successful_executions: 0,
            failed_executions: 0,
            avg_execution_time_ms: 0.0,
            last_execution: None,
            success_rate: 0.0,
        }
    }
}

impl Default for WorkflowConfig {
    fn default() -> Self {
        Self {
            max_concurrent_workflows: 10,
            default_timeout_minutes: 60,
            max_retry_attempts: 3,
            step_timeout_minutes: 30,
            parallel_execution_enabled: true,
            persistence_config: PersistenceConfig {
                enabled: true,
                backend: PersistenceBackend::Redis,
                checkpoint_frequency: CheckpointFrequency::AfterEachStep,
                retention_days: 30,
            },
            error_handling: GlobalErrorHandling {
                default_action: ErrorAction::Stop,
                auto_retry_enabled: true,
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 5,
                    time_window_minutes: 10,
                    recovery_timeout_minutes: 5,
                },
                dead_letter_queue_enabled: true,
            },
        }
    }
}

impl ToString for StepType {
    fn to_string(&self) -> String {
        match self {
            StepType::Action => "action".to_string(),
            StepType::Decision => "decision".to_string(),
            StepType::Loop => "loop".to_string(),
            StepType::Parallel => "parallel".to_string(),
            StepType::SubWorkflow => "sub_workflow".to_string(),
            StepType::Approval => "approval".to_string(),
            StepType::Notification => "notification".to_string(),
            StepType::Wait => "wait".to_string(),
        }
    }
}

// Missing type definitions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkflowMetrics {
    pub playbook_id: String,
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub avg_execution_time_ms: f64,
    pub last_execution: Option<chrono::DateTime<chrono::Utc>>,
    pub success_rate: f64,
}
