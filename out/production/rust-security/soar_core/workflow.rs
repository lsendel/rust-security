//! Workflow engine for executing security playbooks
//!
//! This module provides the workflow orchestration capabilities for
//! executing security playbooks and managing workflow instances.

use super::types::*;
use crate::security_logging::{SecurityEvent, SecurityEventType, SecuritySeverity};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
#[cfg(feature = "soar")]
use handlebars::Handlebars;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Workflow engine for executing security playbooks
pub struct WorkflowEngine {
    /// Active workflow instances
    active_workflows: Arc<DashMap<String, WorkflowInstance>>,

    /// Workflow execution queue
    execution_queue: Arc<Mutex<VecDeque<WorkflowExecutionRequest>>>,

    /// Step executors
    step_executors: Arc<DashMap<String, Box<dyn StepExecutor + Send + Sync>>>,

    /// Template engine for dynamic content
    template_engine: Arc<Handlebars<'static>>,

    /// Security logger
    security_logger: Arc<SecurityLogger>,

    /// Execution metrics
    metrics: Arc<Mutex<WorkflowEngineMetrics>>,
}

impl WorkflowEngine {
    /// Create a new workflow engine
    pub async fn new() -> Result<Self, WorkflowError> {
        let template_engine = {
            #[cfg(feature = "soar")]
            {
                let mut engine = Handlebars::new();
                engine.set_strict_mode(true);
                engine
            }
            #[cfg(not(feature = "soar"))]
            {
                Handlebars::new()
            }
        };

        let security_logger = Arc::new(SecurityLogger::new().await.map_err(|e| WorkflowError {
            code: "LOGGER_INIT_ERROR".to_string(),
            message: format!("Failed to initialize security logger: {}", e),
            details: None,
            failed_step: None,
        })?);

        let engine = Self {
            active_workflows: Arc::new(DashMap::new()),
            execution_queue: Arc::new(Mutex::new(VecDeque::new())),
            step_executors: Arc::new(DashMap::new()),
            template_engine: Arc::new(template_engine),
            security_logger,
            metrics: Arc::new(Mutex::new(WorkflowEngineMetrics::default())),
        };

        // Register default step executors
        engine.register_default_executors().await?;

        Ok(engine)
    }

    /// Start the workflow engine
    pub async fn start(&self) -> Result<(), WorkflowError> {
        info!("Starting workflow engine");

        // Start workflow execution loop
        let engine_clone = self.clone();
        tokio::spawn(async move {
            engine_clone.execution_loop().await;
        });

        info!("Workflow engine started successfully");
        Ok(())
    }

    /// Stop the workflow engine
    pub async fn stop(&self) -> Result<(), WorkflowError> {
        info!("Stopping workflow engine");

        // Cancel all active workflows
        for workflow in self.active_workflows.iter() {
            let mut instance = workflow.value().clone();
            instance.status = WorkflowStatus::Cancelled;
            instance.ended_at = Some(Utc::now());
            self.active_workflows
                .insert(workflow.key().clone(), instance);
        }

        info!("Workflow engine stopped successfully");
        Ok(())
    }

    /// Execute a workflow
    pub async fn execute_workflow(
        &self,
        playbook: SecurityPlaybook,
        inputs: HashMap<String, serde_json::Value>,
        context: HashMap<String, serde_json::Value>,
    ) -> Result<String, WorkflowError> {
        let instance_id = Uuid::new_v4().to_string();

        debug!(
            "Starting workflow execution: {} ({})",
            playbook.name, instance_id
        );

        // Create workflow instance
        let workflow_instance = WorkflowInstance {
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

        self.active_workflows
            .insert(instance_id.clone(), workflow_instance);

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
            let mut queue = self.execution_queue.lock().await;
            queue.push_back(execution_request);
        }

        // Log workflow start
        self.security_logger
            .log_event(SecurityEvent {
                event_id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: SecurityEventType::WorkflowTriggered,
                severity: SecuritySeverity::Info,
                source: "workflow_engine".to_string(),
                description: format!("Workflow execution started: {}", instance_id),
                details: HashMap::new(),
                metadata: HashMap::new(),
            })
            .await
            .map_err(|e| WorkflowError {
                code: "LOGGING_ERROR".to_string(),
                message: format!("Failed to log workflow start: {}", e),
                details: None,
                failed_step: None,
            })?;

        Ok(instance_id)
    }

    /// Get workflow instance
    pub async fn get_workflow_instance(&self, instance_id: &str) -> Option<WorkflowInstance> {
        self.active_workflows
            .get(instance_id)
            .map(|entry| entry.value().clone())
    }

    /// Cancel workflow
    pub async fn cancel_workflow(&self, instance_id: &str) -> Result<(), WorkflowError> {
        if let Some(mut workflow) = self.active_workflows.get_mut(instance_id) {
            workflow.status = WorkflowStatus::Cancelled;
            workflow.ended_at = Some(Utc::now());

            info!("Workflow cancelled: {}", instance_id);
            Ok(())
        } else {
            Err(WorkflowError {
                code: "WORKFLOW_NOT_FOUND".to_string(),
                message: format!("Workflow not found: {}", instance_id),
                details: None,
                failed_step: None,
            })
        }
    }

    /// Register a step executor
    pub async fn register_step_executor(
        &self,
        step_type: String,
        executor: Box<dyn StepExecutor + Send + Sync>,
    ) {
        self.step_executors.insert(step_type, executor);
    }

    /// Main execution loop
    async fn execution_loop(&self) {
        loop {
            // Get next execution request
            let request = {
                let mut queue = self.execution_queue.lock().await;
                queue.pop_front()
            };

            if let Some(request) = request {
                // Execute workflow
                let result = self.execute_workflow_instance(request).await;

                // Update metrics
                {
                    let mut metrics = self.metrics.lock().await;
                    metrics.total_executions += 1;
                    if operation_result.is_ok() {
                        metrics.successful_executions += 1;
                    } else {
                        metrics.failed_executions += 1;
                    }
                }
            } else {
                // No work to do, sleep briefly
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }

    /// Execute a workflow instance
    async fn execute_workflow_instance(
        &self,
        request: WorkflowExecutionRequest,
    ) -> Result<WorkflowResult, WorkflowError> {
        let start_time = std::time::Instant::now();
        let instance_id = request.instance_id.clone();

        // Update workflow status
        if let Some(mut workflow) = self.active_workflows.get_mut(&instance_id) {
            workflow.status = WorkflowStatus::Running;
        }

        let mut execution_context = ExecutionContext {
            variables: request.inputs.clone(),
            metadata: request.context.clone(),
            error_history: Vec::new(),
        };

        let mut step_results = HashMap::new();

        // Execute each step
        for (step_index, step) in request.playbook.steps.iter().enumerate() {
            // Update current step
            if let Some(mut workflow) = self.active_workflows.get_mut(&instance_id) {
                workflow.current_step = step_index;
            }

            // Check dependencies
            if !self.check_step_dependencies(step, &step_results).await {
                debug!("Skipping step {} due to unmet dependencies", step.id);
                continue;
            }

            // Check conditions
            if !self
                .evaluate_step_conditions(step, &execution_context)
                .await
            {
                debug!("Skipping step {} due to unmet conditions", step.id);
                continue;
            }

            // Execute step
            match self.execute_step(step, &execution_context).await {
                Ok(result) => {
                    step_results.insert(step.id.clone(), operation_result.clone());

                    // Update execution context with step outputs
                    for (key, value) in operation_result.outputs {
                        execution_context.variables.insert(key, value);
                    }
                }
                Err(error) => {
                    execution_context.error_history.push(error.clone());

                    // Handle error based on step configuration
                    if !step.error_handling.continue_on_error {
                        // Workflow failed
                        if let Some(mut workflow) = self.active_workflows.get_mut(&instance_id) {
                            workflow.status = WorkflowStatus::Failed;
                            workflow.ended_at = Some(Utc::now());
                            workflow.error = Some(WorkflowError {
                                code: error.code.clone(),
                                message: error.message.clone(),
                                details: error.details.clone(),
                                failed_step: Some(step.id.clone()),
                            });
                        }

                        return Err(WorkflowError {
                            code: error.code,
                            message: error.message,
                            details: error.details,
                            failed_step: Some(step.id.clone()),
                        });
                    }
                }
            }
        }

        // Workflow completed successfully
        let duration = start_time.elapsed();

        if let Some(mut workflow) = self.active_workflows.get_mut(&instance_id) {
            workflow.status = WorkflowStatus::Completed;
            workflow.ended_at = Some(Utc::now());
            workflow.step_results = step_results.clone();
            workflow.outputs = execution_context.variables.clone();
        }

        let result = WorkflowResult {
            instance_id: instance_id.clone(),
            status: WorkflowStatus::Completed,
            outputs: execution_context.variables,
            duration_ms: duration.as_millis() as u64,
            step_results,
        };

        // Log completion
        self.security_logger
            .log_event(SecurityEvent {
                event_id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: SecurityEventType::WorkflowCompleted,
                severity: SecuritySeverity::Info,
                source: "workflow_engine".to_string(),
                description: format!("Workflow completed: {}", instance_id),
                details: HashMap::new(),
                metadata: HashMap::new(),
            })
            .await
            .map_err(|e| WorkflowError {
                code: "LOGGING_ERROR".to_string(),
                message: format!("Failed to log workflow completion: {}", e),
                details: None,
                failed_step: None,
            })?;

        Ok(result)
    }

    /// Execute a single workflow step
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &ExecutionContext,
    ) -> Result<StepResult, StepError> {
        debug!("Executing step: {} ({})", step.name, step.id);

        let start_time = Utc::now();
        let step_type = format!("{:?}", step.step_type);

        // Get step executor
        let executor = self
            .step_executors
            .get(&step_type)
            .ok_or_else(|| StepError {
                code: "EXECUTOR_NOT_FOUND".to_string(),
                message: format!("No executor found for step type: {}", step_type),
                details: None,
                retryable: false,
            })?;

        // Execute step with retry logic
        let mut retry_count = 0;
        let max_retries = step.retry_config.max_attempts;

        loop {
            match executor.execute_step(step, &context.variables).await {
                Ok(outputs) => {
                    return Ok(StepResult {
                        step_id: step.id.clone(),
                        status: StepStatus::Completed,
                        started_at: start_time,
                        ended_at: Some(Utc::now()),
                        outputs,
                        error: None,
                        retry_count,
                    });
                }
                Err(error) => {
                    retry_count += 1;

                    if retry_count >= max_retries || !error.retryable {
                        return Ok(StepResult {
                            step_id: step.id.clone(),
                            status: StepStatus::Failed,
                            started_at: start_time,
                            ended_at: Some(Utc::now()),
                            outputs: HashMap::new(),
                            error: Some(error),
                            retry_count,
                        });
                    }

                    // Wait before retry
                    let delay =
                        std::time::Duration::from_secs(step.retry_config.delay_seconds as u64);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Check if step dependencies are met
    async fn check_step_dependencies(
        &self,
        step: &WorkflowStep,
        step_results: &HashMap<String, StepResult>,
    ) -> bool {
        for dependency in &step.dependencies {
            if let Some(result) = step_results.get(dependency) {
                if operation_result.status != StepStatus::Completed {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }

    /// Evaluate step conditions
    async fn evaluate_step_conditions(
        &self,
        step: &WorkflowStep,
        context: &ExecutionContext,
    ) -> bool {
        for condition in &step.conditions {
            if !self.evaluate_condition(condition, context).await {
                return false;
            }
        }
        true
    }

    /// Evaluate a single condition
    async fn evaluate_condition(
        &self,
        condition: &TriggerCondition,
        context: &ExecutionContext,
    ) -> bool {
        let field_value = context.variables.get(&condition.field);

        match &condition.operator {
            ConditionOperator::Equals => field_value == Some(&condition.value),
            ConditionOperator::NotEquals => field_value != Some(&condition.value),
            ConditionOperator::Contains => {
                if let (Some(field_val), Some(search_val)) = (
                    field_value.and_then(|v| v.as_str()),
                    condition.value.as_str(),
                ) {
                    field_val.contains(search_val)
                } else {
                    false
                }
            }
            // Add other operators as needed
            _ => {
                warn!("Unsupported condition operator: {:?}", condition.operator);
                true // Default to true for unsupported operators
            }
        }
    }

    /// Register default step executors
    async fn register_default_executors(&self) -> Result<(), WorkflowError> {
        // Register basic executors
        self.step_executors
            .insert("Action".to_string(), Box::new(ActionStepExecutor::new()));

        self.step_executors.insert(
            "Notification".to_string(),
            Box::new(NotificationStepExecutor::new()),
        );

        Ok(())
    }
}

impl Clone for WorkflowEngine {
    fn clone(&self) -> Self {
        Self {
            active_workflows: Arc::clone(&self.active_workflows),
            execution_queue: Arc::clone(&self.execution_queue),
            step_executors: Arc::clone(&self.step_executors),
            template_engine: Arc::clone(&self.template_engine),
            security_logger: Arc::clone(&self.security_logger),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Workflow engine metrics
#[derive(Debug, Default)]
pub struct WorkflowEngineMetrics {
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub average_execution_time_ms: f64,
}

/// Basic action step executor
pub struct ActionStepExecutor;

impl ActionStepExecutor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl StepExecutor for ActionStepExecutor {
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, StepError> {
        debug!("Executing action step: {}", step.id);

        match &step.action {
            StepAction::BlockIp {
                ip_address,
                duration_minutes,
                reason,
            } => {
                // Implementation for blocking IP
                let mut outputs = HashMap::new();
                outputs.insert(
                    "blocked_ip".to_string(),
                    serde_json::Value::String(ip_address.clone()),
                );
                outputs.insert(
                    "duration".to_string(),
                    serde_json::Value::Number((*duration_minutes).into()),
                );
                outputs.insert(
                    "reason".to_string(),
                    serde_json::Value::String(reason.clone()),
                );
                Ok(outputs)
            }
            StepAction::SendNotification {
                notification_type,
                recipients,
                subject,
                message,
                priority,
            } => {
                // Implementation for sending notification
                let mut outputs = HashMap::new();
                outputs.insert(
                    "notification_sent".to_string(),
                    serde_json::Value::Bool(true),
                );
                outputs.insert(
                    "recipients_count".to_string(),
                    serde_json::Value::Number(recipients.len().into()),
                );
                Ok(outputs)
            }
            _ => {
                // Default implementation for other actions
                Ok(HashMap::new())
            }
        }
    }

    fn get_step_type(&self) -> String {
        "Action".to_string()
    }
}

/// Basic notification step executor
pub struct NotificationStepExecutor;

impl NotificationStepExecutor {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl StepExecutor for NotificationStepExecutor {
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        _context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, StepError> {
        debug!("Executing notification step: {}", step.id);

        // Basic notification implementation
        let mut outputs = HashMap::new();
        outputs.insert(
            "notification_sent".to_string(),
            serde_json::Value::Bool(true),
        );
        outputs.insert(
            "timestamp".to_string(),
            serde_json::Value::String(Utc::now().to_rfc3339()),
        );

        Ok(outputs)
    }

    fn get_step_type(&self) -> String {
        "Notification".to_string()
    }
}

/// Step executor trait
#[async_trait::async_trait]
pub trait StepExecutor {
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &HashMap<String, serde_json::Value>,
    ) -> Result<HashMap<String, serde_json::Value>, StepError>;

    fn get_step_type(&self) -> String;
}
