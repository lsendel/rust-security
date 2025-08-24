//! Workflow Execution Engine
//!
//! Core workflow execution engine responsible for orchestrating workflow instances,
//! managing step execution, and handling workflow lifecycle.

use super::*;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio::time::{timeout, Duration as TokioDuration};
use tracing::{debug, error, info, warn};

/// Workflow engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEngineConfig {
    /// Maximum concurrent workflow executions
    pub max_concurrent_executions: usize,
    
    /// Default step timeout
    pub default_step_timeout: Duration,
    
    /// Maximum workflow execution time
    pub max_execution_time: Duration,
    
    /// Enable parallel step execution
    pub parallel_execution_enabled: bool,
    
    /// Step execution retry configuration
    pub retry_config: GlobalRetryConfig,
    
    /// Circuit breaker configuration
    pub circuit_breaker_config: CircuitBreakerConfig,
}

/// Global retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRetryConfig {
    /// Default maximum retry attempts
    pub default_max_attempts: u32,
    
    /// Default retry delay
    pub default_delay: Duration,
    
    /// Default backoff multiplier
    pub default_backoff_multiplier: f64,
    
    /// Default maximum delay
    pub default_max_delay: Duration,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold
    pub failure_threshold: u32,
    
    /// Recovery timeout
    pub recovery_timeout: Duration,
    
    /// Half-open max calls
    pub half_open_max_calls: u32,
}

/// Workflow execution engine
pub struct WorkflowEngine {
    /// Configuration
    config: Arc<RwLock<WorkflowEngineConfig>>,
    
    /// Active workflow instances
    active_instances: Arc<DashMap<String, WorkflowInstance>>,
    
    /// Step executor registry
    step_executors: Arc<DashMap<String, Arc<dyn StepExecutor + Send + Sync>>>,
    
    /// Execution semaphore for concurrency control
    execution_semaphore: Arc<Semaphore>,
    
    /// Event publisher
    event_publisher: mpsc::Sender<WorkflowEvent>,
    
    /// Engine metrics
    metrics: Arc<Mutex<EngineMetrics>>,
}

/// Engine metrics
#[derive(Debug, Clone, Default)]
pub struct EngineMetrics {
    /// Total workflows executed
    pub total_workflows_executed: u64,
    
    /// Currently running workflows
    pub running_workflows: u64,
    
    /// Total steps executed
    pub total_steps_executed: u64,
    
    /// Failed workflows
    pub failed_workflows: u64,
    
    /// Average execution time
    pub average_execution_time: Duration,
    
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

/// Step executor trait
#[async_trait]
pub trait StepExecutor {
    /// Execute a workflow step
    async fn execute_step(
        &self,
        step: &WorkflowStep,
        context: &ExecutionContext,
        variables: &HashMap<String, serde_json::Value>,
    ) -> Result<StepResult, WorkflowError>;
    
    /// Validate step configuration
    fn validate_step(&self, step: &WorkflowStep) -> Result<(), WorkflowError>;
    
    /// Get executor metadata
    fn get_metadata(&self) -> ExecutorMetadata;
}

/// Executor metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorMetadata {
    /// Executor name
    pub name: String,
    
    /// Executor version
    pub version: String,
    
    /// Supported step types
    pub supported_step_types: Vec<StepType>,
    
    /// Required parameters
    pub required_parameters: Vec<String>,
    
    /// Optional parameters
    pub optional_parameters: Vec<String>,
}

impl WorkflowEngine {
    /// Create new workflow engine
    pub async fn new(config: WorkflowEngineConfig) -> Result<Self, WorkflowError> {
        let execution_semaphore = Arc::new(Semaphore::new(config.max_concurrent_executions));
        let (event_tx, _event_rx) = mpsc::channel(1000);
        
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            active_instances: Arc::new(DashMap::new()),
            step_executors: Arc::new(DashMap::new()),
            execution_semaphore,
            event_publisher: event_tx,
            metrics: Arc::new(Mutex::new(EngineMetrics::default())),
        })
    }
    
    /// Register a step executor
    pub fn register_executor(
        &self,
        executor_type: String,
        executor: Arc<dyn StepExecutor + Send + Sync>,
    ) {
        self.step_executors.insert(executor_type, executor);
    }
    
    /// Execute a workflow
    pub async fn execute_workflow(
        &self,
        workflow_definition: WorkflowDefinition,
        mut instance: WorkflowInstance,
    ) -> Result<(), WorkflowError> {
        let instance_id = instance.id.clone();
        
        // Acquire execution permit
        let _permit = self.execution_semaphore.acquire().await.map_err(|e| WorkflowError {
            code: "SEMAPHORE_ERROR".to_string(),
            message: format!("Failed to acquire execution permit: {}", e),
            details: None,
            source: None,
        })?;
        
        // Update instance status
        instance.status = WorkflowStatus::Running;
        instance.updated_at = Utc::now();
        
        // Store instance
        self.active_instances.insert(instance_id.clone(), instance.clone());
        
        // Publish workflow started event
        self.publish_event(WorkflowEvent {
            id: Uuid::new_v4().to_string(),
            event_type: WorkflowEventType::WorkflowStarted,
            workflow_instance_id: instance_id.clone(),
            step_id: None,
            data: HashMap::new(),
            timestamp: Utc::now(),
        }).await;
        
        // Execute workflow steps
        let execution_result = self.execute_workflow_steps(&workflow_definition, &mut instance).await;
        
        // Update final status
        match execution_result {
            Ok(_) => {
                instance.status = WorkflowStatus::Completed;
                instance.ended_at = Some(Utc::now());
                
                self.publish_event(WorkflowEvent {
                    id: Uuid::new_v4().to_string(),
                    event_type: WorkflowEventType::WorkflowCompleted,
                    workflow_instance_id: instance_id.clone(),
                    step_id: None,
                    data: HashMap::new(),
                    timestamp: Utc::now(),
                }).await;
            }
            Err(ref error) => {
                instance.status = WorkflowStatus::Failed;
                instance.ended_at = Some(Utc::now());
                
                let mut error_data = HashMap::new();
                error_data.insert("error_code".to_string(), serde_json::Value::String(error.code.clone()));
                error_data.insert("error_message".to_string(), serde_json::Value::String(error.message.clone()));
                
                self.publish_event(WorkflowEvent {
                    id: Uuid::new_v4().to_string(),
                    event_type: WorkflowEventType::WorkflowFailed,
                    workflow_instance_id: instance_id.clone(),
                    step_id: None,
                    data: error_data,
                    timestamp: Utc::now(),
                }).await;
            }
        }
        
        // Update instance
        instance.updated_at = Utc::now();
        self.active_instances.insert(instance_id.clone(), instance);
        
        // Update metrics
        self.update_metrics().await;
        
        execution_result
    }
    
    /// Execute workflow steps
    async fn execute_workflow_steps(
        &self,
        workflow_definition: &WorkflowDefinition,
        instance: &mut WorkflowInstance,
    ) -> Result<(), WorkflowError> {
        let config = self.config.read().await;
        let max_execution_time = config.max_execution_time;
        drop(config);
        
        // Execute with timeout
        timeout(
            TokioDuration::from_secs(max_execution_time.as_secs()),
            self.execute_steps_internal(workflow_definition, instance),
        )
        .await
        .map_err(|_| WorkflowError {
            code: "EXECUTION_TIMEOUT".to_string(),
            message: "Workflow execution timed out".to_string(),
            details: None,
            source: None,
        })?
    }
    
    /// Internal step execution logic
    async fn execute_steps_internal(
        &self,
        workflow_definition: &WorkflowDefinition,
        instance: &mut WorkflowInstance,
    ) -> Result<(), WorkflowError> {
        // Build execution graph
        let execution_graph = self.build_execution_graph(&workflow_definition.steps)?;
        
        // Execute steps according to dependencies
        for step_batch in execution_graph {
            if step_batch.len() == 1 {
                // Sequential execution
                let step = &step_batch[0];
                self.execute_single_step(step, instance).await?;
            } else {
                // Parallel execution
                let config = self.config.read().await;
                if config.parallel_execution_enabled {
                    self.execute_parallel_steps(&step_batch, instance).await?;
                } else {
                    // Fall back to sequential execution
                    for step in step_batch {
                        self.execute_single_step(step, instance).await?;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Build execution graph based on step dependencies
    fn build_execution_graph(&self, steps: &[WorkflowStep]) -> Result<Vec<Vec<WorkflowStep>>, WorkflowError> {
        let mut graph = Vec::new();
        let mut remaining_steps: Vec<_> = steps.iter().cloned().collect();
        let mut completed_steps = std::collections::HashSet::new();
        
        while !remaining_steps.is_empty() {
            let mut current_batch = Vec::new();
            let mut indices_to_remove = Vec::new();
            
            for (index, step) in remaining_steps.iter().enumerate() {
                // Check if all dependencies are satisfied
                let dependencies_satisfied = step.dependencies.iter()
                    .all(|dep| completed_steps.contains(dep));
                
                if dependencies_satisfied {
                    current_batch.push(step.clone());
                    indices_to_remove.push(index);
                    completed_steps.insert(step.id.clone());
                }
            }
            
            if current_batch.is_empty() {
                return Err(WorkflowError {
                    code: "CIRCULAR_DEPENDENCY".to_string(),
                    message: "Circular dependency detected in workflow steps".to_string(),
                    details: None,
                    source: None,
                });
            }
            
            // Remove processed steps
            for &index in indices_to_remove.iter().rev() {
                remaining_steps.remove(index);
            }
            
            graph.push(current_batch);
        }
        
        Ok(graph)
    }
    
    /// Execute a single step
    async fn execute_single_step(
        &self,
        step: &WorkflowStep,
        instance: &mut WorkflowInstance,
    ) -> Result<(), WorkflowError> {
        info!("Executing step: {} ({})", step.name, step.id);
        
        // Update current step
        instance.current_step = Some(step.id.clone());
        instance.updated_at = Utc::now();
        
        // Publish step started event
        self.publish_event(WorkflowEvent {
            id: Uuid::new_v4().to_string(),
            event_type: WorkflowEventType::StepStarted,
            workflow_instance_id: instance.id.clone(),
            step_id: Some(step.id.clone()),
            data: HashMap::new(),
            timestamp: Utc::now(),
        }).await;
        
        // Check pre-conditions
        if !self.evaluate_conditions(&step.conditions, ConditionType::PreCondition, instance).await? {
            // Skip step
            let step_result = StepResult {
                step_id: step.id.clone(),
                status: StepStatus::Skipped,
                data: HashMap::new(),
                error: None,
                duration: Duration::from_secs(0),
                started_at: Utc::now(),
                ended_at: Some(Utc::now()),
                retry_attempts: 0,
            };
            
            instance.step_results.insert(step.id.clone(), step_result);
            
            self.publish_event(WorkflowEvent {
                id: Uuid::new_v4().to_string(),
                event_type: WorkflowEventType::StepSkipped,
                workflow_instance_id: instance.id.clone(),
                step_id: Some(step.id.clone()),
                data: HashMap::new(),
                timestamp: Utc::now(),
            }).await;
            
            return Ok(());
        }
        
        // Execute step with retry logic
        let step_result = self.execute_step_with_retry(step, instance).await;
        
        // Store step result
        instance.step_results.insert(step.id.clone(), step_result.clone());
        instance.updated_at = Utc::now();
        
        // Publish step completed/failed event
        let event_type = if step_result.status == StepStatus::Completed {
            WorkflowEventType::StepCompleted
        } else {
            WorkflowEventType::StepFailed
        };
        
        let mut event_data = HashMap::new();
        if let Some(ref error) = step_result.error {
            event_data.insert("error_code".to_string(), serde_json::Value::String(error.code.clone()));
            event_data.insert("error_message".to_string(), serde_json::Value::String(error.message.clone()));
        }
        
        self.publish_event(WorkflowEvent {
            id: Uuid::new_v4().to_string(),
            event_type,
            workflow_instance_id: instance.id.clone(),
            step_id: Some(step.id.clone()),
            data: event_data,
            timestamp: Utc::now(),
        }).await;
        
        // Handle step failure
        if step_result.status == StepStatus::Failed {
            match step.error_handling.strategy {
                ErrorHandlingStrategy::FailFast => {
                    return Err(WorkflowError {
                        code: "STEP_FAILED".to_string(),
                        message: format!("Step {} failed: {}", step.id, 
                            step_result.error.as_ref().map(|e| &e.message).unwrap_or(&"Unknown error".to_string())),
                        details: None,
                        source: None,
                    });
                }
                ErrorHandlingStrategy::ContinueWithWarnings => {
                    warn!("Step {} failed but continuing with warnings", step.id);
                }
                _ => {
                    // Handle other strategies
                    warn!("Step {} failed, error handling strategy not fully implemented", step.id);
                }
            }
        }
        
        Ok(())
    }
    
    /// Execute step with retry logic
    async fn execute_step_with_retry(
        &self,
        step: &WorkflowStep,
        instance: &WorkflowInstance,
    ) -> StepResult {
        let start_time = Utc::now();
        let mut retry_attempts = 0;
        
        let retry_config = step.retry_config.as_ref().unwrap_or(&RetryConfig {
            max_attempts: 1,
            delay: Duration::from_secs(1),
            backoff_multiplier: 1.0,
            max_delay: Duration::from_secs(60),
            retry_conditions: vec![],
        });
        
        loop {
            let step_start = Utc::now();
            
            // Execute the step
            let execution_result = self.execute_step_internal(step, instance).await;
            
            let step_end = Utc::now();
            let duration = (step_end - step_start).to_std().unwrap_or(Duration::from_secs(0));
            
            match execution_result {
                Ok(data) => {
                    return StepResult {
                        step_id: step.id.clone(),
                        status: StepStatus::Completed,
                        data,
                        error: None,
                        duration,
                        started_at: start_time,
                        ended_at: Some(step_end),
                        retry_attempts,
                    };
                }
                Err(error) => {
                    retry_attempts += 1;
                    
                    // Check if we should retry
                    if retry_attempts >= retry_config.max_attempts || !self.should_retry(&error, &retry_config.retry_conditions) {
                        return StepResult {
                            step_id: step.id.clone(),
                            status: StepStatus::Failed,
                            data: HashMap::new(),
                            error: Some(StepError {
                                code: error.code,
                                message: error.message,
                                details: error.details,
                                timestamp: Utc::now(),
                                retryable: false,
                            }),
                            duration,
                            started_at: start_time,
                            ended_at: Some(step_end),
                            retry_attempts,
                        };
                    }
                    
                    // Calculate retry delay
                    let delay = std::cmp::min(
                        Duration::from_secs_f64(
                            retry_config.delay.as_secs_f64() * 
                            retry_config.backoff_multiplier.powi(retry_attempts as i32 - 1)
                        ),
                        retry_config.max_delay,
                    );
                    
                    warn!("Step {} failed, retrying in {:?} (attempt {}/{})", 
                          step.id, delay, retry_attempts, retry_config.max_attempts);
                    
                    tokio::time::sleep(TokioDuration::from_secs(delay.as_secs())).await;
                }
            }
        }
    }
    
    /// Execute step internal logic
    async fn execute_step_internal(
        &self,
        step: &WorkflowStep,
        instance: &WorkflowInstance,
    ) -> Result<HashMap<String, serde_json::Value>, WorkflowError> {
        // Get step executor
        let executor = self.step_executors.get(&step.config.executor)
            .ok_or_else(|| WorkflowError {
                code: "EXECUTOR_NOT_FOUND".to_string(),
                message: format!("Step executor not found: {}", step.config.executor),
                details: None,
                source: None,
            })?;
        
        // Execute step
        let step_result = executor.execute_step(step, &instance.context, &instance.variables).await?;
        
        Ok(step_result.data)
    }
    
    /// Check if error should trigger a retry
    fn should_retry(&self, _error: &WorkflowError, _retry_conditions: &[RetryCondition]) -> bool {
        // Simplified retry logic - in practice, would check retry conditions
        true
    }
    
    /// Execute steps in parallel
    async fn execute_parallel_steps(
        &self,
        steps: &[WorkflowStep],
        instance: &mut WorkflowInstance,
    ) -> Result<(), WorkflowError> {
        let mut handles = Vec::new();
        
        for step in steps {
            let step_clone = step.clone();
            let instance_clone = instance.clone();
            let engine_clone = self.clone();
            
            let handle = tokio::spawn(async move {
                engine_clone.execute_single_step(&step_clone, &mut instance_clone.clone()).await
            });
            
            handles.push(handle);
        }
        
        // Wait for all steps to complete
        let results = futures::future::join_all(handles).await;
        
        // Check for failures
        for result in results {
            match result {
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(WorkflowError {
                    code: "PARALLEL_EXECUTION_ERROR".to_string(),
                    message: format!("Parallel step execution failed: {}", e),
                    details: None,
                    source: None,
                }),
            }
        }
        
        Ok(())
    }
    
    /// Evaluate step conditions
    async fn evaluate_conditions(
        &self,
        conditions: &[StepCondition],
        condition_type: ConditionType,
        _instance: &WorkflowInstance,
    ) -> Result<bool, WorkflowError> {
        for condition in conditions {
            if condition.condition_type == condition_type {
                // Simplified condition evaluation - in practice, would use expression engine
                if condition.expression == "false" {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
    
    /// Publish workflow event
    async fn publish_event(&self, event: WorkflowEvent) {
        if let Err(e) = self.event_publisher.send(event).await {
            error!("Failed to publish workflow event: {}", e);
        }
    }
    
    /// Update engine metrics
    async fn update_metrics(&self) {
        let mut metrics = self.metrics.lock().await;
        metrics.running_workflows = self.active_instances.len() as u64;
        metrics.last_updated = Utc::now();
    }
    
    /// Get workflow status
    pub async fn get_workflow_status(&self, instance_id: &str) -> Result<WorkflowStatus, WorkflowError> {
        self.active_instances
            .get(instance_id)
            .map(|instance| instance.status.clone())
            .ok_or_else(|| WorkflowError {
                code: "INSTANCE_NOT_FOUND".to_string(),
                message: format!("Workflow instance not found: {}", instance_id),
                details: None,
                source: None,
            })
    }
    
    /// Cancel workflow
    pub async fn cancel_workflow(&self, instance_id: &str) -> Result<(), WorkflowError> {
        if let Some(mut instance) = self.active_instances.get_mut(instance_id) {
            instance.status = WorkflowStatus::Cancelled;
            instance.ended_at = Some(Utc::now());
            instance.updated_at = Utc::now();
            
            self.publish_event(WorkflowEvent {
                id: Uuid::new_v4().to_string(),
                event_type: WorkflowEventType::WorkflowCancelled,
                workflow_instance_id: instance_id.to_string(),
                step_id: None,
                data: HashMap::new(),
                timestamp: Utc::now(),
            }).await;
            
            Ok(())
        } else {
            Err(WorkflowError {
                code: "INSTANCE_NOT_FOUND".to_string(),
                message: format!("Workflow instance not found: {}", instance_id),
                details: None,
                source: None,
            })
        }
    }
}

// Implement Clone for WorkflowEngine (simplified for parallel execution)
impl Clone for WorkflowEngine {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            active_instances: Arc::clone(&self.active_instances),
            step_executors: Arc::clone(&self.step_executors),
            execution_semaphore: Arc::clone(&self.execution_semaphore),
            event_publisher: self.event_publisher.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

#[async_trait]
impl WorkflowComponent for WorkflowEngine {
    async fn initialize(&mut self) -> Result<(), WorkflowError> {
        info!("Initializing workflow engine");
        Ok(())
    }
    
    async fn start(&self) -> Result<(), WorkflowError> {
        info!("Starting workflow engine");
        Ok(())
    }
    
    async fn stop(&self) -> Result<(), WorkflowError> {
        info!("Stopping workflow engine");
        Ok(())
    }
    
    fn get_health_status(&self) -> ComponentHealth {
        ComponentHealth {
            component: "workflow_engine".to_string(),
            status: HealthStatus::Healthy,
            message: "Engine is running normally".to_string(),
            last_check: Utc::now(),
            details: HashMap::new(),
        }
    }
    
    fn get_metrics(&self) -> ComponentMetrics {
        ComponentMetrics {
            component: "workflow_engine".to_string(),
            metrics: HashMap::new(),
            collected_at: Utc::now(),
        }
    }
}

impl Default for WorkflowEngineConfig {
    fn default() -> Self {
        Self {
            max_concurrent_executions: 50,
            default_step_timeout: Duration::from_secs(300), // 5 minutes
            max_execution_time: Duration::from_secs(3600), // 1 hour
            parallel_execution_enabled: true,
            retry_config: GlobalRetryConfig {
                default_max_attempts: 3,
                default_delay: Duration::from_secs(5),
                default_backoff_multiplier: 2.0,
                default_max_delay: Duration::from_secs(300),
            },
            circuit_breaker_config: CircuitBreakerConfig {
                failure_threshold: 5,
                recovery_timeout: Duration::from_secs(60),
                half_open_max_calls: 3,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_workflow_engine_creation() {
        let config = WorkflowEngineConfig::default();
        let engine = WorkflowEngine::new(config).await.unwrap();
        
        assert_eq!(engine.active_instances.len(), 0);
        assert_eq!(engine.step_executors.len(), 0);
    }

    #[test]
    fn test_execution_graph_building() {
        let engine = WorkflowEngine {
            config: Arc::new(RwLock::new(WorkflowEngineConfig::default())),
            active_instances: Arc::new(DashMap::new()),
            step_executors: Arc::new(DashMap::new()),
            execution_semaphore: Arc::new(Semaphore::new(10)),
            event_publisher: mpsc::channel(1).0,
            metrics: Arc::new(Mutex::new(EngineMetrics::default())),
        };
        
        let steps = vec![
            WorkflowStep {
                id: "step1".to_string(),
                name: "Step 1".to_string(),
                step_type: StepType::Action,
                config: StepConfig {
                    executor: "test".to_string(),
                    parameters: HashMap::new(),
                    inputs: HashMap::new(),
                    outputs: HashMap::new(),
                    environment: HashMap::new(),
                },
                dependencies: vec![],
                conditions: vec![],
                timeout: None,
                retry_config: None,
                error_handling: ErrorHandling {
                    strategy: ErrorHandlingStrategy::FailFast,
                    rollback_steps: vec![],
                    notifications: vec![],
                    continue_on_error: false,
                },
                metadata: HashMap::new(),
            },
            WorkflowStep {
                id: "step2".to_string(),
                name: "Step 2".to_string(),
                step_type: StepType::Action,
                config: StepConfig {
                    executor: "test".to_string(),
                    parameters: HashMap::new(),
                    inputs: HashMap::new(),
                    outputs: HashMap::new(),
                    environment: HashMap::new(),
                },
                dependencies: vec!["step1".to_string()],
                conditions: vec![],
                timeout: None,
                retry_config: None,
                error_handling: ErrorHandling {
                    strategy: ErrorHandlingStrategy::FailFast,
                    rollback_steps: vec![],
                    notifications: vec![],
                    continue_on_error: false,
                },
                metadata: HashMap::new(),
            },
        ];
        
        let graph = engine.build_execution_graph(&steps).unwrap();
        assert_eq!(graph.len(), 2); // Two batches
        assert_eq!(graph[0].len(), 1); // First batch has one step
        assert_eq!(graph[1].len(), 1); // Second batch has one step
        assert_eq!(graph[0][0].id, "step1");
        assert_eq!(graph[1][0].id, "step2");
    }
}
