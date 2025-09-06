//! Core Workflow Orchestrator Implementation

use async_trait::async_trait;

use crate::infrastructure::security::security_logging::{
    SecurityEvent, SecurityEventType, SecuritySeverity,
};
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

use super::approval::ApprovalManager;
use super::config::WorkflowConfig;
use super::metrics::WorkflowMetrics;
use super::scheduler::WorkflowScheduler;
use super::types::*;

/// Advanced workflow orchestration engine
pub struct WorkflowOrchestrator {
    /// Configuration
    config: Arc<RwLock<WorkflowConfig>>,

    /// Active workflow instances
    active_workflows: Arc<DashMap<String, WorkflowInstance>>,

    /// Execution queue with priority support
    execution_queue: Arc<RwLock<super::execution::PriorityQueue<WorkflowExecutionRequest>>>,

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

impl WorkflowOrchestrator {
    /// Create a new workflow orchestrator
    #[must_use]
    pub fn new(config: WorkflowConfig) -> Self {
        let (event_publisher, _event_receiver) = mpsc::channel(1000);

        Self {
            config: Arc::new(RwLock::new(config)),
            active_workflows: Arc::new(DashMap::new()),
            execution_queue: Arc::new(RwLock::new(super::execution::PriorityQueue::new())),
            step_executors: Arc::new(DashMap::new()),
            template_engine: Arc::new(Handlebars::new()),
            approval_manager: Arc::new(ApprovalManager::new()),
            scheduler: Arc::new(WorkflowScheduler::new()),
            metrics: Arc::new(Mutex::new(WorkflowMetrics::default())),
            execution_semaphore: Arc::new(Semaphore::new(10)), // Default concurrency
            event_publisher,
            task_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a step executor
    pub fn register_step_executor(
        &self,
        step_type: String,
        executor: Arc<dyn StepExecutor + Send + Sync>,
    ) {
        self.step_executors.insert(step_type, executor);
    }

    /// Submit a workflow for execution
    pub async fn submit_workflow(
        &self,
        workflow: WorkflowDefinition,
        context: HashMap<String, Value>,
    ) -> Result<String, SoarError> {
        let instance_id = Uuid::new_v4().to_string();
        let execution_request = WorkflowExecutionRequest {
            instance_id: instance_id.clone(),
            workflow,
            context,
            priority: super::types::Priority::Normal,
            submitted_at: Utc::now(),
        };

        let priority_item = super::execution::PriorityItem {
            data: execution_request,
            priority: super::types::Priority::Normal,
            queued_at: Utc::now(),
        };

        self.execution_queue.write().await.push(priority_item);

        Ok(instance_id)
    }

    /// Get workflow status
    #[must_use]
    pub fn get_workflow_status(&self, instance_id: &str) -> Option<WorkflowStatus> {
        self.active_workflows
            .get(instance_id)
            .map(|instance| instance.status.clone())
    }

    /// Cancel a workflow
    pub async fn cancel_workflow(&self, instance_id: &str) -> Result<(), SoarError> {
        if let Some(mut instance) = self.active_workflows.get_mut(instance_id) {
            instance.status = WorkflowStatus::Cancelled;
            Ok(())
        } else {
            Err(SoarError::WorkflowNotFound)
        }
    }
}
