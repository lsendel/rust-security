//! Case Management Workflows
//!
//! This module handles automated workflows for case management.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::errors::{SoarError, SoarResult};
use super::models::{CasePriority, CaseStatus, SecurityCase};

/// Workflow client trait for external integrations
#[async_trait]
pub trait WorkflowClient: Send + Sync {
    /// Start a workflow for a case
    async fn start_workflow(&self, case_id: &str, workflow_type: &str) -> SoarResult<()>;

    /// Update workflow status
    async fn update_workflow_status(&self, case_id: &str, status: &str) -> SoarResult<()>;

    /// Complete a workflow
    async fn complete_workflow(&self, case_id: &str) -> SoarResult<()>;
}

/// Case workflow engine
pub struct CaseWorkflowEngine {
    /// Available workflows
    workflows: HashMap<String, Box<dyn Workflow + Send + Sync>>,
    /// Active workflow instances
    active_workflows: Arc<RwLock<HashMap<String, WorkflowInstance>>>,
    /// Workflow client for external integrations
    workflow_client: Option<Arc<dyn WorkflowClient + Send + Sync>>,
}

/// Workflow trait
#[async_trait]
pub trait Workflow: Send + Sync {
    /// Get workflow name
    fn name(&self) -> &str;

    /// Check if workflow can handle a case
    async fn can_handle(&self, case: &SecurityCase) -> bool;

    /// Execute workflow for a case
    async fn execute(&self, case: &mut SecurityCase) -> SoarResult<()>;
}

/// Workflow instance
#[derive(Debug, Clone)]
pub struct WorkflowInstance {
    /// Workflow name
    pub workflow_name: String,
    /// Case ID
    pub case_id: String,
    /// Start time
    pub started_at: DateTime<Utc>,
    /// Current step
    pub current_step: String,
    /// Status
    pub status: WorkflowStatus,
}

/// Workflow status
#[derive(Debug, Clone)]
pub enum WorkflowStatus {
    /// Workflow is running
    Running,
    /// Workflow is waiting for input
    Waiting,
    /// Workflow is completed
    Completed,
    /// Workflow failed
    Failed(String),
}

impl CaseWorkflowEngine {
    /// Create a new workflow engine
    #[must_use]
    pub fn new(workflow_client: Option<Arc<dyn WorkflowClient + Send + Sync>>) -> Self {
        Self {
            workflows: HashMap::new(),
            active_workflows: Arc::new(RwLock::new(HashMap::new())),
            workflow_client,
        }
    }

    /// Register a workflow
    pub fn register_workflow<W: Workflow + Send + Sync + 'static>(&mut self, workflow: W) {
        self.workflows
            .insert(workflow.name().to_string(), Box::new(workflow));
    }

    /// Start workflow for a case
    /// Start a workflow for a case
    ///
    /// # Errors
    /// Returns an error if the workflow cannot be started or the case is not found.
    pub async fn start_case_workflow(&self, case_id: &str) -> SoarResult<()> {
        // Find suitable workflow
        let workflow_name = self.find_suitable_workflow(case_id)?;

        // Start workflow instance
        let instance = WorkflowInstance {
            workflow_name: workflow_name.clone(),
            case_id: case_id.to_string(),
            started_at: Utc::now(),
            current_step: "initialization".to_string(),
            status: WorkflowStatus::Running,
        };

        // Store active workflow
        self.active_workflows
            .write()
            .await
            .insert(case_id.to_string(), instance);

        // Notify external workflow client if available
        if let Some(client) = &self.workflow_client {
            client.start_workflow(case_id, &workflow_name).await?;
        }

        info!("Started workflow '{}' for case {}", workflow_name, case_id);
        Ok(())
    }

    /// Execute workflow step
    /// Execute the next step in a case workflow
    ///
    /// # Errors
    /// Returns an error if the workflow step cannot be executed or the workflow is not found.
    pub async fn execute_workflow_step(
        &self,
        case_id: &str,
        case: &mut SecurityCase,
    ) -> SoarResult<()> {
        let workflows = self.active_workflows.read().await;
        let instance = workflows
            .get(case_id)
            .ok_or_else(|| SoarError::InvalidInput {
                field: "case_id".to_string(),
                reason: format!("No active workflow found for case {case_id}"),
            })?;

        if let Some(workflow) = self.workflows.get(&instance.workflow_name) {
            workflow.execute(case).await?;
        }

        Ok(())
    }

    /// Complete workflow for a case
    /// Complete a case workflow
    ///
    /// # Errors
    /// Returns an error if the workflow cannot be completed or the case is not found.
    pub async fn complete_case_workflow(&self, case_id: &str) -> SoarResult<()> {
        let mut workflows = self.active_workflows.write().await;
        if let Some(mut instance) = workflows.remove(case_id) {
            instance.status = WorkflowStatus::Completed;

            // Notify external workflow client if available
            if let Some(client) = &self.workflow_client {
                client.complete_workflow(case_id).await?;
            }

            info!("Completed workflow for case {}", case_id);
        }

        Ok(())
    }

    /// Find suitable workflow for a case
    ///
    /// # Errors
    /// Returns an error if no suitable workflow can be found
    fn find_suitable_workflow(&self, _case_id: &str) -> SoarResult<String> {
        // For now, return default workflow
        // In a real implementation, this would analyze the case and find the best workflow
        Ok("default_case_workflow".to_string())
    }
}

/// Default case workflow
pub struct DefaultCaseWorkflow;

#[async_trait]
impl Workflow for DefaultCaseWorkflow {
    fn name(&self) -> &str {
        "default_case_workflow"
    }

    async fn can_handle(&self, _case: &SecurityCase) -> bool {
        true // This workflow can handle any case
    }

    async fn execute(&self, case: &mut SecurityCase) -> SoarResult<()> {
        match case.status {
            CaseStatus::Open => {
                // Initial triage
                if case.priority >= CasePriority::High {
                    case.update_status(CaseStatus::Escalated);
                    info!("Case {} escalated due to high priority", case.id);
                }
            }
            CaseStatus::Investigating => {
                // Check if investigation is complete
                if !case.evidence.is_empty() {
                    case.update_status(CaseStatus::Resolving);
                    info!("Case {} moved to resolution phase", case.id);
                }
            }
            CaseStatus::Resolving => {
                // Check if resolution is complete
                if case
                    .updated_at
                    .signed_duration_since(case.created_at)
                    .num_hours()
                    > 24
                {
                    case.update_status(CaseStatus::Resolved);
                    info!("Case {} resolved after investigation", case.id);
                }
            }
            _ => {
                // No action needed for other statuses
            }
        }

        Ok(())
    }
}

/// Priority-based case workflow
pub struct PriorityBasedWorkflow;

#[async_trait]
impl Workflow for PriorityBasedWorkflow {
    fn name(&self) -> &str {
        "priority_based_workflow"
    }

    async fn can_handle(&self, case: &SecurityCase) -> bool {
        // Only handle high priority cases
        case.priority >= CasePriority::High
    }

    async fn execute(&self, case: &mut SecurityCase) -> SoarResult<()> {
        // Expedited workflow for high-priority cases
        match case.status {
            CaseStatus::Open => {
                // Immediate escalation for critical cases
                if case.priority == CasePriority::Critical {
                    case.update_status(CaseStatus::Escalated);
                    warn!("Critical case {} requires immediate attention", case.id);
                }
            }
            CaseStatus::Escalated => {
                // Fast-track investigation
                case.update_status(CaseStatus::Investigating);
                info!(
                    "High-priority case {} fast-tracked for investigation",
                    case.id
                );
            }
            _ => {
                // Follow standard workflow
            }
        }

        Ok(())
    }
}

impl CaseWorkflowEngine {
    /// Create a new workflow engine with default workflows
    #[must_use]
    pub fn new_with_defaults(
        workflow_client: Option<Arc<dyn WorkflowClient + Send + Sync>>,
    ) -> Self {
        let mut engine = Self::new(workflow_client);

        // Register default workflows
        engine.register_workflow(DefaultCaseWorkflow);
        engine.register_workflow(PriorityBasedWorkflow);

        engine
    }
}
