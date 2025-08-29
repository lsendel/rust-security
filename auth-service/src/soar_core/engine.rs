//! Main SOAR engine implementation
//!
//! This module contains the core SOAR engine that orchestrates all
//! security operations, automation, and response activities.

use super::types::*;
use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::security_monitoring::{AlertSeverity, SecurityAlert, SecurityAlertType};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Core SOAR engine responsible for orchestrating security operations
pub struct SoarCore {
    /// Configuration for the SOAR system
    config: Arc<RwLock<SoarConfig>>,

    /// Workflow engine for executing security playbooks
    workflow_engine: Arc<super::workflow::WorkflowEngine>,

    /// Alert correlation engine
    correlation_engine: Arc<super::correlation::AlertCorrelationEngine>,

    /// Response automation engine
    response_engine: Arc<super::response::ResponseAutomationEngine>,

    /// Case management system
    case_manager: Arc<CaseManager>,

    /// Integration framework for external tools
    integration_framework: Arc<super::integration::IntegrationFramework>,

    /// Metrics collector
    metrics_collector: Arc<super::metrics::SoarMetrics>,

    /// Active workflow instances
    active_workflows: Arc<DashMap<String, WorkflowInstance>>,

    /// Event processing queue
    event_queue: mpsc::Sender<SoarEvent>,
    event_receiver: Arc<Mutex<mpsc::Receiver<SoarEvent>>>,

    /// Template engine for notifications
    template_engine: Arc<Handlebars<'static>>,

    /// Security logger
    security_logger: Arc<SecurityLogger>,
}

impl SoarCore {
    /// Create a new SOAR core instance
    pub async fn new(config: SoarConfig) -> Result<Self, SoarError> {
        let (event_tx, event_rx) = mpsc::channel(1000);

        let workflow_engine = Arc::new(super::workflow::WorkflowEngine::new().await?);
        let correlation_engine = Arc::new(
            super::correlation::AlertCorrelationEngine::new(config.correlation_config.clone())
                .await?,
        );
        let response_engine = Arc::new(
            super::response::ResponseAutomationEngine::new(config.auto_response_config.clone())
                .await?,
        );
        let integration_framework = Arc::new(
            super::integration::IntegrationFramework::new(config.integrations.clone()).await?,
        );
        let metrics_collector = Arc::new(super::metrics::SoarMetrics::new().await?);

        let case_manager = Arc::new(CaseManager::new(config.case_management.clone()).await?);
        let security_logger = Arc::new(SecurityLogger::new().await?);

        let mut template_engine = Handlebars::new();
        template_engine.set_strict_mode(true);

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            workflow_engine,
            correlation_engine,
            response_engine,
            case_manager,
            integration_framework,
            metrics_collector,
            active_workflows: Arc::new(DashMap::new()),
            event_queue: event_tx,
            event_receiver: Arc::new(Mutex::new(event_rx)),
            template_engine: Arc::new(template_engine),
            security_logger,
        })
    }

    /// Start the SOAR engine
    pub async fn start(&self) -> Result<(), SoarError> {
        info!("Starting SOAR engine");

        // Start event processing loop
        let event_processor = self.clone();
        tokio::spawn(async move {
            event_processor.process_events().await;
        });

        // Start workflow engine
        self.workflow_engine.start().await?;

        // Start correlation engine
        self.correlation_engine.start().await?;

        // Start response engine
        self.response_engine.start().await?;

        // Start integration health checks
        self.integration_framework.start_health_checks().await?;

        // Start metrics collection
        self.metrics_collector.start().await?;

        info!("SOAR engine started successfully");
        Ok(())
    }

    /// Stop the SOAR engine
    pub async fn stop(&self) -> Result<(), SoarError> {
        info!("Stopping SOAR engine");

        // Stop all components
        self.workflow_engine.stop().await?;
        self.correlation_engine.stop().await?;
        self.response_engine.stop().await?;
        self.integration_framework.stop().await?;
        self.metrics_collector.stop().await?;

        info!("SOAR engine stopped successfully");
        Ok(())
    }

    /// Process incoming security alerts
    pub async fn process_alert(&self, alert: SecurityAlert) -> Result<(), SoarError> {
        debug!("Processing security alert: {}", alert.id);

        // Log the alert
        self.security_logger
            .log_event(SecurityEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: SecurityEventType::AlertReceived,
                severity: SecuritySeverity::from(alert.severity.clone()),
                source: "soar_core".to_string(),
                message: format!("Alert received: {}", alert.title),
                metadata: Some(serde_json::to_value(&alert)?),
            })
            .await?;

        // Send to correlation engine
        self.correlation_engine.process_alert(alert.clone()).await?;

        // Check for auto-response triggers
        if self.should_auto_respond(&alert).await? {
            self.trigger_auto_response(alert.clone()).await?;
        }

        // Create case if configured
        if self.should_create_case(&alert).await? {
            self.case_manager
                .create_case_from_alert(alert.clone())
                .await?;
        }

        // Update metrics
        self.metrics_collector
            .record_alert_processed(&alert)
            .await?;

        Ok(())
    }

    /// Trigger a security playbook
    pub async fn trigger_playbook(
        &self,
        playbook_id: &str,
        inputs: HashMap<String, serde_json::Value>,
        context: HashMap<String, serde_json::Value>,
    ) -> Result<String, SoarError> {
        debug!("Triggering playbook: {}", playbook_id);

        let config = self.config.read().await;
        let playbook = config
            .playbooks
            .get(playbook_id)
            .ok_or_else(|| SoarError::PlaybookNotFound(playbook_id.to_string()))?
            .clone();
        drop(config);

        // Create workflow instance
        let instance_id = Uuid::new_v4().to_string();
        let workflow_instance = WorkflowInstance {
            id: instance_id.clone(),
            playbook_id: playbook_id.to_string(),
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

        // Execute workflow
        self.workflow_engine
            .execute_workflow(playbook, inputs, context)
            .await?;

        // Log workflow trigger
        self.security_logger
            .log_event(SecurityEvent {
                id: Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                event_type: SecurityEventType::WorkflowTriggered,
                severity: SecuritySeverity::Info,
                source: "soar_core".to_string(),
                message: format!("Playbook triggered: {}", playbook_id),
                metadata: Some(serde_json::json!({
                    "playbook_id": playbook_id,
                    "instance_id": instance_id,
                    "inputs": inputs
                })),
            })
            .await?;

        Ok(instance_id)
    }

    /// Get workflow status
    pub async fn get_workflow_status(
        &self,
        instance_id: &str,
    ) -> Result<WorkflowStatus, SoarError> {
        let workflow = self
            .active_workflows
            .get(instance_id)
            .ok_or_else(|| SoarError::WorkflowNotFound(instance_id.to_string()))?;
        Ok(workflow.status.clone())
    }

    /// Get active workflows
    pub async fn get_active_workflows(&self) -> Vec<WorkflowInstance> {
        self.active_workflows
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: SoarConfig) -> Result<(), SoarError> {
        let mut config = self.config.write().await;
        *config = new_config;

        info!("SOAR configuration updated");
        Ok(())
    }

    /// Get current configuration
    pub async fn get_config(&self) -> SoarConfig {
        self.config.read().await.clone()
    }

    /// Get system health status
    pub async fn get_health_status(&self) -> Result<SoarHealthStatus, SoarError> {
        let integration_health = self.integration_framework.get_health_summary().await?;
        let workflow_count = self.active_workflows.len();
        let case_count = self.case_manager.get_active_case_count().await?;

        Ok(SoarHealthStatus {
            overall_status: if integration_health.overall_health_percentage > 80 {
                HealthStatus::Healthy
            } else if integration_health.overall_health_percentage > 50 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Unhealthy
            },
            active_workflows: workflow_count,
            active_cases: case_count,
            integration_health,
            last_check: Utc::now(),
        })
    }

    /// Process events from the event queue
    async fn process_events(&self) {
        let mut receiver = self.event_receiver.lock().await;

        while let Some(event) = receiver.recv().await {
            if let Err(e) = self.handle_event(event).await {
                error!("Error processing SOAR event: {}", e);
            }
        }
    }

    /// Handle individual SOAR events
    async fn handle_event(&self, event: SoarEvent) -> Result<(), SoarError> {
        debug!("Handling SOAR event: {:?}", event.event_type);

        match event.event_type {
            SoarEventType::AlertReceived => {
                if let Ok(alert) = serde_json::from_value::<SecurityAlert>(event.data) {
                    self.process_alert(alert).await?;
                }
            }
            SoarEventType::WorkflowCompleted => {
                self.handle_workflow_completed(&event).await?;
            }
            SoarEventType::WorkflowFailed => {
                self.handle_workflow_failed(&event).await?;
            }
            SoarEventType::ApprovalRequired => {
                self.handle_approval_required(&event).await?;
            }
            SoarEventType::EscalationTriggered => {
                self.handle_escalation(&event).await?;
            }
            _ => {
                debug!("Unhandled event type: {:?}", event.event_type);
            }
        }

        Ok(())
    }

    /// Check if an alert should trigger auto-response
    async fn should_auto_respond(&self, alert: &SecurityAlert) -> Result<bool, SoarError> {
        let config = self.config.read().await;

        if !config.auto_response_config.enabled {
            return Ok(false);
        }

        // Check severity threshold
        if alert.severity < config.auto_response_config.severity_threshold {
            return Ok(false);
        }

        // Check allowed threat types
        if !config.auto_response_config.allowed_threat_types.is_empty()
            && !config
                .auto_response_config
                .allowed_threat_types
                .contains(&alert.alert_type)
        {
            return Ok(false);
        }

        Ok(true)
    }

    /// Trigger automatic response for an alert
    async fn trigger_auto_response(&self, alert: SecurityAlert) -> Result<(), SoarError> {
        debug!("Triggering auto-response for alert: {}", alert.id);

        self.response_engine.trigger_auto_response(alert).await?;

        Ok(())
    }

    /// Check if a case should be created for an alert
    async fn should_create_case(&self, alert: &SecurityAlert) -> Result<bool, SoarError> {
        let config = self.config.read().await;

        if !config.case_management.auto_create_cases {
            return Ok(false);
        }

        // Check severity threshold
        Ok(alert.severity >= config.case_management.case_creation_threshold)
    }

    /// Handle workflow completion
    async fn handle_workflow_completed(&self, event: &SoarEvent) -> Result<(), SoarError> {
        if let Some(instance_id) = event.data.get("instance_id").and_then(|v| v.as_str()) {
            if let Some(mut workflow) = self.active_workflows.get_mut(instance_id) {
                workflow.status = WorkflowStatus::Completed;
                workflow.ended_at = Some(Utc::now());
            }
        }
        Ok(())
    }

    /// Handle workflow failure
    async fn handle_workflow_failed(&self, event: &SoarEvent) -> Result<(), SoarError> {
        if let Some(instance_id) = event.data.get("instance_id").and_then(|v| v.as_str()) {
            if let Some(mut workflow) = self.active_workflows.get_mut(instance_id) {
                workflow.status = WorkflowStatus::Failed;
                workflow.ended_at = Some(Utc::now());

                if let Some(error_data) = event.data.get("error") {
                    if let Ok(error) = serde_json::from_value::<WorkflowError>(error_data.clone()) {
                        workflow.error = Some(error);
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle approval requirements
    async fn handle_approval_required(&self, event: &SoarEvent) -> Result<(), SoarError> {
        // Implementation for handling approval workflows
        debug!("Approval required for workflow");
        Ok(())
    }

    /// Handle escalation events
    async fn handle_escalation(&self, event: &SoarEvent) -> Result<(), SoarError> {
        // Implementation for handling escalations
        debug!("Escalation triggered");
        Ok(())
    }
}

impl Clone for SoarCore {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            workflow_engine: Arc::clone(&self.workflow_engine),
            correlation_engine: Arc::clone(&self.correlation_engine),
            response_engine: Arc::clone(&self.response_engine),
            case_manager: Arc::clone(&self.case_manager),
            integration_framework: Arc::clone(&self.integration_framework),
            metrics_collector: Arc::clone(&self.metrics_collector),
            active_workflows: Arc::clone(&self.active_workflows),
            event_queue: self.event_queue.clone(),
            event_receiver: Arc::clone(&self.event_receiver),
            template_engine: Arc::clone(&self.template_engine),
            security_logger: Arc::clone(&self.security_logger),
        }
    }
}

/// SOAR system health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarHealthStatus {
    /// Overall system health
    pub overall_status: HealthStatus,

    /// Number of active workflows
    pub active_workflows: usize,

    /// Number of active cases
    pub active_cases: usize,

    /// Integration health summary
    pub integration_health: super::integration::HealthMetrics,

    /// Last health check timestamp
    pub last_check: DateTime<Utc>,
}

/// Health status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// SOAR error types
#[derive(Debug, thiserror::Error)]
pub enum SoarError {
    #[error("Playbook not found: {0}")]
    PlaybookNotFound(String),

    #[error("Workflow not found: {0}")]
    WorkflowNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Workflow execution error: {0}")]
    WorkflowExecutionError(String),

    #[error("Integration error: {0}")]
    IntegrationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Case manager implementation (simplified for this module)
pub struct CaseManager {
    config: CaseManagementConfig,
}

impl CaseManager {
    pub async fn new(config: CaseManagementConfig) -> Result<Self, SoarError> {
        Ok(Self { config })
    }

    pub async fn create_case_from_alert(&self, _alert: SecurityAlert) -> Result<String, SoarError> {
        // Implementation would create a case from the alert
        Ok(Uuid::new_v4().to_string())
    }

    pub async fn get_active_case_count(&self) -> Result<usize, SoarError> {
        // Implementation would return actual count
        Ok(0)
    }
}
