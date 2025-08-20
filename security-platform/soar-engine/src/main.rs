//! Security Orchestration, Automation and Response (SOAR) Engine
//! Automated security incident response and workflow orchestration

use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
    Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use petgraph::{Graph, Directed};
use prometheus::{register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec, HistogramVec};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

// Metrics
static INCIDENTS_PROCESSED: once_cell::sync::Lazy<CounterVec> = once_cell::sync::Lazy::new(|| {
    register_counter_vec!(
        "soar_incidents_processed_total",
        "Total security incidents processed",
        &["severity", "status"]
    ).unwrap()
});

static WORKFLOW_EXECUTION_TIME: once_cell::sync::Lazy<HistogramVec> = once_cell::sync::Lazy::new(|| {
    register_histogram_vec!(
        "soar_workflow_execution_seconds",
        "Time taken to execute security workflows",
        &["workflow_type"]
    ).unwrap()
});

static ACTIVE_INCIDENTS: once_cell::sync::Lazy<GaugeVec> = once_cell::sync::Lazy::new(|| {
    register_gauge_vec!(
        "soar_active_incidents",
        "Number of active security incidents",
        &["severity"]
    ).unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    InProgress,
    Escalated,
    Resolved,
    Closed,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentType {
    MalwareDetection,
    UnauthorizedAccess,
    DataBreach,
    PhishingAttempt,
    NetworkAnomaly,
    PrivilegeEscalation,
    SuspiciousProcess,
    FileIntegrityViolation,
    AuthenticationFailure,
    ComplianceViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIncident {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub incident_type: IncidentType,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub source: String,
    pub affected_assets: Vec<String>,
    pub indicators: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub assigned_to: Option<String>,
    pub tags: Vec<String>,
    pub workflow_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub id: Uuid,
    pub name: String,
    pub action_type: ActionType,
    pub parameters: HashMap<String, String>,
    pub conditions: Vec<String>,
    pub timeout: Duration,
    pub retry_count: u32,
    pub on_success: Option<Uuid>,
    pub on_failure: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    // Investigation actions
    CollectLogs,
    AnalyzeArtifacts,
    EnrichThreatIntel,
    CorrelateEvents,
    
    // Containment actions
    IsolateHost,
    BlockIP,
    DisableUser,
    QuarantineFile,
    UpdateFirewall,
    
    // Communication actions
    NotifySOC,
    EscalateToManager,
    SendEmail,
    CreateTicket,
    UpdateDashboard,
    
    // Remediation actions
    PatchSystem,
    ResetPassword,
    RevokeAccess,
    RestoreBackup,
    ScanForMalware,
    
    // Custom actions
    RunScript,
    CallAPI,
    ExecutePlaybook,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityWorkflow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub trigger_conditions: Vec<String>,
    pub steps: Vec<WorkflowStep>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub version: u32,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct WorkflowExecution {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub incident_id: Uuid,
    pub status: ExecutionStatus,
    pub current_step: Option<Uuid>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub execution_log: Vec<ExecutionLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Running,
    Completed,
    Failed,
    Paused,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLogEntry {
    pub timestamp: DateTime<Utc>,
    pub step_id: Uuid,
    pub message: String,
    pub level: LogLevel,
    pub duration: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Debug,
}

pub struct SOAREngine {
    incidents: Arc<DashMap<Uuid, SecurityIncident>>,
    workflows: Arc<DashMap<Uuid, SecurityWorkflow>>,
    executions: Arc<DashMap<Uuid, WorkflowExecution>>,
    threat_intel_cache: Arc<RwLock<HashMap<String, ThreatIntelligence>>>,
    action_handlers: Arc<DashMap<ActionType, Box<dyn ActionHandler + Send + Sync>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub indicator: String,
    pub indicator_type: String,
    pub threat_level: String,
    pub confidence: f64,
    pub sources: Vec<String>,
    pub last_updated: DateTime<Utc>,
    pub context: HashMap<String, String>,
}

#[async_trait::async_trait]
pub trait ActionHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult>;
    fn get_name(&self) -> &str;
    fn get_timeout(&self) -> Duration;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
    pub data: Option<HashMap<String, String>>,
    pub next_action: Option<ActionType>,
}

impl SOAREngine {
    pub fn new() -> Self {
        let mut engine = Self {
            incidents: Arc::new(DashMap::new()),
            workflows: Arc::new(DashMap::new()),
            executions: Arc::new(DashMap::new()),
            threat_intel_cache: Arc::new(RwLock::new(HashMap::new())),
            action_handlers: Arc::new(DashMap::new()),
        };
        
        // Register default action handlers
        engine.register_default_handlers();
        engine
    }

    fn register_default_handlers(&mut self) {
        // Investigation handlers
        self.register_handler(ActionType::CollectLogs, Box::new(LogCollectionHandler));
        self.register_handler(ActionType::AnalyzeArtifacts, Box::new(ArtifactAnalysisHandler));
        self.register_handler(ActionType::EnrichThreatIntel, Box::new(ThreatIntelHandler));
        
        // Containment handlers
        self.register_handler(ActionType::IsolateHost, Box::new(HostIsolationHandler));
        self.register_handler(ActionType::BlockIP, Box::new(IPBlockingHandler));
        self.register_handler(ActionType::DisableUser, Box::new(UserDisableHandler));
        
        // Communication handlers
        self.register_handler(ActionType::NotifySOC, Box::new(SOCNotificationHandler));
        self.register_handler(ActionType::SendEmail, Box::new(EmailHandler));
        self.register_handler(ActionType::CreateTicket, Box::new(TicketingHandler));
    }

    pub fn register_handler(&self, action_type: ActionType, handler: Box<dyn ActionHandler + Send + Sync>) {
        self.action_handlers.insert(action_type, handler);
    }

    pub async fn create_incident(&self, incident: SecurityIncident) -> Result<Uuid> {
        let incident_id = incident.id;
        
        // Update metrics
        INCIDENTS_PROCESSED
            .with_label_values(&[&format!("{:?}", incident.severity), "new"])
            .inc();
        
        ACTIVE_INCIDENTS
            .with_label_values(&[&format!("{:?}", incident.severity)])
            .inc();

        // Store incident
        self.incidents.insert(incident_id, incident.clone());
        
        // Find and trigger matching workflows
        if let Some(workflow) = self.find_matching_workflow(&incident).await {
            self.start_workflow_execution(workflow.id, incident_id).await?;
        }
        
        info!(
            incident_id = %incident_id,
            severity = ?incident.severity,
            incident_type = ?incident.incident_type,
            "Security incident created"
        );
        
        Ok(incident_id)
    }

    async fn find_matching_workflow(&self, incident: &SecurityIncident) -> Option<SecurityWorkflow> {
        for workflow_entry in self.workflows.iter() {
            let workflow = workflow_entry.value();
            
            if workflow.is_active && self.matches_trigger_conditions(incident, &workflow.trigger_conditions) {
                return Some(workflow.clone());
            }
        }
        None
    }

    fn matches_trigger_conditions(&self, incident: &SecurityIncident, conditions: &[String]) -> bool {
        // Simple condition matching - could be enhanced with a proper rule engine
        for condition in conditions {
            if condition.contains(&format!("{:?}", incident.incident_type)) ||
               condition.contains(&format!("{:?}", incident.severity)) {
                return true;
            }
        }
        false
    }

    pub async fn start_workflow_execution(&self, workflow_id: Uuid, incident_id: Uuid) -> Result<Uuid> {
        let execution_id = Uuid::new_v4();
        
        let execution = WorkflowExecution {
            id: execution_id,
            workflow_id,
            incident_id,
            status: ExecutionStatus::Running,
            current_step: None,
            started_at: Utc::now(),
            completed_at: None,
            error_message: None,
            execution_log: Vec::new(),
        };
        
        self.executions.insert(execution_id, execution);
        
        // Start workflow execution in background
        let engine = self.clone();
        tokio::spawn(async move {
            if let Err(e) = engine.execute_workflow(execution_id).await {
                error!(execution_id = %execution_id, error = %e, "Workflow execution failed");
            }
        });
        
        Ok(execution_id)
    }

    async fn execute_workflow(&self, execution_id: Uuid) -> Result<()> {
        let (workflow_id, incident_id) = {
            let execution = self.executions.get(&execution_id)
                .ok_or_else(|| anyhow::anyhow!("Execution not found"))?;
            (execution.workflow_id, execution.incident_id)
        };

        let workflow = self.workflows.get(&workflow_id)
            .ok_or_else(|| anyhow::anyhow!("Workflow not found"))?
            .clone();

        let _timer = WORKFLOW_EXECUTION_TIME
            .with_label_values(&[&workflow.name])
            .start_timer();

        info!(
            execution_id = %execution_id,
            workflow_id = %workflow_id,
            incident_id = %incident_id,
            "Starting workflow execution"
        );

        // Execute workflow steps in sequence
        for step in &workflow.steps {
            if let Err(e) = self.execute_step(execution_id, step).await {
                error!(
                    execution_id = %execution_id,
                    step_id = %step.id,
                    error = %e,
                    "Step execution failed"
                );
                
                self.mark_execution_failed(execution_id, &e.to_string()).await;
                return Err(e);
            }
        }

        self.mark_execution_completed(execution_id).await;
        
        info!(
            execution_id = %execution_id,
            "Workflow execution completed successfully"
        );

        Ok(())
    }

    async fn execute_step(&self, execution_id: Uuid, step: &WorkflowStep) -> Result<()> {
        info!(
            execution_id = %execution_id,
            step_id = %step.id,
            action_type = ?step.action_type,
            "Executing workflow step"
        );

        // Update current step
        if let Some(mut execution) = self.executions.get_mut(&execution_id) {
            execution.current_step = Some(step.id);
        }

        let start_time = std::time::Instant::now();

        // Execute the action
        let result = if let Some(handler) = self.action_handlers.get(&step.action_type) {
            handler.execute(&step.parameters).await?
        } else {
            return Err(anyhow::anyhow!("No handler found for action type: {:?}", step.action_type));
        };

        let duration = start_time.elapsed();

        // Log execution result
        self.log_execution_step(
            execution_id,
            step.id,
            if result.success { LogLevel::Info } else { LogLevel::Error },
            &result.message,
            Some(duration),
        ).await;

        if !result.success {
            return Err(anyhow::anyhow!("Step failed: {}", result.message));
        }

        Ok(())
    }

    async fn log_execution_step(
        &self,
        execution_id: Uuid,
        step_id: Uuid,
        level: LogLevel,
        message: &str,
        duration: Option<Duration>,
    ) {
        let log_entry = ExecutionLogEntry {
            timestamp: Utc::now(),
            step_id,
            message: message.to_string(),
            level,
            duration,
        };

        if let Some(mut execution) = self.executions.get_mut(&execution_id) {
            execution.execution_log.push(log_entry);
        }
    }

    async fn mark_execution_completed(&self, execution_id: Uuid) {
        if let Some(mut execution) = self.executions.get_mut(&execution_id) {
            execution.status = ExecutionStatus::Completed;
            execution.completed_at = Some(Utc::now());
        }
    }

    async fn mark_execution_failed(&self, execution_id: Uuid, error_message: &str) {
        if let Some(mut execution) = self.executions.get_mut(&execution_id) {
            execution.status = ExecutionStatus::Failed;
            execution.completed_at = Some(Utc::now());
            execution.error_message = Some(error_message.to_string());
        }
    }

    pub async fn get_incident(&self, incident_id: Uuid) -> Option<SecurityIncident> {
        self.incidents.get(&incident_id).map(|i| i.clone())
    }

    pub async fn update_incident_status(&self, incident_id: Uuid, status: IncidentStatus) -> Result<()> {
        if let Some(mut incident) = self.incidents.get_mut(&incident_id) {
            let old_status = incident.status.clone();
            incident.status = status.clone();
            incident.updated_at = Utc::now();
            
            // Update metrics
            if matches!(status, IncidentStatus::Resolved | IncidentStatus::Closed) {
                ACTIVE_INCIDENTS
                    .with_label_values(&[&format!("{:?}", incident.severity)])
                    .dec();
            }
            
            info!(
                incident_id = %incident_id,
                old_status = ?old_status,
                new_status = ?status,
                "Incident status updated"
            );
        }
        
        Ok(())
    }

    pub async fn enrich_with_threat_intel(&self, indicators: &[String]) -> HashMap<String, ThreatIntelligence> {
        let mut results = HashMap::new();
        let cache = self.threat_intel_cache.read().await;
        
        for indicator in indicators {
            if let Some(intel) = cache.get(indicator) {
                results.insert(indicator.clone(), intel.clone());
            }
        }
        
        results
    }
}

impl Clone for SOAREngine {
    fn clone(&self) -> Self {
        Self {
            incidents: Arc::clone(&self.incidents),
            workflows: Arc::clone(&self.workflows),
            executions: Arc::clone(&self.executions),
            threat_intel_cache: Arc::clone(&self.threat_intel_cache),
            action_handlers: Arc::clone(&self.action_handlers),
        }
    }
}

// Default Action Handlers
struct LogCollectionHandler;

#[async_trait::async_trait]
impl ActionHandler for LogCollectionHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let host = parameters.get("host").unwrap_or(&"localhost".to_string());
        
        // Simulate log collection
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("Logs collected from host: {}", host),
            data: Some(HashMap::from([
                ("logs_collected".to_string(), "1000".to_string()),
                ("collection_time".to_string(), "2s".to_string()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "Log Collection Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(300)
    }
}

struct ArtifactAnalysisHandler;

#[async_trait::async_trait]
impl ActionHandler for ArtifactAnalysisHandler {
    async fn execute(&self, _parameters: &HashMap<String, String>) -> Result<ActionResult> {
        // Simulate artifact analysis
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        Ok(ActionResult {
            success: true,
            message: "Artifacts analyzed successfully".to_string(),
            data: Some(HashMap::from([
                ("malicious_files".to_string(), "2".to_string()),
                ("suspicious_processes".to_string(), "1".to_string()),
            ])),
            next_action: Some(ActionType::EnrichThreatIntel),
        })
    }

    fn get_name(&self) -> &str {
        "Artifact Analysis Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(600)
    }
}

struct ThreatIntelHandler;

#[async_trait::async_trait]
impl ActionHandler for ThreatIntelHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let indicator = parameters.get("indicator").unwrap_or(&"unknown".to_string());
        
        // Simulate threat intelligence lookup
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("Threat intelligence enriched for indicator: {}", indicator),
            data: Some(HashMap::from([
                ("threat_level".to_string(), "high".to_string()),
                ("confidence".to_string(), "0.8".to_string()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "Threat Intelligence Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

struct HostIsolationHandler;

#[async_trait::async_trait]
impl ActionHandler for HostIsolationHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let host = parameters.get("host").unwrap_or(&"unknown".to_string());
        
        // Simulate host isolation
        tokio::time::sleep(Duration::from_secs(3)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("Host {} isolated successfully", host),
            data: Some(HashMap::from([
                ("isolation_method".to_string(), "network_segmentation".to_string()),
                ("isolation_time".to_string(), Utc::now().to_rfc3339()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "Host Isolation Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(60)
    }
}

struct IPBlockingHandler;

#[async_trait::async_trait]
impl ActionHandler for IPBlockingHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let ip = parameters.get("ip").unwrap_or(&"unknown".to_string());
        
        // Simulate IP blocking
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("IP {} blocked successfully", ip),
            data: Some(HashMap::from([
                ("block_method".to_string(), "firewall_rule".to_string()),
                ("block_duration".to_string(), "24h".to_string()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "IP Blocking Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

struct UserDisableHandler;

#[async_trait::async_trait]
impl ActionHandler for UserDisableHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let user = parameters.get("user").unwrap_or(&"unknown".to_string());
        
        // Simulate user account disabling
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("User account {} disabled successfully", user),
            data: Some(HashMap::from([
                ("disable_method".to_string(), "active_directory".to_string()),
                ("sessions_terminated".to_string(), "3".to_string()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "User Disable Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

struct SOCNotificationHandler;

#[async_trait::async_trait]
impl ActionHandler for SOCNotificationHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let message = parameters.get("message").unwrap_or(&"Security incident detected".to_string());
        
        // Simulate SOC notification
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("SOC notified: {}", message),
            data: Some(HashMap::from([
                ("notification_method".to_string(), "slack_webhook".to_string()),
                ("notification_time".to_string(), Utc::now().to_rfc3339()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "SOC Notification Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(10)
    }
}

struct EmailHandler;

#[async_trait::async_trait]
impl ActionHandler for EmailHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let to = parameters.get("to").unwrap_or(&"security@company.com".to_string());
        let subject = parameters.get("subject").unwrap_or(&"Security Alert".to_string());
        
        // Simulate email sending
        tokio::time::sleep(Duration::from_millis(800)).await;
        
        Ok(ActionResult {
            success: true,
            message: format!("Email sent to {} with subject: {}", to, subject),
            data: Some(HashMap::from([
                ("delivery_status".to_string(), "sent".to_string()),
                ("message_id".to_string(), Uuid::new_v4().to_string()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "Email Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

struct TicketingHandler;

#[async_trait::async_trait]
impl ActionHandler for TicketingHandler {
    async fn execute(&self, parameters: &HashMap<String, String>) -> Result<ActionResult> {
        let title = parameters.get("title").unwrap_or(&"Security Incident".to_string());
        let priority = parameters.get("priority").unwrap_or(&"high".to_string());
        
        // Simulate ticket creation
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        let ticket_id = format!("INC-{}", Uuid::new_v4().to_string().split('-').next().unwrap());
        
        Ok(ActionResult {
            success: true,
            message: format!("Ticket {} created with title: {}", ticket_id, title),
            data: Some(HashMap::from([
                ("ticket_id".to_string(), ticket_id),
                ("priority".to_string(), priority.to_string()),
                ("status".to_string(), "open".to_string()),
            ])),
            next_action: None,
        })
    }

    fn get_name(&self) -> &str {
        "Ticketing Handler"
    }

    fn get_timeout(&self) -> Duration {
        Duration::from_secs(30)
    }
}

// REST API Handlers
async fn create_incident(
    State(engine): State<SOAREngine>,
    Json(incident): Json<SecurityIncident>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    match engine.create_incident(incident).await {
        Ok(incident_id) => Ok(Json(HashMap::from([
            ("incident_id".to_string(), incident_id.to_string()),
            ("status".to_string(), "created".to_string()),
        ]))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_incident(
    State(engine): State<SOAREngine>,
    Path(incident_id): Path<Uuid>,
) -> Result<Json<SecurityIncident>, StatusCode> {
    match engine.get_incident(incident_id).await {
        Some(incident) => Ok(Json(incident)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn update_incident_status(
    State(engine): State<SOAREngine>,
    Path(incident_id): Path<Uuid>,
    Json(request): Json<HashMap<String, String>>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    let status_str = request.get("status").ok_or(StatusCode::BAD_REQUEST)?;
    let status: IncidentStatus = serde_json::from_str(&format!("\"{}\"", status_str))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    match engine.update_incident_status(incident_id, status).await {
        Ok(_) => Ok(Json(HashMap::from([
            ("incident_id".to_string(), incident_id.to_string()),
            ("status".to_string(), "updated".to_string()),
        ]))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn health_check() -> Json<HashMap<String, String>> {
    Json(HashMap::from([
        ("status".to_string(), "healthy".to_string()),
        ("service".to_string(), "soar-engine".to_string()),
        ("timestamp".to_string(), Utc::now().to_rfc3339()),
    ]))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    info!("Starting SOAR Engine");

    let engine = SOAREngine::new();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/incidents", post(create_incident))
        .route("/api/v1/incidents/:id", get(get_incident))
        .route("/api/v1/incidents/:id/status", put(update_incident_status))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    
    info!("SOAR Engine listening on http://0.0.0.0:8080");
    
    axum::serve(listener, app).await?;

    Ok(())
}