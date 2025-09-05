//! Security Operations Center (SOC) Platform
//! Centralized security monitoring, incident management, and response coordination

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
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use prometheus::{register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec, HistogramVec};

// Metrics
static ALERTS_PROCESSED: once_cell::sync::Lazy<CounterVec> = once_cell::sync::Lazy::new(|| {
    register_counter_vec!(
        "soc_alerts_processed_total",
        "Total security alerts processed",
        &["severity", "source", "status"]
    ).unwrap()
});

static ACTIVE_INCIDENTS: once_cell::sync::Lazy<GaugeVec> = once_cell::sync::Lazy::new(|| {
    register_gauge_vec!(
        "soc_active_incidents",
        "Number of active security incidents",
        &["severity", "category"]
    ).unwrap()
});

static RESPONSE_TIME: once_cell::sync::Lazy<HistogramVec> = once_cell::sync::Lazy::new(|| {
    register_histogram_vec!(
        "soc_response_time_seconds",
        "Time from alert to initial response",
        &["severity"]
    ).unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertStatus {
    New,
    Acknowledged,
    InProgress,
    Resolved,
    Closed,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentCategory {
    Malware,
    DataBreach,
    NetworkIntrusion,
    InsiderThreat,
    PhishingAttack,
    DenialOfService,
    PrivilegeEscalation,
    SystemCompromise,
    ComplianceViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub status: AlertStatus,
    pub source: String,
    pub source_ip: Option<String>,
    pub affected_systems: Vec<String>,
    pub indicators: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub assigned_to: Option<String>,
    pub escalation_level: u32,
    pub ttl_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOCIncident {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub category: IncidentCategory,
    pub severity: AlertSeverity,
    pub status: IncidentStatus,
    pub alerts: Vec<Uuid>,
    pub affected_assets: Vec<Asset>,
    pub timeline: Vec<IncidentEvent>,
    pub assigned_analyst: Option<String>,
    pub created_at: DateTime<Utc>,
    pub first_response_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub mttr_minutes: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IncidentStatus {
    New,
    Triaging,
    Investigating,
    Containing,
    Eradicating,
    Recovering,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub asset_type: AssetType,
    pub criticality: AssetCriticality,
    pub ip_addresses: Vec<String>,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetType {
    Server,
    Workstation,
    NetworkDevice,
    Database,
    Application,
    CloudResource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AssetCriticality {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub description: String,
    pub actor: String,
    pub automated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    AlertReceived,
    IncidentCreated,
    AssignmentChanged,
    StatusUpdated,
    EvidenceAdded,
    ActionTaken,
    EscalationTriggered,
    IncidentResolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SOCAnalyst {
    pub id: Uuid,
    pub username: String,
    pub name: String,
    pub email: String,
    pub shift: Shift,
    pub specializations: Vec<String>,
    pub active_incidents: Vec<Uuid>,
    pub performance_metrics: AnalystMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Shift {
    Day,
    Evening,
    Night,
    Weekend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystMetrics {
    pub alerts_handled_today: u32,
    pub incidents_resolved_this_week: u32,
    pub average_response_time_minutes: f64,
    pub escalation_rate: f64,
    pub false_positive_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub id: Uuid,
    pub name: String,
    pub conditions: Vec<EscalationCondition>,
    pub action: EscalationAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationAction {
    NotifyManager,
    CreateIncident,
    AssignToSeniorAnalyst,
    TriggerEmergencyResponse,
    NotifyExecutives,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub category: IncidentCategory,
    pub steps: Vec<PlaybookStep>,
    pub estimated_duration_minutes: u32,
    pub created_by: String,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookStep {
    pub step_number: u32,
    pub title: String,
    pub description: String,
    pub action_type: ActionType,
    pub estimated_duration_minutes: u32,
    pub required_tools: Vec<String>,
    pub verification_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Investigation,
    Containment,
    Evidence_Collection,
    Communication,
    Recovery,
    Documentation,
}

pub struct SOCPlatform {
    alerts: Arc<DashMap<Uuid, SecurityAlert>>,
    incidents: Arc<DashMap<Uuid, SOCIncident>>,
    analysts: Arc<DashMap<Uuid, SOCAnalyst>>,
    playbooks: Arc<DashMap<Uuid, Playbook>>,
    escalation_rules: Arc<DashMap<Uuid, EscalationRule>>,
    alert_correlation: Arc<AlertCorrelationEngine>,
    shift_manager: Arc<ShiftManager>,
}

pub struct AlertCorrelationEngine {
    correlation_rules: Arc<RwLock<Vec<CorrelationRule>>>,
    correlation_window_minutes: u32,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: Uuid,
    pub name: String,
    pub conditions: Vec<String>,
    pub time_window_minutes: u32,
    pub threshold: u32,
    pub create_incident: bool,
}

pub struct ShiftManager {
    current_shift: Arc<RwLock<Shift>>,
    shift_schedule: Arc<RwLock<HashMap<Shift, Vec<Uuid>>>>,
}

impl SOCPlatform {
    pub fn new() -> Self {
        Self {
            alerts: Arc::new(DashMap::new()),
            incidents: Arc::new(DashMap::new()),
            analysts: Arc::new(DashMap::new()),
            playbooks: Arc::new(DashMap::new()),
            escalation_rules: Arc::new(DashMap::new()),
            alert_correlation: Arc::new(AlertCorrelationEngine::new()),
            shift_manager: Arc::new(ShiftManager::new()),
        }
    }

    pub async fn ingest_alert(&self, mut alert: SecurityAlert) -> Result<Uuid> {
        alert.id = Uuid::new_v4();
        alert.created_at = Utc::now();
        alert.updated_at = Utc::now();

        let alert_id = alert.id;

        info!(
            alert_id = %alert_id,
            severity = ?alert.severity,
            source = %alert.source,
            "Security alert ingested"
        );

        // Update metrics
        ALERTS_PROCESSED
            .with_label_values(&[
                &format!("{:?}", alert.severity),
                &alert.source,
                "new",
            ])
            .inc();

        // Store alert
        self.alerts.insert(alert_id, alert.clone());

        // Auto-assign to available analyst
        self.auto_assign_alert(alert_id).await?;

        // Check for correlation
        self.correlate_alert(&alert).await?;

        // Check escalation rules
        self.check_escalation_rules(&alert).await?;

        Ok(alert_id)
    }

    async fn auto_assign_alert(&self, alert_id: Uuid) -> Result<()> {
        let current_shift = *self.shift_manager.current_shift.read().await;
        let shift_schedule = self.shift_manager.shift_schedule.read().await;

        if let Some(analyst_ids) = shift_schedule.get(&current_shift) {
            // Find analyst with least workload
            let mut best_analyst = None;
            let mut min_workload = u32::MAX;

            for analyst_id in analyst_ids {
                if let Some(analyst) = self.analysts.get(analyst_id) {
                    let workload = analyst.active_incidents.len() as u32;
                    if workload < min_workload {
                        min_workload = workload;
                        best_analyst = Some(analyst_id);
                    }
                }
            }

            if let Some(analyst_id) = best_analyst {
                if let Some(mut alert) = self.alerts.get_mut(&alert_id) {
                    if let Some(analyst) = self.analysts.get(analyst_id) {
                        alert.assigned_to = Some(analyst.username.clone());
                        info!(
                            alert_id = %alert_id,
                            analyst = %analyst.username,
                            "Alert auto-assigned"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn correlate_alert(&self, alert: &SecurityAlert) -> Result<()> {
        let correlation_rules = self.alert_correlation.correlation_rules.read().await;
        let window_start = Utc::now() - chrono::Duration::minutes(
            self.alert_correlation.correlation_window_minutes as i64
        );

        for rule in correlation_rules.iter() {
            let mut matching_alerts = Vec::new();

            // Find alerts matching the correlation rule
            for entry in self.alerts.iter() {
                let existing_alert = entry.value();
                if existing_alert.created_at >= window_start && 
                   self.alert_matches_rule(existing_alert, rule) {
                    matching_alerts.push(existing_alert.id);
                }
            }

            // Check if threshold is met
            if matching_alerts.len() >= rule.threshold as usize && rule.create_incident {
                self.create_correlated_incident(&matching_alerts, rule).await?;
            }
        }

        Ok(())
    }

    fn alert_matches_rule(&self, alert: &SecurityAlert, rule: &CorrelationRule) -> bool {
        // Simplified rule matching - could be enhanced with a proper rule engine
        for condition in &rule.conditions {
            if condition.contains(&alert.source) || 
               condition.contains(&format!("{:?}", alert.severity)) {
                return true;
            }
        }
        false
    }

    async fn create_correlated_incident(&self, alert_ids: &[Uuid], rule: &CorrelationRule) -> Result<Uuid> {
        let incident_id = Uuid::new_v4();
        let now = Utc::now();

        let incident = SOCIncident {
            id: incident_id,
            title: format!("Correlated Incident: {}", rule.name),
            description: format!("Incident created from {} correlated alerts", alert_ids.len()),
            category: IncidentCategory::SystemCompromise, // Default category
            severity: AlertSeverity::High, // Default to high for correlated incidents
            status: IncidentStatus::New,
            alerts: alert_ids.to_vec(),
            affected_assets: Vec::new(), // TODO: Extract from alerts
            timeline: vec![IncidentEvent {
                timestamp: now,
                event_type: EventType::IncidentCreated,
                description: "Incident created from alert correlation".to_string(),
                actor: "SOC-Platform".to_string(),
                automated: true,
            }],
            assigned_analyst: None,
            created_at: now,
            first_response_at: None,
            resolved_at: None,
            mttr_minutes: None,
        };

        self.incidents.insert(incident_id, incident);

        // Update metrics
        ACTIVE_INCIDENTS
            .with_label_values(&["High", "SystemCompromise"])
            .inc();

        info!(
            incident_id = %incident_id,
            rule = %rule.name,
            alert_count = %alert_ids.len(),
            "Correlated incident created"
        );

        Ok(incident_id)
    }

    async fn check_escalation_rules(&self, alert: &SecurityAlert) -> Result<()> {
        for entry in self.escalation_rules.iter() {
            let rule = entry.value();
            if rule.enabled && self.alert_meets_escalation_conditions(alert, &rule.conditions) {
                self.execute_escalation_action(alert, &rule.action).await?;
            }
        }
        Ok(())
    }

    fn alert_meets_escalation_conditions(&self, alert: &SecurityAlert, conditions: &[EscalationCondition]) -> bool {
        for condition in conditions {
            let matches = match condition.field.as_str() {
                "severity" => format!("{:?}", alert.severity) == condition.value,
                "source" => alert.source == condition.value,
                "escalation_level" => {
                    let threshold: u32 = condition.value.parse().unwrap_or(0);
                    match condition.operator.as_str() {
                        ">=" => alert.escalation_level >= threshold,
                        ">" => alert.escalation_level > threshold,
                        _ => false,
                    }
                }
                _ => false,
            };

            if !matches {
                return false;
            }
        }
        true
    }

    async fn execute_escalation_action(&self, alert: &SecurityAlert, action: &EscalationAction) -> Result<()> {
        match action {
            EscalationAction::NotifyManager => {
                info!(
                    alert_id = %alert.id,
                    "Escalating alert to manager"
                );
                // TODO: Send notification to manager
            }
            EscalationAction::CreateIncident => {
                self.create_incident_from_alert(alert).await?;
            }
            EscalationAction::AssignToSeniorAnalyst => {
                // TODO: Find and assign to senior analyst
                info!(
                    alert_id = %alert.id,
                    "Escalating alert to senior analyst"
                );
            }
            EscalationAction::TriggerEmergencyResponse => {
                warn!(
                    alert_id = %alert.id,
                    "Emergency response triggered"
                );
                // TODO: Trigger emergency response procedures
            }
            EscalationAction::NotifyExecutives => {
                warn!(
                    alert_id = %alert.id,
                    "Notifying executives of critical alert"
                );
                // TODO: Send executive notifications
            }
        }
        Ok(())
    }

    async fn create_incident_from_alert(&self, alert: &SecurityAlert) -> Result<Uuid> {
        let incident_id = Uuid::new_v4();
        let now = Utc::now();

        let incident = SOCIncident {
            id: incident_id,
            title: format!("Incident: {}", alert.title),
            description: alert.description.clone(),
            category: self.determine_incident_category(alert),
            severity: alert.severity.clone(),
            status: IncidentStatus::New,
            alerts: vec![alert.id],
            affected_assets: alert.affected_systems.iter().map(|system| Asset {
                id: system.clone(),
                name: system.clone(),
                asset_type: AssetType::Server, // Default
                criticality: AssetCriticality::Medium, // Default
                ip_addresses: Vec::new(),
                owner: "Unknown".to_string(),
            }).collect(),
            timeline: vec![IncidentEvent {
                timestamp: now,
                event_type: EventType::IncidentCreated,
                description: "Incident created from escalated alert".to_string(),
                actor: "SOC-Platform".to_string(),
                automated: true,
            }],
            assigned_analyst: alert.assigned_to.clone(),
            created_at: now,
            first_response_at: None,
            resolved_at: None,
            mttr_minutes: None,
        };

        self.incidents.insert(incident_id, incident);

        // Update metrics
        ACTIVE_INCIDENTS
            .with_label_values(&[
                &format!("{:?}", alert.severity),
                &format!("{:?}", self.determine_incident_category(alert)),
            ])
            .inc();

        info!(
            incident_id = %incident_id,
            alert_id = %alert.id,
            "Incident created from escalated alert"
        );

        Ok(incident_id)
    }

    fn determine_incident_category(&self, alert: &SecurityAlert) -> IncidentCategory {
        // Simple category determination based on alert content
        let description_lower = alert.description.to_lowercase();
        let title_lower = alert.title.to_lowercase();

        if description_lower.contains("malware") || title_lower.contains("malware") {
            IncidentCategory::Malware
        } else if description_lower.contains("phish") || title_lower.contains("phish") {
            IncidentCategory::PhishingAttack
        } else if description_lower.contains("intrusion") || title_lower.contains("intrusion") {
            IncidentCategory::NetworkIntrusion
        } else if description_lower.contains("privilege") || title_lower.contains("privilege") {
            IncidentCategory::PrivilegeEscalation
        } else if description_lower.contains("dos") || description_lower.contains("ddos") {
            IncidentCategory::DenialOfService
        } else {
            IncidentCategory::SystemCompromise
        }
    }

    pub async fn update_incident_status(&self, incident_id: Uuid, new_status: IncidentStatus, actor: &str) -> Result<()> {
        if let Some(mut incident) = self.incidents.get_mut(&incident_id) {
            let old_status = incident.status.clone();
            incident.status = new_status.clone();

            // Add timeline event
            incident.timeline.push(IncidentEvent {
                timestamp: Utc::now(),
                event_type: EventType::StatusUpdated,
                description: format!("Status changed from {:?} to {:?}", old_status, new_status),
                actor: actor.to_string(),
                automated: false,
            });

            // Update first response time
            if matches!(new_status, IncidentStatus::Investigating) && incident.first_response_at.is_none() {
                incident.first_response_at = Some(Utc::now());
                
                let response_time = Utc::now()
                    .signed_duration_since(incident.created_at)
                    .num_seconds() as f64;

                RESPONSE_TIME
                    .with_label_values(&[&format!("{:?}", incident.severity)])
                    .observe(response_time);
            }

            // Calculate MTTR if resolved
            if matches!(new_status, IncidentStatus::Closed) && incident.resolved_at.is_none() {
                incident.resolved_at = Some(Utc::now());
                let mttr = Utc::now()
                    .signed_duration_since(incident.created_at)
                    .num_minutes() as u32;
                incident.mttr_minutes = Some(mttr);

                // Update metrics
                ACTIVE_INCIDENTS
                    .with_label_values(&[
                        &format!("{:?}", incident.severity),
                        &format!("{:?}", incident.category),
                    ])
                    .dec();
            }

            info!(
                incident_id = %incident_id,
                old_status = ?old_status,
                new_status = ?new_status,
                actor = %actor,
                "Incident status updated"
            );
        }

        Ok(())
    }

    pub async fn get_soc_dashboard(&self) -> SOCDashboard {
        let total_alerts = self.alerts.len();
        let total_incidents = self.incidents.len();
        
        let mut active_incidents = 0;
        let mut critical_incidents = 0;
        let mut high_incidents = 0;

        for entry in self.incidents.iter() {
            let incident = entry.value();
            if !matches!(incident.status, IncidentStatus::Closed) {
                active_incidents += 1;
                
                match incident.severity {
                    AlertSeverity::Critical => critical_incidents += 1,
                    AlertSeverity::High => high_incidents += 1,
                    _ => {}
                }
            }
        }

        let mut new_alerts = 0;
        let mut unassigned_alerts = 0;

        for entry in self.alerts.iter() {
            let alert = entry.value();
            if matches!(alert.status, AlertStatus::New) {
                new_alerts += 1;
            }
            if alert.assigned_to.is_none() {
                unassigned_alerts += 1;
            }
        }

        SOCDashboard {
            total_alerts,
            new_alerts,
            unassigned_alerts,
            total_incidents,
            active_incidents,
            critical_incidents,
            high_incidents,
            analysts_on_duty: self.get_analysts_on_duty().await,
            current_shift: *self.shift_manager.current_shift.read().await,
        }
    }

    async fn get_analysts_on_duty(&self) -> u32 {
        let current_shift = *self.shift_manager.current_shift.read().await;
        let shift_schedule = self.shift_manager.shift_schedule.read().await;
        
        if let Some(analyst_ids) = shift_schedule.get(&current_shift) {
            analyst_ids.len() as u32
        } else {
            0
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SOCDashboard {
    pub total_alerts: usize,
    pub new_alerts: u32,
    pub unassigned_alerts: u32,
    pub total_incidents: usize,
    pub active_incidents: u32,
    pub critical_incidents: u32,
    pub high_incidents: u32,
    pub analysts_on_duty: u32,
    pub current_shift: Shift,
}

impl AlertCorrelationEngine {
    fn new() -> Self {
        Self {
            correlation_rules: Arc::new(RwLock::new(Vec::new())),
            correlation_window_minutes: 30,
        }
    }
}

impl ShiftManager {
    fn new() -> Self {
        Self {
            current_shift: Arc::new(RwLock::new(Shift::Day)),
            shift_schedule: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

// REST API Handlers
async fn ingest_alert(
    State(platform): State<SOCPlatform>,
    Json(alert): Json<SecurityAlert>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    match platform.ingest_alert(alert).await {
        Ok(alert_id) => Ok(Json(HashMap::from([
            ("alert_id".to_string(), alert_id.to_string()),
            ("status".to_string(), "ingested".to_string()),
        ]))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_dashboard(
    State(platform): State<SOCPlatform>,
) -> Json<SOCDashboard> {
    Json(platform.get_soc_dashboard().await)
}

async fn update_incident_status(
    State(platform): State<SOCPlatform>,
    Path(incident__id): Path<Uuid>,
    Json(request): Json<HashMap<String, String>>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    let status_str = request.get("status").ok_or(StatusCode::BAD_REQUEST)?;
    let actor = request.get("actor").unwrap_or(&"unknown".to_string());
    
    let status: IncidentStatus = serde_json::from_str(&format!("\"{}\"", status_str))
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    match platform.update_incident_status(incident_id, status, actor).await {
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
        ("service".to_string(), "soc-platform".to_string()),
        ("timestamp".to_string(), Utc::now().to_rfc3339()),
    ]))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    info!("Starting SOC Platform");

    let platform = SOCPlatform::new();

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/alerts", post(ingest_alert))
        .route("/api/v1/dashboard", get(get_dashboard))
        .route("/api/v1/incidents/:id/status", put(update_incident_status))
        .with_state(platform);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8082").await?;
    
    info!("SOC Platform listening on http://0.0.0.0:8082");
    
    axum::serve(listener, app).await?;

    Ok(())
}