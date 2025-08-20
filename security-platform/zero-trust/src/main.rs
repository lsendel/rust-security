//! Zero Trust Architecture Implementation
//! Network security based on "never trust, always verify" principle

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
    net::IpAddr,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use prometheus::{register_counter_vec, register_gauge_vec, register_histogram_vec, CounterVec, GaugeVec, HistogramVec};

// Metrics
static ACCESS_ATTEMPTS: once_cell::sync::Lazy<CounterVec> = once_cell::sync::Lazy::new(|| {
    register_counter_vec!(
        "zero_trust_access_attempts_total",
        "Total access attempts",
        &["verdict", "resource_type", "user_type"]
    ).unwrap()
});

static ACTIVE_SESSIONS: once_cell::sync::Lazy<GaugeVec> = once_cell::sync::Lazy::new(|| {
    register_gauge_vec!(
        "zero_trust_active_sessions",
        "Number of active zero trust sessions",
        &["trust_level"]
    ).unwrap()
});

static POLICY_EVALUATION_TIME: once_cell::sync::Lazy<HistogramVec> = once_cell::sync::Lazy::new(|| {
    register_histogram_vec!(
        "zero_trust_policy_evaluation_seconds",
        "Time taken to evaluate zero trust policies",
        &["policy_type"]
    ).unwrap()
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustLevel {
    Untrusted,
    Low,
    Medium,
    High,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessVerdict {
    Allow,
    Deny,
    Challenge,
    Monitor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceType {
    Application,
    Database,
    FileSystem,
    Network,
    API,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
    pub device_type: String,
    pub os_version: String,
    pub last_seen: DateTime<Utc>,
    pub compliance_status: ComplianceStatus,
    pub trust_score: f64,
    pub registered_at: DateTime<Utc>,
    pub certificates: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    Unknown,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub department: String,
    pub roles: Vec<String>,
    pub trust_level: TrustLevel,
    pub last_authentication: DateTime<Utc>,
    pub failed_attempts: u32,
    pub mfa_enabled: bool,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub resource: String,
    pub resource_type: ResourceType,
    pub action: String,
    pub source_ip: IpAddr,
    pub user_agent: String,
    pub timestamp: DateTime<Utc>,
    pub context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub conditions: Vec<Condition>,
    pub action: AccessVerdict,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessDecision {
    pub request_id: Uuid,
    pub verdict: AccessVerdict,
    pub trust_score: f64,
    pub reasons: Vec<String>,
    pub applied_policies: Vec<Uuid>,
    pub session_duration: Option<Duration>,
    pub additional_requirements: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub trust_level: TrustLevel,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub access_count: u32,
    pub continuous_verification: bool,
}

pub struct ZeroTrustEngine {
    users: Arc<DashMap<Uuid, User>>,
    devices: Arc<DashMap<Uuid, Device>>,
    policies: Arc<DashMap<Uuid, PolicyRule>>,
    sessions: Arc<DashMap<Uuid, ZeroTrustSession>>,
    access_logs: Arc<RwLock<Vec<AccessDecision>>>,
    risk_engine: Arc<RiskEngine>,
}

pub struct RiskEngine {
    device_risks: Arc<DashMap<Uuid, f64>>,
    user_risks: Arc<DashMap<Uuid, f64>>,
    ip_reputation: Arc<DashMap<IpAddr, f64>>,
}

impl ZeroTrustEngine {
    pub fn new() -> Self {
        Self {
            users: Arc::new(DashMap::new()),
            devices: Arc::new(DashMap::new()),
            policies: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            access_logs: Arc::new(RwLock::new(Vec::new())),
            risk_engine: Arc::new(RiskEngine::new()),
        }
    }

    pub async fn evaluate_access(&self, request: AccessRequest) -> Result<AccessDecision> {
        let _timer = POLICY_EVALUATION_TIME
            .with_label_values(&[&format!("{:?}", request.resource_type)])
            .start_timer();

        info!(
            request_id = %request.id,
            user_id = %request.user_id,
            resource = %request.resource,
            "Evaluating zero trust access request"
        );

        // Get user and device information
        let user = self.users.get(&request.user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
        let device = self.devices.get(&request.device_id)
            .ok_or_else(|| anyhow::anyhow!("Device not found"))?;

        // Calculate trust score
        let trust_score = self.calculate_trust_score(&request, &user, &device).await?;

        // Apply policies
        let (verdict, applied_policies, reasons) = self.apply_policies(&request, &user, &device, trust_score).await?;

        // Create access decision
        let decision = AccessDecision {
            request_id: request.id,
            verdict: verdict.clone(),
            trust_score,
            reasons,
            applied_policies,
            session_duration: self.calculate_session_duration(&verdict, trust_score),
            additional_requirements: self.get_additional_requirements(&verdict, trust_score),
            timestamp: Utc::now(),
        };

        // Update metrics
        ACCESS_ATTEMPTS
            .with_label_values(&[
                &format!("{:?}", verdict),
                &format!("{:?}", request.resource_type),
                &user.department,
            ])
            .inc();

        // Log decision
        let mut logs = self.access_logs.write().await;
        logs.push(decision.clone());

        // Create or update session if access allowed
        if matches!(verdict, AccessVerdict::Allow) {
            self.create_or_update_session(&request, &user, &device, trust_score).await?;
        }

        info!(
            request_id = %request.id,
            verdict = ?verdict,
            trust_score = %trust_score,
            "Access decision made"
        );

        Ok(decision)
    }

    async fn calculate_trust_score(&self, request: &AccessRequest, user: &User, device: &Device) -> Result<f64> {
        let mut score = 0.5; // Base neutral score

        // User factors
        score += match user.trust_level {
            TrustLevel::Verified => 0.3,
            TrustLevel::High => 0.2,
            TrustLevel::Medium => 0.1,
            TrustLevel::Low => -0.1,
            TrustLevel::Untrusted => -0.3,
        };

        // MFA bonus
        if user.mfa_enabled {
            score += 0.1;
        }

        // Failed attempts penalty
        score -= (user.failed_attempts as f64) * 0.05;

        // Device factors
        score += device.trust_score * 0.2;

        score += match device.compliance_status {
            ComplianceStatus::Compliant => 0.2,
            ComplianceStatus::NonCompliant => -0.3,
            ComplianceStatus::Unknown => -0.1,
            ComplianceStatus::Quarantined => -0.5,
        };

        // Time-based factors
        let hours_since_last_auth = Utc::now()
            .signed_duration_since(user.last_authentication)
            .num_hours();
        
        if hours_since_last_auth > 24 {
            score -= 0.1;
        }

        // IP reputation
        if let Some(ip_risk) = self.risk_engine.ip_reputation.get(&request.source_ip) {
            score -= ip_risk * 0.2;
        }

        // Context factors
        if request.context.contains_key("vpn") {
            score += 0.1;
        }

        if request.context.contains_key("suspicious_location") {
            score -= 0.2;
        }

        // Normalize score to 0.0-1.0
        Ok(score.max(0.0).min(1.0))
    }

    async fn apply_policies(
        &self,
        request: &AccessRequest,
        user: &User,
        device: &Device,
        trust_score: f64,
    ) -> Result<(AccessVerdict, Vec<Uuid>, Vec<String>)> {
        let mut applicable_policies: Vec<_> = self.policies
            .iter()
            .filter(|entry| entry.value().enabled)
            .collect();

        // Sort by priority
        applicable_policies.sort_by_key(|entry| entry.value().priority);

        let mut applied_policies = Vec::new();
        let mut reasons = Vec::new();

        // Default policy - require high trust for admin resources
        if matches!(request.resource_type, ResourceType::Admin) && trust_score < 0.8 {
            return Ok((
                AccessVerdict::Deny,
                applied_policies,
                vec!["Administrative access requires high trust score".to_string()],
            ));
        }

        // Check each policy
        for policy_entry in applicable_policies {
            let policy = policy_entry.value();
            
            if self.evaluate_policy_conditions(&policy.conditions, request, user, device, trust_score) {
                applied_policies.push(policy.id);
                reasons.push(format!("Applied policy: {}", policy.name));
                
                match policy.action {
                    AccessVerdict::Deny => {
                        return Ok((AccessVerdict::Deny, applied_policies, reasons));
                    }
                    AccessVerdict::Challenge => {
                        reasons.push("Additional authentication required".to_string());
                        return Ok((AccessVerdict::Challenge, applied_policies, reasons));
                    }
                    _ => continue,
                }
            }
        }

        // Default decision based on trust score
        let verdict = if trust_score >= 0.8 {
            AccessVerdict::Allow
        } else if trust_score >= 0.6 {
            AccessVerdict::Challenge
        } else if trust_score >= 0.4 {
            AccessVerdict::Monitor
        } else {
            AccessVerdict::Deny
        };

        reasons.push(format!("Trust score: {:.2}", trust_score));

        Ok((verdict, applied_policies, reasons))
    }

    fn evaluate_policy_conditions(
        &self,
        conditions: &[Condition],
        request: &AccessRequest,
        user: &User,
        device: &Device,
        trust_score: f64,
    ) -> bool {
        for condition in conditions {
            let matches = match condition.field.as_str() {
                "user.department" => user.department == condition.value,
                "user.trust_level" => format!("{:?}", user.trust_level) == condition.value,
                "device.compliance" => format!("{:?}", device.compliance_status) == condition.value,
                "resource.type" => format!("{:?}", request.resource_type) == condition.value,
                "trust_score" => {
                    let threshold: f64 = condition.value.parse().unwrap_or(0.0);
                    match condition.operator.as_str() {
                        ">=" => trust_score >= threshold,
                        "<=" => trust_score <= threshold,
                        ">" => trust_score > threshold,
                        "<" => trust_score < threshold,
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

    fn calculate_session_duration(&self, verdict: &AccessVerdict, trust_score: f64) -> Option<Duration> {
        match verdict {
            AccessVerdict::Allow => {
                let base_duration = if trust_score >= 0.9 {
                    Duration::from_secs(8 * 3600) // 8 hours
                } else if trust_score >= 0.7 {
                    Duration::from_secs(4 * 3600) // 4 hours
                } else {
                    Duration::from_secs(1 * 3600) // 1 hour
                };
                Some(base_duration)
            }
            _ => None,
        }
    }

    fn get_additional_requirements(&self, verdict: &AccessVerdict, trust_score: f64) -> Vec<String> {
        let mut requirements = Vec::new();

        match verdict {
            AccessVerdict::Challenge => {
                requirements.push("Multi-factor authentication required".to_string());
                if trust_score < 0.5 {
                    requirements.push("Manager approval required".to_string());
                }
            }
            AccessVerdict::Monitor => {
                requirements.push("Enhanced logging enabled".to_string());
                requirements.push("Activity monitoring increased".to_string());
            }
            _ => {}
        }

        requirements
    }

    async fn create_or_update_session(
        &self,
        request: &AccessRequest,
        user: &User,
        device: &Device,
        trust_score: f64,
    ) -> Result<()> {
        let trust_level = if trust_score >= 0.9 {
            TrustLevel::Verified
        } else if trust_score >= 0.7 {
            TrustLevel::High
        } else if trust_score >= 0.5 {
            TrustLevel::Medium
        } else if trust_score >= 0.3 {
            TrustLevel::Low
        } else {
            TrustLevel::Untrusted
        };

        // Check for existing session
        let existing_session = self.sessions
            .iter()
            .find(|entry| {
                let session = entry.value();
                session.user_id == request.user_id && 
                session.device_id == request.device_id &&
                session.expires_at > Utc::now()
            });

        if let Some(session_entry) = existing_session {
            // Update existing session
            let session_id = session_entry.key().clone();
            if let Some(mut session) = self.sessions.get_mut(&session_id) {
                session.last_activity = Utc::now();
                session.access_count += 1;
                session.trust_level = trust_level;
            }
        } else {
            // Create new session
            let session_id = Uuid::new_v4();
            let duration = self.calculate_session_duration(&AccessVerdict::Allow, trust_score)
                .unwrap_or(Duration::from_secs(3600));

            let session = ZeroTrustSession {
                id: session_id,
                user_id: request.user_id,
                device_id: request.device_id,
                trust_level: trust_level.clone(),
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::from_std(duration)?,
                last_activity: Utc::now(),
                access_count: 1,
                continuous_verification: trust_score < 0.7,
            };

            self.sessions.insert(session_id, session);

            // Update metrics
            ACTIVE_SESSIONS
                .with_label_values(&[&format!("{:?}", trust_level)])
                .inc();
        }

        Ok(())
    }

    pub async fn register_device(&self, device: Device) -> Result<Uuid> {
        let device_id = device.id;
        self.devices.insert(device_id, device);
        
        info!(device_id = %device_id, "Device registered in zero trust system");
        Ok(device_id)
    }

    pub async fn register_user(&self, user: User) -> Result<Uuid> {
        let user_id = user.id;
        self.users.insert(user_id, user);
        
        info!(user_id = %user_id, "User registered in zero trust system");
        Ok(user_id)
    }

    pub async fn add_policy(&self, policy: PolicyRule) -> Result<Uuid> {
        let policy_id = policy.id;
        self.policies.insert(policy_id, policy);
        
        info!(policy_id = %policy_id, "Zero trust policy added");
        Ok(policy_id)
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<()> {
        let now = Utc::now();
        let mut expired_sessions = Vec::new();

        for entry in self.sessions.iter() {
            if entry.value().expires_at <= now {
                expired_sessions.push(*entry.key());
            }
        }

        for session_id in expired_sessions {
            if let Some((_, session)) = self.sessions.remove(&session_id) {
                ACTIVE_SESSIONS
                    .with_label_values(&[&format!("{:?}", session.trust_level)])
                    .dec();
                
                info!(session_id = %session_id, "Zero trust session expired");
            }
        }

        Ok(())
    }
}

impl RiskEngine {
    fn new() -> Self {
        Self {
            device_risks: Arc::new(DashMap::new()),
            user_risks: Arc::new(DashMap::new()),
            ip_reputation: Arc::new(DashMap::new()),
        }
    }

    pub fn update_device_risk(&self, device_id: Uuid, risk_score: f64) {
        self.device_risks.insert(device_id, risk_score);
    }

    pub fn update_user_risk(&self, user_id: Uuid, risk_score: f64) {
        self.user_risks.insert(user_id, risk_score);
    }

    pub fn update_ip_reputation(&self, ip: IpAddr, reputation: f64) {
        self.ip_reputation.insert(ip, reputation);
    }
}

// REST API Handlers
async fn evaluate_access(
    State(engine): State<ZeroTrustEngine>,
    Json(request): Json<AccessRequest>,
) -> Result<Json<AccessDecision>, StatusCode> {
    match engine.evaluate_access(request).await {
        Ok(decision) => Ok(Json(decision)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn register_device(
    State(engine): State<ZeroTrustEngine>,
    Json(device): Json<Device>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    match engine.register_device(device).await {
        Ok(device_id) => Ok(Json(HashMap::from([
            ("device_id".to_string(), device_id.to_string()),
            ("status".to_string(), "registered".to_string()),
        ]))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn register_user(
    State(engine): State<ZeroTrustEngine>,
    Json(user): Json<User>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    match engine.register_user(user).await {
        Ok(user_id) => Ok(Json(HashMap::from([
            ("user_id".to_string(), user_id.to_string()),
            ("status".to_string(), "registered".to_string()),
        ]))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn add_policy(
    State(engine): State<ZeroTrustEngine>,
    Json(policy): Json<PolicyRule>,
) -> Result<Json<HashMap<String, String>>, StatusCode> {
    match engine.add_policy(policy).await {
        Ok(policy_id) => Ok(Json(HashMap::from([
            ("policy_id".to_string(), policy_id.to_string()),
            ("status".to_string(), "added".to_string()),
        ]))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn health_check() -> Json<HashMap<String, String>> {
    Json(HashMap::from([
        ("status".to_string(), "healthy".to_string()),
        ("service".to_string(), "zero-trust-engine".to_string()),
        ("timestamp".to_string(), Utc::now().to_rfc3339()),
    ]))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .init();

    info!("Starting Zero Trust Engine");

    let engine = ZeroTrustEngine::new();

    // Start cleanup task
    let cleanup_engine = engine.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            if let Err(e) = cleanup_engine.cleanup_expired_sessions().await {
                error!("Failed to cleanup expired sessions: {}", e);
            }
        }
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/access/evaluate", post(evaluate_access))
        .route("/api/v1/devices", post(register_device))
        .route("/api/v1/users", post(register_user))
        .route("/api/v1/policies", post(add_policy))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    
    info!("Zero Trust Engine listening on http://0.0.0.0:8081");
    
    axum::serve(listener, app).await?;

    Ok(())
}