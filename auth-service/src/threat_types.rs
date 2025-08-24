use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

/// Core threat security event structure representing all authentication and security-related events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatThreatSecurityEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: ThreatSecurityEventType,
    pub severity: ThreatSeverity,
    pub source: String,
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
    pub description: String,
    pub details: HashMap<String, serde_json::Value>,
    pub outcome: EventOutcome,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub risk_score: Option<u8>,
    pub location: Option<GeoLocation>,
    pub device_fingerprint: Option<String>,
    pub mfa_used: bool,
    pub token_binding_info: Option<TokenBindingInfo>,
}

/// Geographic location information for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeoLocation {
    pub country: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub isp: Option<String>,
}

/// Token binding information for session security
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenBindingInfo {
    pub binding_type: String,
    pub binding_value: String,
    pub verification_method: String,
}

/// Types of security events that can occur
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatSecurityEventType {
    AuthenticationAttempt,
    AuthenticationSuccess,
    AuthenticationFailure,
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    MfaChallenge,
    MfaSuccess,
    MfaFailure,
    SessionCreated,
    SessionTerminated,
    PasswordChange,
    AccountLocked,
    SuspiciousActivity,
    RateLimitHit,
    InputValidationFailure,
    UnauthorizedAccess,
    DataAccess,
    ConfigurationChange,
    SecurityPolicyViolation,
}

/// Possible outcomes of security events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventOutcome {
    Success,
    Failure,
    Blocked,
    Timeout,
    Error,
    Suspicious,
}

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Comprehensive threat signature representing detected threats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSignature {
    pub threat_id: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub indicators: Vec<ThreatIndicator>,
    pub affected_entities: HashSet<String>,
    pub source_ips: HashSet<IpAddr>,
    pub risk_score: u8,
    pub mitigation_actions: Vec<MitigationAction>,
    pub related_events: Vec<String>,
    pub attack_phase: AttackPhase,
    pub campaign_id: Option<String>,
    pub false_positive_probability: f64,
    pub context: ThreatContext,
}

/// Types of threats that can be detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ThreatType {
    CredentialStuffing,
    AccountTakeover,
    BruteForce,
    SessionHijacking,
    BehavioralAnomaly,
    SuspiciousLocation,
    DeviceAnomaly,
    TimePatternAnomaly,
    RateLimitAbuse,
    TokenTheft,
    PrivilegeEscalation,
    DataExfiltration,
    InsiderThreat,
    AdvancedPersistentThreat,
    DenialOfService,
    SqlInjection,
    CrossSiteScripting,
    CommandInjection,
    PathTraversal,
    MaliciousBot,
}

/// Specific threat indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source: String,
    pub tags: HashSet<String>,
}

/// Types of threat indicators
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IndicatorType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    EmailAddress,
    UserAgent,
    JwtToken,
    SessionId,
    DeviceFingerprint,
    BehaviorPattern,
    NetworkPattern,
    TimePattern,
}

/// Available mitigation actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MitigationAction {
    BlockIp { duration_hours: u32 },
    LockAccount { duration_hours: u32 },
    RequireAdditionalAuth,
    RevokeTokens,
    TerminateSessions,
    NotifyUser,
    NotifySecurityTeam,
    IncreaseMonitoring,
    QuarantineDevice,
    RateLimitUser { requests_per_hour: u32 },
    TriggerIncidentResponse,
    LogForensics,
    UpdateSecurityPolicy,
    BanUserAgent,
}

/// Attack kill chain phases
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackPhase {
    Reconnaissance,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

/// Additional threat context information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    pub attack_vector: Option<String>,
    pub targeted_assets: HashSet<String>,
    pub business_impact: BusinessImpact,
    pub regulatory_implications: Vec<String>,
    pub related_cves: Vec<String>,
    pub threat_actor_profile: Option<ThreatActorProfile>,
    pub tactics_techniques_procedures: Vec<String>,
}

/// Business impact assessment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BusinessImpact {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Threat actor profiling information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActorProfile {
    pub actor_type: ActorType,
    pub sophistication_level: SophisticationLevel,
    pub motivations: Vec<ThreatMotivation>,
    pub geographic_origin: Option<String>,
    pub tools_techniques: Vec<String>,
    pub known_campaigns: Vec<String>,
}

/// Types of threat actors
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActorType {
    Unknown,
    Script_kiddie,
    Cybercriminal,
    Insider,
    StateSponsored,
    Terrorist,
    Hacktivist,
    CompetitorEspionage,
}

/// Sophistication levels of attacks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SophisticationLevel {
    Low,
    Medium,
    High,
    Advanced,
    Expert,
}

/// Threat actor motivations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatMotivation {
    Financial,
    Espionage,
    Sabotage,
    Ideology,
    Revenge,
    Curiosity,
    Reputation,
    Chaos,
}

/// User behavioral profile for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorProfile {
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,

    // Time-based patterns
    pub typical_login_hours: Vec<u8>,
    pub typical_days_of_week: Vec<u8>,
    pub login_frequency_pattern: IndexMap<String, u32>,
    pub avg_session_duration_minutes: f64,
    pub session_duration_variance: f64,

    // Location patterns
    pub typical_locations: HashSet<String>,
    pub typical_countries: HashSet<String>,
    pub location_entropy: f64,

    // Device and network patterns
    pub typical_devices: HashSet<String>,
    pub typical_user_agents: HashSet<String>,
    pub typical_ip_ranges: Vec<String>,
    pub device_change_frequency: f64,

    // Behavioral metrics
    pub avg_authentication_attempts: f64,
    pub failed_login_baseline: f64,
    pub mfa_usage_rate: f64,
    pub risk_baseline: f64,
    pub behavior_entropy: f64,

    // Activity patterns
    pub typical_resources_accessed: HashSet<String>,
    pub activity_volume_pattern: Vec<f64>,
    pub request_rate_baseline: f64,

    // Security metrics
    pub security_events_count: u64,
    pub last_security_incident: Option<DateTime<Utc>>,
    pub threat_exposure_score: f64,

    // Machine learning features
    pub ml_feature_vector: Vec<f64>,
    pub anomaly_scores_history: Vec<f64>,
    pub model_version: String,
}

/// Attack pattern representing coordinated threat activities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_id: String,
    pub pattern_name: String,
    pub description: String,
    pub pattern_type: AttackPatternType,
    pub complexity_score: u8,
    pub detection_confidence: f64,
    pub first_observed: DateTime<Utc>,
    pub last_observed: DateTime<Utc>,

    // Pattern characteristics
    pub event_sequence: Vec<ThreatSecurityEventType>,
    pub timing_constraints: Vec<TimingConstraint>,
    pub entity_relationships: Vec<EntityRelationship>,
    pub statistical_signatures: Vec<StatisticalSignature>,

    // Impact and response
    pub potential_impact: BusinessImpact,
    pub recommended_responses: Vec<MitigationAction>,
    pub false_positive_rate: f64,
    pub related_patterns: Vec<String>,
}

/// Types of attack patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttackPatternType {
    Sequential,
    Parallel,
    Cyclical,
    Randomized,
    Adaptive,
    MultiStage,
    LowAndSlow,
    BurstPattern,
    DistributedPattern,
}

/// Timing constraints for pattern matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConstraint {
    pub constraint_type: TimingConstraintType,
    pub min_duration_seconds: Option<u64>,
    pub max_duration_seconds: Option<u64>,
    pub frequency_threshold: Option<f64>,
}

/// Types of timing constraints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimingConstraintType {
    MinInterval,
    MaxInterval,
    Frequency,
    Periodicity,
    BurstDetection,
}

/// Relationships between entities in attack patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRelationship {
    pub relationship_type: RelationshipType,
    pub entity_a: String,
    pub entity_b: String,
    pub strength: f64,
    pub temporal_correlation: f64,
}

/// Types of entity relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationshipType {
    SameUser,
    SameIp,
    SameSession,
    SameDevice,
    SameLocation,
    TemporalProximity,
    BehavioralSimilarity,
    NetworkProximity,
}

/// Statistical signatures for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalSignature {
    pub metric_name: String,
    pub expected_value: f64,
    pub variance: f64,
    pub distribution_type: DistributionType,
    pub confidence_interval: (f64, f64),
    pub significance_threshold: f64,
}

/// Statistical distribution types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DistributionType {
    Normal,
    Exponential,
    Poisson,
    Uniform,
    LogNormal,
    Weibull,
    Binomial,
}

/// Response plan for automated threat mitigation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponsePlan {
    pub plan_id: String,
    pub threat_id: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub status: ResponseStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub execution_start: Option<DateTime<Utc>>,
    pub execution_end: Option<DateTime<Utc>>,

    // Response configuration
    pub auto_execute: bool,
    pub requires_approval: bool,
    pub approval_timeout_minutes: u32,
    pub escalation_rules: Vec<EscalationRule>,

    // Actions and results
    pub planned_actions: Vec<PlannedAction>,
    pub executed_actions: Vec<ExecutedAction>,
    pub failed_actions: Vec<FailedAction>,

    // Monitoring and verification
    pub success_criteria: Vec<SuccessCriterion>,
    pub rollback_plan: Option<RollbackPlan>,
    pub monitoring_duration_hours: u32,
}

/// Status of threat response execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseStatus {
    Planned,
    PendingApproval,
    Approved,
    Executing,
    Completed,
    Failed,
    Cancelled,
    RolledBack,
}

/// Escalation rules for response plans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub trigger_condition: EscalationTrigger,
    pub escalation_action: EscalationAction,
    pub delay_minutes: u32,
    pub max_escalations: u8,
}

/// Conditions that trigger escalation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EscalationTrigger {
    TimeoutReached,
    ActionFailed,
    ThreatSeverityIncreased,
    ManualTrigger,
    AutomaticFailover,
}

/// Actions to take during escalation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EscalationAction {
    NotifyManager,
    NotifySecurityTeam,
    NotifyIncidentResponse,
    ActivateEmergencyProtocol,
    RequestManualIntervention,
    ExecuteFailoverPlan,
}

/// Planned actions in response plans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub action_id: String,
    pub action_type: MitigationAction,
    pub priority: u8,
    pub dependencies: Vec<String>,
    pub timeout_minutes: u32,
    pub retry_count: u8,
    pub parameters: HashMap<String, serde_json::Value>,
}

/// Record of executed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutedAction {
    pub action_id: String,
    pub execution_time: DateTime<Utc>,
    pub duration_seconds: u64,
    pub result: ActionResult,
    pub output: Option<String>,
    pub metrics: HashMap<String, f64>,
}

/// Record of failed actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedAction {
    pub action_id: String,
    pub failure_time: DateTime<Utc>,
    pub error_message: String,
    pub retry_count: u8,
    pub should_retry: bool,
    pub rollback_required: bool,
}

/// Results of action execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionResult {
    Success,
    PartialSuccess,
    Failed,
    Timeout,
    Cancelled,
    RequiresManualIntervention,
}

/// Success criteria for response verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriterion {
    pub criterion_type: SuccessCriterionType,
    pub metric_name: String,
    pub expected_value: f64,
    pub tolerance: f64,
    pub verification_method: VerificationMethod,
}

/// Types of success criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuccessCriterionType {
    MetricThreshold,
    EventCount,
    TimeBasedMetric,
    BooleanCheck,
    ExternalVerification,
}

/// Methods for verifying success
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationMethod {
    PrometheusQuery,
    DatabaseQuery,
    ExternalApiCall,
    LogAnalysis,
    ManualVerification,
}

/// Rollback plans for failed responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackPlan {
    pub rollback_actions: Vec<PlannedAction>,
    pub rollback_timeout_minutes: u32,
    pub verification_steps: Vec<SuccessCriterion>,
    pub emergency_contacts: Vec<String>,
}

impl ThreatSecurityEvent {
    /// Create a new security event with minimal required fields
    pub fn new(
        event_type: ThreatSecurityEventType,
        severity: ThreatSeverity,
        source: String,
        description: String,
        outcome: EventOutcome,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            severity,
            source,
            client_id: None,
            user_id: None,
            ip_address: None,
            user_agent: None,
            request_id: None,
            session_id: None,
            description,
            details: HashMap::new(),
            outcome,
            resource: None,
            action: None,
            risk_score: None,
            location: None,
            device_fingerprint: None,
            mfa_used: false,
            token_binding_info: None,
        }
    }

    /// Calculate risk score based on event characteristics
    pub fn calculate_risk_score(&mut self) {
        let mut score = 0u8;

        // Base score by event type
        score += match self.event_type {
            ThreatSecurityEventType::AuthenticationFailure => 20,
            ThreatSecurityEventType::MfaFailure => 30,
            ThreatSecurityEventType::SuspiciousActivity => 40,
            ThreatSecurityEventType::UnauthorizedAccess => 60,
            ThreatSecurityEventType::SecurityPolicyViolation => 50,
            ThreatSecurityEventType::AuthenticationSuccess => 5,
            _ => 10,
        };

        // Severity multiplier
        let severity_multiplier = match self.severity {
            ThreatSeverity::Info => 0.5,
            ThreatSeverity::Low => 0.8,
            ThreatSeverity::Medium => 1.0,
            ThreatSeverity::High => 1.5,
            ThreatSeverity::Critical => 2.0,
        };

        // Outcome impact
        let outcome_modifier = match self.outcome {
            EventOutcome::Success => {
                if matches!(self.event_type, ThreatSecurityEventType::AuthenticationSuccess) {
                    -10
                } else {
                    0
                }
            }
            EventOutcome::Failure => 15,
            EventOutcome::Blocked => 10,
            EventOutcome::Suspicious => 25,
            EventOutcome::Timeout | EventOutcome::Error => 20,
        };

        // MFA usage bonus
        let mfa_modifier = if self.mfa_used { -5 } else { 10 };

        let final_score =
            ((score as f64 * severity_multiplier) as i16 + outcome_modifier + mfa_modifier)
                .max(0)
                .min(100) as u8;

        self.risk_score = Some(final_score);
    }

    /// Check if event represents a security failure
    pub fn is_security_failure(&self) -> bool {
        matches!(
            self.event_type,
            ThreatSecurityEventType::AuthenticationFailure
                | ThreatSecurityEventType::MfaFailure
                | ThreatSecurityEventType::UnauthorizedAccess
                | ThreatSecurityEventType::SecurityPolicyViolation
                | ThreatSecurityEventType::SuspiciousActivity
        ) || matches!(
            self.outcome,
            EventOutcome::Failure | EventOutcome::Blocked | EventOutcome::Suspicious
        )
    }

    /// Get time window for threat correlation (in minutes)
    pub fn get_correlation_window(&self) -> u64 {
        match self.event_type {
            ThreatSecurityEventType::AuthenticationFailure => 15,
            ThreatSecurityEventType::MfaFailure => 10,
            ThreatSecurityEventType::SuspiciousActivity => 60,
            ThreatSecurityEventType::UnauthorizedAccess => 30,
            _ => 5,
        }
    }
}

impl ThreatSignature {
    /// Create a new threat signature
    pub fn new(threat_type: ThreatType, severity: ThreatSeverity, confidence: f64) -> Self {
        Self {
            threat_id: Uuid::new_v4().to_string(),
            threat_type,
            severity,
            confidence,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            indicators: Vec::new(),
            affected_entities: HashSet::new(),
            source_ips: HashSet::new(),
            risk_score: (confidence * 100.0) as u8,
            mitigation_actions: Vec::new(),
            related_events: Vec::new(),
            attack_phase: AttackPhase::Discovery,
            campaign_id: None,
            false_positive_probability: 0.1,
            context: ThreatContext {
                attack_vector: None,
                targeted_assets: HashSet::new(),
                business_impact: BusinessImpact::Low,
                regulatory_implications: Vec::new(),
                related_cves: Vec::new(),
                threat_actor_profile: None,
                tactics_techniques_procedures: Vec::new(),
            },
        }
    }

    /// Update last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Utc::now();
    }

    /// Add a threat indicator
    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.indicators.push(indicator);
    }

    /// Add affected entity
    pub fn add_affected_entity(&mut self, entity: String) {
        self.affected_entities.insert(entity);
    }

    /// Add source IP
    pub fn add_source_ip(&mut self, ip: IpAddr) {
        self.source_ips.insert(ip);
    }

    /// Check if threat is still active (seen within last hour)
    pub fn is_active(&self) -> bool {
        let now = Utc::now();
        now.signed_duration_since(self.last_seen).num_hours() < 1
    }

    /// Get threat age in hours
    pub fn age_hours(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.first_seen)
            .num_hours()
    }
}

impl UserBehaviorProfile {
    /// Create a new user behavior profile
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            created_at: Utc::now(),
            last_updated: Utc::now(),
            typical_login_hours: Vec::new(),
            typical_days_of_week: Vec::new(),
            login_frequency_pattern: IndexMap::new(),
            avg_session_duration_minutes: 0.0,
            session_duration_variance: 0.0,
            typical_locations: HashSet::new(),
            typical_countries: HashSet::new(),
            location_entropy: 0.0,
            typical_devices: HashSet::new(),
            typical_user_agents: HashSet::new(),
            typical_ip_ranges: Vec::new(),
            device_change_frequency: 0.0,
            avg_authentication_attempts: 1.0,
            failed_login_baseline: 0.0,
            mfa_usage_rate: 0.0,
            risk_baseline: 0.0,
            behavior_entropy: 0.0,
            typical_resources_accessed: HashSet::new(),
            activity_volume_pattern: Vec::new(),
            request_rate_baseline: 0.0,
            security_events_count: 0,
            last_security_incident: None,
            threat_exposure_score: 0.0,
            ml_feature_vector: Vec::new(),
            anomaly_scores_history: Vec::new(),
            model_version: "1.0".to_string(),
        }
    }

    /// Update profile with new security event
    pub fn update_with_event(&mut self, event: &ThreatSecurityEvent) {
        self.last_updated = Utc::now();
        self.security_events_count += 1;

        // Update time patterns
        let hour = event.timestamp.hour() as u8;
        if !self.typical_login_hours.contains(&hour) {
            self.typical_login_hours.push(hour);
        }

        let day_of_week = event.timestamp.weekday().num_days_from_monday() as u8;
        if !self.typical_days_of_week.contains(&day_of_week) {
            self.typical_days_of_week.push(day_of_week);
        }

        // Update location patterns
        if let Some(location) = &event.location {
            self.typical_countries.insert(location.country.clone());
            if let Some(city) = &location.city {
                self.typical_locations.insert(city.clone());
            }
        }

        // Update device patterns
        if let Some(device) = &event.device_fingerprint {
            self.typical_devices.insert(device.clone());
        }

        if let Some(user_agent) = &event.user_agent {
            self.typical_user_agents.insert(user_agent.clone());
        }

        // Update security metrics
        if event.is_security_failure() {
            self.last_security_incident = Some(event.timestamp);
        }

        // Update MFA usage rate
        if event.mfa_used {
            let current_rate = self.mfa_usage_rate;
            let events_with_mfa = (self.security_events_count as f64 * current_rate + 1.0);
            self.mfa_usage_rate = events_with_mfa / self.security_events_count as f64;
        }
    }

    /// Calculate behavior entropy score
    pub fn calculate_behavior_entropy(&mut self) {
        let mut entropy = 0.0;

        // Time entropy
        if !self.typical_login_hours.is_empty() {
            let hour_distribution = self.typical_login_hours.len() as f64 / 24.0;
            entropy += -hour_distribution * hour_distribution.log2();
        }

        // Location entropy
        if !self.typical_locations.is_empty() {
            let location_factor = (self.typical_locations.len() as f64).min(10.0) / 10.0;
            entropy += location_factor;
        }

        // Device entropy
        if !self.typical_devices.is_empty() {
            let device_factor = (self.typical_devices.len() as f64).min(5.0) / 5.0;
            entropy += device_factor;
        }

        self.behavior_entropy = entropy / 3.0; // Normalize to 0-1 range
    }

    /// Check if behavior is suspicious based on entropy and patterns
    pub fn is_behavior_suspicious(&self) -> bool {
        self.behavior_entropy > 0.8
            || self.failed_login_baseline > 5.0
            || self.threat_exposure_score > 0.7
    }

    /// Get profile age in days
    pub fn age_days(&self) -> i64 {
        Utc::now().signed_duration_since(self.created_at).num_days()
    }
}

// Helper functions for threat analysis
impl ThreatType {
    /// Get default severity for threat type
    pub fn default_severity(&self) -> ThreatSeverity {
        match self {
            ThreatType::CredentialStuffing => ThreatSeverity::High,
            ThreatType::AccountTakeover => ThreatSeverity::Critical,
            ThreatType::BruteForce => ThreatSeverity::Medium,
            ThreatType::SessionHijacking => ThreatSeverity::High,
            ThreatType::BehavioralAnomaly => ThreatSeverity::Medium,
            ThreatType::AdvancedPersistentThreat => ThreatSeverity::Critical,
            ThreatType::DataExfiltration => ThreatSeverity::Critical,
            ThreatType::InsiderThreat => ThreatSeverity::High,
            _ => ThreatSeverity::Medium,
        }
    }

    /// Get typical indicators for threat type
    pub fn typical_indicators(&self) -> Vec<IndicatorType> {
        match self {
            ThreatType::CredentialStuffing => vec![
                IndicatorType::IpAddress,
                IndicatorType::UserAgent,
                IndicatorType::BehaviorPattern,
            ],
            ThreatType::AccountTakeover => vec![
                IndicatorType::IpAddress,
                IndicatorType::DeviceFingerprint,
                IndicatorType::BehaviorPattern,
                IndicatorType::TimePattern,
            ],
            ThreatType::SessionHijacking => vec![
                IndicatorType::SessionId,
                IndicatorType::IpAddress,
                IndicatorType::DeviceFingerprint,
            ],
            _ => vec![IndicatorType::BehaviorPattern],
        }
    }
}
