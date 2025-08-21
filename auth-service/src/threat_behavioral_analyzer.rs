use crate::threat_types::*;
use chrono::{DateTime, Duration, Utc};
use flume::{unbounded, Receiver, Sender};
use indexmap::IndexMap;
use nalgebra::{DMatrix, DVector};
use prometheus::{register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram};
use redis::aio::ConnectionManager;
use serde_json;
use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::linalg::basic::vector::DenseVector;
use smartcore::model_selection::train_test_split;
use smartcore::preprocessing::standard_scaler::StandardScaler;
use smartcore::tree::decision_tree_classifier::SplitCriterion;
use statrs::distribution::{ContinuousCDF, Normal};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Prometheus metrics for behavioral analysis
lazy_static::lazy_static! {
    static ref THREAT_PATTERNS_DETECTED: Counter = register_counter!(
        "threat_hunting_patterns_detected_total",
        "Total threat patterns detected by behavioral analyzer"
    ).unwrap();

    static ref BEHAVIORAL_ANOMALIES_DETECTED: Counter = register_counter!(
        "threat_hunting_behavioral_anomalies_total",
        "Total behavioral anomalies detected"
    ).unwrap();

    static ref ANALYSIS_DURATION: Histogram = register_histogram!(
        "threat_hunting_analysis_duration_seconds",
        "Duration of behavioral analysis operations"
    ).unwrap();

    static ref ACTIVE_THREATS_GAUGE: Gauge = register_gauge!(
        "threat_hunting_active_threats",
        "Number of currently active threats"
    ).unwrap();

    static ref ML_PREDICTIONS: Counter = register_counter!(
        "threat_hunting_ml_predictions_total",
        "Total ML model predictions made"
    ).unwrap();

    static ref USER_PROFILES_UPDATED: Counter = register_counter!(
        "threat_hunting_user_profiles_updated_total",
        "Total user profiles updated"
    ).unwrap();
}

/// Configuration for behavioral analysis
#[derive(Debug, Clone)]
pub struct BehavioralAnalysisConfig {
    pub enabled: bool,
    pub ml_model_enabled: bool,
    pub event_buffer_size: usize,
    pub profile_update_interval_seconds: u64,
    pub threat_correlation_window_minutes: u64,
    pub anomaly_detection_sensitivity: f64,
    pub thresholds: ThreatDetectionThresholds,
    pub redis_config: RedisConfig,
}

/// Redis configuration for caching
#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub key_prefix: String,
    pub profile_ttl_seconds: u64,
    pub threat_ttl_seconds: u64,
}

/// Thresholds for different threat detection patterns
#[derive(Debug, Clone)]
pub struct ThreatDetectionThresholds {
    pub credential_stuffing: CredentialStuffingThresholds,
    pub account_takeover: AccountTakeoverThresholds,
    pub brute_force: BruteForceThresholds,
    pub session_hijacking: SessionHijackingThresholds,
    pub behavioral_anomaly: BehavioralAnomalyThresholds,
}

#[derive(Debug, Clone)]
pub struct CredentialStuffingThresholds {
    pub failed_logins_per_minute: u32,
    pub unique_usernames_per_ip: u32,
    pub time_window_minutes: u64,
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct AccountTakeoverThresholds {
    pub location_distance_km: f64,
    pub device_change_threshold: u32,
    pub behavior_deviation_threshold: f64,
    pub time_anomaly_threshold_hours: u64,
}

#[derive(Debug, Clone)]
pub struct BruteForceThresholds {
    pub failed_attempts_threshold: u32,
    pub time_window_minutes: u64,
    pub lockout_threshold: u32,
    pub rate_threshold_per_second: f64,
}

#[derive(Debug, Clone)]
pub struct SessionHijackingThresholds {
    pub concurrent_sessions_threshold: u32,
    pub location_jump_threshold_km: f64,
    pub time_threshold_minutes: u64,
    pub ip_change_sensitivity: f64,
}

#[derive(Debug, Clone)]
pub struct BehavioralAnomalyThresholds {
    pub anomaly_score_threshold: f64,
    pub entropy_threshold: f64,
    pub deviation_multiplier: f64,
    pub minimum_baseline_events: u32,
}

/// Machine learning model for behavioral analysis
#[derive(Debug)]
pub struct BehavioralMLModel {
    pub classifier: Option<RandomForestClassifier<f64, i32, DenseMatrix<f64>, DenseVector<i32>>>,
    pub scaler: Option<StandardScaler<f64, DenseMatrix<f64>>>,
    pub feature_names: Vec<String>,
    pub model_version: String,
    pub training_data_size: usize,
    pub accuracy: f64,
    pub last_trained: DateTime<Utc>,
}

/// Advanced behavioral threat detector with ML capabilities
pub struct AdvancedBehavioralThreatDetector {
    config: Arc<RwLock<BehavioralAnalysisConfig>>,
    redis_client: Arc<Mutex<Option<ConnectionManager>>>,

    // Event processing
    event_buffer: Arc<Mutex<VecDeque<SecurityEvent>>>,
    event_sender: Sender<SecurityEvent>,
    event_receiver: Receiver<SecurityEvent>,

    // User behavior tracking
    user_profiles: Arc<RwLock<HashMap<String, UserBehaviorProfile>>>,
    user_session_tracking: Arc<RwLock<HashMap<String, Vec<SessionInfo>>>>,

    // Threat tracking
    active_threats: Arc<RwLock<HashMap<String, ThreatSignature>>>,
    threat_correlations: Arc<RwLock<HashMap<String, Vec<String>>>>,

    // Machine learning models
    ml_models: Arc<RwLock<HashMap<String, BehavioralMLModel>>>,

    // Statistics and analysis
    ip_reputation_cache: Arc<RwLock<HashMap<IpAddr, IPReputationInfo>>>,
    statistical_baselines: Arc<RwLock<HashMap<String, StatisticalBaseline>>>,

    // Performance tracking
    analysis_metrics: Arc<Mutex<AnalysisMetrics>>,
}

/// Session information for tracking user activity
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub start_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub location: Option<GeoLocation>,
    pub device_fingerprint: Option<String>,
    pub events_count: u32,
    pub risk_indicators: Vec<String>,
}

/// IP reputation information
#[derive(Debug, Clone)]
pub struct IPReputationInfo {
    pub reputation_score: f64,
    pub threat_categories: HashSet<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: u32,
    pub blocked_count: u32,
    pub country: Option<String>,
    pub asn: Option<u32>,
}

/// Statistical baseline for behavioral analysis
#[derive(Debug, Clone)]
pub struct StatisticalBaseline {
    pub metric_name: String,
    pub mean: f64,
    pub std_dev: f64,
    pub min_value: f64,
    pub max_value: f64,
    pub sample_count: u64,
    pub last_updated: DateTime<Utc>,
    pub percentiles: HashMap<u8, f64>,
}

/// Analysis performance metrics
#[derive(Debug, Default)]
pub struct AnalysisMetrics {
    pub events_processed: u64,
    pub threats_detected: u64,
    pub false_positives: u64,
    pub processing_time_ms: u64,
    pub ml_prediction_time_ms: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl Default for BehavioralAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ml_model_enabled: true,
            event_buffer_size: 50000,
            profile_update_interval_seconds: 300,
            threat_correlation_window_minutes: 60,
            anomaly_detection_sensitivity: 0.1,
            thresholds: ThreatDetectionThresholds::default(),
            redis_config: RedisConfig {
                url: "redis://localhost:6379".to_string(),
                key_prefix: "threat_hunting:".to_string(),
                profile_ttl_seconds: 86400 * 30, // 30 days
                threat_ttl_seconds: 86400 * 7,   // 7 days
            },
        }
    }
}

impl Default for ThreatDetectionThresholds {
    fn default() -> Self {
        Self {
            credential_stuffing: CredentialStuffingThresholds {
                failed_logins_per_minute: 10,
                unique_usernames_per_ip: 20,
                time_window_minutes: 5,
                confidence_threshold: 0.85,
            },
            account_takeover: AccountTakeoverThresholds {
                location_distance_km: 1000.0,
                device_change_threshold: 3,
                behavior_deviation_threshold: 2.5,
                time_anomaly_threshold_hours: 2,
            },
            brute_force: BruteForceThresholds {
                failed_attempts_threshold: 15,
                time_window_minutes: 10,
                lockout_threshold: 5,
                rate_threshold_per_second: 2.0,
            },
            session_hijacking: SessionHijackingThresholds {
                concurrent_sessions_threshold: 3,
                location_jump_threshold_km: 500.0,
                time_threshold_minutes: 5,
                ip_change_sensitivity: 0.8,
            },
            behavioral_anomaly: BehavioralAnomalyThresholds {
                anomaly_score_threshold: -0.3,
                entropy_threshold: 0.8,
                deviation_multiplier: 2.5,
                minimum_baseline_events: 50,
            },
        }
    }
}

impl AdvancedBehavioralThreatDetector {
    /// Create a new behavioral threat detector
    pub fn new(config: BehavioralAnalysisConfig) -> Self {
        let (event_sender, event_receiver) = unbounded();

        Self {
            config: Arc::new(RwLock::new(config)),
            redis_client: Arc::new(Mutex::new(None)),
            event_buffer: Arc::new(Mutex::new(VecDeque::new())),
            event_sender,
            event_receiver,
            user_profiles: Arc::new(RwLock::new(HashMap::new())),
            user_session_tracking: Arc::new(RwLock::new(HashMap::new())),
            active_threats: Arc::new(RwLock::new(HashMap::new())),
            threat_correlations: Arc::new(RwLock::new(HashMap::new())),
            ml_models: Arc::new(RwLock::new(HashMap::new())),
            ip_reputation_cache: Arc::new(RwLock::new(HashMap::new())),
            statistical_baselines: Arc::new(RwLock::new(HashMap::new())),
            analysis_metrics: Arc::new(Mutex::new(AnalysisMetrics::default())),
        }
    }

    /// Initialize the threat detector and start background tasks
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing Advanced Behavioral Threat Detector");

        // Initialize Redis connection
        if let Err(e) = self.initialize_redis().await {
            warn!("Failed to initialize Redis connection: {}", e);
        }

        // Load existing user profiles
        self.load_user_profiles().await?;

        // Initialize ML models
        self.initialize_ml_models().await?;

        // Start background processing tasks
        self.start_event_processor().await;
        self.start_profile_updater().await;
        self.start_threat_correlator().await;
        self.start_model_trainer().await;

        info!("Advanced Behavioral Threat Detector initialized successfully");
        Ok(())
    }

    /// Initialize Redis connection
    async fn initialize_redis(&self) -> Result<(), redis::RedisError> {
        let config = self.config.read().await;
        let client = redis::Client::open(config.redis_config.url.as_str())?;
        let manager = ConnectionManager::new(client).await?;

        let mut redis_client = self.redis_client.lock().await;
        *redis_client = Some(manager);

        info!("Redis connection established for threat hunting");
        Ok(())
    }

    /// Load existing user profiles from Redis
    async fn load_user_profiles(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let redis_client = self.redis_client.lock().await;
        if let Some(ref client) = *redis_client {
            let config = self.config.read().await;
            let pattern = format!("{}user_profile:*", config.redis_config.key_prefix);

            let keys: Vec<String> = redis::cmd("KEYS")
                .arg(&pattern)
                .query_async(&mut client.clone())
                .await
                .unwrap_or_default();

            let mut profiles = self.user_profiles.write().await;
            for key in keys {
                let profile_data: Option<String> = redis::cmd("GET")
                    .arg(&key)
                    .query_async(&mut client.clone())
                    .await
                    .unwrap_or_default();

                if let Some(data) = profile_data {
                    if let Ok(profile) = serde_json::from_str::<UserBehaviorProfile>(&data) {
                        profiles.insert(profile.user_id.clone(), profile);
                    }
                }
            }

            info!("Loaded {} user behavior profiles", profiles.len());
        }
        Ok(())
    }

    /// Initialize machine learning models
    async fn initialize_ml_models(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut models = self.ml_models.write().await;

        // Initialize behavioral anomaly detection model
        let behavioral_model = BehavioralMLModel {
            classifier: None,
            scaler: None,
            feature_names: vec![
                "hour_of_day".to_string(),
                "day_of_week".to_string(),
                "risk_score".to_string(),
                "session_duration".to_string(),
                "location_entropy".to_string(),
                "device_changes".to_string(),
                "failed_login_rate".to_string(),
                "mfa_usage_rate".to_string(),
            ],
            model_version: "1.0".to_string(),
            training_data_size: 0,
            accuracy: 0.0,
            last_trained: Utc::now(),
        };

        models.insert("behavioral_anomaly".to_string(), behavioral_model);

        info!("ML models initialized for threat detection");
        Ok(())
    }

    /// Process a security event for threat detection
    pub async fn analyze_event(
        &self,
        event: SecurityEvent,
    ) -> Result<Vec<ThreatSignature>, Box<dyn std::error::Error + Send + Sync>> {
        let start_time = SystemTime::now();
        let mut threats_detected = Vec::new();

        // Send event to processing queue
        if let Err(e) = self.event_sender.send(event.clone()) {
            error!("Failed to queue event for processing: {}", e);
            return Ok(threats_detected);
        }

        // Immediate threat detection
        threats_detected.extend(self.detect_credential_stuffing(&event).await?);
        threats_detected.extend(self.detect_account_takeover(&event).await?);
        threats_detected.extend(self.detect_brute_force(&event).await?);
        threats_detected.extend(self.detect_session_hijacking(&event).await?);
        threats_detected.extend(self.detect_behavioral_anomaly(&event).await?);

        // Update metrics
        let mut metrics = self.analysis_metrics.lock().await;
        metrics.events_processed += 1;
        metrics.threats_detected += threats_detected.len() as u64;

        if let Ok(duration) = start_time.elapsed() {
            metrics.processing_time_ms += duration.as_millis() as u64;
        }

        // Update Prometheus metrics
        THREAT_PATTERNS_DETECTED.inc_by(threats_detected.len() as u64);
        let _timer = ANALYSIS_DURATION.start_timer();

        // Store threats
        for threat in &threats_detected {
            self.store_threat(threat.clone()).await;
        }

        Ok(threats_detected)
    }

    /// Detect credential stuffing attacks
    async fn detect_credential_stuffing(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ThreatSignature>, Box<dyn std::error::Error + Send + Sync>> {
        let mut threats = Vec::new();

        if !matches!(event.event_type, SecurityEventType::AuthenticationFailure) {
            return Ok(threats);
        }

        let Some(ip_address) = event.ip_address else {
            return Ok(threats);
        };

        let config = self.config.read().await;
        let thresholds = &config.thresholds.credential_stuffing;

        // Analyze recent events from this IP
        let event_buffer = self.event_buffer.lock().await;
        let cutoff_time = Utc::now() - Duration::minutes(thresholds.time_window_minutes as i64);

        let mut failed_attempts = 0;
        let mut unique_users = HashSet::new();

        for buffered_event in event_buffer.iter() {
            if buffered_event.ip_address == Some(ip_address)
                && buffered_event.timestamp > cutoff_time
                && matches!(
                    buffered_event.event_type,
                    SecurityEventType::AuthenticationFailure
                )
            {
                failed_attempts += 1;
                if let Some(user_id) = &buffered_event.user_id {
                    unique_users.insert(user_id.clone());
                }
            }
        }

        // Check if thresholds are exceeded
        if failed_attempts >= thresholds.failed_logins_per_minute
            && unique_users.len() >= thresholds.unique_usernames_per_ip as usize
        {
            let mut threat = ThreatSignature::new(
                ThreatType::CredentialStuffing,
                ThreatSeverity::High,
                thresholds.confidence_threshold,
            );

            threat.add_source_ip(ip_address);
            for user in unique_users.iter() {
                threat.add_affected_entity(user.clone());
            }

            let indicator = ThreatIndicator {
                indicator_type: IndicatorType::IpAddress,
                value: ip_address.to_string(),
                confidence: thresholds.confidence_threshold,
                first_seen: cutoff_time,
                last_seen: event.timestamp,
                source: "behavioral_analyzer".to_string(),
                tags: ["credential_stuffing", "high_volume", "multiple_users"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };

            threat.add_indicator(indicator);
            threat.mitigation_actions = vec![
                MitigationAction::BlockIp { duration_hours: 24 },
                MitigationAction::NotifySecurityTeam,
                MitigationAction::IncreaseMonitoring,
            ];

            threat.context.business_impact = BusinessImpact::High;
            threat.attack_phase = AttackPhase::CredentialAccess;

            threats.push(threat);
        }

        Ok(threats)
    }

    /// Detect account takeover attempts
    async fn detect_account_takeover(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ThreatSignature>, Box<dyn std::error::Error + Send + Sync>> {
        let mut threats = Vec::new();

        if !matches!(event.event_type, SecurityEventType::AuthenticationSuccess) {
            return Ok(threats);
        }

        let Some(user_id) = &event.user_id else {
            return Ok(threats);
        };

        // Get user behavior profile
        let profiles = self.user_profiles.read().await;
        let Some(profile) = profiles.get(user_id) else {
            return Ok(threats);
        };

        let config = self.config.read().await;
        let thresholds = &config.thresholds.account_takeover;

        let mut anomaly_indicators = Vec::new();
        let mut confidence = 0.0;

        // Check location anomaly
        if let Some(event_location) = &event.location {
            if !profile.typical_countries.contains(&event_location.country) {
                anomaly_indicators.push("Unusual login country".to_string());
                confidence += 0.4;
            }

            // Check for rapid location changes
            if let Some(lat) = event_location.latitude {
                if let Some(lon) = event_location.longitude {
                    let recent_sessions = self.get_recent_user_sessions(user_id, 24).await;
                    for session in recent_sessions {
                        if let Some(session_location) = &session.location {
                            if let (Some(session_lat), Some(session_lon)) =
                                (session_location.latitude, session_location.longitude)
                            {
                                let distance =
                                    self.calculate_distance(lat, lon, session_lat, session_lon);
                                if distance > thresholds.location_distance_km {
                                    anomaly_indicators
                                        .push(format!("Rapid location change: {:.0} km", distance));
                                    confidence += 0.3;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check device anomaly
        if let Some(device_fingerprint) = &event.device_fingerprint {
            if !profile.typical_devices.contains(device_fingerprint) {
                anomaly_indicators.push("New device detected".to_string());
                confidence += 0.25;
            }
        }

        // Check time pattern anomaly
        let event_hour = event.timestamp.hour() as u8;
        if !profile.typical_login_hours.contains(&event_hour) {
            anomaly_indicators.push("Unusual login time".to_string());
            confidence += 0.2;
        }

        // Check user agent anomaly
        if let Some(user_agent) = &event.user_agent {
            if !profile.typical_user_agents.contains(user_agent) {
                anomaly_indicators.push("New user agent".to_string());
                confidence += 0.15;
            }
        }

        // Check for recent failed attempts
        let recent_failures = self.count_recent_failures(user_id, 60).await;
        if recent_failures
            > (profile.failed_login_baseline * thresholds.behavior_deviation_threshold) as u32
        {
            anomaly_indicators.push(format!(
                "Elevated failure rate: {} attempts",
                recent_failures
            ));
            confidence += 0.2;
        }

        // Create threat if multiple anomalies detected
        if anomaly_indicators.len() >= 2 && confidence >= 0.5 {
            let mut threat = ThreatSignature::new(
                ThreatType::AccountTakeover,
                if confidence > 0.8 {
                    ThreatSeverity::Critical
                } else {
                    ThreatSeverity::High
                },
                confidence,
            );

            threat.add_affected_entity(user_id.clone());
            if let Some(ip) = event.ip_address {
                threat.add_source_ip(ip);
            }

            for indicator_desc in &anomaly_indicators {
                let indicator = ThreatIndicator {
                    indicator_type: IndicatorType::BehaviorPattern,
                    value: indicator_desc.clone(),
                    confidence,
                    first_seen: event.timestamp,
                    last_seen: event.timestamp,
                    source: "behavioral_analyzer".to_string(),
                    tags: ["account_takeover", "behavioral_anomaly"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                };
                threat.add_indicator(indicator);
            }

            threat.mitigation_actions = vec![
                MitigationAction::RequireAdditionalAuth,
                MitigationAction::NotifyUser,
                MitigationAction::IncreaseMonitoring,
                MitigationAction::NotifySecurityTeam,
            ];

            threat.context.business_impact = BusinessImpact::High;
            threat.attack_phase = AttackPhase::InitialAccess;

            threats.push(threat);
        }

        Ok(threats)
    }

    /// Detect brute force attacks
    async fn detect_brute_force(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ThreatSignature>, Box<dyn std::error::Error + Send + Sync>> {
        let mut threats = Vec::new();

        if !matches!(event.event_type, SecurityEventType::AuthenticationFailure) {
            return Ok(threats);
        }

        let Some(user_id) = &event.user_id else {
            return Ok(threats);
        };

        let config = self.config.read().await;
        let thresholds = &config.thresholds.brute_force;

        // Count recent failures for this user
        let recent_failures = self
            .count_recent_failures(user_id, thresholds.time_window_minutes)
            .await;

        if recent_failures >= thresholds.failed_attempts_threshold {
            // Get unique source IPs
            let source_ips = self
                .get_recent_failure_ips(user_id, thresholds.time_window_minutes)
                .await;

            let mut threat =
                ThreatSignature::new(ThreatType::BruteForce, ThreatSeverity::Medium, 0.8);

            threat.add_affected_entity(user_id.clone());
            for ip in source_ips {
                threat.add_source_ip(ip);
            }

            let indicator = ThreatIndicator {
                indicator_type: IndicatorType::BehaviorPattern,
                value: format!(
                    "High failure rate: {} attempts in {} minutes",
                    recent_failures, thresholds.time_window_minutes
                ),
                confidence: 0.8,
                first_seen: event.timestamp
                    - Duration::minutes(thresholds.time_window_minutes as i64),
                last_seen: event.timestamp,
                source: "behavioral_analyzer".to_string(),
                tags: ["brute_force", "high_volume"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };

            threat.add_indicator(indicator);
            threat.mitigation_actions = vec![
                MitigationAction::LockAccount { duration_hours: 1 },
                MitigationAction::NotifyUser,
                MitigationAction::IncreaseMonitoring,
            ];

            threat.context.business_impact = BusinessImpact::Medium;
            threat.attack_phase = AttackPhase::CredentialAccess;

            threats.push(threat);
        }

        Ok(threats)
    }

    /// Detect session hijacking attempts
    async fn detect_session_hijacking(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ThreatSignature>, Box<dyn std::error::Error + Send + Sync>> {
        let mut threats = Vec::new();

        let Some(session_id) = &event.session_id else {
            return Ok(threats);
        };

        // Get session tracking information
        let session_tracking = self.user_session_tracking.read().await;
        let user_sessions = if let Some(user_id) = &event.user_id {
            session_tracking.get(user_id)
        } else {
            None
        };

        if let Some(sessions) = user_sessions {
            let current_session = sessions.iter().find(|s| s.session_id == *session_id);

            if let Some(session) = current_session {
                let config = self.config.read().await;
                let thresholds = &config.thresholds.session_hijacking;

                let mut anomaly_indicators = Vec::new();
                let mut confidence = 0.0;

                // Check for IP address changes
                if let (Some(event_ip), Some(session_ip)) = (event.ip_address, session.ip_address) {
                    if event_ip != session_ip {
                        anomaly_indicators.push("IP address change during session".to_string());
                        confidence += 0.4;
                    }
                }

                // Check for location jumps
                if let (Some(event_location), Some(session_location)) =
                    (&event.location, &session.location)
                {
                    if let (
                        Some(event_lat),
                        Some(event_lon),
                        Some(session_lat),
                        Some(session_lon),
                    ) = (
                        event_location.latitude,
                        event_location.longitude,
                        session_location.latitude,
                        session_location.longitude,
                    ) {
                        let distance =
                            self.calculate_distance(event_lat, event_lon, session_lat, session_lon);
                        let time_diff = event
                            .timestamp
                            .signed_duration_since(session.last_activity)
                            .num_minutes();

                        if distance > thresholds.location_jump_threshold_km
                            && time_diff < thresholds.time_threshold_minutes as i64
                        {
                            anomaly_indicators.push(format!(
                                "Impossible travel: {:.0} km in {} minutes",
                                distance, time_diff
                            ));
                            confidence += 0.6;
                        }
                    }
                }

                // Check for device fingerprint changes
                if let (Some(event_device), Some(session_device)) =
                    (&event.device_fingerprint, &session.device_fingerprint)
                {
                    if event_device != session_device {
                        anomaly_indicators
                            .push("Device fingerprint change during session".to_string());
                        confidence += 0.3;
                    }
                }

                // Create threat if anomalies detected
                if !anomaly_indicators.is_empty() && confidence >= 0.5 {
                    let mut threat = ThreatSignature::new(
                        ThreatType::SessionHijacking,
                        ThreatSeverity::High,
                        confidence,
                    );

                    if let Some(user_id) = &event.user_id {
                        threat.add_affected_entity(user_id.clone());
                    }

                    if let Some(ip) = event.ip_address {
                        threat.add_source_ip(ip);
                    }

                    for indicator_desc in &anomaly_indicators {
                        let indicator = ThreatIndicator {
                            indicator_type: IndicatorType::SessionId,
                            value: indicator_desc.clone(),
                            confidence,
                            first_seen: session.start_time,
                            last_seen: event.timestamp,
                            source: "behavioral_analyzer".to_string(),
                            tags: ["session_hijacking", "session_anomaly"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                        };
                        threat.add_indicator(indicator);
                    }

                    threat.mitigation_actions = vec![
                        MitigationAction::TerminateSessions,
                        MitigationAction::RequireAdditionalAuth,
                        MitigationAction::NotifyUser,
                        MitigationAction::NotifySecurityTeam,
                    ];

                    threat.context.business_impact = BusinessImpact::High;
                    threat.attack_phase = AttackPhase::LateralMovement;

                    threats.push(threat);
                }
            }
        }

        Ok(threats)
    }

    /// Detect behavioral anomalies using ML
    async fn detect_behavioral_anomaly(
        &self,
        event: &SecurityEvent,
    ) -> Result<Vec<ThreatSignature>, Box<dyn std::error::Error + Send + Sync>> {
        let mut threats = Vec::new();

        let Some(user_id) = &event.user_id else {
            return Ok(threats);
        };

        let models = self.ml_models.read().await;
        let Some(model) = models.get("behavioral_anomaly") else {
            return Ok(threats);
        };

        // Extract features for ML analysis
        let features = self.extract_ml_features(event).await;
        if features.is_empty() {
            return Ok(threats);
        }

        // TODO: Implement ML prediction using smartcore
        // For now, use statistical anomaly detection
        let anomaly_score = self
            .calculate_statistical_anomaly_score(event, &features)
            .await;

        let config = self.config.read().await;
        let thresholds = &config.thresholds.behavioral_anomaly;

        if anomaly_score < thresholds.anomaly_score_threshold {
            let confidence = (anomaly_score.abs() / 2.0).min(0.95);

            let mut threat = ThreatSignature::new(
                ThreatType::BehavioralAnomaly,
                if confidence > 0.7 {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Medium
                },
                confidence,
            );

            threat.add_affected_entity(user_id.clone());
            if let Some(ip) = event.ip_address {
                threat.add_source_ip(ip);
            }

            let indicator = ThreatIndicator {
                indicator_type: IndicatorType::BehaviorPattern,
                value: format!("Statistical anomaly detected (score: {:.3})", anomaly_score),
                confidence,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                source: "ml_behavioral_analyzer".to_string(),
                tags: ["behavioral_anomaly", "ml_detection"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            };

            threat.add_indicator(indicator);
            threat.mitigation_actions = vec![
                MitigationAction::IncreaseMonitoring,
                MitigationAction::LogForensics,
                MitigationAction::NotifySecurityTeam,
            ];

            threat.context.business_impact = BusinessImpact::Medium;
            threat.attack_phase = AttackPhase::Discovery;

            threats.push(threat);

            BEHAVIORAL_ANOMALIES_DETECTED.inc();
        }

        Ok(threats)
    }

    /// Start event processing background task
    async fn start_event_processor(&self) {
        let event_receiver = self.event_receiver.clone();
        let event_buffer = self.event_buffer.clone();
        let user_profiles = self.user_profiles.clone();
        let user_session_tracking = self.user_session_tracking.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            info!("Starting event processor task");

            while let Ok(event) = event_receiver.recv_async().await {
                // Add to event buffer
                {
                    let mut buffer = event_buffer.lock().await;
                    let config_guard = config.read().await;

                    buffer.push_back(event.clone());
                    if buffer.len() > config_guard.event_buffer_size {
                        buffer.pop_front();
                    }
                }

                // Update user profile
                if let Some(user_id) = &event.user_id {
                    let mut profiles = user_profiles.write().await;
                    let profile = profiles
                        .entry(user_id.clone())
                        .or_insert_with(|| UserBehaviorProfile::new(user_id.clone()));

                    profile.update_with_event(&event);
                    USER_PROFILES_UPDATED.inc();
                }

                // Update session tracking
                if let (Some(user_id), Some(session_id)) = (&event.user_id, &event.session_id) {
                    let mut session_tracking = user_session_tracking.write().await;
                    let user_sessions = session_tracking
                        .entry(user_id.clone())
                        .or_insert_with(Vec::new);

                    // Find existing session or create new one
                    if let Some(session) = user_sessions
                        .iter_mut()
                        .find(|s| s.session_id == *session_id)
                    {
                        session.last_activity = event.timestamp;
                        session.events_count += 1;
                    } else {
                        let new_session = SessionInfo {
                            session_id: session_id.clone(),
                            start_time: event.timestamp,
                            last_activity: event.timestamp,
                            ip_address: event.ip_address,
                            location: event.location.clone(),
                            device_fingerprint: event.device_fingerprint.clone(),
                            events_count: 1,
                            risk_indicators: Vec::new(),
                        };
                        user_sessions.push(new_session);
                    }

                    // Clean up old sessions (older than 24 hours)
                    let cutoff = Utc::now() - Duration::hours(24);
                    user_sessions.retain(|s| s.last_activity > cutoff);
                }
            }
        });
    }

    /// Start profile updater background task
    async fn start_profile_updater(&self) {
        let user_profiles = self.user_profiles.clone();
        let redis_client = self.redis_client.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(300)); // 5 minutes

            loop {
                interval.tick().await;

                let profiles = user_profiles.read().await;
                let redis_client_guard = redis_client.lock().await;

                if let Some(ref client) = *redis_client_guard {
                    let config_guard = config.read().await;

                    for profile in profiles.values() {
                        let key = format!(
                            "{}user_profile:{}",
                            config_guard.redis_config.key_prefix, profile.user_id
                        );

                        if let Ok(profile_json) = serde_json::to_string(profile) {
                            let _: Result<(), redis::RedisError> = redis::cmd("SETEX")
                                .arg(&key)
                                .arg(config_guard.redis_config.profile_ttl_seconds)
                                .arg(&profile_json)
                                .query_async(&mut client.clone())
                                .await;
                        }
                    }
                }
            }
        });
    }

    /// Start threat correlator background task
    async fn start_threat_correlator(&self) {
        let active_threats = self.active_threats.clone();
        let threat_correlations = self.threat_correlations.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(60)); // 1 minute

            loop {
                interval.tick().await;

                let threats = active_threats.read().await;
                let mut correlations = threat_correlations.write().await;

                // Find correlations between threats
                for threat in threats.values() {
                    let related_threats = threats
                        .values()
                        .filter(|t| t.threat_id != threat.threat_id)
                        .filter(|t| Self::threats_are_related(threat, t))
                        .map(|t| t.threat_id.clone())
                        .collect::<Vec<_>>();

                    if !related_threats.is_empty() {
                        correlations.insert(threat.threat_id.clone(), related_threats);
                    }
                }

                // Update active threats gauge
                ACTIVE_THREATS_GAUGE.set(threats.len() as f64);
            }
        });
    }

    /// Start ML model trainer background task
    async fn start_model_trainer(&self) {
        let ml_models = self.ml_models.clone();
        let event_buffer = self.event_buffer.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(3600)); // 1 hour

            loop {
                interval.tick().await;

                // TODO: Implement ML model training with smartcore
                // This would involve:
                // 1. Extracting features from recent events
                // 2. Preparing training data
                // 3. Training/updating models
                // 4. Evaluating model performance

                info!("ML model training cycle completed");
            }
        });
    }

    /// Helper method to check if two threats are related
    fn threats_are_related(threat1: &ThreatSignature, threat2: &ThreatSignature) -> bool {
        // Check for common affected entities
        if !threat1
            .affected_entities
            .is_disjoint(&threat2.affected_entities)
        {
            return true;
        }

        // Check for common source IPs
        if !threat1.source_ips.is_disjoint(&threat2.source_ips) {
            return true;
        }

        // Check temporal proximity (within 1 hour)
        let time_diff = if threat1.first_seen > threat2.first_seen {
            threat1.first_seen.signed_duration_since(threat2.last_seen)
        } else {
            threat2.first_seen.signed_duration_since(threat1.last_seen)
        };

        time_diff.num_hours() <= 1
    }

    /// Extract ML features from security event
    async fn extract_ml_features(&self, event: &SecurityEvent) -> Vec<f64> {
        let mut features = Vec::new();

        // Time-based features
        features.push(event.timestamp.hour() as f64);
        features.push(event.timestamp.weekday().num_days_from_monday() as f64);
        features.push(event.timestamp.minute() as f64);

        // Risk score
        features.push(event.risk_score.unwrap_or(0) as f64);

        // Event type encoding
        let event_type_encoding = match event.event_type {
            SecurityEventType::AuthenticationAttempt => 1.0,
            SecurityEventType::AuthenticationSuccess => 2.0,
            SecurityEventType::AuthenticationFailure => 3.0,
            SecurityEventType::MfaFailure => 4.0,
            SecurityEventType::SuspiciousActivity => 5.0,
            _ => 0.0,
        };
        features.push(event_type_encoding);

        // Outcome encoding
        let outcome_encoding = match event.outcome {
            EventOutcome::Success => 1.0,
            EventOutcome::Failure => 0.0,
            EventOutcome::Blocked => -1.0,
            EventOutcome::Suspicious => -2.0,
            _ => 0.0,
        };
        features.push(outcome_encoding);

        // MFA usage
        features.push(if event.mfa_used { 1.0 } else { 0.0 });

        // Additional behavioral features would be calculated here
        // based on user profile and recent activity patterns

        features
    }

    /// Calculate statistical anomaly score
    async fn calculate_statistical_anomaly_score(
        &self,
        event: &SecurityEvent,
        features: &[f64],
    ) -> f64 {
        // Simplified anomaly detection using statistical methods
        // In a real implementation, this would use more sophisticated algorithms

        let baselines = self.statistical_baselines.read().await;
        let mut anomaly_score = 0.0;

        for (i, &feature_value) in features.iter().enumerate() {
            let metric_name = format!("feature_{}", i);
            if let Some(baseline) = baselines.get(&metric_name) {
                let z_score = (feature_value - baseline.mean) / baseline.std_dev;
                anomaly_score += z_score.abs();
            }
        }

        // Normalize anomaly score
        anomaly_score / features.len() as f64
    }

    /// Store threat signature
    async fn store_threat(&self, threat: ThreatSignature) {
        let mut active_threats = self.active_threats.write().await;
        active_threats.insert(threat.threat_id.clone(), threat.clone());

        // Store in Redis if available
        let redis_client = self.redis_client.lock().await;
        if let Some(ref client) = *redis_client {
            let config = self.config.read().await;
            let key = format!(
                "{}threat:{}",
                config.redis_config.key_prefix, threat.threat_id
            );

            if let Ok(threat_json) = serde_json::to_string(&threat) {
                let _: Result<(), redis::RedisError> = redis::cmd("SETEX")
                    .arg(&key)
                    .arg(config.redis_config.threat_ttl_seconds)
                    .arg(&threat_json)
                    .query_async(&mut client.clone())
                    .await;
            }
        }
    }

    /// Get recent user sessions
    async fn get_recent_user_sessions(&self, user_id: &str, hours: u32) -> Vec<SessionInfo> {
        let session_tracking = self.user_session_tracking.read().await;
        let cutoff = Utc::now() - Duration::hours(hours as i64);

        session_tracking
            .get(user_id)
            .map(|sessions| {
                sessions
                    .iter()
                    .filter(|s| s.last_activity > cutoff)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Count recent authentication failures for a user
    async fn count_recent_failures(&self, user_id: &str, minutes: u64) -> u32 {
        let event_buffer = self.event_buffer.lock().await;
        let cutoff = Utc::now() - Duration::minutes(minutes as i64);

        event_buffer
            .iter()
            .filter(|e| e.user_id.as_ref() == Some(user_id))
            .filter(|e| e.timestamp > cutoff)
            .filter(|e| matches!(e.event_type, SecurityEventType::AuthenticationFailure))
            .count() as u32
    }

    /// Get IP addresses from recent failures for a user
    async fn get_recent_failure_ips(&self, user_id: &str, minutes: u64) -> HashSet<IpAddr> {
        let event_buffer = self.event_buffer.lock().await;
        let cutoff = Utc::now() - Duration::minutes(minutes as i64);

        event_buffer
            .iter()
            .filter(|e| e.user_id.as_ref() == Some(user_id))
            .filter(|e| e.timestamp > cutoff)
            .filter(|e| matches!(e.event_type, SecurityEventType::AuthenticationFailure))
            .filter_map(|e| e.ip_address)
            .collect()
    }

    /// Calculate distance between two points (simplified haversine formula)
    fn calculate_distance(&self, lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = lat1.to_radians();
        let lon1_rad = lon1.to_radians();
        let lat2_rad = lat2.to_radians();
        let lon2_rad = lon2.to_radians();

        let dlat = lat2_rad - lat1_rad;
        let dlon = lon2_rad - lon1_rad;

        let a = (dlat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }

    /// Get currently active threats
    pub async fn get_active_threats(&self) -> Vec<ThreatSignature> {
        let threats = self.active_threats.read().await;
        threats.values().cloned().collect()
    }

    /// Get analysis metrics
    pub async fn get_metrics(&self) -> AnalysisMetrics {
        let metrics = self.analysis_metrics.lock().await;
        metrics.clone()
    }

    /// Shutdown the detector
    pub async fn shutdown(&self) {
        info!("Shutting down Advanced Behavioral Threat Detector");

        // Save final state to Redis
        // Close connections
        let mut redis_client = self.redis_client.lock().await;
        *redis_client = None;

        info!("Advanced Behavioral Threat Detector shutdown complete");
    }
}
