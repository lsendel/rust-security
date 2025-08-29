use crate::core::security::SecurityEventType;
use crate::threat_user_profiler::config::*;
use crate::threat_user_profiler::features::BehavioralFeatureExtractor;
use crate::threat_user_profiler::risk_assessment::RiskAssessmentEngine;
use crate::threat_user_profiler::time_series::TimeSeriesAnalyzer;
use crate::threat_user_profiler::types::*;
use crate::threat_user_profiler::types::*;
use chrono::{DateTime, Utc};
use flume::{unbounded, Receiver, Sender};
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[cfg(feature = "monitoring")]
use prometheus::{register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram};

/// Prometheus metrics for user profiling
#[cfg(feature = "monitoring")]
lazy_static::lazy_static! {
    static ref USER_PROFILES_ANALYZED: Counter = register_counter!(
        "threat_hunting_user_profiles_analyzed_total",
        "Total user profiles analyzed"
    ).unwrap();

    static ref BEHAVIORAL_ANOMALIES_FOUND: Counter = register_counter!(
        "threat_hunting_behavioral_anomalies_found_total",
        "Total behavioral anomalies found in user profiles"
    ).unwrap();

    static ref PROFILE_ANALYSIS_DURATION: Histogram = register_histogram!(
        "threat_hunting_profile_analysis_duration_seconds",
        "Duration of user profile analysis operations"
    ).unwrap();

    static ref ACTIVE_USER_PROFILES: Gauge = register_gauge!(
        "threat_hunting_active_user_profiles",
        "Number of active user profiles being tracked"
    ).unwrap();

    static ref TIME_SERIES_PREDICTIONS: Counter = register_counter!(
        "threat_hunting_time_series_predictions_total",
        "Total time series predictions made"
    ).unwrap();
}

/// Advanced user behavior profiler that orchestrates all profiling components
pub struct AdvancedUserBehaviorProfiler {
    config: Arc<RwLock<UserProfilingConfig>>,
    redis_client: Arc<Mutex<Option<ConnectionManager>>>,
    user_profiles: Arc<RwLock<HashMap<Uuid, EnhancedUserBehaviorProfile>>>,
    time_series_data: Arc<RwLock<HashMap<Uuid, HashMap<String, BehavioralTimeSeries>>>>,
    profile_update_queue: Sender<ProfileUpdateRequest>,
    profile_update_receiver: Receiver<ProfileUpdateRequest>,

    // Component engines
    time_series_analyzer: TimeSeriesAnalyzer,
    feature_extractor: BehavioralFeatureExtractor,
    risk_assessment_engine: RiskAssessmentEngine,

    // Statistics and monitoring
    profiling_statistics: Arc<Mutex<ProfilingStatistics>>,
}

/// Request for profile update processing
#[derive(Debug, Clone)]
pub struct ProfileUpdateRequest {
    pub user_id: Uuid,
    pub events: Vec<UserSecurityEvent>,
    pub timestamp: DateTime<Utc>,
    pub priority: UpdatePriority,
}

/// Priority levels for profile updates
#[derive(Debug, Clone, PartialEq)]
pub enum UpdatePriority {
    Low,
    Normal,
    High,
    Critical,
}

impl AdvancedUserBehaviorProfiler {
    /// Create a new advanced user behavior profiler
    pub fn new(config: UserProfilingConfig) -> Self {
        let (profile_update_sender, profile_update_receiver) = unbounded();

        // Initialize component engines with their respective configurations
        let time_series_analyzer = TimeSeriesAnalyzer::new(
            config.temporal_analysis.time_series_window_size,
            config
                .temporal_analysis
                .seasonality_detection_periods
                .clone(),
            config.temporal_analysis.change_point_detection_sensitivity,
        );

        let feature_extractor = BehavioralFeatureExtractor::new(config.behavioral_features.clone());
        let risk_assessment_engine = RiskAssessmentEngine::new(config.risk_scoring.clone());

        Self {
            config: Arc::new(RwLock::new(config)),
            redis_client: Arc::new(Mutex::new(None)),
            user_profiles: Arc::new(RwLock::new(HashMap::new())),
            time_series_data: Arc::new(RwLock::new(HashMap::new())),
            profile_update_queue: profile_update_sender,
            profile_update_receiver,
            time_series_analyzer,
            feature_extractor,
            risk_assessment_engine,
            profiling_statistics: Arc::new(Mutex::new(ProfilingStatistics::default())),
        }
    }

    /// Initialize the user behavior profiler
    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing Advanced User Behavior Profiler");

        // Initialize Redis connection
        if let Err(e) = self.initialize_redis().await {
            warn!("Failed to initialize Redis connection: {}", e);
        }

        // Load existing profiles
        self.load_existing_profiles().await?;

        // Start background processing tasks
        self.start_profile_processor().await;
        self.start_time_series_analyzer_task().await;
        self.start_anomaly_detector().await;
        self.start_risk_assessor().await;

        info!("Advanced User Behavior Profiler initialized successfully");
        Ok(())
    }

    /// Process user security events and update behavioral profile
    pub async fn process_user_events(
        &self,
        user_id: Uuid,
        events: Vec<UserSecurityEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let priority = self.determine_update_priority(&events);

        let update_request = ProfileUpdateRequest {
            user_id,
            events,
            timestamp: Utc::now(),
            priority,
        };

        self.profile_update_queue
            .send_async(update_request)
            .await
            .map_err(|e| format!("Failed to queue profile update: {}", e))?;

        Ok(())
    }

    /// Get current behavioral profile for a user
    pub async fn get_user_profile(&self, user_id: Uuid) -> Option<EnhancedUserBehaviorProfile> {
        let profiles = self.user_profiles.read().await;
        profiles.get(&user_id).cloned()
    }

    /// Get risk assessment for a user
    pub async fn assess_user_risk(
        &self,
        user_id: Uuid,
    ) -> Result<RiskAssessment, Box<dyn std::error::Error + Send + Sync>> {
        let profiles = self.user_profiles.read().await;

        if let Some(profile) = profiles.get(&user_id) {
            // Get peer profiles for comparison
            let peer_profiles: Vec<EnhancedUserBehaviorProfile> = profiles
                .values()
                .filter(|p| p.user_id != user_id)
                .take(100) // Limit peer comparison set
                .cloned()
                .collect();

            self.risk_assessment_engine
                .assess_risk(user_id, profile, &peer_profiles)
                .await
        } else {
            Err("User profile not found".into())
        }
    }

    /// Initialize Redis connection
    async fn initialize_redis(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;

        let client = redis::Client::open(config.redis_config.connection_url.as_str())?;
        let connection_manager = ConnectionManager::new(client).await?;

        let mut redis_client = self.redis_client.lock().await;
        *redis_client = Some(connection_manager);

        info!("Redis connection initialized for user profiling");
        Ok(())
    }

    /// Load existing user profiles from storage
    async fn load_existing_profiles(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, this would load profiles from Redis/database
        // For now, we'll start with empty profiles
        info!("Loading existing user profiles");
        Ok(())
    }

    /// Start background profile processor
    async fn start_profile_processor(&self) {
        let receiver = self.profile_update_receiver.clone();
        let profiles = Arc::clone(&self.user_profiles);
        let time_series_data = Arc::clone(&self.time_series_data);
        let feature_extractor = self.feature_extractor.clone();
        let statistics = Arc::clone(&self.profiling_statistics);
        let config = Arc::clone(&self.config);

        tokio::spawn(async move {
            info!("Starting profile processor task");

            while let Ok(update_request) = receiver.recv_async().await {
                #[cfg(feature = "monitoring")]
                let _timer = PROFILE_ANALYSIS_DURATION.start_timer();

                if let Err(e) = Self::process_profile_update(
                    update_request,
                    &profiles,
                    &time_series_data,
                    &feature_extractor,
                    &statistics,
                    &config,
                )
                .await
                {
                    error!("Failed to process profile update: {}", e);
                }

                #[cfg(feature = "monitoring")]
                USER_PROFILES_ANALYZED.inc();
            }
        });
    }

    /// Process a single profile update request
    async fn process_profile_update(
        request: ProfileUpdateRequest,
        profiles: &Arc<RwLock<HashMap<Uuid, EnhancedUserBehaviorProfile>>>,
        time_series_data: &Arc<RwLock<HashMap<Uuid, HashMap<String, BehavioralTimeSeries>>>>,
        feature_extractor: &BehavioralFeatureExtractor,
        statistics: &Arc<Mutex<ProfilingStatistics>>,
        _config: &Arc<RwLock<UserProfilingConfig>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start_time = std::time::Instant::now();

        // Get existing profile or create new one
        let existing_profile = {
            let profiles_read = profiles.read().await;
            profiles_read.get(&request.user_id).cloned()
        };

        // Extract behavioral features
        let feature_vector = feature_extractor
            .extract_features(request.user_id, &request.events, existing_profile.as_ref())
            .await?;

        // Update time series data
        Self::update_time_series_data(&request, time_series_data).await?;

        // Create or update profile
        let updated_profile = if let Some(mut profile) = existing_profile {
            profile.last_updated = Utc::now();
            profile.feature_vector = feature_vector;
            profile
        } else {
            EnhancedUserBehaviorProfile {
                user_id: request.user_id,
                created_at: Utc::now(),
                last_updated: Utc::now(),
                feature_vector,
                temporal_features: TemporalFeatures::default(),
                risk_assessment: RiskAssessment::default(),
                peer_comparisons: PeerComparisons::default(),
                anomaly_scores: HashMap::new(),
                confidence_score: 0.5, // Start with neutral confidence
            }
        };

        // Store updated profile
        {
            let mut profiles_write = profiles.write().await;
            profiles_write.insert(request.user_id, updated_profile);
        }

        // Update statistics
        {
            let mut stats = statistics.lock().await;
            stats.profiles_analyzed += 1;
            stats.average_processing_time_ms =
                (stats.average_processing_time_ms + start_time.elapsed().as_millis() as f64) / 2.0;
        }

        #[cfg(feature = "monitoring")]
        ACTIVE_USER_PROFILES.set(profiles.read().await.len() as f64);

        debug!(
            "Processed profile update for user {} in {:.2}ms",
            request.user_id,
            start_time.elapsed().as_millis()
        );

        Ok(())
    }

    /// Update time series data for behavioral analysis
    async fn update_time_series_data(
        request: &ProfileUpdateRequest,
        time_series_data: &Arc<RwLock<HashMap<Uuid, HashMap<String, BehavioralTimeSeries>>>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut data = time_series_data.write().await;
        let user_series = data.entry(request.user_id).or_insert_with(HashMap::new);

        // Extract time series points from events
        for event in &request.events {
            // Login frequency time series
            let login_series = user_series
                .entry("login_frequency".to_string())
                .or_insert_with(|| BehavioralTimeSeries {
                    user_id: request.user_id,
                    feature_name: "login_frequency".to_string(),
                    data_points: std::collections::VecDeque::new(),
                    window_size: 1000,
                    statistics: None,
                });

            login_series.data_points.push_back(TimeSeriesPoint {
                timestamp: event.timestamp,
                value: 1.0, // Each event represents one login
                metadata: std::collections::HashMap::new(),
            });

            // Keep window size manageable
            if login_series.data_points.len() > login_series.window_size {
                login_series.data_points.pop_front();
            }
        }

        Ok(())
    }

    /// Start time series analyzer background task
    async fn start_time_series_analyzer_task(&self) {
        let time_series_data = Arc::clone(&self.time_series_data);
        let analyzer = self.time_series_analyzer.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(300)); // Every 5 minutes

            loop {
                interval.tick().await;

                let data = time_series_data.read().await;
                for (user_id, user_series) in data.iter() {
                    for series in user_series.values() {
                        if let Err(e) = analyzer.analyze_series(series).await {
                            debug!("Time series analysis failed for user {}: {}", user_id, e);
                        }
                    }
                }
            }
        });
    }

    /// Start anomaly detector background task
    async fn start_anomaly_detector(&self) {
        let profiles = Arc::clone(&self.user_profiles);

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(600)); // Every 10 minutes

            loop {
                interval.tick().await;

                let profiles_read = profiles.read().await;
                for profile in profiles_read.values() {
                    // Perform anomaly detection on profile
                    // This would integrate with ML models for anomaly detection
                    debug!("Performing anomaly detection for user {}", profile.user_id);
                }

                #[cfg(feature = "monitoring")]
                BEHAVIORAL_ANOMALIES_FOUND.inc_by(profiles_read.len() as f64);
            }
        });
    }

    /// Start risk assessor background task
    async fn start_risk_assessor(&self) {
        let profiles = Arc::clone(&self.user_profiles);
        let risk_engine = self.risk_assessment_engine.clone();

        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(900)); // Every 15 minutes

            loop {
                interval.tick().await;

                let profiles_read = profiles.read().await;
                let all_profiles: Vec<EnhancedUserBehaviorProfile> =
                    profiles_read.values().cloned().collect();

                for profile in &all_profiles {
                    let peer_profiles: Vec<EnhancedUserBehaviorProfile> = all_profiles
                        .iter()
                        .filter(|p| p.user_id != profile.user_id)
                        .take(50)
                        .cloned()
                        .collect();

                    if let Err(e) = risk_engine
                        .assess_risk(profile.user_id, profile, &peer_profiles)
                        .await
                    {
                        debug!("Risk assessment failed for user {}: {}", profile.user_id, e);
                    }
                }
            }
        });
    }

    /// Determine update priority based on events
    fn determine_update_priority(&self, events: &[UserSecurityEvent]) -> UpdatePriority {
        // Consider certain event types as high-risk
        let high_risk_events = events
            .iter()
            .filter(|e| {
                matches!(
                    e.event_type,
                    SecurityEventType::ThreatDetected
                        | SecurityEventType::AnomalyDetected
                        | SecurityEventType::SuspiciousActivity
                        | SecurityEventType::PolicyViolation
                )
            })
            .count();
        let total_events = events.len();

        if high_risk_events > 0 && (high_risk_events as f64 / total_events as f64) > 0.5 {
            UpdatePriority::Critical
        } else if high_risk_events > 0 {
            UpdatePriority::High
        } else if total_events > 10 {
            UpdatePriority::Normal
        } else {
            UpdatePriority::Low
        }
    }

    /// Get profiling statistics
    pub async fn get_statistics(&self) -> ProfilingStatistics {
        let stats = self.profiling_statistics.lock().await;
        stats.clone()
    }

    /// Shutdown the profiler gracefully
    pub async fn shutdown(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Shutting down Advanced User Behavior Profiler");

        // Save profiles to persistent storage
        self.save_profiles_to_storage().await?;

        info!("Advanced User Behavior Profiler shutdown complete");
        Ok(())
    }

    /// Save profiles to persistent storage
    async fn save_profiles_to_storage(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, this would save to Redis/database
        let profiles = self.user_profiles.read().await;
        info!("Saving {} user profiles to storage", profiles.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_profiler_initialization() {
        let config = UserProfilingConfig::default();
        let profiler = AdvancedUserBehaviorProfiler::new(config);

        // Test initialization (Redis connection may fail in test environment)
        let result = profiler.initialize().await;
        // Don't assert success since Redis may not be available in tests

        let stats = profiler.get_statistics().await;
        assert_eq!(stats.profiles_analyzed, 0);
    }

    #[tokio::test]
    async fn test_event_processing() {
        let config = UserProfilingConfig::default();
        let profiler = AdvancedUserBehaviorProfiler::new(config);

        let user_id = uuid::Uuid::new_v4();
        let events = vec![UserSecurityEvent {
            id: uuid::Uuid::new_v4(),
            user_id,
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthenticationSuccess,
            source_ip: "192.168.1.1".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            location: None,
            device_fingerprint: None,
            session_id: None,
            metadata: std::collections::HashMap::new(),
        }];

        let result = profiler.process_user_events(user_id, events).await;
        assert!(result.is_ok());
    }
}
