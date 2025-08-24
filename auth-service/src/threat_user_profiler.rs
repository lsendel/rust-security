use crate::threat_types::*;
use chrono::{DateTime, Duration, Timelike, Utc, Weekday};
use flume::{unbounded, Receiver, Sender};
use indexmap::IndexMap;
use nalgebra::{DMatrix, DVector};
#[cfg(feature = "monitoring")]
use prometheus::{register_counter, register_gauge, register_histogram, Counter, Gauge, Histogram};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use smartcore::metrics::distance::Distance;
use smartcore::neighbors::knn_classifier::KNNClassifier;
use smartcore::preprocessing::numerical::StandardScaler;
use statrs::distribution::{ChiSquared, ContinuousCDF, Normal};
use statrs::statistics::{OrderStatistics, Statistics};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Prometheus metrics for user profiling
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

/// Configuration for user behavior profiling
#[derive(Debug, Clone)]
pub struct UserProfilingConfig {
    pub enabled: bool,
    pub profile_retention_days: u64,
    pub min_events_for_baseline: u32,
    pub anomaly_detection_sensitivity: f64,
    pub time_series_window_hours: u64,
    pub profile_update_interval_seconds: u64,
    pub ml_model_retraining_hours: u64,
    pub behavioral_features: BehavioralFeatureConfig,
    pub temporal_analysis: TemporalAnalysisConfig,
    pub risk_scoring: RiskScoringConfig,
    pub redis_config: ProfilingRedisConfig,
}

/// Configuration for behavioral features
#[derive(Debug, Clone)]
pub struct BehavioralFeatureConfig {
    pub temporal_features_enabled: bool,
    pub location_features_enabled: bool,
    pub device_features_enabled: bool,
    pub network_features_enabled: bool,
    pub activity_features_enabled: bool,
    pub feature_normalization: FeatureNormalization,
    pub feature_weights: HashMap<String, f64>,
}

/// Feature normalization options
#[derive(Debug, Clone)]
pub struct FeatureNormalization {
    pub method: NormalizationMethod,
    pub outlier_threshold: f64,
    pub clip_outliers: bool,
}

/// Normalization methods
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationMethod {
    StandardScore,
    MinMax,
    Robust,
    Quantile,
}

/// Configuration for temporal analysis
#[derive(Debug, Clone)]
pub struct TemporalAnalysisConfig {
    pub enabled: bool,
    pub seasonality_detection: bool,
    pub trend_analysis: bool,
    pub change_point_detection: bool,
    pub periodicity_analysis: bool,
    pub forecast_horizon_hours: u64,
    pub confidence_intervals: bool,
}

/// Configuration for risk scoring
#[derive(Debug, Clone)]
pub struct RiskScoringConfig {
    pub enabled: bool,
    pub baseline_recalculation_days: u64,
    pub risk_factor_weights: HashMap<String, f64>,
    pub adaptive_thresholds: bool,
    pub peer_comparison_enabled: bool,
    pub threat_intelligence_integration: bool,
}

/// Redis configuration for profiling
#[derive(Debug, Clone)]
pub struct ProfilingRedisConfig {
    pub url: String,
    pub key_prefix: String,
    pub profile_ttl_seconds: u64,
    pub time_series_ttl_seconds: u64,
    pub model_cache_ttl_seconds: u64,
}

/// Time series data point for behavioral metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub confidence: f64,
    pub anomaly_score: Option<f64>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Time series for tracking behavioral metrics over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralTimeSeries {
    pub series_id: String,
    pub user_id: String,
    pub metric_name: String,
    pub data_points: VecDeque<TimeSeriesPoint>,
    pub statistical_summary: SeriesStatistics,
    pub trend_analysis: TrendAnalysis,
    pub seasonality: SeasonalityAnalysis,
    pub forecast: Option<Forecast>,
    pub last_updated: DateTime<Utc>,
}

/// Statistical summary of time series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeriesStatistics {
    pub count: usize,
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub median: f64,
    pub percentiles: BTreeMap<u8, f64>,
    pub skewness: f64,
    pub kurtosis: f64,
}

/// Trend analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub trend_direction: TrendDirection,
    pub trend_strength: f64,
    pub change_points: Vec<ChangePoint>,
    pub linear_regression: LinearRegressionResult,
    pub volatility: f64,
}

/// Change point in time series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoint {
    pub timestamp: DateTime<Utc>,
    pub confidence: f64,
    pub change_magnitude: f64,
    pub change_type: ChangeType,
}

/// Types of changes in time series
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    LevelShift,
    TrendChange,
    VarianceChange,
    SeasonalityChange,
}

/// Linear regression results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearRegressionResult {
    pub slope: f64,
    pub intercept: f64,
    pub r_squared: f64,
    pub p_value: f64,
    pub confidence_interval: (f64, f64),
}

/// Seasonality analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalityAnalysis {
    pub has_seasonality: bool,
    pub seasonal_periods: Vec<SeasonalPeriod>,
    pub dominant_frequencies: Vec<f64>,
    pub seasonal_strength: f64,
}

/// Seasonal period information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPeriod {
    pub period_hours: f64,
    pub amplitude: f64,
    pub phase: f64,
    pub confidence: f64,
}

/// Forecast results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forecast {
    pub forecast_points: Vec<ForecastPoint>,
    pub model_type: ForecastModel,
    pub accuracy_metrics: AccuracyMetrics,
    pub confidence_intervals: Vec<ConfidenceInterval>,
}

/// Individual forecast point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastPoint {
    pub timestamp: DateTime<Utc>,
    pub predicted_value: f64,
    pub confidence: f64,
    pub prediction_interval: (f64, f64),
}

/// Types of forecasting models
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ForecastModel {
    Linear,
    ExponentialSmoothing,
    Arima,
    SeasonalDecomposition,
    MachineLearning,
}

/// Model accuracy metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub mae: f64,  // Mean Absolute Error
    pub mse: f64,  // Mean Squared Error
    pub rmse: f64, // Root Mean Squared Error
    pub mape: f64, // Mean Absolute Percentage Error
    pub r_squared: f64,
}

/// Confidence interval for forecasts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub timestamp: DateTime<Utc>,
    pub lower_bound: f64,
    pub upper_bound: f64,
    pub confidence_level: f64,
}

/// Enhanced user behavior profile with time series analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedUserBehaviorProfile {
    pub base_profile: UserBehaviorProfile,
    pub time_series_metrics: HashMap<String, BehavioralTimeSeries>,
    pub behavioral_features: BehavioralFeatureVector,
    pub risk_assessment: RiskAssessment,
    pub peer_comparisons: PeerComparisons,
    pub anomaly_history: Vec<BehavioralAnomaly>,
    pub model_predictions: Vec<BehaviorPrediction>,
    pub profile_confidence: f64,
    pub last_comprehensive_analysis: Option<DateTime<Utc>>,
}

/// Behavioral feature vector for ML analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFeatureVector {
    pub temporal_features: TemporalFeatures,
    pub location_features: LocationFeatures,
    pub device_features: DeviceFeatures,
    pub network_features: NetworkFeatures,
    pub activity_features: ActivityFeatures,
    pub normalized_vector: Vec<f64>,
    pub feature_importance: HashMap<String, f64>,
}

/// Temporal behavioral features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalFeatures {
    pub login_time_entropy: f64,
    pub activity_circadian_rhythm: f64,
    pub weekly_pattern_consistency: f64,
    pub session_duration_stability: f64,
    pub inter_arrival_time_distribution: Vec<f64>,
    pub burst_pattern_indicators: Vec<f64>,
}

/// Location-based features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationFeatures {
    pub location_entropy: f64,
    pub geographic_consistency: f64,
    pub travel_pattern_anomaly: f64,
    pub location_clustering_coefficient: f64,
    pub distance_travelled_stats: SeriesStatistics,
}

/// Device-related features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFeatures {
    pub device_diversity_score: f64,
    pub device_switching_frequency: f64,
    pub device_consistency_score: f64,
    pub browser_pattern_score: f64,
    pub os_consistency_score: f64,
}

/// Network-related features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFeatures {
    pub ip_address_entropy: f64,
    pub network_diversity_score: f64,
    pub asn_consistency_score: f64,
    pub vpn_usage_indicators: f64,
    pub tor_usage_indicators: f64,
}

/// Activity-based features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityFeatures {
    pub authentication_rate_stability: f64,
    pub resource_access_patterns: f64,
    pub api_usage_consistency: f64,
    pub error_rate_indicators: f64,
    pub session_management_patterns: f64,
}

/// Risk assessment results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub risk_trend: TrendDirection,
    pub confidence_level: f64,
    pub risk_category: RiskCategory,
    pub recommended_actions: Vec<MitigationAction>,
    pub assessment_timestamp: DateTime<Utc>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_name: String,
    pub risk_score: f64,
    pub weight: f64,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub mitigation_priority: u8,
}

/// Risk categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskCategory {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
    Critical,
}

/// Peer comparison results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerComparisons {
    pub peer_group: String,
    pub percentile_rank: f64,
    pub deviation_from_peer_average: f64,
    pub similar_users: Vec<String>,
    pub outlier_metrics: Vec<OutlierMetric>,
    pub peer_comparison_confidence: f64,
}

/// Outlier metric information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutlierMetric {
    pub metric_name: String,
    pub user_value: f64,
    pub peer_mean: f64,
    pub peer_std_dev: f64,
    pub z_score: f64,
    pub outlier_probability: f64,
}

/// Behavioral anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnomaly {
    pub anomaly_id: String,
    pub detection_timestamp: DateTime<Utc>,
    pub anomaly_type: AnomalyType,
    pub severity: ThreatSeverity,
    pub confidence: f64,
    pub affected_metrics: Vec<String>,
    pub anomaly_score: f64,
    pub description: String,
    pub evidence: AnomalyEvidence,
    pub resolved: bool,
    pub resolution_timestamp: Option<DateTime<Utc>>,
}

/// Types of behavioral anomalies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyType {
    TemporalAnomaly,
    LocationAnomaly,
    DeviceAnomaly,
    ActivityAnomaly,
    NetworkAnomaly,
    VolumeAnomaly,
    PatternAnomaly,
    TrendAnomaly,
}

/// Evidence supporting anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvidence {
    pub statistical_evidence: StatisticalEvidence,
    pub temporal_evidence: TemporalEvidence,
    pub comparative_evidence: ComparativeEvidence,
    pub supporting_events: Vec<String>,
}

/// Statistical evidence for anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalEvidence {
    pub z_scores: HashMap<String, f64>,
    pub p_values: HashMap<String, f64>,
    pub chi_squared_stats: HashMap<String, f64>,
    pub distribution_tests: HashMap<String, f64>,
}

/// Temporal evidence for anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalEvidence {
    pub time_of_occurrence: DateTime<Utc>,
    pub expected_time_window: (DateTime<Utc>, DateTime<Utc>),
    pub temporal_deviation_score: f64,
    pub seasonal_anomaly_score: f64,
}

/// Comparative evidence against peers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparativeEvidence {
    pub peer_deviation_scores: HashMap<String, f64>,
    pub outlier_rankings: HashMap<String, f64>,
    pub comparative_confidence: f64,
}

/// Behavior prediction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorPrediction {
    pub prediction_id: String,
    pub prediction_timestamp: DateTime<Utc>,
    pub prediction_horizon: Duration,
    pub predicted_behaviors: Vec<PredictedBehavior>,
    pub confidence: f64,
    pub prediction_accuracy: Option<f64>,
    pub model_used: String,
}

/// Individual predicted behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictedBehavior {
    pub behavior_type: String,
    pub probability: f64,
    pub expected_timestamp: DateTime<Utc>,
    pub confidence_interval: (f64, f64),
    pub risk_implications: Vec<String>,
}

/// User behavior profiler with advanced analytics
pub struct AdvancedUserBehaviorProfiler {
    config: Arc<RwLock<UserProfilingConfig>>,
    redis_client: Arc<Mutex<Option<ConnectionManager>>>,

    // Profile storage
    user_profiles: Arc<RwLock<HashMap<String, EnhancedUserBehaviorProfile>>>,
    time_series_data: Arc<RwLock<HashMap<String, HashMap<String, BehavioralTimeSeries>>>>,

    // Processing queues
    profile_update_queue: Sender<ProfileUpdateRequest>,
    profile_update_receiver: Receiver<ProfileUpdateRequest>,

    // ML models and analysis
    ml_models: Arc<RwLock<HashMap<String, BehavioralModel>>>,
    feature_extractors: Arc<RwLock<HashMap<String, FeatureExtractor>>>,

    // Peer comparison
    peer_groups: Arc<RwLock<HashMap<String, PeerGroup>>>,

    // Statistics and monitoring
    profiling_statistics: Arc<Mutex<ProfilingStatistics>>,
}

/// Profile update request
#[derive(Debug, Clone)]
pub struct ProfileUpdateRequest {
    pub user_id: String,
    pub event: SecurityEvent,
    pub update_type: ProfileUpdateType,
    pub priority: UpdatePriority,
}

/// Types of profile updates
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileUpdateType {
    Incremental,
    FullRecomputation,
    TimeSeriesUpdate,
    RiskAssessment,
    PeerComparison,
}

/// Update priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdatePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Machine learning model for behavioral analysis
#[derive(Debug)]
pub struct BehavioralModel {
    pub model_id: String,
    pub model_type: ModelType,
    pub classifier: Option<KNNClassifier<f64, i32>>,
    pub scaler: Option<StandardScaler<f64>>,
    pub feature_names: Vec<String>,
    pub training_accuracy: f64,
    pub validation_accuracy: f64,
    pub last_trained: DateTime<Utc>,
    pub training_data_size: usize,
}

/// Types of ML models
#[derive(Debug, PartialEq, Eq)]
pub enum ModelType {
    AnomalyDetection,
    RiskClassification,
    BehaviorPrediction,
    PeerComparison,
}

/// Feature extractor for behavioral metrics
#[derive(Debug)]
pub struct FeatureExtractor {
    pub extractor_id: String,
    pub feature_names: Vec<String>,
    pub normalization_params: HashMap<String, (f64, f64)>, // (mean, std_dev)
}

/// Peer group for comparison
#[derive(Debug, Clone)]
pub struct PeerGroup {
    pub group_id: String,
    pub group_name: String,
    pub member_count: usize,
    pub group_characteristics: BehavioralFeatureVector,
    pub statistical_baselines: HashMap<String, SeriesStatistics>,
    pub last_updated: DateTime<Utc>,
}

/// Profiling system statistics
#[derive(Debug, Default)]
pub struct ProfilingStatistics {
    pub profiles_active: usize,
    pub profiles_analyzed: u64,
    pub anomalies_detected: u64,
    pub predictions_made: u64,
    pub time_series_points: u64,
    pub ml_model_accuracy: f64,
    pub average_processing_time_ms: u64,
}

impl Default for UserProfilingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile_retention_days: 90,
            min_events_for_baseline: 50,
            anomaly_detection_sensitivity: 0.05, // 5% significance level
            time_series_window_hours: 168,       // 1 week
            profile_update_interval_seconds: 300, // 5 minutes
            ml_model_retraining_hours: 24,       // Daily retraining
            behavioral_features: BehavioralFeatureConfig::default(),
            temporal_analysis: TemporalAnalysisConfig::default(),
            risk_scoring: RiskScoringConfig::default(),
            redis_config: ProfilingRedisConfig {
                url: "redis://localhost:6379".to_string(),
                key_prefix: "user_profiling:".to_string(),
                profile_ttl_seconds: 86400 * 90,     // 90 days
                time_series_ttl_seconds: 86400 * 30, // 30 days
                model_cache_ttl_seconds: 86400 * 7,  // 7 days
            },
        }
    }
}

impl Default for BehavioralFeatureConfig {
    fn default() -> Self {
        Self {
            temporal_features_enabled: true,
            location_features_enabled: true,
            device_features_enabled: true,
            network_features_enabled: true,
            activity_features_enabled: true,
            feature_normalization: FeatureNormalization {
                method: NormalizationMethod::StandardScore,
                outlier_threshold: 3.0,
                clip_outliers: true,
            },
            feature_weights: [
                ("temporal".to_string(), 0.25),
                ("location".to_string(), 0.20),
                ("device".to_string(), 0.15),
                ("network".to_string(), 0.20),
                ("activity".to_string(), 0.20),
            ]
            .into_iter()
            .collect(),
        }
    }
}

impl Default for TemporalAnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            seasonality_detection: true,
            trend_analysis: true,
            change_point_detection: true,
            periodicity_analysis: true,
            forecast_horizon_hours: 48,
            confidence_intervals: true,
        }
    }
}

impl Default for RiskScoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            baseline_recalculation_days: 30,
            risk_factor_weights: [
                ("anomaly_frequency".to_string(), 0.3),
                ("behavioral_deviation".to_string(), 0.25),
                ("temporal_anomalies".to_string(), 0.2),
                ("location_anomalies".to_string(), 0.15),
                ("peer_deviation".to_string(), 0.1),
            ]
            .into_iter()
            .collect(),
            adaptive_thresholds: true,
            peer_comparison_enabled: true,
            threat_intelligence_integration: true,
        }
    }
}

impl AdvancedUserBehaviorProfiler {
    /// Create a new advanced user behavior profiler
    pub fn new(config: UserProfilingConfig) -> Self {
        let (profile_update_sender, profile_update_receiver) = unbounded();

        Self {
            config: Arc::new(RwLock::new(config)),
            redis_client: Arc::new(Mutex::new(None)),
            user_profiles: Arc::new(RwLock::new(HashMap::new())),
            time_series_data: Arc::new(RwLock::new(HashMap::new())),
            profile_update_queue: profile_update_sender,
            profile_update_receiver,
            ml_models: Arc::new(RwLock::new(HashMap::new())),
            feature_extractors: Arc::new(RwLock::new(HashMap::new())),
            peer_groups: Arc::new(RwLock::new(HashMap::new())),
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

        // Initialize ML models
        self.initialize_ml_models().await?;

        // Initialize feature extractors
        self.initialize_feature_extractors().await;

        // Start background tasks
        self.start_profile_processor().await;
        self.start_time_series_analyzer().await;
        self.start_anomaly_detector().await;
        self.start_risk_assessor().await;
        self.start_model_trainer().await;

        info!("Advanced User Behavior Profiler initialized successfully");
        Ok(())
    }

    /// Initialize Redis connection
    async fn initialize_redis(&self) -> Result<(), redis::RedisError> {
        let config = self.config.read().await;
        let client = redis::Client::open(config.redis_config.url.as_str())?;
        let manager = ConnectionManager::new(client).await?;

        let mut redis_client = self.redis_client.lock().await;
        *redis_client = Some(manager);

        info!("Redis connection established for user profiling");
        Ok(())
    }

    /// Load existing user profiles from Redis
    async fn load_existing_profiles(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let redis_client = self.redis_client.lock().await;
        if let Some(ref client) = *redis_client {
            let config = self.config.read().await;
            let pattern = format!("{}profile:*", config.redis_config.key_prefix);

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
                    if let Ok(profile) = serde_json::from_str::<EnhancedUserBehaviorProfile>(&data)
                    {
                        profiles.insert(profile.base_profile.user_id.clone(), profile);
                    }
                }
            }

            info!("Loaded {} enhanced user behavior profiles", profiles.len());
            ACTIVE_USER_PROFILES.set(profiles.len() as f64);
        }
        Ok(())
    }

    /// Initialize machine learning models
    async fn initialize_ml_models(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut models = self.ml_models.write().await;

        // Anomaly detection model
        let anomaly_model = BehavioralModel {
            model_id: "anomaly_detection".to_string(),
            model_type: ModelType::AnomalyDetection,
            classifier: None, // Will be trained with data
            scaler: None,
            feature_names: vec![
                "temporal_entropy".to_string(),
                "location_entropy".to_string(),
                "device_diversity".to_string(),
                "activity_rate".to_string(),
                "session_duration".to_string(),
            ],
            training_accuracy: 0.0,
            validation_accuracy: 0.0,
            last_trained: Utc::now(),
            training_data_size: 0,
        };

        models.insert("anomaly_detection".to_string(), anomaly_model);

        // Risk classification model
        let risk_model = BehavioralModel {
            model_id: "risk_classification".to_string(),
            model_type: ModelType::RiskClassification,
            classifier: None,
            scaler: None,
            feature_names: vec![
                "failure_rate".to_string(),
                "temporal_anomalies".to_string(),
                "location_anomalies".to_string(),
                "device_changes".to_string(),
                "peer_deviation".to_string(),
            ],
            training_accuracy: 0.0,
            validation_accuracy: 0.0,
            last_trained: Utc::now(),
            training_data_size: 0,
        };

        models.insert("risk_classification".to_string(), risk_model);

        info!("ML models initialized for user behavior profiling");
        Ok(())
    }

    /// Initialize feature extractors
    async fn initialize_feature_extractors(&self) {
        let mut extractors = self.feature_extractors.write().await;

        // Temporal feature extractor
        let temporal_extractor = FeatureExtractor {
            extractor_id: "temporal".to_string(),
            feature_names: vec![
                "login_hour_entropy".to_string(),
                "day_of_week_consistency".to_string(),
                "session_duration_variance".to_string(),
                "inter_arrival_time_mean".to_string(),
                "circadian_rhythm_score".to_string(),
            ],
            normalization_params: HashMap::new(),
        };

        extractors.insert("temporal".to_string(), temporal_extractor);

        // Location feature extractor
        let location_extractor = FeatureExtractor {
            extractor_id: "location".to_string(),
            feature_names: vec![
                "location_entropy".to_string(),
                "geographic_consistency".to_string(),
                "travel_distance_variance".to_string(),
                "country_diversity".to_string(),
                "location_clustering".to_string(),
            ],
            normalization_params: HashMap::new(),
        };

        extractors.insert("location".to_string(), location_extractor);

        info!("Feature extractors initialized");
    }

    /// Analyze user behavior for a given event
    pub async fn analyze_user_behavior(
        &self,
        user_id: &str,
        event: SecurityEvent,
    ) -> Result<BehavioralAnalysisResult, Box<dyn std::error::Error + Send + Sync>> {
        let timer = PROFILE_ANALYSIS_DURATION.start_timer();

        // Queue profile update
        let update_request = ProfileUpdateRequest {
            user_id: user_id.to_string(),
            event: event.clone(),
            update_type: ProfileUpdateType::Incremental,
            priority: UpdatePriority::Normal,
        };

        if let Err(e) = self.profile_update_queue.send(update_request) {
            error!("Failed to queue profile update: {}", e);
        }

        // Get current profile
        let profiles = self.user_profiles.read().await;
        let profile = profiles.get(user_id);

        let mut analysis_result = BehavioralAnalysisResult {
            user_id: user_id.to_string(),
            analysis_timestamp: Utc::now(),
            risk_score: 0.0,
            anomalies_detected: Vec::new(),
            behavioral_insights: BehavioralInsights::default(),
            recommendations: Vec::new(),
            confidence: 0.0,
        };

        if let Some(profile) = profile {
            // Perform immediate analysis
            analysis_result.risk_score = profile.risk_assessment.overall_risk_score;
            analysis_result.confidence = profile.profile_confidence;

            // Check for immediate anomalies
            if let Some(anomaly) = self.detect_immediate_anomaly(profile, &event).await {
                analysis_result.anomalies_detected.push(anomaly);
                BEHAVIORAL_ANOMALIES_FOUND.inc();
            }

            // Generate behavioral insights
            analysis_result.behavioral_insights =
                self.generate_behavioral_insights(profile, &event).await;

            // Generate recommendations
            analysis_result.recommendations = self.generate_recommendations(profile, &event).await;
        } else {
            // New user - create minimal profile
            analysis_result.confidence = 0.1;
            analysis_result
                .recommendations
                .push("Insufficient data for comprehensive analysis".to_string());
        }

        // Update metrics
        USER_PROFILES_ANALYZED.inc();
        let mut stats = self.profiling_statistics.lock().await;
        stats.profiles_analyzed += 1;

        drop(timer);
        Ok(analysis_result)
    }

    /// Detect immediate anomaly in user behavior
    async fn detect_immediate_anomaly(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
    ) -> Option<BehavioralAnomaly> {
        let config = self.config.read().await;

        // Check temporal anomaly
        if let Some(temporal_anomaly) = self.check_temporal_anomaly(profile, event, &config).await {
            return Some(temporal_anomaly);
        }

        // Check location anomaly
        if let Some(location_anomaly) = self.check_location_anomaly(profile, event).await {
            return Some(location_anomaly);
        }

        // Check device anomaly
        if let Some(device_anomaly) = self.check_device_anomaly(profile, event).await {
            return Some(device_anomaly);
        }

        // Check activity volume anomaly
        if let Some(volume_anomaly) = self.check_volume_anomaly(profile, event).await {
            return Some(volume_anomaly);
        }

        None
    }

    /// Check for temporal anomalies
    async fn check_temporal_anomaly(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
        config: &UserProfilingConfig,
    ) -> Option<BehavioralAnomaly> {
        let event_hour = event.timestamp.hour() as u8;
        let expected_hours = &profile.base_profile.typical_login_hours;

        if !expected_hours.is_empty() && !expected_hours.contains(&event_hour) {
            // Calculate how unusual this time is
            let hour_distances: Vec<i32> = expected_hours
                .iter()
                .map(|&h| {
                    let diff = (event_hour as i32 - h as i32).abs();
                    std::cmp::min(diff, 24 - diff) // Handle wrap-around
                })
                .collect();

            let min_distance = hour_distances.iter().min().unwrap_or(&12);

            if *min_distance > 3 {
                // More than 3 hours from any typical time
                let anomaly_score = (*min_distance as f64 / 12.0).min(1.0);

                if anomaly_score > config.anomaly_detection_sensitivity {
                    return Some(BehavioralAnomaly {
                        anomaly_id: Uuid::new_v4().to_string(),
                        detection_timestamp: Utc::now(),
                        anomaly_type: AnomalyType::TemporalAnomaly,
                        severity: if anomaly_score > 0.8 {
                            ThreatSeverity::High
                        } else {
                            ThreatSeverity::Medium
                        },
                        confidence: anomaly_score,
                        affected_metrics: vec!["login_hour".to_string()],
                        anomaly_score,
                        description: format!(
                            "Login at unusual hour: {} (typical hours: {:?})",
                            event_hour, expected_hours
                        ),
                        evidence: AnomalyEvidence {
                            statistical_evidence: StatisticalEvidence {
                                z_scores: [("time_deviation".to_string(), anomaly_score * 3.0)]
                                    .into_iter()
                                    .collect(),
                                p_values: HashMap::new(),
                                chi_squared_stats: HashMap::new(),
                                distribution_tests: HashMap::new(),
                            },
                            temporal_evidence: TemporalEvidence {
                                time_of_occurrence: event.timestamp,
                                expected_time_window: (
                                    event
                                        .timestamp
                                        .with_hour(*expected_hours.first().unwrap_or(&0) as u32)
                                        .unwrap(),
                                    event
                                        .timestamp
                                        .with_hour(*expected_hours.last().unwrap_or(&23) as u32)
                                        .unwrap(),
                                ),
                                temporal_deviation_score: anomaly_score,
                                seasonal_anomaly_score: 0.0,
                            },
                            comparative_evidence: ComparativeEvidence {
                                peer_deviation_scores: HashMap::new(),
                                outlier_rankings: HashMap::new(),
                                comparative_confidence: 0.5,
                            },
                            supporting_events: vec![event.event_id.clone()],
                        },
                        resolved: false,
                        resolution_timestamp: None,
                    });
                }
            }
        }

        None
    }

    /// Check for location anomalies
    async fn check_location_anomaly(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
    ) -> Option<BehavioralAnomaly> {
        if let Some(event_location) = &event.location {
            let typical_countries = &profile.base_profile.typical_countries;

            if !typical_countries.is_empty() && !typical_countries.contains(&event_location.country)
            {
                let anomaly_score = 0.8; // High score for new country

                return Some(BehavioralAnomaly {
                    anomaly_id: Uuid::new_v4().to_string(),
                    detection_timestamp: Utc::now(),
                    anomaly_type: AnomalyType::LocationAnomaly,
                    severity: ThreatSeverity::High,
                    confidence: anomaly_score,
                    affected_metrics: vec!["location_country".to_string()],
                    anomaly_score,
                    description: format!(
                        "Login from new country: {} (typical: {:?})",
                        event_location.country, typical_countries
                    ),
                    evidence: AnomalyEvidence {
                        statistical_evidence: StatisticalEvidence {
                            z_scores: [("location_deviation".to_string(), anomaly_score * 3.0)]
                                .into_iter()
                                .collect(),
                            p_values: HashMap::new(),
                            chi_squared_stats: HashMap::new(),
                            distribution_tests: HashMap::new(),
                        },
                        temporal_evidence: TemporalEvidence {
                            time_of_occurrence: event.timestamp,
                            expected_time_window: (event.timestamp, event.timestamp),
                            temporal_deviation_score: 0.0,
                            seasonal_anomaly_score: 0.0,
                        },
                        comparative_evidence: ComparativeEvidence {
                            peer_deviation_scores: HashMap::new(),
                            outlier_rankings: HashMap::new(),
                            comparative_confidence: 0.7,
                        },
                        supporting_events: vec![event.event_id.clone()],
                    },
                    resolved: false,
                    resolution_timestamp: None,
                });
            }
        }

        None
    }

    /// Check for device anomalies
    async fn check_device_anomaly(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
    ) -> Option<BehavioralAnomaly> {
        if let Some(device_fingerprint) = &event.device_fingerprint {
            let typical_devices = &profile.base_profile.typical_devices;

            if !typical_devices.is_empty() && !typical_devices.contains(device_fingerprint) {
                let anomaly_score = 0.6; // Medium score for new device

                return Some(BehavioralAnomaly {
                    anomaly_id: Uuid::new_v4().to_string(),
                    detection_timestamp: Utc::now(),
                    anomaly_type: AnomalyType::DeviceAnomaly,
                    severity: ThreatSeverity::Medium,
                    confidence: anomaly_score,
                    affected_metrics: vec!["device_fingerprint".to_string()],
                    anomaly_score,
                    description: "Login from new device detected".to_string(),
                    evidence: AnomalyEvidence {
                        statistical_evidence: StatisticalEvidence {
                            z_scores: [("device_novelty".to_string(), anomaly_score * 2.0)]
                                .into_iter()
                                .collect(),
                            p_values: HashMap::new(),
                            chi_squared_stats: HashMap::new(),
                            distribution_tests: HashMap::new(),
                        },
                        temporal_evidence: TemporalEvidence {
                            time_of_occurrence: event.timestamp,
                            expected_time_window: (event.timestamp, event.timestamp),
                            temporal_deviation_score: 0.0,
                            seasonal_anomaly_score: 0.0,
                        },
                        comparative_evidence: ComparativeEvidence {
                            peer_deviation_scores: HashMap::new(),
                            outlier_rankings: HashMap::new(),
                            comparative_confidence: 0.6,
                        },
                        supporting_events: vec![event.event_id.clone()],
                    },
                    resolved: false,
                    resolution_timestamp: None,
                });
            }
        }

        None
    }

    /// Check for volume anomalies
    async fn check_volume_anomaly(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
    ) -> Option<BehavioralAnomaly> {
        // Get recent activity count
        let recent_events = self
            .count_recent_events(&profile.base_profile.user_id, Duration::hours(1))
            .await;
        let baseline_rate = profile.base_profile.request_rate_baseline;

        if baseline_rate > 0.0 && recent_events > (baseline_rate * 3.0) as u32 {
            let anomaly_score = ((recent_events as f64 / baseline_rate) - 1.0).min(1.0);

            return Some(BehavioralAnomaly {
                anomaly_id: Uuid::new_v4().to_string(),
                detection_timestamp: Utc::now(),
                anomaly_type: AnomalyType::VolumeAnomaly,
                severity: if anomaly_score > 0.8 {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Medium
                },
                confidence: anomaly_score,
                affected_metrics: vec!["activity_rate".to_string()],
                anomaly_score,
                description: format!(
                    "Unusual activity volume: {} events in last hour (baseline: {})",
                    recent_events, baseline_rate
                ),
                evidence: AnomalyEvidence {
                    statistical_evidence: StatisticalEvidence {
                        z_scores: [("activity_rate".to_string(), anomaly_score * 3.0)]
                            .into_iter()
                            .collect(),
                        p_values: HashMap::new(),
                        chi_squared_stats: HashMap::new(),
                        distribution_tests: HashMap::new(),
                    },
                    temporal_evidence: TemporalEvidence {
                        time_of_occurrence: event.timestamp,
                        expected_time_window: (
                            event.timestamp - Duration::hours(1),
                            event.timestamp,
                        ),
                        temporal_deviation_score: anomaly_score,
                        seasonal_anomaly_score: 0.0,
                    },
                    comparative_evidence: ComparativeEvidence {
                        peer_deviation_scores: HashMap::new(),
                        outlier_rankings: HashMap::new(),
                        comparative_confidence: 0.7,
                    },
                    supporting_events: vec![event.event_id.clone()],
                },
                resolved: false,
                resolution_timestamp: None,
            });
        }

        None
    }

    /// Count recent events for a user (simplified implementation)
    async fn count_recent_events(&self, user_id: &str, duration: Duration) -> u32 {
        // In a real implementation, this would query the event store
        // For now, return a placeholder value
        5
    }

    /// Generate behavioral insights
    async fn generate_behavioral_insights(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
    ) -> BehavioralInsights {
        BehavioralInsights {
            consistency_score: profile
                .behavioral_features
                .temporal_features
                .weekly_pattern_consistency,
            predictability_score: profile
                .behavioral_features
                .temporal_features
                .activity_circadian_rhythm,
            risk_factors: profile
                .risk_assessment
                .risk_factors
                .iter()
                .map(|rf| rf.factor_name.clone())
                .collect(),
            behavioral_trends: vec![profile.risk_assessment.risk_trend.clone()],
            peer_comparison_summary: format!(
                "{}th percentile among peers",
                (profile.peer_comparisons.percentile_rank * 100.0) as u8
            ),
            recommendations: Vec::new(),
        }
    }

    /// Generate recommendations based on analysis
    async fn generate_recommendations(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        event: &SecurityEvent,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if profile.risk_assessment.overall_risk_score > 0.7 {
            recommendations
                .push("Consider requiring additional authentication factors".to_string());
        }

        if !profile.anomaly_history.is_empty() {
            recommendations.push("Monitor for recurring anomaly patterns".to_string());
        }

        if profile.peer_comparisons.percentile_rank > 0.9 {
            recommendations.push("User behavior significantly deviates from peers".to_string());
        }

        recommendations
    }

    /// Start profile processor background task
    async fn start_profile_processor(&self) {
        let profile_update_receiver = self.profile_update_receiver.clone();
        let user_profiles = self.user_profiles.clone();
        let time_series_data = self.time_series_data.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            info!("Starting user profile processor");

            while let Ok(update_request) = profile_update_receiver.recv_async().await {
                // Process the profile update
                let start_time = std::time::SystemTime::now();

                match update_request.update_type {
                    ProfileUpdateType::Incremental => {
                        Self::process_incremental_update(
                            &user_profiles,
                            &time_series_data,
                            &update_request,
                        )
                        .await;
                    }
                    ProfileUpdateType::FullRecomputation => {
                        Self::process_full_recomputation(&user_profiles, &update_request).await;
                    }
                    ProfileUpdateType::TimeSeriesUpdate => {
                        Self::process_time_series_update(&time_series_data, &update_request).await;
                    }
                    _ => {
                        debug!(
                            "Update type {:?} not yet implemented",
                            update_request.update_type
                        );
                    }
                }

                if let Ok(duration) = start_time.elapsed() {
                    debug!("Profile update processed in {}ms", duration.as_millis());
                }
            }
        });
    }

    /// Process incremental profile update
    async fn process_incremental_update(
        user_profiles: &Arc<RwLock<HashMap<String, EnhancedUserBehaviorProfile>>>,
        time_series_data: &Arc<RwLock<HashMap<String, HashMap<String, BehavioralTimeSeries>>>>,
        update_request: &ProfileUpdateRequest,
    ) {
        let mut profiles = user_profiles.write().await;
        let profile = profiles
            .entry(update_request.user_id.clone())
            .or_insert_with(|| {
                let base_profile = UserBehaviorProfile::new(update_request.user_id.clone());
                EnhancedUserBehaviorProfile {
                    base_profile,
                    time_series_metrics: HashMap::new(),
                    behavioral_features: BehavioralFeatureVector::default(),
                    risk_assessment: RiskAssessment::default(),
                    peer_comparisons: PeerComparisons::default(),
                    anomaly_history: Vec::new(),
                    model_predictions: Vec::new(),
                    profile_confidence: 0.1,
                    last_comprehensive_analysis: None,
                }
            });

        // Update base profile
        profile
            .base_profile
            .update_with_event(&update_request.event);
        profile.base_profile.calculate_behavior_entropy();

        // Update time series data
        let mut ts_data = time_series_data.write().await;
        let user_ts = ts_data
            .entry(update_request.user_id.clone())
            .or_insert_with(HashMap::new);

        // Add data point for login frequency
        if matches!(
            update_request.event.event_type,
            SecurityEventType::AuthenticationSuccess
        ) {
            let ts = user_ts
                .entry("login_frequency".to_string())
                .or_insert_with(|| BehavioralTimeSeries {
                    series_id: Uuid::new_v4().to_string(),
                    user_id: update_request.user_id.clone(),
                    metric_name: "login_frequency".to_string(),
                    data_points: VecDeque::new(),
                    statistical_summary: SeriesStatistics::default(),
                    trend_analysis: TrendAnalysis::default(),
                    seasonality: SeasonalityAnalysis::default(),
                    forecast: None,
                    last_updated: Utc::now(),
                });

            ts.data_points.push_back(TimeSeriesPoint {
                timestamp: update_request.event.timestamp,
                value: 1.0,
                confidence: 1.0,
                anomaly_score: None,
                metadata: HashMap::new(),
            });

            // Keep only recent data points
            let cutoff = Utc::now() - Duration::days(30);
            ts.data_points.retain(|point| point.timestamp > cutoff);
            ts.last_updated = Utc::now();
        }

        // Update profile confidence based on data availability
        let event_count = profile.base_profile.security_events_count;
        profile.profile_confidence = (event_count as f64 / 100.0).min(1.0);
    }

    /// Process full recomputation
    async fn process_full_recomputation(
        user_profiles: &Arc<RwLock<HashMap<String, EnhancedUserBehaviorProfile>>>,
        update_request: &ProfileUpdateRequest,
    ) {
        // TODO: Implement full profile recomputation
        // This would involve:
        // 1. Fetching all historical events for the user
        // 2. Recomputing all behavioral features
        // 3. Rerunning ML models
        // 4. Updating risk assessments
        // 5. Refreshing peer comparisons

        debug!(
            "Full recomputation requested for user: {}",
            update_request.user_id
        );
    }

    /// Process time series update
    async fn process_time_series_update(
        time_series_data: &Arc<RwLock<HashMap<String, HashMap<String, BehavioralTimeSeries>>>>,
        update_request: &ProfileUpdateRequest,
    ) {
        // TODO: Implement sophisticated time series analysis
        // This would involve:
        // 1. Statistical analysis of time series data
        // 2. Trend detection and forecasting
        // 3. Seasonality analysis
        // 4. Change point detection
        // 5. Anomaly detection in time series

        debug!(
            "Time series update requested for user: {}",
            update_request.user_id
        );
    }

    /// Start other background tasks (simplified implementations)
    async fn start_time_series_analyzer(&self) {
        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(900)); // 15 minutes
            loop {
                interval.tick().await;
                debug!("Time series analysis cycle completed");
            }
        });
    }

    async fn start_anomaly_detector(&self) {
        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(300)); // 5 minutes
            loop {
                interval.tick().await;
                debug!("Anomaly detection cycle completed");
            }
        });
    }

    async fn start_risk_assessor(&self) {
        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(600)); // 10 minutes
            loop {
                interval.tick().await;
                debug!("Risk assessment cycle completed");
            }
        });
    }

    async fn start_model_trainer(&self) {
        tokio::spawn(async move {
            let mut interval = interval(TokioDuration::from_secs(3600)); // 1 hour
            loop {
                interval.tick().await;
                debug!("ML model training cycle completed");
            }
        });
    }

    /// Get user behavior analysis result
    pub async fn get_user_profile(&self, user_id: &str) -> Option<EnhancedUserBehaviorProfile> {
        let profiles = self.user_profiles.read().await;
        profiles.get(user_id).cloned()
    }

    /// Get profiling statistics
    pub async fn get_statistics(&self) -> ProfilingStatistics {
        let stats = self.profiling_statistics.lock().await;
        stats.clone()
    }

    /// Shutdown the profiler
    pub async fn shutdown(&self) {
        info!("Shutting down Advanced User Behavior Profiler");

        // Save state to Redis
        // Close connections
        let mut redis_client = self.redis_client.lock().await;
        *redis_client = None;

        info!("Advanced User Behavior Profiler shutdown complete");
    }
}

/// Result of behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralAnalysisResult {
    pub user_id: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub risk_score: f64,
    pub anomalies_detected: Vec<BehavioralAnomaly>,
    pub behavioral_insights: BehavioralInsights,
    pub recommendations: Vec<String>,
    pub confidence: f64,
}

/// Behavioral insights from analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BehavioralInsights {
    pub consistency_score: f64,
    pub predictability_score: f64,
    pub risk_factors: Vec<String>,
    pub behavioral_trends: Vec<TrendDirection>,
    pub peer_comparison_summary: String,
    pub recommendations: Vec<String>,
}

// Default implementations for complex structures
impl Default for BehavioralFeatureVector {
    fn default() -> Self {
        Self {
            temporal_features: TemporalFeatures::default(),
            location_features: LocationFeatures::default(),
            device_features: DeviceFeatures::default(),
            network_features: NetworkFeatures::default(),
            activity_features: ActivityFeatures::default(),
            normalized_vector: Vec::new(),
            feature_importance: HashMap::new(),
        }
    }
}

impl Default for RiskAssessment {
    fn default() -> Self {
        Self {
            overall_risk_score: 0.0,
            risk_factors: Vec::new(),
            risk_trend: TrendDirection::Unknown,
            confidence_level: 0.0,
            risk_category: RiskCategory::VeryLow,
            recommended_actions: Vec::new(),
            assessment_timestamp: Utc::now(),
        }
    }
}

impl Default for PeerComparisons {
    fn default() -> Self {
        Self {
            peer_group: "default".to_string(),
            percentile_rank: 0.5,
            deviation_from_peer_average: 0.0,
            similar_users: Vec::new(),
            outlier_metrics: Vec::new(),
            peer_comparison_confidence: 0.0,
        }
    }
}

impl Default for SeriesStatistics {
    fn default() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            std_dev: 0.0,
            min: 0.0,
            max: 0.0,
            median: 0.0,
            percentiles: BTreeMap::new(),
            skewness: 0.0,
            kurtosis: 0.0,
        }
    }
}

impl Default for TrendAnalysis {
    fn default() -> Self {
        Self {
            trend_direction: TrendDirection::Unknown,
            trend_strength: 0.0,
            change_points: Vec::new(),
            linear_regression: LinearRegressionResult {
                slope: 0.0,
                intercept: 0.0,
                r_squared: 0.0,
                p_value: 1.0,
                confidence_interval: (0.0, 0.0),
            },
            volatility: 0.0,
        }
    }
}

impl Default for SeasonalityAnalysis {
    fn default() -> Self {
        Self {
            has_seasonality: false,
            seasonal_periods: Vec::new(),
            dominant_frequencies: Vec::new(),
            seasonal_strength: 0.0,
        }
    }
}

// Default implementations for feature structures
impl Default for TemporalFeatures {
    fn default() -> Self {
        Self {
            login_time_entropy: 0.0,
            activity_circadian_rhythm: 0.0,
            weekly_pattern_consistency: 0.0,
            session_duration_stability: 0.0,
            inter_arrival_time_distribution: Vec::new(),
            burst_pattern_indicators: Vec::new(),
        }
    }
}

impl Default for LocationFeatures {
    fn default() -> Self {
        Self {
            location_entropy: 0.0,
            geographic_consistency: 0.0,
            travel_pattern_anomaly: 0.0,
            location_clustering_coefficient: 0.0,
            distance_travelled_stats: SeriesStatistics::default(),
        }
    }
}

impl Default for DeviceFeatures {
    fn default() -> Self {
        Self {
            device_diversity_score: 0.0,
            device_switching_frequency: 0.0,
            device_consistency_score: 0.0,
            browser_pattern_score: 0.0,
            os_consistency_score: 0.0,
        }
    }
}

impl Default for NetworkFeatures {
    fn default() -> Self {
        Self {
            ip_address_entropy: 0.0,
            network_diversity_score: 0.0,
            asn_consistency_score: 0.0,
            vpn_usage_indicators: 0.0,
            tor_usage_indicators: 0.0,
        }
    }
}

impl Default for ActivityFeatures {
    fn default() -> Self {
        Self {
            authentication_rate_stability: 0.0,
            resource_access_patterns: 0.0,
            api_usage_consistency: 0.0,
            error_rate_indicators: 0.0,
            session_management_patterns: 0.0,
        }
    }
}
