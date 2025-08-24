//! Threat User Profiling System
//!
//! Advanced behavioral analysis and threat detection system using machine learning
//! and statistical analysis to identify suspicious user behavior patterns.

pub mod behavioral;
pub mod temporal;
pub mod ml;
pub mod risk;
pub mod profiles;
pub mod profiler;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

pub use behavioral::*;
pub use temporal::*;
pub use ml::*;
pub use risk::*;
pub use profiles::*;
pub use profiler::*;

/// Main threat user profiling system
pub struct ThreatUserProfiler {
    /// Configuration
    config: Arc<RwLock<UserProfilingConfig>>,
    
    /// Behavioral analysis engine
    behavioral_analyzer: Arc<BehavioralAnalyzer>,
    
    /// Temporal analysis engine
    temporal_analyzer: Arc<TemporalAnalyzer>,
    
    /// Machine learning engine
    ml_engine: Arc<MachineLearningEngine>,
    
    /// Risk assessment engine
    risk_assessor: Arc<RiskAssessmentEngine>,
    
    /// Profile manager
    profile_manager: Arc<ProfileManager>,
    
    /// System metrics
    metrics: Arc<Mutex<ProfilingMetrics>>,
}

/// User profiling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfilingConfig {
    /// Enable user profiling
    pub enabled: bool,
    
    /// Profile retention period
    pub profile_retention_days: u64,
    
    /// Minimum events for baseline
    pub min_events_for_baseline: u32,
    
    /// Anomaly detection sensitivity
    pub anomaly_detection_sensitivity: f64,
    
    /// Time series analysis window
    pub time_series_window_hours: u64,
    
    /// Profile update interval
    pub profile_update_interval_seconds: u64,
    
    /// ML model retraining interval
    pub ml_model_retraining_hours: u64,
    
    /// Behavioral feature configuration
    pub behavioral_features: BehavioralFeatureConfig,
    
    /// Temporal analysis configuration
    pub temporal_analysis: TemporalAnalysisConfig,
    
    /// Risk scoring configuration
    pub risk_scoring: RiskScoringConfig,
    
    /// Redis configuration
    pub redis_config: ProfilingRedisConfig,
}

/// Behavioral feature configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFeatureConfig {
    /// Enable temporal features
    pub temporal_features_enabled: bool,
    
    /// Enable location features
    pub location_features_enabled: bool,
    
    /// Enable device features
    pub device_features_enabled: bool,
    
    /// Enable network features
    pub network_features_enabled: bool,
    
    /// Enable activity features
    pub activity_features_enabled: bool,
    
    /// Feature normalization settings
    pub feature_normalization: FeatureNormalization,
    
    /// Feature weights
    pub feature_weights: HashMap<String, f64>,
}

/// Feature normalization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureNormalization {
    /// Normalization method
    pub method: NormalizationMethod,
    
    /// Outlier threshold
    pub outlier_threshold: f64,
    
    /// Clip outliers
    pub clip_outliers: bool,
}

/// Normalization methods
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NormalizationMethod {
    /// Standard score (z-score)
    StandardScore,
    /// Min-max normalization
    MinMax,
    /// Robust scaling
    Robust,
    /// Quantile normalization
    Quantile,
}

/// Temporal analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalAnalysisConfig {
    /// Enable temporal analysis
    pub enabled: bool,
    
    /// Enable seasonality detection
    pub seasonality_detection: bool,
    
    /// Enable trend analysis
    pub trend_analysis: bool,
    
    /// Enable change point detection
    pub change_point_detection: bool,
    
    /// Forecasting configuration
    pub forecasting_config: ForecastingConfig,
    
    /// Time window configurations
    pub time_windows: Vec<TimeWindow>,
}

/// Forecasting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastingConfig {
    /// Enable forecasting
    pub enabled: bool,
    
    /// Forecast horizon (hours)
    pub forecast_horizon_hours: u64,
    
    /// Forecast models to use
    pub models: Vec<ForecastModel>,
    
    /// Model selection strategy
    pub model_selection: ModelSelectionStrategy,
    
    /// Confidence level
    pub confidence_level: f64,
}

/// Forecast models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForecastModel {
    /// Linear regression
    LinearRegression,
    /// ARIMA model
    Arima,
    /// Exponential smoothing
    ExponentialSmoothing,
    /// Neural network
    NeuralNetwork,
    /// Custom model
    Custom(String),
}

/// Model selection strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModelSelectionStrategy {
    /// Best accuracy
    BestAccuracy,
    /// Ensemble of models
    Ensemble,
    /// Weighted average
    WeightedAverage,
    /// Custom strategy
    Custom(String),
}

/// Time window configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Window name
    pub name: String,
    
    /// Window duration
    pub duration: Duration,
    
    /// Window overlap
    pub overlap: Duration,
    
    /// Aggregation method
    pub aggregation: AggregationMethod,
}

/// Aggregation methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationMethod {
    /// Mean aggregation
    Mean,
    /// Median aggregation
    Median,
    /// Sum aggregation
    Sum,
    /// Count aggregation
    Count,
    /// Maximum value
    Max,
    /// Minimum value
    Min,
    /// Standard deviation
    StandardDeviation,
}

/// Risk scoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoringConfig {
    /// Enable risk scoring
    pub enabled: bool,
    
    /// Risk scoring algorithm
    pub algorithm: RiskScoringAlgorithm,
    
    /// Risk thresholds
    pub thresholds: RiskThresholds,
    
    /// Risk factors configuration
    pub risk_factors: Vec<RiskFactorConfig>,
    
    /// Scoring weights
    pub scoring_weights: HashMap<String, f64>,
}

/// Risk scoring algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskScoringAlgorithm {
    /// Weighted sum
    WeightedSum,
    /// Bayesian scoring
    Bayesian,
    /// Machine learning based
    MachineLearning,
    /// Custom algorithm
    Custom(String),
}

/// Risk thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Low risk threshold
    pub low_risk: f64,
    
    /// Medium risk threshold
    pub medium_risk: f64,
    
    /// High risk threshold
    pub high_risk: f64,
    
    /// Critical risk threshold
    pub critical_risk: f64,
}

/// Risk factor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactorConfig {
    /// Factor name
    pub name: String,
    
    /// Factor weight
    pub weight: f64,
    
    /// Factor threshold
    pub threshold: f64,
    
    /// Factor enabled
    pub enabled: bool,
}

/// Redis configuration for profiling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingRedisConfig {
    /// Redis connection URL
    pub url: String,
    
    /// Connection pool size
    pub pool_size: u32,
    
    /// Connection timeout
    pub connection_timeout: Duration,
    
    /// Key prefix for profiling data
    pub key_prefix: String,
    
    /// Data expiration time
    pub expiration_time: Duration,
}

/// Enhanced user behavior profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedUserBehaviorProfile {
    /// User ID
    pub user_id: String,
    
    /// Profile creation timestamp
    pub created_at: DateTime<Utc>,
    
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    
    /// Behavioral feature vector
    pub feature_vector: BehavioralFeatureVector,
    
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
    
    /// Behavioral baseline
    pub baseline: BehavioralBaseline,
    
    /// Anomaly history
    pub anomaly_history: Vec<BehavioralAnomaly>,
    
    /// Profile confidence score
    pub confidence_score: f64,
    
    /// Profile metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Behavioral feature vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFeatureVector {
    /// Temporal features
    pub temporal_features: TemporalFeatures,
    
    /// Location features
    pub location_features: LocationFeatures,
    
    /// Device features
    pub device_features: DeviceFeatures,
    
    /// Network features
    pub network_features: NetworkFeatures,
    
    /// Activity features
    pub activity_features: ActivityFeatures,
    
    /// Feature vector timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Feature vector version
    pub version: String,
}

/// Temporal behavioral features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalFeatures {
    /// Login time patterns
    pub login_time_patterns: Vec<TimePattern>,
    
    /// Activity duration patterns
    pub activity_duration_patterns: Vec<DurationPattern>,
    
    /// Frequency patterns
    pub frequency_patterns: Vec<FrequencyPattern>,
    
    /// Seasonal patterns
    pub seasonal_patterns: Vec<SeasonalPattern>,
}

/// Time pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePattern {
    /// Pattern type
    pub pattern_type: TimePatternType,
    
    /// Pattern strength
    pub strength: f64,
    
    /// Pattern confidence
    pub confidence: f64,
    
    /// Pattern parameters
    pub parameters: HashMap<String, f64>,
}

/// Time pattern types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimePatternType {
    /// Daily pattern
    Daily,
    /// Weekly pattern
    Weekly,
    /// Monthly pattern
    Monthly,
    /// Hourly pattern
    Hourly,
    /// Custom pattern
    Custom(String),
}

/// Duration pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationPattern {
    /// Average duration
    pub average_duration: Duration,
    
    /// Duration variance
    pub variance: f64,
    
    /// Duration distribution
    pub distribution: DistributionType,
    
    /// Pattern confidence
    pub confidence: f64,
}

/// Distribution types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DistributionType {
    /// Normal distribution
    Normal,
    /// Log-normal distribution
    LogNormal,
    /// Exponential distribution
    Exponential,
    /// Uniform distribution
    Uniform,
    /// Custom distribution
    Custom(String),
}

/// Frequency pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrequencyPattern {
    /// Pattern frequency
    pub frequency: f64,
    
    /// Frequency variance
    pub variance: f64,
    
    /// Pattern regularity
    pub regularity: f64,
    
    /// Pattern trend
    pub trend: TrendDirection,
}

/// Trend directions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    /// Increasing trend
    Increasing,
    /// Decreasing trend
    Decreasing,
    /// Stable trend
    Stable,
    /// Cyclical trend
    Cyclical,
}

/// Seasonal pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPattern {
    /// Season type
    pub season_type: SeasonType,
    
    /// Pattern amplitude
    pub amplitude: f64,
    
    /// Pattern phase
    pub phase: f64,
    
    /// Pattern strength
    pub strength: f64,
}

/// Season types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeasonType {
    /// Daily seasonality
    Daily,
    /// Weekly seasonality
    Weekly,
    /// Monthly seasonality
    Monthly,
    /// Yearly seasonality
    Yearly,
    /// Custom seasonality
    Custom(Duration),
}

/// Profiling metrics
#[derive(Debug, Clone, Default)]
pub struct ProfilingMetrics {
    /// Total profiles analyzed
    pub total_profiles_analyzed: u64,
    
    /// Behavioral anomalies found
    pub behavioral_anomalies_found: u64,
    
    /// Average analysis duration
    pub avg_analysis_duration: Duration,
    
    /// Active user profiles
    pub active_user_profiles: u64,
    
    /// Time series predictions made
    pub time_series_predictions: u64,
    
    /// ML model accuracy
    pub ml_model_accuracy: f64,
    
    /// Risk assessments performed
    pub risk_assessments_performed: u64,
    
    /// Last updated timestamp
    pub last_updated: DateTime<Utc>,
}

impl ThreatUserProfiler {
    /// Create new threat user profiler
    pub async fn new(config: UserProfilingConfig) -> Result<Self, ProfilingError> {
        let behavioral_analyzer = Arc::new(BehavioralAnalyzer::new(&config.behavioral_features).await?);
        let temporal_analyzer = Arc::new(TemporalAnalyzer::new(&config.temporal_analysis).await?);
        let ml_engine = Arc::new(MachineLearningEngine::new().await?);
        let risk_assessor = Arc::new(RiskAssessmentEngine::new(&config.risk_scoring).await?);
        let profile_manager = Arc::new(ProfileManager::new(&config.redis_config).await?);
        
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            behavioral_analyzer,
            temporal_analyzer,
            ml_engine,
            risk_assessor,
            profile_manager,
            metrics: Arc::new(Mutex::new(ProfilingMetrics::default())),
        })
    }
    
    /// Analyze user behavior and update profile
    pub async fn analyze_user_behavior(
        &self,
        user_id: &str,
        events: Vec<UserEvent>,
    ) -> Result<EnhancedUserBehaviorProfile, ProfilingError> {
        let start_time = std::time::Instant::now();
        
        tracing::info!("Analyzing behavior for user: {}", user_id);
        
        // Get existing profile or create new one
        let mut profile = self.profile_manager.get_profile(user_id).await?
            .unwrap_or_else(|| self.create_new_profile(user_id));
        
        // Extract behavioral features
        let feature_vector = self.behavioral_analyzer.extract_features(&events).await?;
        
        // Perform temporal analysis
        let temporal_analysis = self.temporal_analyzer.analyze_patterns(&events).await?;
        
        // Update ML models with new data
        self.ml_engine.update_models(&events, &feature_vector).await?;
        
        // Perform risk assessment
        let risk_assessment = self.risk_assessor.assess_risk(&feature_vector, &temporal_analysis).await?;
        
        // Detect anomalies
        let anomalies = self.detect_anomalies(&profile, &feature_vector).await?;
        
        // Update profile
        profile.feature_vector = feature_vector;
        profile.risk_assessment = risk_assessment;
        profile.updated_at = Utc::now();
        
        // Add new anomalies to history
        profile.anomaly_history.extend(anomalies);
        
        // Update confidence score
        profile.confidence_score = self.calculate_confidence_score(&profile).await?;
        
        // Store updated profile
        self.profile_manager.store_profile(&profile).await?;
        
        // Update metrics
        let mut metrics = self.metrics.lock().await;
        metrics.total_profiles_analyzed += 1;
        metrics.behavioral_anomalies_found += profile.anomaly_history.len() as u64;
        metrics.avg_analysis_duration = start_time.elapsed();
        metrics.last_updated = Utc::now();
        
        tracing::info!("Completed behavior analysis for user: {} in {:?}", user_id, start_time.elapsed());
        
        Ok(profile)
    }
    
    /// Create new user profile
    fn create_new_profile(&self, user_id: &str) -> EnhancedUserBehaviorProfile {
        EnhancedUserBehaviorProfile {
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            feature_vector: BehavioralFeatureVector::default(),
            risk_assessment: RiskAssessment::default(),
            baseline: BehavioralBaseline::default(),
            anomaly_history: Vec::new(),
            confidence_score: 0.0,
            metadata: HashMap::new(),
        }
    }
    
    /// Detect behavioral anomalies
    async fn detect_anomalies(
        &self,
        profile: &EnhancedUserBehaviorProfile,
        current_features: &BehavioralFeatureVector,
    ) -> Result<Vec<BehavioralAnomaly>, ProfilingError> {
        // Use ML engine for anomaly detection
        self.ml_engine.detect_anomalies(profile, current_features).await
    }
    
    /// Calculate profile confidence score
    async fn calculate_confidence_score(
        &self,
        profile: &EnhancedUserBehaviorProfile,
    ) -> Result<f64, ProfilingError> {
        // Calculate confidence based on data quality and quantity
        let data_points = profile.baseline.total_events;
        let time_span = (Utc::now() - profile.created_at).num_days();
        
        let data_quality_score = if data_points >= 100 { 1.0 } else { data_points as f64 / 100.0 };
        let temporal_coverage_score = if time_span >= 30 { 1.0 } else { time_span as f64 / 30.0 };
        
        Ok((data_quality_score + temporal_coverage_score) / 2.0)
    }
    
    /// Get profiling metrics
    pub async fn get_metrics(&self) -> ProfilingMetrics {
        self.metrics.lock().await.clone()
    }
}

/// User event for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEvent {
    /// Event ID
    pub event_id: String,
    
    /// User ID
    pub user_id: String,
    
    /// Event type
    pub event_type: UserEventType,
    
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Event data
    pub data: HashMap<String, serde_json::Value>,
    
    /// Event source
    pub source: String,
}

/// User event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserEventType {
    /// Login event
    Login,
    /// Logout event
    Logout,
    /// API access
    ApiAccess,
    /// Resource access
    ResourceAccess,
    /// Configuration change
    ConfigurationChange,
    /// Data access
    DataAccess,
    /// Custom event
    Custom(String),
}

/// Profiling errors
#[derive(Debug, Clone)]
pub enum ProfilingError {
    /// Configuration error
    ConfigurationError(String),
    /// Data processing error
    DataProcessingError(String),
    /// ML model error
    ModelError(String),
    /// Storage error
    StorageError(String),
    /// Analysis error
    AnalysisError(String),
    /// Internal error
    InternalError(String),
}

impl std::fmt::Display for ProfilingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfilingError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            ProfilingError::DataProcessingError(msg) => write!(f, "Data processing error: {}", msg),
            ProfilingError::ModelError(msg) => write!(f, "ML model error: {}", msg),
            ProfilingError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            ProfilingError::AnalysisError(msg) => write!(f, "Analysis error: {}", msg),
            ProfilingError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for ProfilingError {}

impl Default for UserProfilingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            profile_retention_days: 90,
            min_events_for_baseline: 50,
            anomaly_detection_sensitivity: 0.8,
            time_series_window_hours: 24,
            profile_update_interval_seconds: 300,
            ml_model_retraining_hours: 24,
            behavioral_features: BehavioralFeatureConfig {
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
                feature_weights: HashMap::new(),
            },
            temporal_analysis: TemporalAnalysisConfig {
                enabled: true,
                seasonality_detection: true,
                trend_analysis: true,
                change_point_detection: true,
                forecasting_config: ForecastingConfig {
                    enabled: true,
                    forecast_horizon_hours: 24,
                    models: vec![ForecastModel::LinearRegression, ForecastModel::ExponentialSmoothing],
                    model_selection: ModelSelectionStrategy::BestAccuracy,
                    confidence_level: 0.95,
                },
                time_windows: vec![
                    TimeWindow {
                        name: "hourly".to_string(),
                        duration: Duration::hours(1),
                        overlap: Duration::minutes(15),
                        aggregation: AggregationMethod::Mean,
                    },
                    TimeWindow {
                        name: "daily".to_string(),
                        duration: Duration::days(1),
                        overlap: Duration::hours(6),
                        aggregation: AggregationMethod::Mean,
                    },
                ],
            },
            risk_scoring: RiskScoringConfig {
                enabled: true,
                algorithm: RiskScoringAlgorithm::WeightedSum,
                thresholds: RiskThresholds {
                    low_risk: 0.3,
                    medium_risk: 0.6,
                    high_risk: 0.8,
                    critical_risk: 0.95,
                },
                risk_factors: vec![],
                scoring_weights: HashMap::new(),
            },
            redis_config: ProfilingRedisConfig {
                url: "redis://localhost:6379".to_string(),
                pool_size: 10,
                connection_timeout: Duration::from_secs(5),
                key_prefix: "threat_profiling:".to_string(),
                expiration_time: Duration::from_secs(86400 * 90), // 90 days
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_profiling_config_default() {
        let config = UserProfilingConfig::default();
        assert!(config.enabled);
        assert_eq!(config.profile_retention_days, 90);
        assert_eq!(config.min_events_for_baseline, 50);
        assert_eq!(config.anomaly_detection_sensitivity, 0.8);
    }

    #[test]
    fn test_behavioral_feature_vector_creation() {
        let feature_vector = BehavioralFeatureVector::default();
        assert_eq!(feature_vector.version, "1.0");
        // Test that all feature categories are present
        assert!(feature_vector.temporal_features.login_time_patterns.is_empty());
    }

    #[test]
    fn test_risk_thresholds_ordering() {
        let thresholds = RiskThresholds {
            low_risk: 0.3,
            medium_risk: 0.6,
            high_risk: 0.8,
            critical_risk: 0.95,
        };
        
        assert!(thresholds.low_risk < thresholds.medium_risk);
        assert!(thresholds.medium_risk < thresholds.high_risk);
        assert!(thresholds.high_risk < thresholds.critical_risk);
    }
}
