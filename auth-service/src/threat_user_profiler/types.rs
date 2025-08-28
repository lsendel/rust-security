use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

// Import SecurityEventType from core security module
use crate::core::security::SecurityEventType;

/// Geographic location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub country: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
}

/// User security event for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSecurityEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub location: Option<GeoLocation>,
    pub device_fingerprint: Option<String>,
    pub session_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Time series data point for behavioral analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub metadata: HashMap<String, String>,
}

/// Behavioral time series with statistical analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralTimeSeries {
    pub user_id: Uuid,
    pub feature_name: String,
    pub data_points: VecDeque<TimeSeriesPoint>,
    pub window_size: usize,
    pub statistics: Option<SeriesStatistics>,
}

/// Statistical analysis of time series data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeriesStatistics {
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub variance: f64,
    pub min: f64,
    pub max: f64,
    pub percentile_95: f64,
    pub percentile_99: f64,
    pub trend_slope: f64,
    pub seasonality_strength: f64,
}

/// Trend analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub slope: f64,
    pub intercept: f64,
    pub r_squared: f64,
    pub p_value: f64,
    pub trend_direction: TrendDirection,
}

/// Direction of behavioral trend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Increasing,
    Decreasing,
    Stable,
    Volatile,
}

/// Change point detection in behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoint {
    pub timestamp: DateTime<Utc>,
    pub change_magnitude: f64,
    pub confidence: f64,
    pub change_type: ChangeType,
}

/// Type of behavioral change detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChangeType {
    MeanShift,
    VarianceChange,
    TrendChange,
    SeasonalityChange,
    Anomaly,
}

/// Linear regression analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearRegressionResult {
    pub slope: f64,
    pub intercept: f64,
    pub r_squared: f64,
    pub p_value: f64,
    pub residuals: Vec<f64>,
}

/// Seasonality analysis for behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalityAnalysis {
    pub periods: Vec<SeasonalPeriod>,
    pub dominant_period: Option<SeasonalPeriod>,
    pub seasonality_strength: f64,
}

/// Seasonal period in behavioral data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeasonalPeriod {
    pub period_length: usize,
    pub amplitude: f64,
    pub phase: f64,
    pub confidence: f64,
}

/// Behavioral forecast with confidence intervals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Forecast {
    pub user_id: Uuid,
    pub feature_name: String,
    pub forecast_points: Vec<ForecastPoint>,
    pub model_type: ForecastModel,
    pub accuracy_metrics: AccuracyMetrics,
}

/// Individual forecast point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastPoint {
    pub timestamp: DateTime<Utc>,
    pub predicted_value: f64,
    pub confidence_interval: ConfidenceInterval,
    pub prediction_probability: f64,
}

/// Forecasting model types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForecastModel {
    LinearRegression,
    ExponentialSmoothing,
    ARIMA,
    NeuralNetwork,
    EnsembleModel,
}

/// Forecast accuracy metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyMetrics {
    pub mae: f64,  // Mean Absolute Error
    pub mse: f64,  // Mean Squared Error
    pub rmse: f64, // Root Mean Squared Error
    pub mape: f64, // Mean Absolute Percentage Error
    pub r_squared: f64,
}

/// Confidence interval for predictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower_bound: f64,
    pub upper_bound: f64,
    pub confidence_level: f64,
}

/// Enhanced user behavioral profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedUserBehaviorProfile {
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub feature_vector: BehavioralFeatureVector,
    pub temporal_features: TemporalFeatures,
    pub risk_assessment: RiskAssessment,
    pub peer_comparisons: PeerComparisons,
    pub anomaly_scores: HashMap<String, f64>,
    pub confidence_score: f64,
}

/// Comprehensive behavioral feature vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFeatureVector {
    pub temporal_features: TemporalFeatures,
    pub location_features: LocationFeatures,
    pub device_features: DeviceFeatures,
    pub network_features: NetworkFeatures,
    pub activity_features: ActivityFeatures,
}

/// Temporal behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalFeatures {
    pub login_frequency: f64,
    pub session_duration_avg: f64,
    pub session_duration_std: f64,
    pub active_hours_pattern: Vec<f64>,
    pub day_of_week_pattern: Vec<f64>,
    pub time_between_logins_avg: f64,
    pub time_between_logins_std: f64,
}

/// Location-based behavioral features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationFeatures {
    pub unique_locations: usize,
    pub location_entropy: f64,
    pub travel_velocity: f64,
    pub location_consistency: f64,
    pub geofence_violations: usize,
}

/// Device usage behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFeatures {
    pub unique_devices: usize,
    pub device_consistency: f64,
    pub new_device_frequency: f64,
    pub device_type_diversity: f64,
    pub browser_consistency: f64,
}

/// Network behavioral characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkFeatures {
    pub unique_ip_addresses: usize,
    pub ip_geolocation_consistency: f64,
    pub network_type_diversity: f64,
    pub suspicious_ip_interactions: usize,
    pub tor_usage_frequency: f64,
}

/// Activity-based behavioral metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityFeatures {
    pub action_diversity: f64,
    pub action_frequency: HashMap<String, f64>,
    pub action_sequence_patterns: Vec<String>,
    pub resource_access_patterns: HashMap<String, f64>,
    pub failed_action_rate: f64,
}

/// Comprehensive risk assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_risk_score: f64,
    pub risk_factors: Vec<RiskFactor>,
    pub risk_category: RiskCategory,
    pub confidence_level: f64,
    pub assessment_timestamp: DateTime<Utc>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_name: String,
    pub risk_score: f64,
    pub weight: f64,
    pub description: String,
    pub evidence: Vec<String>,
}

/// Risk categorization levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategory {
    Low,
    Medium,
    High,
    Critical,
}

/// Peer group comparison metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerComparisons {
    pub peer_group_id: String,
    pub percentile_rank: f64,
    pub deviation_from_mean: f64,
    pub outlier_score: f64,
    pub similar_users: Vec<Uuid>,
}

/// Profiling statistics for monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfilingStatistics {
    pub profiles_analyzed: u64,
    pub anomalies_detected: u64,
    pub risk_assessments_performed: u64,
    pub ml_predictions_made: u64,
    pub average_processing_time_ms: f64,
}

/// Normalization method for feature scaling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NormalizationMethod {
    StandardScaling,
    MinMaxScaling,
    RobustScaling,
    Quantile,
}

/// Feature normalization parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureNormalization {
    pub method: NormalizationMethod,
    pub parameters: HashMap<String, f64>,
}

impl Default for BehavioralFeatureVector {
    fn default() -> Self {
        Self {
            temporal_features: TemporalFeatures::default(),
            location_features: LocationFeatures::default(),
            device_features: DeviceFeatures::default(),
            network_features: NetworkFeatures::default(),
            activity_features: ActivityFeatures::default(),
        }
    }
}

impl Default for RiskAssessment {
    fn default() -> Self {
        Self {
            overall_risk_score: 0.0,
            risk_factors: Vec::new(),
            risk_category: RiskCategory::Low,
            confidence_level: 0.0,
            assessment_timestamp: Utc::now(),
        }
    }
}

impl Default for PeerComparisons {
    fn default() -> Self {
        Self {
            peer_group_id: String::new(),
            percentile_rank: 0.0,
            deviation_from_mean: 0.0,
            outlier_score: 0.0,
            similar_users: Vec::new(),
        }
    }
}

impl Default for SeriesStatistics {
    fn default() -> Self {
        Self {
            mean: 0.0,
            median: 0.0,
            std_dev: 0.0,
            variance: 0.0,
            min: 0.0,
            max: 0.0,
            percentile_95: 0.0,
            percentile_99: 0.0,
            trend_slope: 0.0,
            seasonality_strength: 0.0,
        }
    }
}

impl Default for TrendAnalysis {
    fn default() -> Self {
        Self {
            slope: 0.0,
            intercept: 0.0,
            r_squared: 0.0,
            p_value: 1.0,
            trend_direction: TrendDirection::Stable,
        }
    }
}

impl Default for SeasonalityAnalysis {
    fn default() -> Self {
        Self {
            periods: Vec::new(),
            dominant_period: None,
            seasonality_strength: 0.0,
        }
    }
}

impl Default for TemporalFeatures {
    fn default() -> Self {
        Self {
            login_frequency: 0.0,
            session_duration_avg: 0.0,
            session_duration_std: 0.0,
            active_hours_pattern: vec![0.0; 24],
            day_of_week_pattern: vec![0.0; 7],
            time_between_logins_avg: 0.0,
            time_between_logins_std: 0.0,
        }
    }
}

impl Default for LocationFeatures {
    fn default() -> Self {
        Self {
            unique_locations: 0,
            location_entropy: 0.0,
            travel_velocity: 0.0,
            location_consistency: 0.0,
            geofence_violations: 0,
        }
    }
}

impl Default for DeviceFeatures {
    fn default() -> Self {
        Self {
            unique_devices: 0,
            device_consistency: 0.0,
            new_device_frequency: 0.0,
            device_type_diversity: 0.0,
            browser_consistency: 0.0,
        }
    }
}

impl Default for NetworkFeatures {
    fn default() -> Self {
        Self {
            unique_ip_addresses: 0,
            ip_geolocation_consistency: 0.0,
            network_type_diversity: 0.0,
            suspicious_ip_interactions: 0,
            tor_usage_frequency: 0.0,
        }
    }
}

impl Default for ActivityFeatures {
    fn default() -> Self {
        Self {
            action_diversity: 0.0,
            action_frequency: HashMap::new(),
            action_sequence_patterns: Vec::new(),
            resource_access_patterns: HashMap::new(),
            failed_action_rate: 0.0,
        }
    }
}
