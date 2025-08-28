use crate::threat_user_profiler::types::*;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration for user behavior profiling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfilingConfig {
    pub behavioral_features: BehavioralFeatureConfig,
    pub temporal_analysis: TemporalAnalysisConfig,
    pub risk_scoring: RiskScoringConfig,
    pub redis_config: ProfilingRedisConfig,
    pub feature_normalization: FeatureNormalization,
    pub enable_ml_predictions: bool,
    pub enable_peer_comparison: bool,
    pub profile_retention_days: i64,
    pub anomaly_detection_threshold: f64,
    pub min_data_points_for_analysis: usize,
}

/// Configuration for behavioral feature extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFeatureConfig {
    pub temporal_window_hours: i64,
    pub location_clustering_radius_km: f64,
    pub device_fingerprint_sensitivity: f64,
    pub activity_pattern_window_days: i64,
    pub enable_advanced_features: bool,
    pub feature_weights: HashMap<String, f64>,
}

/// Configuration for temporal analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalAnalysisConfig {
    pub time_series_window_size: usize,
    pub seasonality_detection_periods: Vec<usize>,
    pub trend_analysis_min_points: usize,
    pub change_point_detection_sensitivity: f64,
    pub forecast_horizon_hours: i64,
    pub enable_real_time_analysis: bool,
}

/// Configuration for risk scoring algorithms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoringConfig {
    pub base_risk_weights: HashMap<String, f64>,
    pub anomaly_score_multiplier: f64,
    pub peer_deviation_threshold: f64,
    pub temporal_risk_decay_hours: i64,
    pub enable_dynamic_thresholds: bool,
    pub risk_aggregation_method: RiskAggregationMethod,
}

/// Methods for aggregating multiple risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskAggregationMethod {
    WeightedAverage,
    MaximumRisk,
    BayesianFusion,
    EnsembleVoting,
}

/// Redis configuration for profiling data storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingRedisConfig {
    pub connection_url: String,
    pub key_prefix: String,
    pub profile_ttl_seconds: u64,
    pub time_series_ttl_seconds: u64,
    pub enable_compression: bool,
    pub max_connections: u32,
}

impl Default for UserProfilingConfig {
    fn default() -> Self {
        Self {
            behavioral_features: BehavioralFeatureConfig::default(),
            temporal_analysis: TemporalAnalysisConfig::default(),
            risk_scoring: RiskScoringConfig::default(),
            redis_config: ProfilingRedisConfig::default(),
            feature_normalization: FeatureNormalization {
                method: NormalizationMethod::StandardScaling,
                parameters: HashMap::new(),
            },
            enable_ml_predictions: true,
            enable_peer_comparison: true,
            profile_retention_days: 90,
            anomaly_detection_threshold: 0.95,
            min_data_points_for_analysis: 10,
        }
    }
}

impl Default for BehavioralFeatureConfig {
    fn default() -> Self {
        let mut feature_weights = HashMap::new();
        feature_weights.insert("temporal_consistency".to_string(), 0.25);
        feature_weights.insert("location_consistency".to_string(), 0.20);
        feature_weights.insert("device_consistency".to_string(), 0.15);
        feature_weights.insert("network_consistency".to_string(), 0.15);
        feature_weights.insert("activity_patterns".to_string(), 0.25);

        Self {
            temporal_window_hours: 168, // 1 week
            location_clustering_radius_km: 5.0,
            device_fingerprint_sensitivity: 0.8,
            activity_pattern_window_days: 30,
            enable_advanced_features: true,
            feature_weights,
        }
    }
}

impl Default for TemporalAnalysisConfig {
    fn default() -> Self {
        Self {
            time_series_window_size: 1000,
            seasonality_detection_periods: vec![24, 168, 720], // hourly, weekly, monthly
            trend_analysis_min_points: 20,
            change_point_detection_sensitivity: 0.05,
            forecast_horizon_hours: 72,
            enable_real_time_analysis: true,
        }
    }
}

impl Default for RiskScoringConfig {
    fn default() -> Self {
        let mut base_risk_weights = HashMap::new();
        base_risk_weights.insert("temporal_anomaly".to_string(), 0.3);
        base_risk_weights.insert("location_anomaly".to_string(), 0.25);
        base_risk_weights.insert("device_anomaly".to_string(), 0.2);
        base_risk_weights.insert("network_anomaly".to_string(), 0.15);
        base_risk_weights.insert("activity_anomaly".to_string(), 0.1);

        Self {
            base_risk_weights,
            anomaly_score_multiplier: 2.0,
            peer_deviation_threshold: 2.5, // standard deviations
            temporal_risk_decay_hours: 24,
            enable_dynamic_thresholds: true,
            risk_aggregation_method: RiskAggregationMethod::WeightedAverage,
        }
    }
}

impl Default for ProfilingRedisConfig {
    fn default() -> Self {
        Self {
            connection_url: "redis://localhost:6379".to_string(),
            key_prefix: "user_profiling:".to_string(),
            profile_ttl_seconds: 7776000,     // 90 days
            time_series_ttl_seconds: 2592000, // 30 days
            enable_compression: true,
            max_connections: 10,
        }
    }
}

impl UserProfilingConfig {
    /// Create a new configuration with custom settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure for high-security environments
    pub fn high_security() -> Self {
        let mut config = Self::default();
        config.anomaly_detection_threshold = 0.99;
        config.risk_scoring.anomaly_score_multiplier = 3.0;
        config.risk_scoring.peer_deviation_threshold = 1.5;
        config.behavioral_features.device_fingerprint_sensitivity = 0.95;
        config.temporal_analysis.change_point_detection_sensitivity = 0.01;
        config
    }

    /// Configure for performance-optimized environments
    pub fn performance_optimized() -> Self {
        let mut config = Self::default();
        config.temporal_analysis.time_series_window_size = 500;
        config.temporal_analysis.enable_real_time_analysis = false;
        config.behavioral_features.enable_advanced_features = false;
        config.enable_ml_predictions = false;
        config.min_data_points_for_analysis = 5;
        config
    }

    /// Configure for development/testing environments
    pub fn development() -> Self {
        let mut config = Self::default();
        config.profile_retention_days = 7;
        config.redis_config.profile_ttl_seconds = 604_800; // 7 days
        config.redis_config.time_series_ttl_seconds = 259200; // 3 days
        config.min_data_points_for_analysis = 3;
        config
    }

    /// Validate configuration settings
    pub fn validate(&self) -> Result<(), String> {
        if self.anomaly_detection_threshold < 0.0 || self.anomaly_detection_threshold > 1.0 {
            return Err("Anomaly detection threshold must be between 0.0 and 1.0".to_string());
        }

        if self.profile_retention_days <= 0 {
            return Err("Profile retention days must be positive".to_string());
        }

        if self.min_data_points_for_analysis == 0 {
            return Err("Minimum data points for analysis must be greater than 0".to_string());
        }

        if self.temporal_analysis.time_series_window_size == 0 {
            return Err("Time series window size must be greater than 0".to_string());
        }

        if self.behavioral_features.temporal_window_hours <= 0 {
            return Err("Temporal window hours must be positive".to_string());
        }

        if self.behavioral_features.location_clustering_radius_km <= 0.0 {
            return Err("Location clustering radius must be positive".to_string());
        }

        // Validate feature weights sum to approximately 1.0
        let weight_sum: f64 = self.behavioral_features.feature_weights.values().sum();
        if (weight_sum - 1.0).abs() > 0.1 {
            return Err("Feature weights should sum to approximately 1.0".to_string());
        }

        // Validate risk weights sum to approximately 1.0
        let risk_weight_sum: f64 = self.risk_scoring.base_risk_weights.values().sum();
        if (risk_weight_sum - 1.0).abs() > 0.1 {
            return Err("Risk weights should sum to approximately 1.0".to_string());
        }

        Ok(())
    }

    /// Update configuration at runtime
    pub fn update_feature_weight(&mut self, feature: &str, weight: f64) -> Result<(), String> {
        if weight < 0.0 || weight > 1.0 {
            return Err("Feature weight must be between 0.0 and 1.0".to_string());
        }

        self.behavioral_features
            .feature_weights
            .insert(feature.to_string(), weight);
        Ok(())
    }

    /// Update risk scoring weight
    pub fn update_risk_weight(&mut self, risk_factor: &str, weight: f64) -> Result<(), String> {
        if weight < 0.0 || weight > 1.0 {
            return Err("Risk weight must be between 0.0 and 1.0".to_string());
        }

        self.risk_scoring
            .base_risk_weights
            .insert(risk_factor.to_string(), weight);
        Ok(())
    }

    /// Get effective configuration for a specific tenant
    pub fn for_tenant(&self, tenant_id: &str) -> Self {
        // In a real implementation, this would load tenant-specific overrides
        // For now, return the base configuration
        let mut config = self.clone();
        config.redis_config.key_prefix =
            format!("{}tenant:{}:", self.redis_config.key_prefix, tenant_id);
        config
    }
}
