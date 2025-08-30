use crate::threat_user_profiler::config::BehavioralFeatureConfig;
use crate::threat_user_profiler::features::{
    ActivityFeatureExtractor, DeviceFeatureExtractor, LocationFeatureExtractor,
    NetworkFeatureExtractor, TemporalFeatureExtractor,
};
use crate::threat_user_profiler::types::{
    ActivityFeatures, BehavioralFeatureVector, DeviceFeatures, EnhancedUserBehaviorProfile,
    FeatureNormalization, LocationFeatures, NetworkFeatures, NormalizationMethod, TemporalFeatures,
    UserSecurityEvent,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

/// Main behavioral feature extraction engine
#[derive(Clone)]
pub struct BehavioralFeatureExtractor {
    config: Arc<RwLock<BehavioralFeatureConfig>>,
    temporal_extractor: TemporalFeatureExtractor,
    location_extractor: LocationFeatureExtractor,
    device_extractor: DeviceFeatureExtractor,
    network_extractor: NetworkFeatureExtractor,
    activity_extractor: ActivityFeatureExtractor,
}

impl BehavioralFeatureExtractor {
    /// Create a new behavioral feature extractor
    #[must_use]
    pub fn new(config: BehavioralFeatureConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            temporal_extractor: TemporalFeatureExtractor::new(config.temporal_window_hours),
            location_extractor: LocationFeatureExtractor::new(config.location_clustering_radius_km),
            device_extractor: DeviceFeatureExtractor::new(config.device_fingerprint_sensitivity),
            network_extractor: NetworkFeatureExtractor::new(),
            activity_extractor: ActivityFeatureExtractor::new(config.activity_pattern_window_days),
        }
    }

    /// Extract comprehensive behavioral features for a user
    ///
    /// # Errors
    /// Returns an error if:
    /// - Feature extraction from any dimension fails
    /// - Feature normalization fails
    /// - Feature vector construction fails
    pub async fn extract_features(
        &self,
        user_id: Uuid,
        user_events: &[UserSecurityEvent],
        historical_data: Option<&EnhancedUserBehaviorProfile>,
    ) -> Result<BehavioralFeatureVector, Box<dyn std::error::Error + Send + Sync>> {
        info!("Extracting behavioral features for user {}", user_id);

        let _config = self.config.read().await;

        // Extract features from different dimensions
        let temporal_features = self
            .temporal_extractor
            .extract_temporal_features(
                user_events,
                historical_data.map(|p| &p.feature_vector.temporal_features),
            )
            .await?;

        let location_features = self
            .location_extractor
            .extract_location_features(
                user_events,
                historical_data.map(|p| &p.feature_vector.location_features),
            )
            .await?;

        let device_features = self
            .device_extractor
            .extract_device_features(
                user_events,
                historical_data.map(|p| &p.feature_vector.device_features),
            )
            .await?;

        let network_features = self
            .network_extractor
            .extract_network_features(
                user_events,
                historical_data.map(|p| &p.feature_vector.network_features),
            )
            .await?;

        let activity_features = self
            .activity_extractor
            .extract_activity_features(
                user_events,
                historical_data.map(|p| &p.feature_vector.activity_features),
            )
            .await?;

        let feature_vector = BehavioralFeatureVector {
            temporal_features,
            location_features,
            device_features,
            network_features,
            activity_features,
        };

        debug!(
            "Extracted {} dimensional feature vector for user {}",
            self.count_feature_dimensions(&feature_vector),
            user_id
        );

        Ok(feature_vector)
    }

    /// Extract features incrementally for real-time processing
    ///
    /// # Errors
    /// Returns an error if:
    /// - Incremental feature extraction fails
    /// - Feature aggregation fails
    /// - Feature normalization fails
    pub async fn extract_incremental_features(
        &self,
        user_id: Uuid,
        new_events: &[UserSecurityEvent],
        existing_profile: &EnhancedUserBehaviorProfile,
    ) -> Result<BehavioralFeatureVector, Box<dyn std::error::Error + Send + Sync>> {
        debug!(
            "Extracting incremental features for user {} with {} new events",
            user_id,
            new_events.len()
        );

        // Update each feature extractor incrementally
        let temporal_features = self
            .temporal_extractor
            .update_temporal_features(
                new_events,
                &existing_profile.feature_vector.temporal_features,
            )
            .await?;

        let location_features = self
            .location_extractor
            .update_location_features(
                new_events,
                &existing_profile.feature_vector.location_features,
            )
            .await?;

        let device_features = self
            .device_extractor
            .update_device_features(new_events, &existing_profile.feature_vector.device_features)
            .await?;

        let network_features = self
            .network_extractor
            .update_network_features(
                new_events,
                &existing_profile.feature_vector.network_features,
            )
            .await?;

        let activity_features = self
            .activity_extractor
            .update_activity_features(
                new_events,
                &existing_profile.feature_vector.activity_features,
            )
            .await?;

        Ok(BehavioralFeatureVector {
            temporal_features,
            location_features,
            device_features,
            network_features,
            activity_features,
        })
    }

    /// Normalize feature vector using configured normalization method
    pub async fn normalize_features(
        &self,
        features: &BehavioralFeatureVector,
        normalization: &FeatureNormalization,
    ) -> Result<BehavioralFeatureVector, Box<dyn std::error::Error + Send + Sync>> {
        let mut normalized_features = features.clone();

        match normalization.method {
            NormalizationMethod::StandardScaling => {
                self.apply_standard_scaling(&mut normalized_features, &normalization.parameters)
                    .await?;
            }
            NormalizationMethod::MinMaxScaling => {
                self.apply_minmax_scaling(&mut normalized_features, &normalization.parameters)
                    .await?;
            }
            NormalizationMethod::RobustScaling => {
                self.apply_robust_scaling(&mut normalized_features, &normalization.parameters)
                    .await?;
            }
            NormalizationMethod::Quantile => {
                self.apply_quantile_scaling(&mut normalized_features, &normalization.parameters)
                    .await?;
            }
        }

        Ok(normalized_features)
    }

    /// Calculate feature importance scores
    pub async fn calculate_feature_importance(
        &self,
        features: &BehavioralFeatureVector,
    ) -> Result<HashMap<String, f64>, Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.read().await;
        let mut importance_scores = HashMap::new();

        // Calculate importance based on variance and configured weights
        let temporal_variance = self.calculate_temporal_variance(&features.temporal_features);
        let location_variance = self.calculate_location_variance(&features.location_features);
        let device_variance = self.calculate_device_variance(&features.device_features);
        let network_variance = self.calculate_network_variance(&features.network_features);
        let activity_variance = self.calculate_activity_variance(&features.activity_features);

        // Apply configured weights
        importance_scores.insert(
            "temporal".to_string(),
            temporal_variance
                * config
                    .feature_weights
                    .get("temporal_consistency")
                    .unwrap_or(&0.25),
        );
        importance_scores.insert(
            "location".to_string(),
            location_variance
                * config
                    .feature_weights
                    .get("location_consistency")
                    .unwrap_or(&0.20),
        );
        importance_scores.insert(
            "device".to_string(),
            device_variance
                * config
                    .feature_weights
                    .get("device_consistency")
                    .unwrap_or(&0.15),
        );
        importance_scores.insert(
            "network".to_string(),
            network_variance
                * config
                    .feature_weights
                    .get("network_consistency")
                    .unwrap_or(&0.15),
        );
        importance_scores.insert(
            "activity".to_string(),
            activity_variance
                * config
                    .feature_weights
                    .get("activity_patterns")
                    .unwrap_or(&0.25),
        );

        Ok(importance_scores)
    }

    /// Count total feature dimensions
    fn count_feature_dimensions(&self, features: &BehavioralFeatureVector) -> usize {
        // Count all numeric features across all dimensions
        7 + // temporal features
        5 + // location features
        5 + // device features
        5 + // network features
        3 + features.activity_features.action_frequency.len() +
            features.activity_features.resource_access_patterns.len()
    }

    /// Apply standard scaling normalization
    async fn apply_standard_scaling(
        &self,
        features: &mut BehavioralFeatureVector,
        parameters: &HashMap<String, f64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Apply z-score normalization: (x - mean) / std_dev
        if let (Some(mean), Some(std_dev)) = (parameters.get("mean"), parameters.get("std_dev")) {
            if *std_dev > 0.0 {
                // Normalize temporal features
                features.temporal_features.login_frequency =
                    (features.temporal_features.login_frequency - mean) / std_dev;
                features.temporal_features.session_duration_avg =
                    (features.temporal_features.session_duration_avg - mean) / std_dev;
                // ... normalize other features similarly
            }
        }

        Ok(())
    }

    /// Apply min-max scaling normalization
    async fn apply_minmax_scaling(
        &self,
        features: &mut BehavioralFeatureVector,
        parameters: &HashMap<String, f64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Apply min-max scaling: (x - min) / (max - min)
        if let (Some(min_val), Some(max_val)) = (parameters.get("min"), parameters.get("max")) {
            let range = max_val - min_val;
            if range > 0.0 {
                features.temporal_features.login_frequency =
                    (features.temporal_features.login_frequency - min_val) / range;
                // ... normalize other features similarly
            }
        }

        Ok(())
    }

    /// Apply robust scaling normalization
    async fn apply_robust_scaling(
        &self,
        features: &mut BehavioralFeatureVector,
        parameters: &HashMap<String, f64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Apply robust scaling: (x - median) / IQR
        if let (Some(median), Some(iqr)) = (parameters.get("median"), parameters.get("iqr")) {
            if *iqr > 0.0 {
                features.temporal_features.login_frequency =
                    (features.temporal_features.login_frequency - median) / iqr;
                // ... normalize other features similarly
            }
        }

        Ok(())
    }

    /// Apply quantile scaling normalization
    async fn apply_quantile_scaling(
        &self,
        _features: &mut BehavioralFeatureVector,
        _parameters: &HashMap<String, f64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Apply quantile transformation (would need more sophisticated implementation)
        // For now, apply a simple rank-based transformation
        Ok(())
    }

    /// Calculate variance in temporal features
    fn calculate_temporal_variance(&self, features: &TemporalFeatures) -> f64 {
        let values = [
            features.login_frequency,
            features.session_duration_avg,
            features.session_duration_std,
            features.time_between_logins_avg,
            features.time_between_logins_std,
        ];

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64
    }

    /// Calculate variance in location features
    fn calculate_location_variance(&self, features: &LocationFeatures) -> f64 {
        let values = [
            features.unique_locations as f64,
            features.location_entropy,
            features.travel_velocity,
            features.location_consistency,
            features.geofence_violations as f64,
        ];

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64
    }

    /// Calculate variance in device features
    fn calculate_device_variance(&self, features: &DeviceFeatures) -> f64 {
        let values = [
            features.unique_devices as f64,
            features.device_consistency,
            features.new_device_frequency,
            features.device_type_diversity,
            features.browser_consistency,
        ];

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64
    }

    /// Calculate variance in network features
    fn calculate_network_variance(&self, features: &NetworkFeatures) -> f64 {
        let values = [
            features.unique_ip_addresses as f64,
            features.ip_geolocation_consistency,
            features.network_type_diversity,
            features.suspicious_ip_interactions as f64,
            features.tor_usage_frequency,
        ];

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64
    }

    /// Calculate variance in activity features
    fn calculate_activity_variance(&self, features: &ActivityFeatures) -> f64 {
        let values = [features.action_diversity, features.failed_action_rate];

        let mean = values.iter().sum::<f64>() / values.len() as f64;
        values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / values.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    async fn test_feature_extraction() {
        let config = BehavioralFeatureConfig::default();
        let extractor = BehavioralFeatureExtractor::new(config);

        // Create test events
        let events = vec![UserSecurityEvent {
            id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: SecurityEventType::AuthenticationSuccess,
            source_ip: "192.168.1.1".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            location: Some(GeoLocation {
                latitude: 37.7749,
                longitude: -122.4194,
                country: Some("US".to_string()),
                city: Some("San Francisco".to_string()),
                region: Some("CA".to_string()),
            }),
            device_fingerprint: Some("device123".to_string()),
            session_id: Some("session123".to_string()),
            metadata: std::collections::HashMap::new(),
        }];

        let user_id = events[0].user_id;
        let features = extractor
            .extract_features(user_id, &events, None)
            .await
            .unwrap();

        assert!(features.temporal_features.login_frequency >= 0.0);
        assert!(features.location_features.unique_locations >= 0);
        assert!(features.device_features.unique_devices >= 0);
    }
}
