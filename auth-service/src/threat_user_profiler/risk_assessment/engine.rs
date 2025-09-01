use crate::threat_user_profiler::config::RiskScoringConfig;
use crate::threat_user_profiler::risk_assessment::peer_analysis::PeerComparisonAnalyzer;
use crate::threat_user_profiler::risk_assessment::scoring::RiskScoringAlgorithm;
use crate::threat_user_profiler::types::{
    ActivityFeatures, DeviceFeatures, EnhancedUserBehaviorProfile, LocationFeatures,
    NetworkFeatures, RiskAssessment, RiskCategory, RiskFactor, TemporalFeatures,
};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

/// Advanced risk assessment engine for behavioral analysis
#[derive(Clone)]
pub struct RiskAssessmentEngine {
    config: Arc<RwLock<RiskScoringConfig>>,
    scoring_algorithm: RiskScoringAlgorithm,
    peer_analyzer: PeerComparisonAnalyzer,
    risk_history: Arc<RwLock<HashMap<Uuid, Vec<RiskAssessment>>>>,
}

impl RiskAssessmentEngine {
    /// Create a new risk assessment engine
    #[must_use]
    pub fn new(config: RiskScoringConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            scoring_algorithm: RiskScoringAlgorithm::new(config),
            peer_analyzer: PeerComparisonAnalyzer::new(),
            risk_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Perform comprehensive risk assessment for a user
    ///
    /// # Errors
    /// Returns an error if:
    /// - Risk calculation fails
    /// - Peer comparison analysis fails
    /// - Risk factor aggregation fails
    pub async fn assess_risk(
        &self,
        user_id: Uuid,
        profile: &EnhancedUserBehaviorProfile,
        peer_profiles: &[EnhancedUserBehaviorProfile],
    ) -> Result<RiskAssessment, Box<dyn std::error::Error + Send + Sync>> {
        info!("Performing risk assessment for user {}", user_id);

        let config = self.config.read().await;

        // Calculate individual risk factors
        let mut risk_factors = Vec::new();

        // Temporal risk factors
        let temporal_risks = self
            .assess_temporal_risks(&profile.feature_vector.temporal_features)
            .await?;
        risk_factors.extend(temporal_risks);

        // Location risk factors
        let location_risks = self
            .assess_location_risks(&profile.feature_vector.location_features)
            .await?;
        risk_factors.extend(location_risks);

        // Device risk factors
        let device_risks = self
            .assess_device_risks(&profile.feature_vector.device_features)
            .await?;
        risk_factors.extend(device_risks);

        // Network risk factors
        let network_risks = self
            .assess_network_risks(&profile.feature_vector.network_features)
            .await?;
        risk_factors.extend(network_risks);

        // Activity risk factors
        let activity_risks = self
            .assess_activity_risks(&profile.feature_vector.activity_features)
            .await?;
        risk_factors.extend(activity_risks);

        // Peer comparison risks
        let peer_risks = self
            .peer_analyzer
            .assess_peer_risks(profile, peer_profiles)
            .await?;
        risk_factors.extend(peer_risks);

        // Anomaly-based risks
        let anomaly_risks = self.assess_anomaly_risks(&profile.anomaly_scores).await?;
        risk_factors.extend(anomaly_risks);

        // Calculate overall risk score
        let overall_risk_score = self
            .scoring_algorithm
            .calculate_overall_risk(&risk_factors, &config.risk_aggregation_method)
            .await?;

        // Determine risk category
        let risk_category = self.categorize_risk(overall_risk_score);

        // Calculate confidence level
        let confidence_level = self.calculate_confidence(&risk_factors, &profile.confidence_score);

        let assessment = RiskAssessment {
            overall_risk_score,
            risk_factors,
            risk_category: risk_category.clone(),
            confidence_level,
            assessment_timestamp: Utc::now(),
        };

        // Store in history for trend analysis
        self.store_risk_history(user_id, assessment.clone()).await;

        debug!(
            "Risk assessment completed for user {}: score={:.3}, category={:?}, confidence={:.3}",
            user_id, overall_risk_score, risk_category, confidence_level
        );

        Ok(assessment)
    }

    /// Assess temporal behavioral risks
    async fn assess_temporal_risks(
        &self,
        temporal_features: &TemporalFeatures,
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        let mut risk_factors = Vec::new();
        let config = self.config.read().await;

        // Login frequency anomalies
        if temporal_features.login_frequency > 50.0 {
            // Unusually high frequency
            risk_factors.push(RiskFactor {
                factor_name: "high_login_frequency".to_string(),
                risk_score: (temporal_features.login_frequency / 50.0).min(1.0),
                weight: config
                    .base_risk_weights
                    .get("temporal_anomaly")
                    .unwrap_or(&0.3)
                    * 0.3,
                description: "Unusually high login frequency detected".to_string(),
                evidence: vec![format!(
                    "Login frequency: {:.1} per day",
                    temporal_features.login_frequency
                )],
            });
        }

        // Session duration anomalies
        if temporal_features.session_duration_std > temporal_features.session_duration_avg * 2.0 {
            risk_factors.push(RiskFactor {
                factor_name: "irregular_session_duration".to_string(),
                risk_score: (temporal_features.session_duration_std
                    / temporal_features.session_duration_avg)
                    .min(1.0),
                weight: config
                    .base_risk_weights
                    .get("temporal_anomaly")
                    .unwrap_or(&0.3)
                    * 0.2,
                description: "Highly irregular session duration patterns".to_string(),
                evidence: vec![
                    format!(
                        "Average session: {:.1} minutes",
                        temporal_features.session_duration_avg
                    ),
                    format!(
                        "Standard deviation: {:.1} minutes",
                        temporal_features.session_duration_std
                    ),
                ],
            });
        }

        // Off-hours activity
        let off_hours_activity =
            self.calculate_off_hours_activity(&temporal_features.active_hours_pattern);
        if off_hours_activity > 0.3 {
            risk_factors.push(RiskFactor {
                factor_name: "off_hours_activity".to_string(),
                risk_score: off_hours_activity,
                weight: config
                    .base_risk_weights
                    .get("temporal_anomaly")
                    .unwrap_or(&0.3)
                    * 0.25,
                description: "Significant activity during off-hours".to_string(),
                evidence: vec![format!(
                    "Off-hours activity: {:.1}%",
                    off_hours_activity * 100.0
                )],
            });
        }

        // Weekend activity anomalies
        let weekend_activity =
            self.calculate_weekend_activity(&temporal_features.day_of_week_pattern);
        if weekend_activity > 0.4 {
            risk_factors.push(RiskFactor {
                factor_name: "weekend_activity".to_string(),
                risk_score: weekend_activity,
                weight: config
                    .base_risk_weights
                    .get("temporal_anomaly")
                    .unwrap_or(&0.3)
                    * 0.25,
                description: "Unusual weekend activity patterns".to_string(),
                evidence: vec![format!(
                    "Weekend activity: {:.1}%",
                    weekend_activity * 100.0
                )],
            });
        }

        Ok(risk_factors)
    }

    /// Assess location-based risks
    async fn assess_location_risks(
        &self,
        location_features: &LocationFeatures,
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        let mut risk_factors = Vec::new();
        let config = self.config.read().await;

        // High location entropy (too many different locations)
        if location_features.location_entropy > 3.0 {
            risk_factors.push(RiskFactor {
                factor_name: "high_location_entropy".to_string(),
                risk_score: (location_features.location_entropy / 5.0).min(1.0),
                weight: config
                    .base_risk_weights
                    .get("location_anomaly")
                    .unwrap_or(&0.25)
                    * 0.4,
                description: "User accessing from too many different locations".to_string(),
                evidence: vec![
                    format!("Unique locations: {}", location_features.unique_locations),
                    format!(
                        "Location entropy: {:.2}",
                        location_features.location_entropy
                    ),
                ],
            });
        }

        // High travel velocity (impossible travel)
        if location_features.travel_velocity > 1000.0 {
            // km/h
            risk_factors.push(RiskFactor {
                factor_name: "impossible_travel".to_string(),
                risk_score: (location_features.travel_velocity / 2000.0).min(1.0),
                weight: config
                    .base_risk_weights
                    .get("location_anomaly")
                    .unwrap_or(&0.25)
                    * 0.5,
                description: "Impossible travel velocity detected".to_string(),
                evidence: vec![format!(
                    "Travel velocity: {:.1} km/h",
                    location_features.travel_velocity
                )],
            });
        }

        // Low location consistency
        if location_features.location_consistency < 0.3 {
            risk_factors.push(RiskFactor {
                factor_name: "low_location_consistency".to_string(),
                risk_score: 1.0 - location_features.location_consistency,
                weight: config
                    .base_risk_weights
                    .get("location_anomaly")
                    .unwrap_or(&0.25)
                    * 0.3,
                description: "Inconsistent location patterns".to_string(),
                evidence: vec![format!(
                    "Location consistency: {:.2}",
                    location_features.location_consistency
                )],
            });
        }

        // Geofence violations
        if location_features.geofence_violations > 0 {
            risk_factors.push(RiskFactor {
                factor_name: "geofence_violations".to_string(),
                risk_score: (location_features.geofence_violations as f64 / 10.0).min(1.0),
                weight: config
                    .base_risk_weights
                    .get("location_anomaly")
                    .unwrap_or(&0.25)
                    * 0.6,
                description: "Geofence policy violations detected".to_string(),
                evidence: vec![format!(
                    "Violations: {}",
                    location_features.geofence_violations
                )],
            });
        }

        Ok(risk_factors)
    }

    /// Assess device-related risks
    async fn assess_device_risks(
        &self,
        device_features: &DeviceFeatures,
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        let mut risk_factors = Vec::new();
        let config = self.config.read().await;

        // Too many unique devices
        if device_features.unique_devices > 10 {
            risk_factors.push(RiskFactor {
                factor_name: "excessive_devices".to_string(),
                risk_score: (device_features.unique_devices as f64 / 20.0).min(1.0),
                weight: config
                    .base_risk_weights
                    .get("device_anomaly")
                    .unwrap_or(&0.2)
                    * 0.4,
                description: "User accessing from excessive number of devices".to_string(),
                evidence: vec![format!(
                    "Unique devices: {}",
                    device_features.unique_devices
                )],
            });
        }

        // Low device consistency
        if device_features.device_consistency < 0.5 {
            risk_factors.push(RiskFactor {
                factor_name: "low_device_consistency".to_string(),
                risk_score: 1.0 - device_features.device_consistency,
                weight: config
                    .base_risk_weights
                    .get("device_anomaly")
                    .unwrap_or(&0.2)
                    * 0.3,
                description: "Inconsistent device usage patterns".to_string(),
                evidence: vec![format!(
                    "Device consistency: {:.2}",
                    device_features.device_consistency
                )],
            });
        }

        // High new device frequency
        if device_features.new_device_frequency > 0.5 {
            risk_factors.push(RiskFactor {
                factor_name: "frequent_new_devices".to_string(),
                risk_score: device_features.new_device_frequency,
                weight: config
                    .base_risk_weights
                    .get("device_anomaly")
                    .unwrap_or(&0.2)
                    * 0.5,
                description: "Frequently using new devices".to_string(),
                evidence: vec![format!(
                    "New device frequency: {:.2}",
                    device_features.new_device_frequency
                )],
            });
        }

        Ok(risk_factors)
    }

    /// Assess network-related risks
    async fn assess_network_risks(
        &self,
        network_features: &NetworkFeatures,
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        let mut risk_factors = Vec::new();
        let config = self.config.read().await;

        // Suspicious IP interactions
        if network_features.suspicious_ip_interactions > 0 {
            risk_factors.push(RiskFactor {
                factor_name: "suspicious_ip_interactions".to_string(),
                risk_score: (network_features.suspicious_ip_interactions as f64 / 5.0).min(1.0),
                weight: config
                    .base_risk_weights
                    .get("network_anomaly")
                    .unwrap_or(&0.15)
                    * 0.6,
                description: "Interactions with suspicious IP addresses".to_string(),
                evidence: vec![format!(
                    "Suspicious IPs: {}",
                    network_features.suspicious_ip_interactions
                )],
            });
        }

        // Tor usage
        if network_features.tor_usage_frequency > 0.0 {
            risk_factors.push(RiskFactor {
                factor_name: "tor_usage".to_string(),
                risk_score: network_features.tor_usage_frequency,
                weight: config
                    .base_risk_weights
                    .get("network_anomaly")
                    .unwrap_or(&0.15)
                    * 0.8,
                description: "Tor network usage detected".to_string(),
                evidence: vec![format!(
                    "Tor usage frequency: {:.2}",
                    network_features.tor_usage_frequency
                )],
            });
        }

        // Low IP geolocation consistency
        if network_features.ip_geolocation_consistency < 0.7 {
            risk_factors.push(RiskFactor {
                factor_name: "inconsistent_ip_geolocation".to_string(),
                risk_score: 1.0 - network_features.ip_geolocation_consistency,
                weight: config
                    .base_risk_weights
                    .get("network_anomaly")
                    .unwrap_or(&0.15)
                    * 0.4,
                description: "Inconsistent IP geolocation patterns".to_string(),
                evidence: vec![format!(
                    "IP consistency: {:.2}",
                    network_features.ip_geolocation_consistency
                )],
            });
        }

        Ok(risk_factors)
    }

    /// Assess activity-related risks
    async fn assess_activity_risks(
        &self,
        activity_features: &ActivityFeatures,
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        let mut risk_factors = Vec::new();
        let config = self.config.read().await;

        // High failed action rate
        if activity_features.failed_action_rate > 0.1 {
            risk_factors.push(RiskFactor {
                factor_name: "high_failure_rate".to_string(),
                risk_score: activity_features.failed_action_rate,
                weight: config
                    .base_risk_weights
                    .get("activity_anomaly")
                    .unwrap_or(&0.1)
                    * 0.7,
                description: "High rate of failed actions".to_string(),
                evidence: vec![format!(
                    "Failed action rate: {:.1}%",
                    activity_features.failed_action_rate * 100.0
                )],
            });
        }

        // Low action diversity (potential bot behavior)
        if activity_features.action_diversity < 0.3 {
            risk_factors.push(RiskFactor {
                factor_name: "low_action_diversity".to_string(),
                risk_score: 1.0 - activity_features.action_diversity,
                weight: config
                    .base_risk_weights
                    .get("activity_anomaly")
                    .unwrap_or(&0.1)
                    * 0.5,
                description: "Low diversity in user actions (potential automation)".to_string(),
                evidence: vec![format!(
                    "Action diversity: {:.2}",
                    activity_features.action_diversity
                )],
            });
        }

        Ok(risk_factors)
    }

    /// Assess anomaly-based risks
    async fn assess_anomaly_risks(
        &self,
        anomaly_scores: &HashMap<String, f64>,
    ) -> Result<Vec<RiskFactor>, Box<dyn std::error::Error + Send + Sync>> {
        let mut risk_factors = Vec::new();
        let config = self.config.read().await;

        for (anomaly_type, &score) in anomaly_scores {
            if score > 0.8 {
                risk_factors.push(RiskFactor {
                    factor_name: format!("anomaly_{anomaly_type}"),
                    risk_score: score,
                    weight: config.anomaly_score_multiplier * 0.1,
                    description: format!("High anomaly score for {anomaly_type}"),
                    evidence: vec![format!("Anomaly score: {:.3}", score)],
                });
            }
        }

        Ok(risk_factors)
    }

    /// Categorize overall risk score into risk levels
    fn categorize_risk(&self, risk_score: f64) -> RiskCategory {
        match risk_score {
            score if score >= 0.8 => RiskCategory::Critical,
            score if score >= 0.6 => RiskCategory::High,
            score if score >= 0.3 => RiskCategory::Medium,
            _ => RiskCategory::Low,
        }
    }

    /// Calculate confidence level for the assessment
    fn calculate_confidence(&self, risk_factors: &[RiskFactor], profile_confidence: &f64) -> f64 {
        if risk_factors.is_empty() {
            return 0.5; // Neutral confidence with no risk factors
        }

        // Combine profile confidence with risk factor consistency
        let risk_consistency = self.calculate_risk_factor_consistency(risk_factors);
        (profile_confidence + risk_consistency) / 2.0
    }

    /// Calculate consistency among risk factors
    fn calculate_risk_factor_consistency(&self, risk_factors: &[RiskFactor]) -> f64 {
        if risk_factors.len() < 2 {
            return 1.0;
        }

        let scores: Vec<f64> = risk_factors.iter().map(|rf| rf.risk_score).collect();
        let mean_score = scores.iter().sum::<f64>() / scores.len() as f64;
        let variance =
            scores.iter().map(|s| (s - mean_score).powi(2)).sum::<f64>() / scores.len() as f64;

        // Lower variance means higher consistency
        1.0 - variance.min(1.0)
    }

    /// Calculate off-hours activity percentage
    fn calculate_off_hours_activity(&self, hourly_pattern: &[f64]) -> f64 {
        if hourly_pattern.len() != 24 {
            return 0.0;
        }

        // Define off-hours as 10 PM to 6 AM (22-6)
        let off_hours_indices = [22, 23, 0, 1, 2, 3, 4, 5];
        let off_hours_activity: f64 = off_hours_indices.iter().map(|&i| hourly_pattern[i]).sum();

        let total_activity: f64 = hourly_pattern.iter().sum();

        if total_activity > 0.0 {
            off_hours_activity / total_activity
        } else {
            0.0
        }
    }

    /// Calculate weekend activity percentage
    fn calculate_weekend_activity(&self, daily_pattern: &[f64]) -> f64 {
        if daily_pattern.len() != 7 {
            return 0.0;
        }

        // Weekend is Saturday (5) and Sunday (6)
        let weekend_activity = daily_pattern[5] + daily_pattern[6];
        let total_activity: f64 = daily_pattern.iter().sum();

        if total_activity > 0.0 {
            weekend_activity / total_activity
        } else {
            0.0
        }
    }

    /// Store risk assessment in history for trend analysis
    async fn store_risk_history(&self, user_id: Uuid, assessment: RiskAssessment) {
        let mut history = self.risk_history.write().await;
        let user_history = history.entry(user_id).or_insert_with(Vec::new);

        user_history.push(assessment);

        // Keep only last 100 assessments per user
        if user_history.len() > 100 {
            user_history.remove(0);
        }
    }

    /// Get risk trend for a user
    pub async fn get_risk_trend(&self, user_id: Uuid) -> Option<Vec<f64>> {
        let history = self.risk_history.read().await;
        history
            .get(&user_id)
            .map(|assessments| assessments.iter().map(|a| a.overall_risk_score).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_risk_assessment() {
        let config = RiskScoringConfig::default();
        let engine = RiskAssessmentEngine::new(config);

        // Create test profile with some risk indicators
        let mut profile = EnhancedUserBehaviorProfile {
            user_id: uuid::Uuid::new_v4(),
            created_at: Utc::now(),
            last_updated: Utc::now(),
            feature_vector: BehavioralFeatureVector::default(),
            temporal_features: TemporalFeatures::default(),
            risk_assessment: RiskAssessment::default(),
            peer_comparisons: PeerComparisons::default(),
            anomaly_scores: HashMap::new(),
            confidence_score: 0.8,
        };

        // Add some risk indicators
        profile.feature_vector.network_features.tor_usage_frequency = 0.5;
        profile.feature_vector.activity_features.failed_action_rate = 0.15;

        let assessment = engine
            .assess_risk(profile.user_id, &profile, &[])
            .await
            .unwrap();

        assert!(assessment.overall_risk_score > 0.0);
        assert!(!assessment.risk_factors.is_empty());
        assert!(assessment.confidence_level > 0.0);
    }
}
