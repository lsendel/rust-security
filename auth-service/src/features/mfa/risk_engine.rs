use crate::mfa::adaptive::{AuthContext, RiskAssessment, RiskFactor, ThreatLevel};
use crate::mfa::errors::{MfaError, MfaResult};
#[cfg(feature = "redis-sessions")]
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RiskEngineError {
    #[error("Risk calculation error: {0}")]
    RiskCalculation(String),
    #[error("Historical data error: {0}")]
    HistoricalData(String),
    #[error("Anomaly detection error: {0}")]
    AnomalyDetection(String),
    #[error("Machine learning error: {0}")]
    MachineLearning(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalAuthPattern {
    pub user_id: String,
    pub usual_locations: Vec<LocationPattern>,
    pub usual_devices: Vec<DevicePattern>,
    pub usual_times: Vec<TimePattern>,
    pub auth_frequency: AuthFrequencyPattern,
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationPattern {
    pub country: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub frequency_score: f64, // 0.0 to 1.0
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePattern {
    pub device_fingerprint: String,
    pub user_agent_family: String,
    pub os_family: String,
    pub frequency_score: f64,
    pub last_seen: u64,
    pub trusted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePattern {
    pub hour_of_day: u8, // 0-23
    pub day_of_week: u8, // 0-6 (Sunday = 0)
    pub frequency_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFrequencyPattern {
    pub daily_average: f64,
    pub weekly_pattern: [f64; 7], // Frequency for each day of week
    pub hourly_pattern: [f64; 24], // Frequency for each hour
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    pub location_anomaly: f64,
    pub device_anomaly: f64,
    pub temporal_anomaly: f64,
    pub behavioral_anomaly: f64,
    pub overall_anomaly: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub ip_reputation: IpReputation,
    pub geo_risk: GeoRisk,
    pub known_attack_patterns: Vec<AttackPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    pub risk_score: f64,
    pub is_malicious: bool,
    pub is_tor: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub abuse_reports: u32,
    pub last_seen_malicious: Option<u64>,
    pub reputation_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRisk {
    pub country_risk_score: f64,
    pub region_risk_score: f64,
    pub is_high_risk_country: bool,
    pub sanctions_list: bool,
    pub fraud_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub pattern_type: AttackPatternType,
    pub confidence: f64,
    pub indicators: Vec<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackPatternType {
    CredentialStuffing,
    BruteForce,
    AccountTakeover,
    SocialEngineering,
    AutomatedBot,
    AdvancedPersistentThreat,
}

pub struct AdvancedRiskEngine {
    redis: Option<ConnectionManager>,
    ml_enabled: bool,
    threat_intel_enabled: bool,
    historical_data_retention: Duration,
}

impl AdvancedRiskEngine {
    pub async fn new() -> Self {
        let redis = Self::create_redis_connection().await;
        Self {
            redis,
            ml_enabled: std::env::var("MFA_ML_ENABLED").unwrap_or_default() == "true",
            threat_intel_enabled: std::env::var("MFA_THREAT_INTEL_ENABLED").unwrap_or_default() == "true",
            historical_data_retention: Duration::from_secs(90 * 24 * 3600), // 90 days
        }
    }

    async fn create_redis_connection() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        client.get_connection_manager().await.ok()
    }

    pub async fn assess_comprehensive_risk(&self, context: &AuthContext) -> MfaResult<RiskAssessment> {
        let mut factors = HashMap::new();

        // Get historical patterns for the user
        let historical_patterns = self.get_user_historical_patterns(&context.user_id).await?;

        // Anomaly detection
        let anomaly_scores = self.detect_anomalies(context, &historical_patterns).await?;

        // Threat intelligence analysis
        let threat_intel = if self.threat_intel_enabled {
            self.analyze_threat_intelligence(context).await?
        } else {
            None
        };

        // Calculate risk factors based on anomalies
        if anomaly_scores.location_anomaly > 0.3 {
            factors.insert(RiskFactor::UnknownLocation, anomaly_scores.location_anomaly);
        }

        if anomaly_scores.device_anomaly > 0.3 {
            factors.insert(RiskFactor::NewDevice, anomaly_scores.device_anomaly);
        }

        if anomaly_scores.temporal_anomaly > 0.3 {
            factors.insert(RiskFactor::UnusualLoginTime, anomaly_scores.temporal_anomaly);
        }

        if anomaly_scores.behavioral_anomaly > 0.3 {
            factors.insert(RiskFactor::MultipleFailedAttempts, anomaly_scores.behavioral_anomaly);
        }

        // Add threat intelligence factors
        if let Some(intel) = &threat_intel {
            if intel.ip_reputation.is_malicious {
                factors.insert(RiskFactor::SuspiciousIpReputation, 0.9);
            } else if intel.ip_reputation.risk_score > 0.5 {
                factors.insert(RiskFactor::SuspiciousIpReputation, intel.ip_reputation.risk_score);
            }

            if intel.ip_reputation.is_vpn || intel.ip_reputation.is_proxy {
                factors.insert(RiskFactor::VpnOrProxy, 0.4);
            }

            if intel.geo_risk.is_high_risk_country {
                factors.insert(RiskFactor::UnknownLocation, intel.geo_risk.country_risk_score);
            }
        }

        // Geo-velocity check
        if let Some(velocity_risk) = self.check_impossible_travel(context, &historical_patterns).await? {
            factors.insert(RiskFactor::GeoVelocityAnomaly, velocity_risk);
        }

        // Machine learning risk scoring (if enabled)
        let ml_risk_score = if self.ml_enabled {
            self.calculate_ml_risk_score(context, &anomaly_scores).await?
        } else {
            None
        };

        // Calculate overall risk score
        let base_score = self.calculate_base_risk_score(&factors);
        let overall_score = if let Some(ml_score) = ml_risk_score {
            // Blend traditional and ML scores
            (base_score * 0.7) + (ml_score * 0.3)
        } else {
            base_score
        };

        // Determine threat level
        let threat_level = self.determine_threat_level(overall_score, &factors);

        // Update user patterns after analysis
        self.update_user_patterns(context, &historical_patterns).await?;

        Ok(RiskAssessment {
            overall_score,
            factors,
            recommendations: self.generate_recommendations(&threat_level, &factors),
            threat_level,
        })
    }

    async fn get_user_historical_patterns(&self, user_id: &str) -> MfaResult<Option<HistoricalAuthPattern>> {
        let Some(mut conn) = self.redis.clone() else {
            return Ok(None);
        };

        let key = format!("risk:patterns:{}", user_id);
        let data: Option<String> = conn.get(&key).await
            .map_err(|e| MfaError::Internal)?;

        match data {
            Some(serialized) => {
                let patterns: HistoricalAuthPattern = serde_json::from_str(&serialized)
                    .map_err(|e| MfaError::Internal)?;
                Ok(Some(patterns))
            }
            None => Ok(None),
        }
    }

    async fn detect_anomalies(&self, context: &AuthContext, historical: &Option<HistoricalAuthPattern>) -> MfaResult<AnomalyScore> {
        let Some(patterns) = historical else {
            // New user - everything is anomalous but with lower confidence
            return Ok(AnomalyScore {
                location_anomaly: 0.3,
                device_anomaly: 0.3,
                temporal_anomaly: 0.2,
                behavioral_anomaly: 0.2,
                overall_anomaly: 0.25,
            });
        };

        let location_anomaly = self.calculate_location_anomaly(context, patterns);
        let device_anomaly = self.calculate_device_anomaly(context, patterns);
        let temporal_anomaly = self.calculate_temporal_anomaly(context, patterns);
        let behavioral_anomaly = self.calculate_behavioral_anomaly(context, patterns);

        let overall_anomaly = (location_anomaly + device_anomaly + temporal_anomaly + behavioral_anomaly) / 4.0;

        Ok(AnomalyScore {
            location_anomaly,
            device_anomaly,
            temporal_anomaly,
            behavioral_anomaly,
            overall_anomaly,
        })
    }

    fn calculate_location_anomaly(&self, context: &AuthContext, patterns: &HistoricalAuthPattern) -> f64 {
        let Some(current_geo) = &context.geolocation else {
            return 0.5; // Missing location data is suspicious
        };

        let Some(country) = &current_geo.country else {
            return 0.5;
        };

        // Check if current location matches historical patterns
        let location_seen = patterns.usual_locations.iter()
            .find(|loc| loc.country == *country)
            .map(|loc| loc.frequency_score)
            .unwrap_or(0.0);

        // Anomaly score is inverse of familiarity
        1.0 - location_seen
    }

    fn calculate_device_anomaly(&self, context: &AuthContext, patterns: &HistoricalAuthPattern) -> f64 {
        let Some(device_fp) = &context.device_fingerprint else {
            return 0.6; // No device fingerprint is suspicious
        };

        let device_seen = patterns.usual_devices.iter()
            .find(|dev| dev.device_fingerprint == *device_fp)
            .map(|dev| dev.frequency_score)
            .unwrap_or(0.0);

        // Check user agent similarity
        let ua_similarity = if let Some(ua) = &context.user_agent {
            patterns.usual_devices.iter()
                .map(|dev| self.calculate_user_agent_similarity(ua, &dev.user_agent_family))
                .fold(0.0, f64::max)
        } else {
            0.0
        };

        // Combine device fingerprint and user agent signals
        let combined_familiarity = (device_seen + ua_similarity) / 2.0;
        1.0 - combined_familiarity
    }

    fn calculate_temporal_anomaly(&self, context: &AuthContext, patterns: &HistoricalAuthPattern) -> f64 {
        let current_time = context.current_time;
        let datetime = chrono::DateTime::from_timestamp(current_time as i64, 0)
            .unwrap_or(chrono::Utc::now());

        let hour = datetime.hour() as u8;
        let weekday = datetime.weekday().num_days_from_sunday() as u8;

        // Check against hourly patterns
        let hourly_familiarity = patterns.auth_frequency.hourly_pattern[hour as usize];

        // Check against daily patterns
        let daily_familiarity = patterns.auth_frequency.weekly_pattern[weekday as usize];

        // Combine temporal signals
        let temporal_familiarity = (hourly_familiarity + daily_familiarity) / 2.0;

        // Anomaly is inverse of familiarity
        1.0 - temporal_familiarity
    }

    fn calculate_behavioral_anomaly(&self, context: &AuthContext, patterns: &HistoricalAuthPattern) -> f64 {
        let mut anomaly_score = 0.0;

        // Check authentication frequency
        if let Some(last_auth) = context.previous_auth_time {
            let time_since_last = context.current_time.saturating_sub(last_auth);
            let days_since_last = time_since_last as f64 / (24.0 * 3600.0);

            // If it's been much longer than usual between authentications
            if days_since_last > patterns.auth_frequency.daily_average * 3.0 {
                anomaly_score += 0.3;
            }
        }

        // Failed attempts factor
        if context.failed_attempts_last_hour > 0 {
            anomaly_score += (context.failed_attempts_last_hour as f64) * 0.1;
        }

        anomaly_score.min(1.0)
    }

    async fn analyze_threat_intelligence(&self, context: &AuthContext) -> MfaResult<Option<ThreatIntelligence>> {
        let Some(ip) = context.ip_address else {
            return Ok(None);
        };

        // In a real implementation, this would query multiple threat intelligence feeds
        let ip_reputation = self.query_ip_reputation(ip).await?;
        let geo_risk = self.query_geo_risk(context).await?;
        let attack_patterns = self.detect_attack_patterns(context).await?;

        Ok(Some(ThreatIntelligence {
            ip_reputation,
            geo_risk,
            known_attack_patterns: attack_patterns,
        }))
    }

    async fn query_ip_reputation(&self, ip: IpAddr) -> MfaResult<IpReputation> {
        // Mock implementation - in reality would query threat feeds
        // like AbuseIPDB, VirusTotal, etc.
        Ok(IpReputation {
            risk_score: 0.1,
            is_malicious: false,
            is_tor: false,
            is_vpn: false,
            is_proxy: false,
            abuse_reports: 0,
            last_seen_malicious: None,
            reputation_sources: vec!["mock_provider".to_string()],
        })
    }

    async fn query_geo_risk(&self, context: &AuthContext) -> MfaResult<GeoRisk> {
        let country_risk = if let Some(geo) = &context.geolocation {
            match geo.country.as_deref() {
                Some("KP") | Some("IR") | Some("SY") => 0.9, // High-risk countries
                Some("CN") | Some("RU") => 0.6, // Medium-high risk
                Some("US") | Some("CA") | Some("GB") | Some("DE") => 0.1, // Low risk
                _ => 0.3, // Default medium risk
            }
        } else {
            0.5
        };

        Ok(GeoRisk {
            country_risk_score: country_risk,
            region_risk_score: country_risk * 0.8,
            is_high_risk_country: country_risk > 0.7,
            sanctions_list: false, // Would check against OFAC/EU sanctions
            fraud_rate: country_risk * 0.1,
        })
    }

    async fn detect_attack_patterns(&self, context: &AuthContext) -> MfaResult<Vec<AttackPattern>> {
        let mut patterns = Vec::new();

        // Check for automated bot patterns
        if let Some(ua) = &context.user_agent {
            if self.is_bot_user_agent(ua) {
                patterns.push(AttackPattern {
                    pattern_type: AttackPatternType::AutomatedBot,
                    confidence: 0.8,
                    indicators: vec!["suspicious_user_agent".to_string()],
                    description: "User agent indicates automated bot".to_string(),
                });
            }
        }

        // Check for credential stuffing (high failure rate)
        if context.failed_attempts_last_hour > 10 {
            patterns.push(AttackPattern {
                pattern_type: AttackPatternType::CredentialStuffing,
                confidence: 0.7,
                indicators: vec!["high_failure_rate".to_string()],
                description: "High number of failed authentication attempts".to_string(),
            });
        }

        Ok(patterns)
    }

    async fn check_impossible_travel(&self, context: &AuthContext, historical: &Option<HistoricalAuthPattern>) -> MfaResult<Option<f64>> {
        let Some(patterns) = historical else {
            return Ok(None);
        };

        let Some(current_geo) = &context.geolocation else {
            return Ok(None);
        };

        // Get the most recent location from patterns
        let most_recent_location = patterns.usual_locations.iter()
            .max_by_key(|loc| loc.last_seen);

        let Some(last_location) = most_recent_location else {
            return Ok(None);
        };

        // Calculate distance and time
        if let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = (
            current_geo.latitude,
            current_geo.longitude,
            // For simplicity, using mock coordinates based on country
            self.get_country_coordinates(&last_location.country),
        ) {
            let distance_km = self.calculate_distance(lat1, lon1, lat2.0, lat2.1);
            let time_diff_hours = (context.current_time.saturating_sub(last_location.last_seen) as f64) / 3600.0;

            if time_diff_hours > 0.0 {
                let speed_kmh = distance_km / time_diff_hours;

                // Impossible if faster than commercial aviation (1000 km/h)
                if speed_kmh > 1000.0 {
                    return Ok(Some(0.9));
                }
                // Suspicious if faster than typical travel (100 km/h)
                else if speed_kmh > 100.0 {
                    return Ok(Some(speed_kmh / 1000.0));
                }
            }
        }

        Ok(None)
    }

    async fn calculate_ml_risk_score(&self, context: &AuthContext, anomaly_scores: &AnomalyScore) -> MfaResult<Option<f64>> {
        // Mock ML implementation - in reality would use a trained model
        let features = vec![
            anomaly_scores.overall_anomaly,
            context.failed_attempts_last_hour as f64 / 10.0,
            if context.is_new_device { 1.0 } else { 0.0 },
            if context.is_vpn_or_proxy { 1.0 } else { 0.0 },
            context.account_age_days as f64 / 365.0,
        ];

        // Simple weighted sum as mock ML model
        let weights = vec![0.3, 0.2, 0.2, 0.15, 0.15];
        let ml_score = features.iter()
            .zip(weights.iter())
            .map(|(feature, weight)| feature * weight)
            .sum::<f64>();

        Ok(Some(ml_score.min(1.0)))
    }

    fn calculate_base_risk_score(&self, factors: &HashMap<RiskFactor, f64>) -> f64 {
        let weights = HashMap::from([
            (RiskFactor::UnknownLocation, 0.25),
            (RiskFactor::NewDevice, 0.20),
            (RiskFactor::MultipleFailedAttempts, 0.25),
            (RiskFactor::SuspiciousIpReputation, 0.15),
            (RiskFactor::VpnOrProxy, 0.10),
            (RiskFactor::GeoVelocityAnomaly, 0.30),
        ]);

        factors.iter()
            .map(|(factor, score)| {
                let weight = weights.get(factor).unwrap_or(&0.1);
                score * weight
            })
            .sum::<f64>()
            .min(1.0)
    }

    fn determine_threat_level(&self, overall_score: f64, factors: &HashMap<RiskFactor, f64>) -> ThreatLevel {
        // Check for critical indicators
        if factors.contains_key(&RiskFactor::GeoVelocityAnomaly) ||
           factors.get(&RiskFactor::SuspiciousIpReputation).unwrap_or(&0.0) > &0.8 {
            return ThreatLevel::Critical;
        }

        match overall_score {
            score if score >= 0.8 => ThreatLevel::Critical,
            score if score >= 0.6 => ThreatLevel::High,
            score if score >= 0.3 => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        }
    }

    fn generate_recommendations(&self, threat_level: &ThreatLevel, factors: &HashMap<RiskFactor, f64>) -> Vec<crate::mfa::adaptive::SecurityRecommendation> {
        use crate::mfa::adaptive::SecurityRecommendation;
        let mut recommendations = Vec::new();

        match threat_level {
            ThreatLevel::Critical => {
                recommendations.push(SecurityRecommendation::BlockAccess);
                recommendations.push(SecurityRecommendation::NotifySecurityTeam);
            }
            ThreatLevel::High => {
                recommendations.push(SecurityRecommendation::RequireAdditionalMfa);
                recommendations.push(SecurityRecommendation::EnableSessionMonitoring);
            }
            ThreatLevel::Medium => {
                recommendations.push(SecurityRecommendation::RequireStepUp);
            }
            ThreatLevel::Low => {
                // Standard security measures
            }
        }

        recommendations
    }

    async fn update_user_patterns(&self, context: &AuthContext, existing: &Option<HistoricalAuthPattern>) -> MfaResult<()> {
        // Implementation would update Redis with new pattern data
        // This is a simplified version
        Ok(())
    }

    // Helper methods
    fn calculate_user_agent_similarity(&self, ua1: &str, ua2: &str) -> f64 {
        // Simple similarity based on common tokens
        let tokens1: std::collections::HashSet<&str> = ua1.split_whitespace().collect();
        let tokens2: std::collections::HashSet<&str> = ua2.split_whitespace().collect();

        let intersection_size = tokens1.intersection(&tokens2).count();
        let union_size = tokens1.union(&tokens2).count();

        if union_size == 0 { 0.0 } else { intersection_size as f64 / union_size as f64 }
    }

    fn is_bot_user_agent(&self, user_agent: &str) -> bool {
        let bot_indicators = ["bot", "crawler", "spider", "scraper", "curl", "wget", "python"];
        let ua_lower = user_agent.to_lowercase();
        bot_indicators.iter().any(|indicator| ua_lower.contains(indicator))
    }

    fn get_country_coordinates(&self, country: &str) -> Option<(f64, f64)> {
        // Mock coordinates for major countries
        match country {
            "US" => Some((39.8283, -98.5795)),
            "GB" => Some((55.3781, -3.4360)),
            "DE" => Some((51.1657, 10.4515)),
            "CN" => Some((35.8617, 104.1954)),
            "JP" => Some((36.2048, 138.2529)),
            _ => None,
        }
    }

    fn calculate_distance(&self, lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
        // Haversine formula for distance calculation
        let r = 6371.0; // Earth's radius in kilometers
        let dlat = (lat2 - lat1).to_radians();
        let dlon = (lon2 - lon1).to_radians();
        let a = (dlat / 2.0).sin().powi(2) + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        r * c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anomaly_detection() {
        let engine = AdvancedRiskEngine::new().await;

        let context = AuthContext {
            user_id: "test_user".to_string(),
            ip_address: Some("192.168.1.1".parse().unwrap()),
            user_agent: Some("Mozilla/5.0".to_string()),
            device_fingerprint: Some("new_device".to_string()),
            geolocation: None,
            session_id: None,
            previous_auth_time: None,
            failed_attempts_last_hour: 0,
            is_new_device: true,
            is_vpn_or_proxy: false,
            time_since_last_password_change: None,
            account_age_days: 1,
            is_privileged_user: false,
            current_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };

        let anomalies = engine.detect_anomalies(&context, &None).await.unwrap();

        // New user should have some anomaly scores
        assert!(anomalies.overall_anomaly > 0.0);
        assert!(anomalies.device_anomaly > 0.0);
    }

    #[test]
    fn test_distance_calculation() {
        let engine = AdvancedRiskEngine {
            redis: None,
            ml_enabled: false,
            threat_intel_enabled: false,
            historical_data_retention: Duration::from_secs(0),
        };

        // Distance from New York to Los Angeles (approximately 3944 km)
        let distance = engine.calculate_distance(40.7128, -74.0060, 34.0522, -118.2437);
        assert!((distance - 3944.0).abs() < 100.0); // Allow 100km tolerance
    }

    #[test]
    fn test_user_agent_similarity() {
        let engine = AdvancedRiskEngine {
            redis: None,
            ml_enabled: false,
            threat_intel_enabled: false,
            historical_data_retention: Duration::from_secs(0),
        };

        let ua1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let ua2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0";
        let ua3 = "curl/7.68.0";

        let similarity_similar = engine.calculate_user_agent_similarity(ua1, ua2);
        let similarity_different = engine.calculate_user_agent_similarity(ua1, ua3);

        assert!(similarity_similar > similarity_different);
        assert!(similarity_similar > 0.5);
        assert!(similarity_different < 0.3);
    }

    #[test]
    fn test_bot_detection() {
        let engine = AdvancedRiskEngine {
            redis: None,
            ml_enabled: false,
            threat_intel_enabled: false,
            historical_data_retention: Duration::from_secs(0),
        };

        assert!(engine.is_bot_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1)"));
        assert!(engine.is_bot_user_agent("curl/7.68.0"));
        assert!(engine.is_bot_user_agent("python-requests/2.25.1"));
        assert!(!engine.is_bot_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"));
    }
}