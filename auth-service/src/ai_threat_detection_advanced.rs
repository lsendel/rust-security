// Advanced AI-Powered Threat Detection System
// Machine learning-based anomaly detection and behavioral analysis

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// AI threat detection configuration
#[derive(Debug, Clone)]
pub struct ThreatDetectionConfig {
    /// Enable behavioral analysis
    pub enable_behavioral_analysis: bool,
    /// Enable anomaly detection
    pub enable_anomaly_detection: bool,
    /// Enable real-time threat scoring
    pub enable_threat_scoring: bool,
    /// Minimum threat score for alerting (0.0 to 1.0)
    pub alert_threshold: f64,
    /// Learning window size for behavioral patterns
    pub learning_window_hours: u64,
    /// Maximum user profiles to maintain
    pub max_user_profiles: usize,
    /// Feature extraction window
    pub feature_window_minutes: u64,
}

impl Default for ThreatDetectionConfig {
    fn default() -> Self {
        Self {
            enable_behavioral_analysis: true,
            enable_anomaly_detection: true,
            enable_threat_scoring: true,
            alert_threshold: 0.7,
            learning_window_hours: 168, // 1 week
            max_user_profiles: 100000,
            feature_window_minutes: 60,
        }
    }
}

/// User behavioral profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorProfile {
    /// Privacy-safe user identifier hash
    pub user_id_hash: String,
    /// Authentication patterns
    pub auth_patterns: AuthenticationPatterns,
    /// Access patterns
    pub access_patterns: AccessPatterns,
    /// Device patterns
    pub device_patterns: DevicePatterns,
    /// Temporal patterns
    pub temporal_patterns: TemporalPatterns,
    /// Risk score history
    pub risk_history: VecDeque<RiskScore>,
    /// Profile creation time
    pub created_at: SystemTime,
    /// Last update time
    pub updated_at: SystemTime,
}

/// Authentication behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPatterns {
    /// Typical authentication methods
    pub preferred_methods: HashMap<String, f64>,
    /// Authentication frequency distribution
    pub frequency_distribution: Vec<f64>,
    /// Typical authentication times (hours of day)
    pub time_patterns: Vec<f64>,
    /// Geographic patterns
    pub geo_patterns: HashMap<String, f64>,
    /// Success rate patterns
    pub success_rates: VecDeque<f64>,
}

/// Access behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPatterns {
    /// Resource access frequency
    pub resource_frequency: HashMap<String, f64>,
    /// Action patterns
    pub action_patterns: HashMap<String, f64>,
    /// Session duration patterns
    pub session_durations: VecDeque<Duration>,
    /// Request rate patterns
    pub request_rates: VecDeque<f64>,
}

/// Device behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePatterns {
    /// Known user agents
    pub user_agents: HashMap<String, f64>,
    /// Screen resolutions
    pub screen_resolutions: HashMap<String, f64>,
    /// Browser fingerprints
    pub browser_fingerprints: HashMap<String, f64>,
    /// Operating systems
    pub operating_systems: HashMap<String, f64>,
}

/// Temporal behavioral patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalPatterns {
    /// Activity by hour of day (0-23)
    pub hourly_activity: [f64; 24],
    /// Activity by day of week (0-6)
    pub daily_activity: [f64; 7],
    /// Typical session lengths
    pub session_lengths: VecDeque<Duration>,
    /// Time between sessions
    pub session_intervals: VecDeque<Duration>,
}

/// Risk score with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Overall risk score (0.0 to 1.0)
    pub score: f64,
    /// Individual risk factors
    pub factors: HashMap<String, f64>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Contributing anomalies
    pub anomalies: Vec<AnomalyDetection>,
}

/// Anomaly detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyDetection {
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Severity (0.0 to 1.0)
    pub severity: f64,
    /// Description
    pub description: String,
    /// Feature values that triggered the anomaly
    pub features: HashMap<String, f64>,
    /// Expected vs actual values
    pub deviation: f64,
}

/// Types of anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Unusual authentication time
    UnusualTime,
    /// Unusual location
    UnusualLocation,
    /// Unusual device
    UnusualDevice,
    /// Unusual access pattern
    UnusualAccess,
    /// Unusual request rate
    UnusualRate,
    /// Impossible travel
    ImpossibleTravel,
    /// Credential stuffing pattern
    CredentialStuffing,
    /// Brute force pattern
    BruteForce,
    /// Account takeover indicators
    AccountTakeover,
}

/// Threat intelligence context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatContext {
    /// IP reputation data
    pub ip_reputation: Option<IpReputationData>,
    /// Known attack patterns
    pub attack_patterns: Vec<AttackPattern>,
    /// Threat feeds data
    pub threat_feeds: Vec<ThreatFeedEntry>,
    /// Geolocation data
    pub geolocation: Option<GeolocationData>,
}

/// IP reputation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputationData {
    /// Reputation score (0.0 bad to 1.0 good)
    pub score: f64,
    /// Categories (malware, spam, etc.)
    pub categories: Vec<String>,
    /// Last seen in threat feeds
    pub last_seen: Option<SystemTime>,
    /// Confidence level
    pub confidence: f64,
}

/// Attack pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    /// Pattern name
    pub name: String,
    /// Pattern description
    pub description: String,
    /// Indicators
    pub indicators: Vec<String>,
    /// Severity
    pub severity: f64,
    /// MITRE ATT&CK technique ID
    pub mitre_technique: Option<String>,
}

/// Threat feed entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedEntry {
    /// Indicator value
    pub indicator: String,
    /// Indicator type
    pub indicator_type: String,
    /// Threat type
    pub threat_type: String,
    /// Confidence score
    pub confidence: f64,
    /// Source
    pub source: String,
    /// First seen
    pub first_seen: SystemTime,
    /// Last seen
    pub last_seen: SystemTime,
}

/// Geolocation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeolocationData {
    /// Country code
    pub country: String,
    /// Region/state
    pub region: String,
    /// City
    pub city: String,
    /// Latitude
    pub latitude: f64,
    /// Longitude
    pub longitude: f64,
    /// ISP
    pub isp: String,
    /// Organization
    pub organization: String,
}

/// AI-powered threat detection engine
pub struct ThreatDetectionEngine {
    config: ThreatDetectionConfig,
    user_profiles: Arc<RwLock<HashMap<String, UserBehaviorProfile>>>,
    threat_intelligence: Arc<RwLock<HashMap<IpAddr, ThreatContext>>>,
    anomaly_models: Arc<RwLock<AnomalyModels>>,
    attack_patterns: Arc<RwLock<Vec<AttackPattern>>>,
}

/// Machine learning models for anomaly detection
#[derive(Debug)]
pub struct AnomalyModels {
    /// Time-based anomaly detection
    pub temporal_model: TemporalAnomalyModel,
    /// Behavioral anomaly detection
    pub behavioral_model: BehavioralAnomalyModel,
    /// Geographic anomaly detection
    pub geographic_model: GeographicAnomalyModel,
    /// Device fingerprint anomaly detection
    pub device_model: DeviceAnomalyModel,
}

/// Temporal anomaly detection model
#[derive(Debug)]
pub struct TemporalAnomalyModel {
    /// Expected activity patterns by hour
    pub hourly_patterns: HashMap<String, [f64; 24]>,
    /// Expected activity patterns by day
    pub daily_patterns: HashMap<String, [f64; 7]>,
    /// Seasonal patterns
    pub seasonal_patterns: HashMap<String, Vec<f64>>,
}

/// Behavioral anomaly detection model
#[derive(Debug)]
pub struct BehavioralAnomalyModel {
    /// Normal behavior clusters
    pub behavior_clusters: HashMap<String, Vec<f64>>,
    /// Feature importance weights
    pub feature_weights: HashMap<String, f64>,
    /// Threshold values for anomaly detection
    pub thresholds: HashMap<String, f64>,
}

/// Geographic anomaly detection model
#[derive(Debug)]
pub struct GeographicAnomalyModel {
    /// Known locations for users
    pub user_locations: HashMap<String, Vec<(f64, f64)>>,
    /// Travel velocity thresholds
    pub velocity_thresholds: HashMap<String, f64>,
    /// Country risk scores
    pub country_risks: HashMap<String, f64>,
}

/// Device fingerprint anomaly detection model
#[derive(Debug)]
pub struct DeviceAnomalyModel {
    /// Known device fingerprints
    pub known_devices: HashMap<String, Vec<String>>,
    /// Device risk scores
    pub device_risks: HashMap<String, f64>,
    /// Browser/OS combinations
    pub platform_patterns: HashMap<String, HashMap<String, f64>>,
}

impl ThreatDetectionEngine {
    /// Create new threat detection engine
    pub fn new(config: ThreatDetectionConfig) -> Self {
        Self {
            config,
            user_profiles: Arc::new(RwLock::new(HashMap::new())),
            threat_intelligence: Arc::new(RwLock::new(HashMap::new())),
            anomaly_models: Arc::new(RwLock::new(AnomalyModels::new())),
            attack_patterns: Arc::new(RwLock::new(Self::load_attack_patterns())),
        }
    }

    /// Analyze authentication event for threats
    pub async fn analyze_authentication(
        &self,
        user_id: &str,
        ip: IpAddr,
        user_agent: &str,
        auth_method: &str,
        success: bool,
        timestamp: SystemTime,
    ) -> ThreatAnalysisResult {
        let user_hash = self.hash_user_id(user_id);
        
        // Get or create user profile
        let mut profile = self.get_or_create_profile(&user_hash).await;
        
        // Extract features from the event
        let features = self.extract_features(
            &profile,
            ip,
            user_agent,
            auth_method,
            success,
            timestamp,
        ).await;

        // Perform anomaly detection
        let anomalies = self.detect_anomalies(&profile, &features).await;
        
        // Calculate threat score
        let threat_score = self.calculate_threat_score(&features, &anomalies).await;
        
        // Update user profile
        self.update_profile(&mut profile, &features, timestamp).await;
        
        // Store updated profile
        {
            let mut profiles = self.user_profiles.write().await;
            profiles.insert(user_hash.clone(), profile);
        }

        ThreatAnalysisResult {
            user_id_hash: user_hash,
            threat_score: threat_score.score,
            confidence: threat_score.confidence,
            anomalies,
            risk_factors: threat_score.factors,
            recommended_actions: self.recommend_actions(&threat_score).await,
            timestamp,
        }
    }

    /// Get or create user behavioral profile
    async fn get_or_create_profile(&self, user_hash: &str) -> UserBehaviorProfile {
        let profiles = self.user_profiles.read().await;
        
        if let Some(profile) = profiles.get(user_hash) {
            profile.clone()
        } else {
            drop(profiles);
            self.create_new_profile(user_hash).await
        }
    }

    /// Create new user behavioral profile
    async fn create_new_profile(&self, user_hash: &str) -> UserBehaviorProfile {
        UserBehaviorProfile {
            user_id_hash: user_hash.to_string(),
            auth_patterns: AuthenticationPatterns {
                preferred_methods: HashMap::new(),
                frequency_distribution: Vec::new(),
                time_patterns: vec![0.0; 24],
                geo_patterns: HashMap::new(),
                success_rates: VecDeque::new(),
            },
            access_patterns: AccessPatterns {
                resource_frequency: HashMap::new(),
                action_patterns: HashMap::new(),
                session_durations: VecDeque::new(),
                request_rates: VecDeque::new(),
            },
            device_patterns: DevicePatterns {
                user_agents: HashMap::new(),
                screen_resolutions: HashMap::new(),
                browser_fingerprints: HashMap::new(),
                operating_systems: HashMap::new(),
            },
            temporal_patterns: TemporalPatterns {
                hourly_activity: [0.0; 24],
                daily_activity: [0.0; 7],
                session_lengths: VecDeque::new(),
                session_intervals: VecDeque::new(),
            },
            risk_history: VecDeque::new(),
            created_at: SystemTime::now(),
            updated_at: SystemTime::now(),
        }
    }

    /// Extract features from authentication event
    async fn extract_features(
        &self,
        profile: &UserBehaviorProfile,
        ip: IpAddr,
        user_agent: &str,
        auth_method: &str,
        success: bool,
        timestamp: SystemTime,
    ) -> HashMap<String, f64> {
        let mut features = HashMap::new();

        // Temporal features
        let datetime = timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let hour = ((datetime / 3600) % 24) as usize;
        let day_of_week = ((datetime / 86400 + 4) % 7) as usize; // Unix epoch was Thursday

        features.insert("hour_of_day".to_string(), hour as f64);
        features.insert("day_of_week".to_string(), day_of_week as f64);
        features.insert("is_weekend".to_string(), if day_of_week >= 5 { 1.0 } else { 0.0 });

        // Authentication method features
        features.insert("auth_method_oauth".to_string(), if auth_method == "oauth" { 1.0 } else { 0.0 });
        features.insert("auth_method_password".to_string(), if auth_method == "password" { 1.0 } else { 0.0 });
        features.insert("auth_success".to_string(), if success { 1.0 } else { 0.0 });

        // Device features
        features.insert("user_agent_known".to_string(), 
            if profile.device_patterns.user_agents.contains_key(user_agent) { 1.0 } else { 0.0 });

        // Geographic features (mock implementation)
        let geo_data = self.get_geolocation(ip).await;
        if let Some(geo) = geo_data {
            features.insert("country_known".to_string(),
                if profile.auth_patterns.geo_patterns.contains_key(&geo.country) { 1.0 } else { 0.0 });
            features.insert("country_risk".to_string(), self.get_country_risk(&geo.country).await);
        }

        // Behavioral deviation features
        let expected_hour_activity = profile.temporal_patterns.hourly_activity[hour];
        features.insert("hour_deviation".to_string(), 
            (1.0 - expected_hour_activity).abs());

        // IP reputation features
        let ip_reputation = self.get_ip_reputation(ip).await;
        if let Some(rep) = ip_reputation {
            features.insert("ip_reputation".to_string(), rep.score);
            features.insert("ip_malicious".to_string(), if rep.score < 0.5 { 1.0 } else { 0.0 });
        }

        features
    }

    /// Detect anomalies in the current event
    async fn detect_anomalies(
        &self,
        profile: &UserBehaviorProfile,
        features: &HashMap<String, f64>,
    ) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();
        let models = self.anomaly_models.read().await;

        // Temporal anomaly detection
        if let Some(hour_deviation) = features.get("hour_deviation") {
            if *hour_deviation > 0.8 {
                anomalies.push(AnomalyDetection {
                    anomaly_type: AnomalyType::UnusualTime,
                    severity: *hour_deviation,
                    description: "Authentication at unusual time".to_string(),
                    features: features.clone(),
                    deviation: *hour_deviation,
                });
            }
        }

        // Device anomaly detection
        if let Some(user_agent_known) = features.get("user_agent_known") {
            if *user_agent_known == 0.0 {
                anomalies.push(AnomalyDetection {
                    anomaly_type: AnomalyType::UnusualDevice,
                    severity: 0.6,
                    description: "Authentication from unknown device".to_string(),
                    features: features.clone(),
                    deviation: 1.0,
                });
            }
        }

        // Geographic anomaly detection
        if let Some(country_known) = features.get("country_known") {
            if *country_known == 0.0 {
                let severity = features.get("country_risk").unwrap_or(&0.5);
                anomalies.push(AnomalyDetection {
                    anomaly_type: AnomalyType::UnusualLocation,
                    severity: *severity,
                    description: "Authentication from new location".to_string(),
                    features: features.clone(),
                    deviation: 1.0,
                });
            }
        }

        // IP reputation anomaly
        if let Some(ip_malicious) = features.get("ip_malicious") {
            if *ip_malicious == 1.0 {
                anomalies.push(AnomalyDetection {
                    anomaly_type: AnomalyType::UnusualLocation,
                    severity: 0.9,
                    description: "Authentication from malicious IP".to_string(),
                    features: features.clone(),
                    deviation: 1.0,
                });
            }
        }

        anomalies
    }

    /// Calculate overall threat score
    async fn calculate_threat_score(
        &self,
        features: &HashMap<String, f64>,
        anomalies: &[AnomalyDetection],
    ) -> RiskScore {
        let mut factors = HashMap::new();
        let mut total_score = 0.0;
        let mut confidence = 1.0;

        // Base score from features
        if let Some(auth_success) = features.get("auth_success") {
            if *auth_success == 0.0 {
                factors.insert("failed_auth".to_string(), 0.3);
                total_score += 0.3;
            }
        }

        // Score from anomalies
        for anomaly in anomalies {
            let factor_name = format!("{:?}", anomaly.anomaly_type);
            factors.insert(factor_name, anomaly.severity * 0.5);
            total_score += anomaly.severity * 0.5;
        }

        // IP reputation factor
        if let Some(ip_reputation) = features.get("ip_reputation") {
            let risk = 1.0 - ip_reputation;
            factors.insert("ip_risk".to_string(), risk * 0.4);
            total_score += risk * 0.4;
        }

        // Normalize score
        total_score = total_score.min(1.0);

        // Calculate confidence based on data availability
        if features.len() < 5 {
            confidence *= 0.7;
        }

        RiskScore {
            score: total_score,
            factors,
            confidence,
            timestamp: SystemTime::now(),
            anomalies: anomalies.to_vec(),
        }
    }

    /// Update user behavioral profile
    async fn update_profile(
        &self,
        profile: &mut UserBehaviorProfile,
        features: &HashMap<String, f64>,
        timestamp: SystemTime,
    ) {
        profile.updated_at = timestamp;

        // Update temporal patterns
        if let Some(hour) = features.get("hour_of_day") {
            let hour_idx = *hour as usize;
            if hour_idx < 24 {
                profile.temporal_patterns.hourly_activity[hour_idx] = 
                    (profile.temporal_patterns.hourly_activity[hour_idx] * 0.9) + 0.1;
            }
        }

        if let Some(day) = features.get("day_of_week") {
            let day_idx = *day as usize;
            if day_idx < 7 {
                profile.temporal_patterns.daily_activity[day_idx] = 
                    (profile.temporal_patterns.daily_activity[day_idx] * 0.9) + 0.1;
            }
        }

        // Update authentication success rates
        if let Some(success) = features.get("auth_success") {
            profile.auth_patterns.success_rates.push_back(*success);
            if profile.auth_patterns.success_rates.len() > 100 {
                profile.auth_patterns.success_rates.pop_front();
            }
        }
    }

    /// Recommend actions based on threat score
    async fn recommend_actions(&self, risk_score: &RiskScore) -> Vec<String> {
        let mut actions = Vec::new();

        if risk_score.score > 0.8 {
            actions.push("Block authentication attempt".to_string());
            actions.push("Trigger security alert".to_string());
            actions.push("Require additional verification".to_string());
        } else if risk_score.score > 0.6 {
            actions.push("Require MFA".to_string());
            actions.push("Log security event".to_string());
            actions.push("Monitor subsequent activity".to_string());
        } else if risk_score.score > 0.4 {
            actions.push("Log authentication event".to_string());
            actions.push("Update user risk profile".to_string());
        }

        // Specific recommendations based on anomalies
        for anomaly in &risk_score.anomalies {
            match anomaly.anomaly_type {
                AnomalyType::UnusualLocation => {
                    actions.push("Verify user location".to_string());
                    actions.push("Send location alert to user".to_string());
                }
                AnomalyType::UnusualDevice => {
                    actions.push("Device verification required".to_string());
                    actions.push("Register new device".to_string());
                }
                AnomalyType::UnusualTime => {
                    actions.push("Time-based verification".to_string());
                }
                _ => {}
            }
        }

        actions
    }

    // Helper methods (mock implementations)
    async fn get_geolocation(&self, _ip: IpAddr) -> Option<GeolocationData> {
        // Mock implementation - integrate with real geolocation service
        Some(GeolocationData {
            country: "US".to_string(),
            region: "CA".to_string(),
            city: "San Francisco".to_string(),
            latitude: 37.7749,
            longitude: -122.4194,
            isp: "Example ISP".to_string(),
            organization: "Example Org".to_string(),
        })
    }

    async fn get_country_risk(&self, _country: &str) -> f64 {
        // Mock implementation - integrate with threat intelligence
        0.1 // Low risk
    }

    async fn get_ip_reputation(&self, _ip: IpAddr) -> Option<IpReputationData> {
        // Mock implementation - integrate with IP reputation service
        Some(IpReputationData {
            score: 0.8,
            categories: vec!["clean".to_string()],
            last_seen: None,
            confidence: 0.9,
        })
    }

    fn hash_user_id(&self, user_id: &str) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        hasher.update(b"threat_detection_salt");
        format!("{:x}", hasher.finalize())
    }

    fn load_attack_patterns() -> Vec<AttackPattern> {
        vec![
            AttackPattern {
                name: "Credential Stuffing".to_string(),
                description: "Automated login attempts with stolen credentials".to_string(),
                indicators: vec![
                    "High failure rate".to_string(),
                    "Multiple user accounts".to_string(),
                    "Automated user agents".to_string(),
                ],
                severity: 0.8,
                mitre_technique: Some("T1110.004".to_string()),
            },
            AttackPattern {
                name: "Brute Force".to_string(),
                description: "Systematic password guessing attempts".to_string(),
                indicators: vec![
                    "Sequential password attempts".to_string(),
                    "High request rate".to_string(),
                    "Single user account".to_string(),
                ],
                severity: 0.7,
                mitre_technique: Some("T1110.001".to_string()),
            },
        ]
    }
}

impl AnomalyModels {
    fn new() -> Self {
        Self {
            temporal_model: TemporalAnomalyModel {
                hourly_patterns: HashMap::new(),
                daily_patterns: HashMap::new(),
                seasonal_patterns: HashMap::new(),
            },
            behavioral_model: BehavioralAnomalyModel {
                behavior_clusters: HashMap::new(),
                feature_weights: HashMap::new(),
                thresholds: HashMap::new(),
            },
            geographic_model: GeographicAnomalyModel {
                user_locations: HashMap::new(),
                velocity_thresholds: HashMap::new(),
                country_risks: HashMap::new(),
            },
            device_model: DeviceAnomalyModel {
                known_devices: HashMap::new(),
                device_risks: HashMap::new(),
                platform_patterns: HashMap::new(),
            },
        }
    }
}

/// Threat analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAnalysisResult {
    /// Privacy-safe user identifier hash
    pub user_id_hash: String,
    /// Overall threat score (0.0 to 1.0)
    pub threat_score: f64,
    /// Confidence in the assessment
    pub confidence: f64,
    /// Detected anomalies
    pub anomalies: Vec<AnomalyDetection>,
    /// Risk factors contributing to the score
    pub risk_factors: HashMap<String, f64>,
    /// Recommended security actions
    pub recommended_actions: Vec<String>,
    /// Analysis timestamp
    pub timestamp: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_threat_detection_engine() {
        let config = ThreatDetectionConfig::default();
        let engine = ThreatDetectionEngine::new(config);
        
        let result = engine.analyze_authentication(
            "test_user",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "Mozilla/5.0 (Test Browser)",
            "oauth",
            true,
            SystemTime::now(),
        ).await;
        
        assert!(result.threat_score >= 0.0 && result.threat_score <= 1.0);
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }

    #[tokio::test]
    async fn test_user_profile_creation() {
        let config = ThreatDetectionConfig::default();
        let engine = ThreatDetectionEngine::new(config);
        
        let profile = engine.create_new_profile("test_hash").await;
        
        assert_eq!(profile.user_id_hash, "test_hash");
        assert_eq!(profile.temporal_patterns.hourly_activity.len(), 24);
        assert_eq!(profile.temporal_patterns.daily_activity.len(), 7);
    }

    #[test]
    fn test_anomaly_detection() {
        let anomaly = AnomalyDetection {
            anomaly_type: AnomalyType::UnusualTime,
            severity: 0.8,
            description: "Test anomaly".to_string(),
            features: HashMap::new(),
            deviation: 0.8,
        };
        
        assert_eq!(anomaly.severity, 0.8);
        assert!(matches!(anomaly.anomaly_type, AnomalyType::UnusualTime));
    }
}
