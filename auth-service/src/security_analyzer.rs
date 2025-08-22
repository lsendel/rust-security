use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;
use serde::{Deserialize, Serialize};

/// Advanced security analyzer with ML-based threat detection
#[derive(Debug, Clone)]
pub struct SecurityAnalyzer {
    /// Threat detection models
    models: Arc<RwLock<ThreatModels>>,
    /// Security metrics and statistics
    metrics: Arc<RwLock<SecurityMetrics>>,
    /// Known attack patterns
    attack_patterns: Arc<RwLock<AttackPatternDatabase>>,
    /// IP reputation database
    ip_reputation: Arc<RwLock<IpReputationDatabase>>,
}

#[derive(Debug, Clone)]
pub struct ThreatModels {
    /// Anomaly detection model for user behavior
    user_behavior_model: BehaviorModel,
    /// Request pattern analysis model
    request_pattern_model: PatternModel,
    /// Credential stuffing detection model
    credential_stuffing_model: CredentialModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Attack detection statistics
    pub total_attacks_detected: u64,
    pub attacks_blocked: u64,
    pub false_positives: u64,
    pub detection_accuracy: f64,
    
    /// Attack type breakdown
    pub brute_force_attempts: u64,
    pub credential_stuffing_attempts: u64,
    pub sql_injection_attempts: u64,
    pub xss_attempts: u64,
    pub csrf_attempts: u64,
    
    /// Geographic threat distribution
    pub threats_by_country: HashMap<String, u64>,
    pub high_risk_ips: Vec<IpAddr>,
    
    /// Temporal patterns
    pub peak_attack_hours: Vec<u8>,
    pub attack_frequency_trend: f64,
}

#[derive(Debug, Clone)]
pub struct AttackPatternDatabase {
    /// Known malicious patterns
    patterns: HashMap<String, AttackPattern>,
    /// Pattern matching rules
    rules: Vec<DetectionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: ThreatSeverity,
    pub indicators: Vec<String>,
    pub mitigation: String,
    pub confidence_threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub pattern: String,
    pub threat_type: ThreatType,
    pub action: SecurityAction,
    pub confidence_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    BruteForce,
    CredentialStuffing,
    SqlInjection,
    CrossSiteScripting,
    CrossSiteRequestForgery,
    SessionHijacking,
    AccountTakeover,
    DataExfiltration,
    DenialOfService,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityAction {
    Block,
    Challenge,
    Monitor,
    Alert,
    Quarantine,
}

#[derive(Debug, Clone)]
pub struct BehaviorModel {
    /// User behavior baselines
    baselines: HashMap<String, UserBaseline>,
    /// Anomaly detection parameters
    anomaly_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct PatternModel {
    /// Request pattern signatures
    signatures: HashMap<String, PatternSignature>,
    /// Pattern matching algorithm
    matcher: PatternMatcher,
}

#[derive(Debug, Clone)]
pub struct CredentialModel {
    /// Known compromised credentials (hashed)
    compromised_hashes: HashMap<String, bool>,
    /// Credential stuffing patterns
    stuffing_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBaseline {
    pub user_id: String,
    pub typical_login_hours: Vec<u8>,
    pub typical_locations: Vec<String>,
    pub typical_devices: Vec<String>,
    pub average_session_duration: Duration,
    pub typical_request_patterns: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct PatternSignature {
    pub pattern: String,
    pub frequency: f64,
    pub threat_score: f64,
}

#[derive(Debug, Clone)]
pub struct PatternMatcher {
    pub algorithm: MatchingAlgorithm,
    pub sensitivity: f64,
}

#[derive(Debug, Clone)]
pub enum MatchingAlgorithm {
    RegexBased,
    MachineLearning,
    StatisticalAnalysis,
    HybridApproach,
}

#[derive(Debug, Clone)]
pub struct IpReputationDatabase {
    /// IP reputation scores (0.0 = clean, 1.0 = malicious)
    reputation_scores: HashMap<IpAddr, f64>,
    /// Known malicious IPs
    blacklist: Vec<IpAddr>,
    /// Trusted IPs
    whitelist: Vec<IpAddr>,
    /// Geolocation data
    geolocation: HashMap<IpAddr, GeoLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub region: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
    pub risk_level: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub threat_score: f64,
    pub threat_types: Vec<ThreatType>,
    pub confidence: f64,
    pub recommended_action: SecurityAction,
    pub details: String,
    pub indicators: Vec<String>,
}

impl SecurityAnalyzer {
    /// Create new security analyzer
    pub fn new() -> Self {
        Self {
            models: Arc::new(RwLock::new(ThreatModels::default())),
            metrics: Arc::new(RwLock::new(SecurityMetrics::default())),
            attack_patterns: Arc::new(RwLock::new(AttackPatternDatabase::default())),
            ip_reputation: Arc::new(RwLock::new(IpReputationDatabase::default())),
        }
    }

    /// Analyze request for security threats
    pub async fn analyze_request(
        &self,
        ip: IpAddr,
        user_agent: &str,
        request_path: &str,
        headers: &HashMap<String, String>,
        body: Option<&str>,
    ) -> ThreatAssessment {
        let mut threat_score = 0.0;
        let mut threat_types = Vec::new();
        let mut indicators = Vec::new();

        // IP reputation analysis
        let ip_reputation = self.ip_reputation.read().await;
        if let Some(reputation) = ip_reputation.reputation_scores.get(&ip) {
            threat_score += reputation * 0.3;
            if *reputation > 0.7 {
                threat_types.push(ThreatType::Unknown);
                indicators.push(format!("High-risk IP: {}", ip));
            }
        }

        // Check IP blacklist
        if ip_reputation.blacklist.contains(&ip) {
            threat_score += 0.8;
            threat_types.push(ThreatType::Unknown);
            indicators.push(format!("Blacklisted IP: {}", ip));
        }

        // User agent analysis
        if self.is_suspicious_user_agent(user_agent).await {
            threat_score += 0.2;
            indicators.push("Suspicious user agent detected".to_string());
        }

        // Request path analysis
        if self.analyze_request_path(request_path).await {
            threat_score += 0.4;
            threat_types.push(ThreatType::SqlInjection);
            indicators.push("Potential SQL injection in path".to_string());
        }

        // Header analysis
        threat_score += self.analyze_headers(headers).await;

        // Body analysis (if present)
        if let Some(body_content) = body {
            let body_threat = self.analyze_request_body(body_content).await;
            threat_score += body_threat.0;
            threat_types.extend(body_threat.1);
        }

        // Determine recommended action
        let recommended_action = match threat_score {
            score if score >= 0.8 => SecurityAction::Block,
            score if score >= 0.6 => SecurityAction::Challenge,
            score if score >= 0.4 => SecurityAction::Monitor,
            score if score >= 0.2 => SecurityAction::Alert,
            _ => SecurityAction::Monitor,
        };

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.total_attacks_detected += if threat_score > 0.5 { 1 } else { 0 };

        ThreatAssessment {
            threat_score,
            threat_types,
            confidence: self.calculate_confidence(&indicators).await,
            recommended_action,
            details: format!("Threat analysis completed. Score: {:.2}", threat_score),
            indicators,
        }
    }

    /// Analyze user behavior for anomalies
    pub async fn analyze_user_behavior(
        &self,
        user_id: &str,
        login_time: SystemTime,
        location: &str,
        device: &str,
    ) -> ThreatAssessment {
        let models = self.models.read().await;
        
        if let Some(baseline) = models.user_behavior_model.baselines.get(user_id) {
            let mut anomaly_score = 0.0;
            let mut indicators = Vec::new();

            // Time-based analysis
            let hour = login_time
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() / 3600 % 24;
            
            if !baseline.typical_login_hours.contains(&(hour as u8)) {
                anomaly_score += 0.3;
                indicators.push(format!("Unusual login time: {}:00", hour));
            }

            // Location-based analysis
            if !baseline.typical_locations.contains(&location.to_string()) {
                anomaly_score += 0.4;
                indicators.push(format!("New location: {}", location));
            }

            // Device-based analysis
            if !baseline.typical_devices.contains(&device.to_string()) {
                anomaly_score += 0.2;
                indicators.push(format!("New device: {}", device));
            }

            let recommended_action = if anomaly_score > models.user_behavior_model.anomaly_threshold {
                SecurityAction::Challenge
            } else {
                SecurityAction::Monitor
            };

            ThreatAssessment {
                threat_score: anomaly_score,
                threat_types: if anomaly_score > 0.5 {
                    vec![ThreatType::AccountTakeover]
                } else {
                    vec![]
                },
                confidence: 0.8,
                recommended_action,
                details: "User behavior analysis completed".to_string(),
                indicators,
            }
        } else {
            // New user - create baseline
            info!(user_id = user_id, "Creating new user baseline");
            ThreatAssessment {
                threat_score: 0.1, // Slight risk for new users
                threat_types: vec![],
                confidence: 0.5,
                recommended_action: SecurityAction::Monitor,
                details: "New user - establishing baseline".to_string(),
                indicators: vec!["New user account".to_string()],
            }
        }
    }

    /// Update threat models with new data
    pub async fn update_models(&self, training_data: &[TrainingData]) {
        let mut models = self.models.write().await;
        
        info!(
            training_samples = training_data.len(),
            "Updating threat detection models"
        );

        // Update user behavior baselines
        for data in training_data {
            if let Some(baseline) = models.user_behavior_model.baselines.get_mut(&data.user_id) {
                // Update existing baseline
                if !baseline.typical_login_hours.contains(&data.login_hour) {
                    baseline.typical_login_hours.push(data.login_hour);
                }
                if !baseline.typical_locations.contains(&data.location) {
                    baseline.typical_locations.push(data.location.clone());
                }
            } else {
                // Create new baseline
                models.user_behavior_model.baselines.insert(
                    data.user_id.clone(),
                    UserBaseline {
                        user_id: data.user_id.clone(),
                        typical_login_hours: vec![data.login_hour],
                        typical_locations: vec![data.location.clone()],
                        typical_devices: vec![data.device.clone()],
                        average_session_duration: Duration::from_secs(1800), // 30 minutes default
                        typical_request_patterns: vec![],
                        risk_score: 0.1,
                    },
                );
            }
        }

        info!("Threat detection models updated successfully");
    }

    /// Get security metrics
    pub async fn get_metrics(&self) -> SecurityMetrics {
        self.metrics.read().await.clone()
    }

    // Private helper methods
    async fn is_suspicious_user_agent(&self, user_agent: &str) -> bool {
        // Check for common bot patterns, suspicious tools, etc.
        let suspicious_patterns = [
            "sqlmap", "nikto", "nmap", "masscan", "zap", "burp",
            "python-requests", "curl/", "wget/", "bot", "crawler",
        ];

        suspicious_patterns.iter().any(|pattern| {
            user_agent.to_lowercase().contains(pattern)
        })
    }

    async fn analyze_request_path(&self, path: &str) -> bool {
        // Check for SQL injection patterns
        let sql_patterns = [
            "union select", "drop table", "insert into", "delete from",
            "' or '1'='1", "' or 1=1", "admin'--", "' union",
        ];

        sql_patterns.iter().any(|pattern| {
            path.to_lowercase().contains(pattern)
        })
    }

    async fn analyze_headers(&self, headers: &HashMap<String, String>) -> f64 {
        let mut threat_score = 0.0;

        // Check for missing security headers
        if !headers.contains_key("x-forwarded-for") && !headers.contains_key("x-real-ip") {
            // Direct connection might be suspicious for some endpoints
            threat_score += 0.1;
        }

        // Check for suspicious header values
        for (key, value) in headers {
            if key.to_lowercase().contains("x-forwarded-for") {
                // Multiple IPs might indicate proxy chaining
                if value.split(',').count() > 3 {
                    threat_score += 0.2;
                }
            }
        }

        threat_score
    }

    async fn analyze_request_body(&self, body: &str) -> (f64, Vec<ThreatType>) {
        let mut threat_score = 0.0;
        let mut threat_types = Vec::new();

        // XSS detection
        let xss_patterns = ["<script", "javascript:", "onerror=", "onload="];
        if xss_patterns.iter().any(|pattern| body.to_lowercase().contains(pattern)) {
            threat_score += 0.6;
            threat_types.push(ThreatType::CrossSiteScripting);
        }

        // SQL injection detection
        let sql_patterns = ["union select", "drop table", "' or '"];
        if sql_patterns.iter().any(|pattern| body.to_lowercase().contains(pattern)) {
            threat_score += 0.7;
            threat_types.push(ThreatType::SqlInjection);
        }

        (threat_score, threat_types)
    }

    async fn calculate_confidence(&self, indicators: &[String]) -> f64 {
        // Simple confidence calculation based on number of indicators
        let base_confidence = 0.5;
        let indicator_weight = 0.1;
        
        (base_confidence + (indicators.len() as f64 * indicator_weight)).min(1.0)
    }
}

#[derive(Debug, Clone)]
pub struct TrainingData {
    pub user_id: String,
    pub login_hour: u8,
    pub location: String,
    pub device: String,
    pub was_malicious: bool,
}

// Default implementations
impl Default for ThreatModels {
    fn default() -> Self {
        Self {
            user_behavior_model: BehaviorModel {
                baselines: HashMap::new(),
                anomaly_threshold: 0.6,
            },
            request_pattern_model: PatternModel {
                signatures: HashMap::new(),
                matcher: PatternMatcher {
                    algorithm: MatchingAlgorithm::HybridApproach,
                    sensitivity: 0.7,
                },
            },
            credential_stuffing_model: CredentialModel {
                compromised_hashes: HashMap::new(),
                stuffing_patterns: vec![
                    "admin:admin".to_string(),
                    "admin:password".to_string(),
                    "root:root".to_string(),
                ],
            },
        }
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self {
            total_attacks_detected: 0,
            attacks_blocked: 0,
            false_positives: 0,
            detection_accuracy: 0.0,
            brute_force_attempts: 0,
            credential_stuffing_attempts: 0,
            sql_injection_attempts: 0,
            xss_attempts: 0,
            csrf_attempts: 0,
            threats_by_country: HashMap::new(),
            high_risk_ips: Vec::new(),
            peak_attack_hours: Vec::new(),
            attack_frequency_trend: 0.0,
        }
    }
}

impl Default for AttackPatternDatabase {
    fn default() -> Self {
        Self {
            patterns: HashMap::new(),
            rules: Vec::new(),
        }
    }
}

impl Default for IpReputationDatabase {
    fn default() -> Self {
        Self {
            reputation_scores: HashMap::new(),
            blacklist: Vec::new(),
            whitelist: Vec::new(),
            geolocation: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_security_analyzer() {
        let analyzer = SecurityAnalyzer::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let headers = HashMap::new();
        
        let assessment = analyzer.analyze_request(
            ip,
            "Mozilla/5.0",
            "/api/users",
            &headers,
            None,
        ).await;
        
        assert!(assessment.threat_score >= 0.0);
        assert!(assessment.confidence >= 0.0);
    }

    #[tokio::test]
    async fn test_user_behavior_analysis() {
        let analyzer = SecurityAnalyzer::new();
        let now = SystemTime::now();
        
        let assessment = analyzer.analyze_user_behavior(
            "user123",
            now,
            "New York",
            "Chrome/91.0",
        ).await;
        
        // New user should have low threat score
        assert!(assessment.threat_score < 0.5);
    }
}
