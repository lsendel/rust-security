use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::info;
use serde::{Deserialize, Serialize};

/// Real-time fraud detection engine with ML-based risk scoring
#[derive(Debug, Clone)]
pub struct FraudDetectionEngine {
    /// Risk scoring models
    models: Arc<RwLock<FraudModels>>,
    /// Real-time transaction monitoring
    monitor: Arc<RwLock<TransactionMonitor>>,
    /// Fraud patterns database
    patterns: Arc<RwLock<FraudPatternDatabase>>,
    /// Risk thresholds and configuration
    config: Arc<RwLock<FraudConfig>>,
}

#[derive(Debug, Clone)]
pub struct FraudModels {
    /// Velocity-based fraud detection
    velocity_model: VelocityModel,
    /// Device fingerprinting model
    device_model: DeviceFingerprintModel,
    /// Behavioral analysis model
    behavioral_model: BehavioralModel,
    /// Geographic anomaly model
    geo_model: GeographicModel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudAssessment {
    /// Overall fraud risk score (0.0 to 1.0)
    pub risk_score: f64,
    /// Individual risk factors
    pub risk_factors: Vec<RiskFactor>,
    /// Recommended action
    pub recommended_action: FraudAction,
    /// Confidence in assessment
    pub confidence: f64,
    /// Detailed explanation
    pub explanation: String,
    /// Risk category
    pub risk_category: RiskCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub score: f64,
    pub weight: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    VelocityAnomaly,
    DeviceAnomaly,
    BehavioralAnomaly,
    GeographicAnomaly,
    TimeAnomaly,
    PatternMatch,
    HistoricalRisk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FraudAction {
    Allow,
    Challenge,
    Block,
    Review,
    Quarantine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskCategory {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct VelocityModel {
    /// Transaction velocity thresholds
    velocity_thresholds: HashMap<String, VelocityThreshold>,
    /// Recent transaction tracking
    recent_transactions: HashMap<String, Vec<TransactionEvent>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VelocityThreshold {
    pub max_per_minute: u32,
    pub max_per_hour: u32,
    pub max_per_day: u32,
    pub burst_threshold: u32,
}

#[derive(Debug, Clone)]
pub struct TransactionEvent {
    pub timestamp: SystemTime,
    pub transaction_type: String,
    pub amount: Option<f64>,
    pub ip_address: IpAddr,
    pub user_agent: String,
}

#[derive(Debug, Clone)]
pub struct DeviceFingerprintModel {
    /// Known device fingerprints
    known_devices: HashMap<String, DeviceProfile>,
    /// Device risk scores
    device_risks: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub device_id: String,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
    pub user_agents: Vec<String>,
    pub screen_resolution: Option<String>,
    pub timezone: Option<String>,
    pub language: Option<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct BehavioralModel {
    /// User behavior baselines
    user_baselines: HashMap<String, UserBehaviorBaseline>,
    /// Behavioral anomaly detection
    anomaly_detector: AnomalyDetector,
}

#[derive(Debug, Clone)]
pub struct UserBehaviorBaseline {
    pub user_id: String,
    pub typical_login_times: Vec<u8>, // Hours of day
    pub typical_session_duration: Duration,
    pub typical_locations: Vec<String>,
    pub typical_devices: Vec<String>,
    pub activity_patterns: HashMap<String, f64>,
}

#[derive(Debug, Clone)]
pub struct AnomalyDetector {
    pub sensitivity: f64,
    pub learning_rate: f64,
    pub detection_threshold: f64,
}

#[derive(Debug, Clone)]
pub struct GeographicModel {
    /// Location risk scores
    location_risks: HashMap<String, f64>,
    /// Travel velocity analysis
    travel_analyzer: TravelAnalyzer,
}

#[derive(Debug, Clone)]
pub struct TravelAnalyzer {
    pub max_realistic_speed: f64, // km/h
    pub suspicious_countries: Vec<String>,
    pub high_risk_regions: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TransactionMonitor {
    /// Active monitoring sessions
    active_sessions: HashMap<String, MonitoringSession>,
    /// Real-time alerts
    alerts: Vec<FraudAlert>,
}

#[derive(Debug, Clone)]
pub struct MonitoringSession {
    pub session_id: String,
    pub user_id: String,
    pub start_time: SystemTime,
    pub events: Vec<TransactionEvent>,
    pub current_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudAlert {
    pub alert_id: String,
    pub severity: AlertSeverity,
    pub alert_type: AlertType,
    pub user_id: String,
    pub description: String,
    pub timestamp: SystemTime,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    VelocityExceeded,
    SuspiciousDevice,
    GeographicAnomaly,
    BehavioralAnomaly,
    PatternMatch,
    MultipleFailures,
}

#[derive(Debug, Clone)]
pub struct FraudPatternDatabase {
    /// Known fraud patterns
    patterns: HashMap<String, FraudPattern>,
    /// Pattern matching rules
    rules: Vec<PatternRule>,
}

#[derive(Debug, Clone)]
pub struct FraudPattern {
    pub pattern_id: String,
    pub name: String,
    pub description: String,
    pub indicators: Vec<String>,
    pub risk_weight: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct PatternRule {
    pub rule_id: String,
    pub pattern: String,
    pub action: FraudAction,
    pub threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudConfig {
    /// Risk score thresholds
    pub low_risk_threshold: f64,
    pub medium_risk_threshold: f64,
    pub high_risk_threshold: f64,
    pub critical_risk_threshold: f64,
    
    /// Velocity limits
    pub default_velocity_limits: VelocityThreshold,
    
    /// Model weights
    pub velocity_weight: f64,
    pub device_weight: f64,
    pub behavioral_weight: f64,
    pub geographic_weight: f64,
    
    /// Real-time monitoring
    pub enable_real_time_monitoring: bool,
    pub alert_threshold: f64,
    pub auto_block_threshold: f64,
}

impl FraudDetectionEngine {
    /// Create new fraud detection engine
    pub fn new() -> Self {
        Self {
            models: Arc::new(RwLock::new(FraudModels::default())),
            monitor: Arc::new(RwLock::new(TransactionMonitor::default())),
            patterns: Arc::new(RwLock::new(FraudPatternDatabase::default())),
            config: Arc::new(RwLock::new(FraudConfig::default())),
        }
    }

    /// Assess fraud risk for a transaction
    pub async fn assess_fraud_risk(
        &self,
        user_id: &str,
        ip_address: IpAddr,
        user_agent: &str,
        transaction_type: &str,
        amount: Option<f64>,
        device_fingerprint: Option<&str>,
        location: Option<&str>,
    ) -> FraudAssessment {
        let mut risk_factors = Vec::new();
        let mut total_risk_score = 0.0;
        let config = self.config.read().await;

        // Velocity analysis
        let velocity_risk = self.analyze_velocity(user_id, transaction_type).await;
        if velocity_risk > 0.1 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::VelocityAnomaly,
                score: velocity_risk,
                weight: config.velocity_weight,
                description: format!("High transaction velocity detected for user {}", user_id),
            });
            total_risk_score += velocity_risk * config.velocity_weight;
        }

        // Device analysis
        if let Some(device_fp) = device_fingerprint {
            let device_risk = self.analyze_device(user_id, device_fp, user_agent).await;
            if device_risk > 0.1 {
                risk_factors.push(RiskFactor {
                    factor_type: RiskFactorType::DeviceAnomaly,
                    score: device_risk,
                    weight: config.device_weight,
                    description: "Suspicious or unknown device detected".to_string(),
                });
                total_risk_score += device_risk * config.device_weight;
            }
        }

        // Behavioral analysis
        let behavioral_risk = self.analyze_behavior(user_id, transaction_type, amount).await;
        if behavioral_risk > 0.1 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::BehavioralAnomaly,
                score: behavioral_risk,
                weight: config.behavioral_weight,
                description: "Unusual behavior pattern detected".to_string(),
            });
            total_risk_score += behavioral_risk * config.behavioral_weight;
        }

        // Geographic analysis
        if let Some(loc) = location {
            let geo_risk = self.analyze_geography(user_id, loc, ip_address).await;
            if geo_risk > 0.1 {
                risk_factors.push(RiskFactor {
                    factor_type: RiskFactorType::GeographicAnomaly,
                    score: geo_risk,
                    weight: config.geographic_weight,
                    description: format!("Geographic anomaly detected: {}", loc),
                });
                total_risk_score += geo_risk * config.geographic_weight;
            }
        }

        // Normalize risk score
        let normalized_risk = (total_risk_score / risk_factors.len() as f64).min(1.0);

        // Determine risk category and action
        let (risk_category, recommended_action) = self.determine_action(normalized_risk, &config).await;

        // Calculate confidence based on number of factors and their consistency
        let confidence = self.calculate_confidence(&risk_factors).await;

        // Record transaction for monitoring
        self.record_transaction(user_id, ip_address, user_agent, transaction_type, amount).await;

        FraudAssessment {
            risk_score: normalized_risk,
            risk_factors,
            recommended_action,
            confidence,
            explanation: self.generate_explanation(normalized_risk, &risk_category).await,
            risk_category,
        }
    }

    /// Start real-time monitoring for a user session
    pub async fn start_monitoring(&self, user_id: &str, session_id: &str) {
        let mut monitor = self.monitor.write().await;
        
        monitor.active_sessions.insert(
            session_id.to_string(),
            MonitoringSession {
                session_id: session_id.to_string(),
                user_id: user_id.to_string(),
                start_time: SystemTime::now(),
                events: Vec::new(),
                current_risk_score: 0.0,
            },
        );

        info!(
            user_id = user_id,
            session_id = session_id,
            "Started real-time fraud monitoring"
        );
    }

    /// Stop monitoring and generate session report
    pub async fn stop_monitoring(&self, session_id: &str) -> Option<SessionReport> {
        let mut monitor = self.monitor.write().await;
        
        if let Some(session) = monitor.active_sessions.remove(session_id) {
            let user_id_clone = session.user_id.clone();
            Some(SessionReport {
                session_id: session.session_id,
                user_id: session.user_id,
                duration: SystemTime::now().duration_since(session.start_time).unwrap_or_default(),
                total_events: session.events.len(),
                final_risk_score: session.current_risk_score,
                alerts_generated: monitor.alerts.iter()
                    .filter(|alert| alert.user_id == user_id_clone)
                    .count(),
            })
        } else {
            None
        }
    }

    // Private helper methods
    async fn analyze_velocity(&self, user_id: &str, transaction_type: &str) -> f64 {
        let models = self.models.read().await;
        
        // Get recent transactions for this user
        if let Some(transactions) = models.velocity_model.recent_transactions.get(user_id) {
            let now = SystemTime::now();
            let one_minute_ago = now - Duration::from_secs(60);
            let one_hour_ago = now - Duration::from_secs(3600);
            
            let recent_count = transactions.iter()
                .filter(|t| t.timestamp > one_minute_ago && t.transaction_type == transaction_type)
                .count();
            
            let hourly_count = transactions.iter()
                .filter(|t| t.timestamp > one_hour_ago && t.transaction_type == transaction_type)
                .count();
            
            // Get thresholds
            if let Some(threshold) = models.velocity_model.velocity_thresholds.get(transaction_type) {
                let minute_risk = if recent_count > threshold.max_per_minute as usize {
                    0.8
                } else {
                    (recent_count as f64) / (threshold.max_per_minute as f64) * 0.5
                };
                
                let hour_risk = if hourly_count > threshold.max_per_hour as usize {
                    0.6
                } else {
                    (hourly_count as f64) / (threshold.max_per_hour as f64) * 0.3
                };
                
                return (minute_risk + hour_risk).min(1.0);
            }
        }
        
        0.0
    }

    async fn analyze_device(&self, _user_id: &str, device_fingerprint: &str, user_agent: &str) -> f64 {
        let models = self.models.read().await;
        
        // Check if device is known for this user
        if let Some(device_profile) = models.device_model.known_devices.get(device_fingerprint) {
            // Known device - check for anomalies
            if !device_profile.user_agents.contains(&user_agent.to_string()) {
                return 0.3; // New user agent on known device
            }
            return device_profile.risk_score * 0.5; // Reduce risk for known devices
        } else {
            // Unknown device
            return 0.6;
        }
    }

    async fn analyze_behavior(&self, user_id: &str, transaction_type: &str, amount: Option<f64>) -> f64 {
        let models = self.models.read().await;
        
        if let Some(baseline) = models.behavioral_model.user_baselines.get(user_id) {
            let mut risk_score: f64 = 0.0;
            
            // Check if transaction type is typical
            if let Some(typical_frequency) = baseline.activity_patterns.get(transaction_type) {
                if *typical_frequency < 0.1 {
                    risk_score += 0.3; // Unusual transaction type
                }
            } else {
                risk_score += 0.4; // Never seen this transaction type
            }
            
            // Check amount if provided
            if let Some(amt) = amount {
                // Simple heuristic - amounts over $1000 are higher risk
                if amt > 1000.0 {
                    risk_score += 0.2;
                }
                if amt > 10000.0 {
                    risk_score += 0.3;
                }
            }
            
            return risk_score.min(1.0);
        }
        
        // No baseline - new user
        0.2
    }

    async fn analyze_geography(&self, _user_id: &str, location: &str, _ip_address: IpAddr) -> f64 {
        let models = self.models.read().await;
        
        // Check location risk
        let location_risk = models.geo_model.location_risks
            .get(location)
            .copied()
            .unwrap_or(0.1);
        
        // Check for suspicious countries
        if models.geo_model.travel_analyzer.suspicious_countries
            .iter()
            .any(|country| location.contains(country)) {
            return (location_risk + 0.5).min(1.0);
        }
        
        location_risk
    }

    async fn determine_action(&self, risk_score: f64, config: &FraudConfig) -> (RiskCategory, FraudAction) {
        match risk_score {
            score if score >= config.critical_risk_threshold => (RiskCategory::Critical, FraudAction::Block),
            score if score >= config.high_risk_threshold => (RiskCategory::High, FraudAction::Challenge),
            score if score >= config.medium_risk_threshold => (RiskCategory::Medium, FraudAction::Review),
            _ => (RiskCategory::Low, FraudAction::Allow),
        }
    }

    async fn calculate_confidence(&self, risk_factors: &[RiskFactor]) -> f64 {
        if risk_factors.is_empty() {
            return 0.5; // Neutral confidence with no factors
        }
        
        let avg_score = risk_factors.iter().map(|f| f.score).sum::<f64>() / risk_factors.len() as f64;
        let factor_count_bonus = (risk_factors.len() as f64 * 0.1).min(0.3);
        
        (0.5 + avg_score * 0.3 + factor_count_bonus).min(1.0)
    }

    async fn generate_explanation(&self, risk_score: f64, risk_category: &RiskCategory) -> String {
        match risk_category {
            RiskCategory::Critical => format!("Critical fraud risk detected (score: {:.2}). Immediate action required.", risk_score),
            RiskCategory::High => format!("High fraud risk detected (score: {:.2}). Additional verification recommended.", risk_score),
            RiskCategory::Medium => format!("Medium fraud risk detected (score: {:.2}). Enhanced monitoring advised.", risk_score),
            RiskCategory::Low => format!("Low fraud risk (score: {:.2}). Transaction appears legitimate.", risk_score),
        }
    }

    async fn record_transaction(
        &self,
        user_id: &str,
        ip_address: IpAddr,
        user_agent: &str,
        transaction_type: &str,
        amount: Option<f64>,
    ) {
        let mut models = self.models.write().await;
        
        let event = TransactionEvent {
            timestamp: SystemTime::now(),
            transaction_type: transaction_type.to_string(),
            amount,
            ip_address,
            user_agent: user_agent.to_string(),
        };
        
        models.velocity_model.recent_transactions
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(event);
        
        // Keep only recent transactions (last 24 hours)
        let cutoff = SystemTime::now() - Duration::from_secs(86400);
        if let Some(transactions) = models.velocity_model.recent_transactions.get_mut(user_id) {
            transactions.retain(|t| t.timestamp > cutoff);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub session_id: String,
    pub user_id: String,
    pub duration: Duration,
    pub total_events: usize,
    pub final_risk_score: f64,
    pub alerts_generated: usize,
}

// Default implementations
impl Default for FraudModels {
    fn default() -> Self {
        Self {
            velocity_model: VelocityModel::default(),
            device_model: DeviceFingerprintModel::default(),
            behavioral_model: BehavioralModel::default(),
            geo_model: GeographicModel::default(),
        }
    }
}

impl Default for VelocityModel {
    fn default() -> Self {
        let mut velocity_thresholds = HashMap::new();
        velocity_thresholds.insert("login".to_string(), VelocityThreshold {
            max_per_minute: 5,
            max_per_hour: 20,
            max_per_day: 100,
            burst_threshold: 10,
        });
        velocity_thresholds.insert("password_reset".to_string(), VelocityThreshold {
            max_per_minute: 2,
            max_per_hour: 5,
            max_per_day: 10,
            burst_threshold: 3,
        });
        
        Self {
            velocity_thresholds,
            recent_transactions: HashMap::new(),
        }
    }
}

impl Default for DeviceFingerprintModel {
    fn default() -> Self {
        Self {
            known_devices: HashMap::new(),
            device_risks: HashMap::new(),
        }
    }
}

impl Default for BehavioralModel {
    fn default() -> Self {
        Self {
            user_baselines: HashMap::new(),
            anomaly_detector: AnomalyDetector {
                sensitivity: 0.7,
                learning_rate: 0.1,
                detection_threshold: 0.6,
            },
        }
    }
}

impl Default for GeographicModel {
    fn default() -> Self {
        let mut location_risks = HashMap::new();
        // Add some example high-risk locations
        location_risks.insert("Unknown".to_string(), 0.8);
        location_risks.insert("Tor Exit Node".to_string(), 0.9);
        
        Self {
            location_risks,
            travel_analyzer: TravelAnalyzer {
                max_realistic_speed: 1000.0, // km/h (commercial flight speed)
                suspicious_countries: vec!["Unknown".to_string()],
                high_risk_regions: vec!["Tor Network".to_string()],
            },
        }
    }
}

impl Default for TransactionMonitor {
    fn default() -> Self {
        Self {
            active_sessions: HashMap::new(),
            alerts: Vec::new(),
        }
    }
}

impl Default for FraudPatternDatabase {
    fn default() -> Self {
        Self {
            patterns: HashMap::new(),
            rules: Vec::new(),
        }
    }
}

impl Default for FraudConfig {
    fn default() -> Self {
        Self {
            low_risk_threshold: 0.2,
            medium_risk_threshold: 0.4,
            high_risk_threshold: 0.7,
            critical_risk_threshold: 0.9,
            default_velocity_limits: VelocityThreshold {
                max_per_minute: 10,
                max_per_hour: 50,
                max_per_day: 200,
                burst_threshold: 20,
            },
            velocity_weight: 0.3,
            device_weight: 0.25,
            behavioral_weight: 0.25,
            geographic_weight: 0.2,
            enable_real_time_monitoring: true,
            alert_threshold: 0.6,
            auto_block_threshold: 0.9,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_fraud_detection() {
        let engine = FraudDetectionEngine::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        let assessment = engine.assess_fraud_risk(
            "user123",
            ip,
            "Mozilla/5.0",
            "login",
            None,
            Some("device123"),
            Some("New York"),
        ).await;
        
        assert!(assessment.risk_score >= 0.0 && assessment.risk_score <= 1.0);
        assert!(assessment.confidence >= 0.0 && assessment.confidence <= 1.0);
    }

    #[tokio::test]
    async fn test_session_monitoring() {
        let engine = FraudDetectionEngine::new();
        
        engine.start_monitoring("user123", "session123").await;
        let report = engine.stop_monitoring("session123").await;
        
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.user_id, "user123");
        assert_eq!(report.session_id, "session123");
    }
}
