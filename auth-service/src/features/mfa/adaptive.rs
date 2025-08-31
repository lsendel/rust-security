use crate::mfa::errors::{MfaError, MfaResult};
use crate::mfa::storage::TotpConfiguration;
use crate::mfa::totp_enhanced::{EnhancedTotpConfig, TotpAlgorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdaptiveSecurityError {
    #[error("Risk assessment error: {0}")]
    RiskAssessment(String),
    #[error("Policy evaluation error: {0}")]
    PolicyEvaluation(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub geolocation: Option<GeoLocation>,
    pub session_id: Option<String>,
    pub previous_auth_time: Option<u64>,
    pub failed_attempts_last_hour: u32,
    pub is_new_device: bool,
    pub is_vpn_or_proxy: bool,
    pub time_since_last_password_change: Option<Duration>,
    pub account_age_days: u32,
    pub is_privileged_user: bool,
    pub current_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_score: f64, // 0.0 to 1.0
    pub factors: HashMap<RiskFactor, f64>,
    pub recommendations: Vec<SecurityRecommendation>,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub enum RiskFactor {
    UnknownLocation,
    NewDevice,
    UnusualLoginTime,
    MultipleFailedAttempts,
    VpnOrProxy,
    GeoVelocityAnomaly,
    WeakUserAgent,
    NoDeviceFingerprint,
    PrivilegedAccount,
    RecentPasswordChange,
    NewAccount,
    SuspiciousIpReputation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityRecommendation {
    RequireStepUp,
    RequireAdditionalMfa,
    BlockAccess,
    RequirePasswordReset,
    NotifySecurityTeam,
    RequireAccountVerification,
    EnableSessionMonitoring,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaRequirement {
    pub methods_required: u32,
    pub totp_config: EnhancedTotpConfig,
    pub session_timeout: Duration,
    pub require_fresh_auth: bool,
    pub additional_verification: Vec<AdditionalVerification>,
    pub monitoring_level: MonitoringLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdditionalVerification {
    EmailVerification,
    SmsVerification,
    SecurityQuestions,
    BiometricVerification,
    AdminApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringLevel {
    Standard,
    Enhanced,
    Continuous,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveSecurityConfig {
    pub base_risk_threshold: f64,
    pub high_risk_threshold: f64,
    pub critical_risk_threshold: f64,
    pub location_risk_weight: f64,
    pub device_risk_weight: f64,
    pub behavioral_risk_weight: f64,
    pub temporal_risk_weight: f64,
    pub reputation_risk_weight: f64,
    pub enable_geo_velocity_check: bool,
    pub max_geo_velocity_kmh: f64,
    pub enable_ml_risk_scoring: bool,
    pub privileged_user_multiplier: f64,
}

impl Default for AdaptiveSecurityConfig {
    fn default() -> Self {
        Self {
            base_risk_threshold: 0.3,
            high_risk_threshold: 0.6,
            critical_risk_threshold: 0.8,
            location_risk_weight: 0.25,
            device_risk_weight: 0.20,
            behavioral_risk_weight: 0.25,
            temporal_risk_weight: 0.15,
            reputation_risk_weight: 0.15,
            enable_geo_velocity_check: true,
            max_geo_velocity_kmh: 1000.0, // Max reasonable travel speed
            enable_ml_risk_scoring: false, // Disabled by default
            privileged_user_multiplier: 1.5,
        }
    }
}

pub struct RiskAssessmentEngine {
    config: AdaptiveSecurityConfig,
    geo_service: Option<GeoLocationService>,
    reputation_service: Option<IpReputationService>,
}

impl RiskAssessmentEngine {
    pub fn new(config: AdaptiveSecurityConfig) -> Self {
        Self {
            config,
            geo_service: None,
            reputation_service: None,
        }
    }

    pub fn with_geo_service(mut self, service: GeoLocationService) -> Self {
        self.geo_service = Some(service);
        self
    }

    pub fn with_reputation_service(mut self, service: IpReputationService) -> Self {
        self.reputation_service = Some(service);
        self
    }

    pub async fn assess_risk(&self, context: &AuthContext) -> MfaResult<RiskAssessment> {
        let mut factors = HashMap::new();
        let mut recommendations = Vec::new();

        // Location-based risk assessment
        let location_risk = self.assess_location_risk(context).await?;
        factors.insert(RiskFactor::UnknownLocation, location_risk);

        // Device-based risk assessment
        let device_risk = self.assess_device_risk(context);
        factors.insert(RiskFactor::NewDevice, device_risk);

        // Behavioral risk assessment
        let behavioral_risk = self.assess_behavioral_risk(context);
        if context.failed_attempts_last_hour > 3 {
            factors.insert(RiskFactor::MultipleFailedAttempts, behavioral_risk);
        }

        // Temporal risk assessment
        let temporal_risk = self.assess_temporal_risk(context);
        factors.insert(RiskFactor::UnusualLoginTime, temporal_risk);

        // IP reputation risk
        if let Some(reputation_risk) = self.assess_ip_reputation_risk(context).await? {
            factors.insert(RiskFactor::SuspiciousIpReputation, reputation_risk);
        }

        // VPN/Proxy detection
        if context.is_vpn_or_proxy {
            factors.insert(RiskFactor::VpnOrProxy, 0.4);
        }

        // Geo-velocity check
        if self.config.enable_geo_velocity_check {
            if let Some(velocity_risk) = self.assess_geo_velocity_risk(context).await? {
                factors.insert(RiskFactor::GeoVelocityAnomaly, velocity_risk);
            }
        }

        // Account-specific risks
        if context.account_age_days < 7 {
            factors.insert(RiskFactor::NewAccount, 0.3);
        }

        if context.is_privileged_user {
            factors.insert(RiskFactor::PrivilegedAccount, 0.2);
        }

        // Calculate overall risk score
        let overall_score = self.calculate_overall_risk_score(&factors, context);

        // Determine threat level
        let threat_level = match overall_score {
            score if score >= self.config.critical_risk_threshold => ThreatLevel::Critical,
            score if score >= self.config.high_risk_threshold => ThreatLevel::High,
            score if score >= self.config.base_risk_threshold => ThreatLevel::Medium,
            _ => ThreatLevel::Low,
        };

        // Generate recommendations
        recommendations.extend(self.generate_recommendations(&threat_level, &factors));

        Ok(RiskAssessment {
            overall_score,
            factors,
            recommendations,
            threat_level,
        })
    }

    async fn assess_location_risk(&self, context: &AuthContext) -> MfaResult<f64> {
        // In a real implementation, this would:
        // 1. Check against user's historical locations
        // 2. Assess country/region risk levels
        // 3. Check for impossible travel scenarios

        if let Some(geo) = &context.geolocation {
            // Example: certain countries might have higher risk
            let country_risk = match geo.country.as_deref() {
                Some("CN") | Some("RU") | Some("KP") => 0.3, // Higher risk countries
                Some("US") | Some("CA") | Some("GB") => 0.1, // Lower risk countries
                _ => 0.2, // Medium risk for unknown/other countries
            };
            Ok(country_risk)
        } else {
            Ok(0.4) // No location data is risky
        }
    }

    fn assess_device_risk(&self, context: &AuthContext) -> f64 {
        let mut risk = 0.0;

        if context.is_new_device {
            risk += 0.4;
        }

        if context.device_fingerprint.is_none() {
            risk += 0.2;
        }

        if context.user_agent.is_none() {
            risk += 0.3;
        } else if let Some(ua) = &context.user_agent {
            if self.is_suspicious_user_agent(ua) {
                risk += 0.3;
            }
        }

        risk.min(1.0)
    }

    fn assess_behavioral_risk(&self, context: &AuthContext) -> f64 {
        let mut risk = 0.0;

        // Failed attempts contribute to risk
        risk += (context.failed_attempts_last_hour as f64) * 0.1;

        // Time since last successful auth
        if let Some(last_auth) = context.previous_auth_time {
            let time_diff = context.current_time.saturating_sub(last_auth);
            if time_diff > 30 * 24 * 3600 { // 30 days
                risk += 0.2;
            }
        }

        risk.min(1.0)
    }

    fn assess_temporal_risk(&self, context: &AuthContext) -> f64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get current hour in UTC
        let current_hour = ((current_time / 3600) % 24) as u8;

        // Higher risk during unusual hours (2 AM - 6 AM UTC)
        match current_hour {
            2..=6 => 0.3,
            22..=24 | 0..=1 => 0.2,
            _ => 0.1,
        }
    }

    async fn assess_ip_reputation_risk(&self, context: &AuthContext) -> MfaResult<Option<f64>> {
        if let (Some(ip), Some(reputation_service)) = (&context.ip_address, &self.reputation_service) {
            let reputation = reputation_service.check_reputation(*ip).await?;
            Ok(Some(reputation.risk_score))
        } else {
            Ok(None)
        }
    }

    async fn assess_geo_velocity_risk(&self, context: &AuthContext) -> MfaResult<Option<f64>> {
        // This would check if the user has moved an impossible distance in a short time
        // For now, return None (no risk detected)
        Ok(None)
    }

    fn calculate_overall_risk_score(&self, factors: &HashMap<RiskFactor, f64>, context: &AuthContext) -> f64 {
        let location_score = factors.get(&RiskFactor::UnknownLocation).unwrap_or(&0.0) * self.config.location_risk_weight;
        let device_score = factors.get(&RiskFactor::NewDevice).unwrap_or(&0.0) * self.config.device_risk_weight;
        let behavioral_score = factors.get(&RiskFactor::MultipleFailedAttempts).unwrap_or(&0.0) * self.config.behavioral_risk_weight;
        let temporal_score = factors.get(&RiskFactor::UnusualLoginTime).unwrap_or(&0.0) * self.config.temporal_risk_weight;
        let reputation_score = factors.get(&RiskFactor::SuspiciousIpReputation).unwrap_or(&0.0) * self.config.reputation_risk_weight;

        let base_score = location_score + device_score + behavioral_score + temporal_score + reputation_score;

        // Apply multipliers
        let final_score = if context.is_privileged_user {
            base_score * self.config.privileged_user_multiplier
        } else {
            base_score
        };

        final_score.min(1.0)
    }

    fn generate_recommendations(&self, threat_level: &ThreatLevel, factors: &HashMap<RiskFactor, f64>) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();

        match threat_level {
            ThreatLevel::Critical => {
                recommendations.push(SecurityRecommendation::BlockAccess);
                recommendations.push(SecurityRecommendation::NotifySecurityTeam);
                recommendations.push(SecurityRecommendation::RequireAccountVerification);
            }
            ThreatLevel::High => {
                recommendations.push(SecurityRecommendation::RequireAdditionalMfa);
                recommendations.push(SecurityRecommendation::EnableSessionMonitoring);
                if factors.contains_key(&RiskFactor::NewDevice) {
                    recommendations.push(SecurityRecommendation::RequireStepUp);
                }
            }
            ThreatLevel::Medium => {
                recommendations.push(SecurityRecommendation::RequireStepUp);
                if factors.contains_key(&RiskFactor::MultipleFailedAttempts) {
                    recommendations.push(SecurityRecommendation::EnableSessionMonitoring);
                }
            }
            ThreatLevel::Low => {
                // No additional recommendations for low threat
            }
        }

        recommendations
    }

    fn is_suspicious_user_agent(&self, user_agent: &str) -> bool {
        let suspicious_patterns = [
            "curl", "wget", "python", "bot", "crawler", "scanner",
            "automated", "script", "test", "headless"
        ];

        let ua_lower = user_agent.to_lowercase();
        suspicious_patterns.iter().any(|pattern| ua_lower.contains(pattern))
    }
}

pub struct AdaptiveMfaPolicy {
    risk_engine: RiskAssessmentEngine,
    config: AdaptiveSecurityConfig,
}

impl AdaptiveMfaPolicy {
    pub fn new(config: AdaptiveSecurityConfig) -> Self {
        let risk_engine = RiskAssessmentEngine::new(config.clone());
        Self {
            risk_engine,
            config,
        }
    }

    pub async fn evaluate_mfa_requirements(&self, context: &AuthContext) -> MfaResult<MfaRequirement> {
        let risk_assessment = self.risk_engine.assess_risk(context).await?;

        let requirement = match risk_assessment.threat_level {
            ThreatLevel::Critical => MfaRequirement {
                methods_required: 3, // TOTP + SMS + Email
                totp_config: EnhancedTotpConfig::high_security(),
                session_timeout: Duration::from_secs(300), // 5 minutes
                require_fresh_auth: true,
                additional_verification: vec![
                    AdditionalVerification::EmailVerification,
                    AdditionalVerification::SmsVerification,
                    AdditionalVerification::AdminApproval,
                ],
                monitoring_level: MonitoringLevel::Continuous,
            },
            ThreatLevel::High => MfaRequirement {
                methods_required: 2, // TOTP + SMS or Email
                totp_config: EnhancedTotpConfig::new(
                    TotpAlgorithm::SHA512,
                    8,
                    15,
                    0,
                    "auth-service".to_string(),
                ).unwrap(),
                session_timeout: Duration::from_secs(900), // 15 minutes
                require_fresh_auth: true,
                additional_verification: vec![AdditionalVerification::EmailVerification],
                monitoring_level: MonitoringLevel::Enhanced,
            },
            ThreatLevel::Medium => MfaRequirement {
                methods_required: 1,
                totp_config: EnhancedTotpConfig::default(),
                session_timeout: Duration::from_secs(3600), // 1 hour
                require_fresh_auth: false,
                additional_verification: vec![],
                monitoring_level: MonitoringLevel::Enhanced,
            },
            ThreatLevel::Low => MfaRequirement {
                methods_required: 1,
                totp_config: EnhancedTotpConfig::default(),
                session_timeout: Duration::from_secs(7200), // 2 hours
                require_fresh_auth: false,
                additional_verification: vec![],
                monitoring_level: MonitoringLevel::Standard,
            },
        };

        Ok(requirement)
    }

    pub async fn should_require_additional_verification(&self, context: &AuthContext) -> MfaResult<bool> {
        let risk_assessment = self.risk_engine.assess_risk(context).await?;
        Ok(risk_assessment.overall_score >= self.config.high_risk_threshold)
    }

    pub async fn get_session_timeout(&self, context: &AuthContext) -> MfaResult<Duration> {
        let requirements = self.evaluate_mfa_requirements(context).await?;
        Ok(requirements.session_timeout)
    }
}

// Mock services for IP reputation and geolocation
#[derive(Debug, Clone)]
pub struct IpReputationService;

#[derive(Debug, Clone)]
pub struct IpReputation {
    pub risk_score: f64,
    pub is_malicious: bool,
    pub categories: Vec<String>,
}

impl IpReputationService {
    pub async fn check_reputation(&self, _ip: IpAddr) -> MfaResult<IpReputation> {
        // Mock implementation - in reality would query threat intelligence feeds
        Ok(IpReputation {
            risk_score: 0.1,
            is_malicious: false,
            categories: vec![],
        })
    }
}

#[derive(Debug, Clone)]
pub struct GeoLocationService;

impl GeoLocationService {
    pub async fn get_location(&self, _ip: IpAddr) -> MfaResult<GeoLocation> {
        // Mock implementation - in reality would query GeoIP service
        Ok(GeoLocation {
            country: Some("US".to_string()),
            region: Some("California".to_string()),
            city: Some("San Francisco".to_string()),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            timezone: Some("America/Los_Angeles".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> AuthContext {
        AuthContext {
            user_id: "test_user".to_string(),
            ip_address: Some("192.168.1.1".parse().unwrap()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
            device_fingerprint: Some("device123".to_string()),
            geolocation: Some(GeoLocation {
                country: Some("US".to_string()),
                region: Some("CA".to_string()),
                city: Some("San Francisco".to_string()),
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                timezone: Some("America/Los_Angeles".to_string()),
            }),
            session_id: Some("session123".to_string()),
            previous_auth_time: Some(1234567890),
            failed_attempts_last_hour: 0,
            is_new_device: false,
            is_vpn_or_proxy: false,
            time_since_last_password_change: Some(Duration::from_secs(86400 * 30)),
            account_age_days: 365,
            is_privileged_user: false,
            current_time: 1234567890,
        }
    }

    #[tokio::test]
    async fn test_low_risk_assessment() {
        let config = AdaptiveSecurityConfig::default();
        let engine = RiskAssessmentEngine::new(config);
        let context = create_test_context();

        let assessment = engine.assess_risk(&context).await.unwrap();
        assert!(matches!(assessment.threat_level, ThreatLevel::Low));
        assert!(assessment.overall_score < 0.3);
    }

    #[tokio::test]
    async fn test_high_risk_assessment() {
        let config = AdaptiveSecurityConfig::default();
        let engine = RiskAssessmentEngine::new(config);
        let mut context = create_test_context();

        // Increase risk factors
        context.is_new_device = true;
        context.failed_attempts_last_hour = 5;
        context.is_vpn_or_proxy = true;
        context.is_privileged_user = true;

        let assessment = engine.assess_risk(&context).await.unwrap();
        assert!(assessment.overall_score > 0.5);
        assert!(!assessment.recommendations.is_empty());
    }

    #[tokio::test]
    async fn test_adaptive_mfa_policy() {
        let config = AdaptiveSecurityConfig::default();
        let policy = AdaptiveMfaPolicy::new(config);
        let context = create_test_context();

        let requirements = policy.evaluate_mfa_requirements(&context).await.unwrap();
        assert_eq!(requirements.methods_required, 1);
        assert!(matches!(requirements.monitoring_level, MonitoringLevel::Standard));
    }

    #[tokio::test]
    async fn test_privileged_user_higher_requirements() {
        let config = AdaptiveSecurityConfig::default();
        let policy = AdaptiveMfaPolicy::new(config);
        let mut context = create_test_context();
        context.is_privileged_user = true;
        context.is_new_device = true;

        let requirements = policy.evaluate_mfa_requirements(&context).await.unwrap();
        assert!(requirements.methods_required >= 1);
        assert!(matches!(requirements.monitoring_level, MonitoringLevel::Enhanced | MonitoringLevel::Continuous));
    }
}