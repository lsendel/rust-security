//! Core security functionality and primitives
//!
//! This module provides security-related functionality including threat detection,
//! security context management, and security policy enforcement.

use crate::core::{auth::AuthContext, crypto::CryptoProvider};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

/// Security context containing security-related information for a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Client IP address
    pub client_ip: IpAddr,
    /// User agent string
    pub user_agent: String,
    /// Request fingerprint
    pub fingerprint: String,
    /// Security level assessment
    pub security_level: SecurityLevel,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f64,
    /// Threat indicators
    pub threat_indicators: Vec<ThreatIndicator>,
    /// Security flags
    pub flags: SecurityFlags,
    /// Additional security metadata
    pub metadata: HashMap<String, String>,
}

impl SecurityContext {
    /// Create a new security context
    #[must_use]
    pub fn new(client_ip: IpAddr, user_agent: String) -> Self {
        let crypto = CryptoProvider::new();
        let fingerprint = Self::generate_fingerprint(&client_ip, &user_agent, &crypto);

        Self {
            client_ip,
            user_agent,
            fingerprint,
            security_level: SecurityLevel::Standard,
            risk_score: 0.0,
            threat_indicators: Vec::new(),
            flags: SecurityFlags::default(),
            metadata: HashMap::new(),
        }
    }

    /// Generate a unique fingerprint for the request
    fn generate_fingerprint(
        client_ip: &IpAddr,
        user_agent: &str,
        crypto: &CryptoProvider,
    ) -> String {
        let combined = format!("{client_ip}:{user_agent}");
        let hash = crypto.hash_sha256(combined.as_bytes());
        hex::encode(&hash[..16]) // First 16 bytes as hex
    }

    /// Add a threat indicator
    pub fn add_threat_indicator(&mut self, indicator: ThreatIndicator) {
        self.threat_indicators.push(indicator);
        self.recalculate_risk_score();
    }

    /// Update risk score based on threat indicators
    fn recalculate_risk_score(&mut self) {
        let base_score = self
            .threat_indicators
            .iter()
            .map(ThreatIndicator::severity_score)
            .fold(0.0, |acc, score| acc + score);

        self.risk_score = (base_score / 10.0).min(1.0); // Normalize to 0.0-1.0

        // Update security level based on risk score
        self.security_level = match self.risk_score {
            score if score < 0.3 => SecurityLevel::Low,
            score if score < 0.6 => SecurityLevel::Standard,
            score if score < 0.8 => SecurityLevel::High,
            _ => SecurityLevel::Critical,
        };
    }

    /// Check if the security context indicates a high-risk situation
    #[must_use]
    pub fn is_high_risk(&self) -> bool {
        self.risk_score > 0.7 || matches!(self.security_level, SecurityLevel::Critical)
    }

    /// Add security metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Security assessment levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    Low,
    Standard,
    High,
    Critical,
}

impl SecurityLevel {
    /// Get the minimum required authentication strength for this security level
    #[must_use]
    pub const fn required_auth_strength(&self) -> AuthenticationStrength {
        match self {
            Self::Low => AuthenticationStrength::Basic,
            Self::Standard => AuthenticationStrength::Standard,
            Self::High => AuthenticationStrength::Strong,
            Self::Critical => AuthenticationStrength::MultiFactorRequired,
        }
    }
}

/// Authentication strength levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthenticationStrength {
    Basic,
    Standard,
    Strong,
    MultiFactorRequired,
}

/// Threat indicators that can be detected in requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatIndicator {
    /// Suspicious IP address
    SuspiciousIp { ip: IpAddr, reason: String },
    /// Rate limiting violation
    RateLimitViolation { limit: u32, current: u32 },
    /// Anomalous user agent
    AnomalousUserAgent { user_agent: String, reason: String },
    /// Geolocation anomaly
    GeolocationAnomaly {
        current_location: String,
        expected_location: String,
    },
    /// Time-based anomaly
    TimeAnomaly {
        current_time: SystemTime,
        expected_pattern: String,
    },
    /// Suspicious request pattern
    SuspiciousPattern {
        pattern_type: String,
        confidence: f64,
    },
    /// Known attack signature
    AttackSignature {
        signature_id: String,
        attack_type: String,
    },
}

impl ThreatIndicator {
    /// Get the severity score for this threat indicator (0.0 - 10.0)
    #[must_use]
    pub fn severity_score(&self) -> f64 {
        match self {
            Self::SuspiciousIp { .. } => 6.0,
            Self::RateLimitViolation { limit, current } => {
                let ratio = f64::from(*current) / f64::from(*limit);
                (ratio * 5.0).min(8.0)
            }
            Self::AnomalousUserAgent { .. } => 3.0,
            Self::GeolocationAnomaly { .. } => 7.0,
            Self::TimeAnomaly { .. } => 4.0,
            Self::SuspiciousPattern { confidence, .. } => confidence * 8.0,
            Self::AttackSignature { .. } => 9.0,
        }
    }

    /// Get the threat category
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::SuspiciousIp { .. } => "network",
            Self::RateLimitViolation { .. } => "rate_limit",
            Self::AnomalousUserAgent { .. } => "user_agent",
            Self::GeolocationAnomaly { .. } => "geolocation",
            Self::TimeAnomaly { .. } => "temporal",
            Self::SuspiciousPattern { .. } => "behavioral",
            Self::AttackSignature { .. } => "signature",
        }
    }
}

/// Security flags for different security states
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationRequirement {
    None,
    Basic,
    Enhanced,
}

impl Default for VerificationRequirement {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityStatus {
    Normal,
    Suspicious,
}

impl Default for ActivityStatus {
    fn default() -> Self {
        Self::Normal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BotStatus {
    Human,
    KnownBot,
    Suspicious,
}

impl Default for BotStatus {
    fn default() -> Self {
        Self::Human
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkType {
    Direct,
    Vpn,
    Tor,
    Proxy,
}

impl Default for NetworkType {
    fn default() -> Self {
        Self::Direct
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockingStatus {
    Allowed,
    RateLimited,
    GeoBlocked,
    CaptchaRequired,
}

impl Default for BlockingStatus {
    fn default() -> Self {
        Self::Allowed
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityFlags {
    /// Verification requirement level
    pub verification_level: VerificationRequirement,
    /// Activity classification
    pub activity_status: ActivityStatus,
    /// Bot detection result
    pub bot_status: BotStatus,
    /// Network classification
    pub network_type: NetworkType,
    /// Current blocking status
    pub blocking_status: BlockingStatus,
}

impl SecurityFlags {
    /// Check if any blocking flags are set
    #[must_use]
    pub const fn has_blocking_flags(&self) -> bool {
        !matches!(self.blocking_status, BlockingStatus::Allowed)
    }

    /// Check if any suspicious flags are set
    #[must_use]
    pub const fn has_suspicious_flags(&self) -> bool {
        matches!(self.activity_status, ActivityStatus::Suspicious)
            || !matches!(self.bot_status, BotStatus::Human)
            || !matches!(self.network_type, NetworkType::Direct)
    }

    /// Check if enhanced verification is required
    #[must_use]
    pub const fn requires_enhanced_verification(&self) -> bool {
        matches!(self.verification_level, VerificationRequirement::Enhanced)
    }

    /// Check if CAPTCHA is required
    #[must_use]
    pub const fn requires_captcha(&self) -> bool {
        matches!(self.blocking_status, BlockingStatus::CaptchaRequired)
    }
}

/// Security policy for request evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Policy name
    pub name: String,
    /// Maximum allowed risk score
    pub max_risk_score: f64,
    /// Required authentication strength
    pub required_auth_strength: AuthenticationStrength,
    /// Allowed IP ranges (CIDR notation)
    pub allowed_ip_ranges: Vec<String>,
    /// Blocked IP ranges (CIDR notation)
    pub blocked_ip_ranges: Vec<String>,
    /// Rate limiting configuration
    pub rate_limits: HashMap<String, RateLimit>,
    /// Geographic restrictions
    pub geo_restrictions: Option<GeoRestrictions>,
    /// Additional policy rules
    pub custom_rules: Vec<SecurityRule>,
}

impl SecurityPolicy {
    /// Evaluate a security context against this policy
    #[must_use]
    pub fn evaluate(&self, context: &SecurityContext) -> PolicyEvaluationResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        // Check risk score
        if context.risk_score > self.max_risk_score {
            violations.push(PolicyViolation {
                rule: "max_risk_score".to_string(),
                message: format!(
                    "Risk score {} exceeds maximum {}",
                    context.risk_score, self.max_risk_score
                ),
                severity: ViolationSeverity::High,
            });
        }

        // Check IP restrictions
        if Self::is_ip_blocked(&context.client_ip) {
            violations.push(PolicyViolation {
                rule: "ip_blocked".to_string(),
                message: format!("IP {} is blocked", context.client_ip),
                severity: ViolationSeverity::Critical,
            });
        }

        // Check security flags
        if context.flags.has_blocking_flags() {
            violations.push(PolicyViolation {
                rule: "blocking_flags".to_string(),
                message: "Request has blocking security flags".to_string(),
                severity: ViolationSeverity::High,
            });
        }

        if context.flags.has_suspicious_flags() {
            warnings.push(PolicyViolation {
                rule: "suspicious_flags".to_string(),
                message: "Request has suspicious security flags".to_string(),
                severity: ViolationSeverity::Medium,
            });
        }

        // Evaluate custom rules
        for rule in &self.custom_rules {
            match rule.evaluate(context) {
                RuleResult::Allow => {}
                RuleResult::Warn(message) => warnings.push(PolicyViolation {
                    rule: rule.name.clone(),
                    message,
                    severity: ViolationSeverity::Medium,
                }),
                RuleResult::Deny(message) => violations.push(PolicyViolation {
                    rule: rule.name.clone(),
                    message,
                    severity: ViolationSeverity::High,
                }),
                RuleResult::Block(message) => violations.push(PolicyViolation {
                    rule: rule.name.clone(),
                    message,
                    severity: ViolationSeverity::Critical,
                }),
            }
        }

        let decision = if violations.is_empty() {
            PolicyDecision::Allow
        } else if violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Critical)
        {
            PolicyDecision::Block
        } else {
            PolicyDecision::Deny
        };

        PolicyEvaluationResult {
            decision,
            violations,
            warnings,
            policy_name: self.name.clone(),
        }
    }

    /// Check if an IP address is blocked by this policy
    const fn is_ip_blocked(_ip: &IpAddr) -> bool {
        // Simplified implementation - in reality would check CIDR ranges
        false
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests allowed
    pub max_requests: u32,
    /// Time window for the limit
    pub window: Duration,
    /// Burst allowance
    pub burst: Option<u32>,
}

/// Geographic restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRestrictions {
    /// Allowed countries (ISO codes)
    pub allowed_countries: Vec<String>,
    /// Blocked countries (ISO codes)
    pub blocked_countries: Vec<String>,
}

/// Custom security rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Rule conditions (simplified as string for now)
    pub conditions: String,
    /// Rule action
    pub action: RuleAction,
}

impl SecurityRule {
    /// Evaluate this rule against a security context
    #[must_use]
    pub const fn evaluate(&self, _context: &SecurityContext) -> RuleResult {
        // Simplified implementation - in reality would evaluate conditions
        RuleResult::Allow
    }
}

/// Security rule actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Warn,
    Deny,
    Block,
    RequireAdditionalAuth,
}

/// Result of rule evaluation
#[derive(Debug, Clone)]
pub enum RuleResult {
    Allow,
    Warn(String),
    Deny(String),
    Block(String),
}

/// Policy evaluation result
#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    pub decision: PolicyDecision,
    pub violations: Vec<PolicyViolation>,
    pub warnings: Vec<PolicyViolation>,
    pub policy_name: String,
}

/// Policy decision
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Block,
}

/// Policy violation
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub rule: String,
    pub message: String,
    pub severity: ViolationSeverity,
}

/// Violation severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security event for logging and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: SecurityEventType,
    /// Associated security context
    pub security_context: SecurityContext,
    /// Auth context if available
    pub auth_context: Option<AuthContext>,
    /// Event details
    pub details: HashMap<String, String>,
    /// Event severity
    pub severity: ViolationSeverity,
}

/// Types of security events
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityEventType {
    AuthenticationFailure,
    AuthenticationSuccess,
    AuthenticationAttempt,
    Login,
    AuthorizationDenied,
    SuspiciousActivity,
    RateLimitExceeded,
    PolicyViolation,
    ThreatDetected,
    AnomalyDetected,
    SecurityScanTriggered,
    MfaFailure,
    MfaChallenge,
    PasswordChange,
    DataAccess,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_security_context_creation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user_agent = "Mozilla/5.0 (Test Browser)".to_string();
        let context = SecurityContext::new(ip, user_agent.clone());

        assert_eq!(context.client_ip, ip);
        assert_eq!(context.user_agent, user_agent);
        assert_eq!(context.security_level, SecurityLevel::Standard);
        assert_eq!(context.risk_score, 0.0);
        assert!(!context.is_high_risk());
    }

    #[test]
    fn test_threat_indicator_severity() {
        let indicator = ThreatIndicator::AttackSignature {
            signature_id: "test".to_string(),
            attack_type: "test".to_string(),
        };
        assert_eq!(indicator.severity_score(), 9.0);
        assert_eq!(indicator.category(), "signature");
    }

    #[test]
    fn test_security_level_auth_requirements() {
        assert_eq!(
            SecurityLevel::Low.required_auth_strength(),
            AuthenticationStrength::Basic
        );
        assert_eq!(
            SecurityLevel::Critical.required_auth_strength(),
            AuthenticationStrength::MultiFactorRequired
        );
    }

    #[test]
    fn test_security_flags() {
        let mut flags = SecurityFlags::default();
        assert!(!flags.has_blocking_flags());
        assert!(!flags.has_suspicious_flags());

        flags.blocking_status = BlockingStatus::RateLimited;
        assert!(flags.has_blocking_flags());

        flags.activity_status = ActivityStatus::Suspicious;
        assert!(flags.has_suspicious_flags());
    }

    #[test]
    fn test_risk_score_calculation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user_agent = "Mozilla/5.0 (Test Browser)".to_string();
        let mut context = SecurityContext::new(ip, user_agent);

        context.add_threat_indicator(ThreatIndicator::AttackSignature {
            signature_id: "test".to_string(),
            attack_type: "test".to_string(),
        });

        assert!(context.risk_score > 0.0);
        assert!(context.is_high_risk());
        assert_eq!(context.security_level, SecurityLevel::Critical);
    }
}
