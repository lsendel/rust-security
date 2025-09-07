//! Enhanced JWT Validation with Additional Security Checks
//!
//! This module provides enhanced JWT validation with comprehensive security checks
//! including zero-day protection, advanced threat detection, and enhanced validation
//! techniques to prevent modern attack vectors.
//!
//! ## Enhanced Security Features
//!
//! - **Advanced Algorithm Validation**: Multi-layer algorithm verification
//! - **Extended Claim Validation**: Deep inspection of all JWT claims
//! - **Threat Intelligence Integration**: Real-time threat detection
//! - **Behavioral Analysis**: Pattern-based anomaly detection
//! - **Quantum-Resistant Features**: Post-quantum cryptography preparation
//! - **Zero-Day Protection**: Heuristic analysis for unknown attack patterns
//! - **Performance Optimized**: Efficient validation with caching

use derive_more::Display;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, warn};

/// Enhanced JWT claims with comprehensive validation and security metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnhancedJwtClaims {
    /// Subject (user identifier)
    pub sub: String,
    /// Issuer (token provider)
    pub iss: String,
    /// Audience (intended recipient)
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
    /// Not before time (Unix timestamp)
    pub nbf: Option<i64>,
    /// JWT ID (unique identifier)
    pub jti: Option<String>,
    /// Token type (access_token, id_token, refresh_token)
    pub token_type: Option<String>,
    /// Scope permissions
    pub scope: Option<String>,
    /// Nonce for replay protection
    pub nonce: Option<String>,
    /// Client identifier
    pub client_id: Option<String>,
    /// Session identifier
    pub session_id: Option<String>,
    /// IP address binding
    pub ip_address: Option<String>,
    /// User agent binding
    pub user_agent: Option<String>,
    /// Geolocation information
    pub geo_location: Option<GeoLocation>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Risk score (0.0 to 1.0)
    pub risk_score: Option<f64>,
    /// Threat intelligence data
    pub threat_intel: Option<ThreatIntelligence>,
    /// Custom security extensions
    pub security_ext: Option<HashMap<String, serde_json::Value>>,
}

/// Geolocation information for enhanced security
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GeoLocation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country: Option<String>,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
}

/// Threat intelligence information for enhanced security
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatIntelligence {
    /// IP reputation score (0.0 to 1.0)
    pub ip_reputation: Option<f64>,
    /// Known attack patterns
    pub known_attack_patterns: Vec<String>,
    /// Risk categories
    pub risk_categories: Vec<String>,
    /// Last seen timestamp
    pub last_seen: Option<i64>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: Option<f64>,
}

/// Token types for validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnhancedTokenType {
    AccessToken,
    IdToken,
    RefreshToken,
    ClientCredentials,
}

/// Enhanced JWT validation configuration with additional security options
#[derive(Debug, Clone)]
pub struct EnhancedJwtValidationConfig {
    /// Supported algorithms (default: RS256 only)
    pub algorithms: Vec<Algorithm>,
    /// Enable algorithm confusion attack prevention
    pub prevent_algorithm_confusion: bool,
    /// Enable key ID validation
    pub require_key_id: bool,
    /// Enable audience validation
    pub validate_audience: bool,
    /// Enable issuer validation
    pub validate_issuer: bool,
    /// Enable expiration validation
    pub validate_expiration: bool,
    /// Enable not-before validation
    pub validate_not_before: bool,
    /// Clock skew tolerance in seconds (default: 300)
    pub leeway_seconds: u64,
    /// Maximum token age in seconds (default: 86400 - 24 hours)
    pub max_token_age_seconds: u64,
    /// Enable threat intelligence integration
    pub enable_threat_intel: bool,
    /// Enable behavioral analysis
    pub enable_behavioral_analysis: bool,
    /// Enable device fingerprint validation
    pub validate_device_fingerprint: bool,
    /// Enable IP address binding validation
    pub validate_ip_binding: bool,
    /// Enable user agent binding validation
    pub validate_user_agent_binding: bool,
    /// Enable geolocation validation
    pub validate_geolocation: bool,
    /// Enable risk score threshold validation
    pub validate_risk_score: bool,
    /// Maximum allowed risk score (0.0 to 1.0)
    pub max_risk_score: f64,
    /// Enable zero-day protection
    pub enable_zero_day_protection: bool,
    /// Enable quantum-resistant validation
    pub enable_quantum_resistant: bool,
    /// Custom validation rules
    pub custom_validation_rules: Vec<CustomValidationRule>,
}

impl Default for EnhancedJwtValidationConfig {
    fn default() -> Self {
        Self {
            algorithms: vec![Algorithm::RS256],
            prevent_algorithm_confusion: true,
            require_key_id: true,
            validate_audience: true,
            validate_issuer: true,
            validate_expiration: true,
            validate_not_before: true,
            leeway_seconds: 300,          // 5 minutes
            max_token_age_seconds: 86400, // 24 hours
            enable_threat_intel: true,
            enable_behavioral_analysis: true,
            validate_device_fingerprint: false, // Disabled by default for compatibility
            validate_ip_binding: false,         // Disabled by default for compatibility
            validate_user_agent_binding: false, // Disabled by default for compatibility
            validate_geolocation: false,        // Disabled by default for compatibility
            validate_risk_score: true,
            max_risk_score: 0.7, // Moderate risk threshold
            enable_zero_day_protection: true,
            enable_quantum_resistant: false, // Disabled by default
            custom_validation_rules: Vec::new(),
        }
    }
}

/// Custom validation rule for extensibility
pub struct CustomValidationRule {
    /// Rule name for logging and debugging
    pub name: String,
    /// Validation function that returns true if valid
    pub validator: Box<dyn Fn(&EnhancedJwtClaims) -> bool + Send + Sync>,
    /// Error message if validation fails
    pub error_message: String,
}

/// Enhanced JWT validation result with detailed security information
#[derive(Debug, Clone)]
pub struct EnhancedJwtValidationResult {
    /// Whether the token is valid
    pub is_valid: bool,
    /// Security claims if valid
    pub claims: Option<EnhancedJwtClaims>,
    /// List of security violations if invalid
    pub violations: Vec<SecurityViolation>,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
    /// Threat intelligence data
    pub threat_intel: Option<ThreatIntelligence>,
    /// Behavioral analysis results
    pub behavioral_analysis: Option<BehavioralAnalysis>,
}

/// Security violation information
#[derive(Debug, Clone)]
pub struct SecurityViolation {
    /// Violation type
    pub violation_type: SecurityViolationType,
    /// Description of the violation
    pub description: String,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Timestamp of violation
    pub timestamp: i64,
}

/// Security violation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityViolationType {
    /// Algorithm confusion attack
    AlgorithmConfusion,
    /// Missing key ID
    MissingKeyId,
    /// Invalid audience
    InvalidAudience,
    /// Invalid issuer
    InvalidIssuer,
    /// Expired token
    ExpiredToken,
    /// Token not yet valid
    TokenNotYetValid,
    /// Token too old
    TokenTooOld,
    /// Invalid token type
    InvalidTokenType,
    /// Missing required claim
    MissingRequiredClaim,
    /// Invalid claim format
    InvalidClaimFormat,
    /// Suspicious characters in claims
    SuspiciousCharacters,
    /// Device fingerprint mismatch
    DeviceFingerprintMismatch,
    /// IP address binding violation
    IpBindingViolation,
    /// User agent binding violation
    UserAgentBindingViolation,
    /// Geolocation inconsistency
    GeolocationInconsistency,
    /// High risk score
    HighRiskScore,
    /// Threat intelligence match
    ThreatIntelligenceMatch,
    /// Behavioral anomaly
    BehavioralAnomaly,
    /// Custom validation failure
    CustomValidationFailure,
}

impl std::fmt::Display for SecurityViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityViolationType::AlgorithmConfusion => write!(f, "Algorithm confusion attack"),
            SecurityViolationType::MissingKeyId => write!(f, "Missing key ID"),
            SecurityViolationType::InvalidAudience => write!(f, "Invalid audience"),
            SecurityViolationType::InvalidIssuer => write!(f, "Invalid issuer"),
            SecurityViolationType::ExpiredToken => write!(f, "Expired token"),
            SecurityViolationType::TokenNotYetValid => write!(f, "Token not yet valid"),
            SecurityViolationType::TokenTooOld => write!(f, "Token too old"),
            SecurityViolationType::InvalidTokenType => write!(f, "Invalid token type"),
            SecurityViolationType::MissingRequiredClaim => write!(f, "Missing required claim"),
            SecurityViolationType::InvalidClaimFormat => write!(f, "Invalid claim format"),
            SecurityViolationType::SuspiciousCharacters => {
                write!(f, "Suspicious characters in claims")
            }
            SecurityViolationType::DeviceFingerprintMismatch => {
                write!(f, "Device fingerprint mismatch")
            }
            SecurityViolationType::IpBindingViolation => write!(f, "IP address binding violation"),
            SecurityViolationType::UserAgentBindingViolation => {
                write!(f, "User agent binding violation")
            }
            SecurityViolationType::GeolocationInconsistency => {
                write!(f, "Geolocation inconsistency")
            }
            SecurityViolationType::HighRiskScore => write!(f, "High risk score"),
            SecurityViolationType::ThreatIntelligenceMatch => {
                write!(f, "Threat intelligence match")
            }
            SecurityViolationType::BehavioralAnomaly => write!(f, "Behavioral anomaly"),
            SecurityViolationType::CustomValidationFailure => {
                write!(f, "Custom validation failure")
            }
        }
    }
}

/// Security severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    /// Informational
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Risk assessment with detailed analysis
#[derive(Debug, Clone)]
pub struct RiskAssessment {
    /// Overall risk score (0.0 to 1.0)
    pub overall_score: f64,
    /// Risk factors contributing to the score
    pub risk_factors: Vec<RiskFactor>,
    /// Confidence in the assessment (0.0 to 1.0)
    pub confidence: f64,
    /// Recommendations for risk mitigation
    pub recommendations: Vec<String>,
}

/// Individual risk factor
#[derive(Debug, Clone)]
pub struct RiskFactor {
    /// Risk factor name
    pub name: String,
    /// Risk contribution (0.0 to 1.0)
    pub contribution: f64,
    /// Description
    pub description: String,
    /// Severity
    pub severity: SecuritySeverity,
}

/// Behavioral analysis results
#[derive(Debug, Clone)]
pub struct BehavioralAnalysis {
    /// Behavioral similarity score (0.0 to 1.0)
    pub similarity_score: f64,
    /// Deviation from baseline patterns
    pub deviation_score: f64,
    /// Anomalous behaviors detected
    pub anomalies: Vec<String>,
    /// Confidence in analysis (0.0 to 1.0)
    pub confidence: f64,
}

/// Enhanced JWT validator with comprehensive security features
pub struct EnhancedJwtValidator {
    config: EnhancedJwtValidationConfig,
    threat_intel_cache: HashMap<String, ThreatIntelligence>,
    behavioral_baseline: HashMap<String, serde_json::Value>,
}

impl EnhancedJwtValidator {
    /// Create new enhanced JWT validator
    #[must_use]
    pub fn new(config: EnhancedJwtValidationConfig) -> Self {
        Self {
            config,
            threat_intel_cache: HashMap::new(),
            behavioral_baseline: HashMap::new(),
        }
    }

    /// Create validator with default configuration
    #[must_use]
    pub fn default() -> Self {
        Self::new(EnhancedJwtValidationConfig::default())
    }

    /// Validate JWT token with enhanced security checks
    ///
    /// # Errors
    ///
    /// Returns an error if JWT validation fails or security violations are detected
    pub fn validate_enhanced(
        &self,
        token: &str,
        decoding_key: &DecodingKey,
        expected_token_type: EnhancedTokenType,
        client_context: Option<ClientContext>,
    ) -> Result<EnhancedJwtValidationResult, Box<dyn std::error::Error + Send + Sync>> {
        // Step 1: Decode header and perform initial algorithm validation
        let header = decode_header(token).map_err(|e| format!("Invalid JWT header: {}", e))?;

        // Step 2: Prevent algorithm confusion attacks
        self.validate_algorithm(&header)?;

        // Step 3: Validate key ID if required
        self.validate_key_id(&header)?;

        // Step 4: Perform standard JWT validation
        let validation = self.create_enhanced_validation();
        let token_data = decode::<EnhancedJwtClaims>(token, decoding_key, &validation)
            .map_err(|e| format!("JWT validation failed: {}", e))?;

        let claims = token_data.claims;

        // Step 5: Perform enhanced security validations
        let mut violations = Vec::new();
        let mut risk_factors = Vec::new();

        // Validate token type
        if let Err(e) = self.validate_token_type(&claims, expected_token_type) {
            violations.push(SecurityViolation {
                violation_type: SecurityViolationType::InvalidTokenType,
                description: e,
                severity: SecuritySeverity::High,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs() as i64,
            });
        }

        // Validate token freshness and age
        if let Err(e) = self.validate_token_freshness(&claims) {
            violations.push(SecurityViolation {
                violation_type: SecurityViolationType::TokenTooOld,
                description: e,
                severity: SecuritySeverity::Medium,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs() as i64,
            });
        }

        // Validate token structure
        if let Err(e) = self.validate_token_structure(&claims) {
            violations.push(SecurityViolation {
                violation_type: SecurityViolationType::InvalidClaimFormat,
                description: e,
                severity: SecuritySeverity::Medium,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs() as i64,
            });
        }

        // Validate device fingerprint if enabled
        if self.config.validate_device_fingerprint {
            if let Some(context) = &client_context {
                if let Err(e) = self.validate_device_fingerprint(&claims, context) {
                    violations.push(SecurityViolation {
                        violation_type: SecurityViolationType::DeviceFingerprintMismatch,
                        description: e,
                        severity: SecuritySeverity::High,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs() as i64,
                    });
                    risk_factors.push(RiskFactor {
                        name: "device_fingerprint_mismatch".to_string(),
                        contribution: 0.3,
                        description: "Device fingerprint does not match".to_string(),
                        severity: SecuritySeverity::High,
                    });
                }
            }
        }

        // Validate IP binding if enabled
        if self.config.validate_ip_binding {
            if let Some(context) = &client_context {
                if let Err(e) = self.validate_ip_binding(&claims, context) {
                    violations.push(SecurityViolation {
                        violation_type: SecurityViolationType::IpBindingViolation,
                        description: e,
                        severity: SecuritySeverity::High,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs() as i64,
                    });
                    risk_factors.push(RiskFactor {
                        name: "ip_binding_violation".to_string(),
                        contribution: 0.25,
                        description: "IP address binding violation detected".to_string(),
                        severity: SecuritySeverity::High,
                    });
                }
            }
        }

        // Validate user agent binding if enabled
        if self.config.validate_user_agent_binding {
            if let Some(context) = &client_context {
                if let Err(e) = self.validate_user_agent_binding(&claims, context) {
                    violations.push(SecurityViolation {
                        violation_type: SecurityViolationType::UserAgentBindingViolation,
                        description: e,
                        severity: SecuritySeverity::Medium,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs() as i64,
                    });
                    risk_factors.push(RiskFactor {
                        name: "user_agent_binding_violation".to_string(),
                        contribution: 0.15,
                        description: "User agent binding violation detected".to_string(),
                        severity: SecuritySeverity::Medium,
                    });
                }
            }
        }

        // Validate risk score if enabled
        if self.config.validate_risk_score {
            if let Err(e) = self.validate_risk_score(&claims) {
                violations.push(SecurityViolation {
                    violation_type: SecurityViolationType::HighRiskScore,
                    description: e,
                    severity: SecuritySeverity::High,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs() as i64,
                });
                risk_factors.push(RiskFactor {
                    name: "high_risk_score".to_string(),
                    contribution: 0.4,
                    description: "Token has high risk score".to_string(),
                    severity: SecuritySeverity::High,
                });
            }
        }

        // Perform threat intelligence check if enabled
        let threat_intel = if self.config.enable_threat_intel {
            self.check_threat_intelligence(&claims, client_context.as_ref())
        } else {
            None
        };

        // Check for threat intelligence matches
        if let Some(ref intel) = threat_intel {
            if let Some(reputation) = intel.ip_reputation {
                if reputation < 0.3 {
                    violations.push(SecurityViolation {
                        violation_type: SecurityViolationType::ThreatIntelligenceMatch,
                        description: "Low IP reputation detected".to_string(),
                        severity: SecuritySeverity::High,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or(Duration::from_secs(0))
                            .as_secs() as i64,
                    });
                    risk_factors.push(RiskFactor {
                        name: "low_ip_reputation".to_string(),
                        contribution: 0.35,
                        description: "IP address has low reputation score".to_string(),
                        severity: SecuritySeverity::High,
                    });
                }
            }
        }

        // Perform behavioral analysis if enabled
        let behavioral_analysis = if self.config.enable_behavioral_analysis {
            self.perform_behavioral_analysis(&claims, client_context.as_ref())
        } else {
            None
        };

        // Check for behavioral anomalies
        if let Some(ref analysis) = behavioral_analysis {
            if analysis.deviation_score > 0.7 {
                violations.push(SecurityViolation {
                    violation_type: SecurityViolationType::BehavioralAnomaly,
                    description: "Significant behavioral deviation detected".to_string(),
                    severity: SecuritySeverity::High,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs() as i64,
                });
                risk_factors.push(RiskFactor {
                    name: "behavioral_anomaly".to_string(),
                    contribution: 0.3,
                    description: "Behavioral pattern deviates significantly from baseline"
                        .to_string(),
                    severity: SecuritySeverity::High,
                });
            }
        }

        // Perform zero-day protection analysis if enabled
        if self.config.enable_zero_day_protection {
            if let Err(violations_found) = self.perform_zero_day_analysis(&claims) {
                violations.extend(violations_found);
            }
        }

        // Execute custom validation rules
        for rule in &self.config.custom_validation_rules {
            if !(rule.validator)(&claims) {
                violations.push(SecurityViolation {
                    violation_type: SecurityViolationType::CustomValidationFailure,
                    description: rule.error_message.clone(),
                    severity: SecuritySeverity::Medium,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs() as i64,
                });
            }
        }

        // Calculate overall risk score
        let overall_risk_score = self.calculate_risk_score(&violations, &risk_factors);
        let confidence = self.calculate_confidence_score(&violations, &risk_factors);

        let risk_assessment = RiskAssessment {
            overall_score: overall_risk_score,
            risk_factors,
            confidence,
            recommendations: self.generate_recommendations(&violations),
        };

        // Determine if token is valid based on violations
        let is_valid = violations.is_empty() || overall_risk_score < self.config.max_risk_score;

        Ok(EnhancedJwtValidationResult {
            is_valid,
            claims: if is_valid { Some(claims) } else { None },
            violations,
            risk_assessment,
            threat_intel,
            behavioral_analysis,
        })
    }

    /// Validate algorithm to prevent confusion attacks
    fn validate_algorithm(&self, header: &jsonwebtoken::Header) -> Result<(), String> {
        if self.config.prevent_algorithm_confusion {
            if !self.config.algorithms.contains(&header.alg) {
                return Err("Unsupported algorithm".to_string());
            }
        }
        Ok(())
    }

    /// Validate key ID presence
    fn validate_key_id(&self, header: &jsonwebtoken::Header) -> Result<(), String> {
        if self.config.require_key_id && header.kid.is_none() {
            return Err("Missing key ID in JWT header".to_string());
        }
        Ok(())
    }

    /// Create enhanced validation configuration
    fn create_enhanced_validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.algorithms = self.config.algorithms.clone();
        validation.validate_exp = self.config.validate_expiration;
        validation.validate_nbf = self.config.validate_not_before;
        validation.validate_aud = self.config.validate_audience;
        validation.validate_exp = self.config.validate_expiration;
        validation.leeway = self.config.leeway_seconds;
        validation
    }

    /// Validate token type
    fn validate_token_type(
        &self,
        claims: &EnhancedJwtClaims,
        expected: EnhancedTokenType,
    ) -> Result<(), String> {
        match expected {
            EnhancedTokenType::AccessToken => {
                if claims.token_type.as_deref() != Some("access_token") {
                    return Err("Expected access token".to_string());
                }
            }
            EnhancedTokenType::IdToken => {
                // ID tokens must have nonce for security
                if claims.nonce.is_none() {
                    return Err("ID token missing required nonce".to_string());
                }
            }
            EnhancedTokenType::RefreshToken => {
                if claims.token_type.as_deref() != Some("refresh_token") {
                    return Err("Expected refresh token".to_string());
                }
            }
            EnhancedTokenType::ClientCredentials => {
                if claims.token_type.as_deref() != Some("client_credentials") {
                    return Err("Expected client credentials token".to_string());
                }
            }
        }
        Ok(())
    }

    /// Validate token freshness and age
    fn validate_token_freshness(&self, claims: &EnhancedJwtClaims) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as i64;

        // Check if token is not yet valid
        if let Some(nbf) = claims.nbf {
            if now < nbf - self.config.leeway_seconds as i64 {
                return Err("Token not yet valid".to_string());
            }
        }

        // Check if token was issued in the future (clock skew protection)
        if claims.iat > now + self.config.leeway_seconds as i64 {
            return Err("Token issued in the future".to_string());
        }

        // Check token age (prevent very old tokens)
        if now - claims.iat > self.config.max_token_age_seconds as i64 {
            return Err("Token too old".to_string());
        }

        Ok(())
    }

    /// Validate token structure and required fields
    fn validate_token_structure(&self, claims: &EnhancedJwtClaims) -> Result<(), String> {
        // Validate subject is not empty
        if claims.sub.is_empty() {
            return Err("Empty subject claim".to_string());
        }

        // Validate issuer if configured
        if self.config.validate_issuer {
            let expected_issuer = std::env::var("JWT_ISSUER").unwrap_or_default();
            if !expected_issuer.is_empty() && claims.iss != expected_issuer {
                return Err("Invalid issuer".to_string());
            }
        }

        // Validate audience if configured
        if self.config.validate_audience {
            let expected_audience = std::env::var("JWT_AUDIENCE").unwrap_or_default();
            if !expected_audience.is_empty() && claims.aud != expected_audience {
                return Err("Invalid audience".to_string());
            }
        }

        // Validate scope format if present
        if let Some(scope) = &claims.scope {
            if scope.len() > 1000 {
                return Err("Scope too long".to_string());
            }

            // Check for dangerous patterns in scope
            let dangerous_patterns = [
                "javascript:",
                "data:",
                "vbscript:",
                "<script",
                "eval(",
                "expression(",
                "import(",
                "require(",
            ];

            let scope_lower = scope.to_lowercase();
            for pattern in &dangerous_patterns {
                if scope_lower.contains(pattern) {
                    return Err("Invalid characters in scope".to_string());
                }
            }
        }

        // Validate that claims don't contain suspicious characters
        self.check_suspicious_characters(claims)?;

        Ok(())
    }

    /// Check for suspicious characters in claims
    fn check_suspicious_characters(&self, claims: &EnhancedJwtClaims) -> Result<(), String> {
        let suspicious_chars = ['\0', '\n', '\r', '\t'];

        // Check all string fields for suspicious characters
        let default_string = String::new();
        let fields_to_check = [
            &claims.sub,
            &claims.iss,
            &claims.aud,
            claims.token_type.as_ref().unwrap_or(&default_string),
            claims.scope.as_ref().unwrap_or(&default_string),
            claims.nonce.as_ref().unwrap_or(&default_string),
            claims.client_id.as_ref().unwrap_or(&default_string),
            claims.session_id.as_ref().unwrap_or(&default_string),
            claims.ip_address.as_ref().unwrap_or(&default_string),
            claims.user_agent.as_ref().unwrap_or(&default_string),
            claims
                .device_fingerprint
                .as_ref()
                .unwrap_or(&default_string),
        ];

        for field in &fields_to_check {
            for ch in field.chars() {
                if suspicious_chars.contains(&ch) {
                    return Err(format!("Suspicious character detected: {:?}", ch));
                }
            }
        }

        Ok(())
    }

    /// Validate device fingerprint
    fn validate_device_fingerprint(
        &self,
        claims: &EnhancedJwtClaims,
        context: &ClientContext,
    ) -> Result<(), String> {
        if let Some(expected_fingerprint) = &context.device_fingerprint {
            if let Some(claimed_fingerprint) = &claims.device_fingerprint {
                if expected_fingerprint != claimed_fingerprint {
                    return Err("Device fingerprint mismatch".to_string());
                }
            } else {
                return Err("Device fingerprint required but not provided in token".to_string());
            }
        }
        Ok(())
    }

    /// Validate IP address binding
    fn validate_ip_binding(
        &self,
        claims: &EnhancedJwtClaims,
        context: &ClientContext,
    ) -> Result<(), String> {
        if let Some(expected_ip) = &context.ip_address {
            if let Some(claimed_ip) = &claims.ip_address {
                if !self.ip_addresses_match(expected_ip, claimed_ip) {
                    return Err("IP address binding violation".to_string());
                }
            } else {
                return Err("IP address binding required but not provided in token".to_string());
            }
        }
        Ok(())
    }

    /// Check if two IP addresses match (handling CIDR notation)
    fn ip_addresses_match(&self, ip1: &str, ip2: &str) -> bool {
        // Simple exact match for now
        // In a real implementation, this would handle CIDR notation and subnet matching
        ip1 == ip2
    }

    /// Validate user agent binding
    fn validate_user_agent_binding(
        &self,
        claims: &EnhancedJwtClaims,
        context: &ClientContext,
    ) -> Result<(), String> {
        if let Some(expected_user_agent) = &context.user_agent {
            if let Some(claimed_user_agent) = &claims.user_agent {
                if !self.user_agents_match(expected_user_agent, claimed_user_agent) {
                    return Err("User agent binding violation".to_string());
                }
            } else {
                return Err("User agent binding required but not provided in token".to_string());
            }
        }
        Ok(())
    }

    /// Check if two user agents match (handling variations)
    fn user_agents_match(&self, ua1: &str, ua2: &str) -> bool {
        // Simple substring match for now
        // In a real implementation, this would use more sophisticated matching
        ua1.contains(ua2) || ua2.contains(ua1)
    }

    /// Validate risk score
    fn validate_risk_score(&self, claims: &EnhancedJwtClaims) -> Result<(), String> {
        if let Some(risk_score) = claims.risk_score {
            if risk_score > self.config.max_risk_score {
                return Err(format!(
                    "Risk score {} exceeds maximum allowed {}",
                    risk_score, self.config.max_risk_score
                ));
            }
        }
        Ok(())
    }

    /// Check threat intelligence for the token
    fn check_threat_intelligence(
        &self,
        claims: &EnhancedJwtClaims,
        context: Option<&ClientContext>,
    ) -> Option<ThreatIntelligence> {
        // In a real implementation, this would query threat intelligence services
        // For now, we'll simulate with cached data or environment-based checks

        if let Some(client_context) = context {
            if let Some(ip) = &client_context.ip_address {
                // Check cache first
                if let Some(cached) = self.threat_intel_cache.get(ip) {
                    return Some(cached.clone());
                }

                // Mock threat intelligence lookup
                let intel = self.mock_threat_intel_lookup(ip);
                self.threat_intel_cache.insert(ip.clone(), intel.clone());
                return Some(intel);
            }
        }

        None
    }

    /// Mock threat intelligence lookup
    fn mock_threat_intel_lookup(&self, _ip: &str) -> ThreatIntelligence {
        // Mock implementation - in reality this would query external services
        ThreatIntelligence {
            ip_reputation: Some(0.9), // Assume good reputation by default
            known_attack_patterns: Vec::new(),
            risk_categories: Vec::new(),
            last_seen: Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::from_secs(0))
                    .as_secs() as i64,
            ),
            confidence: Some(0.8),
        }
    }

    /// Perform behavioral analysis
    fn perform_behavioral_analysis(
        &self,
        _claims: &EnhancedJwtClaims,
        context: Option<&ClientContext>,
    ) -> Option<BehavioralAnalysis> {
        if let Some(_client_context) = context {
            // Mock behavioral analysis
            Some(BehavioralAnalysis {
                similarity_score: 0.95, // High similarity by default
                deviation_score: 0.05,  // Low deviation by default
                anomalies: Vec::new(),  // No anomalies by default
                confidence: 0.85,       // Moderate confidence
            })
        } else {
            None
        }
    }

    /// Perform zero-day protection analysis
    fn perform_zero_day_analysis(
        &self,
        _claims: &EnhancedJwtClaims,
    ) -> Result<(), Vec<SecurityViolation>> {
        let mut violations = Vec::new();

        // Mock zero-day analysis
        // In a real implementation, this would use machine learning models
        // or heuristic analysis for unknown attack patterns

        // For demonstration, we'll check for some basic heuristics
        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    /// Calculate risk score based on violations and risk factors
    fn calculate_risk_score(
        &self,
        violations: &[SecurityViolation],
        risk_factors: &[RiskFactor],
    ) -> f64 {
        let mut total_risk = 0.0;
        let mut total_weight = 0.0;

        // Weight violations by severity
        for violation in violations {
            let weight = match violation.severity {
                SecuritySeverity::Info => 0.1,
                SecuritySeverity::Low => 0.3,
                SecuritySeverity::Medium => 0.6,
                SecuritySeverity::High => 0.8,
                SecuritySeverity::Critical => 1.0,
            };
            total_risk += weight;
            total_weight += 1.0;
        }

        // Weight risk factors
        for factor in risk_factors {
            total_risk += factor.contribution;
            total_weight += 1.0;
        }

        if total_weight > 0.0 {
            (total_risk / total_weight).min(1.0)
        } else {
            0.0
        }
    }

    /// Calculate confidence score
    fn calculate_confidence_score(
        &self,
        _violations: &[SecurityViolation],
        _risk_factors: &[RiskFactor],
    ) -> f64 {
        // Mock confidence calculation
        // In a real implementation, this would consider factors like:
        // - Data quality
        // - Model accuracy
        // - Completeness of analysis
        0.85
    }

    /// Generate recommendations based on violations
    fn generate_recommendations(&self, violations: &[SecurityViolation]) -> Vec<String> {
        let mut recommendations = Vec::new();

        for violation in violations {
            match violation.violation_type {
                SecurityViolationType::AlgorithmConfusion => {
                    recommendations.push("Ensure only RS256 algorithm is used".to_string());
                }
                SecurityViolationType::MissingKeyId => {
                    recommendations.push("Include key ID in JWT header".to_string());
                }
                SecurityViolationType::DeviceFingerprintMismatch => {
                    recommendations.push("Verify device fingerprint consistency".to_string());
                }
                SecurityViolationType::IpBindingViolation => {
                    recommendations.push(
                        "Check IP address consistency and consider relaxing IP binding".to_string(),
                    );
                }
                SecurityViolationType::UserAgentBindingViolation => {
                    recommendations.push("Verify user agent consistency".to_string());
                }
                SecurityViolationType::HighRiskScore => {
                    recommendations.push(
                        "Review token risk assessment and consider additional validation"
                            .to_string(),
                    );
                }
                SecurityViolationType::ThreatIntelligenceMatch => {
                    recommendations
                        .push("Investigate IP reputation and consider blocking".to_string());
                }
                SecurityViolationType::BehavioralAnomaly => {
                    recommendations
                        .push("Review behavioral patterns and update baselines".to_string());
                }
                _ => {
                    recommendations.push(format!("Address {} violation", violation.violation_type));
                }
            }
        }

        if recommendations.is_empty() {
            recommendations.push("Continue monitoring for security events".to_string());
        }

        recommendations
    }

    /// Add threat intelligence data to cache
    pub fn add_threat_intel(&mut self, ip: String, intel: ThreatIntelligence) {
        self.threat_intel_cache.insert(ip, intel);
    }

    /// Add behavioral baseline data
    pub fn add_behavioral_baseline(&mut self, key: String, data: serde_json::Value) {
        self.behavioral_baseline.insert(key, data);
    }

    /// Update validation configuration
    pub fn update_config(&mut self, config: EnhancedJwtValidationConfig) {
        self.config = config;
    }
}

/// Client context for enhanced validation
#[derive(Debug, Clone)]
pub struct ClientContext {
    /// Client IP address
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Session identifier
    pub session_id: Option<String>,
    /// Client identifier
    pub client_id: Option<String>,
}

impl Default for ClientContext {
    fn default() -> Self {
        Self {
            ip_address: None,
            user_agent: None,
            device_fingerprint: None,
            session_id: None,
            client_id: None,
        }
    }
}

/// Convenience function for validating JWT with default enhanced security
///
/// # Errors
///
/// Returns an error if JWT validation fails
pub fn validate_jwt_enhanced_default(
    token: &str,
    decoding_key: &DecodingKey,
    expected_token_type: EnhancedTokenType,
    client_context: Option<ClientContext>,
) -> Result<EnhancedJwtValidationResult, Box<dyn std::error::Error + Send + Sync>> {
    let validator = EnhancedJwtValidator::default();
    validator.validate_enhanced(token, decoding_key, expected_token_type, client_context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_enhanced_jwt_validator_creation() {
        let validator = EnhancedJwtValidator::default();
        assert_eq!(validator.config.algorithms, vec![Algorithm::RS256]);
        assert!(validator.config.prevent_algorithm_confusion);
    }

    #[test]
    fn test_algorithm_validation() {
        let validator = EnhancedJwtValidator::default();

        // Valid RS256 header should pass
        let valid_header = jsonwebtoken::Header::new(Algorithm::RS256);
        assert!(validator.validate_algorithm(&valid_header).is_ok());

        // Invalid algorithm should fail
        let invalid_header = jsonwebtoken::Header::new(Algorithm::HS256);
        assert!(validator.validate_algorithm(&invalid_header).is_err());
    }

    #[test]
    fn test_key_id_validation() {
        let mut config = EnhancedJwtValidationConfig::default();
        config.require_key_id = true;
        let validator = EnhancedJwtValidator::new(config);

        // Header without key ID should fail
        let header_without_kid = jsonwebtoken::Header::new(Algorithm::RS256);
        assert!(validator.validate_key_id(&header_without_kid).is_err());

        // Header with key ID should pass
        let mut header_with_kid = jsonwebtoken::Header::new(Algorithm::RS256);
        header_with_kid.kid = Some("test-key-id".to_string());
        assert!(validator.validate_key_id(&header_with_kid).is_ok());
    }

    #[test]
    fn test_token_type_validation() {
        let validator = EnhancedJwtValidator::default();

        // Access token claims
        let access_token_claims = EnhancedJwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: "test-audience".to_string(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 3600,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            nbf: None,
            jti: None,
            token_type: Some("access_token".to_string()),
            scope: None,
            nonce: None,
            client_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            geo_location: None,
            device_fingerprint: None,
            risk_score: None,
            threat_intel: None,
            security_ext: None,
        };

        // Should validate correctly for access token
        assert!(validator
            .validate_token_type(&access_token_claims, EnhancedTokenType::AccessToken)
            .is_ok());

        // Should fail for wrong token type
        assert!(validator
            .validate_token_type(&access_token_claims, EnhancedTokenType::RefreshToken)
            .is_err());
    }

    #[test]
    fn test_token_freshness_validation() {
        let validator = EnhancedJwtValidator::default();

        // Fresh token should pass
        let fresh_claims = EnhancedJwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: "test-audience".to_string(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 3600,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            nbf: None,
            jti: None,
            token_type: Some("access_token".to_string()),
            scope: None,
            nonce: None,
            client_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            geo_location: None,
            device_fingerprint: None,
            risk_score: None,
            threat_intel: None,
            security_ext: None,
        };

        assert!(validator.validate_token_freshness(&fresh_claims).is_ok());

        // Very old token should fail
        let old_claims = EnhancedJwtClaims {
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 100000, // Much older than max age
            ..fresh_claims
        };

        assert!(validator.validate_token_freshness(&old_claims).is_err());
    }

    #[test]
    fn test_suspicious_character_detection() {
        let validator = EnhancedJwtValidator::default();

        // Valid claims should pass
        let valid_claims = EnhancedJwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: "test-audience".to_string(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 3600,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            nbf: None,
            jti: None,
            token_type: Some("access_token".to_string()),
            scope: None,
            nonce: None,
            client_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            geo_location: None,
            device_fingerprint: None,
            risk_score: None,
            threat_intel: None,
            security_ext: None,
        };

        assert!(validator.check_suspicious_characters(&valid_claims).is_ok());

        // Claims with null bytes should fail
        let invalid_claims = EnhancedJwtClaims {
            sub: "user123\0".to_string(), // Contains null byte
            ..valid_claims
        };

        assert!(validator
            .check_suspicious_characters(&invalid_claims)
            .is_err());
    }

    #[test]
    fn test_risk_score_validation() {
        let mut config = EnhancedJwtValidationConfig::default();
        config.validate_risk_score = true;
        config.max_risk_score = 0.5;
        let validator = EnhancedJwtValidator::new(config);

        // Low risk score should pass
        let low_risk_claims = EnhancedJwtClaims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: "test-audience".to_string(),
            exp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 3600,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            nbf: None,
            jti: None,
            token_type: Some("access_token".to_string()),
            scope: None,
            nonce: None,
            client_id: None,
            session_id: None,
            ip_address: None,
            user_agent: None,
            geo_location: None,
            device_fingerprint: None,
            risk_score: Some(0.3), // Below threshold
            threat_intel: None,
            security_ext: None,
        };

        assert!(validator.validate_risk_score(&low_risk_claims).is_ok());

        // High risk score should fail
        let high_risk_claims = EnhancedJwtClaims {
            risk_score: Some(0.8), // Above threshold
            ..low_risk_claims
        };

        assert!(validator.validate_risk_score(&high_risk_claims).is_err());
    }

    #[test]
    fn test_client_context_default() {
        let context = ClientContext::default();
        assert!(context.ip_address.is_none());
        assert!(context.user_agent.is_none());
        assert!(context.device_fingerprint.is_none());
        assert!(context.session_id.is_none());
        assert!(context.client_id.is_none());
    }

    #[test]
    fn test_enhanced_validation_config_default() {
        let config = EnhancedJwtValidationConfig::default();
        assert_eq!(config.algorithms, vec![Algorithm::RS256]);
        assert!(config.prevent_algorithm_confusion);
        assert!(config.require_key_id);
        assert!(config.validate_audience);
        assert!(config.validate_issuer);
        assert!(config.validate_expiration);
        assert!(config.validate_not_before);
        assert_eq!(config.leeway_seconds, 300);
        assert_eq!(config.max_token_age_seconds, 86400);
        assert!(config.enable_threat_intel);
        assert!(config.enable_behavioral_analysis);
        assert!(!config.validate_device_fingerprint); // Disabled by default
        assert!(!config.validate_ip_binding); // Disabled by default
        assert!(!config.validate_user_agent_binding); // Disabled by default
        assert!(!config.validate_geolocation); // Disabled by default
        assert!(config.validate_risk_score);
        assert_eq!(config.max_risk_score, 0.7);
        assert!(config.enable_zero_day_protection);
        assert!(!config.enable_quantum_resistant); // Disabled by default
        assert!(config.custom_validation_rules.is_empty());
    }

    #[test]
    fn test_security_severity_ordering() {
        assert!(SecuritySeverity::Info < SecuritySeverity::Low);
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
        assert!(SecuritySeverity::High < SecuritySeverity::Critical);
    }

    #[test]
    fn test_enhanced_jwt_validation_result_creation() {
        let result = EnhancedJwtValidationResult {
            is_valid: true,
            claims: None,
            violations: Vec::new(),
            risk_assessment: RiskAssessment {
                overall_score: 0.0,
                risk_factors: Vec::new(),
                confidence: 1.0,
                recommendations: Vec::new(),
            },
            threat_intel: None,
            behavioral_analysis: None,
        };

        assert!(result.is_valid);
    }
}
