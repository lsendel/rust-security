//! Enhanced JWT Validation with Security Constraints
//!
//! This module provides comprehensive JWT validation with strict security constraints
//! including audience, issuer, algorithm, and token type validation.

use crate::infrastructure::monitoring::security_logging_enhanced::{
    SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity,
};
use crate::shared::error::AppError;
use anyhow::{anyhow, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

/// JWT validation configuration with security constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtValidationConfig {
    /// Required issuer (iss claim) - must match exactly
    pub required_issuer: Option<String>,
    /// Allowed audiences (aud claim) - token must contain at least one
    pub allowed_audiences: Option<HashSet<String>>,
    /// Allowed algorithms - restricts which signing algorithms are accepted
    pub allowed_algorithms: HashSet<Algorithm>,
    /// Required token type (typ header) - typically "JWT"
    pub required_token_type: Option<String>,
    /// Clock skew tolerance in seconds
    pub leeway_seconds: u64,
    /// Whether to validate expiration time
    pub validate_expiration: bool,
    /// Whether to validate not-before time
    pub validate_not_before: bool,
    /// Whether to validate issued-at time
    pub validate_issued_at: bool,
    /// Maximum token age in seconds (validates iat claim)
    pub max_token_age_seconds: Option<u64>,
    /// Required claims that must be present
    pub required_claims: HashSet<String>,
    /// Custom claim validators
    pub custom_validators: Vec<CustomClaimValidator>,
}

impl Default for JwtValidationConfig {
    fn default() -> Self {
        let mut allowed_algorithms = HashSet::new();
        allowed_algorithms.insert(Algorithm::RS256);
        allowed_algorithms.insert(Algorithm::RS384);
        allowed_algorithms.insert(Algorithm::RS512);
        allowed_algorithms.insert(Algorithm::ES256);
        allowed_algorithms.insert(Algorithm::ES384);
        allowed_algorithms.insert(Algorithm::EdDSA);

        let mut required_claims = HashSet::new();
        required_claims.insert("sub".to_string());
        required_claims.insert("iat".to_string());
        required_claims.insert("exp".to_string());

        Self {
            required_issuer: std::env::var("JWT_REQUIRED_ISSUER").ok(),
            allowed_audiences: std::env::var("JWT_ALLOWED_AUDIENCES")
                .ok()
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect()),
            allowed_algorithms,
            required_token_type: Some("JWT".to_string()),
            leeway_seconds: 60,
            validate_expiration: true,
            validate_not_before: true,
            validate_issued_at: true,
            max_token_age_seconds: Some(24 * 60 * 60), // 24 hours
            required_claims,
            custom_validators: Vec::new(),
        }
    }
}

/// Custom claim validator function
#[derive(Debug, Clone)]
pub struct CustomClaimValidator {
    pub claim_name: String,
    pub description: String,
    pub validator: fn(&Value) -> Result<(), String>,
}

// Custom serialization for CustomClaimValidator since function pointers can't be serialized
impl Serialize for CustomClaimValidator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CustomClaimValidator", 2)?;
        state.serialize_field("claim_name", &self.claim_name)?;
        state.serialize_field("description", &self.description)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CustomClaimValidator {
    fn deserialize<D>(_deserializer: D) -> Result<CustomClaimValidator, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // For deserialization, we can't restore function pointers, so we provide a default
        Ok(CustomClaimValidator {
            claim_name: String::new(),
            description: String::new(),
            validator: |_| Ok(()),
        })
    }
}

/// Enhanced JWT validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtValidationResult {
    pub claims: Value,
    pub header: jsonwebtoken::Header,
    pub validation_metadata: ValidationMetadata,
}

/// Metadata about the validation process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationMetadata {
    pub algorithm_used: String,
    pub key_id: Option<String>,
    pub issuer: Option<String>,
    pub audience: Option<Vec<String>>,
    pub subject: Option<String>,
    pub expires_at: Option<i64>,
    pub issued_at: Option<i64>,
    pub not_before: Option<i64>,
    pub validation_time: i64,
    pub token_age_seconds: Option<i64>,
}

/// Enhanced JWT validator with comprehensive security constraints
pub struct EnhancedJwtValidator {
    config: JwtValidationConfig,
}

impl EnhancedJwtValidator {
    /// Create a new enhanced JWT validator with the given configuration
    pub fn new(config: JwtValidationConfig) -> Self {
        Self { config }
    }

    /// Create validator from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = JwtValidationConfig::default();

        // Override with environment variables
        if let Ok(issuer) = std::env::var("JWT_REQUIRED_ISSUER") {
            config.required_issuer = Some(issuer);
        }

        if let Ok(audiences) = std::env::var("JWT_ALLOWED_AUDIENCES") {
            config.allowed_audiences =
                Some(audiences.split(',').map(|s| s.trim().to_string()).collect());
        }

        if let Ok(max_age) = std::env::var("JWT_MAX_AGE_SECONDS") {
            config.max_token_age_seconds = Some(
                max_age
                    .parse()
                    .map_err(|_| anyhow!("Invalid JWT_MAX_AGE_SECONDS value"))?,
            );
        }

        if let Ok(leeway) = std::env::var("JWT_LEEWAY_SECONDS") {
            config.leeway_seconds = leeway
                .parse()
                .map_err(|_| anyhow!("Invalid JWT_LEEWAY_SECONDS value"))?;
        }

        Ok(Self::new(config))
    }

    /// Validate a JWT token with comprehensive security checks
    pub async fn validate_token(
        &self,
        token: &str,
        decoding_key: &DecodingKey,
    ) -> Result<JwtValidationResult, crate::shared::error::AppError> {
        let validation_start = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Step 1: Decode header and perform algorithm validation
        let header = jsonwebtoken::decode_header(token).map_err(|e| {
            crate::shared::error::AppError::InvalidToken(format!("Invalid JWT header: {}", e))
        })?;

        self.validate_algorithm(&header.alg)?;
        self.validate_token_type(&header)?;

        // Step 2: Set up validation parameters
        let validation = self.create_validation_params(&header.alg)?;

        // Step 3: Decode and validate token structure
        let token_data =
            jsonwebtoken::decode::<Value>(token, decoding_key, &validation).map_err(|e| {
                self.log_validation_failure("JWT decode failed", &e.to_string());
                crate::shared::error::AppError::InvalidToken(format!(
                    "JWT validation failed: {}",
                    e
                ))
            })?;

        // Step 4: Perform additional custom validations
        self.validate_claims(&token_data.claims)?;
        self.validate_token_age(&token_data.claims, validation_start)?;
        self.run_custom_validators(&token_data.claims)?;

        // Step 5: Create validation result with metadata
        let validation_metadata =
            self.create_validation_metadata(&header, &token_data.claims, validation_start)?;

        let result = JwtValidationResult {
            claims: token_data.claims,
            header,
            validation_metadata,
        };

        self.log_validation_success(&result);
        Ok(result)
    }

    /// Validate that the algorithm is in the allowed list
    fn validate_algorithm(
        &self,
        algorithm: &Algorithm,
    ) -> Result<(), crate::shared::error::AppError> {
        if !self.config.allowed_algorithms.contains(algorithm) {
            let error_msg = format!(
                "Algorithm {:?} not in allowed algorithms: {:?}",
                algorithm, self.config.allowed_algorithms
            );
            self.log_validation_failure("Algorithm not allowed", &error_msg);
            return Err(crate::shared::error::AppError::InvalidToken(error_msg));
        }
        Ok(())
    }

    /// Validate token type in header
    fn validate_token_type(
        &self,
        header: &jsonwebtoken::Header,
    ) -> Result<(), crate::shared::error::AppError> {
        if let Some(required_type) = &self.config.required_token_type {
            let default_type = "JWT".to_string();
            let token_type = header.typ.as_ref().unwrap_or(&default_type);
            if token_type != required_type {
                let error_msg = format!(
                    "Token type '{}' does not match required type '{}'",
                    token_type, required_type
                );
                self.log_validation_failure("Invalid token type", &error_msg);
                return Err(crate::shared::error::AppError::InvalidToken(error_msg));
            }
        }
        Ok(())
    }

    /// Create validation parameters based on configuration
    fn create_validation_params(
        &self,
        algorithm: &Algorithm,
    ) -> Result<Validation, crate::shared::error::AppError> {
        let mut validation = Validation::new(*algorithm);

        validation.validate_exp = self.config.validate_expiration;
        validation.validate_nbf = self.config.validate_not_before;
        validation.leeway = self.config.leeway_seconds;

        // Set issuer validation
        if let Some(ref issuer) = self.config.required_issuer {
            validation.set_issuer(&[issuer]);
        }

        // Set audience validation
        if let Some(ref audiences) = self.config.allowed_audiences {
            let audience_vec: Vec<&str> = audiences.iter().map(|s| s.as_str()).collect();
            validation.set_audience(&audience_vec);
        }

        // Require specific claims
        let required_claims: Vec<&str> = self
            .config
            .required_claims
            .iter()
            .map(|s| s.as_str())
            .collect();
        validation.set_required_spec_claims(&required_claims);

        Ok(validation)
    }

    /// Validate required claims are present
    fn validate_claims(&self, claims: &Value) -> Result<(), crate::shared::error::AppError> {
        for required_claim in &self.config.required_claims {
            if !claims.get(required_claim).is_some() {
                let error_msg = format!("Missing required claim: {}", required_claim);
                self.log_validation_failure("Missing required claim", &error_msg);
                return Err(crate::shared::error::AppError::InvalidToken(error_msg));
            }
        }
        Ok(())
    }

    /// Validate token age if configured
    fn validate_token_age(
        &self,
        claims: &Value,
        current_time: i64,
    ) -> Result<(), crate::shared::error::AppError> {
        if let Some(max_age) = self.config.max_token_age_seconds {
            if let Some(iat) = claims.get("iat").and_then(|v| v.as_i64()) {
                let token_age = current_time - iat;
                if token_age > max_age as i64 {
                    let error_msg = format!(
                        "Token age {} seconds exceeds maximum allowed age {} seconds",
                        token_age, max_age
                    );
                    self.log_validation_failure("Token too old", &error_msg);
                    return Err(crate::shared::error::AppError::InvalidToken(error_msg));
                }
            }
        }
        Ok(())
    }

    /// Run custom claim validators
    fn run_custom_validators(&self, claims: &Value) -> Result<(), crate::shared::error::AppError> {
        for validator in &self.config.custom_validators {
            if let Some(claim_value) = claims.get(&validator.claim_name) {
                if let Err(error) = (validator.validator)(claim_value) {
                    let error_msg = format!(
                        "Custom validation failed for claim '{}': {}",
                        validator.claim_name, error
                    );
                    self.log_validation_failure("Custom validation failed", &error_msg);
                    return Err(crate::shared::error::AppError::InvalidToken(error_msg));
                }
            }
        }
        Ok(())
    }

    /// Create validation metadata
    fn create_validation_metadata(
        &self,
        header: &jsonwebtoken::Header,
        claims: &Value,
        validation_time: i64,
    ) -> Result<ValidationMetadata, crate::shared::error::AppError> {
        let issued_at = claims.get("iat").and_then(|v| v.as_i64());
        let token_age = issued_at.map(|iat| validation_time - iat);

        Ok(ValidationMetadata {
            algorithm_used: format!("{:?}", header.alg),
            key_id: header.kid.clone(),
            issuer: claims
                .get("iss")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            audience: claims.get("aud").and_then(|v| match v {
                Value::String(s) => Some(vec![s.clone()]),
                Value::Array(arr) => Some(
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect(),
                ),
                _ => None,
            }),
            subject: claims
                .get("sub")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            expires_at: claims.get("exp").and_then(|v| v.as_i64()),
            issued_at,
            not_before: claims.get("nbf").and_then(|v| v.as_i64()),
            validation_time,
            token_age_seconds: token_age,
        })
    }

    /// Log successful validation
    fn log_validation_success(&self, result: &JwtValidationResult) {
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::DataAccess,
                SecuritySeverity::Low,
                "jwt-validation".to_string(),
                "JWT token validation successful".to_string(),
            )
            .with_actor("jwt_validator".to_string())
            .with_action("validate_token".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("success".to_string())
            .with_reason("JWT token passed all security validations".to_string())
            .with_detail(
                "algorithm".to_string(),
                result.validation_metadata.algorithm_used.clone(),
            )
            .with_detail(
                "issuer".to_string(),
                result
                    .validation_metadata
                    .issuer
                    .clone()
                    .unwrap_or_default(),
            )
            .with_detail(
                "subject".to_string(),
                result
                    .validation_metadata
                    .subject
                    .clone()
                    .unwrap_or_default(),
            )
            .with_detail(
                "token_age_seconds".to_string(),
                result
                    .validation_metadata
                    .token_age_seconds
                    .unwrap_or_default(),
            ),
        );
    }

    /// Log validation failure
    fn log_validation_failure(&self, failure_type: &str, details: &str) {
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::SecurityViolation,
                SecuritySeverity::High,
                "jwt-validation".to_string(),
                format!("JWT validation failed: {}", failure_type),
            )
            .with_actor("jwt_validator".to_string())
            .with_action("validate_token".to_string())
            .with_target("jwt_token".to_string())
            .with_outcome("failure".to_string())
            .with_reason(details.to_string()),
        );
    }

    /// Get current configuration
    pub fn get_config(&self) -> &JwtValidationConfig {
        &self.config
    }

    /// Update configuration
    pub fn update_config(&mut self, config: JwtValidationConfig) {
        self.config = config;
    }
}

impl Default for EnhancedJwtValidator {
    fn default() -> Self {
        Self::new(JwtValidationConfig::default())
    }
}

/// Convenience function to create a validator for OAuth access tokens
pub fn create_oauth_access_token_validator(
) -> Result<EnhancedJwtValidator, crate::shared::error::AppError> {
    let mut config = JwtValidationConfig::default();

    // OAuth-specific claims
    config.required_claims.insert("token_type".to_string());
    config.required_claims.insert("scope".to_string());

    // Add custom validator for token_type
    config.custom_validators.push(CustomClaimValidator {
        claim_name: "token_type".to_string(),
        description: "Validate token type is access_token".to_string(),
        validator: |value| {
            if let Some(token_type) = value.as_str() {
                if token_type == "access_token" {
                    Ok(())
                } else {
                    Err(format!(
                        "Expected token_type 'access_token', got '{}'",
                        token_type
                    ))
                }
            } else {
                Err("token_type must be a string".to_string())
            }
        },
    });

    Ok(EnhancedJwtValidator::new(config))
}

/// Convenience function to create a validator for ID tokens
pub fn create_id_token_validator() -> Result<EnhancedJwtValidator, crate::shared::error::AppError> {
    let mut config = JwtValidationConfig::default();

    // ID token specific claims
    config.required_claims.insert("aud".to_string());
    config.required_claims.insert("nonce".to_string());

    // Shorter max age for ID tokens
    config.max_token_age_seconds = Some(60 * 60); // 1 hour

    Ok(EnhancedJwtValidator::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    #[test]
    fn test_config_default() {
        let config = JwtValidationConfig::default();
        assert!(config.validate_expiration);
        assert!(config.validate_not_before);
        assert_eq!(config.leeway_seconds, 60);
        assert!(config.allowed_algorithms.contains(&Algorithm::RS256));
    }

    #[test]
    fn test_algorithm_validation() {
        let config = JwtValidationConfig {
            allowed_algorithms: [Algorithm::RS256].iter().cloned().collect(),
            ..Default::default()
        };
        let validator = EnhancedJwtValidator::new(config);

        // Should pass
        assert!(validator.validate_algorithm(&Algorithm::RS256).is_ok());

        // Should fail
        assert!(validator.validate_algorithm(&Algorithm::HS256).is_err());
    }

    #[test]
    fn test_oauth_validator_creation() {
        let validator = create_oauth_access_token_validator().unwrap();
        assert!(validator.config.required_claims.contains("token_type"));
        assert!(validator.config.required_claims.contains("scope"));
    }

    #[test]
    fn test_id_token_validator_creation() {
        let validator = create_id_token_validator().unwrap();
        assert!(validator.config.required_claims.contains("aud"));
        assert!(validator.config.required_claims.contains("nonce"));
        assert_eq!(validator.config.max_token_age_seconds, Some(3600));
    }
}
