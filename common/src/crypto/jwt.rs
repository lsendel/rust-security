//! Unified JWT Operations
//!
//! Consolidates JWT functionality from multiple implementations:
//! - `auth-service/src/security/jwt.rs` - Main JWT module
//! - `auth-service/src/jwt_secure.rs` - Secure validation
//! - `auth-service/src/enhanced_jwt_validation.rs` - Enhanced validation
//! - `auth-service/src/infrastructure/crypto/jwks_rotation.rs` - Key rotation
//! - `auth-service/src/infrastructure/crypto/quantum_jwt.rs` - Post-quantum JWT

use super::*;
use crate::security::UnifiedSecurityConfig;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// JWT-specific errors
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Token validation failed: {0}")]
    ValidationFailed(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token format: {0}")]
    InvalidFormat(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Encoding failed: {0}")]
    EncodingFailed(String),

    #[error("Decoding failed: {0}")]
    DecodingFailed(String),

    #[error("Algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatch { expected: String, actual: String },

    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },

    #[error("Invalid audience: expected {expected:?}, got {actual:?}")]
    InvalidAudience {
        expected: Vec<String>,
        actual: Option<Vec<String>>,
    },
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// JWT signing secret (32+ characters)
    pub secret: String,

    /// JWT algorithm
    pub algorithm: JwtAlgorithm,

    /// Access token TTL in seconds
    pub access_token_ttl: u64,

    /// Refresh token TTL in seconds
    pub refresh_token_ttl: u64,

    /// JWT issuer
    pub issuer: String,

    /// JWT audience (optional)
    pub audience: Option<Vec<String>>,

    /// Enable token binding
    pub token_binding: bool,

    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,

    /// Maximum number of keys to keep
    pub max_keys: usize,

    /// Enable JWKS endpoint
    pub enable_jwks: bool,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: "REPLACE_IN_PRODUCTION_WITH_STRONG_SECRET_KEY_32_CHARS_MIN".to_string(),
            algorithm: JwtAlgorithm::HS256,
            access_token_ttl: 900,    // 15 minutes
            refresh_token_ttl: 86400, // 24 hours
            issuer: "rust-security-platform".to_string(),
            audience: None,
            token_binding: false,
            key_rotation_interval: 3600, // 1 hour
            max_keys: 3,
            enable_jwks: true,
        }
    }
}

impl FromEnvironment for JwtConfig {
    fn from_env() -> CryptoResult<Self> {
        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
            "REPLACE_IN_PRODUCTION_WITH_STRONG_SECRET_KEY_32_CHARS_MIN".to_string()
        });

        let algorithm = env::var("JWT_ALGORITHM")
            .unwrap_or_else(|_| "HS256".to_string())
            .parse()
            .map_err(|_| CryptoError::InvalidConfiguration("Invalid JWT algorithm".to_string()))?;

        let access_token_ttl = env::var("JWT_ACCESS_TOKEN_TTL")
            .unwrap_or_else(|_| "900".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid access token TTL".to_string())
            })?;

        let refresh_token_ttl = env::var("JWT_REFRESH_TOKEN_TTL")
            .unwrap_or_else(|_| "86400".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid refresh token TTL".to_string())
            })?;

        let issuer =
            env::var("JWT_ISSUER").unwrap_or_else(|_| "rust-security-platform".to_string());

        let audience = env::var("JWT_AUDIENCE")
            .ok()
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect());

        let token_binding = env::var("JWT_TOKEN_BINDING")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let key_rotation_interval = env::var("JWT_KEY_ROTATION_INTERVAL")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid key rotation interval".to_string())
            })?;

        let max_keys = env::var("JWT_MAX_KEYS")
            .unwrap_or_else(|_| "3".to_string())
            .parse()
            .map_err(|_| CryptoError::InvalidConfiguration("Invalid max keys".to_string()))?;

        let enable_jwks = env::var("JWT_ENABLE_JWKS")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        Ok(Self {
            secret,
            algorithm,
            access_token_ttl,
            refresh_token_ttl,
            issuer,
            audience,
            token_binding,
            key_rotation_interval,
            max_keys,
            enable_jwks,
        })
    }
}

impl CryptoValidation for JwtConfig {
    fn validate(&self) -> CryptoResult<()> {
        // Secret validation
        if self.secret.len() < 32 {
            return Err(CryptoError::ValidationFailed(
                "JWT secret must be at least 32 characters".to_string(),
            ));
        }

        // Check for development defaults
        if self.secret.contains("REPLACE_IN_PRODUCTION")
            || self.secret.contains("changeme")
            || self.secret.contains("dev")
        {
            return Err(CryptoError::ValidationFailed(
                "JWT secret contains insecure default values".to_string(),
            ));
        }

        // TTL validation
        if self.access_token_ttl < 300 || self.access_token_ttl > 3600 {
            warn!(
                "Access token TTL outside recommended range (5-60 minutes): {}s",
                self.access_token_ttl
            );
        }

        if self.refresh_token_ttl <= self.access_token_ttl {
            return Err(CryptoError::ValidationFailed(
                "Refresh token TTL must be greater than access token TTL".to_string(),
            ));
        }

        // Issuer validation
        if self.issuer.is_empty() {
            return Err(CryptoError::ValidationFailed(
                "JWT issuer cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,

    /// Issuer
    pub iss: String,

    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,

    /// Expiration time (Unix timestamp)
    pub exp: u64,

    /// Issued at (Unix timestamp)
    pub iat: u64,

    /// Not before (Unix timestamp)
    pub nbf: u64,

    /// JWT ID (unique identifier)
    pub jti: String,

    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// JWT key material
#[derive(Clone)]
pub struct JwtKey {
    pub kid: String,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub algorithm: Algorithm,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for JwtKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKey")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Unified JWT operations
#[derive(Debug)]
pub struct JwtOperations {
    config: JwtConfig,
    keys: Arc<RwLock<Vec<JwtKey>>>,
    current_key_id: Arc<RwLock<String>>,
}

impl JwtOperations {
    /// Create new JWT operations instance
    pub async fn new(config: JwtConfig) -> CryptoResult<Self> {
        config.validate()?;

        let operations = Self {
            config: config.clone(),
            keys: Arc::new(RwLock::new(Vec::new())),
            current_key_id: Arc::new(RwLock::new(String::new())),
        };

        // Initialize with first key
        operations.rotate_keys().await?;

        Ok(operations)
    }

    /// Create JWT from unified security config
    pub async fn from_security_config(
        security_config: &UnifiedSecurityConfig,
    ) -> CryptoResult<Self> {
        let jwt_config = JwtConfig {
            secret: security_config.jwt.secret.clone(),
            algorithm: match security_config.jwt.algorithm {
                crate::security::JwtAlgorithm::HS256 => JwtAlgorithm::HS256,
                crate::security::JwtAlgorithm::HS384 => JwtAlgorithm::HS384,
                crate::security::JwtAlgorithm::HS512 => JwtAlgorithm::HS512,
                crate::security::JwtAlgorithm::RS256 => JwtAlgorithm::RS256,
                crate::security::JwtAlgorithm::RS384 => JwtAlgorithm::RS384,
                crate::security::JwtAlgorithm::RS512 => JwtAlgorithm::RS512,
                crate::security::JwtAlgorithm::ES256 => JwtAlgorithm::ES256,
                crate::security::JwtAlgorithm::ES384 => JwtAlgorithm::ES384,
                crate::security::JwtAlgorithm::ES512 => JwtAlgorithm::ES512,
            },
            access_token_ttl: security_config.jwt.access_token_ttl_seconds,
            refresh_token_ttl: security_config.jwt.refresh_token_ttl_seconds,
            issuer: security_config.jwt.issuer.clone(),
            audience: security_config.jwt.audience.clone(),
            token_binding: security_config.jwt.enable_token_binding,
            key_rotation_interval: 3600, // Default 1 hour
            max_keys: 3,
            enable_jwks: true,
        };

        Self::new(jwt_config).await
    }

    /// Generate a new JWT access token
    pub async fn create_access_token(
        &self,
        user_id: &str,
        custom_claims: Option<HashMap<String, serde_json::Value>>,
    ) -> CryptoResult<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.access_token_ttl as i64);

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: exp.timestamp() as u64,
            iat: now.timestamp() as u64,
            nbf: now.timestamp() as u64,
            jti: uuid::Uuid::new_v4().to_string(),
            custom: custom_claims.unwrap_or_default(),
        };

        self.encode_token(&claims).await
    }

    /// Generate a new JWT refresh token
    pub async fn create_refresh_token(&self, user_id: &str) -> CryptoResult<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.refresh_token_ttl as i64);

        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "token_type".to_string(),
            serde_json::Value::String("refresh".to_string()),
        );

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp: exp.timestamp() as u64,
            iat: now.timestamp() as u64,
            nbf: now.timestamp() as u64,
            jti: uuid::Uuid::new_v4().to_string(),
            custom: custom_claims,
        };

        self.encode_token(&claims).await
    }

    /// Validate and decode a JWT token
    pub async fn validate_token(&self, token: &str) -> CryptoResult<Claims> {
        // Try with each available key
        let keys = self.keys.read().await;
        let mut last_error = None;

        for key in keys.iter() {
            match self.decode_with_key(token, key) {
                Ok(claims) => {
                    // Additional validation
                    self.validate_claims(&claims)?;
                    return Ok(claims);
                }
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error
            .unwrap_or(JwtError::ValidationFailed("No valid key found".to_string()).into()))
    }

    /// Get JWKS (JSON Web Key Set) for public key verification
    pub async fn get_jwks(&self) -> CryptoResult<serde_json::Value> {
        if !self.config.enable_jwks {
            return Err(CryptoError::InvalidConfiguration(
                "JWKS disabled".to_string(),
            ));
        }

        let keys = self.keys.read().await;
        let jwks: Vec<serde_json::Value> = keys
            .iter()
            .filter_map(|key| self.key_to_jwk(key).ok())
            .collect();

        Ok(serde_json::json!({
            "keys": jwks
        }))
    }

    /// Rotate JWT signing keys
    pub async fn rotate_keys(&self) -> CryptoResult<()> {
        let new_key = self.generate_new_key().await?;
        let new_key_id = new_key.kid.clone();

        let mut keys = self.keys.write().await;
        let mut current_key_id = self.current_key_id.write().await;

        // Add new key
        keys.push(new_key);
        *current_key_id = new_key_id;

        // Remove expired keys
        let now = Utc::now();
        keys.retain(|key| key.expires_at > now);

        // Limit number of keys
        if keys.len() > self.config.max_keys {
            let excess = keys.len() - self.config.max_keys;
            keys.drain(0..excess);
        }

        info!("JWT keys rotated. Active keys: {}", keys.len());
        Ok(())
    }

    // Private helper methods

    async fn encode_token(&self, claims: &Claims) -> CryptoResult<String> {
        let keys = self.keys.read().await;
        let current_key_id = self.current_key_id.read().await;

        let key = keys
            .iter()
            .find(|k| k.kid == *current_key_id)
            .ok_or(JwtError::KeyNotFound(current_key_id.clone()))?;

        let mut header = Header::new(key.algorithm);
        header.kid = Some(key.kid.clone());

        encode(&header, claims, &key.encoding_key)
            .map_err(|e| JwtError::EncodingFailed(e.to_string()).into())
    }

    fn decode_with_key(&self, token: &str, key: &JwtKey) -> CryptoResult<Claims> {
        let mut validation = Validation::new(key.algorithm);
        validation.set_issuer(&[&self.config.issuer]);

        if let Some(ref audiences) = self.config.audience {
            validation.set_audience(audiences);
        }

        let token_data: TokenData<Claims> = decode(token, &key.decoding_key, &validation)
            .map_err(|e| JwtError::DecodingFailed(e.to_string()))?;

        Ok(token_data.claims)
    }

    fn validate_claims(&self, claims: &Claims) -> CryptoResult<()> {
        let now = Utc::now().timestamp() as u64;

        // Check expiration
        if claims.exp <= now {
            return Err(JwtError::TokenExpired.into());
        }

        // Check not before
        if claims.nbf > now {
            return Err(JwtError::ValidationFailed("Token not yet valid".to_string()).into());
        }

        // Check issuer
        if claims.iss != self.config.issuer {
            return Err(JwtError::InvalidIssuer {
                expected: self.config.issuer.clone(),
                actual: claims.iss.clone(),
            }
            .into());
        }

        // Check audience if configured
        if let Some(ref expected_audiences) = self.config.audience {
            match &claims.aud {
                Some(token_audiences) => {
                    if !expected_audiences
                        .iter()
                        .any(|ea| token_audiences.contains(ea))
                    {
                        return Err(JwtError::InvalidAudience {
                            expected: expected_audiences.clone(),
                            actual: claims.aud.clone(),
                        }
                        .into());
                    }
                }
                None => {
                    return Err(JwtError::InvalidAudience {
                        expected: expected_audiences.clone(),
                        actual: None,
                    }
                    .into());
                }
            }
        }

        Ok(())
    }

    async fn generate_new_key(&self) -> CryptoResult<JwtKey> {
        let kid = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.config.key_rotation_interval as i64 * 2); // Keep for 2 rotation cycles

        let (encoding_key, decoding_key, algorithm) = match self.config.algorithm {
            JwtAlgorithm::HS256 | JwtAlgorithm::HS384 | JwtAlgorithm::HS512 => {
                let alg = match self.config.algorithm {
                    JwtAlgorithm::HS256 => Algorithm::HS256,
                    JwtAlgorithm::HS384 => Algorithm::HS384,
                    JwtAlgorithm::HS512 => Algorithm::HS512,
                    _ => unreachable!(),
                };

                let encoding_key = EncodingKey::from_secret(self.config.secret.as_bytes());
                let decoding_key = DecodingKey::from_secret(self.config.secret.as_bytes());

                (encoding_key, decoding_key, alg)
            }
            _ => {
                return Err(CryptoError::InvalidConfiguration(format!(
                    "Unsupported JWT algorithm: {:?}",
                    self.config.algorithm
                )));
            }
        };

        Ok(JwtKey {
            kid,
            encoding_key,
            decoding_key,
            algorithm,
            created_at: now,
            expires_at,
        })
    }

    fn key_to_jwk(&self, key: &JwtKey) -> CryptoResult<serde_json::Value> {
        match key.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                // HMAC keys shouldn't be exposed in JWKS
                Err(CryptoError::InvalidConfiguration(
                    "Cannot expose HMAC keys in JWKS".to_string(),
                ))
            }
            _ => {
                // For asymmetric keys, we would expose the public key here
                // This is a simplified implementation
                Ok(serde_json::json!({
                    "kid": key.kid,
                    "kty": "oct", // Key type - would vary by algorithm
                    "alg": format!("{:?}", key.algorithm),
                    "use": "sig"
                }))
            }
        }
    }
}

/// Parse JWT algorithm from string
impl std::str::FromStr for JwtAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "HS256" => Ok(JwtAlgorithm::HS256),
            "HS384" => Ok(JwtAlgorithm::HS384),
            "HS512" => Ok(JwtAlgorithm::HS512),
            "RS256" => Ok(JwtAlgorithm::RS256),
            "RS384" => Ok(JwtAlgorithm::RS384),
            "RS512" => Ok(JwtAlgorithm::RS512),
            "ES256" => Ok(JwtAlgorithm::ES256),
            "ES384" => Ok(JwtAlgorithm::ES384),
            "ES512" => Ok(JwtAlgorithm::ES512),
            "EDDSA" => Ok(JwtAlgorithm::EdDSA),
            _ => Err(format!("Unknown JWT algorithm: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::collections::HashMap;
    use std::env;

    // Test JwtError variants
    #[test]
    fn test_jwt_error_display() {
        let error = JwtError::ValidationFailed("test validation".to_string());
        assert_eq!(
            error.to_string(),
            "Token validation failed: test validation"
        );

        let error = JwtError::TokenExpired;
        assert_eq!(error.to_string(), "Token expired");

        let error = JwtError::InvalidFormat("bad format".to_string());
        assert_eq!(error.to_string(), "Invalid token format: bad format");

        let error = JwtError::KeyNotFound("missing key".to_string());
        assert_eq!(error.to_string(), "Key not found: missing key");

        let error = JwtError::EncodingFailed("encoding error".to_string());
        assert_eq!(error.to_string(), "Encoding failed: encoding error");

        let error = JwtError::DecodingFailed("decoding error".to_string());
        assert_eq!(error.to_string(), "Decoding failed: decoding error");

        let error = JwtError::AlgorithmMismatch {
            expected: "HS256".to_string(),
            actual: "RS256".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Algorithm mismatch: expected HS256, got RS256"
        );

        let error = JwtError::InvalidIssuer {
            expected: "issuer1".to_string(),
            actual: "issuer2".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Invalid issuer: expected issuer1, got issuer2"
        );

        let error = JwtError::InvalidAudience {
            expected: vec!["aud1".to_string()],
            actual: Some(vec!["aud2".to_string()]),
        };
        assert!(error.to_string().contains("Invalid audience"));
    }

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::default();
        assert_eq!(
            config.secret,
            "REPLACE_IN_PRODUCTION_WITH_STRONG_SECRET_KEY_32_CHARS_MIN"
        );
        assert_eq!(config.algorithm, JwtAlgorithm::HS256);
        assert_eq!(config.access_token_ttl, 900);
        assert_eq!(config.refresh_token_ttl, 86400);
        assert_eq!(config.issuer, "rust-security-platform");
        assert_eq!(config.audience, None);
        assert!(!config.token_binding);
        assert_eq!(config.key_rotation_interval, 3600);
        assert_eq!(config.max_keys, 3);
        assert!(config.enable_jwks);
    }

    #[test]
    fn test_jwt_config_from_env_basic() {
        // Test that from_env() doesn't panic and returns a config
        let config = JwtConfig::from_env().unwrap();

        // Basic checks that it's a valid config
        assert!(!config.secret.is_empty());
        assert!(config.access_token_ttl > 0);
        assert!(config.refresh_token_ttl > 0);
        assert!(!config.issuer.is_empty());
    }

    #[test]
    fn test_jwt_config_from_env_invalid_algorithm() {
        let vars_to_clear = [
            "JWT_SECRET",
            "JWT_ALGORITHM",
            "JWT_ACCESS_TOKEN_TTL",
            "JWT_REFRESH_TOKEN_TTL",
            "JWT_ISSUER",
            "JWT_AUDIENCE",
            "JWT_TOKEN_BINDING",
            "JWT_KEY_ROTATION_INTERVAL",
            "JWT_MAX_KEYS",
            "JWT_ENABLE_JWKS",
        ];

        for var in &vars_to_clear {
            env::remove_var(var);
        }

        env::set_var("JWT_ALGORITHM", "INVALID_ALG");

        let result = JwtConfig::from_env();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidConfiguration(msg) => {
                assert!(msg.contains("Invalid JWT algorithm"));
            }
            _ => panic!("Expected InvalidConfiguration error"),
        }

        for var in &vars_to_clear {
            env::remove_var(var);
        }
    }

    #[test]
    fn test_jwt_config_from_env_invalid_ttl() {
        let vars_to_clear = [
            "JWT_SECRET",
            "JWT_ALGORITHM",
            "JWT_ACCESS_TOKEN_TTL",
            "JWT_REFRESH_TOKEN_TTL",
            "JWT_ISSUER",
            "JWT_AUDIENCE",
            "JWT_TOKEN_BINDING",
            "JWT_KEY_ROTATION_INTERVAL",
            "JWT_MAX_KEYS",
            "JWT_ENABLE_JWKS",
        ];

        for var in &vars_to_clear {
            env::remove_var(var);
        }

        env::set_var("JWT_ACCESS_TOKEN_TTL", "invalid");

        let result = JwtConfig::from_env();
        assert!(result.is_err());

        for var in &vars_to_clear {
            env::remove_var(var);
        }
    }

    #[test]
    fn test_jwt_config_validation_short_secret() {
        let config = JwtConfig {
            secret: "short".to_string(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::ValidationFailed(msg) => {
                assert!(msg.contains("at least 32 characters"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_jwt_config_validation_insecure_secret() {
        let config = JwtConfig {
            secret: "REPLACE_IN_PRODUCTION_test_secret_32_chars".to_string(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::ValidationFailed(msg) => {
                assert!(msg.contains("insecure default values"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_jwt_config_validation_changeme_secret() {
        let config = JwtConfig {
            secret: "changeme_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::ValidationFailed(msg) => {
                assert!(msg.contains("insecure default values"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_jwt_config_validation_dev_secret() {
        let config = JwtConfig {
            secret: "dev_secret_key_for_development_use_32_chars".to_string(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::ValidationFailed(msg) => {
                assert!(msg.contains("insecure default values"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_jwt_config_validation_invalid_refresh_ttl() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            refresh_token_ttl: 300, // Less than access token TTL
            access_token_ttl: 900,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::ValidationFailed(msg) => {
                assert!(msg.contains("greater than access token TTL"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_jwt_config_validation_empty_issuer() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            issuer: "".to_string(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::ValidationFailed(msg) => {
                assert!(msg.contains("cannot be empty"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[test]
    fn test_jwt_config_validation_valid() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_claims_serialization() {
        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        custom_claims.insert(
            "permissions".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("read".to_string()),
                serde_json::Value::String("write".to_string()),
            ]),
        );

        let claims = Claims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some(vec!["test-audience".to_string()]),
            exp: 1234567890,
            iat: 1234567800,
            nbf: 1234567800,
            jti: "token123".to_string(),
            custom: custom_claims,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("user123"));
        assert!(json.contains("test-issuer"));
        assert!(json.contains("test-audience"));
        assert!(json.contains("admin"));

        let deserialized: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sub, "user123");
        assert_eq!(deserialized.iss, "test-issuer");
        assert_eq!(deserialized.aud, Some(vec!["test-audience".to_string()]));
    }

    #[test]
    fn test_jwt_key_debug() {
        use chrono::Utc;
        let key = JwtKey {
            kid: "test-key-id".to_string(),
            encoding_key: EncodingKey::from_secret(b"secret"),
            decoding_key: DecodingKey::from_secret(b"secret"),
            algorithm: Algorithm::HS256,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(3600),
        };

        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("JwtKey"));
        assert!(debug_str.contains("test-key-id"));
        assert!(debug_str.contains("HS256"));
        // Should not contain sensitive key material
        assert!(!debug_str.contains("secret"));
    }

    #[tokio::test]
    async fn test_jwt_operations_new() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        // Check that keys were initialized
        let keys = jwt_ops.keys.read().await;
        assert!(!keys.is_empty());

        let current_key_id = jwt_ops.current_key_id.read().await;
        assert!(!current_key_id.is_empty());
    }

    #[tokio::test]
    async fn test_jwt_operations_new_invalid_config() {
        let config = JwtConfig {
            secret: "short".to_string(), // Too short
            ..Default::default()
        };

        let result = JwtOperations::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_access_token() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("user".to_string()),
        );

        let token = jwt_ops
            .create_access_token("user123", Some(custom_claims))
            .await
            .unwrap();
        assert!(!token.is_empty());
        assert!(token.is_ascii());
    }

    #[tokio::test]
    async fn test_create_refresh_token() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let token = jwt_ops.create_refresh_token("user123").await.unwrap();
        assert!(!token.is_empty());
        assert!(token.is_ascii());
    }

    #[tokio::test]
    async fn test_validate_token_success() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let token = jwt_ops.create_access_token("user123", None).await.unwrap();
        let claims = jwt_ops.validate_token(&token).await.unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.iss, "rust-security-platform");
    }

    #[tokio::test]
    async fn test_validate_token_with_custom_claims() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let mut custom_claims = HashMap::new();
        custom_claims.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );

        let token = jwt_ops
            .create_access_token("user123", Some(custom_claims))
            .await
            .unwrap();
        let claims = jwt_ops.validate_token(&token).await.unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(
            claims.custom.get("role").unwrap(),
            &serde_json::Value::String("admin".to_string())
        );
    }

    #[tokio::test]
    async fn test_validate_refresh_token() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let token = jwt_ops.create_refresh_token("user123").await.unwrap();
        let claims = jwt_ops.validate_token(&token).await.unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(
            claims.custom.get("token_type").unwrap(),
            &serde_json::Value::String("refresh".to_string())
        );
    }

    #[tokio::test]
    async fn test_validate_token_invalid_signature() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        // Create token with one secret
        let token = jwt_ops.create_access_token("user123", None).await.unwrap();

        // Try to validate with different secret
        let config2 = JwtConfig {
            secret: "different_secret_key_32_characters".to_string(),
            ..Default::default()
        };
        let jwt_ops2 = JwtOperations::new(config2).await.unwrap();

        let result = jwt_ops2.validate_token(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_token_malformed() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let result = jwt_ops.validate_token("malformed.token").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_jwks_enabled() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            enable_jwks: true,
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let jwks = jwt_ops.get_jwks().await.unwrap();
        assert!(jwks.get("keys").is_some());
    }

    #[tokio::test]
    async fn test_get_jwks_disabled() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            enable_jwks: false,
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let result = jwt_ops.get_jwks().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidConfiguration(msg) => {
                assert!(msg.contains("JWKS disabled"));
            }
            _ => panic!("Expected InvalidConfiguration error"),
        }
    }

    #[tokio::test]
    async fn test_rotate_keys() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let keys_before = {
            let keys = jwt_ops.keys.read().await;
            keys.len()
        };

        jwt_ops.rotate_keys().await.unwrap();

        let keys_after = {
            let keys = jwt_ops.keys.read().await;
            keys.len()
        };

        assert!(keys_after >= keys_before);
    }

    #[tokio::test]
    async fn test_key_rotation_limits() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            max_keys: 2,
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        // Rotate keys multiple times
        for _ in 0..5 {
            jwt_ops.rotate_keys().await.unwrap();
        }

        let keys = jwt_ops.keys.read().await;
        assert!(keys.len() <= 2);
    }

    #[tokio::test]
    async fn test_token_with_audience() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            audience: Some(vec![
                "test-audience".to_string(),
                "another-audience".to_string(),
            ]),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let token = jwt_ops.create_access_token("user123", None).await.unwrap();
        let claims = jwt_ops.validate_token(&token).await.unwrap();

        assert_eq!(
            claims.aud,
            Some(vec![
                "test-audience".to_string(),
                "another-audience".to_string()
            ])
        );
    }

    #[tokio::test]
    async fn test_algorithm_from_str() {
        assert_eq!(
            "HS256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS256
        );
        assert_eq!(
            "hs256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS256
        );
        assert_eq!(
            "HS384".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS384
        );
        assert_eq!(
            "HS512".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::HS512
        );
        assert_eq!(
            "RS256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::RS256
        );
        assert_eq!(
            "RS384".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::RS384
        );
        assert_eq!(
            "RS512".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::RS512
        );
        assert_eq!(
            "ES256".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::ES256
        );
        assert_eq!(
            "ES384".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::ES384
        );
        assert_eq!(
            "ES512".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::ES512
        );
        assert_eq!(
            "EDDSA".parse::<JwtAlgorithm>().unwrap(),
            JwtAlgorithm::EdDSA
        );

        let result = "INVALID".parse::<JwtAlgorithm>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown JWT algorithm"));
    }

    #[tokio::test]
    async fn test_from_security_config() {
        use crate::security::{JwtConfig as SecurityJwtConfig, UnifiedSecurityConfig};

        let security_config = UnifiedSecurityConfig {
            jwt: SecurityJwtConfig {
                secret: "test_secret_key_32_characters_long".to_string(),
                algorithm: crate::security::JwtAlgorithm::HS384,
                access_token_ttl_seconds: 1200,
                refresh_token_ttl_seconds: 48000,
                issuer: "test-security-issuer".to_string(),
                audience: Some(vec!["security-audience".to_string()]),
                enable_token_binding: true,
            },
            ..Default::default()
        };

        let jwt_ops = JwtOperations::from_security_config(&security_config)
            .await
            .unwrap();

        assert_eq!(jwt_ops.config.secret, "test_secret_key_32_characters_long");
        assert_eq!(jwt_ops.config.algorithm, JwtAlgorithm::HS384);
        assert_eq!(jwt_ops.config.access_token_ttl, 1200);
        assert_eq!(jwt_ops.config.refresh_token_ttl, 48000);
        assert_eq!(jwt_ops.config.issuer, "test-security-issuer");
        assert_eq!(
            jwt_ops.config.audience,
            Some(vec!["security-audience".to_string()])
        );
        assert!(jwt_ops.config.token_binding);
    }

    #[tokio::test]
    async fn test_unsupported_algorithm() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            algorithm: JwtAlgorithm::RS256, // Not implemented in generate_new_key
            ..Default::default()
        };

        let result = JwtOperations::new(config).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidConfiguration(msg) => {
                assert!(msg.contains("Unsupported JWT algorithm"));
            }
            _ => panic!("Expected InvalidConfiguration error"),
        }
    }

    // Test edge cases and error conditions

    #[tokio::test]
    async fn test_validate_claims_expired_token() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            access_token_ttl: 1, // Very short TTL
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let token = jwt_ops.create_access_token("user123", None).await.unwrap();

        // Wait for token to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let result = jwt_ops.validate_token(&token).await;
        assert!(result.is_err());
        // Note: The error might be wrapped, so we check if it's an expiration-related error
    }

    #[tokio::test]
    async fn test_validate_claims_invalid_issuer() {
        let config1 = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            issuer: "issuer1".to_string(),
            ..Default::default()
        };

        let config2 = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            issuer: "issuer2".to_string(),
            ..Default::default()
        };

        let jwt_ops1 = JwtOperations::new(config1).await.unwrap();
        let jwt_ops2 = JwtOperations::new(config2).await.unwrap();

        let token = jwt_ops1.create_access_token("user123", None).await.unwrap();
        let result = jwt_ops2.validate_token(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_claims_invalid_audience() {
        let config1 = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            audience: Some(vec!["audience1".to_string()]),
            ..Default::default()
        };

        let config2 = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            audience: Some(vec!["audience2".to_string()]),
            ..Default::default()
        };

        let jwt_ops1 = JwtOperations::new(config1).await.unwrap();
        let jwt_ops2 = JwtOperations::new(config2).await.unwrap();

        let token = jwt_ops1.create_access_token("user123", None).await.unwrap();
        let result = jwt_ops2.validate_token(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_key_to_jwk_hmac() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        let keys = jwt_ops.keys.read().await;
        let key = &keys[0];

        let result = jwt_ops.key_to_jwk(key);
        assert!(result.is_err()); // HMAC keys shouldn't be exposed
        match result.unwrap_err() {
            CryptoError::InvalidConfiguration(msg) => {
                assert!(msg.contains("Cannot expose HMAC keys"));
            }
            _ => panic!("Expected InvalidConfiguration error"),
        }
    }

    #[test]
    fn test_jwt_algorithm_all_variants() {
        // Test all algorithm variants can be created and formatted
        let algorithms = vec![
            JwtAlgorithm::HS256,
            JwtAlgorithm::HS384,
            JwtAlgorithm::HS512,
            JwtAlgorithm::RS256,
            JwtAlgorithm::RS384,
            JwtAlgorithm::RS512,
            JwtAlgorithm::ES256,
            JwtAlgorithm::ES384,
            JwtAlgorithm::ES512,
            JwtAlgorithm::EdDSA,
        ];

        for alg in algorithms {
            // Test Debug formatting
            let debug_str = format!("{:?}", alg);
            assert!(!debug_str.is_empty());

            // Test that they can be cloned and compared
            let cloned = alg.clone();
            assert_eq!(alg, cloned);
        }
    }

    #[test]
    fn test_claims_optional_audience() {
        let claims = Claims {
            sub: "user123".to_string(),
            iss: "test-issuer".to_string(),
            aud: None, // Test None case
            exp: 1234567890,
            iat: 1234567800,
            nbf: 1234567800,
            jti: "token123".to_string(),
            custom: HashMap::new(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("\"aud\"")); // Should skip serialization when None

        let deserialized: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.aud, None);
    }

    #[tokio::test]
    async fn test_multiple_key_validation() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        // Create token with current key
        let token1 = jwt_ops.create_access_token("user123", None).await.unwrap();

        // Rotate keys
        jwt_ops.rotate_keys().await.unwrap();

        // Create token with new key
        let token2 = jwt_ops.create_access_token("user456", None).await.unwrap();

        // Both tokens should validate successfully
        let claims1 = jwt_ops.validate_token(&token1).await.unwrap();
        let claims2 = jwt_ops.validate_token(&token2).await.unwrap();

        assert_eq!(claims1.sub, "user123");
        assert_eq!(claims2.sub, "user456");
    }

    #[tokio::test]
    async fn test_no_valid_key_error() {
        let config = JwtConfig {
            secret: "valid_secret_key_32_characters_long".to_string(),
            ..Default::default()
        };

        let jwt_ops = JwtOperations::new(config).await.unwrap();

        // Clear all keys to simulate no valid key scenario
        {
            let mut keys = jwt_ops.keys.write().await;
            keys.clear();
        }

        let result = jwt_ops.validate_token("some.jwt.token").await;
        assert!(result.is_err());
    }
}
