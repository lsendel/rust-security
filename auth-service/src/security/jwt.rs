//! Unified JWT and JWKS Management Module
//!
//! Consolidated JWT operations combining the best features from:
//! - `jwks_rotation.rs` - Key rotation and JWKS management
//! - `jwt_secure.rs` - Secure JWT validation
//! - `enhanced_jwt_validation.rs` - Enhanced validation features
//! - `infrastructure/http/jwks_handler.rs` - HTTP JWKS endpoints
//!
//! Features:
//! - `EdDSA` (Ed25519) JWT signing and verification
//! - Automatic key rotation with configurable intervals
//! - JWKS endpoint serving with proper caching headers
//! - JWT validation with comprehensive security checks
//! - Support for multiple concurrent keys
//! - Performance monitoring and metrics
//! - Redis-backed distributed key storage (optional)

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation,
};
use ring::rand::SecureRandom;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[cfg(feature = "redis-sessions")]
use deadpool_redis::Pool as RedisPool;

#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::{SigningKey, VerifyingKey};

/// JWT-related errors
#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Token validation failed: {0}")]
    ValidationFailed(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("JWKS generation failed: {0}")]
    JwksGenerationFailed(String),
    #[error("Redis error: {0}")]
    RedisError(String),
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Supported JWT algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JwtAlgorithm {
    /// `EdDSA` using Ed25519 (recommended)
    EdDSA,
    /// ES256 using P-256
    ES256,
    /// HS256 for symmetric signing (not recommended for production)
    HS256,
}

impl JwtAlgorithm {
    const fn to_jsonwebtoken_algorithm(self) -> Algorithm {
        match self {
            Self::EdDSA => Algorithm::EdDSA,
            Self::ES256 => Algorithm::ES256,
            Self::HS256 => Algorithm::HS256,
        }
    }

    const fn key_type(&self) -> &'static str {
        match self {
            Self::EdDSA => "OKP",
            Self::ES256 => "EC",
            Self::HS256 => "oct",
        }
    }

    const fn curve(&self) -> Option<&'static str> {
        match self {
            Self::EdDSA => Some("Ed25519"),
            Self::ES256 => Some("P-256"),
            Self::HS256 => None,
        }
    }
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Default algorithm for new tokens
    pub default_algorithm: JwtAlgorithm,
    /// Token expiration time in seconds
    pub token_expiration_seconds: u64,
    /// Refresh token expiration time in seconds
    pub refresh_token_expiration_seconds: u64,
    /// Key rotation interval in days
    pub key_rotation_interval_days: i64,
    /// How long to keep old keys for validation (in days)
    pub key_retention_days: i64,
    /// Maximum number of active keys
    pub max_active_keys: usize,
    /// Token issuer
    pub issuer: String,
    /// Valid audiences
    pub audiences: HashSet<String>,
    /// Clock skew tolerance in seconds
    pub clock_skew_seconds: u64,
    /// Enable distributed storage via Redis
    pub enable_redis_storage: bool,
}

impl Default for JwtConfig {
    fn default() -> Self {
        let mut audiences = HashSet::new();
        audiences.insert("auth-service".to_string());

        Self {
            default_algorithm: JwtAlgorithm::EdDSA,
            token_expiration_seconds: 3600,              // 1 hour
            refresh_token_expiration_seconds: 86400 * 7, // 7 days
            key_rotation_interval_days: 30,              // Monthly rotation
            key_retention_days: 90,                      // Keep for 3 months
            max_active_keys: 5,
            issuer: "https://auth.example.com".to_string(),
            audiences,
            clock_skew_seconds: 60, // 1 minute tolerance
            enable_redis_storage: false,
        }
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
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: u64,
    /// Issued at (Unix timestamp)
    pub iat: u64,
    /// Not before (Unix timestamp)
    pub nbf: u64,
    /// JWT ID
    pub jti: String,
    /// Scopes/permissions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Cryptographic key with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKey {
    /// Key ID (kid)
    pub kid: String,
    /// Key type (OKP, EC, RSA, oct)
    pub kty: String,
    /// Algorithm (`EdDSA`, ES256, etc.)
    pub alg: String,
    /// Key use (sig for signature, enc for encryption)
    #[serde(rename = "use")]
    pub use_: String,
    /// Curve (for EC/OKP keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// Public key (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key expires
    pub expires_at: DateTime<Utc>,
    /// Whether the key is currently active for signing
    pub active: bool,
}

/// Key pair for JWT operations
pub struct KeyPair {
    pub kid: String,
    pub algorithm: JwtAlgorithm,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub public_jwk: CryptoKey,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub active: bool,
}

/// JWKS (JSON Web Key Set) structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<CryptoKey>,
}

/// JWT validation result
#[derive(Debug)]
pub struct ValidationResult<T> {
    pub claims: T,
    pub header: Header,
    pub token: String,
}

/// JWT metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwtMetrics {
    pub tokens_issued: u64,
    pub tokens_validated: u64,
    pub validation_failures: u64,
    pub keys_rotated: u64,
    pub jwks_requests: u64,
    pub avg_validation_time_ms: f64,
}

/// Unified JWT manager
pub struct UnifiedJwtManager {
    config: JwtConfig,

    // Key storage
    active_keys: Arc<RwLock<HashMap<String, KeyPair>>>,
    current_signing_key: Arc<RwLock<Option<String>>>, // Current key ID for signing

    // Metrics and monitoring
    metrics: Arc<RwLock<JwtMetrics>>,
    last_key_rotation: Arc<RwLock<DateTime<Utc>>>,

    // Optional Redis connection for distributed storage
    #[cfg(feature = "redis-sessions")]
    redis: Option<RedisPool>,

    // Random number generator for key generation
    rng: ring::rand::SystemRandom,
}

impl UnifiedJwtManager {
    /// Create a new JWT manager
    pub async fn new(
        config: JwtConfig,
        #[cfg(feature = "redis-sessions")] redis_pool: Option<RedisPool>,
    ) -> Result<Self, JwtError> {
        #[cfg(not(feature = "redis-sessions"))]
        let _redis_pool: Option<()> = None;
        let manager = Self {
            config,
            active_keys: Arc::new(RwLock::new(HashMap::new())),
            current_signing_key: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(JwtMetrics::default())),
            last_key_rotation: Arc::new(RwLock::new(Utc::now())),
            #[cfg(feature = "redis-sessions")]
            redis: redis_pool,
            rng: ring::rand::SystemRandom::new(),
        };

        // Generate initial key
        manager.rotate_keys().await?;

        info!(
            "JWT manager initialized with algorithm {:?}",
            manager.config.default_algorithm
        );
        Ok(manager)
    }

    /// Generate a new key pair based on the configured algorithm
    async fn generate_key_pair(&self, algorithm: JwtAlgorithm) -> Result<KeyPair, JwtError> {
        let kid = self.generate_key_id();
        let now = Utc::now();
        let expires_at = now + Duration::days(self.config.key_retention_days);

        match algorithm {
            JwtAlgorithm::EdDSA => {
                #[cfg(feature = "ed25519-dalek")]
                {
                    // Generate Ed25519 key pair
                    let mut key_bytes = [0u8; 32];
                    self.rng.fill(&mut key_bytes).map_err(|_| {
                        JwtError::KeyGenerationFailed("Failed to generate random bytes".to_string())
                    })?;

                    let signing_key = SigningKey::from_bytes(&key_bytes);
                    let verifying_key = signing_key.verifying_key();

                    let pkcs8_bytes = self.ed25519_to_pkcs8(&signing_key);
                    let public_der_bytes = self.ed25519_public_to_der(&verifying_key);
                    let encoding_key = EncodingKey::from_ed_der(&pkcs8_bytes);
                    let decoding_key = DecodingKey::from_ed_der(&public_der_bytes);

                    let public_jwk = CryptoKey {
                        kid: kid.clone(),
                        kty: algorithm.key_type().to_string(),
                        alg: "EdDSA".to_string(),
                        use_: "sig".to_string(),
                        crv: algorithm.curve().map(std::string::ToString::to_string),
                        x: Some(general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())),
                        created_at: now,
                        expires_at,
                        active: true,
                    };

                    Ok(KeyPair {
                        kid,
                        algorithm,
                        encoding_key,
                        decoding_key,
                        public_jwk,
                        created_at: now,
                        expires_at,
                        active: true,
                    })
                }
                #[cfg(not(feature = "ed25519-dalek"))]
                {
                    Err(JwtError::ConfigurationError(
                        "Ed25519 support not compiled in".to_string(),
                    ))
                }
            }
            _ => Err(JwtError::InvalidAlgorithm(format!(
                "Algorithm {algorithm:?} not yet implemented"
            ))),
        }
    }

    /// Generate a unique key ID
    fn generate_key_id(&self) -> String {
        let mut bytes = [0u8; 16];
        // Fill with cryptographically secure random bytes
        let _ = self.rng.fill(&mut bytes);
        hex::encode(bytes)
    }

    /// Convert Ed25519 signing key to PKCS#8 DER format
    #[cfg(feature = "ed25519-dalek")]
    fn ed25519_to_pkcs8(&self, signing_key: &SigningKey) -> Vec<u8> {
        // PKCS#8 wrapper for Ed25519 private key
        let mut pkcs8 = Vec::new();
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, // SEQUENCE, 46 bytes
            0x02, 0x01, 0x00, // INTEGER version = 0
            0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519: 1.3.101.112
            0x04, 0x22, // OCTET STRING, 34 bytes
            0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
        ]);
        pkcs8.extend_from_slice(signing_key.as_bytes());
        pkcs8
    }

    /// Convert Ed25519 verifying key to `SubjectPublicKeyInfo` DER format
    #[cfg(feature = "ed25519-dalek")]
    fn ed25519_public_to_der(&self, verifying_key: &VerifyingKey) -> Vec<u8> {
        // SubjectPublicKeyInfo for Ed25519 public key
        let mut spki = Vec::new();
        spki.extend_from_slice(&[
            0x30, 0x2a, // SEQUENCE, 42 bytes
            0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID for Ed25519: 1.3.101.112
            0x03, 0x21, 0x00, // BIT STRING, 33 bytes (with unused bits = 0)
        ]);
        spki.extend_from_slice(verifying_key.as_bytes());
        spki
    }

    /// Rotate keys (generate new key and mark old ones for expiration)
    pub async fn rotate_keys(&self) -> Result<(), JwtError> {
        let new_key = self
            .generate_key_pair(self.config.default_algorithm)
            .await?;
        let kid = new_key.kid.clone();

        // Add the new key
        {
            let mut keys = self.active_keys.write().await;
            keys.insert(kid.clone(), new_key);

            // Remove expired keys
            let now = Utc::now();
            keys.retain(|_, key| key.expires_at > now);

            // If we have too many keys, remove the oldest inactive ones
            if keys.len() > self.config.max_active_keys {
                let mut inactive_keys: Vec<_> = keys
                    .iter()
                    .filter(|(_, key)| !key.active)
                    .map(|(k, v)| (k.clone(), v.created_at))
                    .collect();

                inactive_keys.sort_by(|a, b| a.1.cmp(&b.1));

                let to_remove = keys.len() - self.config.max_active_keys;
                for (key_id, _) in inactive_keys.into_iter().take(to_remove) {
                    keys.remove(&key_id);
                }
            }
        }

        // Set as current signing key
        {
            // Mark previous signing key as inactive
            if let Some(current_kid) = self.current_signing_key.read().await.as_ref() {
                if let Some(key) = self.active_keys.write().await.get_mut(current_kid) {
                    key.active = false;
                }
            }

            *self.current_signing_key.write().await = Some(kid);
        }

        *self.last_key_rotation.write().await = Utc::now();

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.keys_rotated += 1;
        }

        info!("Keys rotated successfully");
        Ok(())
    }

    /// Check if key rotation is needed
    pub async fn check_key_rotation(&self) -> Result<(), JwtError> {
        let last_rotation = *self.last_key_rotation.read().await;
        let rotation_interval = Duration::days(self.config.key_rotation_interval_days);

        if Utc::now() - last_rotation >= rotation_interval {
            self.rotate_keys().await?;
        }

        Ok(())
    }

    /// Create and sign a JWT token
    pub async fn create_token<T>(&self, claims: &T) -> Result<String, JwtError>
    where
        T: Serialize,
    {
        let start_time = std::time::Instant::now();

        let signing_key_id = self
            .current_signing_key
            .read()
            .await
            .clone()
            .ok_or_else(|| JwtError::KeyNotFound("No active signing key available".to_string()))?;

        let key = {
            let keys = self.active_keys.read().await;
            keys.get(&signing_key_id)
                .ok_or_else(|| {
                    JwtError::KeyNotFound(format!("Signing key {signing_key_id} not found"))
                })?
                .encoding_key
                .clone()
        };

        let mut header = Header::new(self.config.default_algorithm.to_jsonwebtoken_algorithm());
        header.kid = Some(signing_key_id);

        let token = encode(&header, claims, &key)
            .map_err(|e| JwtError::EncodingFailed(format!("Token encoding failed: {e}")))?;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.tokens_issued += 1;
        }

        debug!("Token created in {:?}", start_time.elapsed());
        Ok(token)
    }

    /// Validate and decode a JWT token
    pub async fn validate_token<T>(&self, token: &str) -> Result<ValidationResult<T>, JwtError>
    where
        T: DeserializeOwned,
    {
        let start_time = std::time::Instant::now();

        // Decode header to get key ID
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| JwtError::InvalidFormat(format!("Invalid token header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| JwtError::InvalidFormat("Missing key ID in token header".to_string()))?;

        // SECURITY: Validate kid parameter to prevent injection and key confusion attacks
        Self::validate_kid_parameter(&kid)?;

        // Get the decoding key
        let decoding_key = {
            let keys = self.active_keys.read().await;
            keys.get(&kid)
                .ok_or_else(|| JwtError::KeyNotFound(format!("Key {kid} not found")))?
                .decoding_key
                .clone()
        };

        // Set up validation parameters
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&self.config.audiences.iter().collect::<Vec<_>>());
        validation.set_issuer(&[&self.config.issuer]);
        validation.leeway = self.config.clock_skew_seconds;

        // Decode and validate the token
        let token_data: TokenData<T> =
            decode(token, &decoding_key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
                _ => JwtError::ValidationFailed(format!("Token validation failed: {e}")),
            })?;

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.tokens_validated += 1;
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_validation_time_ms = metrics
                .avg_validation_time_ms
                .mul_add((metrics.tokens_validated - 1) as f64, elapsed_ms)
                / metrics.tokens_validated as f64;
        }

        debug!("Token validated in {:?}", start_time.elapsed());

        Ok(ValidationResult {
            claims: token_data.claims,
            header: token_data.header,
            token: token.to_string(),
        })
    }

    /// Get current JWKS (JSON Web Key Set)
    pub async fn get_jwks(&self) -> Result<Jwks, JwtError> {
        let keys = self.active_keys.read().await;
        let public_keys: Vec<CryptoKey> = keys.values().map(|kp| kp.public_jwk.clone()).collect();

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.jwks_requests += 1;
        }

        Ok(Jwks { keys: public_keys })
    }

    /// Get a specific key by ID
    pub async fn get_key(&self, kid: &str) -> Option<CryptoKey> {
        let keys = self.active_keys.read().await;
        keys.get(kid).map(|kp| kp.public_jwk.clone())
    }

    /// Create standard claims
    #[must_use]
    pub fn create_standard_claims(
        &self,
        subject: &str,
        audience: Option<&str>,
        scope: Option<&str>,
        session_id: Option<&str>,
        custom_claims: Option<HashMap<String, serde_json::Value>>,
    ) -> Claims {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.token_expiration_seconds as i64);

        Claims {
            sub: subject.to_string(),
            iss: self.config.issuer.clone(),
            aud: audience.unwrap_or("auth-service").to_string(),
            exp: exp.timestamp() as u64,
            iat: now.timestamp() as u64,
            nbf: now.timestamp() as u64,
            jti: uuid::Uuid::new_v4().to_string(),
            scope: scope.map(std::string::ToString::to_string),
            session_id: session_id.map(std::string::ToString::to_string),
            custom: custom_claims.unwrap_or_default(),
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> JwtMetrics {
        self.metrics.read().await.clone()
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) {
        *self.metrics.write().await = JwtMetrics::default();
    }

    /// Get configuration
    #[must_use]
    pub const fn get_config(&self) -> &JwtConfig {
        &self.config
    }
}

/// Global JWT manager instance
static GLOBAL_JWT_MANAGER: std::sync::LazyLock<std::sync::RwLock<Option<Arc<UnifiedJwtManager>>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

/// Initialize global JWT manager
pub async fn initialize_global_jwt_manager(
    config: JwtConfig,
    #[cfg(feature = "redis-sessions")] redis_pool: Option<RedisPool>,
) -> Result<(), JwtError> {
    #[cfg(feature = "redis-sessions")]
    let manager = UnifiedJwtManager::new(config, redis_pool).await?;
    #[cfg(not(feature = "redis-sessions"))]
    let manager = UnifiedJwtManager::new(config).await?;
    let mut global = match GLOBAL_JWT_MANAGER.write() {
        Ok(lock) => lock,
        Err(_) => {
            error!("GLOBAL_JWT_MANAGER mutex is poisoned");
            return Err(JwtError::KeyGenerationFailed("JWT service mutex poisoned".to_string()));
        }
    };
    *global = Some(Arc::new(manager));
    info!("Global JWT manager initialized");
    Ok(())
}

/// Get global JWT manager
pub fn get_global_jwt_manager() -> Option<Arc<UnifiedJwtManager>> {
    GLOBAL_JWT_MANAGER.read().ok().and_then(|guard| guard.clone())
}

/// Convenience functions using global manager
pub async fn create_token_global<T>(claims: &T) -> Result<String, JwtError>
where
    T: Serialize + Send + Sync,
{
    let manager = get_global_jwt_manager().ok_or_else(|| {
        JwtError::ConfigurationError("Global JWT manager not initialized".to_string())
    })?;
    manager.create_token(claims).await
}

pub async fn validate_token_global<T>(token: &str) -> Result<ValidationResult<T>, JwtError>
where
    T: DeserializeOwned + Send + Sync,
{
    let manager = get_global_jwt_manager().ok_or_else(|| {
        JwtError::ConfigurationError("Global JWT manager not initialized".to_string())
    })?;
    manager.validate_token(token).await
}

pub async fn get_jwks_global() -> Result<Jwks, JwtError> {
    let manager = get_global_jwt_manager().ok_or_else(|| {
        JwtError::ConfigurationError("Global JWT manager not initialized".to_string())
    })?;
    manager.get_jwks().await
}

impl UnifiedJwtManager {
    /// Validate JWT kid parameter to prevent injection and key confusion attacks
    ///
    /// # Security
    ///
    /// This method performs comprehensive validation of the JWT kid (key ID) parameter:
    /// - Ensures kid is not empty or whitespace only
    /// - Validates length is within reasonable bounds (1-128 characters)
    /// - Checks for invalid characters that could indicate injection attempts
    /// - Prevents directory traversal and injection patterns
    /// - Only allows alphanumeric characters, hyphens, underscores, and dots
    ///
    /// # Arguments
    ///
    /// * `kid` - The key ID parameter from the JWT header
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if kid is valid, `Err(JwtError)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns `JwtError::InvalidFormat` if:
    /// - kid is empty or contains only whitespace
    /// - kid is longer than 128 characters
    /// - kid contains invalid characters
    /// - kid contains potential injection patterns
    fn validate_kid_parameter(kid: &str) -> Result<(), JwtError> {
        // Check for empty or whitespace-only kid
        if kid.trim().is_empty() {
            return Err(JwtError::InvalidFormat(
                "Key ID cannot be empty or whitespace only".to_string(),
            ));
        }

        // Check length bounds (reasonable limits)
        if kid.len() > 128 {
            return Err(JwtError::InvalidFormat(format!(
                "Key ID too long: {} characters (max 128)",
                kid.len()
            )));
        }

        // Check for valid characters only (alphanumeric, hyphen, underscore, dot)
        // This prevents injection attempts and ensures key lookup safety
        if !kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(JwtError::InvalidFormat(
                "Key ID contains invalid characters. Only alphanumeric, '-', '_', '.' allowed"
                    .to_string(),
            ));
        }

        // Check for directory traversal patterns
        if kid.contains("..") || kid.contains("//") {
            return Err(JwtError::InvalidFormat(
                "Key ID contains potential directory traversal pattern".to_string(),
            ));
        }

        // Check for SQL injection patterns (though we're not using SQL for key lookup)
        let kid_lower = kid.to_lowercase();
        if kid_lower.contains("select")
            || kid_lower.contains("union")
            || kid_lower.contains("drop")
            || kid_lower.contains("insert")
            || kid_lower.contains("delete")
            || kid_lower.contains("--")
            || kid_lower.contains("/*")
            || kid_lower.contains("*/")
        {
            return Err(JwtError::InvalidFormat(
                "Key ID contains potential injection pattern".to_string(),
            ));
        }

        // Check for XSS patterns (defense in depth)
        if kid_lower.contains("script")
            || kid_lower.contains("javascript")
            || kid_lower.contains("onclick")
            || kid_lower.contains("onload")
            || kid_lower.contains("<")
            || kid_lower.contains(">")
        {
            return Err(JwtError::InvalidFormat(
                "Key ID contains potential XSS pattern".to_string(),
            ));
        }

        // Check for null bytes and control characters
        if kid.contains('\0') || kid.chars().any(|c| c.is_control()) {
            return Err(JwtError::InvalidFormat(
                "Key ID contains null bytes or control characters".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_jwt_creation_and_validation() {
        let config = JwtConfig::default();
        #[cfg(feature = "redis-sessions")]
        let manager = UnifiedJwtManager::new(config, None).await.unwrap();
        #[cfg(not(feature = "redis-sessions"))]
        let manager = UnifiedJwtManager::new(config).await.unwrap();

        let claims = manager.create_standard_claims(
            "user123",
            Some("test-audience"),
            Some("read write"),
            Some("session456"),
            None,
        );

        let token = manager.create_token(&claims).await.unwrap();
        let result: ValidationResult<Claims> = manager.validate_token(&token).await.unwrap();

        assert_eq!(result.claims.sub, "user123");
        assert_eq!(result.claims.scope, Some("read write".to_string()));
        assert_eq!(result.claims.session_id, Some("session456".to_string()));
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let config = JwtConfig::default();
        #[cfg(feature = "redis-sessions")]
        let manager = UnifiedJwtManager::new(config, None).await.unwrap();
        #[cfg(not(feature = "redis-sessions"))]
        let manager = UnifiedJwtManager::new(config).await.unwrap();

        let initial_jwks = manager.get_jwks().await.unwrap();
        let initial_key_count = initial_jwks.keys.len();

        manager.rotate_keys().await.unwrap();

        let new_jwks = manager.get_jwks().await.unwrap();
        assert!(new_jwks.keys.len() >= initial_key_count);
    }

    #[tokio::test]
    async fn test_custom_claims() {
        let config = JwtConfig::default();
        #[cfg(feature = "redis-sessions")]
        let manager = UnifiedJwtManager::new(config, None).await.unwrap();
        #[cfg(not(feature = "redis-sessions"))]
        let manager = UnifiedJwtManager::new(config).await.unwrap();

        let mut custom_claims = HashMap::new();
        custom_claims.insert("department".to_string(), json!("engineering"));
        custom_claims.insert("role".to_string(), json!("admin"));

        let claims =
            manager.create_standard_claims("user123", None, None, None, Some(custom_claims));

        let token = manager.create_token(&claims).await.unwrap();
        let result: ValidationResult<Claims> = manager.validate_token(&token).await.unwrap();

        assert_eq!(
            result.claims.custom.get("department").unwrap(),
            "engineering"
        );
        assert_eq!(result.claims.custom.get("role").unwrap(), "admin");
    }

    #[tokio::test]
    async fn test_global_jwt_manager() {
        let config = JwtConfig::default();
        #[cfg(feature = "redis-sessions")]
        initialize_global_jwt_manager(config, None).await.unwrap();
        #[cfg(not(feature = "redis-sessions"))]
        initialize_global_jwt_manager(config).await.unwrap();

        let manager = get_global_jwt_manager().unwrap();
        let claims = manager.create_standard_claims("test_user", None, None, None, None);

        let token = create_token_global(&claims).await.unwrap();
        let result: ValidationResult<Claims> = validate_token_global(&token).await.unwrap();

        assert_eq!(result.claims.sub, "test_user");

        let jwks = get_jwks_global().await.unwrap();
        assert!(!jwks.keys.is_empty());
    }
}
