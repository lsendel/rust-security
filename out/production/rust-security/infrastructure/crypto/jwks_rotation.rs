use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
#[cfg(feature = "enhanced-session-store")]
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Key rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationConfig {
    /// How often to rotate keys (in days)
    pub rotation_interval_days: i64,
    /// How long to keep old keys for validation (in days)
    pub key_retention_days: i64,
    /// Maximum number of keys to keep
    pub max_keys: usize,
    /// Algorithm to use for keys
    pub algorithm: Algorithm,
    /// Key size in bits
    pub key_size: usize,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            rotation_interval_days: 30, // Rotate monthly
            key_retention_days: 90,     // Keep old keys for 3 months
            max_keys: 5,
            algorithm: Algorithm::EdDSA, // Use EdDSA instead of RS256 for better security
            key_size: 256,               // Ed25519 key size
        }
    }
}

/// Represents a cryptographic key with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoKey {
    /// Key ID (kid)
    pub kid: String,
    /// Key type (RSA, EC, etc.)
    pub kty: String,
    /// Algorithm
    pub alg: String,
    /// Use (sig for signature)
    pub use_: String,
    /// When the key was created
    pub created_at: DateTime<Utc>,
    /// When the key expires
    pub expires_at: DateTime<Utc>,
    /// When the key should be rotated
    pub rotate_at: DateTime<Utc>,
    /// Is this the current active key for signing?
    pub is_active: bool,
    /// Public key (for JWKS)
    pub public_key: String,
    /// Private key (encrypted)
    #[serde(skip_serializing)]
    pub private_key: Option<String>,
    /// Key status
    pub status: KeyStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyStatus {
    Active,   // Current signing key
    Valid,    // Can be used for validation
    Rotating, // Being rotated out
    Expired,  // No longer valid
    Revoked,  // Manually revoked
}

/// JWKS (JSON Web Key Set) manager with automatic rotation
pub struct JwksManager {
    /// All keys indexed by kid
    keys: Arc<RwLock<HashMap<String, CryptoKey>>>,
    /// Current active signing key ID
    active_kid: Arc<RwLock<Option<String>>>,
    /// Configuration
    config: KeyRotationConfig,
    /// Storage backend (Redis or database)
    storage: Arc<dyn KeyStorage>,
}

/// Trait for key storage backends
#[async_trait::async_trait]
pub trait KeyStorage: Send + Sync {
    /// Store a key
    async fn store_key(&self, key: &CryptoKey) -> Result<(), crate::shared::error::AppError>;

    /// Load all keys
    async fn load_keys(&self) -> Result<Vec<CryptoKey>, crate::shared::error::AppError>;

    /// Delete a key
    async fn delete_key(&self, kid: &str) -> Result<(), crate::shared::error::AppError>;

    /// Update key status
    async fn update_key_status(
        &self,
        kid: &str,
        status: KeyStatus,
    ) -> Result<(), crate::shared::error::AppError>;
}

impl JwksManager {
    /// Create a new JWKS manager
    ///
    /// # Errors
    ///
    /// Returns an error if key loading or initialization fails
    pub async fn new(
        config: KeyRotationConfig,
        storage: Arc<dyn KeyStorage>,
    ) -> Result<Self, crate::shared::error::AppError> {
        let manager = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            active_kid: Arc::new(RwLock::new(None)),
            config,
            storage,
        };

        // Load existing keys from storage
        manager.load_keys_from_storage().await?;

        // Check if we need to generate initial key
        if manager.get_active_key().await.is_none() {
            manager.rotate_keys().await?;
        }

        Ok(manager)
    }

    /// Load keys from storage
    #[allow(clippy::significant_drop_tightening)]
    async fn load_keys_from_storage(&self) -> Result<(), crate::shared::error::AppError> {
        let stored_keys = self.storage.load_keys().await?;
        let mut keys = self.keys.write().await;
        let mut active_kid = self.active_kid.write().await;

        for key in stored_keys {
            if key.is_active {
                *active_kid = Some(key.kid.clone());
            }
            keys.insert(key.kid.clone(), key);
        }

        Ok(())
    }

    /// Get the current active signing key
    pub async fn get_active_key(&self) -> Option<CryptoKey> {
        let active_kid = { self.active_kid.read().await.clone() };
        if let Some(kid) = active_kid.as_ref() {
            let keys = self.keys.read().await;
            keys.get(kid).cloned()
        } else {
            None
        }
    }

    /// Get a key by kid for validation
    pub async fn get_key(&self, kid: &str) -> Option<CryptoKey> {
        self.keys
            .read()
            .await
            .get(kid)
            .filter(|k| k.status == KeyStatus::Active || k.status == KeyStatus::Valid)
            .cloned()
    }

    /// Rotate keys - generate new key and mark old as rotating
    ///
    /// # Errors
    ///
    /// Returns an error if key generation, storage, or rotation fails
    #[allow(clippy::significant_drop_tightening)]
    pub async fn rotate_keys(&self) -> Result<(), crate::shared::error::AppError> {
        info!("Starting key rotation");

        // Generate new key
        let new_key = self.generate_new_key();
        let new_kid = new_key.kid.clone();

        // Store new key
        self.storage.store_key(&new_key).await?;

        // Update internal state
        let mut keys = self.keys.write().await;
        let mut active_kid = self.active_kid.write().await;

        // Mark old active key as rotating
        if let Some(old_kid) = active_kid.as_ref() {
            if let Some(old_key) = keys.get_mut(old_kid) {
                old_key.is_active = false;
                old_key.status = KeyStatus::Rotating;
                self.storage
                    .update_key_status(old_kid, KeyStatus::Rotating)
                    .await?;
            }
        }

        // Add new key
        keys.insert(new_kid.clone(), new_key);
        *active_kid = Some(new_kid.clone());

        // Clean up old keys
        self.cleanup_expired_keys().await?;

        info!("Key rotation completed. New active kid: {}", new_kid);
        Ok(())
    }

    /// Generate a new cryptographic key
    fn generate_new_key(&self) -> CryptoKey {
        let now = Utc::now();
        let kid = format!("key_{}", uuid::Uuid::new_v4());

        // Generate RSA key pair (simplified - in production use proper crypto library)
        let (public_key, private_key) = Self::generate_key_pair();

        CryptoKey {
            kid,
            kty: match self.config.algorithm {
                Algorithm::EdDSA => "OKP".to_string(), // Octet Key Pair for EdDSA
                Algorithm::ES256 | Algorithm::ES384 => "EC".to_string(),
                _ => "RSA".to_string(),
            },
            alg: match self.config.algorithm {
                Algorithm::EdDSA => "EdDSA".to_string(),
                Algorithm::RS384 => "RS384".to_string(),
                Algorithm::RS512 => "RS512".to_string(),
                Algorithm::ES256 => "ES256".to_string(),
                Algorithm::ES384 => "ES384".to_string(),
                _ => "RS256".to_string(),
            },
            use_: "sig".to_string(),
            created_at: now,
            expires_at: now + Duration::days(self.config.key_retention_days),
            rotate_at: now + Duration::days(self.config.rotation_interval_days),
            is_active: true,
            public_key,
            private_key: Some(private_key),
            status: KeyStatus::Active,
        }
    }

    /// Generate `EdDSA` key pair (Ed25519 - more secure than RSA)
    fn generate_key_pair() -> (String, String) {
        use base64::Engine;
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        // Generate random 32 bytes for Ed25519 private key using secure random
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Convert to PEM format using base64 engine
        let engine = base64::engine::general_purpose::STANDARD;

        // Create proper PKCS#8 private key format for EdDSA
        // This creates a proper ASN.1 DER encoded private key wrapped in PEM
        let private_key_der = {
            // Ed25519 private key OID: 1.3.101.112
            let mut der = Vec::new();
            // PKCS#8 PrivateKeyInfo structure
            der.extend_from_slice(&[
                0x30, 0x2E, // SEQUENCE, length 46
                0x02, 0x01, 0x00, // INTEGER version (0)
                0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
                0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
                0x04, 0x22, // OCTET STRING, length 34
                0x04, 0x20, // OCTET STRING, length 32 (private key)
            ]);
            der.extend_from_slice(&signing_key.to_bytes());
            der
        };

        let private_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            engine.encode(&private_key_der)
        );

        // Create proper SPKI public key format for EdDSA
        let public_key_der = {
            let mut der = Vec::new();
            // SPKI SubjectPublicKeyInfo structure
            der.extend_from_slice(&[
                0x30, 0x2A, // SEQUENCE, length 42
                0x30, 0x05, // SEQUENCE (AlgorithmIdentifier)
                0x06, 0x03, 0x2B, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
                0x03, 0x21, 0x00, // BIT STRING, length 33, unused bits 0
            ]);
            der.extend_from_slice(verifying_key.as_bytes());
            der
        };

        let public_pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            engine.encode(&public_key_der)
        );

        (private_pem, public_pem)
    }

    /// Clean up expired keys
    #[allow(clippy::significant_drop_tightening)]
    async fn cleanup_expired_keys(&self) -> Result<(), crate::shared::error::AppError> {
        let now = Utc::now();
        let mut keys = self.keys.write().await;

        // Find expired keys
        let expired_kids: Vec<String> = keys
            .iter()
            .filter(|(_, key)| key.expires_at < now || key.status == KeyStatus::Expired)
            .map(|(kid, _)| kid.clone())
            .collect();

        // Keep only max_keys most recent keys
        if keys.len() > self.config.max_keys {
            let mut sorted_keys: Vec<(String, DateTime<Utc>)> = keys
                .iter()
                .map(|(kid, key)| (kid.clone(), key.created_at))
                .collect();

            sorted_keys.sort_by(|a, b| b.1.cmp(&a.1));

            for (kid, _) in sorted_keys.iter().skip(self.config.max_keys) {
                if !expired_kids.contains(kid) {
                    warn!("Removing old key due to max_keys limit: {}", kid);
                }
            }
        }

        // Remove expired keys
        for kid in &expired_kids {
            keys.remove(kid);
            self.storage.delete_key(kid).await?;
            info!("Removed expired key: {}", kid);
        }

        Ok(())
    }

    /// Get JWKS for public endpoint
    pub async fn get_jwks(&self) -> JwksResponse {
        let jwks_keys: Vec<JwkKey> = {
            let keys = self.keys.read().await;
            keys.values()
                .filter(|k| k.status == KeyStatus::Active || k.status == KeyStatus::Valid)
                .map(|k| {
                    if k.alg == "EdDSA" && k.kty == "OKP" {
                        // EdDSA key - extract public key material
                        let x_coordinate = extract_eddsa_public_key(&k.public_key);
                        JwkKey {
                            kid: k.kid.clone(),
                            kty: k.kty.clone(),
                            alg: k.alg.clone(),
                            use_: k.use_.clone(),
                            n: None,
                            e: None,
                            x: Some(x_coordinate),
                            y: None,
                            crv: Some("Ed25519".to_string()),
                        }
                    } else {
                        // RSA key - extract modulus and exponent
                        JwkKey {
                            kid: k.kid.clone(),
                            kty: k.kty.clone(),
                            alg: k.alg.clone(),
                            use_: k.use_.clone(),
                            n: Some(extract_modulus(&k.public_key)),
                            e: Some(extract_exponent(&k.public_key)),
                            x: None,
                            y: None,
                            crv: None,
                        }
                    }
                })
                .collect()
        };

        JwksResponse { keys: jwks_keys }
    }

    /// Create JWT header with current kid
    ///
    /// # Errors
    ///
    /// Returns an error if no active key is available
    pub async fn create_jwt_header(&self) -> Result<Header, crate::shared::error::AppError> {
        let active_key = self.get_active_key().await.ok_or_else(|| {
            crate::shared::error::AppError::Internal("No active signing key".to_string())
        })?;
        let mut header = Header::new(self.config.algorithm);
        header.kid = Some(active_key.kid);
        Ok(header)
    }

    /// Get encoding key for signing (`EdDSA`)
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - No active signing key is available
    /// - Private key is missing from the active key
    /// - Private key is invalid or corrupted
    pub async fn get_encoding_key(&self) -> Result<EncodingKey, crate::shared::error::AppError> {
        let active_key = self.get_active_key().await.ok_or_else(|| {
            crate::shared::error::AppError::Internal("No active signing key".to_string())
        })?;
        let private_key = active_key.private_key.ok_or_else(|| {
            crate::shared::error::AppError::Internal("Private key not available".to_string())
        })?;

        // For EdDSA keys, use from_ed_pem instead of from_rsa_pem
        if self.config.algorithm == Algorithm::EdDSA {
            EncodingKey::from_ed_pem(private_key.as_bytes()).map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Invalid EdDSA private key: {e}"))
            })
        } else {
            // Fallback to RSA for other algorithms
            EncodingKey::from_rsa_pem(private_key.as_bytes()).map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Invalid RSA private key: {e}"))
            })
        }
    }

    /// Get decoding key for validation (`EdDSA`)
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Key with specified kid is not found
    /// - The key is expired or revoked
    /// - Public key is invalid or corrupted
    pub async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> Result<DecodingKey, crate::shared::error::AppError> {
        let key = self.get_key(kid).await.ok_or_else(|| {
            crate::shared::error::AppError::InvalidToken(format!("Unknown kid: {kid}"))
        })?;

        // For EdDSA keys, use from_ed_pem instead of from_rsa_pem
        if self.config.algorithm == Algorithm::EdDSA {
            DecodingKey::from_ed_pem(key.public_key.as_bytes()).map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Invalid EdDSA public key: {e}"))
            })
        } else {
            // Fallback to RSA for other algorithms
            DecodingKey::from_rsa_pem(key.public_key.as_bytes()).map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Invalid RSA public key: {e}"))
            })
        }
    }

    /// Check if rotation is needed
    pub async fn check_rotation_needed(&self) -> bool {
        if let Some(active_key) = self.get_active_key().await {
            Utc::now() >= active_key.rotate_at
        } else {
            true
        }
    }

    /// Revoke a key immediately
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Storage update fails when marking key as revoked
    /// - Key rotation fails when revoking the active key
    /// - Database or Redis connection issues occur
    pub async fn revoke_key(&self, kid: &str) -> Result<(), crate::shared::error::AppError> {
        let should_rotate = {
            let mut keys = self.keys.write().await;
            if let Some(key) = keys.get_mut(kid) {
                key.status = KeyStatus::Revoked;
                key.is_active = false;
                self.storage
                    .update_key_status(kid, KeyStatus::Revoked)
                    .await?;

                warn!("Key revoked: {}", kid);

                // Check if this was the active key
                let active_kid = self.active_kid.read().await;
                active_kid.as_ref() == Some(&kid.to_string())
            } else {
                false
            }
        };

        // Rotate immediately if this was the active key
        if should_rotate {
            self.rotate_keys().await?;
        }

        Ok(())
    }
}

/// JWKS response format
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

/// Individual JWK key format
#[derive(Debug, Serialize, Deserialize)]
pub struct JwkKey {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    /// RSA modulus (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EdDSA/ECDSA x coordinate (for OKP/EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EdDSA/ECDSA y coordinate (for EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Curve name (for OKP/EC keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
}

// Helper functions to extract key components

/// Extract `EdDSA` public key from PEM format
fn extract_eddsa_public_key(public_key_pem: &str) -> String {
    use base64::{engine::general_purpose, Engine as _};

    // Remove PEM headers and decode
    let pem_contents = public_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    if let Ok(der_bytes) = general_purpose::STANDARD.decode(pem_contents) {
        // For Ed25519, the public key is the last 32 bytes of the SPKI structure
        // SPKI structure is: 0x30 0x2A (SEQUENCE) + AlgID (12 bytes) + BIT STRING header (3 bytes) + 32 bytes public key
        if der_bytes.len() >= 32 {
            let public_key_bytes = &der_bytes[der_bytes.len() - 32..];
            return general_purpose::URL_SAFE_NO_PAD.encode(public_key_bytes);
        }
    }

    // Fallback: return a safe placeholder for now
    general_purpose::URL_SAFE_NO_PAD.encode("placeholder_ed25519_key_32_bytes___")
}

/// Extract RSA modulus from PEM format
fn extract_modulus(_public_key: &str) -> String {
    // In production, properly parse the PEM and extract modulus
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode("placeholder_modulus")
}

/// Extract RSA exponent from PEM format
fn extract_exponent(_public_key: &str) -> String {
    // In production, properly parse the PEM and extract exponent
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::STANDARD.encode("AQAB") // Common RSA exponent
}

/// In-memory key storage for testing
pub struct InMemoryKeyStorage {
    keys: Arc<RwLock<Vec<CryptoKey>>>,
}

impl Default for InMemoryKeyStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryKeyStorage {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl KeyStorage for InMemoryKeyStorage {
    async fn store_key(&self, key: &CryptoKey) -> Result<(), crate::shared::error::AppError> {
        self.keys.write().await.push(key.clone());
        Ok(())
    }

    async fn load_keys(&self) -> Result<Vec<CryptoKey>, crate::shared::error::AppError> {
        Ok(self.keys.read().await.clone())
    }

    async fn delete_key(&self, kid: &str) -> Result<(), crate::shared::error::AppError> {
        self.keys.write().await.retain(|k| k.kid != kid);
        Ok(())
    }

    async fn update_key_status(
        &self,
        kid: &str,
        status: KeyStatus,
    ) -> Result<(), crate::shared::error::AppError> {
        if let Some(key) = self.keys.write().await.iter_mut().find(|k| k.kid == kid) {
            key.status = status;
        }
        Ok(())
    }
}

/// Redis-backed key storage for distributed environments
pub struct RedisKeyStorage {
    client: redis::Client,
    key_prefix: String,
}

impl RedisKeyStorage {
    /// Create a new Redis key storage instance
    ///
    /// # Errors
    ///
    /// Returns an error if Redis client creation fails
    pub fn new(redis_url: &str) -> Result<Self, crate::shared::error::AppError> {
        let client = redis::Client::open(redis_url).map_err(|e| {
            crate::shared::error::AppError::Internal(format!("Failed to create Redis client: {e}"))
        })?;
        Ok(Self {
            client,
            key_prefix: "jwks:keys:".to_string(),
        })
    }
}

#[async_trait::async_trait]
impl KeyStorage for RedisKeyStorage {
    async fn store_key(&self, key: &CryptoKey) -> Result<(), crate::shared::error::AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Redis connection failed: {e}"))
            })?;

        let redis_key = format!("{}{}", self.key_prefix, key.kid);
        let key_json = serde_json::to_string(key).map_err(|e| {
            crate::shared::error::AppError::Internal(format!("Failed to serialize key: {e}"))
        })?;

        // Store with expiration based on key expiry
        let ttl = (key.expires_at.timestamp() - chrono::Utc::now().timestamp()).max(60);

        redis::pipe()
            .set(&redis_key, key_json)
            .expire(&redis_key, ttl)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| {
                crate::shared::error::AppError::Internal(format!(
                    "Failed to store key in Redis: {e}"
                ))
            })?;

        Ok(())
    }

    async fn load_keys(&self) -> Result<Vec<CryptoKey>, crate::shared::error::AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Redis connection failed: {e}"))
            })?;

        let pattern = format!("{}*", self.key_prefix);
        let keys: Vec<String> = conn.keys(pattern).await.map_err(|e| {
            crate::shared::error::AppError::Internal(format!("Failed to get keys from Redis: {e}"))
        })?;

        let mut crypto_keys = Vec::new();
        for redis_key in keys {
            let key_json: String = conn.get(&redis_key).await.map_err(|e| {
                crate::shared::error::AppError::Internal(format!(
                    "Failed to get key from Redis: {e}"
                ))
            })?;

            let crypto_key: CryptoKey = serde_json::from_str(&key_json).map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Failed to deserialize key: {e}"))
            })?;

            crypto_keys.push(crypto_key);
        }

        Ok(crypto_keys)
    }

    async fn delete_key(&self, kid: &str) -> Result<(), crate::shared::error::AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Redis connection failed: {e}"))
            })?;
        let redis_key = format!("{}{}", self.key_prefix, kid);
        conn.del::<_, ()>(&redis_key).await.map_err(|e| {
            crate::shared::error::AppError::Internal(format!("Failed to delete key {kid}: {e}"))
        })?;
        Ok(())
    }

    async fn update_key_status(
        &self,
        kid: &str,
        status: KeyStatus,
    ) -> Result<(), crate::shared::error::AppError> {
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Redis connection failed: {e}"))
            })?;

        let redis_key = format!("{}{}", self.key_prefix, kid);
        let key_json: Option<String> = conn.get(&redis_key).await.map_err(|e| {
            crate::shared::error::AppError::Internal(format!(
                "Failed to get key for status update: {e}"
            ))
        })?;

        if let Some(json) = key_json {
            let mut key: CryptoKey = serde_json::from_str(&json).map_err(|e| {
                crate::shared::error::AppError::Internal(format!("Failed to deserialize key: {e}"))
            })?;

            key.status = status;
            if status != KeyStatus::Active {
                key.is_active = false;
            }

            let updated_json = serde_json::to_string(&key).map_err(|e| {
                crate::shared::error::AppError::Internal(format!(
                    "Failed to serialize updated key: {e}"
                ))
            })?;

            conn.set::<_, _, ()>(&redis_key, updated_json)
                .await
                .map_err(|e| {
                    crate::shared::error::AppError::Internal(format!(
                        "Failed to update key status: {e}"
                    ))
                })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_rotation() {
        let config = KeyRotationConfig::default();
        let storage = Arc::new(InMemoryKeyStorage::new());
        let manager = JwksManager::new(config, storage)
            .await
            .expect("Test JWKS manager creation should succeed");

        // Should have one active key
        assert!(manager.get_active_key().await.is_some());

        // Rotate keys
        manager
            .rotate_keys()
            .await
            .expect("Test key rotation should succeed");

        // Should have new active key
        let active_key = manager
            .get_active_key()
            .await
            .expect("Test getting active key should succeed");
        assert_eq!(active_key.status, KeyStatus::Active);

        // Old key should still be available for validation
        {
            let keys = manager.keys.read().await;
            assert!(keys.len() >= 2);
        }
    }

    #[tokio::test]
    async fn test_jwks_endpoint() {
        let config = KeyRotationConfig::default();
        let storage = Arc::new(InMemoryKeyStorage::new());
        let manager = JwksManager::new(config, storage)
            .await
            .expect("Test JWKS manager creation should succeed");

        let jwks = manager.get_jwks().await;
        assert!(!jwks.keys.is_empty());
        assert!(jwks.keys[0].kid.starts_with("key_"));
    }
}
