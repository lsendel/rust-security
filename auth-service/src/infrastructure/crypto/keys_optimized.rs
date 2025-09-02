#![allow(clippy::unused_async)]
// Optimized key management implementation using ring for security
// This provides non-blocking RSA key generation and better caching

use base64::Engine as _;
use ring::{
    error::Unspecified,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::Value;
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::sync::{RwLock, Semaphore};

#[derive(Clone)]
pub struct OptimizedSecureKeyMaterial {
    pub kid: String,
    pub keypair: Arc<Ed25519KeyPair>,
    pub public_jwk: Value,
    pub created_at: u64,
    pub usage_count: Arc<std::sync::atomic::AtomicU64>,
}

/// Key generation status for monitoring
#[derive(Debug, Clone)]
pub enum KeyGenerationStatus {
    Available,
    Generating,
    Error(String),
}

/// Optimized key manager with non-blocking operations and ring security
pub struct OptimizedSecureKeyManager {
    keys: Arc<RwLock<Vec<OptimizedSecureKeyMaterial>>>,
    generation_semaphore: Arc<Semaphore>,
    rng: SystemRandom,
    status: Arc<RwLock<KeyGenerationStatus>>,
}

impl Default for OptimizedSecureKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl OptimizedSecureKeyManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(Vec::new())),
            generation_semaphore: Arc::new(Semaphore::new(1)), // Only one key generation at a time
            rng: SystemRandom::new(),
            status: Arc::new(RwLock::new(KeyGenerationStatus::Available)),
        }
    }

    /// Generate a new secure key using Ed25519 (more secure and performant than RSA)
    async fn generate_key(&self) -> Result<OptimizedSecureKeyMaterial, Unspecified> {
        // Generate Ed25519 key pair using Ring
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&self.rng)?;
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;

        let kid = format!("opt-key-{}", self.now_unix());

        // Create JWK for Ed25519
        let public_key_bytes = keypair.public_key().as_ref();
        let public_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key_bytes);

        let public_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "kid": kid,
            "x": public_key_b64,
            "alg": "EdDSA"
        });

        Ok(OptimizedSecureKeyMaterial {
            kid,
            keypair: Arc::new(keypair),
            public_jwk,
            created_at: self.now_unix(),
            usage_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Non-blocking key generation with status tracking
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - RSA key generation fails due to insufficient entropy
    /// - Key serialization or encoding fails
    /// - Internal storage operations fail
    pub async fn ensure_key_available(
        &self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let keys = self.keys.read().await;
        let needs_new_key =
            keys.is_empty() || keys.iter().any(|k| self.now_unix() - k.created_at > 3600);

        if !needs_new_key {
            return Ok(());
        }

        drop(keys); // Release read lock

        // Try to acquire generation semaphore without blocking
        if let Ok(permit) = self.generation_semaphore.try_acquire() {
            // Update status
            *self.status.write().await = KeyGenerationStatus::Generating;

            // Generate key in background
            let result = self.generate_key().await;

            match result {
                Ok(new_key) => {
                    let mut keys = self.keys.write().await;

                    // Keep only recent keys for rotation
                    keys.retain(|k| self.now_unix() - k.created_at < 7200);
                    keys.push(new_key);

                    // Limit to 3 keys maximum
                    if keys.len() > 3 {
                        keys.remove(0);
                    }

                    *self.status.write().await = KeyGenerationStatus::Available;
                }
                Err(e) => {
                    *self.status.write().await = KeyGenerationStatus::Error(e.to_string());
                    return Err(Box::new(e));
                }
            }

            drop(permit);
        }
        // If we can't acquire the semaphore, another task is generating

        Ok(())
    }

    /// Get current JWKS with caching
    pub async fn get_jwks(&self) -> Value {
        let keys = self.keys.read().await;
        let jwk_keys: Vec<Value> = keys.iter().map(|k| k.public_jwk.clone()).collect();

        serde_json::json!({
            "keys": jwk_keys
        })
    }

    /// Sign JWT with usage tracking
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - No keys are available for signing
    /// - Ed25519 signing operation fails
    /// - Cryptographic operations encounter errors
    pub async fn sign_jwt(
        &self,
        payload: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let keys = self.keys.read().await;

        keys.first().map_or_else(
            || Err("No signing key available".into()),
            |key_material| {
                // Increment usage counter
                key_material
                    .usage_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Ed25519 signing is simpler and more secure
                let signature = key_material.keypair.sign(payload);
                Ok(signature.as_ref().to_vec())
            },
        )
    }

    /// Get current key ID
    pub async fn get_current_kid(&self) -> Option<String> {
        let keys = self.keys.read().await;
        keys.first().map(|k| k.kid.clone())
    }

    /// Get key generation status
    pub async fn get_status(&self) -> KeyGenerationStatus {
        self.status.read().await.clone()
    }

    /// Get key usage statistics
    pub async fn get_key_stats(&self) -> Vec<(String, u64, u64)> {
        let keys = self.keys.read().await;
        keys.iter()
            .map(|k| {
                let usage = k.usage_count.load(std::sync::atomic::Ordering::Relaxed);
                (k.kid.clone(), k.created_at, usage)
            })
            .collect()
    }

    // Helper methods
    #[allow(dead_code)] // TODO: Will be used when JWT encoding/decoding is implemented
    fn base64url(&self, data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// Global optimized key manager instance
static OPTIMIZED_KEY_MANAGER: LazyLock<OptimizedSecureKeyManager> =
    LazyLock::new(OptimizedSecureKeyManager::new);

/// Public API functions
pub async fn get_optimized_jwks() -> Value {
    OPTIMIZED_KEY_MANAGER.get_jwks().await
}

/// Sign JWT using the global optimized key manager
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The global key manager is not available
/// - JWT signing operations fail
/// - Cryptographic operations encounter errors
pub async fn sign_jwt_optimized(
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    OPTIMIZED_KEY_MANAGER.sign_jwt(payload).await
}

/// Ensure optimized key is available globally
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The underlying key manager fails to ensure key availability
/// - Key generation operations fail
pub async fn ensure_optimized_key_available() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    OPTIMIZED_KEY_MANAGER.ensure_key_available().await
}

pub async fn get_optimized_current_kid() -> Option<String> {
    OPTIMIZED_KEY_MANAGER.get_current_kid().await
}

pub async fn get_optimized_key_status() -> KeyGenerationStatus {
    OPTIMIZED_KEY_MANAGER.get_status().await
}

pub async fn get_optimized_key_stats() -> Vec<(String, u64, u64)> {
    OPTIMIZED_KEY_MANAGER.get_key_stats().await
}

/// Initialize optimized keys on startup
/// 
/// # Errors
/// 
/// Returns an error if:
/// - Initial key generation or availability checks fail
/// - Cryptographic operations fail during startup
pub async fn initialize_optimized_keys() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ensure_optimized_key_available().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_optimized_key_generation() {
        let manager = OptimizedSecureKeyManager::new();
        manager.ensure_key_available().await.unwrap();

        let kid = manager.get_current_kid().await;
        assert!(kid.is_some());
        assert!(kid.unwrap().starts_with("opt-key-"));
    }

    #[tokio::test]
    async fn test_optimized_jwt_signing() {
        let manager = OptimizedSecureKeyManager::new();
        manager.ensure_key_available().await.unwrap();

        let payload = b"test payload";
        let signature = manager.sign_jwt(payload).await.unwrap();
        assert!(!signature.is_empty());
    }

    #[tokio::test]
    async fn test_optimized_jwks_generation() {
        let manager = OptimizedSecureKeyManager::new();
        manager.ensure_key_available().await.unwrap();

        let jwks = manager.get_jwks().await;
        let keys = jwks.get("keys").unwrap().as_array().unwrap();
        assert!(!keys.is_empty());
    }

    #[tokio::test]
    async fn test_usage_tracking() {
        let manager = OptimizedSecureKeyManager::new();
        manager.ensure_key_available().await.unwrap();

        let payload = b"test payload";
        manager.sign_jwt(payload).await.unwrap();
        manager.sign_jwt(payload).await.unwrap();

        let stats = manager.get_key_stats().await;
        assert!(!stats.is_empty());
        assert_eq!(stats[0].2, 2); // Usage count should be 2
    }

    #[tokio::test]
    async fn test_status_tracking() {
        let manager = OptimizedSecureKeyManager::new();
        let status = manager.get_status().await;

        match status {
            KeyGenerationStatus::Available => assert!(true),
            _ => assert!(false, "Expected Available status"),
        }
    }
}
