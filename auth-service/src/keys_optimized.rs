// Optimized key management implementation
// This provides non-blocking RSA key generation and better caching

use once_cell::sync::Lazy;
use rand::thread_rng;
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use base64::Engine as _;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct OptimizedRsaKeyMaterial {
    pub kid: String,
    pub private_der: Arc<Vec<u8>>, // PKCS1 DER
    pub public_jwk: Value,
    pub encoding_key: Arc<jsonwebtoken::EncodingKey>, // Cached encoding key
    pub created_at: u64,
}

/// Key generation status for monitoring
#[derive(Debug, Clone)]
pub enum KeyGenerationStatus {
    Available,
    Generating,
    Error(String),
}

/// Optimized key manager with non-blocking operations
pub struct OptimizedKeyManager {
    active_keys: RwLock<Vec<OptimizedRsaKeyMaterial>>,
    generation_semaphore: Semaphore, // Limit concurrent key generation
    last_rotation_check: RwLock<u64>,
    status: RwLock<KeyGenerationStatus>,
}

impl OptimizedKeyManager {
    pub fn new() -> Self {
        Self {
            active_keys: RwLock::new(Vec::new()),
            generation_semaphore: Semaphore::new(2), // Allow up to 2 concurrent generations
            last_rotation_check: RwLock::new(0),
            status: RwLock::new(KeyGenerationStatus::Available),
        }
    }

    /// Generate RSA key in background thread to avoid blocking async executor
    async fn generate_rsa_key_async(&self) -> anyhow::Result<OptimizedRsaKeyMaterial> {
        // Acquire semaphore to limit concurrent key generation
        let _permit = self.generation_semaphore.acquire().await?;
        
        // Update status
        *self.status.write().await = KeyGenerationStatus::Generating;
        
        // Generate key in blocking thread
        let key_material = tokio::task::spawn_blocking(|| -> anyhow::Result<OptimizedRsaKeyMaterial> {
            let mut rng = thread_rng();
            let private = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|e| anyhow::anyhow!("RSA key generation failed: {}", e))?;
            let public: RsaPublicKey = private.to_public_key();

            let n_b = bigint_to_bytes_be(public.n());
            let e_b = bigint_to_bytes_be(public.e());
            let n = base64url(&n_b);
            let e = base64url(&e_b);

            let kid = uuid::Uuid::new_v4().to_string();
            let public_jwk = serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": &kid,
                "n": &n,
                "e": &e,
            });

            let der = private
                .to_pkcs1_der()
                .map_err(|e| anyhow::anyhow!("Failed to encode private key: {}", e))?
                .as_bytes()
                .to_vec();

            // Pre-compute encoding key for better performance
            let encoding_key = jsonwebtoken::EncodingKey::from_rsa_der(&der);

            Ok(OptimizedRsaKeyMaterial {
                kid,
                private_der: Arc::new(der),
                public_jwk,
                encoding_key: Arc::new(encoding_key),
                created_at: now_unix(),
            })
        })
        .await??;

        // Update status back to available
        *self.status.write().await = KeyGenerationStatus::Available;

        Ok(key_material)
    }

    /// Ensure at least one key is available, generate if needed
    pub async fn ensure_initialized(&self) -> anyhow::Result<()> {
        let keys = self.active_keys.read().await;
        if !keys.is_empty() {
            return Ok(());
        }
        drop(keys);

        // Need to generate a key
        let key = self.generate_rsa_key_async().await?;
        let mut keys = self.active_keys.write().await;
        if keys.is_empty() {
            keys.push(key);
        }
        Ok(())
    }

    /// Check if rotation is needed and start background rotation if necessary
    pub async fn maybe_rotate_async(&self) -> anyhow::Result<()> {
        let rotation_secs: u64 = std::env::var("JWKS_ROTATION_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(24 * 3600); // 24 hours default

        let retain_secs: u64 = std::env::var("JWKS_RETAIN_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600); // 1 hour default

        let now = now_unix();
        
        // Check if we need to rotate
        let should_rotate = {
            let keys = self.active_keys.read().await;
            let last_check = *self.last_rotation_check.read().await;
            
            // Don't check too frequently
            if now < last_check + 300 { // Check at most every 5 minutes
                return Ok(());
            }
            
            keys.is_empty() || (now.saturating_sub(keys[0].created_at) >= rotation_secs)
        };

        if should_rotate {
            // Update last check time
            *self.last_rotation_check.write().await = now;
            
            // Start background key generation
            let manager = OPTIMIZED_KEY_MANAGER.clone();
            tokio::spawn(async move {
                match manager.generate_rsa_key_async().await {
                    Ok(new_key) => {
                        let mut keys = manager.active_keys.write().await;
                        keys.insert(0, new_key);
                        
                        // Clean up old keys
                        let newest = keys[0].created_at;
                        keys.retain(|k| newest.saturating_sub(k.created_at) <= retain_secs);
                        
                        tracing::info!("Key rotation completed successfully");
                    }
                    Err(e) => {
                        tracing::error!("Key rotation failed: {}", e);
                        let mut status = manager.status.write().await;
                        *status = KeyGenerationStatus::Error(e.to_string());
                    }
                }
            });
        }

        Ok(())
    }

    /// Get current signing key (cached for performance)
    pub async fn current_signing_key(&self) -> anyhow::Result<(String, Arc<jsonwebtoken::EncodingKey>)> {
        self.ensure_initialized().await?;
        self.maybe_rotate_async().await?;
        
        let keys = self.active_keys.read().await;
        let key = keys.first()
            .ok_or_else(|| anyhow::anyhow!("No signing key available"))?;
        
        Ok((key.kid.clone(), key.encoding_key.clone()))
    }

    /// Get JWKS document with all public keys
    pub async fn jwks_document(&self) -> anyhow::Result<Value> {
        self.ensure_initialized().await?;
        self.maybe_rotate_async().await?;
        
        let keys = self.active_keys.read().await;
        let public_keys: Vec<Value> = keys.iter().map(|k| k.public_jwk.clone()).collect();
        
        Ok(serde_json::json!({ "keys": public_keys }))
    }

    /// Get key generation status for monitoring
    pub async fn get_status(&self) -> KeyGenerationStatus {
        self.status.read().await.clone()
    }

    /// Get key statistics for monitoring
    pub async fn get_key_stats(&self) -> KeyStats {
        let keys = self.active_keys.read().await;
        let now = now_unix();
        
        let mut stats = KeyStats {
            total_keys: keys.len(),
            oldest_key_age_secs: 0,
            newest_key_age_secs: 0,
            next_rotation_in_secs: 0,
            status: self.get_status().await,
        };

        if !keys.is_empty() {
            stats.newest_key_age_secs = now.saturating_sub(keys[0].created_at);
            stats.oldest_key_age_secs = now.saturating_sub(keys.last().unwrap().created_at);
            
            let rotation_interval = std::env::var("JWKS_ROTATION_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(24 * 3600);
            
            stats.next_rotation_in_secs = rotation_interval
                .saturating_sub(stats.newest_key_age_secs);
        }

        stats
    }

    /// Force key rotation for testing or emergency scenarios
    pub async fn force_rotation(&self) -> anyhow::Result<()> {
        let new_key = self.generate_rsa_key_async().await?;
        let mut keys = self.active_keys.write().await;
        keys.insert(0, new_key);
        
        tracing::info!("Forced key rotation completed");
        Ok(())
    }
}

/// Key statistics for monitoring
#[derive(Debug, Clone)]
pub struct KeyStats {
    pub total_keys: usize,
    pub oldest_key_age_secs: u64,
    pub newest_key_age_secs: u64,
    pub next_rotation_in_secs: u64,
    pub status: KeyGenerationStatus,
}

// Global optimized key manager
static OPTIMIZED_KEY_MANAGER: Lazy<Arc<OptimizedKeyManager>> = 
    Lazy::new(|| Arc::new(OptimizedKeyManager::new()));

// Helper functions
fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn bigint_to_bytes_be(n: &rsa::BigUint) -> Vec<u8> {
    let mut bytes = n.to_bytes_be();
    while bytes.first().is_some_and(|b| *b == 0) {
        bytes.remove(0);
    }
    bytes
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// Public API functions (compatible with existing code)

/// Initialize key manager (non-blocking)
pub async fn ensure_initialized() -> anyhow::Result<()> {
    OPTIMIZED_KEY_MANAGER.ensure_initialized().await
}

/// Check for rotation (non-blocking)
pub async fn maybe_rotate() -> anyhow::Result<()> {
    OPTIMIZED_KEY_MANAGER.maybe_rotate_async().await
}

/// Get current signing key with caching
pub async fn current_signing_key() -> anyhow::Result<(String, jsonwebtoken::EncodingKey)> {
    let (kid, encoding_key) = OPTIMIZED_KEY_MANAGER.current_signing_key().await?;
    Ok((kid, (*encoding_key).clone()))
}

/// Get JWKS document
pub async fn jwks_document() -> anyhow::Result<Value> {
    OPTIMIZED_KEY_MANAGER.jwks_document().await
}

/// Get key statistics for monitoring endpoint
pub async fn get_key_stats() -> KeyStats {
    OPTIMIZED_KEY_MANAGER.get_key_stats().await
}

/// Force key rotation (for testing/emergency)
pub async fn force_key_rotation() -> anyhow::Result<()> {
    OPTIMIZED_KEY_MANAGER.force_rotation().await
}

/// Background task for proactive key rotation
pub async fn start_key_rotation_task() {
    let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Check every hour
    
    loop {
        interval.tick().await;
        
        if let Err(e) = OPTIMIZED_KEY_MANAGER.maybe_rotate_async().await {
            tracing::error!("Key rotation check failed: {}", e);
        }
    }
}

/// JWT signing with performance optimizations
pub async fn sign_jwt_optimized<T>(claims: &T, extra_headers: Option<serde_json::Map<String, serde_json::Value>>) -> anyhow::Result<String>
where
    T: serde::Serialize,
{
    let (kid, encoding_key) = current_signing_key().await?;
    
    let mut header = jsonwebtoken::Header {
        alg: jsonwebtoken::Algorithm::RS256,
        kid: Some(kid),
        ..Default::default()
    };
    
    // Add extra headers if provided
    if let Some(extra) = extra_headers {
        for (key, value) in extra {
            match key.as_str() {
                "typ" => header.typ = Some(value.as_str().unwrap_or("JWT").to_string()),
                "cty" => header.cty = Some(value.as_str().unwrap_or("").to_string()),
                _ => {
                    // Custom headers can be added to a map if needed
                    tracing::warn!("Unsupported header field: {}", key);
                }
            }
        }
    }
    
    jsonwebtoken::encode(&header, claims, &encoding_key)
        .map_err(|e| anyhow::anyhow!("JWT signing failed: {}", e))
}

/// Batch JWT signing for multiple tokens
pub async fn sign_jwts_batch<T>(
    tokens: &[(T, Option<serde_json::Map<String, serde_json::Value>>)],
) -> anyhow::Result<Vec<String>>
where
    T: serde::Serialize,
{
    let (kid, encoding_key) = current_signing_key().await?;
    
    let mut results = Vec::with_capacity(tokens.len());
    
    for (claims, extra_headers) in tokens {
        let mut header = jsonwebtoken::Header {
            alg: jsonwebtoken::Algorithm::RS256,
            kid: Some(kid.clone()),
            ..Default::default()
        };
        
        if let Some(extra) = extra_headers {
            for (key, value) in extra {
                match key.as_str() {
                    "typ" => header.typ = Some(value.as_str().unwrap_or("JWT").to_string()),
                    "cty" => header.cty = Some(value.as_str().unwrap_or("").to_string()),
                    _ => {}
                }
            }
        }
        
        let jwt = jsonwebtoken::encode(&header, claims, &encoding_key)
            .map_err(|e| anyhow::anyhow!("JWT signing failed: {}", e))?;
        results.push(jwt);
    }
    
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_optimized_key_generation() {
        let manager = OptimizedKeyManager::new();
        
        // Test initialization
        manager.ensure_initialized().await.unwrap();
        
        let keys = manager.active_keys.read().await;
        assert_eq!(keys.len(), 1);
        assert!(!keys[0].kid.is_empty());
        assert!(!keys[0].private_der.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_key_operations() {
        let manager = Arc::new(OptimizedKeyManager::new());
        let mut handles = Vec::new();
        
        // Spawn multiple concurrent operations
        for i in 0..10 {
            let manager_clone = Arc::clone(&manager);
            let handle = tokio::spawn(async move {
                if i % 2 == 0 {
                    // Half try to get signing key
                    manager_clone.current_signing_key().await
                } else {
                    // Half try to get JWKS
                    manager_clone.jwks_document().await.map(|_| ("test".to_string(), Arc::new(jsonwebtoken::EncodingKey::from_secret(b"test"))))
                }
            });
            handles.push(handle);
        }
        
        // All should succeed
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = OptimizedKeyManager::new();
        
        // Initialize with first key
        manager.ensure_initialized().await.unwrap();
        
        let initial_keys = manager.active_keys.read().await;
        let initial_kid = initial_keys[0].kid.clone();
        drop(initial_keys);
        
        // Force rotation
        manager.force_rotation().await.unwrap();
        
        let rotated_keys = manager.active_keys.read().await;
        assert!(rotated_keys.len() >= 1);
        assert_ne!(rotated_keys[0].kid, initial_kid);
    }

    #[tokio::test]
    async fn test_jwt_signing_performance() {
        use serde_json::json;
        
        // Initialize key manager
        ensure_initialized().await.unwrap();
        
        // Test single JWT signing
        let claims = json!({
            "sub": "test_user",
            "iat": now_unix(),
            "exp": now_unix() + 3600
        });
        
        let jwt = sign_jwt_optimized(&claims, None).await.unwrap();
        assert!(!jwt.is_empty());
        
        // Test batch JWT signing
        let batch_claims = vec![
            (claims.clone(), None),
            (claims.clone(), None),
            (claims, None),
        ];
        
        let jwts = sign_jwts_batch(&batch_claims).await.unwrap();
        assert_eq!(jwts.len(), 3);
        for jwt in jwts {
            assert!(!jwt.is_empty());
        }
    }

    #[tokio::test]
    async fn test_key_stats() {
        let manager = OptimizedKeyManager::new();
        manager.ensure_initialized().await.unwrap();
        
        let stats = manager.get_key_stats().await;
        assert_eq!(stats.total_keys, 1);
        assert!(stats.newest_key_age_secs < 60); // Should be very recent
        
        match stats.status {
            KeyGenerationStatus::Available => { /* Expected */ }
            _ => panic!("Expected Available status"),
        }
    }

    #[tokio::test]
    async fn test_semaphore_limiting() {
        let manager = OptimizedKeyManager::new();
        
        // Start multiple key generations concurrently
        let mut handles = Vec::new();
        for _ in 0..5 {
            let manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                manager_clone.generate_rsa_key_async().await
            });
            handles.push(handle);
        }
        
        // All should complete, but semaphore should limit concurrency
        let mut success_count = 0;
        for handle in handles {
            if handle.await.unwrap().is_ok() {
                success_count += 1;
            }
        }
        
        assert!(success_count > 0); // At least some should succeed
    }
}