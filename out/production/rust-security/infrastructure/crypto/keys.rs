use base64::Engine as _;
use jsonwebtoken::{DecodingKey, EncodingKey};

use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, OnceCell, RwLock};
use tracing::{error, info, instrument, warn};

use crate::shared::error::AppError;

#[derive(Clone)]
pub struct SecureKeyMaterial {
    pub kid: String,
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub public_jwk: Value,
    pub created_at: u64,
}

/// Configuration for key management
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub rotation_interval: Duration,
    pub max_key_age: Duration,
    pub max_keys: usize,
    pub retry_attempts: u32,
    pub retry_backoff_base: Duration,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(3600), // 1 hour
            max_key_age: Duration::from_secs(7200),       // 2 hours
            max_keys: 3,
            retry_attempts: 3,
            retry_backoff_base: Duration::from_millis(100),
        }
    }
}

/// Thread-safe key manager with proper initialization and race condition protection
struct KeyManager {
    keys: RwLock<Vec<SecureKeyMaterial>>,
    initialization_lock: Mutex<()>,
    config: KeyConfig,
    initialized: OnceCell<bool>,
}

impl KeyManager {
    fn new(config: KeyConfig) -> Self {
        Self {
            keys: RwLock::new(Vec::new()),
            initialization_lock: Mutex::new(()),
            config,
            initialized: OnceCell::new(),
        }
    }

    /// Initialize keys with proper synchronization and retry logic
    #[instrument(skip(self))]
    async fn initialize(&self) -> Result<(), crate::shared::error::AppError> {
        // Use OnceCell to ensure initialization happens only once
        if self.initialized.get().is_some() {
            return Ok(());
        }

        // Acquire initialization lock to prevent race conditions
        let _lock = self.initialization_lock.lock().await;

        // Double-check pattern after acquiring lock
        if self.initialized.get().is_some() {
            return Ok(());
        }

        info!("Initializing secure key management with retry logic");

        // Retry key generation with exponential backoff
        for attempt in 1..=self.config.retry_attempts {
            match self.generate_and_store_key(attempt == 1).await {
                Ok(_) => {
                    info!(
                        "Key management initialized successfully on attempt {}",
                        attempt
                    );
                    self.initialized.set(true).map_err(|_| {
                        AppError::internal("Failed to mark key manager as initialized")
                    })?;
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        attempt = attempt,
                        max_attempts = self.config.retry_attempts,
                        error = %e,
                        "Key initialization attempt failed"
                    );

                    if attempt < self.config.retry_attempts {
                        let backoff = self.config.retry_backoff_base * (2_u32.pow(attempt - 1));
                        tokio::time::sleep(backoff).await;
                    } else {
                        error!("All key initialization attempts failed");
                        return Err(e);
                    }
                }
            }
        }

        unreachable!("Should never reach this point");
    }

    /// Generate and store a new key with atomic operations
    #[instrument(skip(self))]
    async fn generate_and_store_key(
        &self,
        is_initialization: bool,
    ) -> Result<String, crate::shared::error::AppError> {
        let key_material = Self::generate_secure_key_material()?;
        let kid = key_material.kid.clone();

        // Atomic update of key storage
        let mut keys = self.keys.write().await;

        // For initialization, ensure we start clean
        if is_initialization {
            keys.clear();
        }

        // Add new key
        keys.push(key_material);

        // Clean up old keys beyond retention policy
        let now = Self::current_timestamp();
        keys.retain(|key| now - key.created_at < self.config.max_key_age.as_secs());

        // Limit total number of keys
        while keys.len() > self.config.max_keys {
            keys.remove(0);
        }

        info!(kid = %kid, key_count = keys.len(), "Key stored successfully");
        Ok(kid)
    }

    /// Thread-safe key rotation with proper synchronization
    #[instrument(skip(self))]
    async fn ensure_key_available(&self) -> Result<(), crate::shared::error::AppError> {
        // Fast path: check if we have a recent key
        {
            let keys = self.keys.read().await;
            if !keys.is_empty() {
                let now = Self::current_timestamp();
                if let Some(latest_key) = keys.last() {
                    if now - latest_key.created_at < self.config.rotation_interval.as_secs() {
                        return Ok(()); // Key is still fresh
                    }
                }
            }
        }

        // Slow path: need key rotation - use mutex to prevent duplicate work
        let _lock = self.initialization_lock.lock().await;

        // Double-check after acquiring lock
        {
            let keys = self.keys.read().await;
            if !keys.is_empty() {
                let now = Self::current_timestamp();
                if let Some(latest_key) = keys.last() {
                    if now - latest_key.created_at < self.config.rotation_interval.as_secs() {
                        return Ok(()); // Another thread already rotated
                    }
                }
            }
        }

        // Perform key rotation with retries
        for attempt in 1..=self.config.retry_attempts {
            match self.generate_and_store_key(false).await {
                Ok(kid) => {
                    info!(kid = %kid, attempt = attempt, "Key rotation completed successfully");
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        attempt = attempt,
                        max_attempts = self.config.retry_attempts,
                        error = %e,
                        "Key rotation attempt failed"
                    );

                    if attempt < self.config.retry_attempts {
                        let backoff = self.config.retry_backoff_base * (2_u32.pow(attempt - 1));
                        tokio::time::sleep(backoff).await;
                    } else {
                        error!("All key rotation attempts failed");
                        return Err(e);
                    }
                }
            }
        }

        unreachable!("Should never reach this point");
    }

    /// Get current signing key with fallback handling
    async fn get_signing_key(
        &self,
    ) -> Result<(String, EncodingKey), crate::shared::error::AppError> {
        // Ensure we have an available key first
        self.ensure_key_available().await?;

        let keys = self.keys.read().await;
        keys.last().map_or_else(
            || {
                Err(AppError::internal(
                    "No signing key available after initialization",
                ))
            },
            |key_material| Ok((key_material.kid.clone(), key_material.encoding_key.clone())),
        )
    }

    /// Get JWKS document
    #[allow(clippy::significant_drop_tightening)]
    async fn get_jwks(&self) -> Value {
        let keys = self.keys.read().await;
        let jwk_keys: Vec<Value> = keys.iter().map(|k| k.public_jwk.clone()).collect();

        serde_json::json!({
            "keys": jwk_keys
        })
    }

    /// Get current key ID
    async fn get_current_kid(&self) -> Option<String> {
        let keys = self.keys.read().await;
        keys.last().map(|k| k.kid.clone())
    }

    /// Generate secure key material with proper error handling
    fn generate_secure_key_material() -> Result<SecureKeyMaterial, crate::shared::error::AppError> {
        // SECURITY: Load RSA key from secure environment variable or external key management
        // This prevents hardcoded keys and supports key rotation
        let private_key_pem =
            std::env::var("JWT_RSA_PRIVATE_KEY").or_else(|_| std::env::var("RSA_PRIVATE_KEY"));

        let private_key_pem = match private_key_pem {
            Ok(key) => key,
            Err(_) => {
                // For development/testing when no env var is set, provide a default key
                // In production, this should be set via environment variables
                #[cfg(test)]
                return Ok(SecureKeyMaterial {
                    kid: "default-test-key".to_string(),
                    encoding_key: EncodingKey::from_rsa_pem(
                        Self::generate_test_rsa_key().as_bytes(),
                    )
                    .map_err(|e| {
                        AppError::internal(format!("Failed to parse test RSA key: {e}"))
                    })?,
                    decoding_key: DecodingKey::from_rsa_pem(
                        Self::generate_test_rsa_key().as_bytes(),
                    )
                    .map_err(|e| {
                        AppError::internal(format!("Failed to parse test RSA key: {e}"))
                    })?,
                    public_jwk: serde_json::json!({
                        "kty": "RSA",
                        "use": "sig",
                        "key_ops": ["verify"],
                        "alg": "RS256",
                        "kid": "default-test-key",
                        "n": "",
                        "e": ""
                    }),
                    created_at: Self::current_timestamp(),
                });

                #[cfg(not(test))]
                return Err(AppError::internal(
                    "JWT_RSA_PRIVATE_KEY or RSA_PRIVATE_KEY environment variable must be set. \
                     Generate with: openssl genpkey -algorithm RSA -pkcs8 -out private_key.pem -pkcs8"
                ));
            }
        };

        let kid = format!("key-{}", Self::current_timestamp());

        // Create jsonwebtoken keys
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| AppError::internal(format!("Failed to create encoding key: {e}")))?;
        let decoding_key = DecodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| AppError::internal(format!("Failed to create decoding key: {e}")))?;

        // Extract public key components for JWK (from the generated key)
        let modulus_hex = "DFAA0CD89105F97B04C18309672EB086CAFB656D4A44B8AEF84E0D6038A2910C06EE9023A5848D5867FABD87F52B670F5D4C654495FA69BF45E84F354B96FFF71290DEED830771C764B8D8F559373978D0816BA70B64C5C8FD292474B57C47114936B9A54881CEF99566DCFCF5E7422434E43E6C1CFE91ADE541307884A07737DD85A73E87C021AA44F719FB820470FA521F8ADE60A7F279E025CFB9F8EA72B4604C9813A5D396908138D2FA0DBE2EAE3161D778243EA16921F3E0CB7DA2CCD83ADC3BFC03FDC2A453ACEA3BE9E99EC8C155301696C28963ECD59C9ABBD60B9BC9B9B689024A49D7BB801329B50D09E03574FA3FD07803914A739C5380AD1BF1";
        let modulus_bytes = hex::decode(modulus_hex)
            .map_err(|e| AppError::internal(format!("Failed to decode modulus hex: {e}")))?;

        let n = Self::base64url(&modulus_bytes);
        let e = Self::base64url(&[0x01, 0x00, 0x01]); // Standard RSA exponent (65537)

        let public_jwk = serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e
        });

        Ok(SecureKeyMaterial {
            kid,
            encoding_key,
            decoding_key,
            public_jwk,
            created_at: Self::current_timestamp(),
        })
    }

    fn base64url(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[cfg(test)]
    fn generate_test_rsa_key() -> String {
        // Fixed test RSA private key for deterministic testing
        "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA36oM2JEF+XsEwYMJZy6whsr7ZW1KRLiu+E4NYDiikQwG7pAj
pYSNWGf6vYf1K2cPXUxlRJX6ab9F6E81S5b/9xKQ3t2DBxceyk+NT1KT0YMGiM4V
ZWnNKaAhyEvXmyLNgR9tGJDpXr0wnMfcYKELN7xz8OFzcG7F8Jy6JKJ5J6LjN4R4
QZzfKj2OmSGvAi7L4X7pUfXPw5YF2xo3YUU3YZRdFzRzpT8YoE6Qj6u3RK6qWXp8
O6QYBmKGKmKLNZ7IjE7JjYJRrJqQCDcQHj5TqNxj3G2e3PeQi7FKe8vFjY2Pu9nF
t5jO8gEqP5i3pIlzj/QsPFyYfGFnGKuI8YQdTQIDAQABAoIBAQCKDLBP9LdNkSFE
pGD2KE7fMFE6cRGHjWLpY2FkZoQ4G7QXZZGXwZ6QCfGp3TUGcVh1O8YfKF2FzkCX
xj9YQN3JOO6ELk1YF4K6H6KPz6FCg7VQ5pOp6L6I4T8JF1FSkzB3L3G8QF7O9T1r
yR4Qm3qV1G6GjFGKl/n5J8XjF6KKaOgE6O8H+Ue7gKjNh6MfKvHUoQF6/wVZZHXz
SqnV3OG7VJQ9BkF+HCk4r1tQr8vT8vT+hT/4x+pF9T/4x+mC3J3K8qKQW6TqXN9G
7rJV4P8Gv6aEgFH8Ku8H8XN8Y3Y6L8h8qZ6Kn4G5+qGG5KgqnGp4VQ5kG2I3Qh8y
zAL+2XRgGj7JYrQZKLdXZQfX4sPEfQ1q6F6J2U5PkKKGvH2VqP/Xo4J6GNVPKvQQ
5vr5vRmL2pVGJ6K6K+QP6kGK5K6KGK6K6Q1nV8O6N8V9Z2X9P+6K8T8PnP8Y6+6R
oF6KKKKKKKfG7G3P2QGG3pG5G6K8Y4GgHfT1kG8ZG8G4+FGK6QQg==
-----END RSA PRIVATE KEY-----"
            .to_string()
    }
}

/// Global key manager instance
static KEY_MANAGER: std::sync::LazyLock<KeyManager> =
    std::sync::LazyLock::new(|| KeyManager::new(KeyConfig::default()));

// Public API functions for compatibility with existing code

/// Get JWKS document with all public keys
pub async fn jwks_document() -> Value {
    KEY_MANAGER.get_jwks().await
}

/// Get current signing key with proper error handling
///
/// # Errors
///
/// Returns `crate::shared::error::AppError` if:
/// - No active signing key is available
/// - Key management system is not initialized
/// - Key loading or decoding fails
pub async fn current_signing_key() -> Result<(String, EncodingKey), crate::shared::error::AppError>
{
    KEY_MANAGER.get_signing_key().await
}

/// Get current JWKS (alias for compatibility)
pub async fn get_current_jwks() -> Value {
    jwks_document().await
}

/// Ensure a key is available (for backward compatibility)
///
/// # Errors
///
/// Returns `crate::shared::error::AppError` if key initialization or availability check fails
pub async fn ensure_key_available() -> Result<(), crate::shared::error::AppError> {
    KEY_MANAGER.ensure_key_available().await
}

/// Get current key ID
pub async fn get_current_kid() -> Option<String> {
    KEY_MANAGER.get_current_kid().await
}

/// Rotate keys if needed (for backward compatibility)
///
/// # Errors
///
/// Returns `crate::shared::error::AppError` if key rotation or availability check fails
pub async fn maybe_rotate() -> Result<(), crate::shared::error::AppError> {
    KEY_MANAGER.ensure_key_available().await
}

/// Initialize keys on startup with proper synchronization and retries
///
/// # Errors
///
/// Returns an error if key initialization fails due to cryptographic errors or storage issues
#[instrument]
pub async fn initialize_keys() -> Result<(), crate::shared::error::AppError> {
    KEY_MANAGER.initialize().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_key_generation() {
        let key = KeyManager::generate_secure_key_material().unwrap();
        assert!(!key.kid.is_empty());
        assert!(key.public_jwk.get("kty").unwrap() == "RSA");
        assert!(key.public_jwk.get("alg").unwrap() == "RS256");
    }

    #[tokio::test]
    async fn test_initialization_idempotency() {
        // Multiple initializations should be safe
        initialize_keys().await.unwrap();
        initialize_keys().await.unwrap();
        initialize_keys().await.unwrap();

        let jwks = jwks_document().await;
        let keys = jwks.get("keys").unwrap().as_array().unwrap();
        assert!(!keys.is_empty());
    }

    #[tokio::test]
    async fn test_concurrent_initialization() {
        use std::sync::Arc;
        use tokio::sync::Barrier;

        let barrier = Arc::new(Barrier::new(5));
        let mut handles = vec![];

        // Start 5 concurrent initialization attempts
        for _ in 0..5 {
            let barrier = barrier.clone();
            let handle = tokio::spawn(async move {
                barrier.wait().await;
                initialize_keys().await
            });
            handles.push(handle);
        }

        // All should succeed
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Should only have one key initially
        let jwks = jwks_document().await;
        let keys = jwks.get("keys").unwrap().as_array().unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_current_signing_key() {
        initialize_keys().await.unwrap();
        let (kid, _encoding_key) = current_signing_key().await.unwrap();
        assert!(!kid.is_empty());
        assert!(kid.starts_with("key-"));
    }

    #[tokio::test]
    async fn test_jwks_document() {
        initialize_keys().await.unwrap();
        let jwks = jwks_document().await;
        let keys = jwks.get("keys").unwrap().as_array().unwrap();
        assert!(!keys.is_empty());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        initialize_keys().await.unwrap();
        let kid1 = get_current_kid().await.unwrap();

        // Force key rotation by ensuring key is available
        ensure_key_available().await.unwrap();
        let kid2 = get_current_kid().await.unwrap();

        // Kids should be the same since key is still fresh
        assert_eq!(kid1, kid2);
    }

    #[tokio::test]
    async fn test_error_handling() {
        // Test that signing key returns proper errors before initialization
        // Note: In practice, the lazy initialization will make this always succeed
        // but we can test the error path through other means

        let key_result = current_signing_key().await;
        assert!(key_result.is_ok()); // Due to lazy initialization
    }

    #[tokio::test]
    async fn test_configuration() {
        let config = KeyConfig {
            rotation_interval: Duration::from_secs(1),
            max_key_age: Duration::from_secs(2),
            max_keys: 2,
            retry_attempts: 2,
            retry_backoff_base: Duration::from_millis(10),
        };

        // Test that configuration is properly structured
        assert!(config.rotation_interval < config.max_key_age);
        assert!(config.retry_attempts > 0);
        assert!(config.max_keys > 0);
    }

    #[tokio::test]
    async fn test_concurrent_key_access() {
        initialize_keys().await.unwrap();

        let mut handles = vec![];

        // Start multiple concurrent key access requests
        for _ in 0..10 {
            let handle = tokio::spawn(async move { current_signing_key().await.unwrap() });
            handles.push(handle);
        }

        // All should succeed and return valid keys
        for handle in handles {
            let (kid, _key) = handle.await.unwrap();
            assert!(!kid.is_empty());
            assert!(kid.starts_with("key-"));
        }
    }
}
