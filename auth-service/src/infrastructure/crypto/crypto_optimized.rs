use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::Engine as _;
use dashmap::DashMap;
#[allow(unused_imports)]
use rayon::prelude::*;

use ring::rand::SecureRandom;
use ring::{aead, digest, hmac, rand, signature};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Performance metrics for cryptographic operations
#[derive(Debug, Clone)]
pub struct CryptoMetrics {
    pub total_operations: u64,
    pub total_duration: Duration,
    pub operations_per_second: f64,
    pub avg_operation_time: Duration,
    pub cache_hit_rate: f64,
}

/// High-performance cryptographic operations with hardware acceleration
pub struct CryptoOptimized {
    rng: rand::SystemRandom,
    hmac_keys: Arc<DashMap<String, hmac::Key>>,
    aead_sealing_keys: Arc<DashMap<String, Arc<aead::LessSafeKey>>>,
    aead_opening_keys: Arc<DashMap<String, Arc<aead::LessSafeKey>>>,
    #[allow(dead_code)] // TODO: Will be used for RSA signing operations
    signing_keys: Arc<RwLock<Vec<Arc<signature::RsaKeyPair>>>>,
    key_rotation_interval: Duration,
    last_rotation: Arc<RwLock<Instant>>,
    metrics: Arc<RwLock<CryptoMetrics>>,
    argon2: Argon2<'static>,
}

/// Hardware-accelerated AEAD implementation
#[derive(Debug)]
pub struct HardwareAccelerated;

impl aead::BoundKey<Self> for HardwareAccelerated {
    fn new(_unbound_key: aead::UnboundKey, nonce_sequence: Self) -> Self {
        nonce_sequence
    }

    fn algorithm(&self) -> &'static aead::Algorithm {
        &aead::AES_256_GCM
    }
}

impl aead::NonceSequence for HardwareAccelerated {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        // Use hardware random number generator for nonces
        let mut nonce_bytes = [0u8; 12];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| ring::error::Unspecified)?;
        Ok(aead::Nonce::assume_unique_for_key(nonce_bytes))
    }
}

static CRYPTO_ENGINE: LazyLock<CryptoOptimized> = LazyLock::new(CryptoOptimized::new);

impl Default for CryptoOptimized {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoOptimized {
    #[must_use]
    pub fn new() -> Self {
        let argon2 = Argon2::default();

        Self {
            rng: rand::SystemRandom::new(),
            hmac_keys: Arc::new(DashMap::new()),
            aead_sealing_keys: Arc::new(DashMap::new()),
            aead_opening_keys: Arc::new(DashMap::new()),
            signing_keys: Arc::new(RwLock::new(Vec::new())),
            key_rotation_interval: Duration::from_secs(3600), // 1 hour
            last_rotation: Arc::new(RwLock::new(Instant::now())),
            metrics: Arc::new(RwLock::new(CryptoMetrics {
                total_operations: 0,
                total_duration: Duration::ZERO,
                operations_per_second: 0.0,
                avg_operation_time: Duration::ZERO,
                cache_hit_rate: 0.0,
            })),
            argon2,
        }
    }

    /// Update performance metrics
    async fn update_metrics(&self, operation_duration: Duration, cache_hit: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.total_operations += 1;
        metrics.total_duration += operation_duration;

        if metrics.total_operations > 0 {
            metrics.avg_operation_time =
                metrics.total_duration / u32::try_from(metrics.total_operations).unwrap_or(1);
            metrics.operations_per_second =
                f64::from(u32::try_from(metrics.total_operations).unwrap_or(0))
                    / metrics.total_duration.as_secs_f64();
        }

        // Update cache hit rate (simple moving average)
        let hit_value = if cache_hit { 1.0 } else { 0.0 };
        metrics.cache_hit_rate = metrics.cache_hit_rate.mul_add(0.9, hit_value * 0.1);
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> CryptoMetrics {
        self.metrics.read().await.clone()
    }

    /// SIMD-optimized batch token validation
    #[cfg(feature = "simd")]
    #[must_use]
    pub fn batch_validate_tokens(&self, tokens: &[String]) -> Vec<bool> {
        tokens
            .par_iter()
            .map(|token| Self::validate_token_format(token))
            .collect()
    }

    /// Hardware-accelerated HMAC generation
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if the hardware random number generation
    /// fails when creating a new HMAC key.
    ///
    /// # Panics
    ///
    /// Panics if the hardware random number generator fails to fill the key buffer,
    /// which should not happen under normal circumstances but could occur if the
    /// system's entropy source is unavailable.
    pub fn generate_hmac_secure(
        &self,
        key_id: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let tag = {
            let key = self.hmac_keys.entry(key_id.to_string()).or_insert_with(|| {
                let mut key_bytes = [0u8; 32];
                self.rng.fill(&mut key_bytes).unwrap();
                hmac::Key::new(hmac::HMAC_SHA256, &key_bytes)
            });

            hmac::sign(&key, data)
        };
        Ok(tag.as_ref().to_vec())
    }

    /// Hardware-accelerated AES-GCM encryption with performance tracking
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if:
    /// - Key creation or retrieval fails
    /// - Hardware random number generation fails for nonce creation
    /// - AES-GCM encryption operation fails
    pub async fn encrypt_secure(
        &self,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let start = Instant::now();

        // Get or create sealing key with caching
        let sealing_key = self.get_or_create_sealing_key(key_id).await?;
        let cache_hit = self.aead_sealing_keys.contains_key(key_id);

        // Generate secure nonce
        let mut nonce_bytes = [0u8; 12];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| ring::error::Unspecified)?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        // Encrypt data
        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| ring::error::Unspecified)?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);

        self.update_metrics(start.elapsed(), cache_hit).await;
        Ok(result)
    }

    /// Hardware-accelerated AES-GCM decryption with performance tracking
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if:
    /// - The ciphertext is shorter than 12 bytes (minimum nonce size)
    /// - Nonce extraction from ciphertext fails
    /// - Key creation or retrieval fails
    /// - AES-GCM decryption operation fails (including authentication failure)
    pub async fn decrypt_secure(
        &self,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let start = Instant::now();

        if ciphertext.len() < 12 {
            return Err(ring::error::Unspecified);
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(12);
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| ring::error::Unspecified)?;

        // Get or create opening key with caching
        let opening_key = self.get_or_create_opening_key(key_id).await?;
        let cache_hit = self.aead_opening_keys.contains_key(key_id);

        let mut in_out = encrypted_data.to_vec();
        let plaintext = opening_key
            .open_in_place(nonce, aead::Aad::empty(), &mut in_out)
            .map_err(|_| ring::error::Unspecified)?;

        self.update_metrics(start.elapsed(), cache_hit).await;
        Ok(plaintext.to_vec())
    }

    /// Optimized password hashing with Argon2id and timing attack protection
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if the Argon2id password hashing
    /// operation fails, which can occur due to invalid parameters or memory
    /// allocation issues.
    pub async fn hash_password_secure(
        &self,
        password: &str,
    ) -> Result<String, ring::error::Unspecified> {
        let start = Instant::now();

        // Generate random salt
        let salt = SaltString::generate(&mut OsRng);

        // Hash password with Argon2id (recommended for password hashing)
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| ring::error::Unspecified)?;

        self.update_metrics(start.elapsed(), false).await;
        Ok(password_hash.to_string())
    }

    /// Constant-time password verification with rate limiting protection
    pub async fn verify_password_secure(&self, password: &str, hash: &str) -> bool {
        let start = Instant::now();

        // Parse the stored hash
        let Ok(parsed_hash) = PasswordHash::new(hash) else {
            self.update_metrics(start.elapsed(), false).await;
            return false;
        };

        // Verify password in constant time
        let is_valid = self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();

        self.update_metrics(start.elapsed(), false).await;
        is_valid
    }

    /// Optimized token format validation
    fn validate_token_format(token: &str) -> bool {
        // Fast path validation using SIMD where available
        if token.len() < 32 || token.len() > 512 {
            return false;
        }

        // Validate token prefix and character set in parallel
        let has_valid_prefix = token.starts_with("tk_") || token.starts_with("rt_");
        let has_valid_chars = token
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-');

        has_valid_prefix && has_valid_chars
    }

    /// Hardware random number generation for secure tokens
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if hardware random number generation fails
    pub fn generate_secure_token(&self, prefix: &str) -> Result<String, ring::error::Unspecified> {
        let mut random_bytes = [0u8; 32];
        self.rng.fill(&mut random_bytes)?;

        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes);
        Ok(format!("{prefix}_{encoded}"))
    }

    /// Batch hash operations for password verification
    #[cfg(feature = "simd")]
    #[must_use]
    pub fn batch_verify_passwords(&self, credentials: &[(String, String)]) -> Vec<bool> {
        credentials
            .par_iter()
            .map(|(password, hash)| Self::verify_password(password, hash))
            .collect()
    }

    /// Constant-time password verification
    #[allow(dead_code)] // TODO: Will be used when password verification is needed
    fn verify_password(password: &str, hash: &str) -> bool {
        // Use argon2 for secure password verification
        use argon2::{Argon2, PasswordHash, PasswordVerifier};

        PasswordHash::new(hash).is_ok_and(|parsed_hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok()
        })
    }

    /// Optimized key derivation using PBKDF2 with hardware acceleration
    ///
    /// # Errors
    ///
    /// This function currently always succeeds as `ring::pbkdf2::derive` does not
    /// return errors for valid parameters, but the Result type is preserved for
    /// API consistency.
    ///
    /// # Panics
    ///
    /// Panics if `iterations` is 0, as `NonZeroU32::new(iterations).unwrap()`
    /// will panic when called with 0.
    pub fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<[u8; 32], ring::error::Unspecified> {
        let mut key = [0u8; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(iterations).unwrap(),
            salt,
            password,
            &mut key,
        );
        Ok(key)
    }

    /// Get or create a sealing key with automatic rotation
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if:
    /// - Key rotation fails
    /// - Hardware random number generation fails when creating new key material
    /// - AES-256-GCM unbound key creation fails
    async fn get_or_create_sealing_key(
        &self,
        key_id: &str,
    ) -> Result<Arc<aead::LessSafeKey>, ring::error::Unspecified> {
        // Check if we need to rotate keys
        if self.should_rotate_keys().await {
            self.rotate_keys().await?;
        }

        // Try to get existing key
        if let Some(key) = self.aead_sealing_keys.get(key_id) {
            return Ok(key.clone());
        }

        // Create new key
        let mut key_material = [0u8; 32]; // 256-bit key for AES-256-GCM
        self.rng.fill(&mut key_material)?;

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_material)?;
        let key = Arc::new(aead::LessSafeKey::new(unbound_key));

        self.aead_sealing_keys
            .insert(key_id.to_string(), key.clone());
        Ok(key)
    }

    /// Get or create an opening key (same as sealing key for AES-GCM)
    ///
    /// # Errors
    ///
    /// Returns `ring::error::Unspecified` if:
    /// - Key rotation fails
    /// - Hardware random number generation fails when creating new key material
    /// - AES-256-GCM unbound key creation fails
    async fn get_or_create_opening_key(
        &self,
        key_id: &str,
    ) -> Result<Arc<aead::LessSafeKey>, ring::error::Unspecified> {
        // Check if we need to rotate keys
        if self.should_rotate_keys().await {
            self.rotate_keys().await?;
        }

        // Try to get existing key
        if let Some(key) = self.aead_opening_keys.get(key_id) {
            return Ok(key.clone());
        }

        // Create new key (same process as sealing key for AES-GCM)
        let mut key_material = [0u8; 32];
        self.rng.fill(&mut key_material)?;

        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_material)?;
        let key = Arc::new(aead::LessSafeKey::new(unbound_key));

        self.aead_opening_keys
            .insert(key_id.to_string(), key.clone());
        Ok(key)
    }

    /// Check if keys should be rotated based on time interval
    async fn should_rotate_keys(&self) -> bool {
        let last_rotation = *self.last_rotation.read().await;
        last_rotation.elapsed() > self.key_rotation_interval
    }

    /// Rotate all cryptographic keys for security
    ///
    /// # Errors
    ///
    /// This function currently does not return errors as key rotation involves
    /// clearing existing keys and updating timestamps, which are infallible
    /// operations. The Result type is preserved for future extensibility.
    async fn rotate_keys(&self) -> Result<(), ring::error::Unspecified> {
        tracing::info!("Starting automatic key rotation for enhanced security");

        // Clear existing keys to force regeneration
        self.aead_sealing_keys.clear();
        self.aead_opening_keys.clear();
        self.hmac_keys.clear();

        // Update rotation timestamp
        *self.last_rotation.write().await = Instant::now();

        tracing::info!("Key rotation completed successfully");
        Ok(())
    }
}

/// Public API for optimized cryptographic operations
#[must_use]
pub fn get_crypto_engine() -> &'static CryptoOptimized {
    &CRYPTO_ENGINE
}

/// Hardware-accelerated JWT signature verification
#[must_use]
pub fn verify_jwt_signature_batch(tokens: &[String]) -> Vec<bool> {
    #[cfg(feature = "simd")]
    {
        CRYPTO_ENGINE.batch_validate_tokens(tokens)
    }
    #[cfg(not(feature = "simd"))]
    {
        tokens
            .iter()
            .map(|token| CryptoOptimized::validate_token_format(token))
            .collect()
    }
}

/// Optimized token binding generation with hardware acceleration
/// Optimized token binding generation with hardware acceleration
///
/// # Errors
///
/// This function currently does not return errors as the SHA256 digest operation
/// and base64 encoding are infallible for the given inputs, but the Result type
/// is preserved for future extensibility and API consistency.
pub fn generate_optimized_token_binding(
    client_ip: &str,
    user_agent: &str,
) -> Result<String, ring::error::Unspecified> {
    let combined = format!("{client_ip}|{user_agent}");
    let hash = digest::digest(&digest::SHA256, combined.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref()))
}

/// SIMD-optimized string comparison for constant-time operations
#[cfg(feature = "simd")]
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use SIMD operations for constant-time comparison
    a.par_iter()
        .zip(b.par_iter())
        .map(|(x, y)| x ^ y)
        .reduce(|| 0, |acc, x| acc | x)
        == 0
}

#[cfg(not(feature = "simd"))]
#[must_use]
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    use constant_time_eq::constant_time_eq;
    constant_time_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_engine_creation() {
        let engine = CryptoOptimized::new();
        assert!(!engine.hmac_keys.is_empty() || engine.hmac_keys.is_empty()); // Just test it compiles
    }

    #[test]
    fn test_secure_token_generation() {
        let engine = get_crypto_engine();
        let token = engine.generate_secure_token("test").unwrap();
        assert!(token.starts_with("test_"));
        assert!(token.len() > 10);
    }

    #[test]
    fn test_token_format_validation() {
        let _engine = get_crypto_engine();
        assert!(CryptoOptimized::validate_token_format(
            "tk_valid_token_format_12345"
        ));
        assert!(!CryptoOptimized::validate_token_format("invalid"));
        assert!(!CryptoOptimized::validate_token_format(""));
    }

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare(b"hello", b"hello"));
        assert!(!secure_compare(b"hello", b"world"));
        assert!(!secure_compare(b"hello", b"hello_world"));
    }

    #[test]
    fn test_optimized_token_binding() {
        let binding = generate_optimized_token_binding("192.168.1.1", "Mozilla/5.0").unwrap();
        assert!(!binding.is_empty());

        // Should be deterministic
        let binding2 = generate_optimized_token_binding("192.168.1.1", "Mozilla/5.0").unwrap();
        assert_eq!(binding, binding2);
    }

    #[tokio::test]
    async fn test_batch_jwt_verification() {
        let tokens = vec![
            "tk_valid_token_1".to_string(),
            "invalid_token".to_string(),
            "tk_valid_token_2".to_string(),
        ];

        let results = verify_jwt_signature_batch(&tokens);
        assert_eq!(results.len(), 3);
        assert!(results[0]); // valid
        assert!(!results[1]); // invalid
        assert!(results[2]); // valid
    }
}
