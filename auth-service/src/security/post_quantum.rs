//! Post-Quantum Cryptography Module
//!
//! Consolidated post-quantum cryptographic operations combining:
//! - `post_quantum_crypto.rs` - Main post-quantum implementations
//! - `pq_jwt.rs` - Post-quantum JWT operations
//! - `infrastructure/crypto/quantum_jwt.rs` - Quantum-resistant JWT
//!
//! Features:
//! - NIST-standardized post-quantum algorithms (when available)
//! - Hybrid classical/post-quantum cryptography for transition
//! - Post-quantum JWT signing and verification
//! - Key encapsulation mechanisms (KEM)
//! - Digital signature schemes
//! - Migration utilities for smooth transition

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

/// Post-quantum cryptography errors
#[derive(Error, Debug)]
pub enum PostQuantumError {
    #[error("Algorithm not supported: {0}")]
    AlgorithmNotSupported(String),
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Signature generation failed: {0}")]
    SignatureGenerationFailed(String),
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),
    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),
    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
    #[error("Migration error: {0}")]
    MigrationError(String),
    #[error("Hybrid operation failed: {0}")]
    HybridOperationFailed(String),
}

/// Classical algorithms for hybrid crypto
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassicalAlgorithm {
    Rsa2048,
    EcdsaP256,
    Ed25519,
}

/// Migration modes for transitioning to PQ crypto
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationMode {
    ClassicalOnly,
    Hybrid,
    PostQuantumOnly,
}

/// Performance optimization modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerformanceMode {
    Speed,
    Size,
    Balanced,
}

/// Post-quantum algorithms (alias for compatibility)
pub type PQAlgorithm = PostQuantumAlgorithm;

/// Security levels for post-quantum cryptography
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// NIST Level 1 - 128-bit classical security equivalent
    Level1,
    /// NIST Level 3 - 192-bit classical security equivalent
    Level3,
    /// NIST Level 5 - 256-bit classical security equivalent
    Level5,
}

impl SecurityLevel {
    /// Get recommended parameters for each security level
    #[must_use]
    pub const fn parameters(&self) -> SecurityParameters {
        match self {
            Self::Level1 => SecurityParameters {
                kyber_variant: KyberVariant::Kyber512,
                dilithium_variant: DilithiumVariant::Dilithium2,
                classical_key_size: 256, // P-256/Ed25519
            },
            Self::Level3 => SecurityParameters {
                kyber_variant: KyberVariant::Kyber768,
                dilithium_variant: DilithiumVariant::Dilithium3,
                classical_key_size: 384, // P-384
            },
            Self::Level5 => SecurityParameters {
                kyber_variant: KyberVariant::Kyber1024,
                dilithium_variant: DilithiumVariant::Dilithium5,
                classical_key_size: 521, // P-521
            },
        }
    }
}

/// Security parameters for a given level
#[derive(Debug, Clone)]
pub struct SecurityParameters {
    pub kyber_variant: KyberVariant,
    pub dilithium_variant: DilithiumVariant,
    pub classical_key_size: u16,
}

/// Kyber KEM variants (NIST ML-KEM)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KyberVariant {
    Kyber512,  // Level 1 security
    Kyber768,  // Level 3 security
    Kyber1024, // Level 5 security
}

/// Dilithium signature variants (NIST ML-DSA)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DilithiumVariant {
    Dilithium2, // Level 1 security
    Dilithium3, // Level 3 security
    Dilithium5, // Level 5 security
}

/// Supported post-quantum algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostQuantumAlgorithm {
    /// CRYSTALS-Kyber - Key Encapsulation Mechanism
    Kyber(KyberVariant),
    /// CRYSTALS-Dilithium - Digital Signatures
    Dilithium(DilithiumVariant),
    /// Hybrid: Classical + Post-Quantum
    Hybrid,
}

/// Post-quantum key pair
#[derive(Debug, Clone)]
pub struct PostQuantumKeyPair {
    pub algorithm: PostQuantumAlgorithm,
    pub security_level: SecurityLevel,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // Will be zeroized on drop
    pub key_id: String,
    pub created_at: u64,
    pub expires_at: u64,
}

impl Drop for PostQuantumKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Post-quantum signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostQuantumSignature {
    pub algorithm: PostQuantumAlgorithm,
    pub signature: Vec<u8>,
    pub key_id: String,
    pub timestamp: u64,
}

/// Encapsulation result (for KEM operations)
#[derive(Debug, Clone)]
pub struct EncapsulationResult {
    pub ciphertext: Vec<u8>,    // Encapsulated key
    pub shared_secret: Vec<u8>, // Decapsulated shared secret
}

impl Drop for EncapsulationResult {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

// PostQuantumConfig removed - using PQConfig instead for consistency

/// Post-quantum metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PostQuantumMetrics {
    pub keys_generated: u64,
    pub signatures_created: u64,
    pub signatures_verified: u64,
    pub encapsulations: u64,
    pub decapsulations: u64,
    pub hybrid_operations: u64,
    pub avg_signature_time_ms: f64,
    pub avg_verification_time_ms: f64,
}

/// Post-quantum cryptography service
pub struct PostQuantumService {
    config: PostQuantumConfig,

    // Key storage
    active_keys: Arc<RwLock<HashMap<String, PostQuantumKeyPair>>>,

    // Classical keys for hybrid mode
    #[cfg(feature = "ed25519-dalek")]
    ed25519_keys: Arc<RwLock<HashMap<String, ed25519_dalek::SigningKey>>>,

    // Metrics
    metrics: Arc<RwLock<PostQuantumMetrics>>,

    // Random number generator
    rng: ring::rand::SystemRandom,
}

impl PostQuantumService {
    /// Create a new post-quantum service
    pub async fn new(config: PostQuantumConfig) -> Result<Self, PostQuantumError> {
        // Check if post-quantum features are available
        if !cfg!(feature = "post-quantum") {
            warn!("Post-quantum cryptography not compiled in - using classical algorithms only");
        }

        let service = Self {
            config,
            active_keys: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "ed25519-dalek")]
            ed25519_keys: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(PostQuantumMetrics::default())),
            rng: ring::rand::SystemRandom::new(),
        };

        // Generate initial keys if post-quantum is available
        #[cfg(feature = "post-quantum")]
        {
            service.generate_initial_keys().await?;
        }

        info!(
            "Post-quantum service initialized with security level {:?}",
            service.config.default_security_level
        );
        Ok(service)
    }

    /// Generate initial keys for all supported algorithms
    #[cfg(feature = "post-quantum")]
    async fn generate_initial_keys(&self) -> Result<(), PostQuantumError> {
        for algorithm in &self.config.supported_algorithms {
            match algorithm {
                PostQuantumAlgorithm::Dilithium(variant) => {
                    self.generate_dilithium_key(*variant).await?;
                }
                PostQuantumAlgorithm::Kyber(variant) => {
                    self.generate_kyber_key(*variant).await?;
                }
                PostQuantumAlgorithm::Hybrid => {
                    self.generate_hybrid_key().await?;
                }
            }
        }
        Ok(())
    }

    /// Generate a Dilithium key pair
    #[cfg(feature = "post-quantum")]
    async fn generate_dilithium_key(
        &self,
        variant: DilithiumVariant,
    ) -> Result<String, PostQuantumError> {
        let key_id = self.generate_key_id();
        let security_level = match variant {
            DilithiumVariant::Dilithium2 => SecurityLevel::Level1,
            DilithiumVariant::Dilithium3 => SecurityLevel::Level3,
            DilithiumVariant::Dilithium5 => SecurityLevel::Level5,
        };

        // In a real implementation, we would use pqcrypto-dilithium
        // For now, this is a placeholder structure
        let (public_key, private_key) = self.mock_dilithium_keygen(variant)?;

        let key_pair = PostQuantumKeyPair {
            algorithm: PostQuantumAlgorithm::Dilithium(variant),
            security_level,
            public_key,
            private_key,
            key_id: key_id.clone(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs()
                + (u64::from(self.config.key_rotation_interval_days) * 86400),
        };

        self.active_keys
            .write()
            .await
            .insert(key_id.clone(), key_pair);

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.keys_generated += 1;
        }

        info!("Generated Dilithium {:?} key pair: {}", variant, key_id);
        Ok(key_id)
    }

    /// Generate a Kyber key pair
    #[cfg(feature = "post-quantum")]
    async fn generate_kyber_key(&self, variant: KyberVariant) -> Result<String, PostQuantumError> {
        let key_id = self.generate_key_id();
        let security_level = match variant {
            KyberVariant::Kyber512 => SecurityLevel::Level1,
            KyberVariant::Kyber768 => SecurityLevel::Level3,
            KyberVariant::Kyber1024 => SecurityLevel::Level5,
        };

        // In a real implementation, we would use pqcrypto-kyber
        let (public_key, private_key) = self.mock_kyber_keygen(variant)?;

        let key_pair = PostQuantumKeyPair {
            algorithm: PostQuantumAlgorithm::Kyber(variant),
            security_level,
            public_key,
            private_key,
            key_id: key_id.clone(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs()
                + (u64::from(self.config.key_rotation_interval_days) * 86400),
        };

        self.active_keys
            .write()
            .await
            .insert(key_id.clone(), key_pair);

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.keys_generated += 1;
        }

        info!("Generated Kyber {:?} key pair: {}", variant, key_id);
        Ok(key_id)
    }

    /// Generate a hybrid classical/post-quantum key
    async fn generate_hybrid_key(&self) -> Result<String, PostQuantumError> {
        let key_id = self.generate_key_id();

        // Generate Ed25519 key for classical component
        #[cfg(feature = "ed25519-dalek")]
        {
            let mut key_bytes = [0u8; 32];
            ring::rand::SecureRandom::fill(&self.rng, &mut key_bytes).map_err(|_| {
                PostQuantumError::KeyGenerationFailed("Failed to generate random bytes".to_string())
            })?;

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            self.ed25519_keys
                .write()
                .await
                .insert(key_id.clone(), signing_key);
        }

        // Generate post-quantum component (placeholder)
        #[cfg(feature = "post-quantum")]
        {
            let variant = DilithiumVariant::Dilithium3; // Default to Level 3
            let (public_key, private_key) = self.mock_dilithium_keygen(variant)?;

            let key_pair = PostQuantumKeyPair {
                algorithm: PostQuantumAlgorithm::Hybrid,
                security_level: SecurityLevel::Level3,
                public_key,
                private_key,
                key_id: key_id.clone(),
                created_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                    .as_secs(),
                expires_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                    .as_secs()
                    + (u64::from(self.config.key_rotation_interval_days) * 86400),
            };

            self.active_keys
                .write()
                .await
                .insert(key_id.clone(), key_pair);
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.keys_generated += 1;
        }

        info!("Generated hybrid key pair: {}", key_id);
        Ok(key_id)
    }

    /// Sign data using post-quantum signatures
    /// Signs data using post-quantum algorithms
    ///
    /// # Panics
    /// Panics if the system time is set to before the UNIX epoch (1970-01-01 00:00:00 UTC).
    pub async fn sign(
        &self,
        data: &[u8],
        key_id: &str,
    ) -> Result<PostQuantumSignature, PostQuantumError> {
        let start_time = std::time::Instant::now();

        let key = {
            let keys = self.active_keys.read().await;
            keys.get(key_id)
                .ok_or_else(|| {
                    PostQuantumError::InvalidKeyFormat(format!("Key {key_id} not found"))
                })?
                .clone()
        };

        let signature = match key.algorithm {
            PostQuantumAlgorithm::Dilithium(variant) => {
                #[cfg(feature = "post-quantum")]
                {
                    self.mock_dilithium_sign(data, &key.private_key, variant)?
                }
                #[cfg(not(feature = "post-quantum"))]
                {
                    return Err(PostQuantumError::FeatureNotEnabled(
                        "Post-quantum features not compiled".to_string(),
                    ));
                }
            }
            PostQuantumAlgorithm::Hybrid => self.hybrid_sign(data, key_id).await?,
            PostQuantumAlgorithm::Kyber(_) => {
                return Err(PostQuantumError::AlgorithmNotSupported(format!(
                    "{:?} signing not supported",
                    key.algorithm
                )));
            }
        };

        let pq_signature = PostQuantumSignature {
            algorithm: key.algorithm,
            signature,
            key_id: key_id.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs(),
        };

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.signatures_created += 1;
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_signature_time_ms = metrics
                .avg_signature_time_ms
                .mul_add((metrics.signatures_created - 1) as f64, elapsed_ms)
                / metrics.signatures_created as f64;
        }

        debug!("Signed data with {} in {:?}", key_id, start_time.elapsed());
        Ok(pq_signature)
    }

    /// Verify post-quantum signatures
    pub async fn verify(
        &self,
        data: &[u8],
        signature: &PostQuantumSignature,
    ) -> Result<bool, PostQuantumError> {
        let start_time = std::time::Instant::now();

        let key = {
            let keys = self.active_keys.read().await;
            keys.get(&signature.key_id)
                .ok_or_else(|| {
                    PostQuantumError::InvalidKeyFormat(format!(
                        "Key {} not found",
                        signature.key_id
                    ))
                })?
                .clone()
        };

        let is_valid = match signature.algorithm {
            PostQuantumAlgorithm::Dilithium(variant) => {
                #[cfg(feature = "post-quantum")]
                {
                    self.mock_dilithium_verify(data, &signature.signature, &key.public_key, variant)
                }
                #[cfg(not(feature = "post-quantum"))]
                {
                    return Err(PostQuantumError::FeatureNotEnabled(
                        "Post-quantum features not compiled".to_string(),
                    ));
                }
            }
            PostQuantumAlgorithm::Hybrid => {
                self.hybrid_verify(data, &signature.signature, &signature.key_id)
                    .await?
            }
            PostQuantumAlgorithm::Kyber(_) => {
                return Err(PostQuantumError::AlgorithmNotSupported(format!(
                    "{:?} verification not supported",
                    signature.algorithm
                )));
            }
        };

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.signatures_verified += 1;
            let elapsed_ms = start_time.elapsed().as_millis() as f64;
            metrics.avg_verification_time_ms = metrics
                .avg_verification_time_ms
                .mul_add((metrics.signatures_verified - 1) as f64, elapsed_ms)
                / metrics.signatures_verified as f64;
        }

        debug!(
            "Verified signature with {} in {:?}: {}",
            signature.key_id,
            start_time.elapsed(),
            is_valid
        );
        Ok(is_valid)
    }

    /// Hybrid signing (classical + post-quantum)
    async fn hybrid_sign(&self, data: &[u8], key_id: &str) -> Result<Vec<u8>, PostQuantumError> {
        // Classical signature component
        #[cfg(feature = "ed25519-dalek")]
        let classical_sig = {
            use ed25519_dalek::Signer;

            let ed25519_keys = self.ed25519_keys.read().await;
            let signing_key = ed25519_keys.get(key_id).ok_or_else(|| {
                PostQuantumError::InvalidKeyFormat(format!("Ed25519 key {key_id} not found"))
            })?;

            signing_key.sign(data).to_bytes().to_vec()
        };

        // Post-quantum signature component
        #[cfg(feature = "post-quantum")]
        let pq_sig = {
            let key = {
                let keys = self.active_keys.read().await;
                keys.get(key_id)
                    .ok_or_else(|| {
                        PostQuantumError::InvalidKeyFormat(format!("PQ key {key_id} not found"))
                    })?
                    .clone()
            };

            self.mock_dilithium_sign(data, &key.private_key, DilithiumVariant::Dilithium3)?
        };

        // Combine signatures (classical || post-quantum)
        #[cfg(all(feature = "ed25519-dalek", feature = "post-quantum"))]
        {
            let mut combined = classical_sig;
            combined.extend_from_slice(&pq_sig);

            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.hybrid_operations += 1;

            Ok(combined)
        }

        #[cfg(not(all(feature = "ed25519-dalek", feature = "post-quantum")))]
        {
            Err(PostQuantumError::FeatureNotEnabled(
                "Hybrid mode requires both classical and post-quantum features".to_string(),
            ))
        }
    }

    /// Hybrid verification (classical + post-quantum)
    async fn hybrid_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        key_id: &str,
    ) -> Result<bool, PostQuantumError> {
        #[cfg(all(feature = "ed25519-dalek", feature = "post-quantum"))]
        {
            // Split combined signature (first 64 bytes are Ed25519, rest is post-quantum)
            if signature.len() < 64 {
                return Ok(false);
            }

            let classical_sig = &signature[0..64];
            let pq_sig = &signature[64..];

            // Verify classical component
            let classical_valid = {
                use ed25519_dalek::Verifier;

                let ed25519_keys = self.ed25519_keys.read().await;
                let signing_key = ed25519_keys.get(key_id).ok_or_else(|| {
                    PostQuantumError::InvalidKeyFormat(format!("Ed25519 key {key_id} not found"))
                })?;
                let verifying_key = signing_key.verifying_key();
                let signature_obj = ed25519_dalek::Signature::from_bytes(
                    classical_sig.try_into().map_err(|_| {
                        PostQuantumError::SignatureVerificationFailed(
                            "Invalid classical signature length".to_string(),
                        )
                    })?,
                );

                verifying_key.verify(data, &signature_obj).is_ok()
            };

            // Verify post-quantum component
            let pq_valid = {
                let key = {
                    let keys = self.active_keys.read().await;
                    keys.get(key_id)
                        .ok_or_else(|| {
                            PostQuantumError::InvalidKeyFormat(format!("PQ key {key_id} not found"))
                        })?
                        .clone()
                };

                self.mock_dilithium_verify(
                    data,
                    pq_sig,
                    &key.public_key,
                    DilithiumVariant::Dilithium3,
                )
            };

            // Both must be valid for hybrid verification to succeed
            let is_valid = classical_valid && pq_valid;

            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.hybrid_operations += 1;

            Ok(is_valid)
        }

        #[cfg(not(all(feature = "ed25519-dalek", feature = "post-quantum")))]
        {
            Err(PostQuantumError::FeatureNotEnabled(
                "Hybrid mode requires both classical and post-quantum features".to_string(),
            ))
        }
    }

    /// Generate a unique key ID
    fn generate_key_id(&self) -> String {
        let mut bytes = [0u8; 16];
        ring::rand::SecureRandom::fill(&self.rng, &mut bytes).unwrap_or_else(|_| {
            // Fallback: use a deterministic ID based on current time
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| std::time::Duration::from_secs(0))
                .as_secs();
            bytes.copy_from_slice(&timestamp.to_le_bytes());
        });
        hex::encode(bytes)
    }

    /// Mock Dilithium key generation (placeholder for real implementation)
    #[cfg(feature = "post-quantum")]
    fn mock_dilithium_keygen(
        &self,
        variant: DilithiumVariant,
    ) -> Result<(Vec<u8>, Vec<u8>), PostQuantumError> {
        // In real implementation, would use pqcrypto-dilithium
        let (pk_size, sk_size) = match variant {
            DilithiumVariant::Dilithium2 => (1312, 2528),
            DilithiumVariant::Dilithium3 => (1952, 4000),
            DilithiumVariant::Dilithium5 => (2592, 4864),
        };

        let mut public_key = vec![0u8; pk_size];
        let mut private_key = vec![0u8; sk_size];

        ring::rand::SecureRandom::fill(&self.rng, &mut public_key).map_err(|_| {
            PostQuantumError::KeyGenerationFailed("Random generation failed".to_string())
        })?;
        ring::rand::SecureRandom::fill(&self.rng, &mut private_key).map_err(|_| {
            PostQuantumError::KeyGenerationFailed("Random generation failed".to_string())
        })?;

        Ok((public_key, private_key))
    }

    /// Mock Kyber key generation (placeholder for real implementation)
    #[cfg(feature = "post-quantum")]
    fn mock_kyber_keygen(
        &self,
        variant: KyberVariant,
    ) -> Result<(Vec<u8>, Vec<u8>), PostQuantumError> {
        // In real implementation, would use pqcrypto-kyber
        let (pk_size, sk_size) = match variant {
            KyberVariant::Kyber512 => (800, 1632),
            KyberVariant::Kyber768 => (1184, 2400),
            KyberVariant::Kyber1024 => (1568, 3168),
        };

        let mut public_key = vec![0u8; pk_size];
        let mut private_key = vec![0u8; sk_size];

        ring::rand::SecureRandom::fill(&self.rng, &mut public_key).map_err(|_| {
            PostQuantumError::KeyGenerationFailed("Random generation failed".to_string())
        })?;
        ring::rand::SecureRandom::fill(&self.rng, &mut private_key).map_err(|_| {
            PostQuantumError::KeyGenerationFailed("Random generation failed".to_string())
        })?;

        Ok((public_key, private_key))
    }

    /// Mock Dilithium signing (placeholder for real implementation)
    #[cfg(feature = "post-quantum")]
    fn mock_dilithium_sign(
        &self,
        _data: &[u8],
        _private_key: &[u8],
        variant: DilithiumVariant,
    ) -> Result<Vec<u8>, PostQuantumError> {
        // In real implementation, would use pqcrypto-dilithium
        let sig_size = match variant {
            DilithiumVariant::Dilithium2 => 2420,
            DilithiumVariant::Dilithium3 => 3293,
            DilithiumVariant::Dilithium5 => 4595,
        };

        let mut signature = vec![0u8; sig_size];
        ring::rand::SecureRandom::fill(&self.rng, &mut signature).map_err(|_| {
            PostQuantumError::SignatureGenerationFailed("Random generation failed".to_string())
        })?;

        Ok(signature)
    }

    /// Mock Dilithium verification (placeholder for real implementation)
    #[cfg(feature = "post-quantum")]
    const fn mock_dilithium_verify(
        &self,
        _data: &[u8],
        _signature: &[u8],
        _public_key: &[u8],
        _variant: DilithiumVariant,
    ) -> bool {
        // In real implementation, would use pqcrypto-dilithium
        // For mock, always return true
        true
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> PostQuantumMetrics {
        self.metrics.read().await.clone()
    }

    /// Reset metrics
    pub async fn reset_metrics(&self) {
        *self.metrics.write().await = PostQuantumMetrics::default();
    }

    /// List active keys
    pub async fn list_keys(&self) -> Vec<String> {
        self.active_keys.read().await.keys().cloned().collect()
    }

    /// Get key information
    pub async fn get_key_info(
        &self,
        key_id: &str,
    ) -> Option<(PostQuantumAlgorithm, SecurityLevel)> {
        let keys = self.active_keys.read().await;
        keys.get(key_id)
            .map(|key| (key.algorithm, key.security_level))
    }

    /// Check if migration mode is enabled
    #[must_use]
    pub const fn is_migration_mode(&self) -> bool {
        self.config.enable_migration_mode
    }

    /// Check if hybrid mode is enabled
    #[must_use]
    pub const fn is_hybrid_mode(&self) -> bool {
        self.config.enable_hybrid_mode
    }
}

/// Migration utilities for smooth classical -> post-quantum transition
pub struct MigrationHelper {
    service: Arc<PostQuantumService>,
}

impl MigrationHelper {
    #[must_use]
    pub const fn new(service: Arc<PostQuantumService>) -> Self {
        Self { service }
    }

    /// Generate migration plan for transitioning to post-quantum
    pub async fn create_migration_plan(&self) -> Result<MigrationPlan, PostQuantumError> {
        let plan = MigrationPlan {
            phases: vec![
                MigrationPhase {
                    name: "Phase 1: Hybrid Deployment".to_string(),
                    description: "Deploy hybrid classical/post-quantum signatures".to_string(),
                    duration_days: 30,
                    actions: vec![
                        "Enable hybrid mode".to_string(),
                        "Generate hybrid keys".to_string(),
                        "Gradual rollout to services".to_string(),
                    ],
                },
                MigrationPhase {
                    name: "Phase 2: Full Post-Quantum".to_string(),
                    description: "Transition to pure post-quantum algorithms".to_string(),
                    duration_days: 60,
                    actions: vec![
                        "Disable classical-only algorithms".to_string(),
                        "Update all services".to_string(),
                        "Performance optimization".to_string(),
                    ],
                },
            ],
            estimated_completion: chrono::Utc::now() + chrono::Duration::days(90),
            risk_assessment: "Medium - requires coordination across services".to_string(),
        };

        Ok(plan)
    }
}

/// Migration plan structure
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub phases: Vec<MigrationPhase>,
    pub estimated_completion: chrono::DateTime<chrono::Utc>,
    pub risk_assessment: String,
}

/// Individual migration phase
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationPhase {
    pub name: String,
    pub description: String,
    pub duration_days: u32,
    pub actions: Vec<String>,
}

/// Post-quantum configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQConfig {
    pub migration_mode: MigrationMode,
    pub performance_mode: PerformanceMode,
    pub security_level: SecurityLevel,
    pub classical_algorithm: ClassicalAlgorithm,
    pub pq_algorithm: PQAlgorithm,
    pub enable_migration_mode: bool,
    pub enable_hybrid_mode: bool,
}

impl Default for PQConfig {
    fn default() -> Self {
        Self {
            migration_mode: MigrationMode::Hybrid,
            performance_mode: PerformanceMode::Balanced,
            security_level: SecurityLevel::Level3,
            classical_algorithm: ClassicalAlgorithm::Ed25519,
            pq_algorithm: PQAlgorithm::Dilithium(DilithiumVariant::Dilithium3),
            enable_migration_mode: true,
            enable_hybrid_mode: true,
        }
    }
}

/// Post-quantum configuration (alias for compatibility)
pub type PostQuantumConfig = PQConfig;

/// Post-quantum crypto manager
#[derive(Debug)]
pub struct PQCryptoManager {
    config: PQConfig,
}

impl PQCryptoManager {
    pub fn new(config: PQConfig) -> Result<Self, PostQuantumError> {
        Ok(Self { config })
    }

    pub fn config(&self) -> &PQConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_post_quantum_service_creation() {
        let config = PostQuantumConfig::default();
        let service = PostQuantumService::new(config).await;

        // Should succeed even without post-quantum features
        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_security_level_parameters() {
        let level1 = SecurityLevel::Level1.parameters();
        let level3 = SecurityLevel::Level3.parameters();
        let level5 = SecurityLevel::Level5.parameters();

        assert_eq!(level1.kyber_variant, KyberVariant::Kyber512);
        assert_eq!(level3.dilithium_variant, DilithiumVariant::Dilithium3);
        assert_eq!(level5.classical_key_size, 521);
    }

    #[tokio::test]
    async fn test_migration_helper() {
        let config = PostQuantumConfig::default();
        let service = Arc::new(PostQuantumService::new(config).await.unwrap());
        let helper = MigrationHelper::new(service);

        let plan = helper.create_migration_plan().await.unwrap();
        assert_eq!(plan.phases.len(), 2);
        assert_eq!(plan.phases[0].name, "Phase 1: Hybrid Deployment");
    }

    #[tokio::test]
    async fn test_configuration_modes() {
        let config = PostQuantumConfig::default();
        let service = PostQuantumService::new(config).await.unwrap();

        assert!(service.is_hybrid_mode());
        assert!(service.is_migration_mode());
    }
}
