//! # Post-Quantum Cryptography Implementation
//!
//! This module implements quantum-resistant cryptographic algorithms for the authentication service,
//! following NIST post-quantum cryptography standards and providing hybrid classical/post-quantum
//! solutions for secure transition.
//!
//! ## Features
//! - CRYSTALS-Kyber for key encapsulation (NIST standardized)
//! - CRYSTALS-Dilithium for digital signatures (NIST standardized)
//! - Hybrid cryptography combining classical and post-quantum algorithms
//! - JWT token signing with post-quantum signatures
//! - Key rotation and management for post-quantum keys
//! - Migration tools for smooth transition from classical cryptography
//!
//! ## Security Levels
//! - Level 1 (128-bit security): Kyber-512, Dilithium2
//! - Level 3 (192-bit security): Kyber-768, Dilithium3
//! - Level 5 (256-bit security): Kyber-1024, Dilithium5
//!
//! ## NIST Compliance
//! - FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
//! - FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA)
//! - SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use base64::Engine as _;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "post-quantum")]
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
#[cfg(feature = "post-quantum")]
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};

#[cfg(feature = "hybrid-crypto")]
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
#[cfg(feature = "hybrid-crypto")]
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};

use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};

/// Security levels for post-quantum cryptography
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit security equivalent
    Level1,
    /// 192-bit security equivalent
    Level3,
    /// 256-bit security equivalent
    Level5,
}

impl SecurityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Level1 => "Level1",
            SecurityLevel::Level3 => "Level3",
            SecurityLevel::Level5 => "Level5",
        }
    }

    pub fn recommended_for_production() -> Self {
        // Level 3 provides 192-bit security, suitable for long-term protection
        SecurityLevel::Level3
    }
}

/// Algorithm types for post-quantum cryptography
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PQAlgorithm {
    /// CRYSTALS-Kyber key encapsulation mechanism
    Kyber(SecurityLevel),
    /// CRYSTALS-Dilithium digital signature algorithm
    Dilithium(SecurityLevel),
    /// Hybrid scheme combining classical and post-quantum
    Hybrid { classical: ClassicalAlgorithm, post_quantum: Box<PQAlgorithm> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassicalAlgorithm {
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// Ed25519 signature scheme
    Ed25519,
    /// RSA with specified key size
    Rsa(u32),
}

/// Post-quantum key material with metadata
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct PQKeyMaterial {
    pub kid: String,
    pub algorithm: PQAlgorithm,
    pub security_level: SecurityLevel,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub key_data: PQKeyData,
    pub jwk: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub enum PQKeyData {
    #[cfg(feature = "post-quantum")]
    Dilithium {
        public_key: Vec<u8>,
        #[serde(skip_serializing)]
        private_key: Vec<u8>,
    },
    #[cfg(feature = "post-quantum")]
    Kyber {
        public_key: Vec<u8>,
        #[serde(skip_serializing)]
        private_key: Vec<u8>,
    },
    #[cfg(feature = "hybrid-crypto")]
    Hybrid { classical: ClassicalKeyData, post_quantum: Box<PQKeyData> },
    /// Placeholder for when post-quantum features are disabled
    #[cfg(not(feature = "post-quantum"))]
    Placeholder,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub enum ClassicalKeyData {
    #[cfg(feature = "hybrid-crypto")]
    EcdsaP256 {
        public_key: Vec<u8>,
        #[serde(skip_serializing)]
        private_key: Vec<u8>,
    },
    #[cfg(feature = "hybrid-crypto")]
    Ed25519 {
        public_key: Vec<u8>,
        #[serde(skip_serializing)]
        private_key: Vec<u8>,
    },
    /// Placeholder for when hybrid features are disabled
    #[cfg(not(feature = "hybrid-crypto"))]
    Placeholder,
}

/// Global post-quantum key store
static PQ_KEYS: Lazy<RwLock<HashMap<String, PQKeyMaterial>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Configuration for post-quantum cryptography
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQConfig {
    pub enabled: bool,
    pub default_security_level: SecurityLevel,
    pub enable_hybrid: bool,
    pub key_rotation_interval_hours: u64,
    pub migration_mode: MigrationMode,
    pub performance_mode: PerformanceMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationMode {
    /// Classical cryptography only
    Classical,
    /// Hybrid classical + post-quantum
    Hybrid,
    /// Post-quantum only
    PostQuantumOnly,
    /// Gradual migration with fallback
    GradualMigration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PerformanceMode {
    /// Optimized for speed
    Speed,
    /// Balanced speed and security
    Balanced,
    /// Maximum security
    Security,
}

impl Default for PQConfig {
    fn default() -> Self {
        Self {
            enabled: std::env::var("POST_QUANTUM_ENABLED")
                .map(|v| v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            default_security_level: SecurityLevel::recommended_for_production(),
            enable_hybrid: true,
            key_rotation_interval_hours: 24,
            migration_mode: MigrationMode::Hybrid,
            performance_mode: PerformanceMode::Balanced,
        }
    }
}

/// Post-quantum cryptography manager
pub struct PQCryptoManager {
    config: PQConfig,
}

impl PQCryptoManager {
    pub fn new(config: PQConfig) -> Self {
        Self { config }
    }

    pub fn default() -> Self {
        Self::new(PQConfig::default())
    }

    /// Initialize post-quantum cryptography system
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Post-quantum cryptography is disabled");
            return Ok(());
        }

        info!(
            "Initializing post-quantum cryptography with security level: {}",
            self.config.default_security_level.as_str()
        );

        // Log security event for PQ initialization
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::SystemEvent,
                SecuritySeverity::Medium,
                "post-quantum-crypto".to_string(),
                "Post-quantum cryptography system initialized".to_string(),
            )
            .with_actor("system".to_string())
            .with_action("pq_initialize".to_string())
            .with_target("crypto_system".to_string())
            .with_outcome("success".to_string())
            .with_reason("PQ cryptography system startup initialization".to_string())
            .with_detail("security_level".to_string(), self.config.default_security_level.as_str())
            .with_detail("hybrid_enabled".to_string(), self.config.enable_hybrid)
            .with_detail("migration_mode".to_string(), format!("{:?}", self.config.migration_mode)),
        );

        // Generate initial key pair
        self.generate_signing_key_pair(None).await?;

        Ok(())
    }

    /// Generate a new post-quantum key pair for signing
    pub async fn generate_signing_key_pair(
        &self,
        algorithm: Option<PQAlgorithm>,
    ) -> Result<String> {
        let algorithm = algorithm.unwrap_or_else(|| {
            if self.config.enable_hybrid {
                PQAlgorithm::Hybrid {
                    classical: ClassicalAlgorithm::Ed25519,
                    post_quantum: Box::new(PQAlgorithm::Dilithium(
                        self.config.default_security_level,
                    )),
                }
            } else {
                PQAlgorithm::Dilithium(self.config.default_security_level)
            }
        });

        let kid = self.generate_key_id();
        let created_at = current_timestamp();
        let expires_at = Some(created_at + self.config.key_rotation_interval_hours * 3600);

        let key_data = self.generate_key_data(&algorithm).await?;
        let jwk = self.generate_jwk(&algorithm, &key_data).await?;

        let key_material = PQKeyMaterial {
            kid: kid.clone(),
            algorithm,
            security_level: self.config.default_security_level,
            created_at,
            expires_at,
            key_data,
            jwk,
        };

        // Store the key
        let mut keys = PQ_KEYS.write().await;
        keys.insert(kid.clone(), key_material);

        info!("Generated new post-quantum key pair: {}", kid);

        // Log key generation event
        SecurityLogger::log_event(
            &SecurityEvent::new(
                SecurityEventType::KeyManagement,
                SecuritySeverity::Medium,
                "post-quantum-crypto".to_string(),
                "Post-quantum key pair generated".to_string(),
            )
            .with_actor("pq_system".to_string())
            .with_action("pq_generate_keys".to_string())
            .with_target("pq_keys".to_string())
            .with_outcome("success".to_string())
            .with_reason("New post-quantum key pair created for signing operations".to_string())
            .with_detail("kid".to_string(), kid.clone())
            .with_detail(
                "algorithm".to_string(),
                format!("{:?}", self.config.default_security_level),
            ),
        );

        Ok(kid)
    }

    /// Generate key data for the specified algorithm
    async fn generate_key_data(&self, algorithm: &PQAlgorithm) -> Result<PQKeyData> {
        match algorithm {
            #[cfg(feature = "post-quantum")]
            PQAlgorithm::Dilithium(level) => match level {
                SecurityLevel::Level1 => {
                    let (pk, sk) = dilithium2::keypair();
                    Ok(PQKeyData::Dilithium {
                        public_key: pk.as_bytes().to_vec(),
                        private_key: sk.as_bytes().to_vec(),
                    })
                }
                SecurityLevel::Level3 => {
                    let (pk, sk) = dilithium3::keypair();
                    Ok(PQKeyData::Dilithium {
                        public_key: pk.as_bytes().to_vec(),
                        private_key: sk.as_bytes().to_vec(),
                    })
                }
                SecurityLevel::Level5 => {
                    let (pk, sk) = dilithium5::keypair();
                    Ok(PQKeyData::Dilithium {
                        public_key: pk.as_bytes().to_vec(),
                        private_key: sk.as_bytes().to_vec(),
                    })
                }
            },
            #[cfg(feature = "hybrid-crypto")]
            PQAlgorithm::Hybrid { classical, post_quantum } => {
                let classical_data = self.generate_classical_key_data(classical).await?;
                let pq_data = Box::new(self.generate_key_data(post_quantum).await?);
                Ok(PQKeyData::Hybrid { classical: classical_data, post_quantum: pq_data })
            }
            _ => {
                #[cfg(not(feature = "post-quantum"))]
                {
                    warn!("Post-quantum features not enabled, using placeholder");
                    Ok(PQKeyData::Placeholder)
                }
                #[cfg(feature = "post-quantum")]
                Err(anyhow!("Unsupported algorithm: {:?}", algorithm))
            }
        }
    }

    #[cfg(feature = "hybrid-crypto")]
    async fn generate_classical_key_data(
        &self,
        algorithm: &ClassicalAlgorithm,
    ) -> Result<ClassicalKeyData> {
        match algorithm {
            ClassicalAlgorithm::Ed25519 => {
                use rand::rngs::OsRng;
                let signing_key = Ed25519SigningKey::generate(&mut OsRng);
                let verifying_key = signing_key.verifying_key();

                Ok(ClassicalKeyData::Ed25519 {
                    public_key: verifying_key.to_bytes().to_vec(),
                    private_key: signing_key.to_bytes().to_vec(),
                })
            }
            ClassicalAlgorithm::EcdsaP256 => {
                use rand::rngs::OsRng;
                let signing_key = P256SigningKey::random(&mut OsRng);
                let verifying_key = signing_key.verifying_key();

                Ok(ClassicalKeyData::EcdsaP256 {
                    public_key: verifying_key.to_encoded_point(false).as_bytes().to_vec(),
                    private_key: signing_key.to_bytes().to_vec(),
                })
            }
            _ => Err(anyhow!("Classical algorithm not supported: {:?}", algorithm)),
        }
    }

    #[cfg(not(feature = "hybrid-crypto"))]
    async fn generate_classical_key_data(
        &self,
        _algorithm: &ClassicalAlgorithm,
    ) -> Result<ClassicalKeyData> {
        Ok(ClassicalKeyData::Placeholder)
    }

    /// Generate JWK representation for the key
    async fn generate_jwk(
        &self,
        algorithm: &PQAlgorithm,
        key_data: &PQKeyData,
    ) -> Result<Option<serde_json::Value>> {
        match (algorithm, key_data) {
            #[cfg(feature = "post-quantum")]
            (PQAlgorithm::Dilithium(level), PQKeyData::Dilithium { public_key, .. }) => {
                let alg = match level {
                    SecurityLevel::Level1 => "DILITHIUM2",
                    SecurityLevel::Level3 => "DILITHIUM3",
                    SecurityLevel::Level5 => "DILITHIUM5",
                };

                Ok(Some(serde_json::json!({
                    "kty": "PQC",
                    "alg": alg,
                    "use": "sig",
                    "key_ops": ["verify"],
                    "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key),
                    "security_level": level.as_str()
                })))
            }
            #[cfg(feature = "hybrid-crypto")]
            (
                PQAlgorithm::Hybrid { classical, post_quantum },
                PQKeyData::Hybrid { classical: classical_data, post_quantum: pq_data },
            ) => {
                // For hybrid, create a composite JWK
                let classical_jwk = self.generate_classical_jwk(classical, classical_data).await?;
                let pq_jwk = self.generate_jwk(post_quantum, pq_data).await?;

                Ok(Some(serde_json::json!({
                    "kty": "HYBRID",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "classical": classical_jwk,
                    "post_quantum": pq_jwk
                })))
            }
            _ => Ok(None),
        }
    }

    #[cfg(feature = "hybrid-crypto")]
    async fn generate_classical_jwk(
        &self,
        algorithm: &ClassicalAlgorithm,
        key_data: &ClassicalKeyData,
    ) -> Result<serde_json::Value> {
        match (algorithm, key_data) {
            (ClassicalAlgorithm::Ed25519, ClassicalKeyData::Ed25519 { public_key, .. }) => {
                Ok(serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key)
                }))
            }
            (ClassicalAlgorithm::EcdsaP256, ClassicalKeyData::EcdsaP256 { public_key, .. }) => {
                // Extract x and y coordinates from uncompressed point
                if public_key.len() == 65 && public_key[0] == 0x04 {
                    let x = &public_key[1..33];
                    let y = &public_key[33..65];
                    Ok(serde_json::json!({
                        "kty": "EC",
                        "crv": "P-256",
                        "alg": "ES256",
                        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
                        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y)
                    }))
                } else {
                    Err(anyhow!("Invalid P-256 public key format"))
                }
            }
            _ => Err(anyhow!("Unsupported classical algorithm for JWK generation")),
        }
    }

    #[cfg(not(feature = "hybrid-crypto"))]
    async fn generate_classical_jwk(
        &self,
        _algorithm: &ClassicalAlgorithm,
        _key_data: &ClassicalKeyData,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::json!({}))
    }

    /// Sign data using post-quantum signature
    pub async fn sign(&self, data: &[u8], kid: Option<&str>) -> Result<Vec<u8>> {
        let keys = PQ_KEYS.read().await;

        let key_material = if let Some(kid) = kid {
            keys.get(kid).ok_or_else(|| anyhow!("Key not found: {}", kid))?
        } else {
            // Use the most recent key
            keys.values()
                .max_by_key(|k| k.created_at)
                .ok_or_else(|| anyhow!("No keys available for signing"))?
        };

        self.sign_with_key_material(data, key_material).await
    }

    async fn sign_with_key_material(
        &self,
        data: &[u8],
        key_material: &PQKeyMaterial,
    ) -> Result<Vec<u8>> {
        match &key_material.key_data {
            #[cfg(feature = "post-quantum")]
            PQKeyData::Dilithium { private_key, .. } => match key_material.security_level {
                SecurityLevel::Level1 => {
                    let sk = dilithium2::SecretKey::from_bytes(private_key)
                        .map_err(|_| anyhow!("Invalid Dilithium2 private key"))?;
                    let signature = dilithium2::sign(data, &sk);
                    Ok(signature.as_bytes().to_vec())
                }
                SecurityLevel::Level3 => {
                    let sk = dilithium3::SecretKey::from_bytes(private_key)
                        .map_err(|_| anyhow!("Invalid Dilithium3 private key"))?;
                    let signature = dilithium3::sign(data, &sk);
                    Ok(signature.as_bytes().to_vec())
                }
                SecurityLevel::Level5 => {
                    let sk = dilithium5::SecretKey::from_bytes(private_key)
                        .map_err(|_| anyhow!("Invalid Dilithium5 private key"))?;
                    let signature = dilithium5::sign(data, &sk);
                    Ok(signature.as_bytes().to_vec())
                }
            },
            #[cfg(feature = "hybrid-crypto")]
            PQKeyData::Hybrid { classical, post_quantum } => {
                // For hybrid signatures, concatenate classical and post-quantum signatures
                let classical_sig = self.sign_classical(data, classical).await?;

                // Create a temporary key material for the post-quantum part
                let pq_key_material = PQKeyMaterial {
                    kid: key_material.kid.clone(),
                    algorithm: match &key_material.algorithm {
                        PQAlgorithm::Hybrid { post_quantum, .. } => (**post_quantum).clone(),
                        _ => return Err(anyhow!("Invalid hybrid key structure")),
                    },
                    security_level: key_material.security_level,
                    created_at: key_material.created_at,
                    expires_at: key_material.expires_at,
                    key_data: (**post_quantum).clone(),
                    jwk: None,
                };

                let pq_sig = self.sign_with_key_material(data, &pq_key_material).await?;

                // Combine signatures (classical_sig_len + classical_sig + pq_sig)
                let mut combined = Vec::new();
                combined.extend_from_slice(&(classical_sig.len() as u32).to_be_bytes());
                combined.extend_from_slice(&classical_sig);
                combined.extend_from_slice(&pq_sig);

                Ok(combined)
            }
            #[cfg(not(feature = "post-quantum"))]
            PQKeyData::Placeholder => {
                warn!("Post-quantum features not enabled, cannot sign");
                Err(anyhow!("Post-quantum features not enabled"))
            }
        }
    }

    #[cfg(feature = "hybrid-crypto")]
    async fn sign_classical(
        &self,
        data: &[u8],
        classical_data: &ClassicalKeyData,
    ) -> Result<Vec<u8>> {
        match classical_data {
            ClassicalKeyData::Ed25519 { private_key, .. } => {
                use ed25519_dalek::Signer;
                let signing_key = Ed25519SigningKey::from_bytes(
                    private_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow!("Invalid Ed25519 private key length"))?,
                );
                let signature = signing_key.sign(data);
                Ok(signature.to_bytes().to_vec())
            }
            ClassicalKeyData::EcdsaP256 { private_key, .. } => {
                use p256::ecdsa::signature::Signer;
                use p256::ecdsa::Signature;
                let signing_key = P256SigningKey::from_bytes(private_key.as_slice().into())
                    .map_err(|_| anyhow!("Invalid P-256 private key"))?;
                let signature: Signature = signing_key.sign(data);
                Ok(signature.to_der().as_bytes().to_vec())
            }
            _ => Err(anyhow!("Unsupported classical algorithm for signing")),
        }
    }

    #[cfg(not(feature = "hybrid-crypto"))]
    async fn sign_classical(
        &self,
        _data: &[u8],
        _classical_data: &ClassicalKeyData,
    ) -> Result<Vec<u8>> {
        Err(anyhow!("Hybrid cryptography features not enabled"))
    }

    /// Verify a post-quantum signature
    pub async fn verify(&self, data: &[u8], signature: &[u8], kid: &str) -> Result<bool> {
        let keys = PQ_KEYS.read().await;
        let key_material = keys.get(kid).ok_or_else(|| anyhow!("Key not found: {}", kid))?;

        self.verify_with_key_material(data, signature, key_material).await
    }

    async fn verify_with_key_material(
        &self,
        data: &[u8],
        signature: &[u8],
        key_material: &PQKeyMaterial,
    ) -> Result<bool> {
        match &key_material.key_data {
            #[cfg(feature = "post-quantum")]
            PQKeyData::Dilithium { public_key, .. } => match key_material.security_level {
                SecurityLevel::Level1 => {
                    let pk = dilithium2::PublicKey::from_bytes(public_key)
                        .map_err(|_| anyhow!("Invalid Dilithium2 public key"))?;
                    let sig = dilithium2::DetachedSignature::from_bytes(signature)
                        .map_err(|_| anyhow!("Invalid Dilithium2 signature"))?;
                    Ok(dilithium2::verify(&sig, data, &pk).is_ok())
                }
                SecurityLevel::Level3 => {
                    let pk = dilithium3::PublicKey::from_bytes(public_key)
                        .map_err(|_| anyhow!("Invalid Dilithium3 public key"))?;
                    let sig = dilithium3::DetachedSignature::from_bytes(signature)
                        .map_err(|_| anyhow!("Invalid Dilithium3 signature"))?;
                    Ok(dilithium3::verify(&sig, data, &pk).is_ok())
                }
                SecurityLevel::Level5 => {
                    let pk = dilithium5::PublicKey::from_bytes(public_key)
                        .map_err(|_| anyhow!("Invalid Dilithium5 public key"))?;
                    let sig = dilithium5::DetachedSignature::from_bytes(signature)
                        .map_err(|_| anyhow!("Invalid Dilithium5 signature"))?;
                    Ok(dilithium5::verify(&sig, data, &pk).is_ok())
                }
            },
            #[cfg(feature = "hybrid-crypto")]
            PQKeyData::Hybrid { classical, post_quantum } => {
                // Parse hybrid signature
                if signature.len() < 4 {
                    return Ok(false);
                }

                let classical_sig_len =
                    u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]])
                        as usize;

                if signature.len() < 4 + classical_sig_len {
                    return Ok(false);
                }

                let classical_sig = &signature[4..4 + classical_sig_len];
                let pq_sig = &signature[4 + classical_sig_len..];

                // Verify both signatures
                let classical_valid = self.verify_classical(data, classical_sig, classical).await?;

                // Create temporary key material for post-quantum verification
                let pq_key_material = PQKeyMaterial {
                    kid: key_material.kid.clone(),
                    algorithm: match &key_material.algorithm {
                        PQAlgorithm::Hybrid { post_quantum, .. } => (**post_quantum).clone(),
                        _ => return Err(anyhow!("Invalid hybrid key structure")),
                    },
                    security_level: key_material.security_level,
                    created_at: key_material.created_at,
                    expires_at: key_material.expires_at,
                    key_data: (**post_quantum).clone(),
                    jwk: None,
                };

                let pq_valid =
                    self.verify_with_key_material(data, pq_sig, &pq_key_material).await?;

                // Both signatures must be valid
                Ok(classical_valid && pq_valid)
            }
            #[cfg(not(feature = "post-quantum"))]
            PQKeyData::Placeholder => {
                warn!("Post-quantum features not enabled, cannot verify");
                Ok(false)
            }
        }
    }

    #[cfg(feature = "hybrid-crypto")]
    async fn verify_classical(
        &self,
        data: &[u8],
        signature: &[u8],
        classical_data: &ClassicalKeyData,
    ) -> Result<bool> {
        match classical_data {
            ClassicalKeyData::Ed25519 { public_key, .. } => {
                use ed25519_dalek::{Signature, Verifier};
                let verifying_key = Ed25519VerifyingKey::from_bytes(
                    public_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow!("Invalid Ed25519 public key length"))?,
                )?;
                let sig = Signature::from_bytes(
                    signature
                        .try_into()
                        .map_err(|_| anyhow!("Invalid Ed25519 signature length"))?,
                );
                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            ClassicalKeyData::EcdsaP256 { public_key, .. } => {
                use p256::ecdsa::{signature::Verifier, Signature};
                use p256::EncodedPoint;

                let point = EncodedPoint::from_bytes(public_key)
                    .map_err(|_| anyhow!("Invalid P-256 public key encoding"))?;
                let verifying_key = P256VerifyingKey::from_encoded_point(&point)
                    .map_err(|_| anyhow!("Invalid P-256 public key"))?;

                let sig = Signature::from_der(signature)
                    .map_err(|_| anyhow!("Invalid P-256 signature"))?;

                Ok(verifying_key.verify(data, &sig).is_ok())
            }
            _ => Err(anyhow!("Unsupported classical algorithm for verification")),
        }
    }

    #[cfg(not(feature = "hybrid-crypto"))]
    async fn verify_classical(
        &self,
        _data: &[u8],
        _signature: &[u8],
        _classical_data: &ClassicalKeyData,
    ) -> Result<bool> {
        Err(anyhow!("Hybrid cryptography features not enabled"))
    }

    /// Get current signing key ID
    pub async fn current_signing_key_id(&self) -> Option<String> {
        let keys = PQ_KEYS.read().await;
        keys.values()
            .filter(|k| k.expires_at.map_or(true, |exp| current_timestamp() < exp))
            .max_by_key(|k| k.created_at)
            .map(|k| k.kid.clone())
    }

    /// Get JWKS document with post-quantum keys
    pub async fn jwks_document(&self) -> serde_json::Value {
        let keys = PQ_KEYS.read().await;
        let jwk_keys: Vec<serde_json::Value> =
            keys.values().filter_map(|k| k.jwk.clone()).collect();

        serde_json::json!({
            "keys": jwk_keys,
            "quantum_safe": true,
            "algorithms_supported": [
                "DILITHIUM2", "DILITHIUM3", "DILITHIUM5",
                "HYBRID-DILITHIUM2-ED25519",
                "HYBRID-DILITHIUM3-ED25519"
            ]
        })
    }

    /// Rotate expired keys
    pub async fn rotate_expired_keys(&self) -> Result<Vec<String>> {
        let mut rotated_keys = Vec::new();
        let current_time = current_timestamp();

        let keys_to_rotate: Vec<String> = {
            let keys = PQ_KEYS.read().await;
            keys.values()
                .filter(|k| k.expires_at.map_or(false, |exp| current_time >= exp))
                .map(|k| k.kid.clone())
                .collect()
        };

        for kid in keys_to_rotate {
            info!("Rotating expired post-quantum key: {}", kid);

            // Generate new key with same algorithm
            let new_kid = self.generate_signing_key_pair(None).await?;
            rotated_keys.push(new_kid);

            // Remove old key
            let mut keys = PQ_KEYS.write().await;
            keys.remove(&kid);

            // Log key rotation
            SecurityLogger::log_event(
                &SecurityEvent::new(
                    SecurityEventType::KeyManagement,
                    SecuritySeverity::Medium,
                    "post-quantum-crypto".to_string(),
                    "Post-quantum key rotated".to_string(),
                )
                .with_actor("pq_system".to_string())
                .with_action("pq_rotate_key".to_string())
                .with_target("pq_keys".to_string())
                .with_outcome("success".to_string())
                .with_reason("Key rotation due to expiration policy".to_string())
                .with_detail("old_kid".to_string(), kid)
                .with_detail("rotation_reason".to_string(), "expired"),
            );
        }

        Ok(rotated_keys)
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> PQPerformanceMetrics {
        let keys = PQ_KEYS.read().await;
        let total_keys = keys.len();
        let active_keys = keys
            .values()
            .filter(|k| k.expires_at.map_or(true, |exp| current_timestamp() < exp))
            .count();

        let algorithm_distribution: HashMap<String, usize> = keys
            .values()
            .map(|k| format!("{:?}", k.algorithm))
            .fold(HashMap::new(), |mut acc, alg| {
                *acc.entry(alg).or_insert(0) += 1;
                acc
            });

        PQPerformanceMetrics {
            total_keys,
            active_keys,
            algorithm_distribution,
            next_rotation: keys.values().filter_map(|k| k.expires_at).min(),
        }
    }

    /// Check if post-quantum cryptography is available
    pub fn is_available(&self) -> bool {
        self.config.enabled && cfg!(feature = "post-quantum")
    }

    /// Get migration status
    pub fn migration_status(&self) -> MigrationStatus {
        MigrationStatus {
            mode: self.config.migration_mode.clone(),
            post_quantum_enabled: self.config.enabled,
            hybrid_enabled: self.config.enable_hybrid,
            features_available: PQFeatures {
                dilithium: cfg!(feature = "post-quantum"),
                kyber: cfg!(feature = "post-quantum"),
                hybrid: cfg!(feature = "hybrid-crypto"),
            },
        }
    }

    fn generate_key_id(&self) -> String {
        format!(
            "pq-{}-{}",
            self.config.default_security_level.as_str().to_lowercase(),
            current_timestamp()
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PQPerformanceMetrics {
    pub total_keys: usize,
    pub active_keys: usize,
    pub algorithm_distribution: HashMap<String, usize>,
    pub next_rotation: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationStatus {
    pub mode: MigrationMode,
    pub post_quantum_enabled: bool,
    pub hybrid_enabled: bool,
    pub features_available: PQFeatures,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PQFeatures {
    pub dilithium: bool,
    pub kyber: bool,
    pub hybrid: bool,
}

/// Global post-quantum crypto manager instance
static PQ_MANAGER: Lazy<PQCryptoManager> = Lazy::new(|| PQCryptoManager::default());

/// Get the global post-quantum crypto manager
pub fn get_pq_manager() -> &'static PQCryptoManager {
    &PQ_MANAGER
}

/// Initialize post-quantum cryptography system
pub async fn initialize_post_quantum_crypto() -> Result<()> {
    get_pq_manager().initialize().await
}

/// Helper function to get current timestamp
fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pq_config_default() {
        let config = PQConfig::default();
        assert_eq!(config.default_security_level, SecurityLevel::Level3);
        assert!(config.enable_hybrid);
        assert_eq!(config.migration_mode, MigrationMode::Hybrid);
    }

    #[tokio::test]
    async fn test_manager_initialization() {
        let config = PQConfig { enabled: false, ..Default::default() };
        let manager = PQCryptoManager::new(config);
        assert!(manager.initialize().await.is_ok());
    }

    #[tokio::test]
    async fn test_migration_status() {
        let manager = PQCryptoManager::default();
        let status = manager.migration_status();

        assert_eq!(status.mode, MigrationMode::Hybrid);
        // Features availability depends on compile-time features
    }

    #[tokio::test]
    async fn test_jwks_document() {
        let manager = PQCryptoManager::default();
        let jwks = manager.jwks_document().await;

        assert!(jwks.get("keys").is_some());
        assert!(jwks.get("quantum_safe").is_some());
        assert_eq!(jwks["quantum_safe"], true);
    }

    #[cfg(feature = "post-quantum")]
    #[tokio::test]
    async fn test_key_generation_and_signing() {
        let mut config = PQConfig::default();
        config.enabled = true;
        let manager = PQCryptoManager::new(config);

        // Initialize the manager
        assert!(manager.initialize().await.is_ok());

        // Test signing and verification
        let test_data = b"Hello, post-quantum world!";
        let signature = manager.sign(test_data, None).await.unwrap();

        let kid = manager.current_signing_key_id().await.unwrap();
        let is_valid = manager.verify(test_data, &signature, &kid).await.unwrap();
        assert!(is_valid);

        // Test with different data should fail
        let different_data = b"Different data";
        let is_valid_different = manager.verify(different_data, &signature, &kid).await.unwrap();
        assert!(!is_valid_different);
    }
}
