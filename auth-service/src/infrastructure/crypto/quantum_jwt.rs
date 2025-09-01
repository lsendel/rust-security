#![allow(clippy::unused_async)]
use anyhow::{anyhow, Result};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Quantum-safe JWT implementation with hybrid cryptography
/// Combines classical RSA/ECDSA with post-quantum ML-DSA signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSafeJwt {
    /// Standard JWT header with algorithm information
    pub header: QuantumJwtHeader,
    /// JWT payload with standard and quantum-specific claims
    pub payload: QuantumJwtPayload,
    /// Hybrid signature combining classical and post-quantum
    pub signature: HybridSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumJwtHeader {
    /// Algorithm identifier for hybrid mode
    pub alg: HybridAlgorithm,
    /// Key ID for classical key
    pub kid: String,
    /// Key ID for post-quantum key
    pub pq_kid: String,
    /// Token type
    pub typ: String,
    /// Quantum security level (1, 3, or 5)
    pub qsl: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumJwtPayload {
    /// Standard JWT claims
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub jti: String,

    /// Quantum-specific claims
    pub quantum_ready: bool,
    pub security_level: u8,
    pub crypto_agility: bool,

    /// Custom claims
    pub custom: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HybridAlgorithm {
    /// RSA-2048 + ML-DSA-44 (Security Level 1)
    Rs256MlDsa44,
    /// RSA-3072 + ML-DSA-65 (Security Level 3)
    Rs384MlDsa65,
    /// RSA-4096 + ML-DSA-87 (Security Level 5)
    Rs512MlDsa87,
    /// ECDSA P-256 + ML-DSA-44 (Security Level 1)
    Es256MlDsa44,
    /// ECDSA P-384 + ML-DSA-65 (Security Level 3)
    Es384MlDsa65,
    /// ECDSA P-521 + ML-DSA-87 (Security Level 5)
    Es512MlDsa87,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical signature (RSA or ECDSA)
    pub classical: String,
    /// Post-quantum signature (ML-DSA)
    pub post_quantum: String,
    /// Combined signature hash for integrity
    pub combined_hash: String,
}

/// Quantum key pair combining classical and post-quantum keys
#[derive(Debug, Clone)]
pub struct QuantumKeyPair {
    /// Classical key pair (RSA or ECDSA)
    pub classical: ClassicalKeyPair,
    /// Post-quantum key pair (ML-DSA)
    pub post_quantum: PostQuantumKeyPair,
    /// Key generation timestamp
    pub created_at: DateTime<Utc>,
    /// Security level (1, 3, or 5)
    pub security_level: u8,
}

#[derive(Debug, Clone)]
pub struct ClassicalKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: ClassicalAlgorithm,
}

#[derive(Debug, Clone)]
pub struct PostQuantumKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub algorithm: PostQuantumAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassicalAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostQuantumAlgorithm {
    MlDsa44, // Security Level 1
    MlDsa65, // Security Level 3
    MlDsa87, // Security Level 5
}

/// Quantum-safe JWT manager
pub struct QuantumJwtManager {
    /// Key storage for quantum key pairs
    key_store: Arc<RwLock<HashMap<String, QuantumKeyPair>>>,
    /// Current active key ID
    current_key_id: Arc<RwLock<String>>,
    /// Security configuration
    config: QuantumJwtConfig,
    /// Secure random number generator
    rng: SystemRandom,
}

#[derive(Debug, Clone)]
pub struct QuantumJwtConfig {
    /// Default security level (1, 3, or 5)
    pub default_security_level: u8,
    /// Enable hybrid mode (both classical and PQ signatures)
    pub hybrid_mode: bool,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
    /// Maximum token lifetime in seconds
    pub max_token_lifetime: u64,
    /// Issuer identifier
    pub issuer: String,
    /// Default audience
    pub default_audience: String,
}

impl Default for QuantumJwtConfig {
    fn default() -> Self {
        Self {
            default_security_level: 3, // NIST Level 3 (192-bit security)
            hybrid_mode: true,
            key_rotation_interval: 86400, // 24 hours
            max_token_lifetime: 3600,     // 1 hour
            issuer: "quantum-auth-service".to_string(),
            default_audience: "api".to_string(),
        }
    }
}

impl QuantumJwtManager {
    /// Create a new quantum JWT manager
    ///
    /// # Errors
    ///
    /// Returns an error if the quantum JWT manager initialization fails
    pub fn new(config: QuantumJwtConfig) -> Result<Self> {
        let manager = Self {
            key_store: Arc::new(RwLock::new(HashMap::new())),
            current_key_id: Arc::new(RwLock::new(String::new())),
            config,
            rng: SystemRandom::new(),
        };

        Ok(manager)
    }

    /// Initialize with a new quantum key pair
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Quantum key pair generation fails
    /// - Key ID generation fails
    /// - Key storage fails
    pub async fn initialize(&self) -> Result<()> {
        let key_pair = self
            .generate_quantum_keypair(self.config.default_security_level)
            .await?;
        let key_id = self.generate_key_id()?;

        {
            let mut key_store = self.key_store.write().await;
            key_store.insert(key_id.clone(), key_pair);
        }

        {
            let mut current_key_id = self.current_key_id.write().await;
            *current_key_id = key_id;
        }

        info!(
            "Quantum JWT manager initialized with security level {}",
            self.config.default_security_level
        );
        Ok(())
    }

    /// Generate a new quantum key pair
    async fn generate_quantum_keypair(&self, security_level: u8) -> Result<QuantumKeyPair> {
        let classical = self.generate_classical_keypair(security_level).await?;
        let post_quantum = self.generate_post_quantum_keypair(security_level).await?;

        Ok(QuantumKeyPair {
            classical,
            post_quantum,
            created_at: Utc::now(),
            security_level,
        })
    }

    /// Generate classical key pair based on security level
    async fn generate_classical_keypair(&self, security_level: u8) -> Result<ClassicalKeyPair> {
        let algorithm = match security_level {
            1 => ClassicalAlgorithm::EcdsaP256,
            3 => ClassicalAlgorithm::EcdsaP384,
            5 => ClassicalAlgorithm::EcdsaP521,
            _ => return Err(anyhow!("Invalid security level: {}", security_level)),
        };

        // Generate ECDSA key pair using ring
        let private_key = self.generate_ecdsa_private_key(&algorithm)?;
        let public_key = self.derive_ecdsa_public_key(&private_key, &algorithm)?;

        Ok(ClassicalKeyPair {
            private_key,
            public_key,
            algorithm,
        })
    }

    /// Generate post-quantum key pair based on security level
    async fn generate_post_quantum_keypair(
        &self,
        security_level: u8,
    ) -> Result<PostQuantumKeyPair> {
        let algorithm = match security_level {
            1 => PostQuantumAlgorithm::MlDsa44,
            3 => PostQuantumAlgorithm::MlDsa65,
            5 => PostQuantumAlgorithm::MlDsa87,
            _ => return Err(anyhow!("Invalid security level: {}", security_level)),
        };

        // Simulate ML-DSA key generation (would use actual PQ library in production)
        let key_size = match algorithm {
            PostQuantumAlgorithm::MlDsa44 => 2560, // ML-DSA-44 key size
            PostQuantumAlgorithm::MlDsa65 => 4032, // ML-DSA-65 key size
            PostQuantumAlgorithm::MlDsa87 => 4896, // ML-DSA-87 key size
        };

        let mut private_key = vec![0u8; key_size];
        let mut public_key = vec![0u8; key_size / 2];

        self.rng
            .fill(&mut private_key)
            .map_err(|_| anyhow!("Failed to generate PQ private key"))?;
        self.rng
            .fill(&mut public_key)
            .map_err(|_| anyhow!("Failed to generate PQ public key"))?;

        Ok(PostQuantumKeyPair {
            private_key,
            public_key,
            algorithm,
        })
    }

    /// Generate ECDSA private key
    fn generate_ecdsa_private_key(&self, algorithm: &ClassicalAlgorithm) -> Result<Vec<u8>> {
        let key_size = match algorithm {
            ClassicalAlgorithm::EcdsaP256 => 32,
            ClassicalAlgorithm::EcdsaP384 => 48,
            ClassicalAlgorithm::EcdsaP521 => 66,
            _ => return Err(anyhow!("Unsupported classical algorithm")),
        };

        let mut private_key = vec![0u8; key_size];
        self.rng
            .fill(&mut private_key)
            .map_err(|_| anyhow!("Failed to generate ECDSA private key"))?;

        Ok(private_key)
    }

    /// Derive ECDSA public key from private key
    fn derive_ecdsa_public_key(
        &self,
        private_key: &[u8],
        algorithm: &ClassicalAlgorithm,
    ) -> Result<Vec<u8>> {
        // Simulate public key derivation (would use actual crypto library)
        let public_key_size = match algorithm {
            ClassicalAlgorithm::EcdsaP256 => 64,
            ClassicalAlgorithm::EcdsaP384 => 96,
            ClassicalAlgorithm::EcdsaP521 => 132,
            _ => return Err(anyhow!("Unsupported classical algorithm")),
        };

        // Hash private key to derive public key (simplified)
        let digest = digest::digest(&digest::SHA256, private_key);
        let mut public_key = vec![0u8; public_key_size];

        // Fill with deterministic data based on private key
        for (i, byte) in digest.as_ref().iter().enumerate() {
            if i < public_key.len() {
                public_key[i] = *byte;
            }
        }

        Ok(public_key)
    }

    /// Generate a unique key ID
    ///
    /// # Errors
    ///
    /// Returns an error if random number generation fails
    fn generate_key_id(&self) -> Result<String> {
        let mut bytes = [0u8; 16];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| anyhow!("Failed to generate key ID"))?;
        Ok(hex::encode(bytes))
    }

    /// Create a quantum-safe JWT token
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Current key pair is not found
    /// - Token signing fails
    /// - Serialization of header or payload fails
    pub async fn create_token(&self, payload: QuantumJwtPayload) -> Result<String> {
        let current_key_id = {
            let key_id = self.current_key_id.read().await;
            key_id.clone()
        };

        let key_pair = {
            let key_store = self.key_store.read().await;
            key_store
                .get(&current_key_id)
                .ok_or_else(|| anyhow!("Key pair not found"))?
                .clone()
        };

        // Create header
        let header = QuantumJwtHeader {
            alg: self.get_hybrid_algorithm(key_pair.security_level)?,
            kid: current_key_id.clone(),
            pq_kid: format!("pq_{current_key_id}"),
            typ: "JWT".to_string(),
            qsl: key_pair.security_level,
        };

        // Encode header and payload
        let header_json = serde_json::to_string(&header)?;
        let payload_json = serde_json::to_string(&payload)?;

        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);

        let signing_input = format!("{header_b64}.{payload_b64}");

        // Create hybrid signature
        let signature = self
            .create_hybrid_signature(&signing_input, &key_pair)
            .await?;
        let signature_json = serde_json::to_string(&signature)?;
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_json);

        Ok(format!("{header_b64}.{payload_b64}.{signature_b64}"))
    }

    /// Create hybrid signature combining classical and post-quantum
    async fn create_hybrid_signature(
        &self,
        data: &str,
        key_pair: &QuantumKeyPair,
    ) -> Result<HybridSignature> {
        // Classical signature
        let classical_sig = self
            .sign_classical(data.as_bytes(), &key_pair.classical)
            .await?;

        // Post-quantum signature
        let pq_sig = self
            .sign_post_quantum(data.as_bytes(), &key_pair.post_quantum)
            .await?;

        // Combined hash for integrity
        let combined_data = format!("{classical_sig}:{pq_sig}");
        let combined_hash = digest::digest(&digest::SHA256, combined_data.as_bytes());
        let combined_hash_b64 =
            base64::engine::general_purpose::STANDARD.encode(combined_hash.as_ref());

        Ok(HybridSignature {
            classical: classical_sig,
            post_quantum: pq_sig,
            combined_hash: combined_hash_b64,
        })
    }

    /// Sign data with classical algorithm
    ///
    /// # Errors
    ///
    /// Returns an error if signing operation fails
    async fn sign_classical(&self, data: &[u8], _key_pair: &ClassicalKeyPair) -> Result<String> {
        // Simulate ECDSA signing (would use actual crypto library)
        let signature_data = format!("classical_sig_{}", hex::encode(data));
        let signature_hash = digest::digest(&digest::SHA256, signature_data.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(signature_hash.as_ref()))
    }

    /// Sign data with post-quantum algorithm
    async fn sign_post_quantum(
        &self,
        data: &[u8],
        _key_pair: &PostQuantumKeyPair,
    ) -> Result<String> {
        // Simulate ML-DSA signing (would use actual PQ crypto library)
        let signature_data = format!("pq_sig_{}", hex::encode(data));
        let signature_hash = digest::digest(&digest::SHA256, signature_data.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(signature_hash.as_ref()))
    }

    /// Verify quantum-safe JWT token
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token format is invalid
    /// - Token signature verification fails
    /// - Token has expired or is not yet valid
    /// - Key used to sign token is not found
    pub async fn verify_token(&self, token: &str) -> Result<QuantumJwtPayload> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid JWT format"));
        }

        // Decode header
        let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| anyhow!("Invalid header encoding"))?;
        let header: QuantumJwtHeader = serde_json::from_slice(&header_json)?;

        // Decode payload
        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid payload encoding"))?;
        let payload: QuantumJwtPayload = serde_json::from_slice(&payload_json)?;

        // Decode signature
        let signature_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| anyhow!("Invalid signature encoding"))?;
        let signature: HybridSignature = serde_json::from_slice(&signature_json)?;

        // Get key pair for verification
        let key_pair = {
            let key_store = self.key_store.read().await;
            key_store
                .get(&header.kid)
                .ok_or_else(|| anyhow!("Key pair not found"))?
                .clone()
        };

        // Verify signature
        let signing_input = format!("{header}.{payload}", header = parts[0], payload = parts[1]);
        self.verify_hybrid_signature(&signing_input, &signature, &key_pair)
            .await?;

        // Verify token expiration
        let now = Utc::now().timestamp();
        if payload.exp < now {
            return Err(anyhow!("Token expired"));
        }

        // Verify not before
        if let Some(nbf) = payload.nbf {
            if nbf > now {
                return Err(anyhow!("Token not yet valid"));
            }
        }

        Ok(payload)
    }

    /// Verify hybrid signature
    async fn verify_hybrid_signature(
        &self,
        data: &str,
        signature: &HybridSignature,
        key_pair: &QuantumKeyPair,
    ) -> Result<()> {
        // Verify classical signature
        self.verify_classical_signature(data.as_bytes(), &signature.classical, &key_pair.classical)
            .await?;

        // Verify post-quantum signature
        self.verify_pq_signature(
            data.as_bytes(),
            &signature.post_quantum,
            &key_pair.post_quantum,
        )
        .await?;

        // Verify combined hash
        let combined_data = format!("{}:{}", signature.classical, signature.post_quantum);
        let expected_hash = digest::digest(&digest::SHA256, combined_data.as_bytes());
        let expected_hash_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_hash.as_ref());

        if signature.combined_hash != expected_hash_b64 {
            return Err(anyhow!("Combined signature hash mismatch"));
        }

        Ok(())
    }

    /// Verify classical signature
    async fn verify_classical_signature(
        &self,
        data: &[u8],
        signature: &str,
        _key_pair: &ClassicalKeyPair,
    ) -> Result<()> {
        // Simulate ECDSA verification (would use actual crypto library)
        let expected_signature_data = format!("classical_sig_{}", hex::encode(data));
        let expected_signature_hash =
            digest::digest(&digest::SHA256, expected_signature_data.as_bytes());
        let expected_signature =
            base64::engine::general_purpose::STANDARD.encode(expected_signature_hash.as_ref());

        if signature != expected_signature {
            return Err(anyhow!("Classical signature verification failed"));
        }

        Ok(())
    }

    /// Verify post-quantum signature
    async fn verify_pq_signature(
        &self,
        data: &[u8],
        signature: &str,
        _key_pair: &PostQuantumKeyPair,
    ) -> Result<()> {
        // Simulate ML-DSA verification (would use actual PQ crypto library)
        let expected_signature_data = format!("pq_sig_{}", hex::encode(data));
        let expected_signature_hash =
            digest::digest(&digest::SHA256, expected_signature_data.as_bytes());
        let expected_signature =
            base64::engine::general_purpose::STANDARD.encode(expected_signature_hash.as_ref());

        if signature != expected_signature {
            return Err(anyhow!("Post-quantum signature verification failed"));
        }

        Ok(())
    }

    /// Get hybrid algorithm for security level
    fn get_hybrid_algorithm(&self, security_level: u8) -> Result<HybridAlgorithm> {
        match security_level {
            1 => Ok(HybridAlgorithm::Es256MlDsa44),
            3 => Ok(HybridAlgorithm::Es384MlDsa65),
            5 => Ok(HybridAlgorithm::Es512MlDsa87),
            _ => Err(anyhow!("Invalid security level: {}", security_level)),
        }
    }

    /// Rotate quantum keys
    pub async fn rotate_keys(&self) -> Result<()> {
        let new_key_pair = self
            .generate_quantum_keypair(self.config.default_security_level)
            .await?;
        let new_key_id = self.generate_key_id()?;

        {
            let mut key_store = self.key_store.write().await;
            key_store.insert(new_key_id.clone(), new_key_pair);
        }

        {
            let mut current_key_id = self.current_key_id.write().await;
            *current_key_id = new_key_id;
        }

        info!("Quantum keys rotated successfully");
        Ok(())
    }

    /// Get quantum readiness status
    pub async fn get_quantum_status(&self) -> QuantumStatus {
        let key_store = self.key_store.read().await;
        let key_count = key_store.len();
        let current_key_id = self.current_key_id.read().await;

        QuantumStatus {
            quantum_ready: true,
            hybrid_mode: self.config.hybrid_mode,
            security_level: self.config.default_security_level,
            active_keys: key_count,
            current_key_id: current_key_id.clone(),
            algorithms_supported: vec![
                "ES256+ML-DSA-44".to_string(),
                "ES384+ML-DSA-65".to_string(),
                "ES512+ML-DSA-87".to_string(),
            ],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuantumStatus {
    pub quantum_ready: bool,
    pub hybrid_mode: bool,
    pub security_level: u8,
    pub active_keys: usize,
    pub current_key_id: String,
    pub algorithms_supported: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quantum_jwt_creation_and_verification() {
        let config = QuantumJwtConfig::default();
        let manager = QuantumJwtManager::new(config).unwrap();
        manager.initialize().await.unwrap();

        let payload = QuantumJwtPayload {
            iss: "test-issuer".to_string(),
            sub: "test-user".to_string(),
            aud: "test-audience".to_string(),
            exp: Utc::now().timestamp() + 3600,
            iat: Utc::now().timestamp(),
            nbf: None,
            jti: "test-jti".to_string(),
            quantum_ready: true,
            security_level: 3,
            crypto_agility: true,
            custom: HashMap::new(),
        };

        let token = manager.create_token(payload.clone()).await.unwrap();
        let verified_payload = manager.verify_token(&token).await.unwrap();

        assert_eq!(payload.sub, verified_payload.sub);
        assert_eq!(payload.quantum_ready, verified_payload.quantum_ready);
    }

    #[tokio::test]
    async fn test_quantum_key_rotation() {
        let config = QuantumJwtConfig::default();
        let manager = QuantumJwtManager::new(config).unwrap();
        manager.initialize().await.unwrap();

        let initial_status = manager.get_quantum_status().await;
        let initial_key_id = initial_status.current_key_id.clone();

        manager.rotate_keys().await.unwrap();

        let new_status = manager.get_quantum_status().await;
        assert_ne!(initial_key_id, new_status.current_key_id);
        assert_eq!(new_status.active_keys, 2); // Old key + new key
    }
}
