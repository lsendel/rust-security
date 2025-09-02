use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::{
    error::Unspecified,
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: Option<String>,
    pub use_: Option<String>,
    pub key_ops: Option<Vec<String>>,
    pub alg: Option<String>,
    pub kid: String,
    pub x: Option<String>,
    // RSA fields (kept for backward compatibility)
    pub n: Option<String>,
    pub e: Option<String>,
}

pub struct SecureKeyManager {
    current_keypair: Arc<RwLock<Ed25519KeyPair>>,
    key_id: String,
    rng: SystemRandom,
}

impl SecureKeyManager {
    /// Create a new secure key manager with an Ed25519 key pair
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Ed25519 key pair generation fails due to insufficient entropy
    /// - PKCS#8 encoding of the generated key pair fails
    /// - Key pair construction from PKCS#8 data fails
    pub fn new() -> Result<Self, Unspecified> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let key_id = format!("key-{}", chrono::Utc::now().timestamp());

        Ok(Self {
            current_keypair: Arc::new(RwLock::new(keypair)),
            key_id,
            rng,
        })
    }

    /// Get the JSON Web Key Set containing the public key
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - Base64 encoding of the public key fails
    /// - JSON serialization of the JWKS structure fails
    /// - Lock acquisition for the key pair fails
    pub async fn get_jwks(&self) -> Result<JwkSet, Box<dyn std::error::Error + Send + Sync>> {
        let keypair = self.current_keypair.read().await;
        let public_key_bytes = keypair.public_key().as_ref();

        let jwk = Jwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            alg: Some("EdDSA".to_string()),
            kid: self.key_id.clone(),
            x: Some(STANDARD.encode(public_key_bytes)),
            n: None,
            e: None,
        };

        Ok(JwkSet { keys: vec![jwk] })
    }

    /// Sign a JWT payload using Ed25519
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - The signing operation fails
    /// - Lock acquisition for the key pair fails
    pub async fn sign_jwt(&self, payload: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let keypair = self.current_keypair.read().await;
        let signature = keypair.sign(payload);
        Ok(signature.as_ref().to_vec())
    }

    /// Rotate the current Ed25519 key pair
    /// 
    /// # Errors
    /// 
    /// Returns an error if:
    /// - New Ed25519 key pair generation fails
    /// - PKCS#8 encoding operations fail
    /// - Lock acquisition fails during key rotation
    pub async fn rotate_key(&self) -> Result<(), Unspecified> {
        // Generate new Ed25519 key pair
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&self.rng)?;
        let new_keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;

        let mut current = self.current_keypair.write().await;
        *current = new_keypair;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_generation() {
        let key_manager = SecureKeyManager::new().unwrap();
        let jwks = key_manager.get_jwks().await.unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "OKP");
        assert_eq!(jwks.keys[0].alg, Some("EdDSA".to_string()));
    }

    #[tokio::test]
    async fn test_jwt_signing() {
        let key_manager = SecureKeyManager::new().unwrap();
        let payload = b"test payload";

        let signature = key_manager.sign_jwt(payload).await.unwrap();
        assert!(!signature.is_empty());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let key_manager = SecureKeyManager::new().unwrap();

        // Get initial JWKS
        let jwks1 = key_manager.get_jwks().await.unwrap();

        // Rotate key
        key_manager.rotate_key().await.unwrap();

        // Get new JWKS
        let jwks2 = key_manager.get_jwks().await.unwrap();

        // Keys should be different (different modulus)
        assert_ne!(jwks1.keys[0].x, jwks2.keys[0].x);
    }
}
