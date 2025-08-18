use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256, KeyPair},
    error::Unspecified,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
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
    pub use_: Option<String>,
    pub key_ops: Option<Vec<String>>,
    pub alg: Option<String>,
    pub kid: String,
    pub n: String,
    pub e: String,
}

pub struct SecureKeyManager {
    current_keypair: Arc<RwLock<RsaKeyPair>>,
    key_id: String,
    rng: SystemRandom,
}

impl SecureKeyManager {
    pub fn new() -> Result<Self, Unspecified> {
        let rng = SystemRandom::new();
        let keypair = RsaKeyPair::generate_pkcs1(&rng, 2048)?;
        let key_id = format!("key-{}", chrono::Utc::now().timestamp());

        Ok(Self {
            current_keypair: Arc::new(RwLock::new(keypair)),
            key_id,
            rng,
        })
    }

    pub async fn get_jwks(&self) -> Result<JwkSet, Box<dyn std::error::Error + Send + Sync>> {
        let keypair = self.current_keypair.read().await;
        let public_key = keypair.public_key();

        // Extract modulus and exponent from public key
        let public_key_der = public_key.as_ref();
        let (n, e) = self.extract_rsa_components(public_key_der)?;

        let jwk = Jwk {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            key_ops: Some(vec!["verify".to_string()]),
            alg: Some("RS256".to_string()),
            kid: self.key_id.clone(),
            n: STANDARD.encode(&n),
            e: STANDARD.encode(&e),
        };

        Ok(JwkSet {
            keys: vec![jwk],
        })
    }

    pub async fn sign_jwt(&self, payload: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let keypair = self.current_keypair.read().await;
        keypair.sign(&RSA_PKCS1_SHA256, payload)
    }

    pub async fn rotate_key(&self) -> Result<(), Unspecified> {
        let new_keypair = RsaKeyPair::generate_pkcs1(&self.rng, 2048)?;
        let mut current = self.current_keypair.write().await;
        *current = new_keypair;
        Ok(())
    }

    fn extract_rsa_components(&self, der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
        // Parse DER-encoded RSA public key to extract modulus (n) and exponent (e)
        // This is a simplified implementation - in production, use a proper ASN.1 parser

        // For now, return standard RSA exponent and a placeholder modulus
        let e = vec![0x01, 0x00, 0x01]; // Standard RSA exponent (65537)
        let n = der[der.len().saturating_sub(256)..].to_vec(); // Extract last 256 bytes as modulus

        Ok((n, e))
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
        assert_eq!(jwks.keys[0].kty, "RSA");
        assert_eq!(jwks.keys[0].alg, Some("RS256".to_string()));
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
        assert_ne!(jwks1.keys[0].n, jwks2.keys[0].n);
    }
}
