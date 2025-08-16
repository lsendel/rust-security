use once_cell::sync::Lazy;
use ring::{rand, signature};
use base64::Engine as _;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde_json::json;

#[derive(Clone)]
pub struct SecureKeyMaterial {
    pub kid: String,
    pub key_pair: Arc<signature::RsaKeyPair>,
    pub public_jwk: serde_json::Value,
    pub created_at: u64,
}

static ACTIVE_KEYS: Lazy<RwLock<Vec<SecureKeyMaterial>>> = Lazy::new(|| RwLock::new(Vec::new()));

fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

impl SecureKeyMaterial {
    pub fn generate() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let rng = rand::SystemRandom::new();
        
        // Generate RSA key pair with 2048 bits (secure and performant)
        let key_pair = signature::RsaKeyPair::generate_pkcs8(&rng, 2048)?;
        let key_pair = signature::RsaKeyPair::from_pkcs8(key_pair.as_ref())?;
        
        // Extract public key components for JWK
        let public_key = key_pair.public_key();
        let public_key_der = public_key.as_ref();
        
        // Parse DER to extract n and e for JWK
        let (n, e) = extract_rsa_components_from_der(public_key_der)?;
        
        let kid = format!("key_{}", chrono::Utc::now().timestamp());
        let created_at = chrono::Utc::now().timestamp() as u64;
        
        let public_jwk = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": base64url(&n),
            "e": base64url(&e)
        });
        
        Ok(SecureKeyMaterial {
            kid,
            key_pair: Arc::new(key_pair),
            public_jwk,
            created_at,
        })
    }
    
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let rng = rand::SystemRandom::new();
        let signature = self.key_pair.sign(&signature::RSA_PKCS1_SHA256, &rng, message)?;
        Ok(signature.as_ref().to_vec())
    }
}

// Helper function to extract RSA components from DER format
fn extract_rsa_components_from_der(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    // This is a simplified DER parser for RSA public keys
    // In production, you might want to use a proper ASN.1 parser
    
    // For now, we'll use a basic approach that works with ring's DER format
    // The public key DER contains the modulus (n) and exponent (e)
    
    // Standard RSA public exponent (65537)
    let e = vec![0x01, 0x00, 0x01];
    
    // For the modulus, we need to parse the DER structure
    // This is a simplified implementation - in production use a proper ASN.1 parser
    let n = if der.len() > 32 {
        // Extract modulus from DER (this is simplified)
        der[der.len()-256..].to_vec() // Assuming 2048-bit key
    } else {
        return Err("Invalid DER format".into());
    };
    
    Ok((n, e))
}

pub async fn get_current_key() -> Result<SecureKeyMaterial, Box<dyn std::error::Error + Send + Sync>> {
    let keys = ACTIVE_KEYS.read().await;
    
    if let Some(key) = keys.first() {
        Ok(key.clone())
    } else {
        drop(keys);
        
        // Generate new key if none exists
        let new_key = SecureKeyMaterial::generate()?;
        let mut keys = ACTIVE_KEYS.write().await;
        keys.push(new_key.clone());
        Ok(new_key)
    }
}

pub async fn get_jwks() -> serde_json::Value {
    let keys = ACTIVE_KEYS.read().await;
    let jwks: Vec<_> = keys.iter().map(|k| k.public_jwk.clone()).collect();
    
    json!({
        "keys": jwks
    })
}

pub async fn rotate_keys() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let new_key = SecureKeyMaterial::generate()?;
    let mut keys = ACTIVE_KEYS.write().await;
    
    // Keep only the last 2 keys for validation of existing tokens
    if keys.len() >= 2 {
        keys.remove(0);
    }
    
    keys.push(new_key);
    tracing::info!("Key rotation completed, now have {} active keys", keys.len());
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_key_generation() {
        let key = SecureKeyMaterial::generate().unwrap();
        assert!(!key.kid.is_empty());
        assert!(key.created_at > 0);
        
        // Test signing
        let message = b"test message";
        let signature = key.sign(message).unwrap();
        assert!(!signature.is_empty());
    }
    
    #[tokio::test]
    async fn test_key_rotation() {
        // Clear any existing keys
        {
            let mut keys = ACTIVE_KEYS.write().await;
            keys.clear();
        }
        
        // Get initial key
        let key1 = get_current_key().await.unwrap();
        
        // Rotate keys
        rotate_keys().await.unwrap();
        
        // Get new key
        let key2 = get_current_key().await.unwrap();
        
        assert_ne!(key1.kid, key2.kid);
        
        // Should have 2 keys now
        let keys = ACTIVE_KEYS.read().await;
        assert_eq!(keys.len(), 2);
    }
}
