use crate::crypto_unified::{
    EncryptedData, SymmetricAlgorithm, UnifiedCryptoError, UnifiedCryptoManager,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Unified crypto error: {0}")]
    UnifiedCrypto(#[from] UnifiedCryptoError),
    #[error("Invalid key format")]
    InvalidKeyFormat,
}

// Re-export unified encrypted data with MFA-specific naming
pub type EncryptedSecret = EncryptedData;

/// MFA Secret Manager using unified crypto backend
pub struct SecretManager {
    crypto_manager: UnifiedCryptoManager,
}

impl SecretManager {
    /// Create new SecretManager with ChaCha20-Poly1305 (for MFA compatibility)
    pub fn new() -> Result<Self, CryptoError> {
        let crypto_manager = UnifiedCryptoManager::new_chacha()?;
        Ok(Self { crypto_manager })
    }

    /// Create SecretManager from environment variable
    pub fn from_env() -> Result<Self, CryptoError> {
        // Use the unified crypto manager's env loading with ChaCha20
        if std::env::var("MFA_ENCRYPTION_KEY").is_ok() {
            // Rename env var for unified manager
            if let Ok(key) = std::env::var("MFA_ENCRYPTION_KEY") {
                std::env::set_var("UNIFIED_ENCRYPTION_KEY", key);
            }
        }
        let crypto_manager = UnifiedCryptoManager::from_env(SymmetricAlgorithm::ChaCha20Poly1305)?;
        Ok(Self { crypto_manager })
    }

    /// Encrypt MFA secret data
    pub async fn encrypt_secret(&self, secret: &[u8]) -> Result<EncryptedSecret, CryptoError> {
        Ok(self.crypto_manager.encrypt(secret).await?)
    }

    /// Decrypt MFA secret data
    pub async fn decrypt_secret(
        &self,
        encrypted: &EncryptedSecret,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(self.crypto_manager.decrypt(encrypted).await?)
    }

    /// Get current encryption key version
    pub async fn current_key_version(&self) -> u32 {
        self.crypto_manager.current_key_version().await
    }

    /// Rotate the encryption key
    pub async fn rotate_key(&self) -> Result<(), CryptoError> {
        Ok(self.crypto_manager.rotate_key().await?)
    }

    /// Check if key should be rotated
    pub async fn should_rotate_key(&self) -> bool {
        self.crypto_manager.should_rotate_key().await
    }

    /// Clean up old encryption keys
    pub async fn cleanup_old_keys(&self, max_age: chrono::Duration) {
        self.crypto_manager.cleanup_old_keys(max_age).await;
    }
}

impl Default for SecretManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default SecretManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let manager = SecretManager::new().unwrap();
        let secret = b"test_secret_data_123";

        let encrypted = manager.encrypt_secret(secret).await.unwrap();
        let decrypted = manager.decrypt_secret(&encrypted).await.unwrap();

        assert_eq!(secret, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let manager = SecretManager::new().unwrap();
        let secret = b"test_secret";

        // Encrypt with initial key
        let encrypted_v1 = manager.encrypt_secret(secret).await.unwrap();
        assert_eq!(encrypted_v1.key_version, 1);

        // Rotate key
        manager.rotate_key().await.unwrap();

        // Encrypt with new key
        let encrypted_v2 = manager.encrypt_secret(secret).await.unwrap();
        assert_eq!(encrypted_v2.key_version, 2);

        // Should be able to decrypt both
        let decrypted_v1 = manager.decrypt_secret(&encrypted_v1).await.unwrap();
        let decrypted_v2 = manager.decrypt_secret(&encrypted_v2).await.unwrap();

        assert_eq!(secret, decrypted_v1.as_slice());
        assert_eq!(secret, decrypted_v2.as_slice());
    }

    #[tokio::test]
    async fn test_different_secrets_different_ciphertext() {
        let manager = SecretManager::new().unwrap();
        let secret1 = b"secret1";
        let secret2 = b"secret2";

        let encrypted1 = manager.encrypt_secret(secret1).await.unwrap();
        let encrypted2 = manager.encrypt_secret(secret2).await.unwrap();

        // Same secret encrypted twice should have different ciphertext (due to random nonce)
        let encrypted1_again = manager.encrypt_secret(secret1).await.unwrap();

        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.ciphertext, encrypted1_again.ciphertext);
        assert_ne!(encrypted1.nonce, encrypted1_again.nonce);
    }
}
