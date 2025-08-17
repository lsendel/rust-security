use crate::mfa::crypto::{CryptoError, EncryptedSecret, SecretManager};
use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MfaStorageError {
    #[error("Redis error: {0}")]
    RedisError(#[from] RedisError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Secret not found for user: {0}")]
    SecretNotFound(String),
    #[error("Invalid backup code")]
    InvalidBackupCode,
    #[error("Storage unavailable")]
    StorageUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaUserRecord {
    pub user_id: String,
    pub encrypted_secret: EncryptedSecret,
    pub verified: bool,
    pub backup_codes_hashed: HashSet<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub totp_config: TotpConfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfiguration {
    pub algorithm: String, // "SHA1", "SHA256", "SHA512"
    pub digits: u32,       // 6-8
    pub period: u64,       // seconds
    pub skew_tolerance: i64, // number of periods
}

impl Default for TotpConfiguration {
    fn default() -> Self {
        Self {
            algorithm: "SHA256".to_string(),
            digits: 6,
            period: 30,
            skew_tolerance: 1,
        }
    }
}

pub struct MfaStorage {
    redis: Option<ConnectionManager>,
    secret_manager: SecretManager,
}

impl MfaStorage {
    pub async fn new(secret_manager: SecretManager) -> Self {
        let redis = Self::create_redis_connection().await;
        Self {
            redis,
            secret_manager,
        }
    }

    async fn create_redis_connection() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").ok()?;
        let client = redis::Client::open(url).ok()?;
        client.get_connection_manager().await.ok()
    }

    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    pub async fn store_user_record(&self, record: &MfaUserRecord) -> Result<(), MfaStorageError> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaStorageError::StorageUnavailable);
        };

        let key = format!("mfa:user:{}", record.user_id);
        let serialized = serde_json::to_string(record)?;
        
        conn.set(&key, serialized).await?;
        
        // Set TTL if configured
        if let Ok(ttl_str) = std::env::var("MFA_USER_RECORD_TTL_SECS") {
            if let Ok(ttl) = ttl_str.parse::<u64>() {
                conn.expire(&key, ttl).await?;
            }
        }

        tracing::debug!("Stored MFA record for user: {}", record.user_id);
        Ok(())
    }

    pub async fn get_user_record(&self, user_id: &str) -> Result<MfaUserRecord, MfaStorageError> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaStorageError::StorageUnavailable);
        };

        let key = format!("mfa:user:{}", user_id);
        let data: Option<String> = conn.get(&key).await?;
        
        match data {
            Some(serialized) => {
                let record: MfaUserRecord = serde_json::from_str(&serialized)?;
                Ok(record)
            }
            None => Err(MfaStorageError::UserNotFound(user_id.to_string())),
        }
    }

    pub async fn create_user_mfa(&self, user_id: &str, secret: &[u8], totp_config: Option<TotpConfiguration>) -> Result<MfaUserRecord, MfaStorageError> {
        let encrypted_secret = self.secret_manager.encrypt_secret(secret).await?;
        let now = Self::current_timestamp();
        
        let record = MfaUserRecord {
            user_id: user_id.to_string(),
            encrypted_secret,
            verified: false,
            backup_codes_hashed: HashSet::new(),
            created_at: now,
            updated_at: now,
            totp_config: totp_config.unwrap_or_default(),
        };

        self.store_user_record(&record).await?;
        Ok(record)
    }

    pub async fn get_decrypted_secret(&self, user_id: &str) -> Result<Vec<u8>, MfaStorageError> {
        let record = self.get_user_record(user_id).await?;
        let secret = self.secret_manager.decrypt_secret(&record.encrypted_secret).await?;
        Ok(secret)
    }

    pub async fn mark_user_verified(&self, user_id: &str) -> Result<(), MfaStorageError> {
        let mut record = self.get_user_record(user_id).await?;
        record.verified = true;
        record.updated_at = Self::current_timestamp();
        self.store_user_record(&record).await
    }

    pub async fn is_user_verified(&self, user_id: &str) -> Result<bool, MfaStorageError> {
        let record = self.get_user_record(user_id).await?;
        Ok(record.verified)
    }

    pub async fn update_backup_codes(&self, user_id: &str, hashed_codes: HashSet<String>) -> Result<(), MfaStorageError> {
        let mut record = self.get_user_record(user_id).await?;
        record.backup_codes_hashed = hashed_codes;
        record.updated_at = Self::current_timestamp();
        self.store_user_record(&record).await
    }

    pub async fn consume_backup_code(&self, user_id: &str, code_hash: &str) -> Result<bool, MfaStorageError> {
        let mut record = self.get_user_record(user_id).await?;
        
        if record.backup_codes_hashed.remove(code_hash) {
            record.updated_at = Self::current_timestamp();
            self.store_user_record(&record).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn get_backup_codes(&self, user_id: &str) -> Result<HashSet<String>, MfaStorageError> {
        let record = self.get_user_record(user_id).await?;
        Ok(record.backup_codes_hashed)
    }

    pub async fn update_totp_config(&self, user_id: &str, config: TotpConfiguration) -> Result<(), MfaStorageError> {
        let mut record = self.get_user_record(user_id).await?;
        record.totp_config = config;
        record.updated_at = Self::current_timestamp();
        self.store_user_record(&record).await
    }

    pub async fn get_totp_config(&self, user_id: &str) -> Result<TotpConfiguration, MfaStorageError> {
        let record = self.get_user_record(user_id).await?;
        Ok(record.totp_config)
    }

    pub async fn delete_user_mfa(&self, user_id: &str) -> Result<bool, MfaStorageError> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaStorageError::StorageUnavailable);
        };

        let key = format!("mfa:user:{}", user_id);
        let deleted: u64 = conn.del(&key).await?;
        
        // Also clean up related keys
        let patterns = vec![
            format!("mfa:totp:{}:*", user_id),
            format!("mfa:otp:{}", user_id),
            format!("mfa:last_verified:{}", user_id),
        ];

        for pattern in patterns {
            let keys: Vec<String> = conn.keys(&pattern).await?;
            if !keys.is_empty() {
                let _: u64 = conn.del(&keys).await?;
            }
        }

        tracing::info!("Deleted MFA data for user: {}", user_id);
        Ok(deleted > 0)
    }

    pub async fn rotate_user_secret(&self, user_id: &str, new_secret: &[u8]) -> Result<(), MfaStorageError> {
        let mut record = self.get_user_record(user_id).await?;
        
        // Encrypt new secret
        let new_encrypted_secret = self.secret_manager.encrypt_secret(new_secret).await?;
        
        // Update record
        record.encrypted_secret = new_encrypted_secret;
        record.verified = false; // Require re-verification after rotation
        record.updated_at = Self::current_timestamp();
        
        self.store_user_record(&record).await?;
        
        tracing::info!("Rotated secret for user: {}", user_id);
        Ok(())
    }

    pub async fn list_users_for_maintenance(&self, limit: usize) -> Result<Vec<String>, MfaStorageError> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaStorageError::StorageUnavailable);
        };

        let pattern = "mfa:user:*";
        let keys: Vec<String> = conn.keys(&pattern).await?;
        
        let user_ids: Vec<String> = keys
            .into_iter()
            .filter_map(|key| {
                key.strip_prefix("mfa:user:").map(|s| s.to_string())
            })
            .take(limit)
            .collect();

        Ok(user_ids)
    }

    pub async fn cleanup_expired_records(&self) -> Result<u64, MfaStorageError> {
        let Some(mut conn) = self.redis.clone() else {
            return Err(MfaStorageError::StorageUnavailable);
        };

        let pattern = "mfa:user:*";
        let keys: Vec<String> = conn.keys(&pattern).await?;
        let mut cleaned = 0;

        for key in keys {
            let ttl: i64 = conn.ttl(&key).await?;
            if ttl < 0 && ttl != -1 { // -1 means no expiry, -2 means expired
                let deleted: u64 = conn.del(&key).await?;
                cleaned += deleted;
            }
        }

        if cleaned > 0 {
            tracing::info!("Cleaned up {} expired MFA records", cleaned);
        }

        Ok(cleaned)
    }

    pub async fn get_user_statistics(&self, user_id: &str) -> Result<MfaUserStatistics, MfaStorageError> {
        let record = self.get_user_record(user_id).await?;
        
        Ok(MfaUserStatistics {
            user_id: user_id.to_string(),
            created_at: record.created_at,
            updated_at: record.updated_at,
            verified: record.verified,
            backup_codes_count: record.backup_codes_hashed.len(),
            secret_key_version: record.encrypted_secret.key_version,
            totp_algorithm: record.totp_config.algorithm,
            totp_digits: record.totp_config.digits,
            totp_period: record.totp_config.period,
        })
    }

    pub async fn health_check(&self) -> Result<MfaStorageHealth, MfaStorageError> {
        let redis_available = self.redis.is_some();
        
        if let Some(mut conn) = self.redis.clone() {
            // Test Redis connectivity
            let ping_result: Result<String, RedisError> = redis::cmd("PING").query_async(&mut conn).await;
            let redis_responsive = ping_result.is_ok();
            
            // Get basic statistics
            let user_pattern = "mfa:user:*";
            let user_keys: Vec<String> = conn.keys(&user_pattern).await.unwrap_or_default();
            let total_users = user_keys.len();
            
            Ok(MfaStorageHealth {
                redis_available,
                redis_responsive,
                total_users,
                secret_manager_available: true,
            })
        } else {
            Ok(MfaStorageHealth {
                redis_available: false,
                redis_responsive: false,
                total_users: 0,
                secret_manager_available: true,
            })
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaUserStatistics {
    pub user_id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub verified: bool,
    pub backup_codes_count: usize,
    pub secret_key_version: u32,
    pub totp_algorithm: String,
    pub totp_digits: u32,
    pub totp_period: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MfaStorageHealth {
    pub redis_available: bool,
    pub redis_responsive: bool,
    pub total_users: usize,
    pub secret_manager_available: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mfa::crypto::SecretManager;

    async fn create_test_storage() -> MfaStorage {
        let secret_manager = SecretManager::new().unwrap();
        MfaStorage::new(secret_manager).await
    }

    #[tokio::test]
    async fn test_user_record_storage() {
        let storage = create_test_storage().await;
        let user_id = "test_user";
        let secret = b"test_secret_data";

        // Create user MFA
        let record = storage.create_user_mfa(user_id, secret, None).await.unwrap();
        assert_eq!(record.user_id, user_id);
        assert!(!record.verified);

        // Retrieve and verify
        let retrieved = storage.get_user_record(user_id).await.unwrap();
        assert_eq!(retrieved.user_id, record.user_id);
        assert_eq!(retrieved.verified, record.verified);

        // Test secret decryption
        let decrypted = storage.get_decrypted_secret(user_id).await.unwrap();
        assert_eq!(decrypted, secret);
    }

    #[tokio::test]
    async fn test_backup_codes_management() {
        let storage = create_test_storage().await;
        let user_id = "test_user";
        let secret = b"test_secret";

        // Create user
        let _record = storage.create_user_mfa(user_id, secret, None).await.unwrap();

        // Add backup codes
        let mut codes = HashSet::new();
        codes.insert("hash1".to_string());
        codes.insert("hash2".to_string());
        
        storage.update_backup_codes(user_id, codes.clone()).await.unwrap();
        
        // Retrieve codes
        let retrieved_codes = storage.get_backup_codes(user_id).await.unwrap();
        assert_eq!(retrieved_codes, codes);

        // Consume a code
        let consumed = storage.consume_backup_code(user_id, "hash1").await.unwrap();
        assert!(consumed);

        // Verify code was removed
        let remaining_codes = storage.get_backup_codes(user_id).await.unwrap();
        assert_eq!(remaining_codes.len(), 1);
        assert!(remaining_codes.contains("hash2"));
        assert!(!remaining_codes.contains("hash1"));
    }

    #[tokio::test]
    async fn test_totp_config_management() {
        let storage = create_test_storage().await;
        let user_id = "test_user";
        let secret = b"test_secret";

        // Create user with custom config
        let custom_config = TotpConfiguration {
            algorithm: "SHA512".to_string(),
            digits: 8,
            period: 15,
            skew_tolerance: 0,
        };

        let _record = storage.create_user_mfa(user_id, secret, Some(custom_config.clone())).await.unwrap();

        // Retrieve config
        let retrieved_config = storage.get_totp_config(user_id).await.unwrap();
        assert_eq!(retrieved_config.algorithm, custom_config.algorithm);
        assert_eq!(retrieved_config.digits, custom_config.digits);
        assert_eq!(retrieved_config.period, custom_config.period);
    }

    #[tokio::test]
    async fn test_secret_rotation() {
        let storage = create_test_storage().await;
        let user_id = "test_user";
        let original_secret = b"original_secret";
        let new_secret = b"new_secret";

        // Create user
        let _record = storage.create_user_mfa(user_id, original_secret, None).await.unwrap();
        
        // Mark as verified
        storage.mark_user_verified(user_id).await.unwrap();
        assert!(storage.is_user_verified(user_id).await.unwrap());

        // Rotate secret
        storage.rotate_user_secret(user_id, new_secret).await.unwrap();

        // Should be unverified after rotation
        assert!(!storage.is_user_verified(user_id).await.unwrap());

        // Should be able to decrypt new secret
        let decrypted = storage.get_decrypted_secret(user_id).await.unwrap();
        assert_eq!(decrypted, new_secret);
    }
}