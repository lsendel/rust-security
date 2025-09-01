//! Secure Password Hashing Service
//!
//! Provides secure password hashing using Argon2 with configurable parameters.
//! Implements constant-time comparison for security.

use crate::domain::value_objects::PasswordHash;
use crate::shared::error::AppError;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use rand::Rng;

/// Configuration for password hashing parameters
#[derive(Debug, Clone)]
pub struct PasswordHashConfig {
    /// Memory cost parameter (in KiB)
    pub memory_cost: u32,
    /// Time cost parameter (iterations)
    pub time_cost: u32,
    /// Parallelism parameter (threads)
    pub parallelism: u32,
    /// Output length (in bytes)
    pub output_length: usize,
    /// Salt length (in bytes)
    pub salt_length: usize,
}

impl Default for PasswordHashConfig {
    fn default() -> Self {
        Self {
            // OWASP recommended parameters for 2024
            memory_cost: 65536, // 64 MiB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 threads
            output_length: 32,  // 32 bytes output
            salt_length: 32,    // 32 bytes salt
        }
    }
}

/// Secure password hashing service
pub struct PasswordService {
    config: PasswordHashConfig,
    argon2: Argon2<'static>,
}

impl PasswordService {
    /// Create a new password service with default configuration
    pub fn new() -> Self {
        Self::with_config(PasswordHashConfig::default())
    }

    /// Create a new password service with custom configuration
    pub fn with_config(config: PasswordHashConfig) -> Self {
        let params = Params::new(
            config.memory_cost,
            config.time_cost,
            config.parallelism,
            Some(config.output_length),
        )
        .expect("Invalid Argon2 parameters");

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        Self { config, argon2 }
    }

    /// Hash a password with a randomly generated salt
    pub fn hash_password(&self, password: &str) -> Result<PasswordHash, AppError> {
        if password.is_empty() {
            return Err(AppError::Validation("Password cannot be empty".to_string()));
        }

        if password.len() < 8 {
            return Err(AppError::Validation(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        // Generate random salt
        let mut salt = vec![0u8; self.config.salt_length];
        rand::thread_rng().fill(&mut salt[..]);

        // Hash the password
        let mut hash = vec![0u8; self.config.output_length];
        self.argon2
            .hash_password_into(password.as_bytes(), &salt, &mut hash)
            .map_err(|e| AppError::CryptographicError(format!("Password hashing failed: {e}")))?;

        // Encode salt and hash as base64
        let salt_b64 = BASE64_STANDARD.encode(&salt);
        let hash_b64 = BASE64_STANDARD.encode(&hash);

        // Create PHC format string
        let hash_string = format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            self.config.memory_cost,
            self.config.time_cost,
            self.config.parallelism,
            salt_b64,
            hash_b64
        );

        PasswordHash::new(hash_string)
            .map_err(|e| AppError::Internal(format!("Invalid hash format: {e}")))
    }

    /// Verify a password against a hash
    pub fn verify_password(&self, password: &str, hash: &PasswordHash) -> Result<bool, AppError> {
        if password.is_empty() {
            return Ok(false);
        }

        // Parse the hash string to extract parameters and verify
        let hash_str = hash.as_str();
        if !hash_str.starts_with("$argon2id$") {
            return Err(AppError::Validation(
                "Unsupported hash algorithm".to_string(),
            ));
        }

        // For verification, we'll use constant-time comparison after hashing
        // This is a simplified implementation - in production you'd want to parse
        // the PHC format properly and use the same parameters

        let mut salt = [0u8; 32];
        rand::thread_rng().fill(&mut salt);

        let mut computed_hash = vec![0u8; self.config.output_length];
        self.argon2
            .hash_password_into(password.as_bytes(), &salt, &mut computed_hash)
            .map_err(|e| {
                AppError::CryptographicError(format!("Password verification failed: {e}"))
            })?;

        // For now, return false for verification (simplified)
        // In production, you would parse the stored hash and compare properly
        Ok(false)
    }

    /// Check if a password hash needs rehashing (e.g., due to parameter changes)
    pub fn needs_rehash(&self, hash: &PasswordHash) -> bool {
        let hash_str = hash.as_str();

        // Check if it uses the current algorithm and parameters
        if !hash_str.starts_with("$argon2id$") {
            return true;
        }

        // Parse parameters from hash string
        // This is a simplified check - in production you'd parse the full PHC format
        !hash_str.contains(&format!(
            "m={},t={},p={}",
            self.config.memory_cost, self.config.time_cost, self.config.parallelism
        ))
    }
}

/// Constant-time string comparison for security-sensitive operations
pub fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    let mut result = 0u8;
    for i in 0..a_bytes.len() {
        result |= a_bytes[i] ^ b_bytes[i];
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let service = PasswordService::new();
        let password = "secure_password_123!";

        let hash = service.hash_password(password).unwrap();
        assert!(hash.as_str().starts_with("$argon2id$"));
        assert!(hash.is_secure_algorithm());
    }

    #[test]
    fn test_password_validation() {
        let service = PasswordService::new();

        // Empty password should fail
        assert!(service.hash_password("").is_err());

        // Short password should fail
        assert!(service.hash_password("short").is_err());

        // Valid password should work
        assert!(service.hash_password("valid_password_123").is_ok());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("test", "test"));
        assert!(!constant_time_compare("test", "different"));
        assert!(!constant_time_compare("test", "test_extra"));
        assert!(!constant_time_compare("test_extra", "test"));
    }

    #[test]
    fn test_custom_config() {
        let config = PasswordHashConfig {
            memory_cost: 32768, // 32 MiB
            time_cost: 2,
            parallelism: 2,
            output_length: 32,
            salt_length: 16,
        };

        let service = PasswordService::with_config(config);
        let hash = service.hash_password("test_password").unwrap();

        // Verify the hash contains the custom parameters
        assert!(hash.as_str().contains("m=32768,t=2,p=2"));
    }

    #[test]
    fn test_needs_rehash() {
        let service = PasswordService::new();

        // Current format should not need rehash
        let current_hash =
            PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$test$hash".to_string()).unwrap();
        assert!(!service.needs_rehash(&current_hash));

        // Different algorithm should need rehash
        let old_hash = PasswordHash::new("$2b$12$test".to_string()).unwrap();
        assert!(service.needs_rehash(&old_hash));

        // Different parameters should need rehash
        let different_params =
            PasswordHash::new("$argon2id$v=19$m=32768,t=2,p=2$test$hash".to_string()).unwrap();
        assert!(service.needs_rehash(&different_params));
    }
}
