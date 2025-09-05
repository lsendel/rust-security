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
    /// Memory cost parameter (in `KiB`)
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

impl Default for PasswordService {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordService {
    /// Create a new password service with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PasswordHashConfig::default())
    }

    /// Create a new password service with custom configuration
    #[must_use]
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

        // Enhanced password strength validation
        if !self.is_password_strong_enough(password) {
            return Err(AppError::Validation(
                "Password does not meet strength requirements. Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character".to_string(),
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

        // Parse PHC format: $argon2id$v=19$m=65536,t=3,p=4$salt_b64$hash_b64
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() != 6 {
            return Err(AppError::Validation("Invalid hash format".to_string()));
        }

        // Extract parameters
        let param_str = parts[3];
        let salt_b64 = parts[4];
        let stored_hash_b64 = parts[5];

        // Parse parameters (m=memory,t=time,p=parallelism)
        let mut memory_cost = 0u32;
        let mut time_cost = 0u32;
        let mut parallelism = 0u32;

        for param in param_str.split(',') {
            if let Some(value) = param.strip_prefix("m=") {
                memory_cost = value.parse().map_err(|_| {
                    AppError::Validation("Invalid memory cost parameter".to_string())
                })?;
            } else if let Some(value) = param.strip_prefix("t=") {
                time_cost = value
                    .parse()
                    .map_err(|_| AppError::Validation("Invalid time cost parameter".to_string()))?;
            } else if let Some(value) = param.strip_prefix("p=") {
                parallelism = value.parse().map_err(|_| {
                    AppError::Validation("Invalid parallelism parameter".to_string())
                })?;
            }
        }

        // Decode salt and stored hash
        let salt = BASE64_STANDARD
            .decode(salt_b64)
            .map_err(|_| AppError::Validation("Invalid salt encoding".to_string()))?;

        let stored_hash = BASE64_STANDARD
            .decode(stored_hash_b64)
            .map_err(|_| AppError::Validation("Invalid hash encoding".to_string()))?;

        // Create Argon2 instance with the same parameters as the stored hash
        let params = Params::new(memory_cost, time_cost, parallelism, Some(stored_hash.len()))
            .map_err(|e| AppError::CryptographicError(format!("Invalid Argon2 parameters: {e}")))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Hash the provided password with the same salt
        let mut computed_hash = vec![0u8; stored_hash.len()];
        argon2
            .hash_password_into(password.as_bytes(), &salt, &mut computed_hash)
            .map_err(|e| {
                AppError::CryptographicError(format!("Password verification failed: {e}"))
            })?;

        // Use constant-time comparison to prevent timing attacks
        Ok(constant_time_compare_bytes(&computed_hash, &stored_hash))
    }

    /// Check if a password meets strength requirements
    fn is_password_strong_enough(&self, password: &str) -> bool {
        // Check for at least one uppercase letter
        let has_uppercase = password.chars().any(|c| c.is_uppercase());

        // Check for at least one lowercase letter
        let has_lowercase = password.chars().any(|c| c.is_lowercase());

        // Check for at least one digit
        let has_digit = password.chars().any(|c| c.is_ascii_digit());

        // Check for at least one special character
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        // All requirements must be met
        has_uppercase && has_lowercase && has_digit && has_special
    }

    /// Check if a password hash needs rehashing (e.g., due to parameter changes)
    #[must_use]
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
#[must_use]
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

/// Constant-time byte slice comparison for hash verification
#[must_use]
pub fn constant_time_compare_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let service = PasswordService::new();
        let password = "StrongP@ssw0rd123!";

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

        // Weak passwords should fail
        assert!(service.hash_password("valid_password_123").is_err());

        // Valid strong password should work
        assert!(service.hash_password("StrongP@ssw0rd123!").is_ok());
    }

    #[test]
    fn test_password_verification() {
        let service = PasswordService::new();
        let password = "StrongP@ssw0rd123!";
        let wrong_password = "Wr0ngP@ssw0rd!";

        // Hash the password
        let hash = service.hash_password(password).unwrap();

        // Verify correct password
        assert!(service.verify_password(password, &hash).unwrap());

        // Verify incorrect password
        assert!(!service.verify_password(wrong_password, &hash).unwrap());

        // Verify empty password
        assert!(!service.verify_password("", &hash).unwrap());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("test", "test"));
        assert!(!constant_time_compare("test", "different"));
        assert!(!constant_time_compare("test", "test_extra"));
        assert!(!constant_time_compare("test_extra", "test"));
    }

    #[test]
    fn test_constant_time_compare_bytes() {
        let a = b"test_bytes";
        let b = b"test_bytes";
        let c = b"different";

        assert!(constant_time_compare_bytes(a, b));
        assert!(!constant_time_compare_bytes(a, c));
        assert!(!constant_time_compare_bytes(a, b"test_bytes_extra"));
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
        let hash = service.hash_password("StrongP@ssw0rd123!").unwrap();

        // Verify the hash contains the custom parameters
        assert!(hash.as_str().contains("m=32768,t=2,p=2"));
    }

    #[test]
    fn test_needs_rehash() {
        let service = PasswordService::new();

        // Current format should not need rehash
        let current_hash =
            PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$testsalt$hash".to_string()).unwrap();
        assert!(!service.needs_rehash(&current_hash));

        // Different algorithm should need rehash
        let old_hash = PasswordHash::new("$2b$12$LQH7rPZCXqOQKj7JTzZPue".to_string()).unwrap();
        assert!(service.needs_rehash(&old_hash));

        // Different parameters should need rehash
        let different_params =
            PasswordHash::new("$argon2id$v=19$m=32768,t=2,p=2$testsalt$hash".to_string()).unwrap();
        assert!(service.needs_rehash(&different_params));
    }
}
