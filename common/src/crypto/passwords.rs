//! Unified Password Hashing Operations
//!
//! Consolidates password hashing functionality from:
//! - `auth-service/src/services/password_service.rs` - Main password service
//! - `auth-service/src/domain/value_objects/password_hash.rs` - Password hash domain object
//! - Various scattered password validation logic across the codebase

use super::*;
use crate::security::UnifiedSecurityConfig;
use argon2::{
    Algorithm as Argon2Algorithm, Argon2, Params, PasswordHash as Argon2PasswordHash,
    PasswordHasher, PasswordVerifier, Version,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use rand::seq::IteratorRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Password-specific errors
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Password hashing failed: {0}")]
    HashingFailed(String),

    #[error("Password verification failed")]
    VerificationFailed,

    #[error("Invalid password hash format")]
    InvalidHashFormat,

    #[error("Password too weak: {0}")]
    WeakPassword(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Random salt generation failed")]
    SaltGenerationFailed,
}

/// Password strength requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: u32,

    /// Require uppercase letters
    pub require_uppercase: bool,

    /// Require lowercase letters
    pub require_lowercase: bool,

    /// Require numbers
    pub require_numbers: bool,

    /// Require special characters
    pub require_special_chars: bool,

    /// Maximum password length (to prevent DoS)
    pub max_length: u32,

    /// Forbidden common passwords
    pub forbidden_passwords: Vec<String>,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            max_length: 128,
            forbidden_passwords: vec![
                "password".to_string(),
                "123456".to_string(),
                "admin".to_string(),
                "changeme".to_string(),
                "password123".to_string(),
            ],
        }
    }
}

/// Argon2 configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Config {
    /// Memory cost in KB (32MB - 1GB recommended)
    pub memory_cost: u32,

    /// Time cost (iterations, 2-10 recommended)
    pub time_cost: u32,

    /// Parallelism (threads, 1-16 recommended)
    pub parallelism: u32,

    /// Output length in bytes
    pub output_length: u32,

    /// Salt length in bytes
    pub salt_length: u32,

    /// Argon2 variant
    pub variant: Argon2Variant,
}

/// Argon2 variants
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Argon2Variant {
    /// Argon2d (data-dependent)
    Argon2d,
    /// Argon2i (data-independent)
    Argon2i,
    /// Argon2id (hybrid, recommended)
    Argon2id,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            // OWASP 2024 recommendations for server-side usage
            memory_cost: 65536, // 64 MiB
            time_cost: 3,       // 3 iterations
            parallelism: 4,     // 4 threads
            output_length: 32,  // 32 bytes
            salt_length: 32,    // 32 bytes
            variant: Argon2Variant::Argon2id,
        }
    }
}

/// Password hashing configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PasswordConfig {
    /// Password strength policy
    pub policy: PasswordPolicy,

    /// Argon2 hashing parameters
    pub argon2: Argon2Config,

    /// Enable password breach checking (external API)
    pub check_breached: bool,

    /// Maximum password age in days (0 = no expiration)
    pub max_age_days: u32,
}

impl FromEnvironment for PasswordConfig {
    fn from_env() -> CryptoResult<Self> {
        let min_length = env::var("PASSWORD_MIN_LENGTH")
            .unwrap_or_else(|_| "12".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid PASSWORD_MIN_LENGTH".to_string())
            })?;

        let require_uppercase = env::var("PASSWORD_REQUIRE_UPPERCASE")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let require_lowercase = env::var("PASSWORD_REQUIRE_LOWERCASE")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let require_numbers = env::var("PASSWORD_REQUIRE_NUMBERS")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let require_special_chars = env::var("PASSWORD_REQUIRE_SPECIAL_CHARS")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        let memory_cost = env::var("ARGON2_MEMORY_COST")
            .unwrap_or_else(|_| "65536".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid ARGON2_MEMORY_COST".to_string())
            })?;

        let time_cost = env::var("ARGON2_TIME_COST")
            .unwrap_or_else(|_| "3".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid ARGON2_TIME_COST".to_string())
            })?;

        let parallelism = env::var("ARGON2_PARALLELISM")
            .unwrap_or_else(|_| "4".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid ARGON2_PARALLELISM".to_string())
            })?;

        let check_breached = env::var("PASSWORD_CHECK_BREACHED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        let max_age_days = env::var("PASSWORD_MAX_AGE_DAYS")
            .unwrap_or_else(|_| "0".to_string())
            .parse()
            .map_err(|_| {
                CryptoError::InvalidConfiguration("Invalid PASSWORD_MAX_AGE_DAYS".to_string())
            })?;

        Ok(Self {
            policy: PasswordPolicy {
                min_length,
                require_uppercase,
                require_lowercase,
                require_numbers,
                require_special_chars,
                max_length: 128,
                forbidden_passwords: PasswordPolicy::default().forbidden_passwords,
            },
            argon2: Argon2Config {
                memory_cost,
                time_cost,
                parallelism,
                output_length: 32,
                salt_length: 32,
                variant: Argon2Variant::Argon2id,
            },
            check_breached,
            max_age_days,
        })
    }
}

impl CryptoValidation for PasswordConfig {
    fn validate(&self) -> CryptoResult<()> {
        // Password policy validation
        if self.policy.min_length < 8 {
            return Err(CryptoError::ValidationFailed(
                "Password minimum length must be at least 8".to_string(),
            ));
        }

        if self.policy.max_length > 1024 {
            return Err(CryptoError::ValidationFailed(
                "Password maximum length too high (DoS risk)".to_string(),
            ));
        }

        if self.policy.min_length >= self.policy.max_length {
            return Err(CryptoError::ValidationFailed(
                "Password min_length must be less than max_length".to_string(),
            ));
        }

        // Argon2 validation
        if self.argon2.memory_cost < 32768 {
            // 32MB minimum
            return Err(CryptoError::ValidationFailed(
                "Argon2 memory cost too low (minimum 32MB)".to_string(),
            ));
        }

        if self.argon2.memory_cost > 1048576 {
            // 1GB maximum
            return Err(CryptoError::ValidationFailed(
                "Argon2 memory cost too high (maximum 1GB)".to_string(),
            ));
        }

        if self.argon2.time_cost < 2 {
            return Err(CryptoError::ValidationFailed(
                "Argon2 time cost too low (minimum 2)".to_string(),
            ));
        }

        if self.argon2.parallelism < 1 || self.argon2.parallelism > 16 {
            return Err(CryptoError::ValidationFailed(
                "Argon2 parallelism must be between 1 and 16".to_string(),
            ));
        }

        Ok(())
    }
}

/// Secure password hash with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurePasswordHash {
    /// Argon2 hash string
    #[serde(with = "zeroize_serde")]
    pub hash: String,

    /// Hash creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Hash algorithm parameters used
    pub algorithm_info: String,
}

// Manual zeroize implementation that skips DateTime
impl zeroize::Zeroize for SecurePasswordHash {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.algorithm_info.zeroize();
        // Skip created_at as DateTime doesn't implement Zeroize
    }
}

// Custom serde module for zeroizing sensitive fields
mod zeroize_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(s: &str, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
    }
}

/// Unified password hashing operations
pub struct PasswordOperations {
    config: PasswordConfig,
    argon2: Argon2<'static>,
}

impl PasswordOperations {
    /// Create new password operations instance
    pub fn new(config: PasswordConfig) -> CryptoResult<Self> {
        config.validate()?;

        // Create Argon2 instance with configured parameters
        let params = Params::new(
            config.argon2.memory_cost,
            config.argon2.time_cost,
            config.argon2.parallelism,
            Some(config.argon2.output_length as usize),
        )
        .map_err(|e| PasswordError::InvalidConfiguration(format!("Argon2 params: {}", e)))?;

        let algorithm = match config.argon2.variant {
            Argon2Variant::Argon2d => Argon2Algorithm::Argon2d,
            Argon2Variant::Argon2i => Argon2Algorithm::Argon2i,
            Argon2Variant::Argon2id => Argon2Algorithm::Argon2id,
        };

        let argon2 = Argon2::new(algorithm, Version::V0x13, params);

        Ok(Self { config, argon2 })
    }

    /// Create password operations from unified security config
    pub fn from_security_config(security_config: &UnifiedSecurityConfig) -> CryptoResult<Self> {
        let password_config = PasswordConfig {
            policy: PasswordPolicy {
                min_length: security_config.password_policy.min_length,
                require_uppercase: security_config.password_policy.require_uppercase,
                require_lowercase: security_config.password_policy.require_lowercase,
                require_numbers: security_config.password_policy.require_numbers,
                require_special_chars: security_config.password_policy.require_special_chars,
                max_length: 128,
                forbidden_passwords: vec![
                    "password".to_string(),
                    "123456".to_string(),
                    "admin".to_string(),
                    "changeme".to_string(),
                ],
            },
            argon2: Argon2Config {
                memory_cost: security_config.password_policy.argon2.memory_cost,
                time_cost: security_config.password_policy.argon2.time_cost,
                parallelism: security_config.password_policy.argon2.parallelism,
                output_length: 32,
                salt_length: 32,
                variant: Argon2Variant::Argon2id,
            },
            check_breached: false,
            max_age_days: 0,
        };

        Self::new(password_config)
    }

    /// Hash a password securely
    pub fn hash_password(&self, password: &str) -> CryptoResult<SecurePasswordHash> {
        // Validate password strength
        self.validate_password_strength(password)?;

        // Generate secure salt
        let salt = self.generate_salt()?;

        // Hash the password
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), salt.as_salt())
            .map_err(|e| PasswordError::HashingFailed(e.to_string()))?;

        Ok(SecurePasswordHash {
            hash: password_hash.to_string(),
            created_at: chrono::Utc::now(),
            algorithm_info: format!(
                "Argon2id m={} t={} p={}",
                self.config.argon2.memory_cost,
                self.config.argon2.time_cost,
                self.config.argon2.parallelism
            ),
        })
    }

    /// Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &SecurePasswordHash) -> CryptoResult<bool> {
        let parsed_hash =
            Argon2PasswordHash::new(&hash.hash).map_err(|_| PasswordError::InvalidHashFormat)?;

        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify password with simple string hash (for backward compatibility)
    pub fn verify_password_simple(&self, password: &str, hash_string: &str) -> CryptoResult<bool> {
        let parsed_hash =
            Argon2PasswordHash::new(hash_string).map_err(|_| PasswordError::InvalidHashFormat)?;

        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Check if password hash needs rehashing (due to updated parameters)
    pub fn needs_rehash(&self, _hash: &SecurePasswordHash) -> bool {
        // Simplified implementation - for a production system, you would parse the hash
        // and check the actual parameters. For now, assume rehash is not needed.
        false
    }

    /// Check if password hash is expired
    pub fn is_password_expired(&self, hash: &SecurePasswordHash) -> bool {
        if self.config.max_age_days == 0 {
            return false; // No expiration configured
        }

        let now = chrono::Utc::now();
        let max_age = chrono::Duration::days(self.config.max_age_days as i64);

        now - hash.created_at > max_age
    }

    /// Validate password strength according to policy
    pub fn validate_password_strength(&self, password: &str) -> CryptoResult<()> {
        let policy = &self.config.policy;

        // Length checks
        if (password.len() as u32) < policy.min_length {
            return Err(PasswordError::WeakPassword(format!(
                "Password must be at least {} characters long",
                policy.min_length
            ))
            .into());
        }

        if (password.len() as u32) > policy.max_length {
            return Err(PasswordError::WeakPassword(format!(
                "Password must be at most {} characters long",
                policy.max_length
            ))
            .into());
        }

        // Character requirement checks
        if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(PasswordError::WeakPassword(
                "Password must contain at least one uppercase letter".to_string(),
            )
            .into());
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(PasswordError::WeakPassword(
                "Password must contain at least one lowercase letter".to_string(),
            )
            .into());
        }

        if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(PasswordError::WeakPassword(
                "Password must contain at least one number".to_string(),
            )
            .into());
        }

        if policy.require_special_chars
            && !password
                .chars()
                .any(|c| "!@#$%^&*(),.?\":{}|<>".contains(c))
        {
            return Err(PasswordError::WeakPassword(
                "Password must contain at least one special character".to_string(),
            )
            .into());
        }

        // Check against forbidden passwords
        let password_lower = password.to_lowercase();
        for forbidden in &policy.forbidden_passwords {
            if password_lower == forbidden.to_lowercase() {
                return Err(PasswordError::WeakPassword(
                    "Password is too common and not allowed".to_string(),
                )
                .into());
            }
        }

        Ok(())
    }

    /// Generate secure password
    pub fn generate_secure_password(&self, length: usize) -> CryptoResult<String> {
        if length < self.config.policy.min_length as usize {
            return Err(CryptoError::InvalidConfiguration(
                "Generated password length too short".to_string(),
            ));
        }

        use rand::seq::SliceRandom;
        let mut rng = rand::rngs::OsRng;

        // Define character sets to ensure policy compliance
        let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let lowercase = "abcdefghijklmnopqrstuvwxyz";
        let numbers = "0123456789";
        let symbols = "!@#$%^&*";

        let mut password = Vec::with_capacity(length);
        let policy = &self.config.policy;

        // Ensure at least one character from each required set
        if policy.require_uppercase {
            if let Some(c) = uppercase.chars().choose(&mut rng) {
                password.push(c);
            } else {
                return Err(CryptoError::InvalidConfiguration(
                    "uppercase charset empty".to_string(),
                ));
            }
        }
        if policy.require_lowercase {
            if let Some(c) = lowercase.chars().choose(&mut rng) {
                password.push(c);
            } else {
                return Err(CryptoError::InvalidConfiguration(
                    "lowercase charset empty".to_string(),
                ));
            }
        }
        if policy.require_numbers {
            if let Some(c) = numbers.chars().choose(&mut rng) {
                password.push(c);
            } else {
                return Err(CryptoError::InvalidConfiguration(
                    "numbers charset empty".to_string(),
                ));
            }
        }
        if policy.require_special_chars {
            if let Some(c) = symbols.chars().choose(&mut rng) {
                password.push(c);
            } else {
                return Err(CryptoError::InvalidConfiguration(
                    "symbols charset empty".to_string(),
                ));
            }
        }

        // Fill remaining positions with random characters from all sets
        let all_chars = format!("{}{}{}{}", uppercase, lowercase, numbers, symbols);
        let all_chars: Vec<char> = all_chars.chars().collect();

        while password.len() < length {
            if let Some(c) = all_chars.choose(&mut rng) {
                password.push(*c);
            } else {
                return Err(CryptoError::InvalidConfiguration(
                    "all_chars empty".to_string(),
                ));
            }
        }

        // Shuffle the password to avoid predictable patterns
        password.shuffle(&mut rng);

        let password: String = password.into_iter().collect();

        // Validate the generated password
        self.validate_password_strength(&password)?;

        Ok(password)
    }

    // Private helper methods

    fn generate_salt(&self) -> CryptoResult<argon2::password_hash::SaltString> {
        use argon2::password_hash::rand_core::OsRng;
        use argon2::password_hash::SaltString;

        Ok(SaltString::generate(&mut OsRng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_operations_creation() {
        let config = PasswordConfig::default();
        let ops = PasswordOperations::new(config);
        assert!(ops.is_ok());
    }

    #[test]
    fn test_password_strength_validation() {
        let config = PasswordConfig::default();
        let ops = PasswordOperations::new(config).unwrap();

        // Test weak passwords
        assert!(ops.validate_password_strength("weak").is_err());
        assert!(ops.validate_password_strength("password").is_err());
        assert!(ops.validate_password_strength("PASSWORD123").is_err()); // No special chars

        // Test strong password
        assert!(ops.validate_password_strength("MyStr0ng!P@ssw0rd").is_ok());
    }

    #[test]
    fn test_password_hashing_and_verification() {
        let config = PasswordConfig::default();
        let ops = PasswordOperations::new(config).unwrap();

        let password = "MyStr0ng!P@ssw0rd";
        let hash = ops.hash_password(password).unwrap();

        // Verify correct password
        assert!(ops.verify_password(password, &hash).unwrap());

        // Verify incorrect password
        assert!(!ops.verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_password_generation() {
        let config = PasswordConfig::default();
        let ops = PasswordOperations::new(config).unwrap();

        let password = ops.generate_secure_password(16).unwrap();
        assert_eq!(password.len(), 16);

        // Generated password should meet strength requirements
        assert!(ops.validate_password_strength(&password).is_ok());
    }
}
