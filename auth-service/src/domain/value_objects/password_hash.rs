//! Password hash value object with validation.

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Password hash value object with validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    /// Create a new password hash with validation
    pub fn new(hash: String) -> Result<Self, String> {
        Self::validate(&hash)?;
        Ok(Self(hash))
    }

    /// Get the hash as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the hash algorithm type
    pub fn algorithm(&self) -> Option<&str> {
        if let Some(dollar_pos) = self.0.find('$') {
            let algorithm_part = &self.0[1..dollar_pos];
            if let Some(second_dollar) = algorithm_part.find('$') {
                Some(&algorithm_part[..second_dollar])
            } else {
                Some(algorithm_part)
            }
        } else {
            None
        }
    }

    /// Verify if the hash uses a secure algorithm
    pub fn is_secure_algorithm(&self) -> bool {
        match self.algorithm() {
            Some("argon2id" | "argon2i" | "scrypt" | "bcrypt") => true,
            _ => false,
        }
    }

    /// Validate password hash format
    fn validate(hash: &str) -> Result<(), String> {
        if hash.is_empty() {
            return Err("Password hash cannot be empty".to_string());
        }

        if hash.len() < 20 {
            return Err("Password hash is too short".to_string());
        }

        // Check for basic hash format (should start with $ for most algorithms)
        if !hash.starts_with('$') && !hash.starts_with("pbkdf2") {
            return Err("Invalid password hash format".to_string());
        }

        // Check for suspicious patterns (all same character)
        if hash
            .chars()
            .all(|c| c == hash.chars().next().unwrap_or(' '))
        {
            return Err(
                "Password hash appears to be invalid (same character repeated)".to_string(),
            );
        }

        Ok(())
    }
}

impl FromStr for PasswordHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl std::fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]") // Never display actual hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_argon2_hash_creation() {
        let hash_str = "$argon2id$v=19$m=4096,t=3,p=1$test".to_string();
        let hash = PasswordHash::new(hash_str.clone());
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().as_str(), hash_str);
    }

    #[test]
    fn test_bcrypt_hash_creation() {
        let hash_str = "$2b$12$LQH7rPZCXqOQKj7JTzZPue".to_string();
        let hash = PasswordHash::new(hash_str.clone());
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().as_str(), hash_str);
    }

    #[test]
    fn test_password_hash_from_str() {
        let hash = PasswordHash::from_str("$argon2id$v=19$m=4096,t=3,p=1$test");
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().as_str(), "$argon2id$v=19$m=4096,t=3,p=1$test");
    }

    #[test]
    fn test_password_hash_display() {
        let hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();
        assert_eq!(format!("{}", hash), "[REDACTED]");
    }

    #[test]
    fn test_algorithm_detection() {
        let argon2_hash =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();
        assert_eq!(argon2_hash.algorithm(), Some("argon2id"));

        let bcrypt_hash = PasswordHash::new("$2b$12$LQH7rPZCXqOQKj7JTzZPue".to_string()).unwrap();
        assert_eq!(bcrypt_hash.algorithm(), Some("2b"));

        let pbkdf2_hash = PasswordHash::new("pbkdf2_sha256$test".to_string()).unwrap();
        assert_eq!(pbkdf2_hash.algorithm(), None); // pbkdf2 doesn't follow $ format
    }

    #[test]
    fn test_secure_algorithm_detection() {
        let secure_hashes = vec![
            "$argon2id$v=19$m=4096,t=3,p=1$test",
            "$argon2i$v=19$m=4096,t=3,p=1$test",
            "$scrypt$test",
            "$2b$12$LQH7rPZCXqOQKj7JTzZPue", // bcrypt
        ];

        for hash_str in secure_hashes {
            let hash = PasswordHash::new(hash_str.to_string()).unwrap();
            assert!(
                hash.is_secure_algorithm(),
                "Hash {} should be considered secure",
                hash_str
            );
        }

        let insecure_hashes = vec![
            "$md5$test",
            "$sha1$test",
            "$sha256$test",
            "plaintext_password",
        ];

        for hash_str in insecure_hashes {
            let hash = PasswordHash::new(hash_str.to_string()).unwrap();
            assert!(
                !hash.is_secure_algorithm(),
                "Hash {} should NOT be considered secure",
                hash_str
            );
        }
    }

    #[test]
    fn test_empty_hash() {
        let hash = PasswordHash::new("".to_string());
        assert!(hash.is_err());
        assert_eq!(hash.unwrap_err(), "Password hash cannot be empty");
    }

    #[test]
    fn test_hash_too_short() {
        let hash = PasswordHash::new("short".to_string());
        assert!(hash.is_err());
        assert_eq!(hash.unwrap_err(), "Password hash is too short");
    }

    #[test]
    fn test_invalid_format() {
        let invalid_hashes = vec!["plaintext", "md5hash", "no-dollar-sign-hash"];

        for invalid_hash in invalid_hashes {
            let hash = PasswordHash::new(invalid_hash.to_string());
            assert!(hash.is_err(), "Hash '{}' should be invalid", invalid_hash);
        }
    }

    #[test]
    fn test_suspicious_pattern() {
        let suspicious_hashes = vec![
            "aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "$$$$$$$$$$$$$$$$$$$$$$$$$$",
            "11111111111111111111111111",
        ];

        for suspicious_hash in suspicious_hashes {
            let hash = PasswordHash::new(suspicious_hash.to_string());
            assert!(
                hash.is_err(),
                "Hash '{}' should be considered suspicious",
                suspicious_hash
            );
            assert!(hash.unwrap_err().contains("same character"));
        }
    }

    #[test]
    fn test_hash_equality() {
        let hash1 = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();
        let hash2 = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();
        let hash3 =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$different".to_string()).unwrap();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_pbkdf2_format() {
        // pbkdf2 doesn't follow the $ format but should still be valid
        let pbkdf2_hash = "pbkdf2_sha256$36000$test$salt".to_string();
        let hash = PasswordHash::new(pbkdf2_hash);
        assert!(hash.is_ok());
    }

    #[test]
    fn test_complex_argon2_parameters() {
        let complex_hash = "$argon2id$v=19$m=65536,t=4,p=8$longsalt$longhash".to_string();
        let hash = PasswordHash::new(complex_hash.clone());
        assert!(hash.is_ok());
        assert_eq!(hash.unwrap().as_str(), complex_hash);
    }
}
