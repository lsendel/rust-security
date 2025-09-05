//! Password hash value object with validation.

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use zeroize::Zeroize;

/// Password hash value object with validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordHash(String);

impl Drop for PasswordHash {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl PasswordHash {
    /// Create a new password hash with validation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The password hash is empty
    /// - The password hash is shorter than 20 characters
    /// - The hash format is invalid (must start with '$' or 'pbkdf2')
    /// - The hash appears to be invalid (same character repeated throughout)
    pub fn new(hash: String) -> Result<Self, String> {
        Self::validate(&hash)?;
        Ok(Self(hash))
    }

    /// Get the hash as a string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the hash algorithm type
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        // Skip the first character if it's '$'
        let start_pos = usize::from(self.0.starts_with('$'));

        self.0[start_pos..].find('$').and_then(|dollar_pos| {
            let algorithm_part = &self.0[start_pos..start_pos + dollar_pos];
            algorithm_part
                .find('$')
                .map_or(Some(algorithm_part), |second_dollar| {
                    Some(&algorithm_part[..second_dollar])
                })
        })
    }

    /// Verify if the hash uses a secure algorithm
    #[must_use]
    pub fn is_secure_algorithm(&self) -> bool {
        matches!(
            self.algorithm(),
            Some("argon2id" | "argon2i" | "scrypt" | "bcrypt" | "2b" | "2y" | "2a" | "2x")
        )
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

        // Check for suspicious patterns (repeated characters)
        // Extract the "payload" part (after format prefix)
        let payload = if let Some(stripped) = hash.strip_prefix('$') {
            stripped
        } else if hash.starts_with("pbkdf2") {
            // For pbkdf2, skip to the part after the first '$'
            hash.split('$').nth(1).unwrap_or("")
        } else {
            hash
        };

        // Check if payload consists of mostly repeated characters
        if !payload.is_empty() {
            let chars: Vec<char> = payload.chars().collect();
            let total_chars = chars.len();

            // Check if any character is repeated more than 80% of the time
            for &test_char in &chars {
                let repeated_chars = chars.iter().filter(|&&c| c == test_char).count();
                if repeated_chars * 5 >= total_chars * 4 {
                    return Err(
                        "Password hash appears to be invalid (same character repeated)".to_string(),
                    );
                }
            }

            // Also check for very long sequences of the same character (10+ in a row)
            let mut consecutive_count = 1;
            for i in 1..chars.len() {
                if chars[i] == chars[i - 1] {
                    consecutive_count += 1;
                    if consecutive_count >= 10 {
                        return Err(
                            "Password hash appears to be invalid (same character repeated)"
                                .to_string(),
                        );
                    }
                } else {
                    consecutive_count = 1;
                }
            }
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
        let hash_str = "$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx".to_string();
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
        let hash = PasswordHash::from_str("$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx");
        assert!(hash.is_ok());
        assert_eq!(
            hash.unwrap().as_str(),
            "$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx"
        );
    }

    #[test]
    fn test_password_hash_display() {
        let hash =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx".to_string())
                .unwrap();
        assert_eq!(format!("{hash}"), "[REDACTED]");
    }

    #[test]
    fn test_algorithm_detection() {
        let argon2_hash =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx".to_string())
                .unwrap();
        assert_eq!(argon2_hash.algorithm(), Some("argon2id"));

        let bcrypt_hash = PasswordHash::new("$2b$12$LQH7rPZCXqOQKj7JTzZPue".to_string()).unwrap();
        assert_eq!(bcrypt_hash.algorithm(), Some("2b"));

        let pbkdf2_hash =
            PasswordHash::new("pbkdf2_sha256$abcdefghijklmnopqrstuvwx".to_string()).unwrap();
        assert_eq!(pbkdf2_hash.algorithm(), Some("pbkdf2_sha256"));
    }

    #[test]
    fn test_secure_algorithm_detection() {
        let secure_hashes = vec![
            "$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx",
            "$argon2i$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx",
            "$scrypt$abcdefghijklmnopqrstuvwx",
            "$2b$12$LQH7rPZCXqOQKj7JTzZPue", // bcrypt
        ];

        for hash_str in secure_hashes {
            let hash = PasswordHash::new(hash_str.to_string()).unwrap();
            assert!(
                hash.is_secure_algorithm(),
                "Hash {hash_str} should be considered secure"
            );
        }

        let insecure_hashes = vec![
            "$md5$abcdefghijklmnopqrstuvwx",
            "$sha1$abcdefghijklmnopqrstuvwx",
            "$sha256$abcdefghijklmnopqrstuvwx",
            "plaintext_password_long_enough",
        ];

        for hash_str in insecure_hashes {
            if let Ok(hash) = PasswordHash::new(hash_str.to_string()) {
                assert!(
                    !hash.is_secure_algorithm(),
                    "Hash {hash_str} should NOT be considered secure"
                );
            }
            // If hash creation fails, that's also acceptable for insecure formats
        }
    }

    #[test]
    fn test_empty_hash() {
        let hash = PasswordHash::new(String::new());
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
            assert!(hash.is_err(), "Hash '{invalid_hash}' should be invalid");
        }
    }

    #[test]
    fn test_suspicious_pattern() {
        let suspicious_hashes = vec![
            "$aaaaaaaaaaaaaaaaaaaaaaaaa",
            "$$11111111111111111111111",
            "pbkdf2_sha256$aaaaaaaaaaaa",
        ];

        for suspicious_hash in suspicious_hashes {
            let hash = PasswordHash::new(suspicious_hash.to_string());
            assert!(
                hash.is_err(),
                "Hash '{suspicious_hash}' should be considered suspicious"
            );
            assert!(hash.unwrap_err().contains("same character repeated"));
        }
    }

    #[test]
    fn test_hash_equality() {
        let hash1 =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx".to_string())
                .unwrap();
        let hash2 =
            PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$abcdefghijklmnopqrstuvwx".to_string())
                .unwrap();
        let hash3 = PasswordHash::new(
            "$argon2id$v=19$m=4096,t=3,p=1$zyxwvutsrqponmlkjihgfedcba".to_string(),
        )
        .unwrap();

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
