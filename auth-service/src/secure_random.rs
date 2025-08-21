use crate::{internal_error, AuthError};
use data_encoding::BASE64URL_NOPAD;
use getrandom::getrandom;

/// Cryptographically secure random number generator
pub struct SecureRandomGenerator;

impl SecureRandomGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate cryptographically secure random bytes
    pub fn generate_bytes(&self, length: usize) -> Result<Vec<u8>, AuthError> {
        let mut bytes = vec![0u8; length];
        getrandom(&mut bytes)
            .map_err(|_| internal_error("Failed to generate secure random bytes"))?;
        Ok(bytes)
    }

    /// Generate secure random string with specified length (base64url encoded)
    pub fn generate_string(&self, byte_length: usize) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(byte_length)?;
        Ok(BASE64URL_NOPAD.encode(&bytes))
    }

    /// Generate secure authorization code (OAuth2)
    pub fn generate_authorization_code(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(format!("ac_{}", BASE64URL_NOPAD.encode(&bytes)))
    }

    /// Generate secure access token
    pub fn generate_access_token(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(format!("tk_{}", BASE64URL_NOPAD.encode(&bytes)))
    }

    /// Generate secure refresh token
    pub fn generate_refresh_token(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(format!("rt_{}", BASE64URL_NOPAD.encode(&bytes)))
    }

    /// Generate secure session ID
    pub fn generate_session_id(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(format!("sess_{}", BASE64URL_NOPAD.encode(&bytes)))
    }

    /// Generate secure CSRF token
    pub fn generate_csrf_token(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(format!("csrf_{}", BASE64URL_NOPAD.encode(&bytes)))
    }

    /// Generate secure TOTP secret (160 bits as per RFC 6238)
    pub fn generate_totp_secret(&self) -> Result<Vec<u8>, AuthError> {
        self.generate_bytes(20) // 160 bits
    }

    /// Generate secure backup codes for MFA
    pub fn generate_backup_codes(&self, count: usize) -> Result<Vec<String>, AuthError> {
        let mut codes = Vec::with_capacity(count);
        for _ in 0..count {
            // Generate 8-digit backup codes
            let bytes = self.generate_bytes(4)?;
            let code = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 100_000_000;
            codes.push(format!("{:08}", code));
        }
        Ok(codes)
    }

    /// Generate secure PKCE code verifier (RFC 7636)
    pub fn generate_pkce_verifier(&self) -> Result<String, AuthError> {
        // PKCE code verifier: 43-128 characters, we'll use 128 for maximum security
        let bytes = self.generate_bytes(96)?; // 96 bytes = 128 base64url chars
        Ok(BASE64URL_NOPAD.encode(&bytes))
    }

    /// Generate secure state parameter for OAuth2
    pub fn generate_oauth_state(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(BASE64URL_NOPAD.encode(&bytes))
    }

    /// Generate secure nonce for OpenID Connect
    pub fn generate_oidc_nonce(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(BASE64URL_NOPAD.encode(&bytes))
    }

    /// Generate secure salt for password hashing
    pub fn generate_salt(&self) -> Result<Vec<u8>, AuthError> {
        self.generate_bytes(32) // 256 bits
    }

    /// Generate secure API key
    pub fn generate_api_key(&self) -> Result<String, AuthError> {
        let bytes = self.generate_bytes(32)?; // 256 bits of entropy
        Ok(format!("ak_{}", BASE64URL_NOPAD.encode(&bytes)))
    }
}

impl Default for SecureRandomGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Global secure random generator instance
static SECURE_RNG: once_cell::sync::Lazy<SecureRandomGenerator> =
    once_cell::sync::Lazy::new(SecureRandomGenerator::new);

/// Convenience functions using the global secure RNG
pub fn generate_secure_authorization_code() -> Result<String, AuthError> {
    SECURE_RNG.generate_authorization_code()
}

pub fn generate_secure_access_token() -> Result<String, AuthError> {
    SECURE_RNG.generate_access_token()
}

pub fn generate_secure_refresh_token() -> Result<String, AuthError> {
    SECURE_RNG.generate_refresh_token()
}

pub fn generate_secure_session_id() -> Result<String, AuthError> {
    SECURE_RNG.generate_session_id()
}

pub fn generate_secure_csrf_token() -> Result<String, AuthError> {
    SECURE_RNG.generate_csrf_token()
}

pub fn generate_secure_totp_secret() -> Result<Vec<u8>, AuthError> {
    SECURE_RNG.generate_totp_secret()
}

pub fn generate_secure_backup_codes(count: usize) -> Result<Vec<String>, AuthError> {
    SECURE_RNG.generate_backup_codes(count)
}

pub fn generate_secure_pkce_verifier() -> Result<String, AuthError> {
    SECURE_RNG.generate_pkce_verifier()
}

pub fn generate_secure_oauth_state() -> Result<String, AuthError> {
    SECURE_RNG.generate_oauth_state()
}

pub fn generate_secure_oidc_nonce() -> Result<String, AuthError> {
    SECURE_RNG.generate_oidc_nonce()
}

pub fn generate_secure_salt() -> Result<Vec<u8>, AuthError> {
    SECURE_RNG.generate_salt()
}

pub fn generate_secure_api_key() -> Result<String, AuthError> {
    SECURE_RNG.generate_api_key()
}

/// Legacy function for backward compatibility - now uses secure generation
pub fn generate_secure_code() -> String {
    generate_secure_authorization_code().unwrap_or_else(|_| format!("ac_{}", uuid::Uuid::new_v4()))
    // Fallback to UUID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_random_generation() {
        let rng = SecureRandomGenerator::new();

        // Test different token types
        let auth_code = rng.generate_authorization_code().unwrap();
        assert!(auth_code.starts_with("ac_"));
        assert!(auth_code.len() > 40);

        let access_token = rng.generate_access_token().unwrap();
        assert!(access_token.starts_with("tk_"));
        assert!(access_token.len() > 40);

        let refresh_token = rng.generate_refresh_token().unwrap();
        assert!(refresh_token.starts_with("rt_"));
        assert!(refresh_token.len() > 40);
    }

    #[test]
    fn test_entropy_uniqueness() {
        let rng = SecureRandomGenerator::new();

        // Generate multiple tokens and ensure they're unique
        let mut tokens = std::collections::HashSet::new();
        for _ in 0..1000 {
            let token = rng.generate_access_token().unwrap();
            assert!(tokens.insert(token), "Generated duplicate token");
        }
    }

    #[test]
    fn test_backup_codes() {
        let rng = SecureRandomGenerator::new();
        let codes = rng.generate_backup_codes(10).unwrap();

        assert_eq!(codes.len(), 10);
        for code in &codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }

        // Ensure uniqueness
        let unique_codes: std::collections::HashSet<_> = codes.into_iter().collect();
        assert_eq!(unique_codes.len(), 10);
    }

    #[test]
    fn test_pkce_verifier() {
        let rng = SecureRandomGenerator::new();
        let verifier = rng.generate_pkce_verifier().unwrap();

        // PKCE verifier should be 128 characters (96 bytes base64url encoded)
        assert_eq!(verifier.len(), 128);
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_totp_secret() {
        let rng = SecureRandomGenerator::new();
        let secret = rng.generate_totp_secret().unwrap();

        // TOTP secret should be 160 bits (20 bytes)
        assert_eq!(secret.len(), 20);
    }

    #[test]
    fn test_salt_generation() {
        let rng = SecureRandomGenerator::new();
        let salt1 = rng.generate_salt().unwrap();
        let salt2 = rng.generate_salt().unwrap();

        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // Should be unique
    }
}
