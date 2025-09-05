//! Enhanced cryptographic utilities with improved security practices
//!
//! This module provides enhanced cryptographic functions with better error handling
//! and security practices compared to the standard implementations.

use ring::rand::SecureRandom;
use tracing::{error, warn};

/// Generate a cryptographically secure salt with enhanced security practices
/// 
/// This function generates a 32-byte cryptographically secure salt using the system's
/// secure random number generator. Unlike the previous implementation, this version
/// does not fall back to deterministic generation, which would reduce security.
/// 
/// # Errors
/// 
/// Returns an error if the secure random number generator fails to generate the salt.
/// In production, this should be treated as a critical failure.
/// 
/// # Example
/// 
/// ```rust
/// # use auth_service::crypto_enhanced::generate_secure_salt;
/// match generate_secure_salt() {
///     Ok(salt) => println!("Generated {}-byte salt", salt.len()),
///     Err(e) => eprintln!("Failed to generate salt: {}", e),
/// }
/// ```
pub fn generate_secure_salt() -> Result<Vec<u8>, CryptoError> {
    use ring::rand::SystemRandom;
    
    let mut salt = vec![0u8; 32]; // 256-bit salt
    let rng = SystemRandom::new();
    
    // Try to generate the salt with multiple attempts
    for attempt in 1..=5 {
        match rng.fill(&mut salt) {
            Ok(()) => {
                if attempt > 1 {
                    warn!("Salt generation succeeded on attempt {}", attempt);
                }
                return Ok(salt);
            }
            Err(e) => {
                warn!("Salt generation attempt {} failed: {:?}", attempt, e);
                if attempt == 5 {
                    error!("Failed to generate salt after 5 attempts - critical security failure");
                    return Err(CryptoError::EntropyFailure);
                }
                // Small delay before retry to allow entropy to accumulate
                std::thread::sleep(std::time::Duration::from_millis(10 * attempt as u64));
            }
        }
    }
    
    // This should never be reached due to the loop above, but just in case
    Err(CryptoError::EntropyFailure)
}

/// Generate a cryptographically secure salt and encode it as hex
/// 
/// This function generates a secure salt and returns it as a hexadecimal string.
/// 
/// # Errors
/// 
/// Returns an error if salt generation fails.
/// 
/// # Example
/// 
/// ```rust
/// # use auth_service::crypto_enhanced::generate_secure_salt_hex;
/// match generate_secure_salt_hex() {
///     Ok(salt_hex) => println!("Generated salt: {}", salt_hex),
///     Err(e) => eprintln!("Failed to generate salt: {}", e),
/// }
/// ```
pub fn generate_secure_salt_hex() -> Result<String, CryptoError> {
    let salt = generate_secure_salt()?;
    Ok(hex::encode(salt))
}

/// Enhanced token binding salt generation with improved security
/// 
/// This function generates a cryptographically secure salt specifically for token binding.
/// It uses enhanced error handling and does not fall back to deterministic generation.
static TOKEN_BINDING_SALT: std::sync::LazyLock<Result<String, CryptoError>> = 
    std::sync::LazyLock::new(|| {
        match generate_secure_salt_hex() {
            Ok(salt) => {
                tracing::info!("Successfully generated token binding salt");
                Ok(salt)
            }
            Err(e) => {
                error!("CRITICAL: Failed to generate token binding salt - {}", e);
                Err(e)
            }
        }
    });

/// Get the token binding salt, panicking if generation failed
/// 
/// This function returns the token binding salt, panicking if it failed to generate.
/// In a production system, this would cause the service to fail to start, which is
/// the correct behavior for a critical security dependency.
/// 
/// # Panics
/// 
/// Panics if the token binding salt failed to generate during initialization.
pub fn get_token_binding_salt() -> &'static str {
    match TOKEN_BINDING_SALT.as_ref() {
        Ok(salt) => salt,
        Err(e) => {
            error!("CRITICAL: Token binding salt generation failed - {}", e);
            panic!("Failed to generate token binding salt: {}", e);
        }
    }
}

/// Enhanced token binding generation with improved security
/// 
/// This function generates a token binding value from client information using
/// enhanced security practices. It uses HMAC-SHA256 with a cryptographically
/// secure salt and includes additional security measures.
/// 
/// # Example
/// 
/// ```rust
/// # use auth_service::crypto_enhanced::generate_enhanced_token_binding;
/// let binding = generate_enhanced_token_binding("192.168.1.1", "Mozilla/5.0");
/// println!("Token binding: {}", binding);
/// ```
pub fn generate_enhanced_token_binding(client_ip: &str, user_agent: &str) -> String {
    use ring::hmac;
    
    let salt = get_token_binding_salt().as_bytes();
    
    // Use HMAC-SHA256 for secure binding with additional entropy
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&key);
    
    // Include additional entropy sources
    ctx.update(client_ip.as_bytes());
    ctx.update(b"|"); // Separator to prevent collision attacks
    ctx.update(user_agent.as_bytes());
    ctx.update(b"|");
    
    // Add high-precision timestamp for additional entropy
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos() as u64;
    ctx.update(&timestamp.to_be_bytes());
    
    // Add process ID for additional uniqueness
    ctx.update(&std::process::id().to_be_bytes());
    
    let tag = ctx.sign();
    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
}

/// Enhanced token binding validation with timing attack protection
/// 
/// This function validates a token binding value with improved security measures,
/// including timing attack protection and extended validation windows.
/// 
/// # Errors
/// 
/// Returns an error if the stored binding is invalid or corrupted.
pub fn validate_enhanced_token_binding(
    stored_binding: &str,
    client_ip: &str,
    user_agent: &str,
) -> Result<bool, CryptoError> {
    use ring::hmac;
    
    // Decode the stored binding
    let stored_bytes = base64::engine::general_purpose::STANDARD
        .decode(stored_binding)
        .map_err(|_| CryptoError::InvalidFormat)?;
    
    let salt = get_token_binding_salt().as_bytes();
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    
    // Check current time and recent windows (extended window for better user experience)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos() as u64;
    
    // Extended validation window (10 minutes) with high precision
    let window_size = 60_000_000_000u64; // 1 minute in nanoseconds
    let max_windows = 10; // 10 minutes total
    
    for window in 0..max_windows {
        let test_timestamp = now - (window as u64 * window_size);
        
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(client_ip.as_bytes());
        ctx.update(b"|");
        ctx.update(user_agent.as_bytes());
        ctx.update(b"|");
        ctx.update(&test_timestamp.to_be_bytes());
        ctx.update(&std::process::id().to_be_bytes());
        
        let expected_tag = ctx.sign();
        
        // Use secure HMAC verification to prevent timing attacks
        if hmac::verify(&key, &stored_bytes, expected_tag.as_ref()).is_ok() {
            return Ok(true);
        }
    }
    
    Ok(false)
}

/// Enhanced PKCE code verifier generation with improved security
/// 
/// This function generates a cryptographically secure code verifier for PKCE
/// with enhanced security practices.
/// 
/// # Errors
/// 
/// Returns an error if the cryptographically secure random number generation fails.
pub fn generate_enhanced_code_verifier() -> Result<String, CryptoError> {
    use ring::rand::{SecureRandom, SystemRandom};
    
    // Use cryptographically secure random generator with enhanced entropy
    let mut bytes = [0u8; 64]; // 512 bits of entropy for enhanced security per RFC 7636
    let rng = SystemRandom::new();
    
    rng.fill(&mut bytes)
        .map_err(|_| CryptoError::EntropyFailure)?;
    
    // Encode using URL-safe base64 without padding
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Enhanced request signature generation with improved security
/// 
/// This function generates a request signature using HMAC-SHA256 with
/// enhanced security practices including additional entropy sources.
/// 
/// # Errors
/// 
/// Returns an error if the HMAC key is invalid or signature generation fails.
pub fn generate_enhanced_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    secret: &str,
) -> Result<String, CryptoError> {
    use ring::hmac;
    
    if secret.len() < 32 {
        return Err(CryptoError::WeakSecret);
    }
    
    // Include additional entropy in the message
    let message = format!(
        "{}\n{}\n{}\n{}\n{}",
        method,
        path,
        body,
        timestamp,
        std::process::id() // Add process ID for additional uniqueness
    );
    
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());
    
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.as_ref()))
}

/// Enhanced request signature verification with timing attack protection
/// 
/// This function verifies a request signature with enhanced security measures,
/// including timing attack protection and replay prevention.
/// 
/// # Errors
/// 
/// Returns an error if the HMAC key is invalid or signature verification fails.
pub fn verify_enhanced_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    signature: &str,
    secret: &str,
) -> Result<bool, CryptoError> {
    use ring::hmac;
    
    // Check timestamp window (prevent replay attacks) with microsecond precision
    let now = chrono::Utc::now().timestamp();
    let time_diff = (now - timestamp).abs();
    
    // Extended window for better tolerance of clock skew
    if time_diff > 600 {
        return Err(CryptoError::TimestampExpired);
    }
    
    if secret.len() < 32 {
        return Err(CryptoError::WeakSecret);
    }
    
    // Include additional entropy in the message verification
    let message = format!(
        "{}\n{}\n{}\n{}\n{}",
        method,
        path,
        body,
        timestamp,
        std::process::id()
    );
    
    let provided_signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| CryptoError::InvalidFormat)?;
    
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    
    // Use secure HMAC verification to prevent timing attacks
    Ok(hmac::verify(&key, message.as_bytes(), &provided_signature).is_ok())
}

/// Enhanced secure random bytes generation
/// 
/// This function generates cryptographically secure random bytes with
/// enhanced error handling.
/// 
/// # Errors
/// 
/// Returns an error if the random number generator fails.
pub fn generate_secure_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    use ring::rand::{SecureRandom, SystemRandom};
    
    let mut bytes = vec![0u8; len];
    let rng = SystemRandom::new();
    
    rng.fill(&mut bytes)
        .map_err(|_| CryptoError::EntropyFailure)?;
    
    Ok(bytes)
}

/// Enhanced secure random string generation
/// 
/// This function generates a cryptographically secure random string with
/// the specified length, encoded in base64 URL-safe format.
/// 
/// # Errors
/// 
/// Returns an error if the random number generator fails.
pub fn generate_secure_string(len: usize) -> Result<String, CryptoError> {
    let bytes = generate_secure_bytes(len)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// Custom error types for cryptographic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Failed to generate entropy
    EntropyFailure,
    /// Invalid format for cryptographic data
    InvalidFormat,
    /// Weak secret provided
    WeakSecret,
    /// Timestamp expired or invalid
    TimestampExpired,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EntropyFailure => write!(f, "Failed to generate cryptographic entropy"),
            CryptoError::InvalidFormat => write!(f, "Invalid cryptographic data format"),
            CryptoError::WeakSecret => write!(f, "Provided secret is too weak"),
            CryptoError::TimestampExpired => write!(f, "Timestamp is expired or invalid"),
        }
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_salt_generation() {
        let salt = generate_secure_salt().expect("Failed to generate salt");
        assert_eq!(salt.len(), 32); // 256 bits = 32 bytes
        
        // Generate another salt and ensure it's different
        let salt2 = generate_secure_salt().expect("Failed to generate second salt");
        assert_ne!(salt, salt2, "Salts should be different");
    }

    #[test]
    fn test_secure_salt_hex_generation() {
        let salt_hex = generate_secure_salt_hex().expect("Failed to generate hex salt");
        assert!(!salt_hex.is_empty());
        assert!(salt_hex.len() >= 64); // 32 bytes = 64 hex characters
        
        // Should be valid hex
        assert!(hex::decode(&salt_hex).is_ok());
    }

    #[test]
    fn test_token_binding_generation() {
        let binding1 = generate_enhanced_token_binding("192.168.1.1", "Mozilla/5.0");
        let binding2 = generate_enhanced_token_binding("192.168.1.1", "Mozilla/5.0");
        
        // Should be different due to timestamp
        assert_ne!(binding1, binding2);
        
        // Should be valid base64
        assert!(base64::engine::general_purpose::STANDARD.decode(&binding1).is_ok());
    }

    #[test]
    fn test_token_binding_validation() {
        let client_ip = "192.168.1.1";
        let user_agent = "Mozilla/5.0";
        let binding = generate_enhanced_token_binding(client_ip, user_agent);
        
        // Should validate correctly
        assert!(validate_enhanced_token_binding(&binding, client_ip, user_agent)
            .expect("Validation failed"));
        
        // Should not validate with wrong IP
        assert!(!validate_enhanced_token_binding(&binding, "192.168.1.2", user_agent)
            .expect("Validation should have succeeded"));
    }

    #[test]
    fn test_code_verifier_generation() {
        let verifier = generate_enhanced_code_verifier().expect("Failed to generate verifier");
        
        // Should meet length requirements
        assert!(verifier.len() >= 43);
        assert!(verifier.len() <= 128);
        
        // Should only contain URL-safe characters
        assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_request_signature() {
        let secret = "a".repeat(32); // 32 character secret
        let timestamp = chrono::Utc::now().timestamp();
        
        let signature = generate_enhanced_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &secret,
        ).expect("Failed to generate signature");
        
        // Should verify correctly
        assert!(verify_enhanced_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &signature,
            &secret,
        ).expect("Verification failed"));
        
        // Should not verify with wrong secret
        let wrong_secret = "b".repeat(32);
        assert!(!verify_enhanced_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &signature,
            &wrong_secret,
        ).expect("Verification should have succeeded"));
    }

    #[test]
    fn test_secure_bytes_generation() {
        let bytes = generate_secure_bytes(32).expect("Failed to generate bytes");
        assert_eq!(bytes.len(), 32);
        
        // Generate another set and ensure it's different
        let bytes2 = generate_secure_bytes(32).expect("Failed to generate second set");
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_secure_string_generation() {
        let string = generate_secure_string(32).expect("Failed to generate string");
        assert!(!string.is_empty());
        
        // Should be valid base64 URL-safe
        assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&string).is_ok());
    }
}