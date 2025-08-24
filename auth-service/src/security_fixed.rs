use base64::Engine as _;
use once_cell::sync::Lazy;
use ring::{digest, hmac, rand::{SecureRandom as RingSecureRandom, SystemRandom}};

/// Secure token binding salt - loaded from environment or generated
static TOKEN_BINDING_SALT: Lazy<String> = Lazy::new(|| {
    std::env::var("TOKEN_BINDING_SALT").unwrap_or_else(|_| {
        // Generate a cryptographically secure salt
        let mut salt = [0u8; 32];
        SystemRandom::new().fill(&mut salt).expect("Failed to generate salt");
        hex::encode(salt)
    })
});

/// Generate a token binding value from client information using secure practices
pub fn generate_token_binding(client_ip: &str, user_agent: &str) -> Result<String, SecurityError> {
    let salt = TOKEN_BINDING_SALT.as_bytes();
    
    // Use HMAC-SHA256 for secure binding
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&key);
    
    ctx.update(client_ip.as_bytes());
    ctx.update(b"|"); // Separator to prevent collision attacks
    ctx.update(user_agent.as_bytes());
    ctx.update(b"|");
    ctx.update(&chrono::Utc::now().timestamp().to_be_bytes()); // Add timestamp
    
    let tag = ctx.sign();
    Ok(base64::engine::general_purpose::STANDARD.encode(tag.as_ref()))
}

/// Validate token binding to ensure token is used from the same client
pub fn validate_token_binding(
    stored_binding: &str, 
    client_ip: &str, 
    user_agent: &str,
    max_age_seconds: i64,
) -> Result<bool, SecurityError> {
    // Decode the stored binding
    let stored_bytes = base64::engine::general_purpose::STANDARD
        .decode(stored_binding)
        .map_err(|_| SecurityError::InvalidTokenBinding)?;
    
    // For validation, we need to check against recent timestamps
    let now = chrono::Utc::now().timestamp();
    
    // Check multiple recent timestamps to account for clock skew
    for offset in 0..=max_age_seconds {
        let test_timestamp = now - offset;
        
        let salt = TOKEN_BINDING_SALT.as_bytes();
        let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
        let mut ctx = hmac::Context::with_key(&key);
        
        ctx.update(client_ip.as_bytes());
        ctx.update(b"|");
        ctx.update(user_agent.as_bytes());
        ctx.update(b"|");
        ctx.update(&test_timestamp.to_be_bytes());
        
        let expected_tag = ctx.sign();
        
        // Use constant-time comparison to prevent timing attacks
        if hmac::verify(&key, &stored_bytes, expected_tag.as_ref()).is_ok() {
            return Ok(true);
        }
    }
    
    Ok(false)
}

/// PKCE (Proof Key for Code Exchange) support with secure implementation
/// Generate a cryptographically secure code verifier for PKCE
pub fn generate_code_verifier() -> Result<String, SecurityError> {
    // Use cryptographically secure random generator
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| SecurityError::RandomGenerationFailed)?;
    
    // Encode using URL-safe base64 without padding
    let mut verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    
    // Ensure minimum length requirement (43-128 characters per RFC 7636)
    while verifier.len() < 43 {
        let mut additional = [0u8; 8];
        SystemRandom::new()
            .fill(&mut additional)
            .map_err(|_| SecurityError::RandomGenerationFailed)?;
        verifier.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(additional));
    }
    
    // Truncate to maximum length
    verifier.truncate(128);
    Ok(verifier)
}

/// Generate a code challenge from a code verifier using SHA256
pub fn generate_code_challenge(code_verifier: &str) -> Result<String, SecurityError> {
    if code_verifier.len() < 43 || code_verifier.len() > 128 {
        return Err(SecurityError::InvalidCodeVerifier);
    }
    
    let digest = digest::digest(&digest::SHA256, code_verifier.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref()))
}

/// Verify a code verifier against a code challenge with timing attack protection
pub fn verify_code_challenge(code_verifier: &str, code_challenge: &str) -> Result<bool, SecurityError> {
    let computed_challenge = generate_code_challenge(code_verifier)?;
    
    // Use constant-time comparison to prevent timing attacks
    use ring::constant_time;
    Ok(constant_time::verify_slices_are_equal(
        computed_challenge.as_bytes(),
        code_challenge.as_bytes(),
    ).is_ok())
}

/// PKCE challenge methods - Only S256 is supported for security
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
}

impl std::str::FromStr for CodeChallengeMethod {
    type Err = SecurityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "S256" => Ok(CodeChallengeMethod::S256),
            "plain" => Err(SecurityError::UnsupportedChallengeMethod(
                "Plain PKCE method is not supported for security reasons".to_string()
            )),
            _ => Err(SecurityError::UnsupportedChallengeMethod(
                "Only S256 challenge method is supported".to_string()
            )),
        }
    }
}

/// Validate PKCE parameters with comprehensive security checks
pub fn validate_pkce_params(
    code_verifier: &str,
    code_challenge: &str,
    method: CodeChallengeMethod,
) -> Result<bool, SecurityError> {
    // Validate code verifier format
    if !code_verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~') {
        return Err(SecurityError::InvalidCodeVerifier);
    }
    
    // Validate code challenge format
    if !code_challenge.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(SecurityError::InvalidCodeChallenge);
    }
    
    match method {
        CodeChallengeMethod::S256 => verify_code_challenge(code_verifier, code_challenge),
    }
}

/// Request signing for critical operations using HMAC-SHA256
pub fn generate_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    secret: &str,
) -> Result<String, SecurityError> {
    if secret.len() < 32 {
        return Err(SecurityError::WeakSigningSecret);
    }
    
    let message = format!("{}\n{}\n{}\n{}", method, path, body, timestamp);
    
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let signature = hmac::sign(&key, message.as_bytes());
    
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.as_ref()))
}

/// Verify request signature with timing attack protection
pub fn verify_request_signature(
    method: &str,
    path: &str,
    body: &str,
    timestamp: i64,
    signature: &str,
    secret: &str,
) -> Result<bool, SecurityError> {
    // Check timestamp window (prevent replay attacks)
    let now = chrono::Utc::now().timestamp();
    let time_diff = (now - timestamp).abs();
    
    if time_diff > 300 { // 5 minutes window
        return Err(SecurityError::RequestTooOld);
    }
    
    let expected_signature = generate_request_signature(method, path, body, timestamp, secret)?;
    
    // Use constant-time comparison
    use ring::constant_time;
    Ok(constant_time::verify_slices_are_equal(
        expected_signature.as_bytes(),
        signature.as_bytes(),
    ).is_ok())
}

/// Security error types
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Random number generation failed")]
    RandomGenerationFailed,
    #[error("Invalid token binding")]
    InvalidTokenBinding,
    #[error("Invalid code verifier")]
    InvalidCodeVerifier,
    #[error("Invalid code challenge")]
    InvalidCodeChallenge,
    #[error("Unsupported challenge method: {0}")]
    UnsupportedChallengeMethod(String),
    #[error("Weak signing secret")]
    WeakSigningSecret,
    #[error("Request timestamp too old")]
    RequestTooOld,
}

/// Secure random number generation utilities
pub struct SecureRandom {
    rng: SystemRandom,
}

impl SecureRandom {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }
    
    /// Generate secure random bytes
    pub fn generate_bytes(&self, len: usize) -> Result<Vec<u8>, SecurityError> {
        let mut bytes = vec![0u8; len];
        self.rng.fill(&mut bytes)
            .map_err(|_| SecurityError::RandomGenerationFailed)?;
        Ok(bytes)
    }
    
    /// Generate secure random string (base64url encoded)
    pub fn generate_string(&self, byte_len: usize) -> Result<String, SecurityError> {
        let bytes = self.generate_bytes(byte_len)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }
    
    /// Generate secure session ID
    pub fn generate_session_id(&self) -> Result<String, SecurityError> {
        self.generate_string(32) // 256 bits of entropy
    }
    
    /// Generate secure API key
    pub fn generate_api_key(&self) -> Result<String, SecurityError> {
        let bytes = self.generate_bytes(32)?;
        Ok(format!("sk_{}", hex::encode(bytes)))
    }
}

impl Default for SecureRandom {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_verifier_generation() {
        let verifier = generate_code_verifier().unwrap();
        assert!(verifier.len() >= 43);
        assert!(verifier.len() <= 128);
        
        // Should only contain URL-safe characters
        assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_pkce_flow() {
        let verifier = generate_code_verifier().unwrap();
        let challenge = generate_code_challenge(&verifier).unwrap();
        
        assert!(verify_code_challenge(&verifier, &challenge).unwrap());
        assert!(!verify_code_challenge("wrong_verifier", &challenge).unwrap());
    }

    #[test]
    fn test_request_signing() {
        let secret = "test_secret_that_is_long_enough_for_security";
        let timestamp = chrono::Utc::now().timestamp();
        
        let signature = generate_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            secret,
        ).unwrap();
        
        assert!(verify_request_signature(
            "POST",
            "/oauth/token",
            "grant_type=client_credentials",
            timestamp,
            &signature,
            secret,
        ).unwrap());
    }

    #[test]
    fn test_token_binding() {
        let binding = generate_token_binding("192.168.1.1", "Mozilla/5.0").unwrap();
        
        // Should validate within time window
        assert!(validate_token_binding(&binding, "192.168.1.1", "Mozilla/5.0", 300).unwrap());
        
        // Should not validate with different IP
        assert!(!validate_token_binding(&binding, "192.168.1.2", "Mozilla/5.0", 300).unwrap());
    }
}
