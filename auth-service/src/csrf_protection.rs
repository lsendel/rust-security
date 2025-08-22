// CSRF Protection Implementation
// Double-submit cookie pattern with secure token generation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};

type HmacSha256 = Hmac<Sha256>;

/// CSRF protection configuration
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Secret key for HMAC signing
    pub secret_key: Vec<u8>,
    /// Token lifetime in seconds
    pub token_lifetime: Duration,
    /// Cookie name for CSRF token
    pub cookie_name: String,
    /// Header name for CSRF token
    pub header_name: String,
    /// Form field name for CSRF token
    pub form_field_name: String,
    /// SameSite cookie policy
    pub same_site_policy: SameSite,
    /// Secure cookie flag
    pub secure_cookie: bool,
    /// HttpOnly cookie flag
    pub http_only: bool,
    /// Endpoints exempt from CSRF protection
    pub exempt_endpoints: Vec<String>,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        // Generate a random secret key
        let mut secret_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret_key);
        
        Self {
            secret_key,
            token_lifetime: Duration::from_hours(24),
            cookie_name: "csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            form_field_name: "csrf_token".to_string(),
            same_site_policy: SameSite::Strict,
            secure_cookie: true,
            http_only: false, // Must be false for JavaScript access
            exempt_endpoints: vec![
                "/health".to_string(),
                "/metrics".to_string(),
                "/oauth/token".to_string(), // API endpoints
            ],
        }
    }
}

/// SameSite cookie policy
#[derive(Debug, Clone, Copy)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}

/// CSRF token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfToken {
    /// Random token value
    pub token: String,
    /// Token expiration timestamp
    pub expires_at: u64,
    /// Session identifier (optional)
    pub session_id: Option<String>,
}

impl CsrfToken {
    /// Create a new CSRF token
    pub fn new(lifetime: Duration, session_id: Option<String>) -> Self {
        let mut token_bytes = vec![0u8; 32];
        OsRng.fill_bytes(&mut token_bytes);
        let token = URL_SAFE_NO_PAD.encode(&token_bytes);
        
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + lifetime.as_secs();
        
        Self {
            token,
            expires_at,
            session_id,
        }
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }

    /// Generate HMAC signature for the token
    pub fn sign(&self, secret_key: &[u8]) -> Result<String, CsrfError> {
        let mut mac = HmacSha256::new_from_slice(secret_key)
            .map_err(|_| CsrfError::InvalidSecretKey)?;
        
        let payload = format!("{}:{}:{}", 
            self.token, 
            self.expires_at,
            self.session_id.as_deref().unwrap_or("")
        );
        
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        Ok(URL_SAFE_NO_PAD.encode(&signature))
    }

    /// Verify HMAC signature
    pub fn verify(&self, signature: &str, secret_key: &[u8]) -> Result<bool, CsrfError> {
        let expected_signature = self.sign(secret_key)?;
        Ok(constant_time_eq(signature.as_bytes(), expected_signature.as_bytes()))
    }
}

/// CSRF protection errors
#[derive(Debug, thiserror::Error)]
pub enum CsrfError {
    #[error("CSRF token missing")]
    TokenMissing,
    #[error("CSRF token invalid")]
    TokenInvalid,
    #[error("CSRF token expired")]
    TokenExpired,
    #[error("CSRF token signature invalid")]
    SignatureInvalid,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Token generation failed")]
    TokenGenerationFailed,
}

/// CSRF protection service
pub struct CsrfProtection {
    config: CsrfConfig,
    active_tokens: Arc<RwLock<HashMap<String, CsrfToken>>>,
}

impl CsrfProtection {
    /// Create new CSRF protection service
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            config,
            active_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate a new CSRF token
    pub async fn generate_token(&self, session_id: Option<String>) -> Result<(String, String), CsrfError> {
        let token = CsrfToken::new(self.config.token_lifetime, session_id.clone());
        let signature = token.sign(&self.config.secret_key)?;
        
        // Store token for validation
        {
            let mut tokens = self.active_tokens.write().await;
            tokens.insert(token.token.clone(), token.clone());
        }
        
        // Create signed token for client
        let signed_token = format!("{}:{}", token.token, signature);
        
        info!("Generated CSRF token for session: {:?}", session_id);
        Ok((token.token, signed_token))
    }

    /// Validate CSRF token
    pub async fn validate_token(
        &self,
        token_value: &str,
        signature: &str,
        session_id: Option<&str>,
    ) -> Result<(), CsrfError> {
        // Get token from storage
        let token = {
            let tokens = self.active_tokens.read().await;
            tokens.get(token_value)
                .cloned()
                .ok_or(CsrfError::TokenInvalid)?
        };

        // Check expiration
        if token.is_expired() {
            self.cleanup_expired_token(token_value).await;
            return Err(CsrfError::TokenExpired);
        }

        // Verify signature
        if !token.verify(signature, &self.config.secret_key)? {
            return Err(CsrfError::SignatureInvalid);
        }

        // Check session match if provided
        if let Some(session_id) = session_id {
            if token.session_id.as_deref() != Some(session_id) {
                return Err(CsrfError::TokenInvalid);
            }
        }

        info!("CSRF token validated successfully");
        Ok(())
    }

    /// Check if endpoint is exempt from CSRF protection
    pub fn is_exempt_endpoint(&self, path: &str) -> bool {
        self.config.exempt_endpoints.iter().any(|exempt| {
            path.starts_with(exempt)
        })
    }

    /// Generate cookie header for CSRF token
    pub fn generate_cookie_header(&self, signed_token: &str) -> String {
        format!(
            "{}={}; Path=/; SameSite={}{}{}{}",
            self.config.cookie_name,
            signed_token,
            self.config.same_site_policy,
            if self.config.secure_cookie { "; Secure" } else { "" },
            if self.config.http_only { "; HttpOnly" } else { "" },
            format!("; Max-Age={}", self.config.token_lifetime.as_secs())
        )
    }

    /// Extract token from request headers or form data
    pub fn extract_token_from_request(
        &self,
        headers: &HashMap<String, String>,
        form_data: Option<&HashMap<String, String>>,
    ) -> Option<(String, String)> {
        // Try header first
        if let Some(header_value) = headers.get(&self.config.header_name) {
            if let Some((token, signature)) = header_value.split_once(':') {
                return Some((token.to_string(), signature.to_string()));
            }
        }

        // Try form data
        if let Some(form) = form_data {
            if let Some(form_value) = form.get(&self.config.form_field_name) {
                if let Some((token, signature)) = form_value.split_once(':') {
                    return Some((token.to_string(), signature.to_string()));
                }
            }
        }

        None
    }

    /// Cleanup expired tokens
    pub async fn cleanup_expired_tokens(&self) {
        let mut tokens = self.active_tokens.write().await;
        let initial_count = tokens.len();
        
        tokens.retain(|_, token| !token.is_expired());
        
        let cleaned_count = initial_count - tokens.len();
        if cleaned_count > 0 {
            info!("Cleaned up {} expired CSRF tokens", cleaned_count);
        }
    }

    /// Remove specific token
    async fn cleanup_expired_token(&self, token_value: &str) {
        let mut tokens = self.active_tokens.write().await;
        tokens.remove(token_value);
    }

    /// Get token statistics
    pub async fn get_token_stats(&self) -> TokenStats {
        let tokens = self.active_tokens.read().await;
        let total_tokens = tokens.len();
        let expired_tokens = tokens.values().filter(|t| t.is_expired()).count();
        
        TokenStats {
            total_tokens,
            active_tokens: total_tokens - expired_tokens,
            expired_tokens,
        }
    }
}

/// Token statistics
#[derive(Debug, Serialize)]
pub struct TokenStats {
    pub total_tokens: usize,
    pub active_tokens: usize,
    pub expired_tokens: usize,
}

/// Middleware function for CSRF protection
pub async fn csrf_middleware(
    csrf: Arc<CsrfProtection>,
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    form_data: Option<&HashMap<String, String>>,
    session_id: Option<&str>,
) -> Result<(), CsrfError> {
    // Skip CSRF protection for safe methods
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return Ok(());
    }

    // Skip exempt endpoints
    if csrf.is_exempt_endpoint(path) {
        return Ok(());
    }

    // Extract and validate token
    let (token, signature) = csrf
        .extract_token_from_request(headers, form_data)
        .ok_or(CsrfError::TokenMissing)?;

    csrf.validate_token(&token, &signature, session_id).await?;

    info!("CSRF protection passed for {} {}", method, path);
    Ok(())
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_csrf_token_generation() {
        let config = CsrfConfig::default();
        let csrf = CsrfProtection::new(config);
        
        let (token, signed_token) = csrf.generate_token(Some("session123".to_string())).await.unwrap();
        
        assert!(!token.is_empty());
        assert!(signed_token.contains(':'));
    }

    #[tokio::test]
    async fn test_csrf_token_validation() {
        let config = CsrfConfig::default();
        let csrf = CsrfProtection::new(config);
        
        let (token, signed_token) = csrf.generate_token(Some("session123".to_string())).await.unwrap();
        let (token_part, signature_part) = signed_token.split_once(':').unwrap();
        
        // Valid token should pass
        assert!(csrf.validate_token(token_part, signature_part, Some("session123")).await.is_ok());
        
        // Invalid signature should fail
        assert!(csrf.validate_token(token_part, "invalid_signature", Some("session123")).await.is_err());
        
        // Wrong session should fail
        assert!(csrf.validate_token(token_part, signature_part, Some("wrong_session")).await.is_err());
    }

    #[test]
    fn test_exempt_endpoints() {
        let config = CsrfConfig::default();
        let csrf = CsrfProtection::new(config);
        
        assert!(csrf.is_exempt_endpoint("/health"));
        assert!(csrf.is_exempt_endpoint("/oauth/token"));
        assert!(!csrf.is_exempt_endpoint("/admin/users"));
    }

    #[test]
    fn test_cookie_header_generation() {
        let config = CsrfConfig::default();
        let csrf = CsrfProtection::new(config);
        
        let header = csrf.generate_cookie_header("token123:signature456");
        
        assert!(header.contains("csrf_token=token123:signature456"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Secure"));
    }

    #[test]
    fn test_token_extraction() {
        let config = CsrfConfig::default();
        let csrf = CsrfProtection::new(config);
        
        let mut headers = HashMap::new();
        headers.insert("X-CSRF-Token".to_string(), "token123:signature456".to_string());
        
        let (token, signature) = csrf.extract_token_from_request(&headers, None).unwrap();
        assert_eq!(token, "token123");
        assert_eq!(signature, "signature456");
    }

    #[tokio::test]
    async fn test_token_cleanup() {
        let mut config = CsrfConfig::default();
        config.token_lifetime = Duration::from_millis(1); // Very short lifetime
        
        let csrf = CsrfProtection::new(config);
        
        // Generate token
        let (token, _) = csrf.generate_token(None).await.unwrap();
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Cleanup should remove expired token
        csrf.cleanup_expired_tokens().await;
        
        let stats = csrf.get_token_stats().await;
        assert_eq!(stats.active_tokens, 0);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hello world"));
    }
}
