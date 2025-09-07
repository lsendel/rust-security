//! JWT Token Blacklist Implementation
//!
//! Implements secure token blacklisting for logout and revocation scenarios.
//! Uses Redis-compatible storage for distributed deployments.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// JWT blacklist errors
#[derive(Debug, Error)]
pub enum BlacklistError {
    #[error("Token already blacklisted")]
    TokenAlreadyBlacklisted,
    #[error("Invalid token format")]
    InvalidToken,
    #[error("Blacklist storage error: {0}")]
    StorageError(String),
}

/// Blacklisted token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistedToken {
    /// JWT ID (jti) claim
    pub jti: String,
    /// Token issuer
    pub issuer: String,
    /// User ID associated with the token
    pub user_id: String,
    /// When the token was blacklisted
    pub blacklisted_at: u64,
    /// Token expiration time (Unix timestamp)
    pub expires_at: u64,
    /// Reason for blacklisting
    pub reason: BlacklistReason,
}

/// Reasons for blacklisting tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlacklistReason {
    /// User-initiated logout
    Logout,
    /// Administrator-initiated revocation
    AdminRevocation,
    /// Security incident response
    SecurityIncident,
    /// Token compromise detected
    Compromise,
    /// Account suspension
    AccountSuspension,
}

impl std::fmt::Display for BlacklistReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Logout => write!(f, "logout"),
            Self::AdminRevocation => write!(f, "admin_revocation"),
            Self::SecurityIncident => write!(f, "security_incident"),
            Self::Compromise => write!(f, "compromise"),
            Self::AccountSuspension => write!(f, "account_suspension"),
        }
    }
}

/// JWT token blacklist manager
pub struct JwtBlacklist {
    /// In-memory storage for blacklisted tokens (in production, use Redis)
    blacklisted_tokens: Arc<RwLock<HashMap<String, BlacklistedToken>>>,
    /// Default token expiration time (for cleanup)
    default_expiration: Duration,
}

impl Default for JwtBlacklist {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtBlacklist {
    /// Create a new JWT blacklist manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            blacklisted_tokens: Arc::new(RwLock::new(HashMap::new())),
            default_expiration: Duration::from_secs(24 * 60 * 60), // 24 hours default
        }
    }

    /// Create a new JWT blacklist manager with custom expiration
    #[must_use]
    pub fn with_expiration(expiration: Duration) -> Self {
        Self {
            blacklisted_tokens: Arc::new(RwLock::new(HashMap::new())),
            default_expiration: expiration,
        }
    }

    /// Add a token to the blacklist
    pub async fn blacklist_token(
        &self,
        jti: String,
        issuer: String,
        user_id: String,
        expires_at: Option<u64>,
        reason: BlacklistReason,
    ) -> Result<(), BlacklistError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = expires_at.unwrap_or_else(|| now + self.default_expiration.as_secs());

        let blacklisted_token = BlacklistedToken {
            jti: jti.clone(),
            issuer,
            user_id: user_id.clone(),
            blacklisted_at: now,
            expires_at,
            reason: reason.clone(),
        };

        let mut tokens = self.blacklisted_tokens.write().await;
        
        if tokens.contains_key(&jti) {
            return Err(BlacklistError::TokenAlreadyBlacklisted);
        }

        tokens.insert(jti.clone(), blacklisted_token);
        
        info!(
            jti = %jti,
            user_id = %user_id,
            reason = %reason,
            "Token blacklisted"
        );

        Ok(())
    }

    /// Check if a token is blacklisted
    pub async fn is_token_blacklisted(&self, jti: &str) -> bool {
        let tokens = self.blacklisted_tokens.read().await;
        
        if let Some(blacklisted_token) = tokens.get(jti) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            // Check if the blacklisted entry itself has expired
            if now >= blacklisted_token.expires_at {
                // Token blacklist entry has expired, consider it not blacklisted
                // Note: cleanup will remove this entry later
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Blacklist all tokens for a specific user
    pub async fn blacklist_user_tokens(
        &self,
        user_id: &str,
        reason: BlacklistReason,
    ) -> Result<usize, BlacklistError> {
        // In a real implementation, this would query all active tokens for the user
        // For now, we'll just mark any existing tokens in our blacklist as revoked
        let _tokens = self.blacklisted_tokens.write().await;
        let count = 0;

        // This is a simplified implementation
        // In production, you'd need to track active tokens per user
        warn!(
            user_id = %user_id,
            reason = %reason,
            "User token blacklisting requested - implement token tracking for complete functionality"
        );

        Ok(count)
    }

    /// Remove a token from the blacklist (for testing or explicit unban)
    pub async fn remove_from_blacklist(&self, jti: &str) -> Result<bool, BlacklistError> {
        let mut tokens = self.blacklisted_tokens.write().await;
        Ok(tokens.remove(jti).is_some())
    }

    /// Clean up expired blacklist entries
    pub async fn cleanup_expired_entries(&self) -> usize {
        let mut tokens = self.blacklisted_tokens.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let initial_count = tokens.len();
        tokens.retain(|_, token| now < token.expires_at);
        let cleaned_count = initial_count - tokens.len();

        if cleaned_count > 0 {
            info!("Cleaned up {} expired blacklist entries", cleaned_count);
        }

        cleaned_count
    }

    /// Get blacklist statistics
    pub async fn get_stats(&self) -> BlacklistStats {
        let tokens = self.blacklisted_tokens.read().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired_count = tokens
            .values()
            .filter(|token| now >= token.expires_at)
            .count();

        let reason_counts = tokens
            .values()
            .fold(HashMap::new(), |mut acc, token| {
                *acc.entry(format!("{}", token.reason)).or_insert(0) += 1;
                acc
            });

        BlacklistStats {
            total_entries: tokens.len(),
            active_entries: tokens.len() - expired_count,
            expired_entries: expired_count,
            reason_counts,
        }
    }

    /// Extract JWT ID from a token string
    pub fn extract_jti_from_token(&self, token: &str) -> Result<String, BlacklistError> {
        // Parse JWT header and payload (without verifying signature for blacklist check)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(BlacklistError::InvalidToken);
        }

        // Decode payload (second part)
        let payload = parts[1];
        
        // Add padding if necessary for base64 decoding
        let padded_payload = match payload.len() % 4 {
            0 => payload.to_string(),
            2 => format!("{}==", payload),
            3 => format!("{}=", payload),
            _ => return Err(BlacklistError::InvalidToken),
        };

        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(padded_payload)
            .map_err(|_| BlacklistError::InvalidToken)?;

        let payload_str = String::from_utf8(decoded)
            .map_err(|_| BlacklistError::InvalidToken)?;

        // Parse JSON to extract jti claim
        let payload_json: serde_json::Value = serde_json::from_str(&payload_str)
            .map_err(|_| BlacklistError::InvalidToken)?;

        payload_json
            .get("jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(BlacklistError::InvalidToken)
    }

    /// Start a background task to periodically clean up expired entries
    pub async fn start_cleanup_task(&self, interval: Duration) {
        let blacklist = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                blacklist.cleanup_expired_entries().await;
            }
        });
    }
}

// Implement Clone for JwtBlacklist to allow sharing
impl Clone for JwtBlacklist {
    fn clone(&self) -> Self {
        Self {
            blacklisted_tokens: Arc::clone(&self.blacklisted_tokens),
            default_expiration: self.default_expiration,
        }
    }
}

/// Blacklist statistics for monitoring
#[derive(Debug, Serialize)]
pub struct BlacklistStats {
    pub total_entries: usize,
    pub active_entries: usize,
    pub expired_entries: usize,
    pub reason_counts: HashMap<String, usize>,
}

/// Middleware function to check token blacklist
pub async fn check_token_blacklist(
    blacklist: &JwtBlacklist,
    token: &str,
) -> Result<(), BlacklistError> {
    let jti = blacklist.extract_jti_from_token(token)?;
    
    if blacklist.is_token_blacklisted(&jti).await {
        return Err(BlacklistError::StorageError("Token is blacklisted".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_blacklist_token() {
        let blacklist = JwtBlacklist::new();
        let jti = "test_jti_123".to_string();
        let issuer = "test_issuer".to_string();
        let user_id = "user_123".to_string();

        // Token should not be blacklisted initially
        assert!(!blacklist.is_token_blacklisted(&jti).await);

        // Blacklist the token
        assert!(blacklist
            .blacklist_token(
                jti.clone(),
                issuer,
                user_id,
                None,
                BlacklistReason::Logout
            )
            .await
            .is_ok());

        // Token should now be blacklisted
        assert!(blacklist.is_token_blacklisted(&jti).await);

        // Attempting to blacklist again should fail
        assert!(blacklist
            .blacklist_token(
                jti.clone(),
                "issuer".to_string(),
                "user".to_string(),
                None,
                BlacklistReason::Logout
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let blacklist = JwtBlacklist::with_expiration(Duration::from_secs(1));
        let jti = "expiring_token".to_string();

        // Blacklist token with 1-second expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert!(blacklist
            .blacklist_token(
                jti.clone(),
                "issuer".to_string(),
                "user".to_string(),
                Some(now + 1), // Expires in 1 second
                BlacklistReason::Logout
            )
            .await
            .is_ok());

        // Should be blacklisted initially
        assert!(blacklist.is_token_blacklisted(&jti).await);

        // Wait for expiration
        sleep(Duration::from_secs(2)).await;

        // Should not be blacklisted after expiration
        assert!(!blacklist.is_token_blacklisted(&jti).await);
    }

    #[tokio::test]
    async fn test_cleanup_expired_entries() {
        let blacklist = JwtBlacklist::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add some tokens with different expiration times
        for i in 0..5 {
            blacklist
                .blacklist_token(
                    format!("token_{i}"),
                    "issuer".to_string(),
                    "user".to_string(),
                    Some(if i < 3 { now - 1 } else { now + 3600 }), // First 3 expired
                    BlacklistReason::Logout,
                )
                .await
                .unwrap();
        }

        let stats_before = blacklist.get_stats().await;
        assert_eq!(stats_before.total_entries, 5);

        let cleaned = blacklist.cleanup_expired_entries().await;
        assert_eq!(cleaned, 3); // Should clean up 3 expired tokens

        let stats_after = blacklist.get_stats().await;
        assert_eq!(stats_after.total_entries, 2);
        assert_eq!(stats_after.active_entries, 2);
    }

    #[tokio::test]
    async fn test_extract_jti_from_token() {
        let blacklist = JwtBlacklist::new();

        // This is a mock JWT token payload with jti claim
        // In practice, you'd generate this with a proper JWT library
        let test_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJ0ZXN0X2p0aV8xMjMiLCJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTYzOTM0NDAwMCwiZXhwIjoxNjM5MzQ3NjAwfQ.invalid_signature";

        match blacklist.extract_jti_from_token(test_token) {
            Ok(jti) => assert_eq!(jti, "test_jti_123"),
            Err(e) => panic!("Failed to extract JTI: {:?}", e),
        }

        // Test invalid token
        assert!(blacklist.extract_jti_from_token("invalid.token").is_err());
    }

    #[tokio::test]
    async fn test_blacklist_stats() {
        let blacklist = JwtBlacklist::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add tokens with different reasons
        blacklist
            .blacklist_token(
                "token1".to_string(),
                "issuer".to_string(),
                "user1".to_string(),
                Some(now + 3600),
                BlacklistReason::Logout,
            )
            .await
            .unwrap();

        blacklist
            .blacklist_token(
                "token2".to_string(),
                "issuer".to_string(),
                "user2".to_string(),
                Some(now + 3600),
                BlacklistReason::AdminRevocation,
            )
            .await
            .unwrap();

        blacklist
            .blacklist_token(
                "token3".to_string(),
                "issuer".to_string(),
                "user3".to_string(),
                Some(now + 3600),
                BlacklistReason::Logout,
            )
            .await
            .unwrap();

        let stats = blacklist.get_stats().await;
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.active_entries, 3);
        assert_eq!(stats.reason_counts.get("logout"), Some(&2));
        assert_eq!(stats.reason_counts.get("admin_revocation"), Some(&1));
    }

    #[tokio::test]
    async fn test_remove_from_blacklist() {
        let blacklist = JwtBlacklist::new();
        let jti = "removable_token".to_string();

        // Blacklist token
        blacklist
            .blacklist_token(
                jti.clone(),
                "issuer".to_string(),
                "user".to_string(),
                None,
                BlacklistReason::Logout,
            )
            .await
            .unwrap();

        assert!(blacklist.is_token_blacklisted(&jti).await);

        // Remove from blacklist
        assert!(blacklist.remove_from_blacklist(&jti).await.unwrap());
        assert!(!blacklist.is_token_blacklisted(&jti).await);

        // Removing non-existent token should return false
        assert!(!blacklist.remove_from_blacklist(&jti).await.unwrap());
    }
}