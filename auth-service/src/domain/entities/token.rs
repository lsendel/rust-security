//! Token Entity
//!
//! Represents authentication tokens in the system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::value_objects::UserId;

/// Token types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    Access,
    Refresh,
    ApiKey,
}

/// Token entity representing an authentication token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Unique token identifier
    pub id: String,

    /// User this token belongs to
    pub user_id: UserId,

    /// Token type
    pub token_type: TokenType,

    /// Token value (hashed for storage)
    pub token_hash: String,

    /// Token creation timestamp
    pub created_at: DateTime<Utc>,

    /// Token expiration timestamp
    pub expires_at: DateTime<Utc>,

    /// Whether the token is revoked
    pub is_revoked: bool,

    /// IP address that created the token
    pub created_ip: Option<String>,

    /// User agent that created the token
    pub user_agent: Option<String>,

    /// Associated session ID (for access tokens)
    pub session_id: Option<String>,
}

impl Token {
    /// Create a new access token
    pub fn new_access_token(
        user_id: UserId,
        token_hash: String,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            token_type: TokenType::Access,
            token_hash,
            created_at: Utc::now(),
            expires_at,
            is_revoked: false,
            created_ip: None,
            user_agent: None,
            session_id: None,
        }
    }

    /// Create a new refresh token
    pub fn new_refresh_token(
        user_id: UserId,
        token_hash: String,
        expires_at: DateTime<Utc>,
        session_id: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            token_type: TokenType::Refresh,
            token_hash,
            created_at: Utc::now(),
            expires_at,
            is_revoked: false,
            created_ip: None,
            user_agent: None,
            session_id: Some(session_id),
        }
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the token is active (not expired and not revoked)
    pub fn is_active(&self) -> bool {
        !self.is_expired() && !self.is_revoked
    }

    /// Revoke the token
    pub fn revoke(&mut self) {
        self.is_revoked = true;
    }

    /// Set the IP address
    pub fn with_ip(mut self, ip: String) -> Self {
        self.created_ip = Some(ip);
        self
    }

    /// Set the user agent
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::UserId;
    use chrono::Duration;

    #[test]
    fn test_access_token_creation() {
        let user_id = UserId::new();
        let expires_at = Utc::now() + Duration::hours(1);
        let token = Token::new_access_token(
            user_id,
            "hash123".to_string(),
            expires_at,
        );

        assert_eq!(token.token_type, TokenType::Access);
        assert!(!token.is_revoked);
        assert!(token.is_active());
    }

    #[test]
    fn test_refresh_token_creation() {
        let user_id = UserId::new();
        let expires_at = Utc::now() + Duration::days(30);
        let session_id = "session123".to_string();
        let token = Token::new_refresh_token(
            user_id,
            "hash123".to_string(),
            expires_at,
            session_id.clone(),
        );

        assert_eq!(token.token_type, TokenType::Refresh);
        assert_eq!(token.session_id, Some(session_id));
        assert!(!token.is_revoked);
    }

    #[test]
    fn test_token_expiration() {
        let user_id = UserId::new();
        let expires_at = Utc::now() - Duration::hours(1); // Already expired
        let token = Token::new_access_token(
            user_id,
            "hash123".to_string(),
            expires_at,
        );

        assert!(token.is_expired());
        assert!(!token.is_active());
    }

    #[test]
    fn test_token_revocation() {
        let user_id = UserId::new();
        let expires_at = Utc::now() + Duration::hours(1);
        let mut token = Token::new_access_token(
            user_id,
            "hash123".to_string(),
            expires_at,
        );

        assert!(token.is_active());
        token.revoke();
        assert!(!token.is_active());
    }
}
