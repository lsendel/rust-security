//! Mock implementation of `TokenServiceTrait` for testing

use async_trait::async_trait;
use chrono::Utc;

use crate::domain::entities::token::TokenType;
use crate::domain::entities::Token;
use crate::domain::value_objects::UserId;
use crate::services::token_service::{TokenError, TokenServiceTrait};

/// Mock token service for testing
pub struct MockTokenService;

impl MockTokenService {
    /// Create a new mock token service
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockTokenService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TokenServiceTrait for MockTokenService {
    async fn revoke_token(&self, _token_hash: &str) -> Result<(), TokenError> {
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, _user_id: &UserId) -> Result<(), TokenError> {
        Ok(())
    }

    async fn validate_token(&self, _token_hash: &str) -> Result<Token, TokenError> {
        // Return a mock token for validation
        Ok(Token {
            id: "mock-token-id".to_string(),
            user_id: UserId::new(),
            token_type: TokenType::Refresh,
            token_hash: "mock_hash".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            is_revoked: false,
            created_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("Mock User Agent".to_string()),
            session_id: None,
        })
    }

    async fn cleanup_expired_tokens(&self) -> Result<i64, TokenError> {
        Ok(0)
    }

    async fn get_user_tokens(&self, _user_id: &UserId) -> Result<Vec<Token>, TokenError> {
        Ok(vec![])
    }
}
