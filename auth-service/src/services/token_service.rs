//! Token Service
//!
//! Business logic for token management operations.

use async_trait::async_trait;
use std::sync::Arc;

use crate::domain::entities::{Token, TokenType};
use crate::domain::repositories::{TokenRepository, SessionRepository, DynTokenRepository, DynSessionRepository};
use crate::domain::value_objects::UserId;
use crate::shared::crypto::CryptoService;

/// Token service errors
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("Token not found")]
    NotFound,
    #[error("Token expired")]
    Expired,
    #[error("Token revoked")]
    Revoked,
    #[error("Invalid token")]
    Invalid,
    #[error("Repository error: {0}")]
    Repository(#[from] crate::domain::repositories::RepositoryError),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// Token service trait
#[async_trait]
pub trait TokenServiceTrait: Send + Sync {
    async fn revoke_token(&self, token_hash: &str) -> Result<(), TokenError>;
    async fn revoke_all_user_tokens(&self, user_id: &UserId) -> Result<(), TokenError>;
    async fn validate_token(&self, token_hash: &str) -> Result<Token, TokenError>;
    async fn cleanup_expired_tokens(&self) -> Result<i64, TokenError>;
    async fn get_user_tokens(&self, user_id: &UserId) -> Result<Vec<Token>, TokenError>;
}

/// Token service implementation
pub struct TokenService {
    token_repo: DynTokenRepository,
    session_repo: DynSessionRepository,
    crypto_service: Arc<CryptoService>,
}

impl TokenService {
    /// Create a new token service
    pub fn new(
        token_repo: DynTokenRepository,
        session_repo: DynSessionRepository,
        crypto_service: Arc<CryptoService>,
    ) -> Self {
        Self {
            token_repo,
            session_repo,
            crypto_service,
        }
    }
}

#[async_trait]
impl TokenServiceTrait for TokenService {
    async fn revoke_token(&self, token_hash: &str) -> Result<(), TokenError> {
        self.token_repo.revoke_by_hash(token_hash).await?;
        Ok(())
    }

    async fn revoke_all_user_tokens(&self, user_id: &UserId) -> Result<(), TokenError> {
        self.token_repo.revoke_by_user_id(user_id).await?;
        Ok(())
    }

    async fn validate_token(&self, token_hash: &str) -> Result<Token, TokenError> {
        let token = self.token_repo
            .find_by_hash(token_hash)
            .await?
            .ok_or(TokenError::NotFound)?;

        if !token.is_active() {
            if token.is_expired() {
                return Err(TokenError::Expired);
            } else {
                return Err(TokenError::Revoked);
            }
        }

        Ok(token)
    }

    async fn cleanup_expired_tokens(&self) -> Result<i64, TokenError> {
        let count = self.token_repo.delete_expired().await?;
        Ok(count)
    }

    async fn get_user_tokens(&self, user_id: &UserId) -> Result<Vec<Token>, TokenError> {
        let tokens = self.token_repo.find_by_user_id(user_id).await?;
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::repositories::token_repository::MockTokenRepository;
    use crate::domain::repositories::session_repository::MockSessionRepository;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_token_service_creation() {
        let token_repo = Arc::new(MockTokenRepository::new());
        let session_repo = Arc::new(MockSessionRepository::new());
        let crypto = Arc::new(crate::shared::crypto::CryptoService::new("test".to_string()));

        let service = TokenService::new(token_repo, session_repo, crypto);
        assert!(true); // Basic smoke test
    }
}
