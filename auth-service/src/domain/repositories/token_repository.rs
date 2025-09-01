//! Token Repository Interface
//!
//! Defines the contract for token data access operations.

use async_trait::async_trait;
use chrono::Utc;

use crate::domain::entities::{Token, TokenType};
use crate::domain::value_objects::UserId;

/// Token repository errors
#[derive(Debug, thiserror::Error)]
pub enum TokenRepositoryError {
    #[error("Token not found")]
    NotFound,
    #[error("Token already exists")]
    AlreadyExists,
    #[error("Database error: {0}")]
    Database(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("Connection error: {0}")]
    Connection(String),
}

/// Token repository trait
#[async_trait]
pub trait TokenRepository: Send + Sync {
    /// Find a token by its hash
    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<Token>, TokenRepositoryError>;

    /// Find all active tokens for a user
    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Token>, TokenRepositoryError>;

    /// Find tokens by type for a user
    async fn find_by_user_and_type(
        &self,
        user_id: &UserId,
        token_type: &TokenType,
    ) -> Result<Vec<Token>, TokenRepositoryError>;

    /// Save a new token
    async fn save(&self, token: &Token) -> Result<(), TokenRepositoryError>;

    /// Update an existing token
    async fn update(&self, token: &Token) -> Result<(), TokenRepositoryError>;

    /// Delete a token by hash
    async fn delete_by_hash(&self, token_hash: &str) -> Result<(), TokenRepositoryError>;

    /// Delete all tokens for a user
    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), TokenRepositoryError>;

    /// Delete all tokens for a user of a specific type
    async fn delete_by_user_and_type(
        &self,
        user_id: &UserId,
        token_type: &TokenType,
    ) -> Result<(), TokenRepositoryError>;

    /// Revoke a token by hash
    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), TokenRepositoryError>;

    /// Revoke all tokens for a user
    async fn revoke_by_user_id(&self, user_id: &UserId) -> Result<(), TokenRepositoryError>;

    /// Delete expired tokens
    async fn delete_expired(&self) -> Result<i64, TokenRepositoryError>;

    /// Check if a token exists and is active
    async fn exists_and_active(&self, token_hash: &str) -> Result<bool, TokenRepositoryError>;

    /// Count active tokens for a user
    async fn count_active_by_user(&self, user_id: &UserId) -> Result<i64, TokenRepositoryError>;
}

/// Type alias for token repository trait object  
pub type DynTokenRepository = std::sync::Arc<dyn TokenRepository>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::{Token, TokenType};
    use crate::domain::value_objects::UserId;
    use std::collections::HashMap;
    use std::sync::RwLock;

    // Mock implementation for testing
    pub(crate) struct MockTokenRepository {
        tokens: RwLock<HashMap<String, Token>>,
    }

    impl MockTokenRepository {
        pub fn new() -> Self {
            Self {
                tokens: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl TokenRepository for MockTokenRepository {
        async fn find_by_hash(
            &self,
            token_hash: &str,
        ) -> Result<Option<Token>, TokenRepositoryError> {
            let tokens = self.tokens.read().unwrap();
            Ok(tokens.get(token_hash).cloned())
        }

        async fn find_by_user_id(
            &self,
            user_id: &UserId,
        ) -> Result<Vec<Token>, TokenRepositoryError> {
            let tokens = self.tokens.read().unwrap();
            let user_tokens = tokens
                .values()
                .filter(|t| t.user_id == *user_id)
                .cloned()
                .collect();
            Ok(user_tokens)
        }

        async fn find_by_user_and_type(
            &self,
            user_id: &UserId,
            token_type: &TokenType,
        ) -> Result<Vec<Token>, TokenRepositoryError> {
            let tokens = self.tokens.read().unwrap();
            let user_tokens = tokens
                .values()
                .filter(|t| t.user_id == *user_id && t.token_type == *token_type)
                .cloned()
                .collect();
            Ok(user_tokens)
        }

        async fn save(&self, token: &Token) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            if tokens.contains_key(&token.token_hash) {
                return Err(TokenRepositoryError::AlreadyExists);
            }
            tokens.insert(token.token_hash.clone(), token.clone());
            Ok(())
        }

        async fn update(&self, token: &Token) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            if !tokens.contains_key(&token.token_hash) {
                return Err(TokenRepositoryError::NotFound);
            }
            tokens.insert(token.token_hash.clone(), token.clone());
            Ok(())
        }

        async fn delete_by_hash(&self, token_hash: &str) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            if tokens.remove(token_hash).is_none() {
                return Err(TokenRepositoryError::NotFound);
            }
            Ok(())
        }

        async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            tokens.retain(|_, token| token.user_id != *user_id);
            Ok(())
        }

        async fn delete_by_user_and_type(
            &self,
            user_id: &UserId,
            token_type: &TokenType,
        ) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            tokens
                .retain(|_, token| !(token.user_id == *user_id && token.token_type == *token_type));
            Ok(())
        }

        async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            if let Some(token) = tokens.get_mut(token_hash) {
                token.revoke();
                Ok(())
            } else {
                Err(TokenRepositoryError::NotFound)
            }
        }

        async fn revoke_by_user_id(&self, user_id: &UserId) -> Result<(), TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            for token in tokens.values_mut() {
                if token.user_id == *user_id {
                    token.revoke();
                }
            }
            Ok(())
        }

        async fn delete_expired(&self) -> Result<i64, TokenRepositoryError> {
            let mut tokens = self.tokens.write().unwrap();
            let before_count = tokens.len();
            let now = Utc::now();
            tokens.retain(|_, token| !token.is_expired());
            let deleted_count = before_count - tokens.len();
            Ok(deleted_count as i64)
        }

        async fn exists_and_active(&self, token_hash: &str) -> Result<bool, TokenRepositoryError> {
            let tokens = self.tokens.read().unwrap();
            if let Some(token) = tokens.get(token_hash) {
                Ok(token.is_active())
            } else {
                Ok(false)
            }
        }

        async fn count_active_by_user(
            &self,
            user_id: &UserId,
        ) -> Result<i64, TokenRepositoryError> {
            let tokens = self.tokens.read().unwrap();
            let count = tokens
                .values()
                .filter(|t| t.user_id == *user_id && t.is_active())
                .count();
            Ok(count as i64)
        }
    }
}
