use redis::aio::MultiplexedConnection;
use redis::{Client, RedisError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Simple error type for token operations
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Redis connection error: {0}")]
    Connection(#[from] RedisError),
    #[error("Token not found")]
    NotFound,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Simple token storage data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    pub user_id: String,
    pub expires_at: u64,
    pub permissions: Vec<String>,
}

/// Simple async Redis token storage for MVP
pub struct AsyncTokenStorage {
    client: Client,
}

impl AsyncTokenStorage {
    /// Create a new async token storage with simple Redis connection
    pub fn new(redis_url: &str) -> Result<Self, TokenError> {
        let client = Client::open(redis_url)?;
        Ok(Self { client })
    }

    /// Store a token with associated data
    pub async fn store_token(&self, token: &str, data: &TokenData) -> Result<(), TokenError> {
        let mut conn = self.get_connection().await?;

        let json_data =
            serde_json::to_string(data).map_err(|e| TokenError::Serialization(e.to_string()))?;

        redis::cmd("SET")
            .arg(format!("token:{token}"))
            .arg(&json_data)
            .arg("EX")
            .arg(3600) // 1 hour expiration
            .query_async::<()>(&mut conn)
            .await?;

        Ok(())
    }

    /// Get token data
    pub async fn get_token(&self, token: &str) -> Result<Option<TokenData>, TokenError> {
        let mut conn = self.get_connection().await?;

        let result: Option<String> = redis::cmd("GET")
            .arg(format!("token:{token}"))
            .query_async(&mut conn)
            .await?;

        match result {
            Some(json_data) => {
                let data: TokenData = serde_json::from_str(&json_data)
                    .map_err(|e| TokenError::Serialization(e.to_string()))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Delete a token
    pub async fn delete_token(&self, token: &str) -> Result<bool, TokenError> {
        let mut conn = self.get_connection().await?;

        let deleted: i32 = redis::cmd("DEL")
            .arg(format!("token:{token}"))
            .query_async(&mut conn)
            .await?;

        Ok(deleted > 0)
    }

    /// Get an async Redis connection
    async fn get_connection(&self) -> Result<MultiplexedConnection, TokenError> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(TokenError::Connection)
    }
}

/// Utility function to create token data
#[must_use] pub const fn create_token_data(user_id: String, expires_at: u64, permissions: Vec<String>) -> TokenData {
    TokenData {
        user_id,
        expires_at,
        permissions,
    }
}

/// Check if token is expired
#[must_use] pub fn is_token_expired(data: &TokenData) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    data.expires_at < now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_storage_basic_operations() {
        // This test would need a running Redis instance
        // For now, we'll just test token data creation and expiration

        let token_data = create_token_data(
            "user123".to_string(),
            9999999999, // Far future
            vec!["read".to_string(), "write".to_string()],
        );

        assert_eq!(token_data.user_id, "user123");
        assert!(!is_token_expired(&token_data));

        let expired_data = create_token_data(
            "user123".to_string(),
            1, // Far past
            vec!["read".to_string()],
        );

        assert!(is_token_expired(&expired_data));
    }

    #[test]
    fn test_token_expiration() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_data = create_token_data(
            "user1".to_string(),
            current_time + 3600, // 1 hour from now
            vec!["read".to_string()],
        );

        let expired_data = create_token_data(
            "user2".to_string(),
            current_time - 3600, // 1 hour ago
            vec!["read".to_string()],
        );

        assert!(!is_token_expired(&valid_data));
        assert!(is_token_expired(&expired_data));
    }
}
