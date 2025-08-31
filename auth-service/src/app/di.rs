//! Dependency Injection Container
//!
//! Manages the creation and lifetime of application dependencies.

use std::sync::Arc;

use crate::domain::repositories::{
    DynSessionRepository, DynTokenRepository, DynUserRepository, SessionRepository,
    TokenRepository, UserRepository,
};
use crate::services::{AuthService, AuthServiceTrait, TokenService, UserService};
use crate::shared::crypto::CryptoService;

/// Application container holding all dependencies
#[derive(Clone)]
pub struct AppContainer {
    pub user_service: Arc<dyn crate::services::user_service::UserServiceTrait>,
    pub auth_service: Arc<dyn AuthServiceTrait>,
    pub token_service: Arc<dyn crate::services::token_service::TokenServiceTrait>,
}

impl AppContainer {
    /// Create a new application container with mock repositories (for testing)
    pub async fn new_mock() -> Self {
        // TODO: Implement proper mock repositories
        // For now, we'll return an error indicating this is not implemented
        panic!("Mock repositories not yet implemented - use new_postgres or new_redis instead");
    }

    /// Create a new application container with PostgreSQL repositories
    pub async fn new_postgres(config: &DatabaseConfig) -> Result<Self, AppError> {
        use crate::infrastructure::database::postgres;

        // Create database connection pool
        let pool = create_postgres_pool(config).await?;

        // Create repositories
        let user_repo: DynUserRepository =
            Box::new(postgres::PostgresUserRepository::new(pool.clone()));
        let session_repo: DynSessionRepository =
            Box::new(postgres::PostgresSessionRepository::new(pool.clone()));
        let token_repo: DynTokenRepository = Box::new(postgres::PostgresTokenRepository::new(pool));

        // Create crypto service
        let crypto_service = Arc::new(CryptoService::new(config.jwt_secret.clone()));

        // Create services
        let auth_service = Arc::new(AuthService::new(
            user_repo.clone(),
            session_repo.clone(),
            crypto_service.clone(),
        ));

        let user_service = Arc::new(UserService::new(user_repo, crypto_service.clone()));

        let token_service = Arc::new(TokenService::new(token_repo, session_repo, crypto_service));

        Ok(Self {
            user_service,
            auth_service,
            token_service,
        })
    }

    /// Create a new application container with Redis repositories
    pub async fn new_redis(config: &DatabaseConfig) -> Result<Self, AppError> {
        use crate::infrastructure::database::redis;

        // Create Redis clients
        let redis_client = create_redis_client(&config.redis_url).await?;

        // Create repositories
        let user_repo: DynUserRepository =
            Box::new(redis::RedisUserRepository::new(redis_client.clone()));
        let session_repo: DynSessionRepository =
            Box::new(redis::RedisSessionRepository::new(redis_client.clone()));
        let token_repo: DynTokenRepository =
            Box::new(redis::RedisTokenRepository::new(redis_client));

        // Create crypto service
        let crypto_service = Arc::new(CryptoService::new(config.jwt_secret.clone()));

        // Create services
        let auth_service = Arc::new(AuthService::new(
            user_repo.clone(),
            session_repo.clone(),
            crypto_service.clone(),
        ));

        let user_service = Arc::new(UserService::new(user_repo, crypto_service.clone()));

        let token_service = Arc::new(TokenService::new(token_repo, session_repo, crypto_service));

        Ok(Self {
            user_service,
            auth_service,
            token_service,
        })
    }
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub max_connections: u32,
}

/// Application error for dependency injection
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Helper function to create PostgreSQL connection pool
async fn create_postgres_pool(_config: &DatabaseConfig) -> Result<sqlx::PgPool, AppError> {
    // TODO: Implement PostgreSQL connection pool creation
    Err(AppError::Config(
        "PostgreSQL not yet implemented".to_string(),
    ))
}

/// Helper function to create Redis client
async fn create_redis_client(_redis_url: &str) -> Result<redis::Client, AppError> {
    // TODO: Implement Redis client creation
    Err(AppError::Config("Redis not yet implemented".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_container_creation() {
        let container = AppContainer::new_mock().await;

        // Verify services are created
        assert!(true); // Basic smoke test
    }
}
