//! Dependency Injection Container
//!
//! Manages the creation and lifetime of application dependencies.

use std::sync::Arc;

use crate::health_check::HealthChecker;
use crate::infrastructure::monitoring::MetricsCollector;
use crate::services::AuthServiceTrait;

/// Application container holding all dependencies
#[derive(Clone)]
pub struct AppContainer {
    pub user_service: Arc<dyn crate::services::user_service::UserServiceTrait>,
    pub auth_service: Arc<dyn AuthServiceTrait>,
    pub token_service: Arc<dyn crate::services::token_service::TokenServiceTrait>,
    pub metrics_collector: Arc<MetricsCollector>,
    pub health_checker: Arc<HealthChecker>,
}

impl AppContainer {
    /// Create a new application container with mock repositories (for testing)
    ///
    /// This creates a fully functional container with mock implementations
    /// of all services, suitable for unit testing and integration testing.
    #[cfg(test)]
    #[must_use]
    pub fn new_mock() -> Self {
        use crate::mocks::auth_service::MockAuthService;
        use crate::mocks::health_checker::MockHealthChecker;
        use crate::mocks::metrics_collector::MockMetricsCollector;
        use crate::mocks::token_service::MockTokenService;
        use crate::mocks::user_service::MockUserService;

        Self {
            user_service: Arc::new(MockUserService::new()),
            auth_service: Arc::new(MockAuthService::new()),
            token_service: Arc::new(MockTokenService::new()),
            metrics_collector: Arc::new(MockMetricsCollector::new().into()),
            health_checker: Arc::new(MockHealthChecker::new().into()),
        }
    }

    /*
    /// Create a new application container with PostgreSQL repositories
    #[cfg(feature = "postgres")]
    pub async fn new_postgres(config: &DatabaseConfig) -> Result<Self, AppError> {
        use crate::infrastructure::database::postgres;

        // Create database connection pool
        let pool = create_postgres_pool(config).await?;

        // Create repositories
        let user_repo: DynUserRepository =
            Arc::new(postgres::PostgresUserRepository::new(Arc::new(pool.clone())));
        let session_repo: DynSessionRepository =
            Arc::new(postgres::PostgresSessionRepository::new(Arc::new(pool.clone())));
        let token_repo: DynTokenRepository = Arc::new(postgres::PostgresTokenRepository::new(Arc::new(pool)));

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

        // Create monitoring components
        let metrics_collector = Arc::new(MetricsCollector::new()
            .map_err(|e| AppError::Config(format!("Failed to create metrics collector: {e}")))?);
        let health_checker = Arc::new(HealthChecker::new());

        Ok(Self {
            user_service,
            auth_service,
            token_service,
            metrics_collector,
            health_checker,
        })
    }
    */

    /*
    /// Create a new application container with Redis repositories
    pub async fn new_redis(config: &DatabaseConfig) -> Result<Self, AppError> {
        use crate::infrastructure::database::redis;

        // Create Redis clients
        let redis_client = create_redis_client(&config.redis_url).await?;

        // Create repositories
        let redis_client = Arc::new(redis_client);
        let user_repo: DynUserRepository =
            Arc::new(redis::RedisUserRepository::new(redis_client.clone()));
        let session_repo: DynSessionRepository =
            Arc::new(redis::RedisSessionRepository::new(redis_client.clone()));
        let token_repo: DynTokenRepository =
            Arc::new(redis::RedisTokenRepository::new(redis_client));

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

        // Create monitoring components
        let metrics_collector = Arc::new(MetricsCollector::new()
            .map_err(|e| AppError::Config(format!("Failed to create metrics collector: {e}")))?);
        let health_checker = Arc::new(HealthChecker::new());

        Ok(Self {
            user_service,
            auth_service,
            token_service,
            metrics_collector,
            health_checker,
        })
    }
    */
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
    #[cfg(feature = "postgres")]
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    // #[error("Redis error: {0}")]
    // Redis(#[from] redis::RedisError),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// Helper function to create `PostgreSQL` connection pool
#[cfg(feature = "postgres")]
#[allow(dead_code)] // TODO: Will be used when PostgreSQL implementation is completed
fn create_postgres_pool(_config: &DatabaseConfig) -> Result<sqlx::PgPool, AppError> {
    // TODO: Implement PostgreSQL connection pool creation
    Err(AppError::Config(
        "PostgreSQL not yet implemented".to_string(),
    ))
}

// /// Helper function to create Redis client
// async fn create_redis_client(_redis_url: &str) -> Result<redis::Client, AppError> {
//     // TODO: Implement Redis client creation
//     Err(AppError::Config("Redis not yet implemented".to_string()))
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_container_creation() {
        let container = AppContainer::new_mock();

        // Verify that the container was created successfully (smoke test)
        // Services exist (Arc pointers are non-null)
        // Just verify they can be accessed without panicking
        let _user_service = &container.user_service;
        let _auth_service = &container.auth_service; 
        let _token_service = &container.token_service;
    }
}
