//! Unified Database Operations Module
//!
//! This module consolidates all database operations to eliminate duplication across
//! the rust-security codebase. It provides unified connection management, repository
//! patterns, and storage abstractions for PostgreSQL, Redis, and other databases.

pub mod config;
pub mod connections;
pub mod error;
pub mod migrations;
pub mod pools;
pub mod repositories;

// Re-export main types for convenience
pub use config::{DatabaseConfig, PoolConfig, UnifiedDatabaseConfig};
pub use connections::{ConnectionFactory, DatabaseConnections};
pub use error::{DatabaseError, DatabaseResult};
pub use pools::{DatabasePools, PoolManager};
pub use repositories::{Repository, RepositoryManager};

/// Database operations manager that coordinates all database-related functionality
#[derive(Debug)]
pub struct DatabaseOperations {
    config: UnifiedDatabaseConfig,
    connections: DatabaseConnections,
    pools: DatabasePools,
    repositories: RepositoryManager,
}

impl DatabaseOperations {
    /// Create new database operations instance
    pub async fn new(config: UnifiedDatabaseConfig) -> DatabaseResult<Self> {
        // Initialize connection factory
        let connection_factory = ConnectionFactory::new(&config)?;

        // Create connections
        let connections = connection_factory.create_connections().await?;

        // Initialize pools
        let pools = DatabasePools::new(&config, &connections).await?;

        // Create repositories
        let repositories = RepositoryManager::new(&pools);

        Ok(Self {
            config,
            connections,
            pools,
            repositories,
        })
    }

    /// Get database pools
    pub fn pools(&self) -> &DatabasePools {
        &self.pools
    }

    /// Get repository manager
    pub fn repositories(&self) -> &RepositoryManager {
        &self.repositories
    }

    /// Get database connections
    pub fn connections(&self) -> &DatabaseConnections {
        &self.connections
    }

    /// Get configuration
    pub fn config(&self) -> &UnifiedDatabaseConfig {
        &self.config
    }

    /// Health check for all database connections
    pub async fn health_check(&self) -> DatabaseResult<()> {
        // Delegate to pools for proper separation of concerns
        let health_status = self.pools.health_check().await?;

        if !health_status.postgres_healthy && self.pools.postgresql().is_some() {
            return Err(DatabaseError::ConnectionError(
                health_status
                    .postgres_error
                    .unwrap_or_else(|| "PostgreSQL health check failed".to_string()),
            ));
        }

        if !health_status.redis_healthy && self.pools.redis().is_some() {
            return Err(DatabaseError::ConnectionError(
                health_status
                    .redis_error
                    .unwrap_or_else(|| "Redis health check failed".to_string()),
            ));
        }

        Ok(())
    }

    /// Run database migrations
    pub async fn run_migrations(&self) -> DatabaseResult<()> {
        if let Some(_pg_pool) = self.pools.postgresql() {
            // TODO: Implement embedded migrations without external directory
            // For now, just log that migration would run
            tracing::info!("Migrations would run here when implemented");
        }
        Ok(())
    }
}

/// Builder for database operations
pub struct DatabaseOperationsBuilder {
    config: Option<UnifiedDatabaseConfig>,
    enable_migrations: bool,
    enable_health_checks: bool,
}

impl DatabaseOperationsBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            config: None,
            enable_migrations: false,
            enable_health_checks: true,
        }
    }

    /// Set configuration
    pub fn with_config(mut self, config: UnifiedDatabaseConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Enable migrations
    pub fn with_migrations(mut self) -> Self {
        self.enable_migrations = true;
        self
    }

    /// Enable health checks
    pub fn with_health_checks(mut self, enabled: bool) -> Self {
        self.enable_health_checks = enabled;
        self
    }

    /// Build database operations
    pub async fn build(self) -> DatabaseResult<DatabaseOperations> {
        let config = self.config.ok_or_else(|| {
            DatabaseError::ConfigurationError("Database configuration is required".to_string())
        })?;

        let ops = DatabaseOperations::new(config).await?;

        if self.enable_migrations {
            ops.run_migrations().await?;
        }

        if self.enable_health_checks {
            ops.health_check().await?;
        }

        Ok(ops)
    }
}

impl Default for DatabaseOperationsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::database::config::{DatabaseConfig, PoolConfig, PoolStrategy, PostgresConfig};
    use std::time::Duration;

    fn create_test_config() -> UnifiedDatabaseConfig {
        UnifiedDatabaseConfig {
            database: DatabaseConfig {
                postgres: Some(PostgresConfig {
                    url: "postgresql://test:test@localhost:5432/test_db".to_string(),
                    max_connections: 5,
                    connect_timeout: Duration::from_secs(5),
                    query_timeout: Duration::from_secs(30),
                    ssl_mode: "prefer".to_string(),
                    database_name: "test_db".to_string(),
                    schema_name: "public".to_string(),
                    enable_logging: false,
                    enable_prepared_statements: true,
                }),
                redis: None,
                pool: PoolConfig {
                    min_idle: 2,
                    max_idle: 8,
                    idle_timeout: Duration::from_secs(600),
                    max_lifetime: Duration::from_secs(3600),
                    health_check_interval: Duration::from_secs(30),
                    enable_recycling: true,
                    retry_attempts: 3,
                    retry_delay: Duration::from_secs(1),
                },
                enable_migrations: true,
                enable_health_checks: true,
                migration_timeout: Duration::from_secs(300),
            },
            environment: "test".to_string(),
            service_name: "test-service".to_string(),
            pool_strategy: PoolStrategy::Balanced,
            enable_metrics: false,
            enable_tracing: false,
        }
    }

    #[test]
    fn test_database_operations_builder_new() {
        let builder = DatabaseOperationsBuilder::new();
        assert!(builder.config.is_none());
        assert!(!builder.enable_migrations);
        assert!(builder.enable_health_checks);
    }

    #[test]
    fn test_database_operations_builder_default() {
        let builder = DatabaseOperationsBuilder::default();
        assert!(builder.config.is_none());
        assert!(!builder.enable_migrations);
        assert!(builder.enable_health_checks);
    }

    #[test]
    fn test_database_operations_builder_with_config() {
        let config = create_test_config();
        let builder = DatabaseOperationsBuilder::new().with_config(config.clone());

        assert!(builder.config.is_some());
        let builder_config = builder.config.unwrap();
        assert!(builder_config.database.postgres.is_some());
        assert_eq!(
            builder_config.database.postgres.unwrap().database_name,
            "test_db"
        );
    }

    #[test]
    fn test_database_operations_builder_with_migrations() {
        let builder = DatabaseOperationsBuilder::new().with_migrations();
        assert!(builder.enable_migrations);
    }

    #[test]
    fn test_database_operations_builder_with_health_checks() {
        let builder = DatabaseOperationsBuilder::new().with_health_checks(false);
        assert!(!builder.enable_health_checks);

        let builder = DatabaseOperationsBuilder::new().with_health_checks(true);
        assert!(builder.enable_health_checks);
    }

    #[tokio::test]
    async fn test_database_operations_builder_build_without_config_fails() {
        let builder = DatabaseOperationsBuilder::new();
        let result = builder.build().await;

        assert!(result.is_err());
        match result.unwrap_err() {
            DatabaseError::ConfigurationError(msg) => {
                assert_eq!(msg, "Database configuration is required");
            }
            _ => panic!("Expected ConfigurationError"),
        }
    }

    #[test]
    fn test_postgres_config_validation() {
        let config = PostgresConfig {
            url: "postgresql://test:test@localhost:5432/test_db".to_string(),
            max_connections: 5,
            ..Default::default()
        };

        // This should be valid
        assert_eq!(config.database_name, "rust_security");
        assert_eq!(config.schema_name, "public");
        assert!(config.enable_prepared_statements);
    }

    #[test]
    fn test_postgres_config_default_values() {
        let config = PostgresConfig::default();

        assert_eq!(config.url, "postgresql://localhost/rust_security");
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.query_timeout, Duration::from_secs(30));
        assert_eq!(config.ssl_mode, "prefer");
        assert_eq!(config.database_name, "rust_security");
        assert_eq!(config.schema_name, "public");
        assert!(config.enable_logging);
        assert!(config.enable_prepared_statements);
    }

    #[test]
    fn test_database_error_display() {
        let error = DatabaseError::ConfigurationError("test config error".to_string());
        assert_eq!(error.to_string(), "Configuration error: test config error");

        let error = DatabaseError::ConnectionError("connection failed".to_string());
        assert_eq!(error.to_string(), "Connection error: connection failed");

        let error = DatabaseError::PoolError("pool exhausted".to_string());
        assert_eq!(error.to_string(), "Pool error: pool exhausted");

        let error = DatabaseError::NotFound("user not found".to_string());
        assert_eq!(error.to_string(), "Not found: user not found");

        let error = DatabaseError::ValidationError("invalid data".to_string());
        assert_eq!(error.to_string(), "Validation error: invalid data");
    }

    #[test]
    fn test_database_error_types() {
        // Test that all error variants can be created
        let errors = vec![
            DatabaseError::PoolError("test".to_string()),
            DatabaseError::ConnectionError("test".to_string()),
            DatabaseError::ConfigurationError("test".to_string()),
            DatabaseError::MigrationError("test".to_string()),
            DatabaseError::SerializationError("test".to_string()),
            DatabaseError::TimeoutError("test".to_string()),
            DatabaseError::TransactionError("test".to_string()),
            DatabaseError::RepositoryError("test".to_string()),
            DatabaseError::ValidationError("test".to_string()),
            DatabaseError::NotFound("test".to_string()),
            DatabaseError::AlreadyExists("test".to_string()),
            DatabaseError::DeadpoolError("test".to_string()),
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();

        assert_eq!(config.min_idle, 2);
        assert_eq!(config.max_idle, 8);
        assert_eq!(config.idle_timeout, Duration::from_secs(600));
        assert_eq!(config.max_lifetime, Duration::from_secs(3600));
        assert_eq!(config.health_check_interval, Duration::from_secs(30));
        assert!(config.enable_recycling);
        assert_eq!(config.retry_attempts, 3);
        assert_eq!(config.retry_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_unified_database_config_creation() {
        let postgres_config = PostgresConfig::default();
        let pool_config = PoolConfig::default();

        let config = UnifiedDatabaseConfig {
            database: DatabaseConfig {
                postgres: Some(postgres_config.clone()),
                redis: None,
                pool: pool_config.clone(),
                enable_migrations: true,
                enable_health_checks: true,
                migration_timeout: Duration::from_secs(300),
            },
            environment: "test".to_string(),
            service_name: "test-service".to_string(),
            pool_strategy: PoolStrategy::Balanced,
            enable_metrics: false,
            enable_tracing: false,
        };

        assert!(config.database.postgres.is_some());
        assert!(config.database.redis.is_none());
        assert_eq!(
            config.database.postgres.unwrap().database_name,
            postgres_config.database_name
        );
    }

    #[test]
    fn test_builder_chaining() {
        let config = create_test_config();
        let builder = DatabaseOperationsBuilder::new()
            .with_config(config)
            .with_migrations()
            .with_health_checks(false);

        assert!(builder.config.is_some());
        assert!(builder.enable_migrations);
        assert!(!builder.enable_health_checks);
    }

    // Example tests using mock implementations

    #[tokio::test]
    async fn test_database_operations_with_mocks() {
        use crate::mocks::{MockConnectionFactory, MockDatabaseConnection};

        // Create mock connections for testing
        let mock_factory = MockConnectionFactory::new();

        // Test successful connections
        let result = mock_factory.test_connections().await.unwrap();
        assert!(result.all_successful());
        assert_eq!(result.summary(), "PostgreSQL: OK, Redis: OK");

        // Test PostgreSQL operations
        if let Some(pg_mock) = mock_factory.postgres() {
            assert!(pg_mock.health_check().await.is_ok());

            // Test query operations
            let query_result = pg_mock.query("SELECT * FROM users").await.unwrap();
            assert!(query_result.row_count() > 0);

            // Test execute operations
            let affected = pg_mock
                .execute("INSERT INTO users (name) VALUES ('test')")
                .await
                .unwrap();
            assert_eq!(affected, 1);
        }

        // Test Redis operations
        if let Some(redis_mock) = mock_factory.redis() {
            assert!(redis_mock.health_check().await.is_ok());

            // Test key-value operations
            assert!(redis_mock.set("test_key", "test_value").await.is_ok());
            assert_eq!(
                redis_mock.get("test_key").await.unwrap(),
                Some("test_value".to_string())
            );
            assert!(redis_mock.del("test_key").await.is_ok());
            assert_eq!(redis_mock.get("test_key").await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn test_database_operations_with_failing_mocks() {
        use crate::mocks::MockConnectionFactory;

        // Create failing mock connections
        let failing_factory = MockConnectionFactory::failing();

        // Test that connections fail as expected
        let result = failing_factory.test_connections().await.unwrap();
        assert!(!result.all_successful());
        assert!(result.summary().contains("FAILED"));

        // Test that individual operations fail
        if let Some(pg_mock) = failing_factory.postgres() {
            assert!(pg_mock.health_check().await.is_err());
            assert!(pg_mock.query("SELECT 1").await.is_err());
            assert!(pg_mock
                .execute("INSERT INTO test VALUES (1)")
                .await
                .is_err());
        }

        if let Some(redis_mock) = failing_factory.redis() {
            assert!(redis_mock.health_check().await.is_err());
            assert!(redis_mock.set("key", "value").await.is_err());
            assert!(redis_mock.get("key").await.is_err());
        }
    }

    #[tokio::test]
    async fn test_partial_database_configuration_with_mocks() {
        use crate::mocks::MockConnectionFactory;

        // Test with only PostgreSQL enabled
        let mut factory = MockConnectionFactory::new();
        factory.with_redis(false);

        let result = factory.test_connections().await.unwrap();
        assert!(result.postgres_configured);
        assert!(!result.redis_configured);
        assert!(result.all_successful());

        // Test with only Redis enabled
        let mut factory = MockConnectionFactory::new();
        factory.with_postgres(false);

        let result = factory.test_connections().await.unwrap();
        assert!(!result.postgres_configured);
        assert!(result.redis_configured);
        assert!(result.all_successful());
    }

    // Mock tests for functionality that requires actual database connections
    // These test the error handling and validation logic

    #[test]
    fn test_database_operations_accessors() {
        // Since we can't easily create DatabaseOperations without a real DB,
        // we test that the struct fields and methods are properly defined
        // by checking that they compile and have the expected signatures

        // This function tests that all the accessor methods exist and have correct signatures
        fn _test_compilation(ops: &DatabaseOperations) {
            let _pools = ops.pools();
            let _repos = ops.repositories();
            let _connections = ops.connections();
            let _config = ops.config();
        }

        // This test passes since the above function exists and compiles
        // We can't actually call it without a real DatabaseOperations instance
    }
}
