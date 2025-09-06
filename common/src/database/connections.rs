//! Database Connections
//!
//! Unified connection factory and management

use super::config::UnifiedDatabaseConfig;
use super::error::{DatabaseError, DatabaseResult};
use redis::Client as RedisClient;
use std::sync::Arc;

/// Database connections container
#[derive(Debug)]
pub struct DatabaseConnections {
    /// PostgreSQL connection string
    postgres_url: Option<String>,

    /// Redis client
    redis_client: Option<Arc<RedisClient>>,

    /// Configuration reference
    config: UnifiedDatabaseConfig,
}

impl DatabaseConnections {
    /// Create new database connections
    pub fn new(config: UnifiedDatabaseConfig) -> Self {
        Self {
            postgres_url: None,
            redis_client: None,
            config,
        }
    }

    /// Get PostgreSQL connection URL
    pub fn postgres_url(&self) -> Option<&str> {
        self.postgres_url.as_deref()
    }

    /// Get Redis client
    pub fn redis_client(&self) -> Option<&RedisClient> {
        self.redis_client.as_deref()
    }

    /// Get configuration
    pub fn config(&self) -> &UnifiedDatabaseConfig {
        &self.config
    }
}

/// Connection factory for creating database connections
pub struct ConnectionFactory {
    config: UnifiedDatabaseConfig,
}

impl ConnectionFactory {
    /// Create new connection factory
    pub fn new(config: &UnifiedDatabaseConfig) -> DatabaseResult<Self> {
        Ok(Self {
            config: config.clone(),
        })
    }

    /// Create all configured database connections
    pub async fn create_connections(&self) -> DatabaseResult<DatabaseConnections> {
        let mut connections = DatabaseConnections::new(self.config.clone());

        // Create PostgreSQL connection
        if let Some(pg_config) = self.config.postgres_config() {
            connections.postgres_url = Some(pg_config.url.clone());
        }

        // Create Redis connection
        if let Some(redis_config) = self.config.redis_config() {
            let client = self.create_redis_client(redis_config).await?;
            connections.redis_client = Some(Arc::new(client));
        }

        Ok(connections)
    }

    /// Create Redis client
    async fn create_redis_client(
        &self,
        redis_config: &crate::redis_config::UnifiedRedisConfig,
    ) -> DatabaseResult<RedisClient> {
        let client = RedisClient::open(redis_config.url.as_str()).map_err(|e| {
            DatabaseError::ConnectionError(format!("Redis connection failed: {}", e))
        })?;

        // Test the connection
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                DatabaseError::ConnectionError(format!("Redis connection test failed: {}", e))
            })?;

        // Use INFO command to verify connection
        let _: String = redis::cmd("INFO")
            .query_async(&mut conn)
            .await
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis info failed: {}", e)))?;

        Ok(client)
    }

    /// Test all connections
    pub async fn test_connections(&self) -> DatabaseResult<ConnectionTestResults> {
        let mut results = ConnectionTestResults::default();

        // Test PostgreSQL connection
        if let Some(pg_config) = self.config.postgres_config() {
            match self.test_postgres_connection(pg_config).await {
                Ok(_) => results.postgres_success = true,
                Err(e) => {
                    results.postgres_success = false;
                    results.postgres_error = Some(e.to_string());
                }
            }
        }

        // Test Redis connection
        if let Some(redis_config) = self.config.redis_config() {
            match self.test_redis_connection(redis_config).await {
                Ok(_) => results.redis_success = true,
                Err(e) => {
                    results.redis_success = false;
                    results.redis_error = Some(e.to_string());
                }
            }
        }

        Ok(results)
    }

    /// Test PostgreSQL connection
    async fn test_postgres_connection(
        &self,
        pg_config: &super::config::PostgresConfig,
    ) -> DatabaseResult<()> {
        use sqlx::postgres::PgConnectOptions;
        use sqlx::{Connection, PgConnection};

        let connect_options: PgConnectOptions = pg_config.url.parse().map_err(|e| {
            DatabaseError::ConnectionError(format!("Invalid PostgreSQL URL: {}", e))
        })?;

        let mut conn = PgConnection::connect_with(&connect_options)
            .await
            .map_err(|e| {
                DatabaseError::ConnectionError(format!("PostgreSQL connection failed: {}", e))
            })?;

        // Test query
        sqlx::query("SELECT 1")
            .execute(&mut conn)
            .await
            .map_err(|e| {
                DatabaseError::ConnectionError(format!("PostgreSQL test query failed: {}", e))
            })?;

        Ok(())
    }

    /// Test Redis connection
    async fn test_redis_connection(
        &self,
        redis_config: &crate::redis_config::UnifiedRedisConfig,
    ) -> DatabaseResult<()> {
        let client = RedisClient::open(redis_config.url.as_str()).map_err(|e| {
            DatabaseError::ConnectionError(format!("Redis client creation failed: {}", e))
        })?;

        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                DatabaseError::ConnectionError(format!("Redis connection failed: {}", e))
            })?;

        // Test with INFO command
        let _: String = redis::cmd("INFO")
            .query_async(&mut conn)
            .await
            .map_err(|e| DatabaseError::ConnectionError(format!("Redis info failed: {}", e)))?;

        Ok(())
    }

    /// Get connection health status
    pub async fn health_status(&self) -> DatabaseResult<ConnectionHealth> {
        let mut health = ConnectionHealth::default();

        // Check PostgreSQL
        if let Some(pg_config) = self.config.postgres_config() {
            health.postgres_configured = true;
            health.postgres_healthy = self.test_postgres_connection(pg_config).await.is_ok();
        }

        // Check Redis
        if let Some(redis_config) = self.config.redis_config() {
            health.redis_configured = true;
            health.redis_healthy = self.test_redis_connection(redis_config).await.is_ok();
        }

        Ok(health)
    }
}

/// Connection test results
#[derive(Debug, Default)]
pub struct ConnectionTestResults {
    pub postgres_success: bool,
    pub postgres_error: Option<String>,
    pub redis_success: bool,
    pub redis_error: Option<String>,
}

impl ConnectionTestResults {
    /// Check if all configured connections are successful
    pub fn all_successful(&self) -> bool {
        (!self.postgres_configured() || self.postgres_success)
            && (!self.redis_configured() || self.redis_success)
    }

    /// Check if PostgreSQL is configured
    pub fn postgres_configured(&self) -> bool {
        self.postgres_success || self.postgres_error.is_some()
    }

    /// Check if Redis is configured
    pub fn redis_configured(&self) -> bool {
        self.redis_success || self.redis_error.is_some()
    }

    /// Get summary of results
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();

        if self.postgres_configured() {
            if self.postgres_success {
                parts.push("PostgreSQL: OK".to_string());
            } else {
                parts.push(format!(
                    "PostgreSQL: FAILED ({})",
                    self.postgres_error
                        .as_ref()
                        .unwrap_or(&"Unknown error".to_string())
                ));
            }
        }

        if self.redis_configured() {
            if self.redis_success {
                parts.push("Redis: OK".to_string());
            } else {
                parts.push(format!(
                    "Redis: FAILED ({})",
                    self.redis_error
                        .as_ref()
                        .unwrap_or(&"Unknown error".to_string())
                ));
            }
        }

        if parts.is_empty() {
            "No databases configured".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Connection health status
#[derive(Debug, Default)]
pub struct ConnectionHealth {
    pub postgres_configured: bool,
    pub postgres_healthy: bool,
    pub redis_configured: bool,
    pub redis_healthy: bool,
}

impl ConnectionHealth {
    /// Check if all configured databases are healthy
    pub fn all_healthy(&self) -> bool {
        (!self.postgres_configured || self.postgres_healthy)
            && (!self.redis_configured || self.redis_healthy)
    }

    /// Get unhealthy databases
    pub fn unhealthy_databases(&self) -> Vec<&str> {
        let mut unhealthy = Vec::new();

        if self.postgres_configured && !self.postgres_healthy {
            unhealthy.push("PostgreSQL");
        }

        if self.redis_configured && !self.redis_healthy {
            unhealthy.push("Redis");
        }

        unhealthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::config::{DatabaseConfig, PoolConfig, PoolStrategy, PostgresConfig};
    use crate::redis_config::UnifiedRedisConfig;
    use std::time::Duration;

    fn create_test_postgres_config() -> PostgresConfig {
        PostgresConfig {
            url: "postgresql://test:test@localhost:5432/test_db".to_string(),
            max_connections: 5,
            connect_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(30),
            ssl_mode: "prefer".to_string(),
            database_name: "test_db".to_string(),
            schema_name: "public".to_string(),
            enable_logging: false,
            enable_prepared_statements: true,
        }
    }

    fn create_test_redis_config() -> UnifiedRedisConfig {
        UnifiedRedisConfig {
            url: "redis://localhost:6379".to_string(),
            max_connections: 10,
            timeout_ms: 5000,
            ttl_secs: 3600,
            enable_pooling: true,
            idle_timeout_secs: 300,
            max_retries: 3,
            retry_delay_ms: 100,
            enable_cluster: false,
            database: 0,
            keep_alive_secs: 30,
        }
    }

    fn create_test_unified_config() -> UnifiedDatabaseConfig {
        UnifiedDatabaseConfig {
            database: DatabaseConfig {
                postgres: Some(create_test_postgres_config()),
                redis: Some(create_test_redis_config()),
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
    fn test_database_connections_new() {
        let config = create_test_unified_config();
        let connections = DatabaseConnections::new(config.clone());

        assert!(connections.postgres_url.is_none());
        assert!(connections.redis_client.is_none());
        assert_eq!(connections.config.service_name, "test-service");
    }

    #[test]
    fn test_database_connections_accessors() {
        let config = create_test_unified_config();
        let mut connections = DatabaseConnections::new(config.clone());

        // Test postgres_url accessor
        assert!(connections.postgres_url().is_none());
        connections.postgres_url = Some("postgresql://test@localhost/db".to_string());
        assert_eq!(
            connections.postgres_url(),
            Some("postgresql://test@localhost/db")
        );

        // Test redis_client accessor
        assert!(connections.redis_client().is_none());

        // Test config accessor
        assert_eq!(connections.config().service_name, "test-service");
    }

    #[test]
    fn test_connection_factory_new() {
        let config = create_test_unified_config();
        let result = ConnectionFactory::new(&config);

        assert!(result.is_ok());
        let factory = result.unwrap();
        assert_eq!(factory.config.service_name, "test-service");
    }

    #[test]
    fn test_connection_test_results_default() {
        let results = ConnectionTestResults::default();

        assert!(!results.postgres_success);
        assert!(results.postgres_error.is_none());
        assert!(!results.redis_success);
        assert!(results.redis_error.is_none());
    }

    #[test]
    fn test_connection_test_results_all_successful() {
        let mut results = ConnectionTestResults::default();

        // No connections configured - should be successful
        assert!(results.all_successful());

        // PostgreSQL configured and successful
        results.postgres_success = true;
        assert!(results.all_successful());

        // PostgreSQL configured but failed
        results.postgres_success = false;
        results.postgres_error = Some("Connection failed".to_string());
        assert!(!results.all_successful());

        // Both configured and successful
        results.postgres_success = true;
        results.postgres_error = None;
        results.redis_success = true;
        assert!(results.all_successful());

        // Redis configured but failed
        results.redis_success = false;
        results.redis_error = Some("Redis failed".to_string());
        assert!(!results.all_successful());
    }

    #[test]
    fn test_connection_test_results_postgres_configured() {
        let mut results = ConnectionTestResults::default();

        // Not configured initially
        assert!(!results.postgres_configured());

        // Configured with success
        results.postgres_success = true;
        assert!(results.postgres_configured());

        // Reset and configure with error
        results.postgres_success = false;
        results.postgres_error = Some("Error".to_string());
        assert!(results.postgres_configured());
    }

    #[test]
    fn test_connection_test_results_redis_configured() {
        let mut results = ConnectionTestResults::default();

        // Not configured initially
        assert!(!results.redis_configured());

        // Configured with success
        results.redis_success = true;
        assert!(results.redis_configured());

        // Reset and configure with error
        results.redis_success = false;
        results.redis_error = Some("Error".to_string());
        assert!(results.redis_configured());
    }

    #[test]
    fn test_connection_test_results_summary() {
        let mut results = ConnectionTestResults::default();

        // No databases configured
        assert_eq!(results.summary(), "No databases configured");

        // PostgreSQL successful
        results.postgres_success = true;
        assert_eq!(results.summary(), "PostgreSQL: OK");

        // PostgreSQL failed
        results.postgres_success = false;
        results.postgres_error = Some("Connection timeout".to_string());
        assert_eq!(results.summary(), "PostgreSQL: FAILED (Connection timeout)");

        // Both databases configured - PostgreSQL failed, Redis successful
        results.redis_success = true;
        let summary = results.summary();
        assert!(summary.contains("PostgreSQL: FAILED"));
        assert!(summary.contains("Redis: OK"));

        // Both databases failed
        results.redis_success = false;
        results.redis_error = Some("Redis timeout".to_string());
        let summary = results.summary();
        assert!(summary.contains("PostgreSQL: FAILED (Connection timeout)"));
        assert!(summary.contains("Redis: FAILED (Redis timeout)"));
    }

    #[test]
    fn test_connection_health_default() {
        let health = ConnectionHealth::default();

        assert!(!health.postgres_configured);
        assert!(!health.postgres_healthy);
        assert!(!health.redis_configured);
        assert!(!health.redis_healthy);
    }

    #[test]
    fn test_connection_health_all_healthy() {
        let mut health = ConnectionHealth::default();

        // No databases configured - should be healthy
        assert!(health.all_healthy());

        // PostgreSQL configured and healthy
        health.postgres_configured = true;
        health.postgres_healthy = true;
        assert!(health.all_healthy());

        // PostgreSQL configured but unhealthy
        health.postgres_healthy = false;
        assert!(!health.all_healthy());

        // Both configured and healthy
        health.postgres_healthy = true;
        health.redis_configured = true;
        health.redis_healthy = true;
        assert!(health.all_healthy());

        // Redis configured but unhealthy
        health.redis_healthy = false;
        assert!(!health.all_healthy());
    }

    #[test]
    fn test_connection_health_unhealthy_databases() {
        let mut health = ConnectionHealth::default();

        // No databases configured
        assert!(health.unhealthy_databases().is_empty());

        // PostgreSQL configured but unhealthy
        health.postgres_configured = true;
        health.postgres_healthy = false;
        let unhealthy = health.unhealthy_databases();
        assert_eq!(unhealthy, vec!["PostgreSQL"]);

        // Redis also configured but unhealthy
        health.redis_configured = true;
        health.redis_healthy = false;
        let unhealthy = health.unhealthy_databases();
        assert_eq!(unhealthy, vec!["PostgreSQL", "Redis"]);

        // PostgreSQL becomes healthy
        health.postgres_healthy = true;
        let unhealthy = health.unhealthy_databases();
        assert_eq!(unhealthy, vec!["Redis"]);

        // All healthy
        health.redis_healthy = true;
        let unhealthy = health.unhealthy_databases();
        assert!(unhealthy.is_empty());
    }

    #[test]
    fn test_connection_test_results_summary_with_unknown_error() {
        let mut results = ConnectionTestResults {
            postgres_success: false,
            postgres_error: Some("temp".to_string()),
            ..Default::default()
        };

        // When an error is present, it's considered configured
        assert!(results.postgres_configured());

        // If we clear the error and success is false, it's not considered configured
        results.postgres_error = None;
        assert!(!results.postgres_configured());

        // Verify summary formatting when error string is empty
        results.postgres_success = false;
        results.postgres_error = Some("".to_string()); // Empty error string
        let summary = results.summary();
        assert!(summary.contains("PostgreSQL: FAILED ()"));
    }

    #[test]
    fn test_database_connections_debug() {
        let config = create_test_unified_config();
        let connections = DatabaseConnections::new(config);

        // Test that Debug trait is implemented (this will compile if Debug is derived)
        let debug_str = format!("{:?}", connections);
        assert!(debug_str.contains("DatabaseConnections"));
    }

    #[test]
    fn test_connection_factory_config_access() {
        let config = create_test_unified_config();
        let factory = ConnectionFactory::new(&config).unwrap();

        // Verify the factory stores the config correctly
        assert_eq!(factory.config.service_name, "test-service");
        assert_eq!(factory.config.environment, "test");
        assert!(factory.config.database.postgres.is_some());
        assert!(factory.config.database.redis.is_some());
    }

    #[test]
    fn test_connection_test_results_complex_scenarios() {
        // Test scenario: PostgreSQL succeeds, Redis fails
        let mut results = ConnectionTestResults {
            postgres_success: true,
            postgres_error: None,
            redis_success: false,
            redis_error: Some("Connection refused".to_string()),
        };

        assert!(!results.all_successful());
        assert!(results.postgres_configured());
        assert!(results.redis_configured());

        let summary = results.summary();
        assert!(summary.contains("PostgreSQL: OK"));
        assert!(summary.contains("Redis: FAILED (Connection refused)"));

        // Test scenario: Both fail with different errors
        results.postgres_success = false;
        results.postgres_error = Some("Authentication failed".to_string());

        assert!(!results.all_successful());
        let summary = results.summary();
        assert!(summary.contains("PostgreSQL: FAILED (Authentication failed)"));
        assert!(summary.contains("Redis: FAILED (Connection refused)"));
    }
}
