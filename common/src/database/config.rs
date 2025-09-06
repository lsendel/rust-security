//! Database Configuration
//!
//! Unified configuration for all database connections and settings

use super::error::{DatabaseError, DatabaseResult};
use crate::redis_config::UnifiedRedisConfig;
use crate::types::ServiceConfig;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::Duration;
use url::Url;
use validator::Validate;

/// PostgreSQL connection configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PostgresConfig {
    /// Database URL
    #[validate(url)]
    pub url: String,

    /// Maximum number of connections in the pool
    #[validate(range(min = 1, max = 100))]
    pub max_connections: u32,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Query timeout
    pub query_timeout: Duration,

    /// Enable SSL
    pub ssl_mode: String,

    /// Database name
    pub database_name: String,

    /// Schema name
    pub schema_name: String,

    /// Enable query logging
    pub enable_logging: bool,

    /// Enable prepared statements
    pub enable_prepared_statements: bool,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/rust_security".to_string()),
            max_connections: 10,
            connect_timeout: Duration::from_secs(5),
            query_timeout: Duration::from_secs(30),
            ssl_mode: std::env::var("DATABASE_SSL_MODE").unwrap_or_else(|_| "prefer".to_string()), // Default to prefer SSL
            database_name: std::env::var("DATABASE_NAME")
                .unwrap_or_else(|_| "rust_security".to_string()),
            schema_name: std::env::var("DATABASE_SCHEMA").unwrap_or_else(|_| "public".to_string()),
            enable_logging: std::env::var("DATABASE_LOGGING")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            enable_prepared_statements: true,
        }
    }
}

/// Pool configuration for connection management
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PoolConfig {
    /// Minimum idle connections
    #[validate(range(min = 0, max = 50))]
    pub min_idle: u32,

    /// Maximum idle connections
    #[validate(range(min = 1, max = 100))]
    pub max_idle: u32,

    /// Connection idle timeout
    pub idle_timeout: Duration,

    /// Connection lifetime
    pub max_lifetime: Duration,

    /// Health check interval
    pub health_check_interval: Duration,

    /// Enable connection recycling
    pub enable_recycling: bool,

    /// Connection retry attempts
    #[validate(range(min = 0, max = 10))]
    pub retry_attempts: u32,

    /// Retry delay
    pub retry_delay: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_idle: 2,
            max_idle: 8,
            idle_timeout: Duration::from_secs(600), // 10 minutes
            max_lifetime: Duration::from_secs(3600), // 1 hour
            health_check_interval: Duration::from_secs(30),
            enable_recycling: true,
            retry_attempts: 3,
            retry_delay: Duration::from_secs(1),
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DatabaseConfig {
    /// PostgreSQL configuration
    pub postgres: Option<PostgresConfig>,

    /// Redis configuration
    pub redis: Option<UnifiedRedisConfig>,

    /// Pool configuration
    pub pool: PoolConfig,

    /// Enable migrations
    pub enable_migrations: bool,

    /// Enable health checks
    pub enable_health_checks: bool,

    /// Migration timeout
    pub migration_timeout: Duration,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            postgres: Some(PostgresConfig::default()),
            redis: Some(UnifiedRedisConfig::default()),
            pool: PoolConfig::default(),
            enable_migrations: true,
            enable_health_checks: true,
            migration_timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Unified database configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UnifiedDatabaseConfig {
    /// Database configuration
    #[validate(nested)]
    pub database: DatabaseConfig,

    /// Environment (development, production, test)
    pub environment: String,

    /// Service name for connection identification
    pub service_name: String,

    /// Connection pool strategy
    pub pool_strategy: PoolStrategy,

    /// Enable metrics collection
    pub enable_metrics: bool,

    /// Enable distributed tracing
    pub enable_tracing: bool,
}

/// Pool strategy for different workloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoolStrategy {
    /// Optimized for high throughput
    HighThroughput,

    /// Optimized for low latency
    LowLatency,

    /// Balanced configuration
    Balanced,

    /// Custom configuration
    Custom(PoolConfig),
}

impl Default for UnifiedDatabaseConfig {
    fn default() -> Self {
        Self {
            database: DatabaseConfig::default(),
            environment: "development".to_string(),
            service_name: "rust-security".to_string(),
            pool_strategy: PoolStrategy::Balanced,
            enable_metrics: true,
            enable_tracing: true,
        }
    }
}

impl UnifiedDatabaseConfig {
    /// Validate database URL for security issues
    fn validate_database_url(url: &str) -> DatabaseResult<()> {
        // Parse the URL
        let parsed_url = Url::parse(url).map_err(|_| {
            DatabaseError::ConfigurationError("Invalid database URL format".to_string())
        })?;

        // Check scheme
        if !matches!(parsed_url.scheme(), "postgresql" | "postgres") {
            return Err(DatabaseError::ConfigurationError(
                "Database URL must use postgresql:// or postgres:// scheme".to_string(),
            ));
        }

        // Check for embedded credentials (security risk in logs)
        if parsed_url.username() != "" || parsed_url.password().is_some() {
            return Err(DatabaseError::ConfigurationError(
                "Database credentials should not be embedded in URL. Use connection string without credentials.".to_string()
            ));
        }

        // Validate SSL requirement for production
        let ssl_mode = std::env::var("DATABASE_SSL_MODE").unwrap_or_else(|_| "require".to_string());
        if ssl_mode == "disable"
            && std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string())
                == "production"
        {
            return Err(DatabaseError::ConfigurationError(
                "SSL must be enabled for production database connections".to_string(),
            ));
        }

        Ok(())
    }

    /// Load configuration from environment variables
    pub fn from_env() -> DatabaseResult<Self> {
        let mut config = Self::default();

        // Environment
        if let Ok(env) = env::var("ENVIRONMENT") {
            config.environment = env;
        }

        // Service name
        if let Ok(service) = env::var("SERVICE_NAME") {
            config.service_name = service;
        }

        // PostgreSQL configuration
        if let Ok(postgres_url) = env::var("DATABASE_URL") {
            // Validate database URL for security issues
            Self::validate_database_url(&postgres_url)?;
            let mut pg_config = PostgresConfig {
                url: postgres_url,
                ..Default::default()
            };

            if let Ok(max_conns) = env::var("DATABASE_MAX_CONNECTIONS") {
                pg_config.max_connections = max_conns.parse().map_err(|_| {
                    DatabaseError::ConfigurationError(
                        "Invalid DATABASE_MAX_CONNECTIONS".to_string(),
                    )
                })?;
            }

            if let Ok(db_name) = env::var("DATABASE_NAME") {
                pg_config.database_name = db_name;
            }

            config.database.postgres = Some(pg_config);
        }

        // Redis configuration from environment
        if env::var("REDIS_URL").is_ok() {
            config.database.redis = Some(UnifiedRedisConfig::from_env().map_err(|e| {
                DatabaseError::ConfigurationError(format!("Redis config error: {}", e))
            })?);
        }

        // Pool strategy
        if let Ok(strategy) = env::var("POOL_STRATEGY") {
            config.pool_strategy = match strategy.as_str() {
                "high_throughput" => PoolStrategy::HighThroughput,
                "low_latency" => PoolStrategy::LowLatency,
                "balanced" => PoolStrategy::Balanced,
                _ => PoolStrategy::Balanced,
            };
        }

        // Metrics and tracing
        config.enable_metrics = env::var("ENABLE_METRICS")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        config.enable_tracing = env::var("ENABLE_TRACING")
            .unwrap_or_else(|_| "true".to_string())
            .parse()
            .unwrap_or(true);

        // Validate configuration
        use crate::types::ServiceConfig;
        let validation_result = ServiceConfig::validate(&config);
        if !validation_result.valid {
            return Err(DatabaseError::ValidationError(
                validation_result.errors.join(", "),
            ));
        }

        Ok(config)
    }

    /// Get effective pool configuration based on strategy
    pub fn effective_pool_config(&self) -> PoolConfig {
        match &self.pool_strategy {
            PoolStrategy::HighThroughput => PoolConfig {
                min_idle: 5,
                max_idle: 20,
                idle_timeout: Duration::from_secs(300),
                max_lifetime: Duration::from_secs(1800),
                ..self.database.pool.clone()
            },
            PoolStrategy::LowLatency => PoolConfig {
                min_idle: 8,
                max_idle: 15,
                idle_timeout: Duration::from_secs(900),
                max_lifetime: Duration::from_secs(7200),
                ..self.database.pool.clone()
            },
            PoolStrategy::Balanced => self.database.pool.clone(),
            PoolStrategy::Custom(config) => config.clone(),
        }
    }

    /// Check if PostgreSQL is enabled
    pub fn has_postgres(&self) -> bool {
        self.database.postgres.is_some()
    }

    /// Check if Redis is enabled
    pub fn has_redis(&self) -> bool {
        self.database.redis.is_some()
    }

    /// Get PostgreSQL configuration
    pub fn postgres_config(&self) -> Option<&PostgresConfig> {
        self.database.postgres.as_ref()
    }

    /// Get Redis configuration
    pub fn redis_config(&self) -> Option<&UnifiedRedisConfig> {
        self.database.redis.as_ref()
    }
}

impl crate::types::ServiceConfig for UnifiedDatabaseConfig {
    fn validate(&self) -> crate::types::ValidationResult {
        let mut errors = Vec::new();
        let warnings = Vec::new();

        // Basic validation - in production, add comprehensive checks
        if self.database.pool.max_idle == 0 {
            errors.push("max_idle must be > 0".to_string());
        }

        crate::types::ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }
}
