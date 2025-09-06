//! Database Connection Pools
//!
//! Unified connection pool management for PostgreSQL and Redis

use super::config::{PoolConfig, UnifiedDatabaseConfig};
use super::connections::DatabaseConnections;
use super::error::{DatabaseError, DatabaseResult};
use deadpool_redis::{Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Database connection pools manager
#[derive(Clone, Debug)]
pub struct DatabasePools {
    /// PostgreSQL connection pool
    postgres: Option<PgPool>,

    /// Redis connection pool
    redis: Option<RedisPool>,

    /// Configuration
    config: UnifiedDatabaseConfig,

    /// Pool metrics
    metrics: Arc<RwLock<PoolMetrics>>,
}

/// Pool metrics for monitoring
#[derive(Debug, Default, Clone)]
pub struct PoolMetrics {
    /// Total connections created
    pub total_connections: u64,

    /// Active connections
    pub active_connections: u32,

    /// Idle connections
    pub idle_connections: u32,

    /// Failed connection attempts
    pub failed_connections: u64,

    /// Average connection time
    pub avg_connection_time: Duration,

    /// Pool hits
    pub pool_hits: u64,

    /// Pool misses
    pub pool_misses: u64,
}

impl DatabasePools {
    /// Create new database pools
    pub async fn new(
        config: &UnifiedDatabaseConfig,
        _connections: &DatabaseConnections,
    ) -> DatabaseResult<Self> {
        let mut pools = Self {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        // Initialize PostgreSQL pool
        if let Some(pg_config) = config.postgres_config() {
            pools.postgres = Some(pools.create_postgres_pool(pg_config).await?);
        }

        // Initialize Redis pool
        if let Some(redis_config) = config.redis_config() {
            pools.redis = Some(pools.create_redis_pool(redis_config).await?);
        }

        Ok(pools)
    }

    /// Create PostgreSQL connection pool
    async fn create_postgres_pool(
        &self,
        pg_config: &super::config::PostgresConfig,
    ) -> DatabaseResult<PgPool> {
        let pool_config = self.config.effective_pool_config();

        let pool = PgPoolOptions::new()
            .max_connections(pg_config.max_connections)
            .min_connections(pool_config.min_idle)
            .max_lifetime(Some(pool_config.max_lifetime))
            .idle_timeout(Some(pool_config.idle_timeout))
            .acquire_timeout(pg_config.connect_timeout)
            .test_before_acquire(true)
            .connect(&pg_config.url)
            .await?;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.total_connections += pg_config.max_connections as u64;

        Ok(pool)
    }

    /// Create Redis connection pool
    async fn create_redis_pool(
        &self,
        redis_config: &crate::redis_config::UnifiedRedisConfig,
    ) -> DatabaseResult<RedisPool> {
        let pool_config = self.config.effective_pool_config();

        let cfg = RedisPoolConfig::from_url(&redis_config.url);

        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| DatabaseError::PoolError(format!("Redis pool creation failed: {}", e)))?;

        // Test connection
        let conn = pool.get().await?;
        drop(conn);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.total_connections += pool_config.max_idle as u64;

        Ok(pool)
    }

    /// Get PostgreSQL pool
    pub fn postgresql(&self) -> Option<&PgPool> {
        self.postgres.as_ref()
    }

    /// Get Redis pool
    pub fn redis(&self) -> Option<&RedisPool> {
        self.redis.as_ref()
    }

    /// Get pool metrics
    pub async fn metrics(&self) -> PoolMetrics {
        let mut metrics = self.metrics.write().await;

        // Update current connection counts
        if let Some(pg_pool) = &self.postgres {
            metrics.active_connections = pg_pool.size();
            metrics.idle_connections = pg_pool.num_idle() as u32;
        }

        metrics.clone()
    }

    /// Health check for all pools
    pub async fn health_check(&self) -> DatabaseResult<PoolHealthStatus> {
        let mut status = PoolHealthStatus::default();

        // Check PostgreSQL pool
        if let Some(pg_pool) = &self.postgres {
            match sqlx::query("SELECT 1").execute(pg_pool).await {
                Ok(_) => status.postgres_healthy = true,
                Err(e) => {
                    status.postgres_healthy = false;
                    status.postgres_error = Some(e.to_string());
                }
            }
        }

        // Check Redis pool
        if let Some(redis_pool) = &self.redis {
            match redis_pool.get().await {
                Ok(_) => status.redis_healthy = true,
                Err(e) => {
                    status.redis_healthy = false;
                    status.redis_error = Some(e.to_string());
                }
            }
        }

        Ok(status)
    }

    /// Close all pools
    pub async fn close(&self) -> DatabaseResult<()> {
        // PostgreSQL pools close automatically when dropped
        if let Some(_pg_pool) = &self.postgres {
            // sqlx PgPool doesn't have an explicit close method
            // It will be closed when the pool is dropped
        }

        // Redis pools also close when dropped
        if let Some(_redis_pool) = &self.redis {
            // deadpool doesn't require explicit closing
        }

        Ok(())
    }

    /// Get pool statistics
    pub async fn statistics(&self) -> PoolStatistics {
        let metrics = self.metrics().await;

        let mut stats = PoolStatistics {
            postgres_stats: None,
            redis_stats: None,
            total_connections: metrics.total_connections,
            failed_connections: metrics.failed_connections,
            pool_hit_rate: if metrics.pool_hits + metrics.pool_misses > 0 {
                metrics.pool_hits as f64 / (metrics.pool_hits + metrics.pool_misses) as f64
            } else {
                0.0
            },
            avg_connection_time: metrics.avg_connection_time,
        };

        // PostgreSQL stats
        if let Some(pg_pool) = &self.postgres {
            stats.postgres_stats = Some(PostgresPoolStats {
                size: pg_pool.size(),
                idle: pg_pool.num_idle() as u32,
                connections_created: metrics.total_connections,
            });
        }

        // Redis stats
        if let Some(redis_pool) = &self.redis {
            stats.redis_stats = Some(RedisPoolStats {
                size: redis_pool.status().size,
                available: redis_pool.status().available,
                max_size: redis_pool.status().max_size,
            });
        }

        stats
    }
}

/// Pool health status
#[derive(Debug, Default)]
pub struct PoolHealthStatus {
    pub postgres_healthy: bool,
    pub postgres_error: Option<String>,
    pub redis_healthy: bool,
    pub redis_error: Option<String>,
}

/// Pool statistics
#[derive(Debug)]
pub struct PoolStatistics {
    pub postgres_stats: Option<PostgresPoolStats>,
    pub redis_stats: Option<RedisPoolStats>,
    pub total_connections: u64,
    pub failed_connections: u64,
    pub pool_hit_rate: f64,
    pub avg_connection_time: Duration,
}

/// PostgreSQL pool statistics
#[derive(Debug)]
pub struct PostgresPoolStats {
    pub size: u32,
    pub idle: u32,
    pub connections_created: u64,
}

/// Redis pool statistics
#[derive(Debug)]
pub struct RedisPoolStats {
    pub size: usize,
    pub available: usize,
    pub max_size: usize,
}

/// Pool manager for advanced operations
pub struct PoolManager {
    pools: Arc<DatabasePools>,
}

impl PoolManager {
    /// Create new pool manager
    pub fn new(pools: DatabasePools) -> Self {
        Self {
            pools: Arc::new(pools),
        }
    }

    /// Get database pools
    pub fn pools(&self) -> &DatabasePools {
        &self.pools
    }

    /// Warm up pools by creating initial connections
    pub async fn warmup(&self) -> DatabaseResult<()> {
        // PostgreSQL warmup
        if let Some(pg_pool) = self.pools.postgresql() {
            // Create a few connections to warm up the pool
            for _ in 0..3 {
                let _conn = pg_pool.acquire().await?;
                // Connection is automatically returned to pool when dropped
            }
        }

        // Redis warmup
        if let Some(redis_pool) = self.pools.redis() {
            // Create a few connections to warm up the pool
            for _ in 0..3 {
                let _conn = redis_pool.get().await?;
                // Connection is automatically returned to pool when dropped
            }
        }

        Ok(())
    }

    /// Periodic maintenance task
    pub async fn maintenance(&self) -> DatabaseResult<()> {
        // Update metrics
        let _metrics = self.pools.metrics().await;

        // Pool maintenance is handled automatically by the underlying libraries
        // This method is for future extensions

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::config::{DatabaseConfig, PoolConfig, PoolStrategy, PostgresConfig};
    use crate::redis_config::UnifiedRedisConfig;

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
                redis: Some(UnifiedRedisConfig {
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
                }),
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
    fn test_pool_metrics_default() {
        let metrics = PoolMetrics::default();

        assert_eq!(metrics.total_connections, 0);
        assert_eq!(metrics.active_connections, 0);
        assert_eq!(metrics.idle_connections, 0);
        assert_eq!(metrics.failed_connections, 0);
        assert_eq!(metrics.avg_connection_time, Duration::default());
        assert_eq!(metrics.pool_hits, 0);
        assert_eq!(metrics.pool_misses, 0);
    }

    #[test]
    fn test_pool_metrics_clone() {
        let metrics = PoolMetrics {
            total_connections: 10,
            active_connections: 5,
            idle_connections: 3,
            failed_connections: 2,
            avg_connection_time: Duration::from_millis(100),
            pool_hits: 100,
            pool_misses: 10,
        };

        let cloned = metrics.clone();
        assert_eq!(cloned.total_connections, 10);
        assert_eq!(cloned.active_connections, 5);
        assert_eq!(cloned.pool_hits, 100);
    }

    #[test]
    fn test_pool_health_status_default() {
        let status = PoolHealthStatus::default();

        assert!(!status.postgres_healthy);
        assert!(status.postgres_error.is_none());
        assert!(!status.redis_healthy);
        assert!(status.redis_error.is_none());
    }

    #[test]
    fn test_pool_health_status_debug() {
        let status = PoolHealthStatus {
            postgres_healthy: true,
            postgres_error: None,
            redis_healthy: false,
            redis_error: Some("connection failed".to_string()),
        };

        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("postgres_healthy: true"));
        assert!(debug_str.contains("redis_healthy: false"));
        assert!(debug_str.contains("connection failed"));
    }

    #[test]
    fn test_pool_statistics_debug() {
        let stats = PoolStatistics {
            postgres_stats: Some(PostgresPoolStats {
                size: 5,
                idle: 3,
                connections_created: 10,
            }),
            redis_stats: None,
            total_connections: 10,
            failed_connections: 2,
            pool_hit_rate: 0.9,
            avg_connection_time: Duration::from_millis(50),
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("size: 5"));
        assert!(debug_str.contains("idle: 3"));
        assert!(debug_str.contains("pool_hit_rate: 0.9"));
    }

    #[test]
    fn test_postgres_pool_stats() {
        let stats = PostgresPoolStats {
            size: 10,
            idle: 5,
            connections_created: 20,
        };

        assert_eq!(stats.size, 10);
        assert_eq!(stats.idle, 5);
        assert_eq!(stats.connections_created, 20);

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("PostgresPoolStats"));
    }

    #[test]
    fn test_redis_pool_stats() {
        let stats = RedisPoolStats {
            size: 8,
            available: 6,
            max_size: 10,
        };

        assert_eq!(stats.size, 8);
        assert_eq!(stats.available, 6);
        assert_eq!(stats.max_size, 10);

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("RedisPoolStats"));
    }

    #[test]
    fn test_pool_manager_creation() {
        let config = create_test_config();

        // Create mock pools (without actual connections)
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        let manager = PoolManager::new(pools);
        assert!(manager.pools().postgresql().is_none());
        assert!(manager.pools().redis().is_none());
    }

    #[test]
    fn test_pool_hit_rate_calculation() {
        // Test with hits and misses
        let metrics = PoolMetrics {
            pool_hits: 90,
            pool_misses: 10,
            ..Default::default()
        };

        let hit_rate = metrics.pool_hits as f64 / (metrics.pool_hits + metrics.pool_misses) as f64;
        assert_eq!(hit_rate, 0.9);

        // Test with no hits or misses (should be 0.0)
        let empty_metrics = PoolMetrics::default();
        let empty_rate = if empty_metrics.pool_hits + empty_metrics.pool_misses > 0 {
            empty_metrics.pool_hits as f64
                / (empty_metrics.pool_hits + empty_metrics.pool_misses) as f64
        } else {
            0.0
        };
        assert_eq!(empty_rate, 0.0);
    }

    #[tokio::test]
    async fn test_database_pools_without_connections() {
        use crate::mocks::MockConnectionFactory;

        let config = create_test_config();
        let _mock_connections = MockConnectionFactory::new();
        let connections = crate::database::connections::DatabaseConnections::new(config.clone());

        // Create pools without actual database connections (will fail but we test structure)
        let pools_result = DatabasePools::new(&config, &connections).await;

        // This will fail without real databases, but we test the error handling
        assert!(pools_result.is_err());
    }

    #[tokio::test]
    async fn test_pool_metrics_async() {
        let config = create_test_config();
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        let metrics = pools.metrics().await;
        assert_eq!(metrics.total_connections, 0);
        assert_eq!(metrics.active_connections, 0);
    }

    #[tokio::test]
    async fn test_pool_health_check_no_pools() {
        let config = create_test_config();
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        let health_status = pools.health_check().await.unwrap();

        // With no pools configured, they should be "healthy" by default
        assert!(!health_status.postgres_healthy);
        assert!(!health_status.redis_healthy);
        assert!(health_status.postgres_error.is_none());
        assert!(health_status.redis_error.is_none());
    }

    #[tokio::test]
    async fn test_pool_close() {
        let config = create_test_config();
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        let result = pools.close().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pool_statistics() {
        let config = create_test_config();
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics {
                total_connections: 10,
                failed_connections: 2,
                pool_hits: 80,
                pool_misses: 20,
                avg_connection_time: Duration::from_millis(100),
                ..Default::default()
            })),
        };

        let stats = pools.statistics().await;
        assert_eq!(stats.total_connections, 10);
        assert_eq!(stats.failed_connections, 2);
        assert_eq!(stats.pool_hit_rate, 0.8); // 80 / (80 + 20)
        assert_eq!(stats.avg_connection_time, Duration::from_millis(100));
        assert!(stats.postgres_stats.is_none());
        assert!(stats.redis_stats.is_none());
    }

    #[tokio::test]
    async fn test_pool_manager_warmup_no_pools() {
        let config = create_test_config();
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        let manager = PoolManager::new(pools);
        let result = manager.warmup().await;
        assert!(result.is_ok()); // Should succeed with no pools
    }

    #[tokio::test]
    async fn test_pool_manager_maintenance() {
        let config = create_test_config();
        let pools = DatabasePools {
            postgres: None,
            redis: None,
            config: config.clone(),
            metrics: Arc::new(RwLock::new(PoolMetrics::default())),
        };

        let manager = PoolManager::new(pools);
        let result = manager.maintenance().await;
        assert!(result.is_ok());
    }
}
