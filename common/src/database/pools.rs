//! Database Connection Pools
//!
//! Unified connection pool management for PostgreSQL and Redis

use super::config::{UnifiedDatabaseConfig, PoolConfig};
use super::connections::DatabaseConnections;
use super::error::{DatabaseError, DatabaseResult};
use deadpool_redis::{Config as RedisPoolConfig, Pool as RedisPool, Runtime};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Database connection pools manager
#[derive(Clone)]
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
    pub async fn new(config: &UnifiedDatabaseConfig, _connections: &DatabaseConnections) -> DatabaseResult<Self> {
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
    async fn create_postgres_pool(&self, pg_config: &super::config::PostgresConfig) -> DatabaseResult<PgPool> {
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
    async fn create_redis_pool(&self, redis_config: &crate::redis_config::UnifiedRedisConfig) -> DatabaseResult<RedisPool> {
        let pool_config = self.config.effective_pool_config();
        
        let cfg = RedisPoolConfig::from_url(&redis_config.url);
        
        let pool = cfg.create_pool(Some(Runtime::Tokio1))
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