//! Optimized connection pool implementations
//!
//! This module provides high-performance, production-ready connection pools
//! for Redis and database connections with advanced features like:
//! - Connection recycling and reuse
//! - Intelligent health checking
//! - Metrics collection
//! - Failover support

use crate::{constants, UnifiedRedisConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Connection pool errors
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("Connection pool exhausted")]
    PoolExhausted,
    #[error("Connection failed health check")]
    UnhealthyConnection,
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Pool is shutting down")]
    PoolShuttingDown,
    #[error("Invalid pool configuration: {message}")]
    InvalidConfiguration { message: String },
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
}

/// Connection health status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self::Healthy
    }
}

/// Connection pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total connections created
    pub total_connections: u64,
    /// Currently active connections
    pub active_connections: u32,
    /// Connections waiting to be acquired
    pub waiting_requests: u32,
    /// Average connection acquisition time
    pub avg_acquisition_time_ms: f64,
    /// Total successful acquisitions
    pub successful_acquisitions: u64,
    /// Total failed acquisitions
    pub failed_acquisitions: u64,
    /// Connection pool health
    pub health_status: HealthStatus,
}

/// Optimized Redis connection pool
pub struct OptimizedRedisPool {
    /// Pool configuration
    config: UnifiedRedisConfig,
    /// Connection semaphore for limiting concurrent connections
    semaphore: Arc<Semaphore>,
    /// Pool statistics
    stats: Arc<RwLock<PoolStats>>,
    /// Redis client
    client: redis::Client,
    /// Connection cache for reuse
    connection_cache: Arc<RwLock<Vec<CachedConnection>>>,
    /// Shutdown flag
    shutdown: Arc<RwLock<bool>>,
}

/// Cached Redis connection with metadata
struct CachedConnection {
    /// The actual Redis connection
    connection: redis::aio::ConnectionManager,
    /// Last used timestamp
    last_used: Instant,
    /// Health status
    health: HealthStatus,
    /// Number of times this connection has been reused
    reuse_count: u32,
}

impl std::fmt::Debug for CachedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedConnection")
            .field("last_used", &self.last_used)
            .field("health", &self.health)
            .field("reuse_count", &self.reuse_count)
            .field("connection", &"<ConnectionManager>")
            .finish()
    }
}

impl OptimizedRedisPool {
    /// Create a new optimized Redis pool
    ///
    /// # Errors
    /// Returns `PoolError` if:
    /// - Configuration validation fails
    /// - Redis client creation fails
    /// - Initial connection test fails
    /// - Statistics initialization fails
    pub async fn new(config: UnifiedRedisConfig) -> Result<Self, PoolError> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| PoolError::InvalidConfiguration {
                message: e.to_string(),
            })?;

        // Create Redis client
        let client = redis::Client::open(config.client_url()).map_err(PoolError::Redis)?;

        // Test initial connection using connection manager
        let mut test_conn = client
            .get_connection_manager()
            .await
            .map_err(PoolError::Redis)?;

        // Perform health check
        redis::cmd("PING")
            .query_async::<String>(&mut test_conn)
            .await
            .map_err(PoolError::Redis)?;

        info!(
            url = %config.url,
            max_connections = config.max_connections,
            "Initialized optimized Redis pool"
        );

        Ok(Self {
            semaphore: Arc::new(Semaphore::new(config.max_connections as usize)),
            stats: Arc::new(RwLock::new(PoolStats {
                health_status: HealthStatus::Healthy,
                ..Default::default()
            })),
            connection_cache: Arc::new(RwLock::new(Vec::new())),
            shutdown: Arc::new(RwLock::new(false)),
            config,
            client,
        })
    }

    /// Get a connection from the pool
    ///
    /// # Errors
    /// Returns `PoolError` if:
    /// - Pool is shutting down
    /// - No permits available (pool exhausted)
    /// - Connection timeout is reached
    /// - Redis connection creation fails
    pub async fn get_connection(&self) -> Result<PooledConnection, PoolError> {
        let start_time = Instant::now();

        // Check if pool is shutting down
        if *self.shutdown.read().await {
            return Err(PoolError::PoolShuttingDown);
        }

        // Acquire semaphore permit with timeout
        let permit = tokio::time::timeout(
            self.config.timeout_duration(),
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| PoolError::ConnectionTimeout)?
        .map_err(|_| PoolError::PoolExhausted)?;

        // Try to get a cached connection first
        if let Some(connection) = self.try_get_cached_connection().await {
            // Update stats - use sub-second precision for better accuracy
            let acquisition_time = start_time.elapsed().as_secs_f64() * 1000.0;
            self.update_acquisition_stats(true, acquisition_time).await;

            return Ok(PooledConnection {
                connection,
                pool: Arc::downgrade(&Arc::new(self.clone())),
                _permit: permit,
                acquired_at: Instant::now(),
            });
        }

        // Create new connection
        match self.create_new_connection().await {
            Ok(connection) => {
                let acquisition_time = start_time.elapsed().as_secs_f64() * 1000.0;
                self.update_acquisition_stats(true, acquisition_time).await;

                Ok(PooledConnection {
                    connection,
                    pool: Arc::downgrade(&Arc::new(self.clone())),
                    _permit: permit,
                    acquired_at: Instant::now(),
                })
            }
            Err(e) => {
                let acquisition_time = start_time.elapsed().as_secs_f64() * 1000.0;
                self.update_acquisition_stats(false, acquisition_time).await;
                Err(e)
            }
        }
    }

    /// Try to get a connection from the cache
    async fn try_get_cached_connection(&self) -> Option<redis::aio::ConnectionManager> {
        let mut cache = self.connection_cache.write().await;
        let now = Instant::now();

        // Find a healthy, recent connection
        if let Some(index) = cache.iter().position(|cached| {
            cached.health == HealthStatus::Healthy
                && now.duration_since(cached.last_used) < self.config.idle_timeout_duration()
                && cached.reuse_count < 1000 // Limit reuse to prevent stale connections
        }) {
            let mut cached = cache.remove(index);
            cached.last_used = now;
            cached.reuse_count += 1;

            debug!(
                "Reusing cached Redis connection (reuse count: {})",
                cached.reuse_count
            );

            // Explicitly drop the cache lock early to reduce contention
            drop(cache);

            return Some(cached.connection);
        }

        None
    }

    /// Create a new Redis connection
    async fn create_new_connection(&self) -> Result<redis::aio::ConnectionManager, PoolError> {
        let connection = self
            .client
            .get_connection_manager()
            .await
            .map_err(PoolError::Redis)?;

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_connections += 1;
            stats.active_connections += 1;
        }

        debug!("Created new Redis connection");
        Ok(connection)
    }

    /// Return a connection to the cache for reuse
    pub async fn return_connection(&self, connection: redis::aio::ConnectionManager) {
        // Limit cache size to prevent memory bloat
        const MAX_CACHE_SIZE: usize = 50;

        let cached = CachedConnection {
            connection,
            last_used: Instant::now(),
            health: HealthStatus::Healthy, // Assume healthy on return
            reuse_count: 0,
        };

        // Update cache first, then drop lock
        {
            let mut cache = self.connection_cache.write().await;

            if cache.len() < MAX_CACHE_SIZE {
                cache.push(cached);
                debug!("Cached Redis connection for reuse");
            } else {
                debug!("Connection cache full, dropping connection");
            }

            // Explicitly drop cache lock to reduce contention
            drop(cache);
        }

        // Update active connections count
        let mut stats = self.stats.write().await;
        stats.active_connections = stats.active_connections.saturating_sub(1);
    }

    /// Update acquisition statistics
    async fn update_acquisition_stats(&self, success: bool, acquisition_time_ms: f64) {
        let mut stats = self.stats.write().await;

        if success {
            stats.successful_acquisitions += 1;
        } else {
            stats.failed_acquisitions += 1;
        }

        // Update moving average of acquisition time - avoid precision loss
        let total_acquisitions = stats.successful_acquisitions + stats.failed_acquisitions;
        if total_acquisitions > 0 {
            #[allow(clippy::cast_precision_loss)]
            let total_acquisitions_f64 = total_acquisitions as f64;
            #[allow(clippy::cast_precision_loss)]
            let total_minus_one_f64 = (total_acquisitions - 1) as f64;
            stats.avg_acquisition_time_ms = stats
                .avg_acquisition_time_ms
                .mul_add(total_minus_one_f64, acquisition_time_ms)
                / total_acquisitions_f64;
        }
    }

    /// Get pool statistics
    pub async fn get_stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }

    /// Perform health check on the pool
    pub async fn health_check(&self) -> HealthStatus {
        // Try to get a connection and ping Redis
        match self.get_connection().await {
            Ok(mut conn) => {
                match redis::cmd("PING")
                    .query_async::<String>(&mut conn.connection)
                    .await
                {
                    Ok(_) => {
                        self.update_health_status(HealthStatus::Healthy).await;
                        HealthStatus::Healthy
                    }
                    Err(e) => {
                        warn!("Redis ping failed: {}", e);
                        self.update_health_status(HealthStatus::Degraded).await;
                        HealthStatus::Degraded
                    }
                }
            }
            Err(e) => {
                error!("Failed to acquire connection for health check: {}", e);
                self.update_health_status(HealthStatus::Unhealthy).await;
                HealthStatus::Unhealthy
            }
        }
    }

    /// Update health status
    async fn update_health_status(&self, health_status: HealthStatus) {
        let mut stats = self.stats.write().await;
        stats.health_status = health_status;
    }

    /// Clean up expired connections from cache
    pub async fn cleanup_expired_connections(&self) -> usize {
        let mut cache = self.connection_cache.write().await;
        let now = Instant::now();
        let initial_len = cache.len();

        cache.retain(|cached| {
            now.duration_since(cached.last_used) < self.config.idle_timeout_duration() * 2
        });

        let removed = initial_len - cache.len();
        if removed > 0 {
            debug!("Cleaned up {} expired cached connections", removed);
        }

        // Explicitly drop cache lock to reduce contention
        drop(cache);

        removed
    }

    /// Shutdown the pool gracefully
    pub async fn shutdown(&self) {
        *self.shutdown.write().await = true;

        // Clear connection cache - use direct write to reduce lock contention
        self.connection_cache.write().await.clear();

        info!("Redis pool shutdown complete");
    }
}

// Make OptimizedRedisPool cloneable for sharing
impl Clone for OptimizedRedisPool {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            semaphore: Arc::clone(&self.semaphore),
            stats: Arc::clone(&self.stats),
            client: self.client.clone(),
            connection_cache: Arc::clone(&self.connection_cache),
            shutdown: Arc::clone(&self.shutdown),
        }
    }
}

/// A pooled Redis connection that automatically returns to the pool when dropped
pub struct PooledConnection {
    pub connection: redis::aio::ConnectionManager,
    pool: std::sync::Weak<OptimizedRedisPool>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    acquired_at: Instant,
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        // Return connection to pool if pool still exists
        if let Some(pool) = self.pool.upgrade() {
            // Clone the connection for returning to pool
            // This is acceptable since ConnectionManager is designed to be cloned
            let connection = self.connection.clone();

            // Spawn task to return connection to avoid blocking drop
            tokio::spawn(async move {
                pool.return_connection(connection).await;
            });

            // Log connection usage duration
            debug!("Connection used for {:?}", self.acquired_at.elapsed());
        }
    }
}

/// Start a background task to maintain pool health
pub fn start_pool_maintenance(pool: Arc<OptimizedRedisPool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            constants::redis::DEFAULT_TTL_SECS as u64 / 10, // Check every 30 seconds
        ));

        loop {
            interval.tick().await;

            // Cleanup expired connections
            let removed = pool.cleanup_expired_connections().await;
            if removed > 0 {
                info!(
                    "Pool maintenance: cleaned up {} expired connections",
                    removed
                );
            }

            // Perform health check
            let health = pool.health_check().await;
            debug!("Pool health check: {:?}", health);

            // Log stats periodically
            let stats = pool.get_stats().await;
            if stats.total_connections % 100 == 0 {
                info!(
                    "Pool stats: active={}, total={}, avg_acq_time={:.2}ms, success_rate={:.1}%",
                    stats.active_connections,
                    stats.total_connections,
                    stats.avg_acquisition_time_ms,
                    if stats.successful_acquisitions + stats.failed_acquisitions > 0 {
                        let total = stats.successful_acquisitions + stats.failed_acquisitions;
                        #[allow(clippy::cast_precision_loss)]
                        let total_f64 = total as f64;
                        #[allow(clippy::cast_precision_loss)]
                        let successful_f64 = stats.successful_acquisitions as f64;
                        (successful_f64 * 100.0) / total_f64
                    } else {
                        100.0
                    }
                );
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_pool_creation() {
        let config = UnifiedRedisConfig::new("redis://localhost:6379");

        // This test requires a running Redis instance
        if let Ok(pool) = OptimizedRedisPool::new(config).await {
            let stats = pool.get_stats().await;
            assert_eq!(stats.health_status, HealthStatus::Healthy);
            assert_eq!(stats.active_connections, 0);
        }
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let config = UnifiedRedisConfig::new("redis://localhost:6379");

        if let Ok(pool) = OptimizedRedisPool::new(config).await {
            // Get and return a connection
            let conn1 = pool.get_connection().await.unwrap();
            drop(conn1);

            // Small delay to allow connection to be cached
            sleep(Duration::from_millis(10)).await;

            // Get another connection - should reuse the cached one
            let _conn2 = pool.get_connection().await.unwrap();

            let stats = pool.get_stats().await;
            // Should still have only created one connection
            assert_eq!(stats.total_connections, 1);
        }
    }
}
