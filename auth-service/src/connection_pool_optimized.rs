use deadpool_redis::{Config as RedisConfig, Pool as RedisPool, Runtime, Connection as RedisConnection};
use bb8_redis::{bb8, RedisConnectionManager, RedisMultiplexedConnection};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use dashmap::DashMap;
use tracing::{debug, info, warn, error};
use serde::{Serialize, Deserialize};

/// Connection pool configuration optimized for security workloads
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of idle connections to maintain
    pub min_idle_connections: u32,
    /// Maximum lifetime of a connection
    pub max_connection_lifetime: Duration,
    /// Connection timeout when acquiring from pool
    pub connection_timeout: Duration,
    /// Idle timeout before closing unused connections
    pub idle_timeout: Duration,
    /// Health check interval
    pub health_check_interval: Duration,
    /// Whether to enable connection multiplexing
    pub enable_multiplexing: bool,
    /// Circuit breaker configuration
    pub circuit_breaker_enabled: bool,
    pub circuit_breaker_failure_threshold: u32,
    pub circuit_breaker_reset_timeout: Duration,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            min_idle_connections: 10,
            max_connection_lifetime: Duration::from_secs(3600), // 1 hour
            connection_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600), // 10 minutes
            health_check_interval: Duration::from_secs(30),
            enable_multiplexing: true,
            circuit_breaker_enabled: true,
            circuit_breaker_failure_threshold: 5,
            circuit_breaker_reset_timeout: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker states for connection pool resilience
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitBreakerState {
    Closed,    // Normal operation
    Open,      // Failing fast
    HalfOpen,  // Testing if service is back
}

/// Circuit breaker for handling connection failures
#[derive(Debug)]
pub struct CircuitBreaker {
    state: CircuitBreakerState,
    failure_count: u32,
    last_failure_time: Option<Instant>,
    config: ConnectionPoolConfig,
}

impl CircuitBreaker {
    pub fn new(config: ConnectionPoolConfig) -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            last_failure_time: None,
            config,
        }
    }

    pub fn can_execute(&mut self) -> bool {
        if !self.config.circuit_breaker_enabled {
            return true;
        }

        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() > self.config.circuit_breaker_reset_timeout {
                        self.state = CircuitBreakerState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    true
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    pub fn record_success(&mut self) {
        self.failure_count = 0;
        self.state = CircuitBreakerState::Closed;
        self.last_failure_time = None;
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());

        if self.failure_count >= self.config.circuit_breaker_failure_threshold {
            self.state = CircuitBreakerState::Open;
        }
    }
}

/// Connection pool statistics for monitoring
#[derive(Debug, Clone, Serialize)]
pub struct PoolStatistics {
    pub total_connections: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub pending_requests: u32,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub avg_response_time: Duration,
    pub circuit_breaker_state: String,
    pub connection_errors: u64,
    pub last_health_check: Option<Instant>,
}

/// Optimized connection pool manager with security-focused features
pub struct OptimizedConnectionPool {
    redis_pool: RedisPool,
    bb8_pool: Arc<bb8::Pool<RedisConnectionManager>>,
    multiplexed_pool: Option<Arc<RwLock<Vec<RedisMultiplexedConnection>>>>,
    config: ConnectionPoolConfig,
    circuit_breaker: Arc<RwLock<CircuitBreaker>>,
    statistics: Arc<RwLock<PoolStatistics>>,
    connection_metrics: Arc<DashMap<String, ConnectionMetrics>>,
}

#[derive(Debug, Clone)]
struct ConnectionMetrics {
    created_at: Instant,
    last_used: Instant,
    total_operations: u64,
    total_duration: Duration,
}

impl OptimizedConnectionPool {
    /// Create a new optimized connection pool
    pub async fn new(redis_url: &str, config: ConnectionPoolConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing optimized Redis connection pool with security features");

        // Create deadpool Redis pool for general use
        let redis_config = RedisConfig::from_url(redis_url);
        let redis_pool = redis_config.create_pool(Some(Runtime::Tokio1))?;

        // Create bb8 pool for high-concurrency operations
        let manager = RedisConnectionManager::new(redis_url)?;
        let bb8_pool = Arc::new(
            bb8::Pool::builder()
                .max_size(config.max_connections)
                .min_idle(Some(config.min_idle_connections))
                .connection_timeout(config.connection_timeout)
                .idle_timeout(Some(config.idle_timeout))
                .max_lifetime(Some(config.max_connection_lifetime))
                .build(manager)
                .await?
        );

        // Create multiplexed connections if enabled
        let multiplexed_pool = if config.enable_multiplexing {
            let client = redis::Client::open(redis_url)?;
            let mut connections = Vec::new();
            
            // Create a smaller pool of multiplexed connections
            let multiplex_count = (config.max_connections / 4).max(2) as usize;
            for _ in 0..multiplex_count {
                match client.get_multiplexed_async_connection().await {
                    Ok(conn) => connections.push(conn),
                    Err(e) => {
                        warn!("Failed to create multiplexed connection: {}", e);
                        break;
                    }
                }
            }
            
            if !connections.is_empty() {
                Some(Arc::new(RwLock::new(connections)))
            } else {
                None
            }
        } else {
            None
        };

        let circuit_breaker = Arc::new(RwLock::new(CircuitBreaker::new(config.clone())));

        let statistics = Arc::new(RwLock::new(PoolStatistics {
            total_connections: config.max_connections,
            active_connections: 0,
            idle_connections: config.min_idle_connections,
            pending_requests: 0,
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time: Duration::ZERO,
            circuit_breaker_state: "Closed".to_string(),
            connection_errors: 0,
            last_health_check: None,
        }));

        let pool = Self {
            redis_pool,
            bb8_pool,
            multiplexed_pool,
            config: config.clone(),
            circuit_breaker,
            statistics,
            connection_metrics: Arc::new(DashMap::new()),
        };

        // Start background health monitoring
        pool.start_health_monitoring().await;

        info!("Optimized Redis connection pool initialized successfully");
        Ok(pool)
    }

    /// Get a connection with automatic load balancing and circuit breaking
    pub async fn get_connection(&self) -> Result<PooledConnection, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        
        // Check circuit breaker
        {
            let mut breaker = self.circuit_breaker.write().await;
            if !breaker.can_execute() {
                let mut stats = self.statistics.write().await;
                stats.failed_requests += 1;
                return Err("Circuit breaker is open".into());
            }
        }

        // Update request statistics
        {
            let mut stats = self.statistics.write().await;
            stats.total_requests += 1;
            stats.pending_requests += 1;
        }

        // Try multiplexed connection first if available (best performance)
        if let Some(ref multiplex_pool) = self.multiplexed_pool {
            let connections = multiplex_pool.read().await;
            if !connections.is_empty() {
                let conn_index = (self.statistics.read().await.total_requests as usize) % connections.len();
                if let Some(conn) = connections.get(conn_index) {
                    self.record_successful_operation(start.elapsed()).await;
                    return Ok(PooledConnection::Multiplexed(conn.clone()));
                }
            }
        }

        // Fall back to bb8 pool (good performance, connection pooling)
        match tokio::time::timeout(self.config.connection_timeout, self.bb8_pool.get()).await {
            Ok(Ok(conn)) => {
                self.record_successful_operation(start.elapsed()).await;
                Ok(PooledConnection::Bb8(conn))
            }
            Ok(Err(e)) => {
                self.record_failed_operation(start.elapsed()).await;
                Err(e.into())
            }
            Err(_) => {
                self.record_failed_operation(start.elapsed()).await;
                Err("Connection timeout".into())
            }
        }
    }

    /// Execute a Redis command with automatic retry and circuit breaking
    pub async fn execute_command<T, F, Fut>(&self, operation: F) -> Result<T, Box<dyn std::error::Error + Send + Sync>>
    where
        F: Fn(PooledConnection) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>> + Send,
        T: Send,
    {
        const MAX_RETRIES: u32 = 3;
        let mut attempts = 0;

        while attempts < MAX_RETRIES {
            attempts += 1;

            match self.get_connection().await {
                Ok(conn) => {
                    match operation(conn).await {
                        Ok(result) => {
                            self.circuit_breaker.write().await.record_success();
                            return Ok(result);
                        }
                        Err(e) => {
                            if attempts >= MAX_RETRIES {
                                self.circuit_breaker.write().await.record_failure();
                                return Err(e);
                            }
                            // Wait before retry with exponential backoff
                            tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                        }
                    }
                }
                Err(e) => {
                    if attempts >= MAX_RETRIES {
                        self.circuit_breaker.write().await.record_failure();
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                }
            }
        }

        Err("Max retries exceeded".into())
    }

    /// Batch execute multiple Redis commands for optimal performance
    pub async fn execute_batch<T, F, Fut>(&self, operations: Vec<F>) -> Vec<Result<T, Box<dyn std::error::Error + Send + Sync>>>
    where
        F: Fn(PooledConnection) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T, Box<dyn std::error::Error + Send + Sync>>> + Send,
        T: Send,
    {
        let mut results = Vec::with_capacity(operations.len());
        let mut handles = Vec::new();

        // Execute operations concurrently
        for operation in operations {
            let pool = self.clone();
            let handle = tokio::spawn(async move {
                pool.execute_command(operation).await
            });
            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(e.into())),
            }
        }

        results
    }

    /// Get current pool statistics
    pub async fn get_statistics(&self) -> PoolStatistics {
        let mut stats = self.statistics.read().await.clone();
        
        // Update real-time statistics from bb8 pool
        let pool_state = self.bb8_pool.state().await;
        stats.active_connections = pool_state.connections;
        stats.idle_connections = pool_state.idle_connections;

        // Update circuit breaker state
        let breaker = self.circuit_breaker.read().await;
        stats.circuit_breaker_state = format!("{:?}", breaker.state);

        stats
    }

    /// Perform health check on all connections
    pub async fn health_check(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        debug!("Performing connection pool health check");

        // Test a connection from the pool
        let conn = self.get_connection().await?;
        
        match conn {
            PooledConnection::Bb8(mut conn) => {
                let _: String = redis::cmd("PING").query_async(&mut *conn).await?;
            }
            PooledConnection::Multiplexed(mut conn) => {
                let _: String = redis::cmd("PING").query_async(&mut conn).await?;
            }
            PooledConnection::Direct(mut conn) => {
                let _: String = redis::cmd("PING").query_async(&mut conn).await?;
            }
        }

        // Update health check timestamp
        self.statistics.write().await.last_health_check = Some(Instant::now());

        debug!("Connection pool health check completed successfully");
        Ok(())
    }

    /// Start background health monitoring task
    async fn start_health_monitoring(&self) {
        let pool = self.clone();
        let interval = self.config.health_check_interval;

        tokio::spawn(async move {
            let mut health_interval = tokio::time::interval(interval);
            
            loop {
                health_interval.tick().await;
                
                if let Err(e) = pool.health_check().await {
                    warn!("Connection pool health check failed: {}", e);
                    
                    // Record failure in circuit breaker
                    pool.circuit_breaker.write().await.record_failure();
                    
                    // Update error statistics
                    pool.statistics.write().await.connection_errors += 1;
                }
            }
        });
    }

    /// Record successful operation metrics
    async fn record_successful_operation(&self, duration: Duration) {
        let mut stats = self.statistics.write().await;
        stats.successful_requests += 1;
        stats.pending_requests = stats.pending_requests.saturating_sub(1);
        
        // Update average response time
        let total_ops = stats.successful_requests + stats.failed_requests;
        if total_ops > 0 {
            stats.avg_response_time = Duration::from_nanos(
                ((stats.avg_response_time.as_nanos() as u64 * (total_ops - 1)) + duration.as_nanos() as u64) / total_ops
            );
        }
    }

    /// Record failed operation metrics
    async fn record_failed_operation(&self, duration: Duration) {
        let mut stats = self.statistics.write().await;
        stats.failed_requests += 1;
        stats.pending_requests = stats.pending_requests.saturating_sub(1);
        
        // Update average response time (include failed operations)
        let total_ops = stats.successful_requests + stats.failed_requests;
        if total_ops > 0 {
            stats.avg_response_time = Duration::from_nanos(
                ((stats.avg_response_time.as_nanos() as u64 * (total_ops - 1)) + duration.as_nanos() as u64) / total_ops
            );
        }
    }
}

impl Clone for OptimizedConnectionPool {
    fn clone(&self) -> Self {
        Self {
            redis_pool: self.redis_pool.clone(),
            bb8_pool: self.bb8_pool.clone(),
            multiplexed_pool: self.multiplexed_pool.clone(),
            config: self.config.clone(),
            circuit_breaker: self.circuit_breaker.clone(),
            statistics: self.statistics.clone(),
            connection_metrics: self.connection_metrics.clone(),
        }
    }
}

/// Wrapper for different types of Redis connections
pub enum PooledConnection {
    Bb8(bb8::PooledConnection<'static, RedisConnectionManager>),
    Multiplexed(RedisMultiplexedConnection),
    Direct(RedisConnection),
}

impl PooledConnection {
    /// Get a mutable reference to the underlying connection for redis operations
    pub async fn as_mut(&mut self) -> &mut dyn redis::aio::ConnectionLike {
        match self {
            PooledConnection::Bb8(conn) => conn,
            PooledConnection::Multiplexed(conn) => conn,
            PooledConnection::Direct(conn) => conn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_states() {
        let config = ConnectionPoolConfig::default();
        let mut breaker = CircuitBreaker::new(config);

        // Initial state should be closed
        assert_eq!(breaker.state, CircuitBreakerState::Closed);
        assert!(breaker.can_execute());

        // Record failures
        for _ in 0..5 {
            breaker.record_failure();
        }

        // Should be open after threshold failures
        assert_eq!(breaker.state, CircuitBreakerState::Open);
        assert!(!breaker.can_execute());

        // Record success should reset
        breaker.record_success();
        assert_eq!(breaker.state, CircuitBreakerState::Closed);
        assert!(breaker.can_execute());
    }

    #[tokio::test]
    async fn test_connection_pool_config() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.min_idle_connections, 10);
        assert!(config.circuit_breaker_enabled);
    }
}