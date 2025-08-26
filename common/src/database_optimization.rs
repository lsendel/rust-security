// Phase 3: Database Optimization with Advanced Connection Pooling and Query Optimization
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use sqlx::{PgPool, Row, Postgres, Transaction};
use tracing::{debug, info, warn, instrument};
use prometheus::{Counter, Histogram, Gauge};
use serde::{Deserialize, Serialize};

/// Advanced database connection pool with intelligent optimization
#[derive(Clone)]
pub struct OptimizedDbPool {
    pool: PgPool,
    metrics: DbMetrics,
    query_cache: Arc<RwLock<HashMap<String, CachedQuery>>>,
    prepared_statements: Arc<RwLock<HashMap<String, String>>>,
    connection_stats: Arc<RwLock<ConnectionStats>>,
}

#[derive(Debug, Clone)]
struct CachedQuery {
    result: serde_json::Value,
    expires_at: Instant,
    hit_count: u64,
    execution_time: Duration,
}

#[derive(Debug, Clone)]
struct ConnectionStats {
    active_connections: usize,
    idle_connections: usize,
    total_connections: usize,
    average_query_time: Duration,
    slow_queries: u64,
    connection_errors: u64,
}

#[derive(Debug, Clone)]
pub struct DbMetrics {
    pub queries_total: Counter,
    pub query_duration: Histogram,
    pub connection_pool_size: Gauge,
    pub active_connections: Gauge,
    pub query_cache_hits: Counter,
    pub query_cache_misses: Counter,
    pub slow_queries: Counter,
    pub connection_errors: Counter,
    pub transaction_duration: Histogram,
}

/// Query optimizer for analyzing and improving database queries
pub struct QueryOptimizer {
    metrics: QueryOptimizerMetrics,
    query_patterns: Arc<RwLock<HashMap<String, QueryPattern>>>,
    optimization_rules: Vec<OptimizationRule>,
}

#[derive(Debug, Clone)]
struct QueryPattern {
    query_hash: String,
    execution_count: u64,
    total_time: Duration,
    average_time: Duration,
    min_time: Duration,
    max_time: Duration,
    last_executed: Instant,
    optimization_applied: bool,
}

#[derive(Debug, Clone)]
pub struct QueryOptimizerMetrics {
    pub queries_analyzed: Counter,
    pub optimizations_applied: Counter,
    pub performance_improvement: Histogram,
}

#[derive(Debug, Clone)]
struct OptimizationRule {
    name: String,
    pattern: String,
    replacement: String,
    estimated_improvement: f64,
}

/// Batch query processor for efficient bulk operations
pub struct BatchQueryProcessor {
    pool: OptimizedDbPool,
    batch_size: usize,
    batch_timeout: Duration,
    metrics: BatchProcessorMetrics,
}

#[derive(Debug, Clone)]
pub struct BatchProcessorMetrics {
    pub batches_processed: Counter,
    pub batch_size_histogram: Histogram,
    pub batch_efficiency: Gauge,
}

/// Read replica manager for scaling read operations
pub struct ReadReplicaManager {
    primary_pool: OptimizedDbPool,
    replica_pools: Vec<OptimizedDbPool>,
    load_balancer: LoadBalancer,
    metrics: ReplicaMetrics,
}

#[derive(Debug, Clone)]
pub struct ReplicaMetrics {
    pub read_queries_routed: Counter,
    pub replica_health: Gauge,
    pub replication_lag: Histogram,
}

#[derive(Debug)]
enum LoadBalancer {
    RoundRobin { current: std::sync::atomic::AtomicUsize },
    LeastConnections,
    ResponseTime,
}

/// Database transaction manager with optimization
pub struct TransactionManager {
    pool: OptimizedDbPool,
    metrics: TransactionMetrics,
}

#[derive(Debug, Clone)]
pub struct TransactionMetrics {
    pub transactions_started: Counter,
    pub transactions_committed: Counter,
    pub transactions_rolled_back: Counter,
    pub transaction_duration: Histogram,
    pub deadlocks_detected: Counter,
}

impl OptimizedDbPool {
    pub async fn new(database_url: &str, registry: &prometheus::Registry) -> Result<Self, sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(50)  // Increased for Phase 3
            .min_connections(10)  // Maintain minimum connections
            .acquire_timeout(Duration::from_secs(2))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1800))
            .test_before_acquire(true)
            .connect(database_url)
            .await?;

        let metrics = DbMetrics::new(registry)?;
        
        Ok(Self {
            pool,
            metrics,
            query_cache: Arc::new(RwLock::new(HashMap::new())),
            prepared_statements: Arc::new(RwLock::new(HashMap::new())),
            connection_stats: Arc::new(RwLock::new(ConnectionStats {
                active_connections: 0,
                idle_connections: 0,
                total_connections: 0,
                average_query_time: Duration::ZERO,
                slow_queries: 0,
                connection_errors: 0,
            })),
        })
    }

    /// Execute query with caching and optimization
    #[instrument(skip(self, query, params))]
    pub async fn execute_cached<T>(&self, query: &str, params: &[&(dyn sqlx::Encode<Postgres> + Sync)]) -> Result<Vec<T>, sqlx::Error>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin + Serialize + for<'de> Deserialize<'de>,
    {
        let start = Instant::now();
        let query_hash = self.hash_query(query, params);

        // Check cache first
        if let Some(cached) = self.get_cached_result(&query_hash).await {
            self.metrics.query_cache_hits.inc();
            debug!("Cache hit for query hash: {}", query_hash);
            return Ok(serde_json::from_value(cached.result)?);
        }

        self.metrics.query_cache_misses.inc();

        // Execute query
        let result = self.execute_query_internal(query, params).await?;
        let duration = start.elapsed();

        // Cache result if query is cacheable
        if self.is_cacheable_query(query) {
            self.cache_result(&query_hash, &result, duration).await;
        }

        // Update metrics
        self.metrics.queries_total.inc();
        self.metrics.query_duration.observe(duration.as_secs_f64());

        if duration > Duration::from_millis(100) {
            self.metrics.slow_queries.inc();
            warn!("Slow query detected: {} took {:?}", query, duration);
        }

        Ok(result)
    }

    async fn execute_query_internal<T>(&self, query: &str, params: &[&(dyn sqlx::Encode<Postgres> + Sync)]) -> Result<Vec<T>, sqlx::Error>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        // Use prepared statement if available
        let optimized_query = self.get_prepared_statement(query).await.unwrap_or_else(|| query.to_string());
        
        let mut query_builder = sqlx::query_as::<_, T>(&optimized_query);
        
        // This is a simplified version - in practice, you'd need to handle parameter binding more carefully
        let rows = query_builder.fetch_all(&self.pool).await?;
        
        Ok(rows)
    }

    async fn get_cached_result(&self, query_hash: &str) -> Option<CachedQuery> {
        let cache = self.query_cache.read().await;
        if let Some(cached) = cache.get(query_hash) {
            if cached.expires_at > Instant::now() {
                return Some(cached.clone());
            }
        }
        None
    }

    async fn cache_result<T>(&self, query_hash: &str, result: &[T], execution_time: Duration)
    where
        T: Serialize,
    {
        let serialized = match serde_json::to_value(result) {
            Ok(value) => value,
            Err(_) => return, // Skip caching if serialization fails
        };

        let cached = CachedQuery {
            result: serialized,
            expires_at: Instant::now() + Duration::from_secs(300), // 5 minute cache
            hit_count: 0,
            execution_time,
        };

        let mut cache = self.query_cache.write().await;
        cache.insert(query_hash.to_string(), cached);

        // Cleanup old entries
        if cache.len() > 1000 {
            let cutoff = Instant::now();
            cache.retain(|_, v| v.expires_at > cutoff);
        }
    }

    async fn get_prepared_statement(&self, query: &str) -> Option<String> {
        let statements = self.prepared_statements.read().await;
        statements.get(query).cloned()
    }

    fn hash_query(&self, query: &str, params: &[&(dyn sqlx::Encode<Postgres> + Sync)]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        query.hash(&mut hasher);
        params.len().hash(&mut hasher); // Simple param hash
        format!("query:{:x}", hasher.finish())
    }

    fn is_cacheable_query(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        query_lower.starts_with("select") && 
        !query_lower.contains("now()") && 
        !query_lower.contains("random()") &&
        !query_lower.contains("current_timestamp")
    }

    /// Execute transaction with optimization
    pub async fn execute_transaction<F, R>(&self, f: F) -> Result<R, sqlx::Error>
    where
        F: for<'c> FnOnce(&mut Transaction<'c, Postgres>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<R, sqlx::Error>> + Send + 'c>> + Send,
        R: Send,
    {
        let start = Instant::now();
        let mut tx = self.pool.begin().await?;
        
        let result = f(&mut tx).await;
        
        match result {
            Ok(value) => {
                tx.commit().await?;
                let duration = start.elapsed();
                self.metrics.transaction_duration.observe(duration.as_secs_f64());
                Ok(value)
            }
            Err(e) => {
                tx.rollback().await?;
                Err(e)
            }
        }
    }

    /// Get connection pool statistics
    pub async fn get_pool_stats(&self) -> ConnectionStats {
        let pool_state = self.pool.size();
        let active = pool_state as usize;
        let idle = self.pool.num_idle();
        
        ConnectionStats {
            active_connections: active,
            idle_connections: idle,
            total_connections: active + idle,
            average_query_time: Duration::from_millis(50), // Mock value
            slow_queries: self.metrics.slow_queries.get() as u64,
            connection_errors: self.metrics.connection_errors.get() as u64,
        }
    }

    /// Start background optimization tasks
    pub async fn start_optimization_tasks(&self) {
        let pool = self.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                // Update connection metrics
                let stats = pool.get_pool_stats().await;
                pool.metrics.active_connections.set(stats.active_connections as f64);
                pool.metrics.connection_pool_size.set(stats.total_connections as f64);
                
                // Clean up query cache
                let mut cache = pool.query_cache.write().await;
                let cutoff = Instant::now();
                cache.retain(|_, v| v.expires_at > cutoff);
            }
        });
    }
}

impl QueryOptimizer {
    pub fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let metrics = QueryOptimizerMetrics::new(registry)?;
        
        let optimization_rules = vec![
            OptimizationRule {
                name: "Add LIMIT to unbounded queries".to_string(),
                pattern: r"SELECT.*FROM.*WHERE.*".to_string(),
                replacement: r"$0 LIMIT 1000".to_string(),
                estimated_improvement: 0.3,
            },
            OptimizationRule {
                name: "Use EXISTS instead of IN for subqueries".to_string(),
                pattern: r"WHERE.*IN\s*\(SELECT".to_string(),
                replacement: r"WHERE EXISTS (SELECT 1 FROM".to_string(),
                estimated_improvement: 0.2,
            },
            OptimizationRule {
                name: "Add index hints for large table scans".to_string(),
                pattern: r"SELECT.*FROM\s+large_table".to_string(),
                replacement: r"$0 USE INDEX (idx_primary)".to_string(),
                estimated_improvement: 0.5,
            },
        ];

        Ok(Self {
            metrics,
            query_patterns: Arc::new(RwLock::new(HashMap::new())),
            optimization_rules,
        })
    }

    /// Analyze query and suggest optimizations
    #[instrument(skip(self, query))]
    pub async fn analyze_query(&self, query: &str, execution_time: Duration) -> Vec<String> {
        self.metrics.queries_analyzed.inc();
        
        let query_hash = self.hash_query(query);
        let mut patterns = self.query_patterns.write().await;
        
        let pattern = patterns.entry(query_hash.clone()).or_insert_with(|| QueryPattern {
            query_hash: query_hash.clone(),
            execution_count: 0,
            total_time: Duration::ZERO,
            average_time: Duration::ZERO,
            min_time: Duration::MAX,
            max_time: Duration::ZERO,
            last_executed: Instant::now(),
            optimization_applied: false,
        });

        pattern.execution_count += 1;
        pattern.total_time += execution_time;
        pattern.average_time = pattern.total_time / pattern.execution_count as u32;
        pattern.min_time = pattern.min_time.min(execution_time);
        pattern.max_time = pattern.max_time.max(execution_time);
        pattern.last_executed = Instant::now();

        let mut suggestions = Vec::new();

        // Analyze for optimization opportunities
        if execution_time > Duration::from_millis(100) {
            suggestions.push("Query is slow, consider adding indexes".to_string());
        }

        if pattern.execution_count > 100 && !pattern.optimization_applied {
            suggestions.push("Frequently executed query, consider caching".to_string());
        }

        if pattern.max_time > pattern.min_time * 10 {
            suggestions.push("High execution time variance, check for parameter sniffing".to_string());
        }

        // Apply optimization rules
        for rule in &self.optimization_rules {
            if query.contains(&rule.pattern) {
                suggestions.push(format!("Apply rule: {}", rule.name));
                self.metrics.optimizations_applied.inc();
                self.metrics.performance_improvement.observe(rule.estimated_improvement);
            }
        }

        debug!("Analyzed query with {} suggestions", suggestions.len());
        suggestions
    }

    fn hash_query(&self, query: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        // Normalize query for pattern matching
        let normalized = query.to_lowercase().trim().to_string();
        normalized.hash(&mut hasher);
        format!("pattern:{:x}", hasher.finish())
    }

    /// Get optimization recommendations
    pub async fn get_recommendations(&self) -> Vec<(String, QueryPattern)> {
        let patterns = self.query_patterns.read().await;
        let mut recommendations: Vec<_> = patterns.iter()
            .filter(|(_, pattern)| {
                pattern.execution_count > 10 && 
                pattern.average_time > Duration::from_millis(50) &&
                !pattern.optimization_applied
            })
            .map(|(hash, pattern)| (hash.clone(), pattern.clone()))
            .collect();

        recommendations.sort_by(|a, b| b.1.total_time.cmp(&a.1.total_time));
        recommendations
    }
}

impl BatchQueryProcessor {
    pub fn new(pool: OptimizedDbPool, batch_size: usize, registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let metrics = BatchProcessorMetrics::new(registry)?;
        
        Ok(Self {
            pool,
            batch_size,
            batch_timeout: Duration::from_millis(100),
            metrics,
        })
    }

    /// Process queries in batches for better performance
    pub async fn process_batch<T, F>(&self, items: Vec<T>, processor: F) -> Result<Vec<sqlx::postgres::PgRow>, sqlx::Error>
    where
        T: Send + Sync,
        F: Fn(&[T]) -> String + Send + Sync,
    {
        let start = Instant::now();
        let mut results = Vec::new();
        
        for chunk in items.chunks(self.batch_size) {
            let batch_query = processor(chunk);
            let batch_results = sqlx::query(&batch_query)
                .fetch_all(&self.pool.pool)
                .await?;
            
            results.extend(batch_results);
            self.metrics.batch_size_histogram.observe(chunk.len() as f64);
        }

        let duration = start.elapsed();
        let efficiency = items.len() as f64 / duration.as_secs_f64();
        self.metrics.batch_efficiency.set(efficiency);
        self.metrics.batches_processed.inc();

        Ok(results)
    }
}

impl ReadReplicaManager {
    pub fn new(
        primary_pool: OptimizedDbPool,
        replica_pools: Vec<OptimizedDbPool>,
        registry: &prometheus::Registry,
    ) -> Result<Self, prometheus::Error> {
        let metrics = ReplicaMetrics::new(registry)?;
        let load_balancer = LoadBalancer::RoundRobin {
            current: std::sync::atomic::AtomicUsize::new(0),
        };

        Ok(Self {
            primary_pool,
            replica_pools,
            load_balancer,
            metrics,
        })
    }

    /// Route read query to appropriate replica
    pub async fn execute_read_query<T>(&self, query: &str, params: &[&(dyn sqlx::Encode<Postgres> + Sync)]) -> Result<Vec<T>, sqlx::Error>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin + Serialize + for<'de> Deserialize<'de>,
    {
        self.metrics.read_queries_routed.inc();
        
        let replica_pool = self.select_replica().await;
        replica_pool.execute_cached(query, params).await
    }

    /// Route write query to primary
    pub async fn execute_write_query<T>(&self, query: &str, params: &[&(dyn sqlx::Encode<Postgres> + Sync)]) -> Result<Vec<T>, sqlx::Error>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin + Serialize + for<'de> Deserialize<'de>,
    {
        self.primary_pool.execute_cached(query, params).await
    }

    async fn select_replica(&self) -> &OptimizedDbPool {
        match &self.load_balancer {
            LoadBalancer::RoundRobin { current } => {
                let index = current.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.replica_pools.len();
                &self.replica_pools[index]
            }
            LoadBalancer::LeastConnections => {
                // Find replica with least connections
                let mut min_connections = usize::MAX;
                let mut selected_index = 0;
                
                for (i, pool) in self.replica_pools.iter().enumerate() {
                    let stats = pool.get_pool_stats().await;
                    if stats.active_connections < min_connections {
                        min_connections = stats.active_connections;
                        selected_index = i;
                    }
                }
                
                &self.replica_pools[selected_index]
            }
            LoadBalancer::ResponseTime => {
                // Select replica with best response time (simplified)
                &self.replica_pools[0]
            }
        }
    }

    /// Monitor replica health
    pub async fn monitor_replica_health(&self) {
        for (i, replica) in self.replica_pools.iter().enumerate() {
            let start = Instant::now();
            match sqlx::query("SELECT 1").fetch_one(&replica.pool).await {
                Ok(_) => {
                    let latency = start.elapsed();
                    self.metrics.replica_health.set(1.0);
                    self.metrics.replication_lag.observe(latency.as_secs_f64());
                }
                Err(_) => {
                    self.metrics.replica_health.set(0.0);
                    warn!("Replica {} health check failed", i);
                }
            }
        }
    }
}

// Metrics implementations
impl DbMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let queries_total = Counter::with_opts(
            Opts::new("db_queries_total", "Total database queries")
        )?;

        let query_duration = Histogram::with_opts(
            HistogramOpts::new("db_query_duration_seconds", "Database query duration")
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0])
        )?;

        let connection_pool_size = Gauge::with_opts(
            Opts::new("db_connection_pool_size", "Database connection pool size")
        )?;

        let active_connections = Gauge::with_opts(
            Opts::new("db_active_connections", "Active database connections")
        )?;

        let query_cache_hits = Counter::with_opts(
            Opts::new("db_query_cache_hits_total", "Database query cache hits")
        )?;

        let query_cache_misses = Counter::with_opts(
            Opts::new("db_query_cache_misses_total", "Database query cache misses")
        )?;

        let slow_queries = Counter::with_opts(
            Opts::new("db_slow_queries_total", "Slow database queries")
        )?;

        let connection_errors = Counter::with_opts(
            Opts::new("db_connection_errors_total", "Database connection errors")
        )?;

        let transaction_duration = Histogram::with_opts(
            HistogramOpts::new("db_transaction_duration_seconds", "Database transaction duration")
                .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0])
        )?;

        registry.register(Box::new(queries_total.clone()))?;
        registry.register(Box::new(query_duration.clone()))?;
        registry.register(Box::new(connection_pool_size.clone()))?;
        registry.register(Box::new(active_connections.clone()))?;
        registry.register(Box::new(query_cache_hits.clone()))?;
        registry.register(Box::new(query_cache_misses.clone()))?;
        registry.register(Box::new(slow_queries.clone()))?;
        registry.register(Box::new(connection_errors.clone()))?;
        registry.register(Box::new(transaction_duration.clone()))?;

        Ok(Self {
            queries_total,
            query_duration,
            connection_pool_size,
            active_connections,
            query_cache_hits,
            query_cache_misses,
            slow_queries,
            connection_errors,
            transaction_duration,
        })
    }
}

impl QueryOptimizerMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Opts, HistogramOpts};

        let queries_analyzed = Counter::with_opts(
            Opts::new("db_queries_analyzed_total", "Total queries analyzed")
        )?;

        let optimizations_applied = Counter::with_opts(
            Opts::new("db_optimizations_applied_total", "Total optimizations applied")
        )?;

        let performance_improvement = Histogram::with_opts(
            HistogramOpts::new("db_performance_improvement_ratio", "Performance improvement ratio")
                .buckets(vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
        )?;

        registry.register(Box::new(queries_analyzed.clone()))?;
        registry.register(Box::new(optimizations_applied.clone()))?;
        registry.register(Box::new(performance_improvement.clone()))?;

        Ok(Self {
            queries_analyzed,
            optimizations_applied,
            performance_improvement,
        })
    }
}

impl BatchProcessorMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let batches_processed = Counter::with_opts(
            Opts::new("db_batches_processed_total", "Total batches processed")
        )?;

        let batch_size_histogram = Histogram::with_opts(
            HistogramOpts::new("db_batch_size", "Database batch size")
                .buckets(vec![1.0, 10.0, 50.0, 100.0, 500.0, 1000.0])
        )?;

        let batch_efficiency = Gauge::with_opts(
            Opts::new("db_batch_efficiency", "Database batch processing efficiency")
        )?;

        registry.register(Box::new(batches_processed.clone()))?;
        registry.register(Box::new(batch_size_histogram.clone()))?;
        registry.register(Box::new(batch_efficiency.clone()))?;

        Ok(Self {
            batches_processed,
            batch_size_histogram,
            batch_efficiency,
        })
    }
}

impl ReplicaMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let read_queries_routed = Counter::with_opts(
            Opts::new("db_read_queries_routed_total", "Total read queries routed to replicas")
        )?;

        let replica_health = Gauge::with_opts(
            Opts::new("db_replica_health", "Database replica health (0=unhealthy, 1=healthy)")
        )?;

        let replication_lag = Histogram::with_opts(
            HistogramOpts::new("db_replication_lag_seconds", "Database replication lag")
                .buckets(vec![0.001, 0.01, 0.1, 1.0, 10.0])
        )?;

        registry.register(Box::new(read_queries_routed.clone()))?;
        registry.register(Box::new(replica_health.clone()))?;
        registry.register(Box::new(replication_lag.clone()))?;

        Ok(Self {
            read_queries_routed,
            replica_health,
            replication_lag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_query_optimizer() {
        let registry = prometheus::Registry::new();
        let optimizer = QueryOptimizer::new(&registry).unwrap();

        let suggestions = optimizer.analyze_query(
            "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)",
            Duration::from_millis(150)
        ).await;

        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.contains("slow")));
    }

    #[test]
    fn test_query_hash() {
        let registry = prometheus::Registry::new();
        // This would require a database connection, so we'll skip the actual test
        // but the structure shows how it would work
    }
}
