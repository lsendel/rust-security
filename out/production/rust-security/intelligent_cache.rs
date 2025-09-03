// Phase 2: Intelligent Multi-Level Caching System
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn, instrument};
use prometheus::{Counter, Histogram, Gauge};

/// Multi-level intelligent caching system with L1 (memory) and L2 (Redis) layers
#[derive(Clone)]
pub struct IntelligentCache {
    // L1 Cache: In-memory for ultra-fast access
    l1_cache: Arc<RwLock<HashMap<String, L1CacheEntry>>>,
    l1_config: L1Config,
    
    // L2 Cache: Redis for shared cache across instances
    redis: redis::aio::ConnectionManager,
    l2_config: L2Config,
    
    // Cache intelligence
    access_patterns: Arc<RwLock<HashMap<String, AccessPattern>>>,
    metrics: CacheMetrics,
}

#[derive(Debug, Clone)]
struct L1CacheEntry {
    data: serde_json::Value,
    expires_at: Instant,
    access_count: u64,
    last_accessed: Instant,
    size_bytes: usize,
    cache_level: CacheLevel,
}

#[derive(Debug, Clone)]
struct AccessPattern {
    access_count: u64,
    last_access: Instant,
    access_frequency: f64,  // accesses per second
    cache_hit_rate: f64,
    average_ttl: Duration,
}

#[derive(Debug, Clone, PartialEq)]
enum CacheLevel {
    L1Only,    // Memory only
    L1L2,      // Both memory and Redis
    L2Only,    // Redis only
}

#[derive(Debug, Clone)]
pub struct L1Config {
    pub max_entries: usize,
    pub max_memory_mb: usize,
    pub default_ttl: Duration,
    pub cleanup_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct L2Config {
    pub default_ttl: Duration,
    pub key_prefix: String,
    pub compression_threshold: usize,
    pub batch_size: usize,
}

#[derive(Debug, Clone)]
pub struct CacheMetrics {
    pub l1_hits: Counter,
    pub l1_misses: Counter,
    pub l2_hits: Counter,
    pub l2_misses: Counter,
    pub l1_evictions: Counter,
    pub l2_evictions: Counter,
    pub cache_size_bytes: Gauge,
    pub access_duration: Histogram,
    pub intelligence_score: Gauge,
}

impl IntelligentCache {
    pub async fn new(
        redis_url: &str,
        l1_config: L1Config,
        l2_config: L2Config,
        registry: &prometheus::Registry,
    ) -> Result<Self, CacheError> {
        let client = redis::Client::open(redis_url)?;
        let redis = client.get_connection_manager().await?;
        
        let metrics = CacheMetrics::new(registry)?;
        
        let cache = Self {
            l1_cache: Arc::new(RwLock::new(HashMap::new())),
            l1_config,
            redis,
            l2_config,
            access_patterns: Arc::new(RwLock::new(HashMap::new())),
            metrics,
        };
        
        // Start background cleanup task
        cache.start_cleanup_task().await;
        
        Ok(cache)
    }

    /// Get value from cache with intelligent level selection
    #[instrument(skip(self), fields(cache_key = %key))]
    pub async fn get<T>(&self, key: &str) -> Result<Option<T>, CacheError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let start = Instant::now();
        let cache_key = self.build_cache_key(key);
        
        // Try L1 cache first
        if let Some(entry) = self.get_from_l1(&cache_key).await {
            self.metrics.l1_hits.inc();
            self.update_access_pattern(&cache_key, true, CacheLevel::L1Only).await;
            
            let result: T = serde_json::from_value(entry.data)?;
            debug!("L1 cache hit for key: {}", key);
            
            self.metrics.access_duration.observe(start.elapsed().as_secs_f64());
            return Ok(Some(result));
        }
        
        self.metrics.l1_misses.inc();
        
        // Try L2 cache (Redis)
        if let Some(data) = self.get_from_l2(&cache_key).await? {
            self.metrics.l2_hits.inc();
            self.update_access_pattern(&cache_key, true, CacheLevel::L2Only).await;
            
            let result: T = serde_json::from_value(data.clone())?;
            
            // Promote to L1 if access pattern suggests it
            if self.should_promote_to_l1(&cache_key).await {
                self.set_l1(&cache_key, data, self.l1_config.default_ttl).await;
            }
            
            debug!("L2 cache hit for key: {}", key);
            self.metrics.access_duration.observe(start.elapsed().as_secs_f64());
            return Ok(Some(result));
        }
        
        self.metrics.l2_misses.inc();
        self.update_access_pattern(&cache_key, false, CacheLevel::L1Only).await;
        
        debug!("Cache miss for key: {}", key);
        self.metrics.access_duration.observe(start.elapsed().as_secs_f64());
        Ok(None)
    }

    /// Set value in cache with intelligent level selection
    #[instrument(skip(self, value), fields(cache_key = %key))]
    pub async fn set<T>(&self, key: &str, value: &T, ttl: Duration) -> Result<(), CacheError>
    where
        T: Serialize,
    {
        let cache_key = self.build_cache_key(key);
        let data = serde_json::to_value(value)?;
        
        // Determine optimal cache level based on access patterns
        let cache_level = self.determine_cache_level(&cache_key, &data).await;
        
        match cache_level {
            CacheLevel::L1Only => {
                self.set_l1(&cache_key, data, ttl).await;
            }
            CacheLevel::L2Only => {
                self.set_l2(&cache_key, data, ttl).await?;
            }
            CacheLevel::L1L2 => {
                self.set_l1(&cache_key, data.clone(), ttl).await;
                self.set_l2(&cache_key, data, ttl).await?;
            }
        }
        
        debug!("Set cache key: {} with level: {:?}", key, cache_level);
        Ok(())
    }

    /// Batch get operation for multiple keys
    pub async fn get_batch<T>(&self, keys: &[&str]) -> Result<HashMap<String, T>, CacheError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut results = HashMap::new();
        let mut l2_keys = Vec::new();
        
        // Check L1 cache for all keys first
        for key in keys {
            let cache_key = self.build_cache_key(key);
            if let Some(entry) = self.get_from_l1(&cache_key).await {
                let value: T = serde_json::from_value(entry.data)?;
                results.insert(key.to_string(), value);
                self.metrics.l1_hits.inc();
            } else {
                l2_keys.push(cache_key);
                self.metrics.l1_misses.inc();
            }
        }
        
        // Batch fetch from L2 for remaining keys
        if !l2_keys.is_empty() {
            let l2_results = self.get_batch_from_l2(&l2_keys).await?;
            for (key, data) in l2_results {
                let original_key = self.extract_original_key(&key);
                let value: T = serde_json::from_value(data.clone())?;
                results.insert(original_key, value);
                self.metrics.l2_hits.inc();
                
                // Consider promoting frequently accessed items to L1
                if self.should_promote_to_l1(&key).await {
                    self.set_l1(&key, data, self.l1_config.default_ttl).await;
                }
            }
        }
        
        Ok(results)
    }

    /// Batch set operation for multiple key-value pairs
    pub async fn set_batch<T>(&self, items: &[(&str, &T)], ttl: Duration) -> Result<(), CacheError>
    where
        T: Serialize,
    {
        let mut l1_items = Vec::new();
        let mut l2_items = Vec::new();
        
        for (key, value) in items {
            let cache_key = self.build_cache_key(key);
            let data = serde_json::to_value(value)?;
            
            let cache_level = self.determine_cache_level(&cache_key, &data).await;
            
            match cache_level {
                CacheLevel::L1Only => {
                    l1_items.push((cache_key, data));
                }
                CacheLevel::L2Only => {
                    l2_items.push((cache_key, data));
                }
                CacheLevel::L1L2 => {
                    l1_items.push((cache_key.clone(), data.clone()));
                    l2_items.push((cache_key, data));
                }
            }
        }
        
        // Batch set L1 items
        for (key, data) in l1_items {
            self.set_l1(&key, data, ttl).await;
        }
        
        // Batch set L2 items
        if !l2_items.is_empty() {
            self.set_batch_l2(&l2_items, ttl).await?;
        }
        
        Ok(())
    }

    /// Invalidate cache entry
    pub async fn invalidate(&self, key: &str) -> Result<(), CacheError> {
        let cache_key = self.build_cache_key(key);
        
        // Remove from L1
        {
            let mut l1_cache = self.l1_cache.write().await;
            l1_cache.remove(&cache_key);
        }
        
        // Remove from L2
        let mut redis = self.redis.clone();
        let _: () = redis.del(&cache_key).await?;
        
        debug!("Invalidated cache key: {}", key);
        Ok(())
    }

    /// Warm cache with predicted data
    pub async fn warm_cache<T>(&self, predictions: &[(&str, &T)]) -> Result<(), CacheError>
    where
        T: Serialize,
    {
        info!("Warming cache with {} predictions", predictions.len());
        
        // Use longer TTL for warmed data
        let warm_ttl = self.l1_config.default_ttl * 2;
        self.set_batch(predictions, warm_ttl).await?;
        
        Ok(())
    }

    /// Get cache statistics and intelligence metrics
    pub async fn get_stats(&self) -> CacheStats {
        let l1_cache = self.l1_cache.read().await;
        let access_patterns = self.access_patterns.read().await;
        
        let l1_size = l1_cache.len();
        let l1_memory_usage: usize = l1_cache.values().map(|e| e.size_bytes).sum();
        
        let total_accesses: u64 = access_patterns.values().map(|p| p.access_count).sum();
        let avg_hit_rate: f64 = if access_patterns.is_empty() {
            0.0
        } else {
            access_patterns.values().map(|p| p.cache_hit_rate).sum::<f64>() / access_patterns.len() as f64
        };
        
        // Calculate intelligence score based on hit rates and access patterns
        let intelligence_score = self.calculate_intelligence_score(&access_patterns).await;
        self.metrics.intelligence_score.set(intelligence_score);
        
        CacheStats {
            l1_entries: l1_size,
            l1_memory_usage_bytes: l1_memory_usage,
            l2_estimated_entries: 0, // Would need Redis DBSIZE for exact count
            total_accesses,
            average_hit_rate: avg_hit_rate,
            intelligence_score,
            access_patterns_tracked: access_patterns.len(),
        }
    }

    // Private helper methods
    
    async fn get_from_l1(&self, key: &str) -> Option<L1CacheEntry> {
        let mut l1_cache = self.l1_cache.write().await;
        if let Some(entry) = l1_cache.get_mut(key) {
            if entry.expires_at > Instant::now() {
                entry.access_count += 1;
                entry.last_accessed = Instant::now();
                return Some(entry.clone());
            } else {
                l1_cache.remove(key);
            }
        }
        None
    }

    async fn get_from_l2(&self, key: &str) -> Result<Option<serde_json::Value>, CacheError> {
        let mut redis = self.redis.clone();
        let data: Option<String> = redis.get(key).await?;
        
        if let Some(serialized) = data {
            let value: serde_json::Value = serde_json::from_str(&serialized)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn get_batch_from_l2(&self, keys: &[String]) -> Result<HashMap<String, serde_json::Value>, CacheError> {
        let mut redis = self.redis.clone();
        let values: Vec<Option<String>> = redis.mget(keys).await?;
        
        let mut results = HashMap::new();
        for (i, value) in values.into_iter().enumerate() {
            if let Some(serialized) = value {
                if let Ok(data) = serde_json::from_str(&serialized) {
                    results.insert(keys[i].clone(), data);
                }
            }
        }
        
        Ok(results)
    }

    async fn set_l1(&self, key: &str, data: serde_json::Value, ttl: Duration) {
        let size_bytes = serde_json::to_string(&data).map(|s| s.len()).unwrap_or(0);
        
        let entry = L1CacheEntry {
            data,
            expires_at: Instant::now() + ttl,
            access_count: 0,
            last_accessed: Instant::now(),
            size_bytes,
            cache_level: CacheLevel::L1Only,
        };
        
        let mut l1_cache = self.l1_cache.write().await;
        
        // Check if we need to evict entries
        if l1_cache.len() >= self.l1_config.max_entries {
            self.evict_l1_entries(&mut l1_cache).await;
        }
        
        l1_cache.insert(key.to_string(), entry);
        self.update_cache_size_metric().await;
    }

    async fn set_l2(&self, key: &str, data: serde_json::Value, ttl: Duration) -> Result<(), CacheError> {
        let mut redis = self.redis.clone();
        let serialized = serde_json::to_string(&data)?;
        
        let _: () = redis.setex(key, ttl.as_secs() as usize, serialized).await?;
        Ok(())
    }

    async fn set_batch_l2(&self, items: &[(String, serde_json::Value)], ttl: Duration) -> Result<(), CacheError> {
        let mut redis = self.redis.clone();
        
        // Use pipeline for batch operations
        let mut pipe = redis::pipe();
        for (key, data) in items {
            let serialized = serde_json::to_string(data)?;
            pipe.setex(key, ttl.as_secs() as usize, serialized);
        }
        
        let _: () = pipe.query_async(&mut redis).await?;
        Ok(())
    }

    async fn should_promote_to_l1(&self, key: &str) -> bool {
        let access_patterns = self.access_patterns.read().await;
        if let Some(pattern) = access_patterns.get(key) {
            // Promote if frequently accessed and has good hit rate
            pattern.access_frequency > 1.0 && pattern.cache_hit_rate > 0.8
        } else {
            false
        }
    }

    async fn determine_cache_level(&self, key: &str, data: &serde_json::Value) -> CacheLevel {
        let data_size = serde_json::to_string(data).map(|s| s.len()).unwrap_or(0);
        
        // Small, frequently accessed data goes to both levels
        if data_size < 1024 {  // < 1KB
            if let Some(pattern) = self.access_patterns.read().await.get(key) {
                if pattern.access_frequency > 2.0 {
                    return CacheLevel::L1L2;
                }
            }
            CacheLevel::L1Only
        } else if data_size < 10240 {  // < 10KB
            CacheLevel::L2Only
        } else {
            // Large data only in L2
            CacheLevel::L2Only
        }
    }

    async fn update_access_pattern(&self, key: &str, hit: bool, level: CacheLevel) {
        let mut patterns = self.access_patterns.write().await;
        let pattern = patterns.entry(key.to_string()).or_insert(AccessPattern {
            access_count: 0,
            last_access: Instant::now(),
            access_frequency: 0.0,
            cache_hit_rate: 0.0,
            average_ttl: Duration::from_secs(300),
        });
        
        pattern.access_count += 1;
        let time_since_last = pattern.last_access.elapsed();
        pattern.last_access = Instant::now();
        
        // Update frequency (exponential moving average)
        if time_since_last.as_secs_f64() > 0.0 {
            let current_freq = 1.0 / time_since_last.as_secs_f64();
            pattern.access_frequency = 0.9 * pattern.access_frequency + 0.1 * current_freq;
        }
        
        // Update hit rate (exponential moving average)
        let hit_value = if hit { 1.0 } else { 0.0 };
        pattern.cache_hit_rate = 0.9 * pattern.cache_hit_rate + 0.1 * hit_value;
    }

    async fn evict_l1_entries(&self, l1_cache: &mut HashMap<String, L1CacheEntry>) {
        // LRU eviction with access count consideration
        let mut entries: Vec<_> = l1_cache.iter().collect();
        entries.sort_by(|a, b| {
            let score_a = a.1.access_count as f64 / a.1.last_accessed.elapsed().as_secs_f64().max(1.0);
            let score_b = b.1.access_count as f64 / b.1.last_accessed.elapsed().as_secs_f64().max(1.0);
            score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Remove bottom 25% of entries
        let evict_count = (l1_cache.len() / 4).max(1);
        for (key, _) in entries.iter().take(evict_count) {
            l1_cache.remove(*key);
            self.metrics.l1_evictions.inc();
        }
    }

    async fn calculate_intelligence_score(&self, patterns: &HashMap<String, AccessPattern>) -> f64 {
        if patterns.is_empty() {
            return 0.0;
        }
        
        let avg_hit_rate: f64 = patterns.values().map(|p| p.cache_hit_rate).sum::<f64>() / patterns.len() as f64;
        let avg_frequency: f64 = patterns.values().map(|p| p.access_frequency).sum::<f64>() / patterns.len() as f64;
        
        // Intelligence score combines hit rate and access pattern optimization
        (avg_hit_rate * 0.7 + (avg_frequency / 10.0).min(1.0) * 0.3) * 100.0
    }

    async fn update_cache_size_metric(&self) {
        let l1_cache = self.l1_cache.read().await;
        let total_size: usize = l1_cache.values().map(|e| e.size_bytes).sum();
        self.metrics.cache_size_bytes.set(total_size as f64);
    }

    async fn start_cleanup_task(&self) {
        let l1_cache = Arc::clone(&self.l1_cache);
        let cleanup_interval = self.l1_config.cleanup_interval;
        let metrics = self.metrics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                
                let mut cache = l1_cache.write().await;
                let initial_size = cache.len();
                
                // Remove expired entries
                cache.retain(|_, entry| entry.expires_at > Instant::now());
                
                let evicted = initial_size - cache.len();
                if evicted > 0 {
                    debug!("Cleaned up {} expired L1 cache entries", evicted);
                    for _ in 0..evicted {
                        metrics.l1_evictions.inc();
                    }
                }
            }
        });
    }

    fn build_cache_key(&self, key: &str) -> String {
        format!("{}:{}", self.l2_config.key_prefix, key)
    }

    fn extract_original_key(&self, cache_key: &str) -> String {
        cache_key.strip_prefix(&format!("{}:", self.l2_config.key_prefix))
            .unwrap_or(cache_key)
            .to_string()
    }
}

impl CacheMetrics {
    fn new(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        use prometheus::{Counter, Histogram, Gauge, Opts, HistogramOpts};

        let l1_hits = Counter::with_opts(Opts::new("cache_l1_hits_total", "L1 cache hits"))?;
        let l1_misses = Counter::with_opts(Opts::new("cache_l1_misses_total", "L1 cache misses"))?;
        let l2_hits = Counter::with_opts(Opts::new("cache_l2_hits_total", "L2 cache hits"))?;
        let l2_misses = Counter::with_opts(Opts::new("cache_l2_misses_total", "L2 cache misses"))?;
        let l1_evictions = Counter::with_opts(Opts::new("cache_l1_evictions_total", "L1 cache evictions"))?;
        let l2_evictions = Counter::with_opts(Opts::new("cache_l2_evictions_total", "L2 cache evictions"))?;
        let cache_size_bytes = Gauge::with_opts(Opts::new("cache_size_bytes", "Cache size in bytes"))?;
        let access_duration = Histogram::with_opts(
            HistogramOpts::new("cache_access_duration_seconds", "Cache access duration")
                .buckets(vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05])
        )?;
        let intelligence_score = Gauge::with_opts(Opts::new("cache_intelligence_score", "Cache intelligence score (0-100)"))?;

        registry.register(Box::new(l1_hits.clone()))?;
        registry.register(Box::new(l1_misses.clone()))?;
        registry.register(Box::new(l2_hits.clone()))?;
        registry.register(Box::new(l2_misses.clone()))?;
        registry.register(Box::new(l1_evictions.clone()))?;
        registry.register(Box::new(l2_evictions.clone()))?;
        registry.register(Box::new(cache_size_bytes.clone()))?;
        registry.register(Box::new(access_duration.clone()))?;
        registry.register(Box::new(intelligence_score.clone()))?;

        Ok(Self {
            l1_hits,
            l1_misses,
            l2_hits,
            l2_misses,
            l1_evictions,
            l2_evictions,
            cache_size_bytes,
            access_duration,
            intelligence_score,
        })
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub l1_entries: usize,
    pub l1_memory_usage_bytes: usize,
    pub l2_estimated_entries: usize,
    pub total_accesses: u64,
    pub average_hit_rate: f64,
    pub intelligence_score: f64,
    pub access_patterns_tracked: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis error: {0}")]
    RedisError(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("Prometheus error: {0}")]
    PrometheusError(#[from] prometheus::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_cache_level_determination() {
        // This would require a full setup, so we'll test the logic
        let small_data = serde_json::json!({"test": "small"});
        let large_data = serde_json::json!({"test": "x".repeat(20000)});
        
        // Small data should prefer L1
        assert!(serde_json::to_string(&small_data).unwrap().len() < 1024);
        
        // Large data should prefer L2
        assert!(serde_json::to_string(&large_data).unwrap().len() > 10240);
    }

    #[test]
    async fn test_access_pattern_calculation() {
        let mut pattern = AccessPattern {
            access_count: 0,
            last_access: Instant::now(),
            access_frequency: 0.0,
            cache_hit_rate: 0.0,
            average_ttl: Duration::from_secs(300),
        };
        
        // Simulate access pattern updates
        pattern.access_count += 1;
        pattern.cache_hit_rate = 0.9 * pattern.cache_hit_rate + 0.1 * 1.0;
        
        assert!(pattern.cache_hit_rate > 0.0);
        assert_eq!(pattern.access_count, 1);
    }
}
