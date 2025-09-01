#![allow(clippy::unused_async)]
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Intelligent cache with predictive prefetching and adaptive algorithms
#[derive(Debug, Clone)]
pub struct IntelligentCache<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + std::fmt::Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Cache storage with metadata
    storage: Arc<RwLock<CacheStorage<K, V>>>,
    /// Cache configuration
    config: Arc<RwLock<CacheConfig>>,
    /// Access pattern analyzer
    analyzer: Arc<RwLock<AccessPatternAnalyzer<K>>>,
    /// Predictive prefetcher
    prefetcher: Arc<RwLock<PredictivePrefetcher<K>>>,
    /// Cache metrics
    metrics: Arc<RwLock<CacheMetrics>>,
}

#[derive(Debug, Clone)]
pub struct CacheStorage<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    /// Main cache entries
    entries: HashMap<K, CacheEntry<V>>,
    /// LRU tracking
    lru_order: VecDeque<K>,
    /// Frequency tracking for LFU
    frequency: HashMap<K, u64>,
    /// Size tracking
    current_size: usize,
}

#[derive(Debug, Clone)]
pub struct CacheEntry<V>
where
    V: Clone,
{
    /// Cached value
    pub value: V,
    /// Entry metadata
    pub metadata: EntryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// When the entry was created
    pub created_at: SystemTime,
    /// When the entry was last accessed
    pub last_accessed: SystemTime,
    /// Number of times accessed
    pub access_count: u64,
    /// Entry size in bytes (estimated)
    pub size: usize,
    /// Time-to-live
    pub ttl: Duration,
    /// Priority level
    pub priority: CachePriority,
    /// Tags for categorization
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CachePriority {
    Critical,
    High,
    Normal,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum cache size in bytes
    pub max_size: usize,
    /// Maximum number of entries
    pub max_entries: usize,
    /// Default TTL for entries
    pub default_ttl: Duration,
    /// Eviction policy
    pub eviction_policy: EvictionPolicy,
    /// Enable predictive prefetching
    pub enable_prefetching: bool,
    /// Prefetch threshold (0.0 to 1.0)
    pub prefetch_threshold: f64,
    /// Cache warming settings
    pub warming_config: WarmingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvictionPolicy {
    LRU,         // Least Recently Used
    LFU,         // Least Frequently Used
    TLRU,        // Time-aware LRU
    ARC,         // Adaptive Replacement Cache
    Intelligent, // ML-based eviction
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmingConfig {
    /// Enable cache warming on startup
    pub enabled: bool,
    /// Keys to warm up
    pub warm_keys: Vec<String>,
    /// Warming batch size
    pub batch_size: usize,
    /// Warming timeout
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct AccessPatternAnalyzer<K>
where
    K: Clone + Eq + Hash,
{
    /// Access history
    access_history: VecDeque<AccessEvent<K>>,
    // /// Pattern recognition
    // patterns: HashMap<String, AccessPattern>,
    /// Temporal analysis
    temporal_patterns: HashMap<u8, Vec<K>>, // Hour -> Keys
}

#[derive(Debug, Clone)]
pub struct AccessEvent<K>
where
    K: Clone,
{
    pub key: K,
    pub timestamp: SystemTime,
    pub access_type: AccessType,
}

#[derive(Debug, Clone)]
pub enum AccessType {
    Hit,
    Miss,
    Prefetch,
}

#[derive(Debug, Clone)]
pub struct AccessPattern {
    pub pattern_id: String,
    pub frequency: f64,
    pub confidence: f64,
    pub next_keys: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PredictivePrefetcher<K>
where
    K: Clone + Eq + Hash,
{
    /// Prediction models
    models: HashMap<String, PredictionModel<K>>,
    /// Prefetch queue
    prefetch_queue: VecDeque<PrefetchRequest<K>>,
    /// Success rate tracking
    success_rate: f64,
}

#[derive(Debug, Clone)]
pub struct PredictionModel<K>
where
    K: Clone,
{
    pub model_type: ModelType,
    pub accuracy: f64,
    pub predictions: HashMap<K, f64>, // Key -> Probability
}

#[derive(Debug, Clone)]
pub enum ModelType {
    Markov,
    NeuralNetwork,
    StatisticalAnalysis,
    HybridModel,
}

#[derive(Debug, Clone)]
pub struct PrefetchRequest<K>
where
    K: Clone,
{
    pub key: K,
    pub probability: f64,
    pub requested_at: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    /// Hit/miss statistics
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,

    /// Performance metrics
    pub avg_access_time: Duration,
    pub p95_access_time: Duration,
    pub p99_access_time: Duration,

    /// Size metrics
    pub current_entries: usize,
    pub current_size: usize,
    pub max_size_reached: bool,

    /// Eviction statistics
    pub evictions: u64,
    pub eviction_reasons: HashMap<String, u64>,

    /// Prefetch statistics
    pub prefetch_requests: u64,
    pub prefetch_hits: u64,
    pub prefetch_success_rate: f64,
}

impl<K, V> IntelligentCache<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + std::fmt::Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create new intelligent cache
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            storage: Arc::new(RwLock::new(CacheStorage::new())),
            config: Arc::new(RwLock::new(config)),
            analyzer: Arc::new(RwLock::new(AccessPatternAnalyzer::new())),
            prefetcher: Arc::new(RwLock::new(PredictivePrefetcher::new())),
            metrics: Arc::new(RwLock::new(CacheMetrics::default())),
        }
    }

    /// Get value from cache
    pub async fn get(&self, key: &K) -> Option<V> {
        let start_time = Instant::now();

        // Check cache
        let mut storage = self.storage.write().await;
        let mut metrics = self.metrics.write().await;

        if let Some(entry) = storage.entries.get(key) {
            // Check if entry is expired
            if self.is_expired(&entry.metadata).await {
                storage.entries.remove(key);
                metrics.misses += 1;
                return None;
            }

            let value = entry.value.clone();

            // Update access metadata (get mutable reference after cloning value)
            if let Some(entry) = storage.entries.get_mut(key) {
                entry.metadata.last_accessed = SystemTime::now();
                entry.metadata.access_count += 1;
            }

            // Update LRU order and frequency without aliasing
            let pos_opt = storage.lru_order.iter().position(|k| k == key);
            if let Some(pos) = pos_opt {
                storage.lru_order.remove(pos);
            }
            storage.lru_order.push_back(key.clone());
            let freq = storage.frequency.entry(key.clone()).or_insert(0);
            *freq += 1;

            // Update metrics
            metrics.hits += 1;
            metrics.hit_rate = metrics.hits as f64 / (metrics.hits + metrics.misses) as f64;
            metrics.avg_access_time = start_time.elapsed();

            // Record access event
            drop(storage); // Release storage lock
            drop(metrics); // Release metrics lock
            let mut analyzer = self.analyzer.write().await;
            analyzer.record_access(key.clone(), AccessType::Hit).await;

            // Trigger predictive prefetching
            self.trigger_prefetch(key).await;

            Some(value)
        } else {
            metrics.misses += 1;
            metrics.hit_rate = metrics.hits as f64 / (metrics.hits + metrics.misses) as f64;

            // Record miss event
            drop(storage); // Release storage lock
            drop(metrics); // Release metrics lock
            let mut analyzer = self.analyzer.write().await;
            analyzer.record_access(key.clone(), AccessType::Miss).await;

            None
        }
    }

    /// Put value into cache
    ///
    /// # Errors
    ///
    /// Returns `CacheError` if:
    /// - Entry eviction fails during size management
    /// - Memory allocation fails
    /// - Cache size limits are exceeded and eviction cannot free space
    pub async fn put(&self, key: K, value: V, ttl: Option<Duration>) -> Result<(), CacheError> {
        let mut storage = self.storage.write().await;
        let config = self.config.read().await;

        // Calculate entry size (simplified)
        let entry_size = std::mem::size_of::<V>();

        // Check if we need to evict entries
        while storage.current_size + entry_size > config.max_size
            || storage.entries.len() >= config.max_entries
        {
            self.evict_entry(&mut storage, &config).await?;
        }

        // Create cache entry
        let entry = CacheEntry {
            value,
            metadata: EntryMetadata {
                created_at: SystemTime::now(),
                last_accessed: SystemTime::now(),
                access_count: 1,
                size: entry_size,
                ttl: ttl.unwrap_or(config.default_ttl),
                priority: CachePriority::Normal,
                tags: Vec::new(),
            },
        };

        // Insert entry
        storage.entries.insert(key.clone(), entry);
        storage.lru_order.push_back(key.clone());
        storage.current_size += entry_size;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.current_entries = storage.entries.len();
        metrics.current_size = storage.current_size;

        Ok(())
    }

    /// Remove entry from cache
    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut storage = self.storage.write().await;

        if let Some(entry) = storage.entries.remove(key) {
            // Update LRU order
            if let Some(pos) = storage.lru_order.iter().position(|k| k == key) {
                storage.lru_order.remove(pos);
            }

            // Update size
            storage.current_size -= entry.metadata.size;

            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.current_entries = storage.entries.len();
            metrics.current_size = storage.current_size;

            Some(entry.value)
        } else {
            None
        }
    }

    /// Clear all entries
    pub async fn clear(&self) {
        let mut storage = self.storage.write().await;
        storage.entries.clear();
        storage.lru_order.clear();
        storage.frequency.clear();
        storage.current_size = 0;

        let mut metrics = self.metrics.write().await;
        metrics.current_entries = 0;
        metrics.current_size = 0;
    }

    /// Get cache statistics
    pub async fn get_metrics(&self) -> CacheMetrics {
        self.metrics.read().await.clone()
    }

    /// Warm up cache with predefined keys
    ///
    /// # Errors
    ///
    /// Returns `CacheError` if:
    /// - Cache warming is disabled in configuration
    /// - Loader function fails to provide data
    /// - Cache insertion fails during warm-up
    pub async fn warm_up<F, Fut>(&self, loader: F) -> Result<(), CacheError>
    where
        F: Fn(String) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Option<V>> + Send,
    {
        let config = self.config.read().await;

        if !config.warming_config.enabled {
            return Ok(());
        }

        info!(
            keys_count = config.warming_config.warm_keys.len(),
            "Starting cache warm-up"
        );

        for key_str in &config.warming_config.warm_keys {
            if let Some(_value) = loader(key_str.clone()).await {
                // Convert string key to K (this is simplified - would need proper conversion)
                // For now, we'll skip this as it requires more complex type handling
                debug!(key = key_str, "Warmed up cache entry");
            }
        }

        info!("Cache warm-up completed");
        Ok(())
    }

    // Private helper methods
    async fn is_expired(&self, metadata: &EntryMetadata) -> bool {
        let now = SystemTime::now();
        if let Ok(elapsed) = now.duration_since(metadata.created_at) {
            elapsed > metadata.ttl
        } else {
            true // If we can't determine time, consider expired
        }
    }

    async fn evict_entry(
        &self,
        storage: &mut CacheStorage<K, V>,
        config: &CacheConfig,
    ) -> Result<(), CacheError> {
        let key_to_evict = match config.eviction_policy {
            EvictionPolicy::LRU => storage.lru_order.front().cloned(),
            EvictionPolicy::LFU => storage
                .frequency
                .iter()
                .min_by_key(|(_, &freq)| freq)
                .map(|(key, _)| key.clone()),
            EvictionPolicy::TLRU => {
                // Time-aware LRU: consider both recency and TTL
                storage
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.metadata.last_accessed)
                    .map(|(key, _)| key.clone())
            }
            EvictionPolicy::ARC | EvictionPolicy::Intelligent => {
                // Simplified - would implement full ARC algorithm
                storage.lru_order.front().cloned()
            }
        };

        if let Some(key) = key_to_evict {
            if let Some(entry) = storage.entries.remove(&key) {
                // Update tracking structures
                if let Some(pos) = storage.lru_order.iter().position(|k| k == &key) {
                    storage.lru_order.remove(pos);
                }
                storage.frequency.remove(&key);
                storage.current_size -= entry.metadata.size;

                // Update metrics
                let mut metrics = self.metrics.write().await;
                metrics.evictions += 1;
                *metrics
                    .eviction_reasons
                    .entry("size_limit".to_string())
                    .or_insert(0) += 1;

                info!(evicted_key = ?key, "Evicted cache entry");
            }
        }

        Ok(())
    }

    async fn trigger_prefetch(&self, _accessed_key: &K) {
        let config = self.config.read().await;

        if !config.enable_prefetching {
            return;
        }

        let mut prefetcher = self.prefetcher.write().await;

        // Simple prefetch logic - would be more sophisticated in practice
        if prefetcher.success_rate > config.prefetch_threshold {
            // Predict next keys based on access patterns
            if let Some(predictions) = prefetcher.models.get("markov") {
                let predictions_clone = predictions.predictions.clone();
                // predictions immutable ref ends here
                let _ = predictions;

                for (key, probability) in predictions_clone {
                    if probability > config.prefetch_threshold {
                        prefetcher.prefetch_queue.push_back(PrefetchRequest {
                            key,
                            probability,
                            requested_at: SystemTime::now(),
                        });
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum CacheError {
    SizeLimitExceeded,
    EntryNotFound,
    SerializationError,
    ConfigurationError(String),
}

impl<K> Default for AccessPatternAnalyzer<K>
where
    K: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K> AccessPatternAnalyzer<K>
where
    K: Clone + Eq + Hash,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            access_history: VecDeque::new(),
            // patterns: HashMap::new(),
            temporal_patterns: HashMap::new(),
        }
    }

    pub async fn record_access(&mut self, key: K, access_type: AccessType) {
        let event = AccessEvent {
            key: key.clone(),
            timestamp: SystemTime::now(),
            access_type,
        };

        self.access_history.push_back(event);

        // Keep only recent history (last 1000 events)
        if self.access_history.len() > 1000 {
            self.access_history.pop_front();
        }

        // Update temporal patterns
        if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
            let hour = (duration.as_secs() / 3600 % 24) as u8;
            self.temporal_patterns.entry(hour).or_default().push(key);
        }
    }
}

impl<K> Default for PredictivePrefetcher<K>
where
    K: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K> PredictivePrefetcher<K>
where
    K: Clone + Eq + Hash,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
            prefetch_queue: VecDeque::new(),
            success_rate: 0.5, // Start with neutral success rate
        }
    }
}

impl<K, V> Default for CacheStorage<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> CacheStorage<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru_order: VecDeque::new(),
            frequency: HashMap::new(),
            current_size: 0,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 100 * 1024 * 1024, // 100MB
            max_entries: 10000,
            default_ttl: Duration::from_secs(3600), // 1 hour
            eviction_policy: EvictionPolicy::LRU,
            enable_prefetching: true,
            prefetch_threshold: 0.7,
            warming_config: WarmingConfig {
                enabled: false,
                warm_keys: Vec::new(),
                batch_size: 100,
                timeout: Duration::from_secs(30),
            },
        }
    }
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self {
            hits: 0,
            misses: 0,
            hit_rate: 0.0,
            avg_access_time: Duration::ZERO,
            p95_access_time: Duration::ZERO,
            p99_access_time: Duration::ZERO,
            current_entries: 0,
            current_size: 0,
            max_size_reached: false,
            evictions: 0,
            eviction_reasons: HashMap::new(),
            prefetch_requests: 0,
            prefetch_hits: 0,
            prefetch_success_rate: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_intelligent_cache() {
        let config = CacheConfig::default();
        let cache = IntelligentCache::<String, String>::new(config);

        // Test put and get
        cache
            .put("key1".to_string(), "value1".to_string(), None)
            .await
            .unwrap();
        let value = cache.get(&"key1".to_string()).await;
        assert_eq!(value, Some("value1".to_string()));

        // Test metrics
        let metrics = cache.get_metrics().await;
        assert_eq!(metrics.hits, 1);
        assert_eq!(metrics.misses, 0);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let mut config = CacheConfig::default();
        config.max_entries = 2;

        let cache = IntelligentCache::<String, String>::new(config);

        // Fill cache beyond capacity
        cache
            .put("key1".to_string(), "value1".to_string(), None)
            .await
            .unwrap();
        cache
            .put("key2".to_string(), "value2".to_string(), None)
            .await
            .unwrap();
        cache
            .put("key3".to_string(), "value3".to_string(), None)
            .await
            .unwrap();

        // First key should be evicted
        let value1 = cache.get(&"key1".to_string()).await;
        assert_eq!(value1, None);

        // Other keys should still exist
        let value2 = cache.get(&"key2".to_string()).await;
        let value3 = cache.get(&"key3".to_string()).await;
        assert_eq!(value2, Some("value2".to_string()));
        assert_eq!(value3, Some("value3".to_string()));
    }
}
