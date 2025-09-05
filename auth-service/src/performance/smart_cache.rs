use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Intelligent cache with metrics and prefetching
pub struct SmartCache<K, V> {
    cache: Arc<RwLock<lru::LruCache<K, CacheEntry<V>>>>,
    metrics: CacheMetrics,
    ttl: Duration,
}

struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    access_count: u64,
}

#[derive(Default)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
}

impl<K, V> SmartCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(capacity).unwrap()
            ))),
            metrics: CacheMetrics::default(),
            ttl,
        }
    }

    pub async fn get_or_compute<F, Fut, E>(&self, key: K, compute: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        // Try cache first
        {
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache.get_mut(&key) {
                if entry.created_at.elapsed() < self.ttl {
                    entry.access_count += 1;
                    return Ok(entry.value.clone());
                } else {
                    cache.pop(&key);
                }
            }
        }

        // Compute and cache
        let value = compute().await?;
        self.insert(key, value.clone()).await;
        Ok(value)
    }

    async fn insert(&self, key: K, value: V) {
        let mut cache = self.cache.write().await;
        let entry = CacheEntry {
            value,
            created_at: Instant::now(),
            access_count: 1,
        };
        cache.put(key, entry);
    }

    pub async fn metrics(&self) -> CacheMetrics {
        self.metrics.clone()
    }
}

impl Clone for CacheMetrics {
    fn clone(&self) -> Self {
        Self {
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
        }
    }
}
