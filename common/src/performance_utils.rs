//! Performance optimization utilities

use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Efficient string concatenation that avoids unnecessary allocations
pub fn efficient_concat<'a>(prefix: &'a str, suffix: &'a str) -> Cow<'a, str> {
    match (prefix.is_empty(), suffix.is_empty()) {
        (true, false) => suffix.into(),
        (false, true) => prefix.into(),
        (true, true) => "".into(),
        (false, false) => format!("{}{}", prefix, suffix).into(),
    }
}

/// High-performance cache with metrics
pub struct PerformanceCache<K, V> {
    cache: HashMap<K, CacheEntry<V>>,
    hits: AtomicU64,
    misses: AtomicU64,
    max_size: usize,
}

struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    ttl: Duration,
    access_count: AtomicU64,
}

impl<K, V> PerformanceCache<K, V>
where
    K: Eq + Hash + Clone,
    V: Clone,
{
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::with_capacity(max_size),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            max_size,
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        if let Some(entry) = self.cache.get(key) {
            if entry.created_at.elapsed() < entry.ttl {
                entry.access_count.fetch_add(1, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.value.clone());
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert(&mut self, key: K, value: V, ttl: Duration) {
        if self.cache.len() >= self.max_size {
            self.evict_oldest();
        }

        let entry = CacheEntry {
            value,
            created_at: Instant::now(),
            ttl,
            access_count: AtomicU64::new(0),
        };

        self.cache.insert(key, entry);
    }

    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    fn evict_oldest(&mut self) {
        if let Some((key, _)) = self
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(k, v)| (k.clone(), v.created_at))
        {
            self.cache.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_efficient_concat() {
        assert_eq!(efficient_concat("", "test"), "test");
        assert_eq!(efficient_concat("test", ""), "test");
        assert_eq!(efficient_concat("hello", "world"), "helloworld");
    }

    #[test]
    fn test_performance_cache() {
        let mut cache = PerformanceCache::new(2);

        cache.insert("key1", "value1", Duration::from_secs(60));
        assert_eq!(cache.get(&"key1"), Some("value1"));
        assert!(cache.hit_rate() > 0.0);
    }
}
