//! Caching Layer Module
//!
//! This module provides high-performance caching implementations for the auth service,
//! including token caching, policy caching, and intelligent caching strategies.
//!
//! ## Features
//!
//! - **Token Caching**: LRU-based token cache with automatic cleanup
//! - **Policy Caching**: Policy decision caching with TTL support
//! - **Intelligent Caching**: Smart cache with Redis and in-memory fallbacks
//! - **Performance**: Optimized for high-throughput scenarios

pub mod basic_cache;
pub mod token_cache;
pub mod policy_cache;
pub mod intelligent_cache;

// Re-export main cache types
pub use token_cache::{LruTokenCache, TokenCacheConfig};
pub use policy_cache::{PolicyCache, PolicyCacheConfig};
pub use intelligent_cache::{IntelligentCache, CacheConfig as IntelligentCacheConfig, CacheError as IntelligentCacheError};

// Common cache traits
use async_trait::async_trait;
use std::fmt::Debug;

/// Common cache operations trait
#[async_trait]
pub trait Cache<K, V>: Send + Sync + Debug
where
    K: Send + Sync + Clone + std::hash::Hash + Eq + std::fmt::Display,
    V: Send + Sync + Clone,
{
    /// Get a value from the cache
    async fn get(&self, key: &K) -> Option<V>;

    /// Insert a value into the cache
    async fn insert(&self, key: K, value: V) -> Result<(), CacheError>;

    /// Remove a value from the cache
    async fn remove(&self, key: &K) -> Option<V>;

    /// Check if a key exists in the cache
    async fn contains(&self, key: &K) -> bool;

    /// Clear all entries from the cache
    async fn clear(&self) -> Result<(), CacheError>;

    /// Get cache statistics
    async fn stats(&self) -> CacheStats;
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total number of entries
    pub entries: usize,
    /// Cache hit count
    pub hits: u64,
    /// Cache miss count
    pub misses: u64,
    /// Hit rate as percentage
    pub hit_rate: f64,
}

/// Common cache error type
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("Redis connection error: {0}")]
    RedisError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Cache operation timeout")]
    Timeout,
    #[error("Cache is full")]
    CacheFull,
}
