//! Cache Integration Tests
//!
//! Comprehensive testing for cache functionality including Redis integration,
//! fallback mechanisms, and performance under load.

use auth_service::cache::{CacheConfig, RedisCache};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Test cache operations with Redis backend
#[tokio::test]
async fn test_redis_cache_operations() {
    let config = CacheConfig {
        redis_url: Some("redis://localhost:6379".to_string()),
        ttl_seconds: 300,
        max_connections: 10,
        key_prefix: "test:".to_string(),
    };

    let cache = RedisCache::new(config).await.unwrap();

    // Test basic set/get operations
    cache.set("test_key", "test_value", None).await.unwrap();
    let value: String = cache.get("test_key").await.unwrap().unwrap();
    assert_eq!(value, "test_value");

    // Test TTL functionality
    cache.set("ttl_key", "ttl_value", Some(2)).await.unwrap();
    sleep(Duration::from_secs(3)).await;
    let expired_value: Option<String> = cache.get("ttl_key").await.unwrap();
    assert!(expired_value.is_none());
}

/// Test cache performance under concurrent load
#[tokio::test]
async fn test_cache_concurrent_performance() {
    let config = CacheConfig {
        redis_url: Some("redis://localhost:6379".to_string()),
        ttl_seconds: 300,
        max_connections: 20,
        key_prefix: "perf:".to_string(),
    };

    let cache = RedisCache::new(config).await.unwrap();
    let start_time = Instant::now();

    // Spawn multiple concurrent operations
    let mut handles = vec![];
    for i in 0..100 {
        let cache_clone = cache.clone();
        let handle = tokio::spawn(async move {
            let key = format!("concurrent_key_{}", i);
            let value = format!("concurrent_value_{}", i);

            // Perform multiple operations per task
            cache_clone.set(&key, &value, None).await.unwrap();
            let retrieved: String = cache_clone.get(&key).await.unwrap().unwrap();
            assert_eq!(retrieved, value);
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    let duration = start_time.elapsed();
    println!("Concurrent cache operations completed in: {:?}", duration);

    // Performance assertion - should complete within reasonable time
    assert!(duration < Duration::from_secs(10));
}

/// Test cache fallback mechanisms when Redis is unavailable
#[tokio::test]
async fn test_cache_fallback_mechanisms() {
    // Test with invalid Redis URL to force fallback
    let config = CacheConfig {
        redis_url: Some("redis://invalid:6379".to_string()),
        ttl_seconds: 300,
        max_connections: 5,
        key_prefix: "fallback:".to_string(),
    };

    let cache = RedisCache::new(config).await.unwrap();

    // Operations should still work via fallback mechanism
    cache.set("fallback_key", "fallback_value", None).await.unwrap();
    let value: String = cache.get("fallback_key").await.unwrap().unwrap();
    assert_eq!(value, "fallback_value");
}

/// Test cache statistics and monitoring
#[tokio::test]
async fn test_cache_monitoring_and_stats() {
    let config = CacheConfig {
        redis_url: Some("redis://localhost:6379".to_string()),
        ttl_seconds: 300,
        max_connections: 10,
        key_prefix: "stats:".to_string(),
    };

    let cache = RedisCache::new(config).await.unwrap();

    // Perform various operations to generate statistics
    for i in 0..50 {
        cache.set(&format!("stats_key_{}", i), &format!("value_{}", i), None).await.unwrap();
    }

    // Verify all values can be retrieved
    for i in 0..50 {
        let value: String = cache.get(&format!("stats_key_{}", i)).await.unwrap().unwrap();
        assert_eq!(value, format!("value_{}", i));
    }
}

/// Test cache cleanup and memory management
#[tokio::test]
async fn test_cache_cleanup_and_memory_management() {
    let config = CacheConfig {
        redis_url: Some("redis://localhost:6379".to_string()),
        ttl_seconds: 60, // Short TTL for testing
        max_connections: 10,
        key_prefix: "cleanup:".to_string(),
    };

    let cache = RedisCache::new(config).await.unwrap();

    // Create many entries
    for i in 0..200 {
        cache.set(&format!("cleanup_key_{}", i), &format!("cleanup_value_{}", i), Some(30)).await.unwrap();
    }

    // Verify entries exist
    let count_before = (0..200).filter(|i| {
        cache.get(&format!("cleanup_key_{}", i)).await.unwrap().is_some()
    }).count();

    assert_eq!(count_before, 200);

    // Wait for TTL to expire
    sleep(Duration::from_secs(35)).await;

    // Check that entries have been cleaned up
    let count_after = (0..200).filter(|i| {
        cache.get(&format!("cleanup_key_{}", i)).await.unwrap().is_some()
    }).count();

    // Should be significantly fewer entries after cleanup
    assert!(count_after < 50);
}
