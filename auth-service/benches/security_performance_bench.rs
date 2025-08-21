use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

// Import the actual auth service modules for realistic benchmarks
use auth_service::{
    async_optimized::{AsyncConfig, AsyncError, AsyncSecurityExecutor},
    cache::{Cache, CacheConfig},
    connection_pool_optimized::{ConnectionPoolConfig, OptimizedConnectionPool},
    crypto_optimized::{get_crypto_engine, CryptoOptimized},
    rate_limit_optimized::{RateLimitConfig, ShardedRateLimiter},
};

/// Comprehensive security performance benchmarks
/// These benchmarks test real-world security scenarios with varying loads

fn bench_crypto_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("crypto_operations");
    group.measurement_time(Duration::from_secs(10));

    // Test different payload sizes for encryption
    for payload_size in [64, 256, 1024, 4096, 16384].iter() {
        let payload = vec![0u8; *payload_size];

        group.throughput(Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt_aes_gcm", payload_size),
            payload_size,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let crypto = get_crypto_engine();
                    let result = crypto.encrypt_secure("benchmark_key", &payload).await;
                    black_box(result)
                });
            },
        );
    }

    // Test password hashing performance
    group.bench_function("password_hash_argon2", |b| {
        b.to_async(&rt).iter(|| async {
            let crypto = get_crypto_engine();
            let password = "secure_password_123!@#";
            let result = crypto.hash_password_secure(password).await;
            black_box(result)
        });
    });

    // Test password verification performance
    let password_hash = rt.block_on(async {
        let crypto = get_crypto_engine();
        crypto.hash_password_secure("test_password").await.unwrap()
    });

    group.bench_function("password_verify_argon2", |b| {
        let hash = password_hash.clone();
        b.to_async(&rt).iter(|| async {
            let crypto = get_crypto_engine();
            let result = crypto.verify_password_secure("test_password", &hash).await;
            black_box(result)
        });
    });

    // Test HMAC generation
    group.bench_function("hmac_sha256", |b| {
        b.iter(|| {
            let crypto = get_crypto_engine();
            let data = b"test data for hmac generation";
            let result = crypto.generate_hmac_secure("hmac_key", data);
            black_box(result)
        });
    });

    // Test secure token generation
    group.bench_function("secure_token_generation", |b| {
        b.iter(|| {
            let crypto = get_crypto_engine();
            let result = crypto.generate_secure_token("tk");
            black_box(result)
        });
    });

    // Test SIMD token validation if available
    #[cfg(feature = "simd")]
    {
        let tokens: Vec<String> = (0..1000).map(|i| format!("tk_valid_token_{}", i)).collect();

        group.bench_function("simd_token_validation", |b| {
            b.iter(|| {
                let crypto = get_crypto_engine();
                let result = crypto.batch_validate_tokens(&tokens);
                black_box(result)
            });
        });
    }

    group.finish();
}

fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");

    // Test different concurrency levels
    for concurrent_clients in [1, 10, 50, 100, 500].iter() {
        let rate_limiter = ShardedRateLimiter::new(RateLimitConfig {
            requests_per_window: 1000,
            window_duration_secs: 60,
            burst_allowance: 50,
            cleanup_interval_secs: 300,
        });

        group.throughput(Throughput::Elements(*concurrent_clients as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_rate_checks", concurrent_clients),
            concurrent_clients,
            |b, &concurrent_clients| {
                b.iter(|| {
                    let handles: Vec<_> = (0..concurrent_clients)
                        .map(|i| {
                            let client_key = format!("client_{}", i);
                            let limiter = &rate_limiter;
                            std::thread::spawn(move || limiter.check_rate_limit(&client_key))
                        })
                        .collect();

                    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

                    black_box(results)
                });
            },
        );
    }

    // Test cleanup performance
    group.bench_function("cleanup_stale_entries", |b| {
        let rate_limiter = ShardedRateLimiter::new(RateLimitConfig::default());

        // Pre-populate with entries
        for i in 0..10000 {
            rate_limiter.check_rate_limit(&format!("client_{}", i));
        }

        b.iter(|| {
            let removed = rate_limiter.cleanup_stale_entries();
            black_box(removed)
        });
    });

    group.finish();
}

fn bench_caching_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("caching");

    // Setup cache
    let cache = rt.block_on(async {
        let config = CacheConfig {
            use_redis: false, // Use memory cache for consistent benchmarks
            default_ttl: 300,
            max_memory_cache_size: 10000,
            ..Default::default()
        };
        Cache::new(config).await.unwrap()
    });

    // Pre-populate cache
    rt.block_on(async {
        for i in 0..1000 {
            let key = format!("key_{}", i);
            let value = json!({"user_id": i, "scope": "read write", "client_id": "test_client"});
            cache.set(&key, &value, None).await.unwrap();
        }
    });

    // Test cache read performance
    group.bench_function("cache_read_hit", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("key_{}", rand::random::<usize>() % 1000);
            let result: Option<serde_json::Value> = cache.get(&key).await;
            black_box(result)
        });
    });

    group.bench_function("cache_read_miss", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("missing_key_{}", rand::random::<usize>());
            let result: Option<serde_json::Value> = cache.get(&key).await;
            black_box(result)
        });
    });

    // Test cache write performance
    group.bench_function("cache_write", |b| {
        b.to_async(&rt).iter(|| async {
            let key = format!("new_key_{}", rand::random::<usize>());
            let value = json!({"test": "data", "timestamp": chrono::Utc::now().timestamp()});
            let result = cache.set(&key, &value, None).await;
            black_box(result)
        });
    });

    // Test concurrent cache operations
    for concurrent_ops in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*concurrent_ops as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_cache_ops", concurrent_ops),
            concurrent_ops,
            |b, &concurrent_ops| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for i in 0..concurrent_ops {
                        let cache = &cache;
                        let handle = tokio::spawn(async move {
                            let key = format!("concurrent_key_{}", i);
                            let value = json!({"operation": i, "timestamp": chrono::Utc::now().timestamp()});
                            cache.set(&key, &value, None).await.unwrap();

                            let retrieved: Option<serde_json::Value> = cache.get(&key).await;
                            retrieved
                        });
                        handles.push(handle);
                    }

                    let results: Vec<_> = futures::future::join_all(handles).await;
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

fn bench_async_security_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("async_security");

    let config = AsyncConfig {
        max_concurrent_operations: 1000,
        default_timeout: Duration::from_secs(10),
        max_retry_attempts: 3,
        enable_batching: true,
        batch_size: 50,
        ..Default::default()
    };

    let executor = AsyncSecurityExecutor::new(config);

    // Test single async operation
    group.bench_function("single_security_operation", |b| {
        b.to_async(&rt).iter(|| async {
            let result = executor
                .execute_operation(async {
                    // Simulate security validation
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    Ok::<String, AsyncError>("validation_success".to_string())
                })
                .await;
            black_box(result)
        });
    });

    // Test batch operations
    for batch_size in [10, 50, 100, 500].iter() {
        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_security_operations", batch_size),
            batch_size,
            |b, &batch_size| {
                b.to_async(&rt).iter(|| async {
                    let operations = (0..batch_size)
                        .map(|i| async move {
                            // Simulate different security operations
                            let delay = Duration::from_millis(1 + (i % 5) as u64);
                            tokio::time::sleep(delay).await;
                            Ok::<String, AsyncError>(format!("operation_{}", i))
                        })
                        .collect();

                    let results = executor.execute_batch(operations).await;
                    black_box(results)
                });
            },
        );
    }

    // Test with failure scenarios
    group.bench_function("async_operations_with_failures", |b| {
        b.to_async(&rt).iter(|| async {
            let operations = (0..50)
                .map(|i| async move {
                    if i % 10 == 0 {
                        // Simulate failures for 10% of operations
                        Err(AsyncError::OperationFailed {
                            message: "Simulated failure".to_string(),
                        })
                    } else {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        Ok::<String, AsyncError>(format!("success_{}", i))
                    }
                })
                .collect();

            let results = executor.execute_batch(operations).await;
            black_box(results)
        });
    });

    group.finish();
}

fn bench_token_operations_e2e(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("token_operations_e2e");

    // End-to-end token operation benchmarks that combine multiple components

    // Setup
    let rate_limiter = Arc::new(ShardedRateLimiter::new(RateLimitConfig::default()));
    let cache = rt.block_on(async {
        let config = CacheConfig {
            use_redis: false,
            ..Default::default()
        };
        Arc::new(Cache::new(config).await.unwrap())
    });

    // Token generation + validation + caching pipeline
    group.bench_function("token_generation_pipeline", |b| {
        b.to_async(&rt).iter(|| async {
            let client_id = "bench_client";

            // 1. Check rate limit
            let rate_result = rate_limiter.check_rate_limit(client_id);
            if let auth_service::rate_limit_optimized::RateLimitResult::RateLimited { .. } =
                rate_result
            {
                return black_box(Err("Rate limited"));
            }

            // 2. Generate secure token
            let crypto = get_crypto_engine();
            let token = crypto.generate_secure_token("tk").unwrap();

            // 3. Create token metadata
            let metadata = json!({
                "client_id": client_id,
                "scope": "read write",
                "iat": chrono::Utc::now().timestamp(),
                "exp": chrono::Utc::now().timestamp() + 3600
            });

            // 4. Cache token
            let cache_key = format!("token:{}", token);
            cache
                .set(&cache_key, &metadata, Some(Duration::from_secs(3600)))
                .await
                .unwrap();

            black_box(Ok(token))
        });
    });

    // Token introspection pipeline
    group.bench_function("token_introspection_pipeline", |b| {
        // Pre-generate some tokens
        let tokens: Vec<String> = rt.block_on(async {
            let mut tokens = Vec::new();
            for i in 0..100 {
                let crypto = get_crypto_engine();
                let token = crypto.generate_secure_token("tk").unwrap();

                let metadata = json!({
                    "client_id": format!("client_{}", i),
                    "scope": "read write",
                    "active": true,
                    "exp": chrono::Utc::now().timestamp() + 3600
                });

                let cache_key = format!("token:{}", token);
                cache
                    .set(&cache_key, &metadata, Some(Duration::from_secs(3600)))
                    .await
                    .unwrap();
                tokens.push(token);
            }
            tokens
        });

        b.to_async(&rt).iter(|| async {
            let token = &tokens[rand::random::<usize>() % tokens.len()];

            // 1. Check rate limit
            let rate_result = rate_limiter.check_rate_limit("introspect_client");
            if let auth_service::rate_limit_optimized::RateLimitResult::RateLimited { .. } =
                rate_result
            {
                return black_box(Err("Rate limited"));
            }

            // 2. Lookup token in cache
            let cache_key = format!("token:{}", token);
            let metadata: Option<serde_json::Value> = cache.get(&cache_key).await;

            // 3. Validate token format
            let crypto = get_crypto_engine();
            let is_valid_format = token.starts_with("tk_") && token.len() > 10;

            let result = match (metadata, is_valid_format) {
                (Some(meta), true) => Ok(meta),
                _ => Err("Invalid token"),
            };

            black_box(result)
        });
    });

    // Concurrent token operations
    for concurrent_ops in [10, 50, 100].iter() {
        group.throughput(Throughput::Elements(*concurrent_ops as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_token_ops", concurrent_ops),
            concurrent_ops,
            |b, &concurrent_ops| {
                b.to_async(&rt).iter(|| async {
                    let mut handles = Vec::new();

                    for i in 0..concurrent_ops {
                        let rate_limiter = rate_limiter.clone();
                        let cache = cache.clone();

                        let handle = tokio::spawn(async move {
                            // Mix of operations: 70% introspection, 30% generation
                            if i % 10 < 7 {
                                // Token introspection
                                let client_id = format!("client_{}", i);
                                rate_limiter.check_rate_limit(&client_id);

                                let cache_key = format!("token:sample_{}", i);
                                let result: Option<serde_json::Value> = cache.get(&cache_key).await;
                                black_box(result)
                            } else {
                                // Token generation
                                let client_id = format!("gen_client_{}", i);
                                rate_limiter.check_rate_limit(&client_id);

                                let crypto = get_crypto_engine();
                                let token = crypto.generate_secure_token("tk").unwrap();

                                let metadata = json!({
                                    "client_id": client_id,
                                    "scope": "read",
                                    "iat": chrono::Utc::now().timestamp()
                                });

                                let cache_key = format!("token:{}", token);
                                cache.set(&cache_key, &metadata, None).await.unwrap();
                                black_box(token)
                            }
                        });
                        handles.push(handle);
                    }

                    let results: Vec<_> = futures::future::join_all(handles).await;
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Test memory efficiency of different data structures
    group.bench_function("dashmap_vs_hashmap", |b| {
        b.iter(|| {
            let dashmap = dashmap::DashMap::new();
            let mut hashmap = std::collections::HashMap::new();

            // Insert 10000 entries
            for i in 0..10000 {
                dashmap.insert(format!("key_{}", i), format!("value_{}", i));
                hashmap.insert(format!("key_{}", i), format!("value_{}", i));
            }

            // Read operations
            for i in 0..1000 {
                let key = format!("key_{}", i);
                let _dashmap_result = dashmap.get(&key);
                let _hashmap_result = hashmap.get(&key);
            }

            black_box((dashmap.len(), hashmap.len()))
        });
    });

    // Test Arc vs Rc performance
    group.bench_function("arc_vs_rc_cloning", |b| {
        let arc_data = Arc::new(vec![0u8; 1024]);
        let rc_data = std::rc::Rc::new(vec![0u8; 1024]);

        b.iter(|| {
            let mut arc_clones = Vec::new();
            let mut rc_clones = Vec::new();

            for _ in 0..1000 {
                arc_clones.push(arc_data.clone());
                rc_clones.push(rc_data.clone());
            }

            black_box((arc_clones.len(), rc_clones.len()))
        });
    });

    group.finish();
}

// Configure criterion with security-appropriate settings
criterion_group!(
    name = security_benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(15))
        .sample_size(200)
        .warm_up_time(Duration::from_secs(5))
        .with_plots();
    targets =
        bench_crypto_operations,
        bench_rate_limiting,
        bench_caching_operations,
        bench_async_security_operations,
        bench_token_operations_e2e,
        bench_memory_usage
);

criterion_main!(security_benches);
