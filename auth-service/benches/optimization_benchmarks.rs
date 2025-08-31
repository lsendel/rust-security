//! Performance benchmarks for optimization validation
//!
//! Measures the performance impact of the implemented optimizations
//! to validate that our changes provide measurable improvements.

use auth_service::security::{generate_token_binding, validate_token_binding};
use auth_service::storage::cache::{LruTokenCache, TokenCacheConfig};
use common::TokenRecord;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Benchmark token validation performance
fn bench_token_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_validation");

    let rt = Runtime::new().unwrap();

    group.bench_function("generate_token_binding", |b| {
        b.iter(|| {
            let binding = generate_token_binding(
                black_box("192.168.1.1"),
                black_box("Mozilla/5.0 (Test Browser)"),
            );
            black_box(binding)
        });
    });

    // Benchmark validation with the optimized window approach
    let client_ip = "192.168.1.1";
    let user_agent = "Mozilla/5.0 (Test Browser)";
    let binding = generate_token_binding(client_ip, user_agent);

    group.bench_function("validate_token_binding_optimized", |b| {
        b.iter(|| {
            let result = validate_token_binding(
                black_box(client_ip),
                black_box(user_agent),
                black_box(&binding),
            );
            black_box(result)
        });
    });

    group.finish();
}

/// Benchmark LRU cache performance vs HashMap
fn bench_cache_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_performance");

    let rt = Runtime::new().unwrap();

    // Create test data
    let token = TokenRecord {
        active: true,
        scope: Some("read write admin".to_string()),
        client_id: Some("test_client".to_string()),
        exp: Some(1234567890),
        iat: Some(1234567800),
        sub: Some("test_user".to_string()),
        token_binding: None,
        mfa_verified: false,
    };

    // Benchmark LRU cache operations
    let cache_config = TokenCacheConfig {
        max_tokens: 10_000,
        max_age: Duration::from_secs(3600),
        cleanup_interval: Duration::from_secs(300),
    };
    let lru_cache = Arc::new(LruTokenCache::with_config(cache_config));

    // Pre-populate cache
    rt.block_on(async {
        for i in 0..1000 {
            lru_cache
                .insert(format!("token_{}", i), token.clone())
                .await;
        }
    });

    group.bench_function("lru_cache_get", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = lru_cache.get(black_box("token_500")).await;
                black_box(result)
            })
        });
    });

    group.bench_function("lru_cache_insert", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            rt.block_on(async {
                lru_cache
                    .insert(
                        black_box(format!("new_token_{}", counter)),
                        black_box(token.clone()),
                    )
                    .await;
            })
        });
    });

    // Benchmark traditional HashMap (for comparison)
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    let hashmap_cache = Arc::new(RwLock::new(HashMap::<String, TokenRecord>::new()));

    // Pre-populate HashMap
    rt.block_on(async {
        let mut cache = hashmap_cache.write().await;
        for i in 0..1000 {
            cache.insert(format!("token_{}", i), token.clone());
        }
    });

    group.bench_function("hashmap_get", |b| {
        b.iter(|| {
            rt.block_on(async {
                let cache = hashmap_cache.read().await;
                let result = cache.get(black_box("token_500")).cloned();
                black_box(result)
            })
        });
    });

    group.bench_function("hashmap_insert", |b| {
        let mut counter = 0;
        b.iter(|| {
            counter += 1;
            rt.block_on(async {
                let mut cache = hashmap_cache.write().await;
                cache.insert(
                    black_box(format!("new_token_{}", counter)),
                    black_box(token.clone()),
                );
            })
        });
    });

    group.finish();
}

/// Benchmark Arc cloning optimization
fn bench_arc_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("arc_optimization");

    use std::sync::Arc;

    let data = Arc::new("expensive_to_clone_data".repeat(1000));

    // Benchmark inefficient cloning
    group.bench_function("arc_inefficient_clone", |b| {
        b.iter(|| {
            let cloned = data.clone();
            black_box(cloned)
        });
    });

    // Benchmark efficient Arc cloning
    group.bench_function("arc_efficient_clone", |b| {
        b.iter(|| {
            let cloned = Arc::clone(&data);
            black_box(cloned)
        });
    });

    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Test String vs Box<str> for immutable data
    let test_data = "immutable_string_data".to_string();

    group.bench_function("string_clone", |b| {
        b.iter(|| {
            let cloned = test_data.clone();
            black_box(cloned)
        });
    });

    let boxed_data: Box<str> = test_data.clone().into_boxed_str();

    group.bench_function("boxed_str_clone", |b| {
        b.iter(|| {
            let cloned = boxed_data.clone();
            black_box(cloned)
        });
    });

    group.finish();
}

/// Integration benchmark measuring overall performance
fn bench_integration_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("integration");

    let rt = Runtime::new().unwrap();
    let cache = Arc::new(LruTokenCache::new());

    let token = TokenRecord {
        active: true,
        scope: Some("read write".to_string()),
        client_id: Some("integration_client".to_string()),
        exp: Some(1234567890),
        iat: Some(1234567800),
        sub: Some("integration_user".to_string()),
        token_binding: None,
        mfa_verified: false,
    };

    group.bench_function("auth_flow_simulation", |b| {
        let mut request_counter = 0;
        b.iter(|| {
            request_counter += 1;
            rt.block_on(async {
                // Simulate typical auth flow
                let client_ip = "192.168.1.100";
                let user_agent = "Test Client/1.0";

                // 1. Generate token binding
                let binding = generate_token_binding(client_ip, user_agent);
                let binding = generate_token_binding(client_ip, user_agent);

                // 2. Store token in cache
                let token_key = format!("req_{}", request_counter);
                cache.insert(token_key.clone(), token.clone()).await;

                // 3. Validate token binding
                let validation = validate_token_binding(client_ip, user_agent, &binding).unwrap();

                // 4. Retrieve token from cache
                let cached_token = cache.get(&token_key).await;

                black_box((binding, validation, cached_token))
            })
        });
    });

    group.finish();
}

criterion_group!(
    optimization_benchmarks,
    bench_token_validation,
    bench_cache_performance,
    bench_arc_optimization,
    bench_memory_usage,
    bench_integration_performance
);

criterion_main!(optimization_benchmarks);
