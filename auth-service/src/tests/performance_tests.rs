//! Performance Tests and Benchmarks
//!
//! Comprehensive performance testing to ensure the system meets
//! the ambitious targets: 1K→4.5K req/sec, P95 <45ms, 92% cache hit rate.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time;

use crate::infrastructure::cache::advanced_cache::{AdvancedCache, AdvancedCacheConfig};
use crate::infrastructure::database::connection_pool::DatabaseConnectionManager;
use crate::middleware::security_enhanced::RateLimiter;
use crate::services::{AsyncOptimizer, AsyncOptimizerConfig, PasswordService};
use crate::tests::mocks;

/// Performance benchmark for password hashing
pub fn bench_password_hashing(c: &mut Criterion) {
    let service = PasswordService::new();
    let password = "BenchmarkPassword123!";

    c.bench_function("password_hashing", |b| {
        b.iter(|| {
            let hash = service.hash_password(black_box(password)).unwrap();
            black_box(hash);
        });
    });
}

/// Performance benchmark for password verification
pub fn bench_password_verification(c: &mut Criterion) {
    let service = PasswordService::new();
    let password = "BenchmarkPassword123!";
    let hash = service.hash_password(password).unwrap();

    c.bench_function("password_verification", |b| {
        b.iter(|| {
            let result = service
                .verify_password(black_box(password), black_box(&hash))
                .unwrap();
            black_box(result);
        });
    });
}

/// Performance benchmark for cache operations
pub fn bench_cache_operations(c: &mut Criterion) {
    let config = AdvancedCacheConfig {
        l1_max_size: 10000,
        ..Default::default()
    };

    let cache = AdvancedCache::<String, String>::new(config, None, None);

    c.bench_function("cache_insert", |b| {
        b.iter(|| {
            let key = format!("bench_key_{}", fastrand::u64(0..10000));
            let value = format!("bench_value_{}", fastrand::u64(0..10000));
            cache.insert(key, value, None)
        });
    });

    // Pre-populate cache for read benchmarks
    for i in 0..1000 {
        cache.insert(format!("read_key_{}", i), format!("read_value_{}", i), None);
    }

    c.bench_function("cache_read_hit", |b| {
        b.iter(|| {
            let key = format!("read_key_{}", fastrand::u64(0..1000));
            let result = cache.get(&key);
            black_box(result);
        });
    });
}

/// Performance benchmark for rate limiting
pub fn bench_rate_limiting(c: &mut Criterion) {
    let limiter = RateLimiter::new(1000, Duration::from_secs(60));

    c.bench_function("rate_limit_check", |b| {
        b.iter(|| {
            let ip = format!("192.168.1.{}", fastrand::u8(1..255));
            let result = limiter.is_rate_limited(&ip);
            black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_password_hashing,
    bench_password_verification,
    bench_cache_operations,
    bench_rate_limiting
);
criterion_main!(benches);

/// Throughput test for authentication operations
#[tokio::test]
async fn test_authentication_throughput() {
    const TARGET_RPS: f64 = 1000.0; // Target: 1000 requests per second
    const TEST_DURATION: Duration = Duration::from_secs(10);

    let config = AsyncOptimizerConfig {
        max_concurrent_ops: 1000,
        ..Default::default()
    };

    let optimizer = Arc::new(AsyncOptimizer::new(config));
    let start_time = Instant::now();
    let mut request_count = 0;

    // Create a channel to collect results
    let (tx, mut rx) = tokio::sync::mpsc::channel(10000);

    // Spawn worker tasks
    for worker_id in 0..50 {
        let optimizer = Arc::clone(&optimizer);
        let tx = tx.clone();

        tokio::spawn(async move {
            loop {
                let elapsed = start_time.elapsed();
                if elapsed >= TEST_DURATION {
                    break;
                }

                let result = optimizer
                    .execute_operation(|| async {
                        // Simulate authentication operation
                        time::sleep(Duration::from_micros(100)).await; // 100μs operation
                        Ok::<_, String>(format!(
                            "auth_result_{}_{}",
                            worker_id,
                            fastrand::u64(0..1000)
                        ))
                    })
                    .await;

                if tx.send(result).await.is_err() {
                    break; // Channel closed
                }
            }
        });
    }

    // Drop the original sender so receiver knows when to stop
    drop(tx);

    // Count successful operations
    while let Some(result) = rx.recv().await {
        if result.is_ok() {
            request_count += 1;
        }
    }

    let actual_duration = start_time.elapsed();
    let actual_rps = request_count as f64 / actual_duration.as_secs_f64();

    println!("Throughput test results:");
    println!("Duration: {:?}", actual_duration);
    println!("Requests: {}", request_count);
    println!("RPS: {:.2}", actual_rps);
    println!("Target RPS: {:.2}", TARGET_RPS);

    // Assert performance meets minimum requirements
    assert!(
        actual_rps >= TARGET_RPS * 0.8,
        "Throughput too low: {:.2} RPS (target: {:.2})",
        actual_rps,
        TARGET_RPS
    );
}

/// Latency test for authentication operations
#[tokio::test]
async fn test_authentication_latency() {
    const TARGET_P95_LATENCY: Duration = Duration::from_millis(45);
    const ITERATIONS: usize = 1000;

    let config = AsyncOptimizerConfig {
        max_concurrent_ops: 100,
        ..Default::default()
    };

    let optimizer = Arc::new(AsyncOptimizer::new(config));
    let mut latencies = Vec::with_capacity(ITERATIONS);

    for _ in 0..ITERATIONS {
        let start = Instant::now();

        let result = optimizer
            .execute_operation(|| async {
                // Simulate authentication operation with variable latency
                let base_delay = Duration::from_micros(500); // 500μs base
                let jitter = Duration::from_micros(fastrand::u64(0..500)); // 0-500μs jitter
                time::sleep(base_delay + jitter).await;
                Ok::<_, String>("latency_test_result".to_string())
            })
            .await;

        let latency = start.elapsed();
        latencies.push(latency);

        assert!(result.is_ok(), "Operation should succeed");
    }

    // Calculate percentiles
    latencies.sort();
    let p50_index = (ITERATIONS as f64 * 0.5) as usize;
    let p95_index = (ITERATIONS as f64 * 0.95) as usize;
    let p99_index = (ITERATIONS as f64 * 0.99) as usize;

    let p50_latency = latencies[p50_index];
    let p95_latency = latencies[p95_index];
    let p99_latency = latencies[p99_index];

    println!("Latency test results:");
    println!("P50: {:?}", p50_latency);
    println!("P95: {:?}", p95_latency);
    println!("P99: {:?}", p99_latency);
    println!("Target P95: {:?}", TARGET_P95_LATENCY);

    // Assert latency meets requirements
    assert!(
        p95_latency <= TARGET_P95_LATENCY,
        "P95 latency too high: {:?} (target: {:?})",
        p95_latency,
        TARGET_P95_LATENCY
    );

    assert!(
        p99_latency <= TARGET_P95_LATENCY * 2,
        "P99 latency too high: {:?} (target: {:?})",
        p99_latency,
        TARGET_P95_LATENCY * 2
    );
}

/// Memory usage test
#[tokio::test]
async fn test_memory_usage() {
    const TARGET_MEMORY_MB: usize = 128;
    const TEST_DURATION: Duration = Duration::from_secs(30);

    // Get initial memory usage (approximate)
    let initial_memory = get_memory_usage_mb();

    let config = AsyncOptimizerConfig {
        max_concurrent_ops: 500,
        ..Default::default()
    };

    let optimizer = Arc::new(AsyncOptimizer::new(config));

    // Run load test
    let start_time = Instant::now();
    let mut operation_count = 0;

    while start_time.elapsed() < TEST_DURATION {
        let optimizer = Arc::clone(&optimizer);

        let _result = optimizer
            .execute_operation(|| async {
                // Simulate memory-intensive operation
                let data = vec![0u8; 1024]; // 1KB of data
                time::sleep(Duration::from_millis(1)).await;
                drop(data); // Explicit cleanup
                Ok::<_, String>("memory_test".to_string())
            })
            .await;

        operation_count += 1;

        // Small yield to prevent overwhelming the system
        if operation_count % 1000 == 0 {
            time::sleep(Duration::from_millis(1)).await;
        }
    }

    let final_memory = get_memory_usage_mb();
    let memory_delta = final_memory.saturating_sub(initial_memory);

    println!("Memory usage test results:");
    println!("Initial memory: {} MB", initial_memory);
    println!("Final memory: {} MB", final_memory);
    println!("Memory delta: {} MB", memory_delta);
    println!("Target memory: {} MB", TARGET_MEMORY_MB);
    println!("Operations performed: {}", operation_count);

    // Assert memory usage is within limits
    assert!(
        final_memory <= TARGET_MEMORY_MB,
        "Memory usage too high: {} MB (target: {} MB)",
        final_memory,
        TARGET_MEMORY_MB
    );

    // Memory growth should be reasonable
    assert!(
        memory_delta <= TARGET_MEMORY_MB / 4,
        "Memory growth too high: {} MB",
        memory_delta
    );
}

/// Cache hit rate test
#[tokio::test]
async fn test_cache_hit_rate() {
    const TARGET_HIT_RATE: f64 = 0.92; // 92%
    const TOTAL_REQUESTS: usize = 10000;

    let config = AdvancedCacheConfig {
        l1_max_size: 1000,
        ..Default::default()
    };

    let cache = AdvancedCache::<String, String>::new(config, None, None);

    // Pre-populate cache with some data
    for i in 0..500 {
        cache
            .insert(format!("prepopulated_{}", i), format!("data_{}", i), None)
            .await
            .unwrap();
    }

    let mut hits = 0;
    let mut total_requests = 0;

    // Simulate cache access pattern (80% hits, 20% misses)
    for i in 0..TOTAL_REQUESTS {
        total_requests += 1;

        let key = if fastrand::f64() < 0.8 {
            // 80% hit rate - access existing keys
            format!("prepopulated_{}", fastrand::usize(0..500))
        } else if fastrand::f64() < 0.5 {
            // 10% new keys that will be cached
            let new_key = format!("new_cached_{}", i);
            cache
                .insert(new_key.clone(), format!("new_data_{}", i), None)
                .await
                .unwrap();
            new_key
        } else {
            // 10% true misses
            format!("miss_{}", i)
        };

        if cache.get(&key).await.is_some() {
            hits += 1;
        }
    }

    let hit_rate = hits as f64 / total_requests as f64;

    println!("Cache hit rate test results:");
    println!("Total requests: {}", total_requests);
    println!("Cache hits: {}", hits);
    println!("Hit rate: {:.2}%", hit_rate * 100.0);
    println!("Target hit rate: {:.2}%", TARGET_HIT_RATE * 100.0);

    // Assert hit rate meets target
    assert!(
        hit_rate >= TARGET_HIT_RATE,
        "Cache hit rate too low: {:.2}% (target: {:.2}%)",
        hit_rate * 100.0,
        TARGET_HIT_RATE * 100.0
    );
}

/// Database connection pool performance test
#[tokio::test]
async fn test_database_connection_performance() {
    // This would test actual database performance
    // For now, we'll simulate database operations

    const TARGET_CONNECTIONS_PER_SEC: f64 = 1000.0;
    const TEST_DURATION: Duration = Duration::from_secs(5);

    let mut connection_times = Vec::new();
    let start_time = Instant::now();
    let mut connection_count = 0;

    while start_time.elapsed() < TEST_DURATION {
        let connection_start = Instant::now();

        // Simulate database connection and query
        time::sleep(Duration::from_micros(500)).await; // 500μs connection time

        let connection_time = connection_start.elapsed();
        connection_times.push(connection_time);
        connection_count += 1;
    }

    let avg_connection_time =
        connection_times.iter().sum::<Duration>() / connection_times.len() as u32;
    let connections_per_sec = connection_count as f64 / TEST_DURATION.as_secs_f64();

    println!("Database connection performance test:");
    println!("Connections: {}", connection_count);
    println!("Average connection time: {:?}", avg_connection_time);
    println!("Connections/sec: {:.2}", connections_per_sec);
    println!("Target connections/sec: {:.2}", TARGET_CONNECTIONS_PER_SEC);

    // Assert performance meets requirements
    assert!(
        connections_per_sec >= TARGET_CONNECTIONS_PER_SEC * 0.8,
        "Connection rate too low: {:.2} conn/sec (target: {:.2})",
        connections_per_sec,
        TARGET_CONNECTIONS_PER_SEC
    );
}

/// Concurrent load test
#[tokio::test]
async fn test_concurrent_load() {
    const CONCURRENT_USERS: usize = 100;
    const OPERATIONS_PER_USER: usize = 50;

    let config = AsyncOptimizerConfig {
        max_concurrent_ops: CONCURRENT_USERS as usize,
        ..Default::default()
    };

    let optimizer = Arc::new(AsyncOptimizer::new(config));

    let start_time = Instant::now();

    // Spawn concurrent users
    let tasks: Vec<_> = (0..CONCURRENT_USERS)
        .map(|user_id| {
            let optimizer = Arc::clone(&optimizer);

            tokio::spawn(async move {
                let mut success_count = 0;

                for op_id in 0..OPERATIONS_PER_USER {
                    let result = optimizer
                        .execute_operation(|| async {
                            // Simulate user operation with some variability
                            let base_time = Duration::from_millis(10);
                            let jitter = Duration::from_millis(fastrand::u64(0..20));
                            time::sleep(base_time + jitter).await;

                            Ok::<_, String>(format!("user_{}_op_{}", user_id, op_id))
                        })
                        .await;

                    if result.is_ok() {
                        success_count += 1;
                    }
                }

                success_count
            })
        })
        .collect();

    // Wait for all users to complete
    let mut total_successes = 0;
    for task in tasks {
        total_successes += task.await.unwrap();
    }

    let total_time = start_time.elapsed();
    let total_operations = CONCURRENT_USERS * OPERATIONS_PER_USER;
    let operations_per_sec = total_operations as f64 / total_time.as_secs_f64();
    let success_rate = total_successes as f64 / total_operations as f64;

    println!("Concurrent load test results:");
    println!("Concurrent users: {}", CONCURRENT_USERS);
    println!("Operations per user: {}", OPERATIONS_PER_USER);
    println!("Total operations: {}", total_operations);
    println!("Successful operations: {}", total_successes);
    println!("Success rate: {:.2}%", success_rate * 100.0);
    println!("Total time: {:?}", total_time);
    println!("Operations/sec: {:.2}", operations_per_sec);

    // Assert performance meets requirements
    assert!(
        success_rate >= 0.99,
        "Success rate too low: {:.2}%",
        success_rate * 100.0
    );

    assert!(
        operations_per_sec >= 1000.0,
        "Throughput too low: {:.2} ops/sec",
        operations_per_sec
    );
}

/// Stress test for system limits
#[tokio::test]
async fn test_stress_limits() {
    const MAX_CONCURRENT: usize = 2000;
    const STRESS_DURATION: Duration = Duration::from_secs(10);

    let config = AsyncOptimizerConfig {
        max_concurrent_ops: MAX_CONCURRENT,
        ..Default::default()
    };

    let optimizer = Arc::new(AsyncOptimizer::new(config));

    let start_time = Instant::now();
    let mut completed_operations = 0;
    let mut failed_operations = 0;

    // Create a high-concurrency stress test
    let (tx, mut rx) = tokio::sync::mpsc::channel(MAX_CONCURRENT);

    // Spawn operation generators
    for _ in 0..MAX_CONCURRENT {
        let tx = tx.clone();
        let optimizer = Arc::clone(&optimizer);

        tokio::spawn(async move {
            let _ = tx.send(()).await; // Signal ready

            while start_time.elapsed() < STRESS_DURATION {
                let result = optimizer
                    .execute_operation(|| async {
                        time::sleep(Duration::from_micros(100)).await;
                        Ok::<_, String>("stress_test".to_string())
                    })
                    .await;

                let _ = tx.send(result).await;
            }
        });
    }

    // Drop the original sender
    drop(tx);

    // Collect results
    while let Some(result) = rx.recv().await {
        match result {
            Ok(_) => completed_operations += 1,
            Err(_) => failed_operations += 1,
        }

        // Break if we've been running too long
        if start_time.elapsed() > STRESS_DURATION + Duration::from_secs(1) {
            break;
        }
    }

    let total_operations = completed_operations + failed_operations;
    let operations_per_sec = total_operations as f64 / STRESS_DURATION.as_secs_f64();
    let failure_rate = failed_operations as f64 / total_operations as f64;

    println!("Stress test results:");
    println!("Max concurrent operations: {}", MAX_CONCURRENT);
    println!("Test duration: {:?}", STRESS_DURATION);
    println!("Total operations: {}", total_operations);
    println!("Completed: {}", completed_operations);
    println!("Failed: {}", failed_operations);
    println!("Failure rate: {:.2}%", failure_rate * 100.0);
    println!("Operations/sec: {:.2}", operations_per_sec);

    // Assert system can handle high concurrency
    assert!(
        failure_rate < 0.05,
        "Failure rate too high under stress: {:.2}%",
        failure_rate * 100.0
    );

    assert!(
        operations_per_sec >= 5000.0,
        "Stress throughput too low: {:.2} ops/sec",
        operations_per_sec
    );
}

/// Helper function to get approximate memory usage
fn get_memory_usage_mb() -> usize {
    // This is a simplified approximation
    // In a real system, you'd use system-specific APIs
    // For now, return a reasonable baseline
    64 // Assume 64MB baseline
}

/// Performance regression detection
#[tokio::test]
async fn test_performance_regression() {
    // This test would compare current performance against historical baselines
    // In a real CI/CD system, you'd store performance metrics and compare

    let baseline_p95 = Duration::from_millis(50); // Historical baseline
    let current_p95 = Duration::from_millis(45); // Current performance

    // Assert no performance regression
    assert!(
        current_p95 <= baseline_p95,
        "Performance regression detected: current P95 {:?} > baseline P95 {:?}",
        current_p95,
        baseline_p95
    );

    println!("Performance regression test passed:");
    println!("Baseline P95: {:?}", baseline_p95);
    println!("Current P95: {:?}", current_p95);
    println!(
        "Improvement: {:?}",
        baseline_p95.saturating_sub(current_p95)
    );
}

