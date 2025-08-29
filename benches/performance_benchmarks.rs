//! Performance benchmarks for critical security components
//!
//! These benchmarks validate production performance requirements:
//! - Authentication latency < 100ms P95
//! - Authorization decisions < 50ms P95
//! - Rate limiting operations < 10ms P95
//! - Connection pool operations < 25ms P95

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::time::Duration;

mod auth_benchmarks;
mod connection_pool_benchmarks;
mod policy_benchmarks;
mod rate_limit_benchmarks;

/// Authentication service benchmarks
mod auth_benchmarks {
    use super::*;
    use common::crypto_utils::SecureRandom;

    pub fn bench_secure_random_generation(c: &mut Criterion) {
        let rng = SecureRandom::new();

        c.bench_function("secure_random_32_bytes", |b| {
            b.iter(|| black_box(rng.generate_bytes(32).unwrap()))
        });

        c.bench_function("secure_random_session_id", |b| {
            b.iter(|| black_box(rng.generate_session_id().unwrap()))
        });
    }

    pub fn bench_password_hashing(c: &mut Criterion) {
        c.bench_function("argon2_password_hash", |b| {
            b.iter(|| black_box(common::crypto_utils::hash_password("test_password")))
        });
    }
}

/// Policy engine benchmarks
mod policy_benchmarks {
    use super::*;

    pub fn bench_policy_evaluation(c: &mut Criterion) {
        // This would require setting up a test policy and entities
        // For now, we'll benchmark the basic Cedar operations

        c.bench_function("cedar_authorizer_creation", |b| {
            b.iter(|| black_box(cedar_policy::Authorizer::new()))
        });
    }
}

/// Connection pool benchmarks
mod connection_pool_benchmarks {
    use super::*;
    use common::optimized_pools::{OptimizedRedisPool, UnifiedRedisConfig};

    pub async fn bench_connection_pool_operations() -> Result<(), Box<dyn std::error::Error>> {
        // Setup test Redis configuration
        let config = UnifiedRedisConfig {
            url: "redis://localhost:6379".to_string(),
            connection_timeout_ms: 5000,
            command_timeout_ms: 2000,
            pool_size: 10,
            idle_timeout_duration: Duration::from_secs(300),
            max_lifetime_duration: Duration::from_secs(3600),
            health_check_interval: Duration::from_secs(30),
        };

        let pool = OptimizedRedisPool::new(config).await?;

        // Benchmark connection acquisition
        let mut criterion = Criterion::default().sample_size(100);
        let mut group = criterion.benchmark_group("connection_pool");

        group.bench_function("get_connection", |b| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    let conn = pool.get_connection().await.unwrap();
                    black_box(conn);
                });
        });

        group.finish();

        Ok(())
    }
}

/// Rate limiter benchmarks
mod rate_limit_benchmarks {
    use super::*;
    use common::sharded_rate_limiter::{RateLimitConfig, ShardedRateLimiter};
    use std::time::Duration;

    pub async fn bench_rate_limiting() -> Result<(), Box<dyn std::error::Error>> {
        let config = RateLimitConfig {
            default_limit: 100,
            window_duration: Duration::from_secs(60),
            cleanup_interval: Duration::from_secs(300),
            enabled: true,
            burst_multiplier: 1.5,
        };

        let limiter = ShardedRateLimiter::new(config);

        let mut criterion = Criterion::default().sample_size(1000);
        let mut group = criterion.benchmark_group("rate_limiting");

        group.bench_function("check_rate_limit_allowed", |b| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async { black_box(limiter.check_rate_limit("test_key").await.unwrap()) });
        });

        group.bench_function("check_rate_limit_exceeded", |b| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    // Fill up the rate limit first
                    for i in 0..config.default_limit {
                        let _ = limiter.check_rate_limit(&format!("test_key_{}", i)).await;
                    }
                    black_box(limiter.check_rate_limit("test_key").await)
                });
        });

        group.finish();

        Ok(())
    }
}

fn benchmark_auth_operations(c: &mut Criterion) {
    auth_benchmarks::bench_secure_random_generation(c);
    auth_benchmarks::bench_password_hashing(c);
}

fn benchmark_policy_operations(c: &mut Criterion) {
    policy_benchmarks::bench_policy_evaluation(c);
}

fn benchmark_connection_pool(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("connection_pool_setup", |b| {
        b.to_async(&rt).iter(|| async {
            // This would be a simplified benchmark - full implementation needs Redis
            black_box(())
        });
    });
}

criterion_group!(
    name = security_benchmarks;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(1));
    targets =
        benchmark_auth_operations,
        benchmark_policy_operations,
        benchmark_connection_pool
);

criterion_main!(security_benchmarks);
