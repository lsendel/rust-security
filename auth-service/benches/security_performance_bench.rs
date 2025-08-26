use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;
use tokio::runtime::Runtime;
use base64;
use ring;
use chrono;

// Import the actual auth service modules for realistic benchmarks
use auth_service::{
    jwt_secure::create_secure_jwt_validation,
    rate_limit_secure::{RateLimitConfig, SecureRateLimiter},
    security::{
        generate_code_challenge, generate_code_verifier, generate_token_binding,
        verify_request_signature,
    },
};

// Simple mock PerformanceMonitor for benchmarks
pub struct PerformanceMonitor;

impl PerformanceMonitor {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self)
    }
    
    pub fn record_operation(&self, _operation: &str, _duration: Duration) {
        // Mock implementation for benchmarks
    }
    
    pub fn record_request(&self, _endpoint: &str, _method: &str, _status: u16, _duration: Duration) {
        // Mock implementation for benchmarks
    }
    
    pub fn get_metrics(&self) -> String {
        // Mock implementation returning empty metrics
        String::new()
    }
}

/// Comprehensive security performance benchmarks
/// These benchmarks test real-world security scenarios with varying loads

fn bench_crypto_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("crypto_operations");
    group.throughput(Throughput::Elements(1));

    // Benchmark token binding generation
    group.bench_function("token_binding_generation", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(generate_token_binding("192.168.1.1", "Mozilla/5.0").unwrap())
            })
        })
    });

    group.finish();
}

fn bench_jwt_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("jwt_operations");
    group.throughput(Throughput::Elements(1));

    group.bench_function("jwt_validation_setup", |b| {
        b.iter(|| black_box(create_secure_jwt_validation()))
    });

    group.finish();
}

fn bench_pkce_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pkce_operations");
    group.throughput(Throughput::Elements(1));

    group.bench_function("code_verifier_generation", |b| {
        b.iter(|| black_box(generate_code_verifier().unwrap()))
    });

    group.bench_function("code_challenge_generation", |b| {
        b.iter(|| {
            let verifier = generate_code_verifier().unwrap();
            black_box(generate_code_challenge(&verifier).unwrap())
        })
    });

    group.finish();
}

fn bench_rate_limiting(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("rate_limiting");
    group.throughput(Throughput::Elements(1));

    group.bench_function("rate_limit_check", |b| {
        let config = RateLimitConfig::default();
        let limiter = SecureRateLimiter::new(config);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

        b.iter(|| {
            rt.block_on(async {
                black_box(
                    limiter
                        .check_rate_limit(ip, None, "/test", Some("Mozilla/5.0"))
                        .await,
                )
            })
        })
    });

    group.finish();
}

fn bench_performance_monitoring(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("performance_monitoring");
    group.throughput(Throughput::Elements(1));

    group.bench_function("metrics_recording", |b| {
        let monitor = PerformanceMonitor::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                // Fixed: Use the correct method signature for mock implementation
                monitor.record_operation("test_operation", Duration::from_millis(50));
                black_box(())
            })
        })
    });

    group.bench_function("metrics_retrieval", |b| {
        let monitor = PerformanceMonitor::new().unwrap();

        b.iter(|| rt.block_on(async { black_box(monitor.get_metrics()) }))
    });

    group.finish();
}

fn bench_request_signature_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("request_signature");
    group.throughput(Throughput::Elements(1));

    group.bench_function("signature_verification", |b| {
        let secret = "test-secret-key-that-is-long-enough-for-security";
        let timestamp = chrono::Utc::now().timestamp();

        // Pre-generate signature for verification
        let signature = {
            use base64::Engine;
            use ring::hmac;
            let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
            let message = format!(
                "POST\n/oauth/token\ngrant_type=client_credentials\n{}",
                timestamp
            );
            let tag = hmac::sign(&key, message.as_bytes());
            base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
        };

        b.iter(|| {
            black_box(
                verify_request_signature(
                    "POST",
                    "/oauth/token",
                    "grant_type=client_credentials",
                    timestamp,
                    &signature,
                    secret,
                )
                .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_operations");

    for concurrent_users in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_token_binding", concurrent_users),
            concurrent_users,
            |b, &concurrent_users| {
                b.iter(|| {
                    rt.block_on(async move {
                        let tasks: Vec<_> = (0..concurrent_users)
                            .map(|i| {
                                let ip = format!("192.168.1.{}", (i % 254) + 1);
                                tokio::spawn(async move {
                                    generate_token_binding(&ip, "Mozilla/5.0").unwrap()
                                })
                            })
                            .collect();

                        for task in tasks {
                            black_box(task.await.unwrap());
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

fn bench_memory_intensive_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_intensive");
    group.throughput(Throughput::Elements(1));

    group.bench_function("large_payload_processing", |b| {
        let large_payload = "x".repeat(1_000); // 1KB payload (reduced for faster benchmarks)

        b.iter(|| black_box(generate_token_binding("192.168.1.1", &large_payload).unwrap()))
    });

    group.finish();
}

fn bench_security_validation_pipeline(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("security_pipeline");
    group.throughput(Throughput::Elements(1));

    group.bench_function("full_security_validation", |b| {
        let config = RateLimitConfig::default();
        let limiter = SecureRateLimiter::new(config);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let secret = "test-secret-key-that-is-long-enough-for-security";

        b.iter(|| {
            rt.block_on(async {
                // Step 1: Rate limiting check
                let _rate_check = limiter
                    .check_rate_limit(ip, None, "/oauth/token", Some("Mozilla/5.0"))
                    .await;

                // Step 2: Token binding generation
                let _token_binding = generate_token_binding("192.168.1.1", "Mozilla/5.0").unwrap();

                // Step 3: PKCE code generation
                let verifier = generate_code_verifier().unwrap();
                let _challenge = generate_code_challenge(&verifier).unwrap();

                // Step 4: Request signature verification
                let timestamp = chrono::Utc::now().timestamp();
                let signature = {
                    use base64::Engine;
                    use ring::hmac;
                    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
                    let message = format!(
                        "POST\n/oauth/token\ngrant_type=authorization_code\n{}",
                        timestamp
                    );
                    let tag = hmac::sign(&key, message.as_bytes());
                    base64::engine::general_purpose::STANDARD.encode(tag.as_ref())
                };

                let _sig_valid = verify_request_signature(
                    "POST",
                    "/oauth/token",
                    "grant_type=authorization_code",
                    timestamp,
                    &signature,
                    secret,
                )
                .unwrap();

                black_box(())
            })
        })
    });

    group.finish();
}

fn bench_high_throughput_scenarios(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("high_throughput");

    for rps in [10, 50, 100].iter() {
        // Reduced for faster benchmarks
        group.bench_with_input(
            BenchmarkId::new("requests_per_second", rps),
            rps,
            |b, &rps| {
                b.iter(|| {
                    rt.block_on(async move {
                        let start = std::time::Instant::now();
                        let mut tasks = Vec::new();

                        for i in 0..rps {
                            let ip = format!("192.168.1.{}", (i % 254) + 1);
                            tasks.push(tokio::spawn(async move {
                                generate_token_binding(&ip, "Mozilla/5.0").unwrap()
                            }));
                        }

                        for task in tasks {
                            black_box(task.await.unwrap());
                        }

                        let elapsed = start.elapsed();
                        black_box(elapsed);
                    })
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_crypto_operations,
    bench_jwt_operations,
    bench_pkce_operations,
    bench_rate_limiting,
    bench_performance_monitoring,
    bench_request_signature_verification,
    bench_concurrent_operations,
    bench_memory_intensive_operations,
    bench_security_validation_pipeline,
    bench_high_throughput_scenarios
);

criterion_main!(benches);
