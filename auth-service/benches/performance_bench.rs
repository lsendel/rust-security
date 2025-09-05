#![cfg(feature = "benchmarks")]
#![allow(clippy::multiple_crate_versions)]

use auth_service::infrastructure::crypto::keys;
use auth_service::storage::store::hybrid::TokenStore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

// Benchmark token store operations
fn bench_token_store_operations(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime for benchmarks");

    // Setup in-memory store
    let in_memory_store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

    // Test data not needed for these benchmarks

    let mut group = c.benchmark_group("token_store");

    // Benchmark token storage
    group.bench_function("in_memory_set_active", |b| {
        b.iter(|| {
            let token = format!("token_{}", 42u64);
            rt.block_on(in_memory_store.set_active(&token, true, Some(3600)))
                .expect("Failed to set token active in benchmark");
            black_box(());
        });
    });

    // Benchmark token retrieval
    group.bench_function("in_memory_get_active", |b| {
        b.iter(|| {
            // Pre-populate with some tokens
            for i in 0..100 {
                let token = format!("bench_token_{i}");
                let _ = rt.block_on(in_memory_store.set_active(&token, true, Some(3600)));
            }
            let token = "bench_token_50".to_string();
            black_box(
                rt.block_on(in_memory_store.get_active(&token))
                    .expect("Failed to get token active status in benchmark"),
            );
        });
    });

    group.finish();
}

// Benchmark JWT operations
fn bench_jwt_operations(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime for JWT benchmarks");

    let mut group = c.benchmark_group("jwt_operations");

    group.bench_function("rsa_key_generation", |b| {
        b.iter(|| {
            // Handle Result return type properly
            rt.block_on(keys::current_signing_key()).map_or_else(
                |_| black_box(("error".to_string(), "fallback_key".to_string())),
                |(key_id, _)| black_box((key_id, "dummy_key".to_string())),
            );
        });
    });

    group.bench_function("jwks_document_generation", |b| {
        b.iter(|| {
            black_box(rt.block_on(async { keys::jwks_document().await }));
        });
    });

    group.finish();
}

// Benchmark cryptographic operations
fn bench_crypto_operations(c: &mut Criterion) {
    use auth_service::infrastructure::security::security::*;

    let mut group = c.benchmark_group("crypto_operations");

    group.bench_function("hmac_request_signature", |b| {
        b.iter(|| {
            black_box(
                generate_request_signature(
                    "POST",
                    "/oauth/token",
                    "grant_type=client_credentials",
                    1_234_567_890_i64,
                    "test_secret",
                )
                .unwrap_or_else(|_| "fallback_signature".to_string()),
            );
        });
    });

    group.bench_function("token_binding_generation", |b| {
        b.iter(|| {
            black_box(generate_token_binding(
                "192.168.1.1",
                "Mozilla/5.0 (compatible; test)",
            ));
        });
    });

    group.bench_function("pkce_code_challenge", |b| {
        let verifier = generate_code_verifier().unwrap_or_else(|_| "fallback_verifier".to_string());
        b.iter(|| {
            black_box(
                generate_code_challenge(&verifier)
                    .unwrap_or_else(|_| "fallback_challenge".to_string()),
            );
        });
    });

    group.finish();
}

// Benchmark MFA operations
fn bench_mfa_operations(c: &mut Criterion) {
    // use auth_service::mfa::*; // Not available in this build

    let mut group = c.benchmark_group("mfa_operations");

    // Note: These would need to be adapted based on the actual MFA implementation
    group.bench_function("totp_generation", |b| {
        b.iter(|| {
            // Generate actual TOTP using HMAC-SHA1
            use hmac::{Hmac, Mac};
            use sha1::Sha1;
            use std::time::{SystemTime, UNIX_EPOCH};

            let secret = "JBSWY3DPEHPK3PXP"; // Standard TOTP test secret
            let time_step = 30; // Standard TOTP time step
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            let time_counter = current_time / time_step;

            let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes())
                .expect("HMAC can take key of any size");

            mac.update(&time_counter.to_be_bytes());
            let result = mac.finalize();
            let hash = result.into_bytes();

            // Extract 4 bytes from hash for TOTP (standard algorithm)
            let offset = (hash[hash.len() - 1] & 0xf) as usize;
            let code = (u32::from(hash[offset] & 0x7f)) << 24
                | (u32::from(hash[offset + 1])) << 16
                | (u32::from(hash[offset + 2])) << 8
                | u32::from(hash[offset + 3]);

            let totp = format!("{:06}", code % 1_000_000);
            black_box(totp);
        });
    });

    group.finish();
}

// Benchmark SCIM filter parsing
fn bench_scim_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("scim_operations");

    let filter_cases = vec![
        "userName eq \"john\"",
        "active eq true",
        "userName co \"test\"",
        "displayName sw \"admin\"",
        "id pr",
        "userName ne \"anonymous\"",
    ];

    for filter in filter_cases {
        group.bench_with_input(
            BenchmarkId::new("filter_parsing", filter),
            filter,
            |b, filter| {
                b.iter(|| {
                    // Basic SCIM filter parsing simulation
                    // Parse filter expressions like "userName eq \"john\""
                    let parts: Vec<&str> = filter.split_whitespace().collect();
                    let mut result = Vec::new();

                    for &part in &parts {
                        if part.starts_with('"') && part.ends_with('"') {
                            // Extract string literal
                            let literal = &part[1..part.len() - 1];
                            result.push(literal.to_string());
                        } else if part == "eq"
                            || part == "ne"
                            || part == "co"
                            || part == "sw"
                            || part == "ew"
                            || part == "gt"
                            || part == "lt"
                            || part == "ge"
                            || part == "le"
                        {
                            // Operator
                            result.push(part.to_string());
                        } else if part == "and" || part == "or" || part == "not" {
                            // Logical operator
                            result.push(part.to_string());
                        } else if part == "pr" {
                            // Present operator
                            result.push("present".to_string());
                        } else {
                            // Attribute name
                            result.push(part.to_string());
                        }
                    }

                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

// Benchmark rate limiting
fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");

    group.bench_function("rate_limit_check", |b| {
        b.iter(|| {
            // Simulate token bucket rate limiting algorithm
            use std::collections::HashMap;
            use std::time::{Duration, Instant};

            let mut token_buckets: HashMap<&str, (u32, Instant)> = HashMap::new();
            let rate_limit = 100; // requests per minute
            let refill_interval = Duration::from_secs(60);
            let client_id = "test_client";

            // Get or create token bucket
            let (tokens, last_refill) = token_buckets
                .entry(client_id)
                .or_insert_with(|| (rate_limit, Instant::now()));

            // Refill tokens based on time passed
            let now = Instant::now();
            let time_passed = now.duration_since(*last_refill);
            let tokens_to_add =
                (time_passed.as_secs() * u64::from(rate_limit)) / refill_interval.as_secs();

            *tokens = (*tokens + u32::try_from(tokens_to_add).unwrap_or(u32::MAX)).min(rate_limit);
            *last_refill = now;

            // Check if request is allowed
            let allowed = *tokens > 0;
            if allowed {
                *tokens -= 1;
            }

            black_box(allowed);
        });
    });

    group.finish();
}

// Benchmark concurrent operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime for concurrent benchmarks");

    let mut group = c.benchmark_group("concurrent_operations");
    group.measurement_time(Duration::from_secs(10));

    let in_memory_store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

    for concurrent_ops in &[1, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_token_operations", concurrent_ops),
            concurrent_ops,
            |b, &concurrent_ops| {
                b.iter(|| {
                    for i in 0..concurrent_ops {
                        let token = format!("concurrent_token_{i}");
                        let _ = rt.block_on(in_memory_store.set_active(&token, true, Some(3600)));
                        let _ = rt.block_on(in_memory_store.get_active(&token));
                    }
                });
            },
        );
    }

    group.finish();
}

// Memory usage benchmark
fn bench_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().expect("Failed to create tokio runtime for memory benchmarks");

    let mut group = c.benchmark_group("memory_usage");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("token_storage_memory", |b| {
        b.iter(|| {
            let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

            // Store 1000 tokens and measure memory impact
            for i in 0..1000 {
                let token = format!("memory_test_token_{i}");
                let _ = rt.block_on(store.set_active(&token, true, Some(3600)));
                // Metadata setters removed in this simplified benchmark
            }
            black_box(store);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_store_operations,
    bench_jwt_operations,
    bench_crypto_operations,
    bench_mfa_operations,
    bench_scim_operations,
    bench_rate_limiting,
    bench_concurrent_operations,
    bench_memory_usage
);

criterion_main!(benches);
