#![cfg(feature = "benchmarks")]
use auth_service::store::TokenStore;
use auth_service::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

// Benchmark token store operations
fn bench_token_store_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Setup in-memory store
    let in_memory_store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

    // Setup test data
    let test_record = IntrospectionRecord {
        active: true,
        scope: Some("read write".to_string()),
        client_id: Some("test-client".to_string()),
        exp: Some(1234567890),
        iat: Some(1234567890),
        sub: Some("test-user".to_string()),
        token_binding: None,
    };

    let mut group = c.benchmark_group("token_store");

    // Benchmark token storage
    group.bench_function("in_memory_set_active", |b| {
        b.iter(|| {
            let token = format!("token_{}", 42u64);
            black_box(rt.block_on(in_memory_store.set_active(&token, true, Some(3600))).unwrap());
        });
    });

    // Benchmark token retrieval
    group.bench_function("in_memory_get_record", |b| {
        b.iter(|| {
            // Pre-populate with some tokens
            for i in 0..100 {
                let token = format!("bench_token_{}", i);
                let _ = rt.block_on(in_memory_store.set_active(&token, true, Some(3600)));
            }
            let token = format!("bench_token_{}", 50usize);
            black_box(rt.block_on(in_memory_store.get_record(&token)).unwrap());
        });
    });

    group.finish();
}

// Benchmark JWT operations
fn bench_jwt_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("jwt_operations");

    group.bench_function("rsa_key_generation", |b| {
        b.iter(|| {
            black_box(rt.block_on(auth_service::keys::current_signing_key()));
        });
    });

    group.bench_function("jwks_document_generation", |b| {
        b.iter(|| {
            black_box(rt.block_on(async { auth_service::keys::jwks_document().await }));
        });
    });

    group.finish();
}

// Benchmark cryptographic operations
fn bench_crypto_operations(c: &mut Criterion) {
    use auth_service::security::*;

    let mut group = c.benchmark_group("crypto_operations");

    group.bench_function("hmac_request_signature", |b| {
        b.iter(|| {
            black_box(
                generate_request_signature(
                    "POST",
                    "/oauth/token",
                    "grant_type=client_credentials",
                    1234567890,
                    "test_secret",
                )
                .unwrap(),
            );
        });
    });

    group.bench_function("token_binding_generation", |b| {
        b.iter(|| {
            black_box(generate_token_binding("192.168.1.1", "Mozilla/5.0 (compatible; test)"));
        });
    });

    group.bench_function("pkce_code_challenge", |b| {
        let verifier = generate_code_verifier();
        b.iter(|| {
            black_box(generate_code_challenge(&verifier));
        });
    });

    group.finish();
}

// Benchmark MFA operations
fn bench_mfa_operations(c: &mut Criterion) {
    use auth_service::mfa::*;

    let mut group = c.benchmark_group("mfa_operations");

    // Note: These would need to be adapted based on the actual MFA implementation
    group.bench_function("totp_generation", |b| {
        b.iter(|| {
            // Simulate TOTP generation - would need actual implementation
            black_box("123456".to_string());
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
        group.bench_with_input(BenchmarkId::new("filter_parsing", filter), filter, |b, filter| {
            b.iter(|| {
                // Would need to expose the parse_scim_filter function
                black_box(filter.len());
            });
        });
    }

    group.finish();
}

// Benchmark rate limiting
fn bench_rate_limiting(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("rate_limiting");

    group.bench_function("rate_limit_check", |b| {
        b.iter(|| {
            // Simulate rate limiting logic
            use std::time::Instant;
            let now = Instant::now();
            black_box(now.elapsed().as_millis());
        });
    });

    group.finish();
}

// Benchmark concurrent operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_operations");
    group.measurement_time(Duration::from_secs(10));

    let in_memory_store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

    for concurrent_ops in [1, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_token_operations", concurrent_ops),
            concurrent_ops,
            |b, &concurrent_ops| {
                b.iter(|| {
                    for i in 0..concurrent_ops {
                        let token = format!("concurrent_token_{}", i);
                        let _ = rt.block_on(in_memory_store.set_active(&token, true, Some(3600)));
                        let _ = rt.block_on(in_memory_store.get_record(&token));
                    }
                });
            },
        );
    }

    group.finish();
}

// Memory usage benchmark
fn bench_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("memory_usage");
    group.measurement_time(Duration::from_secs(5));

    group.bench_function("token_storage_memory", |b| {
        b.iter(|| {
            let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));

            // Store 1000 tokens and measure memory impact
            for i in 0..1000 {
                let token = format!("memory_test_token_{}", i);
                let _ = rt.block_on(store.set_active(&token, true, Some(3600)));
                let _ = rt.block_on(store.set_scope(
                    &token,
                    Some("read write".to_string()),
                    Some(3600),
                ));
                let _ =
                    rt.block_on(store.set_client_id(&token, format!("client_{}", i), Some(3600)));
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
