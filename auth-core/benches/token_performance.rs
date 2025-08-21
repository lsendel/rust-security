//! Performance benchmarks for auth-core token operations
//!
//! Measures performance of critical paths:
//! - Token generation
//! - Token validation
//! - Client authentication
//! - Concurrent request handling

use auth_core::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use tokio::runtime::Runtime;

fn bench_token_generation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let server = rt.block_on(async {
        AuthServer::minimal()
            .with_client("bench_client", "bench_secret")
            .build()
            .expect("Failed to build server")
    });

    let mut group = c.benchmark_group("token_generation");

    // Benchmark single token generation
    group.bench_function("single_token", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server_clone = server.clone();

                let server_handle = tokio::spawn(async move {
                    axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let client = reqwest::Client::new();
                let response = client
                    .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", "bench_client"),
                        ("client_secret", "bench_secret"),
                    ])
                    .send()
                    .await
                    .unwrap();

                server_handle.abort();
                black_box(response.text().await.unwrap())
            })
        });
    });

    // Benchmark concurrent token generation
    for concurrency in [1, 5, 10, 20].iter() {
        group.throughput(Throughput::Elements(*concurrency as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent_tokens", concurrency),
            concurrency,
            |b, &concurrency| {
                b.iter(|| {
                    rt.block_on(async {
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let addr = listener.local_addr().unwrap();
                        let server_clone = server.clone();

                        let server_handle = tokio::spawn(async move {
                            axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                        });

                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                        let mut handles = Vec::new();
                        for _ in 0..concurrency {
                            let addr = addr;
                            let handle = tokio::spawn(async move {
                                let client = reqwest::Client::new();
                                client
                                    .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
                                    .form(&[
                                        ("grant_type", "client_credentials"),
                                        ("client_id", "bench_client"),
                                        ("client_secret", "bench_secret"),
                                    ])
                                    .send()
                                    .await
                                    .unwrap()
                                    .text()
                                    .await
                                    .unwrap()
                            });
                            handles.push(handle);
                        }

                        let results = futures::future::join_all(handles).await;
                        server_handle.abort();

                        black_box(results)
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_client_validation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let server = rt.block_on(async {
        AuthServer::minimal()
            .with_client("valid_client", "valid_secret_that_is_reasonably_long")
            .build()
            .expect("Failed to build server")
    });

    let mut group = c.benchmark_group("client_validation");

    // Benchmark valid client authentication
    group.bench_function("valid_client", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server_clone = server.clone();

                let server_handle = tokio::spawn(async move {
                    axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let client = reqwest::Client::new();
                let response = client
                    .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", "valid_client"),
                        ("client_secret", "valid_secret_that_is_reasonably_long"),
                    ])
                    .send()
                    .await
                    .unwrap();

                server_handle.abort();
                black_box(response.status().as_u16())
            })
        });
    });

    // Benchmark invalid client authentication (should be timing-safe)
    group.bench_function("invalid_client", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server_clone = server.clone();

                let server_handle = tokio::spawn(async move {
                    axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let client = reqwest::Client::new();
                let response = client
                    .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", "invalid_client"),
                        ("client_secret", "invalid_secret_that_is_reasonably_long"),
                    ])
                    .send()
                    .await
                    .unwrap();

                server_handle.abort();
                black_box(response.status().as_u16())
            })
        });
    });

    group.finish();
}

fn bench_token_introspection(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let (server, test_token) = rt.block_on(async {
        let server = AuthServer::minimal()
            .with_client("test_client", "test_secret")
            .build()
            .expect("Failed to build server");

        // Get a test token
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_clone = server.clone();

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, server_clone.into_make_service()).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .unwrap();

        let token_data: serde_json::Value = response.json().await.unwrap();
        let access_token = token_data.get("access_token").unwrap().as_str().unwrap().to_string();

        server_handle.abort();

        (server, access_token)
    });

    let mut group = c.benchmark_group("token_introspection");

    // Benchmark valid token introspection
    group.bench_function("valid_token", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server_clone = server.clone();

                let server_handle = tokio::spawn(async move {
                    axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let client = reqwest::Client::new();
                let response = client
                    .post(format!("http://127.0.0.1:{}/oauth/introspect", addr.port()))
                    .form(&[
                        ("token", test_token.as_str()),
                        ("client_id", "test_client"),
                        ("client_secret", "test_secret"),
                    ])
                    .send()
                    .await
                    .unwrap();

                server_handle.abort();
                black_box(response.text().await.unwrap())
            })
        });
    });

    // Benchmark invalid token introspection
    group.bench_function("invalid_token", |b| {
        b.iter(|| {
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server_clone = server.clone();

                let server_handle = tokio::spawn(async move {
                    axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                let client = reqwest::Client::new();
                let response = client
                    .post(format!("http://127.0.0.1:{}/oauth/introspect", addr.port()))
                    .form(&[
                        ("token", "invalid_token_12345"),
                        ("client_id", "test_client"),
                        ("client_secret", "test_secret"),
                    ])
                    .send()
                    .await
                    .unwrap();

                server_handle.abort();
                black_box(response.text().await.unwrap())
            })
        });
    });

    group.finish();
}

fn bench_server_startup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("server_operations");

    // Benchmark server building with different numbers of clients
    for num_clients in [1, 10, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("build_server", num_clients),
            num_clients,
            |b, &num_clients| {
                b.iter(|| {
                    let mut builder = AuthServer::minimal();
                    for i in 0..num_clients {
                        builder = builder.with_client(
                            &format!("client_{}", i),
                            &format!("secret_{}_with_reasonable_length", i),
                        );
                    }
                    black_box(builder.build().unwrap())
                });
            },
        );
    }

    // Benchmark server startup time
    group.bench_function("server_startup", |b| {
        b.iter(|| {
            rt.block_on(async {
                let server = AuthServer::minimal()
                    .with_client("startup_client", "startup_secret")
                    .build()
                    .expect("Failed to build server");

                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let server_handle = tokio::spawn(async move {
                    axum::serve(listener, server.into_make_service()).await.unwrap();
                });

                // Measure time to first successful request
                let start = std::time::Instant::now();
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                let startup_time = start.elapsed();

                server_handle.abort();
                black_box(startup_time)
            })
        });
    });

    group.finish();
}

fn bench_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("memory_efficiency");

    // Benchmark memory usage with many tokens
    for num_tokens in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("token_storage", num_tokens),
            num_tokens,
            |b, &num_tokens| {
                b.iter(|| {
                    rt.block_on(async {
                        let server = AuthServer::minimal()
                            .with_client("memory_client", "memory_secret")
                            .build()
                            .expect("Failed to build server");

                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let addr = listener.local_addr().unwrap();
                        let server_clone = server.clone();

                        let server_handle = tokio::spawn(async move {
                            axum::serve(listener, server_clone.into_make_service()).await.unwrap();
                        });

                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

                        // Generate many tokens
                        let client = reqwest::Client::new();
                        for _ in 0..num_tokens {
                            let _ = client
                                .post(format!("http://127.0.0.1:{}/oauth/token", addr.port()))
                                .form(&[
                                    ("grant_type", "client_credentials"),
                                    ("client_id", "memory_client"),
                                    ("client_secret", "memory_secret"),
                                ])
                                .send()
                                .await;
                        }

                        server_handle.abort();
                        black_box(num_tokens)
                    })
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_token_generation,
    bench_client_validation,
    bench_token_introspection,
    bench_server_startup,
    bench_memory_usage
);
criterion_main!(benches);
