//! Performance benchmarks for auth-core
//!
//! Simplified benchmarks focusing on core functionality:
//! - Server creation and building
//! - Configuration operations
//! - Method calls

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use auth_core::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tokio::runtime::Runtime;

fn bench_server_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("server_creation");

    // Benchmark minimal server creation
    group.bench_function("minimal_server", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    AuthServer::minimal()
                        .with_client("bench_client", "bench_secret")
                        .build()
                        .expect("Failed to build server"),
                )
            })
        })
    });

    // Benchmark server with multiple clients
    group.bench_function("multi_client_server", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    AuthServer::minimal()
                        .with_client("client1", "secret1")
                        .with_client("client2", "secret2")
                        .with_client("client3", "secret3")
                        .with_client("client4", "secret4")
                        .with_client("client5", "secret5")
                        .build()
                        .expect("Failed to build server"),
                )
            })
        })
    });

    group.finish();
}

fn bench_server_methods(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let server = rt.block_on(async {
        AuthServer::minimal()
            .with_client("test_client", "test_secret")
            .build()
            .expect("Failed to build server")
    });

    let mut group = c.benchmark_group("server_methods");

    // Benchmark server cloning
    group.bench_function("clone_server", |b| b.iter(|| black_box(server.clone())));

    // Benchmark build method
    group.bench_function("build_method", |b| {
        b.iter(|| black_box(server.clone().build().expect("Build should work")))
    });

    // Benchmark into_make_service method
    group.bench_function("into_make_service", |b| {
        b.iter(|| {
            let server_clone = server.clone();
            black_box(server_clone.into_make_service())
        })
    });

    group.finish();
}

fn bench_builder_pattern(c: &mut Criterion) {
    let mut group = c.benchmark_group("builder_pattern");

    // Benchmark builder creation
    group.bench_function("builder_creation", |b| {
        b.iter(|| black_box(AuthServer::minimal()))
    });

    // Benchmark adding clients
    group.bench_function("add_single_client", |b| {
        b.iter(|| black_box(AuthServer::minimal().with_client("client", "secret")))
    });

    // Benchmark configuration methods
    group.bench_function("full_configuration", |b| {
        b.iter(|| {
            black_box(
                AuthServer::minimal()
                    .with_client("client", "secret")
                    .with_cors(true)
                    .with_rate_limit(100)
                    .with_jwt_secret("test-secret")
                    .with_token_ttl(3600)
                    .with_scope("read"),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_server_creation,
    bench_server_methods,
    bench_builder_pattern
);
criterion_main!(benches);
