use criterion::{black_box, criterion_group, criterion_main, Criterion};
use common::performance_utils::{efficient_concat, PerformanceCache};
use std::time::Duration;

fn benchmark_string_operations(c: &mut Criterion) {
    c.bench_function("efficient_concat_empty", |b| {
        b.iter(|| efficient_concat(black_box(""), black_box("test")))
    });
    
    c.bench_function("efficient_concat_both", |b| {
        b.iter(|| efficient_concat(black_box("prefix_"), black_box("suffix")))
    });
}

fn benchmark_cache_performance(c: &mut Criterion) {
    let mut cache = PerformanceCache::new(1000);
    cache.insert("benchmark_key", "benchmark_value", Duration::from_secs(60));
    
    c.bench_function("cache_hit", |b| {
        b.iter(|| cache.get(black_box(&"benchmark_key")))
    });
    
    c.bench_function("cache_miss", |b| {
        b.iter(|| cache.get(black_box(&"nonexistent_key")))
    });
}

criterion_group!(benches, benchmark_string_operations, benchmark_cache_performance);
criterion_main!(benches);
