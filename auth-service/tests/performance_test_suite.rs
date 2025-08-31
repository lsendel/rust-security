//! Comprehensive Performance Test Suite
//!
//! Performance benchmarking and optimization for critical security components.
//! Identifies bottlenecks and measures improvements across different scenarios.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// Import our storage modules
use auth_service::storage::cache::{LruTokenCache, TokenCacheConfig};
use auth_service::storage::session::store::RedisSessionStore;

// Import test framework
use crate::tests::test_framework::*;

/// Performance benchmark results
#[derive(Debug, Clone)]
pub struct PerformanceBenchmark {
    pub name: String,
    pub operations_per_second: f64,
    pub average_latency: Duration,
    pub p50_latency: Duration,
    pub p95_latency: Duration,
    pub p99_latency: Duration,
    pub total_operations: usize,
    pub total_duration: Duration,
    pub memory_usage: Option<u64>,
    pub metadata: HashMap<String, String>,
}

impl PerformanceBenchmark {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            operations_per_second: 0.0,
            average_latency: Duration::default(),
            p50_latency: Duration::default(),
            p95_latency: Duration::default(),
            p99_latency: Duration::default(),
            total_operations: 0,
            total_duration: Duration::default(),
            memory_usage: None,
            metadata: HashMap::new(),
        }
    }
}

/// Performance test suite
pub struct PerformanceTestSuite {
    benchmarks: Arc<RwLock<Vec<PerformanceBenchmark>>>,
    baseline_results: Arc<RwLock<HashMap<String, PerformanceBenchmark>>>,
}

impl PerformanceTestSuite {
    pub fn new() -> Self {
        Self {
            benchmarks: Arc::new(RwLock::new(Vec::new())),
            baseline_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Run token cache performance benchmark
    pub async fn benchmark_token_cache(
        &self,
        name: &str,
        config: TokenCacheConfig,
        concurrent_users: usize,
        operations_per_user: usize,
    ) -> Result<(), String> {
        info!("Running token cache benchmark: {}", name);

        let cache = Arc::new(LruTokenCache::with_config(config.clone()));
        let start_time = Instant::now();

        // Pre-populate cache
        for i in 0..1000 {
            let token = common::TokenRecord { active: true, scope: Some("read write".to_string()), client_id: Some("client".to_string()), exp: None, iat: None, sub: Some(format!("user_{}", i)), token_binding: None, mfa_verified: false };
            cache
                .insert(format!("token_{}", i), token)
                .await;
        }

        // Run concurrent benchmark
        let mut handles = Vec::new();
        let mut all_latencies = Vec::new();

        for user_id in 0..concurrent_users {
            let cache = cache.clone();
            let handle = tokio::spawn(async move {
                let mut user_latencies = Vec::new();

                for op in 0..operations_per_user {
                    let start = Instant::now();

                    // Mix of read and write operations
                    if op % 3 == 0 {
                        // Write operation
                        let token = common::TokenRecord { active: true, scope: Some("read write".to_string()), client_id: Some("client".to_string()), exp: None, iat: None, sub: Some(format!("user_{}_{}", user_id, op)), token_binding: None, mfa_verified: false };
                        let _ = cache
                            .insert(format!("token_{}_{}", user_id, op), token)
                            .await;
                    } else {
                        // Read operation
                        let _ = cache.get(&format!("token_{}", op % 1000)).await;
                    }

                    user_latencies.push(start.elapsed());
                }

                user_latencies
            });

            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(latencies) => all_latencies.extend(latencies),
                Err(e) => return Err(format!("Benchmark task failed: {}", e)),
            }
        }

        let total_duration = start_time.elapsed();
        let total_operations = all_latencies.len();

        // Calculate percentiles
        all_latencies.sort();
        let p50_idx = (total_operations as f64 * 0.5) as usize;
        let p95_idx = (total_operations as f64 * 0.95) as usize;
        let p99_idx = (total_operations as f64 * 0.99) as usize;

        let benchmark = PerformanceBenchmark {
            name: name.to_string(),
            operations_per_second: total_operations as f64 / total_duration.as_secs_f64(),
            average_latency: total_duration / total_operations as u32,
            p50_latency: all_latencies
                .get(p50_idx)
                .copied()
                .unwrap_or(Duration::default()),
            p95_latency: all_latencies
                .get(p95_idx)
                .copied()
                .unwrap_or(Duration::default()),
            p99_latency: all_latencies
                .get(p99_idx)
                .copied()
                .unwrap_or(Duration::default()),
            total_operations,
            total_duration,
            memory_usage: None, // Would require external monitoring
            metadata: HashMap::from([
                ("concurrent_users".to_string(), concurrent_users.to_string()),
                (
                    "operations_per_user".to_string(),
                    operations_per_user.to_string(),
                ),
                ("cache_config".to_string(), format!("{:?}", config)),
            ]),
        };

        let mut benchmarks = self.benchmarks.write().await;
        benchmarks.push(benchmark);

        Ok(())
    }

    /// Benchmark session store performance
    pub async fn benchmark_session_store(
        &self,
        name: &str,
        concurrent_sessions: usize,
        operations_per_session: usize,
    ) -> Result<(), String> {
        info!("Running session store benchmark: {}", name);

        // For this benchmark, we'll simulate session operations
        // In a real implementation, this would use the actual RedisSessionStore

        let start_time = Instant::now();
        let mut all_latencies = Vec::new();

        // Simulate concurrent session operations
        let handles: Vec<_> = (0..concurrent_sessions)
            .map(|session_id| {
                tokio::spawn(async move {
                    let mut latencies = Vec::new();

                    for op in 0..operations_per_session {
                        let start = Instant::now();

                        // Simulate session operation (create, read, update, delete)
                        match op % 4 {
                            0 => {
                                // Create session
                                let session_data = auth_service::storage::session::secure::SecureSessionData {
                                    user_id: format!("user_{}", session_id),
                                    client_id: Some(format!("client_{}", session_id)),
                                    created_at: chrono::Utc::now(),
                                    last_accessed: chrono::Utc::now(),
                                    expires_at: chrono::Utc::now(),
                                    ip_address: "127.0.0.1".to_string(),
                                    user_agent_hash: "ua".to_string(),
                                    is_authenticated: true,
                                    requires_mfa: false,
                                    mfa_completed: true,
                                    csrf_token: "csrf".to_string(),
                                    session_version: 1,
                                    access_count: 0,
                                    last_rotation: chrono::Utc::now(),
                                };
                                // Simulate storage operation
                                tokio::time::sleep(Duration::from_micros(50)).await;
                            }
                            1 => {
                                // Read session
                                tokio::time::sleep(Duration::from_micros(30)).await;
                            }
                            2 => {
                                // Update session
                                tokio::time::sleep(Duration::from_micros(40)).await;
                            }
                            3 => {
                                // Delete session
                                tokio::time::sleep(Duration::from_micros(35)).await;
                            }
                            _ => unreachable!(),
                        }

                        latencies.push(start.elapsed());
                    }

                    latencies
                })
            })
            .collect();

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(latencies) => all_latencies.extend(latencies),
                Err(e) => return Err(format!("Session benchmark task failed: {}", e)),
            }
        }

        let total_duration = start_time.elapsed();
        let total_operations = all_latencies.len();

        // Calculate percentiles
        all_latencies.sort();
        let p50_idx = (total_operations as f64 * 0.5) as usize;
        let p95_idx = (total_operations as f64 * 0.95) as usize;
        let p99_idx = (total_operations as f64 * 0.99) as usize;

        let benchmark = PerformanceBenchmark {
            name: name.to_string(),
            operations_per_second: total_operations as f64 / total_duration.as_secs_f64(),
            average_latency: total_duration / total_operations as u32,
            p50_latency: all_latencies
                .get(p50_idx)
                .copied()
                .unwrap_or(Duration::default()),
            p95_latency: all_latencies
                .get(p95_idx)
                .copied()
                .unwrap_or(Duration::default()),
            p99_latency: all_latencies
                .get(p99_idx)
                .copied()
                .unwrap_or(Duration::default()),
            total_operations,
            total_duration,
            memory_usage: None,
            metadata: HashMap::from([
                (
                    "concurrent_sessions".to_string(),
                    concurrent_sessions.to_string(),
                ),
                (
                    "operations_per_session".to_string(),
                    operations_per_session.to_string(),
                ),
                ("backend".to_string(), "simulated".to_string()),
            ]),
        };

        let mut benchmarks = self.benchmarks.write().await;
        benchmarks.push(benchmark);

        Ok(())
    }

    /// Compare current results with baseline
    pub async fn compare_with_baseline(
        &self,
        baseline_name: &str,
    ) -> HashMap<String, PerformanceComparison> {
        let benchmarks = self.benchmarks.read().await;
        let baseline_results = self.baseline_results.read().await;
        let mut comparisons = HashMap::new();

        for benchmark in &*benchmarks {
            if let Some(baseline) = baseline_results.get(&benchmark.name) {
                let ops_per_sec_change = ((benchmark.operations_per_second
                    - baseline.operations_per_second)
                    / baseline.operations_per_second)
                    * 100.0;

                let avg_latency_change = if baseline.average_latency.as_nanos() > 0 {
                    ((benchmark.average_latency.as_nanos() as f64
                        - baseline.average_latency.as_nanos() as f64)
                        / baseline.average_latency.as_nanos() as f64)
                        * 100.0
                } else {
                    0.0
                };

                comparisons.insert(
                    benchmark.name.clone(),
                    PerformanceComparison {
                        benchmark_name: benchmark.name.clone(),
                        ops_per_sec_change,
                        avg_latency_change,
                        baseline_ops_per_sec: baseline.operations_per_second,
                        current_ops_per_sec: benchmark.operations_per_second,
                        baseline_avg_latency: baseline.average_latency,
                        current_avg_latency: benchmark.average_latency,
                    },
                );
            }
        }

        comparisons
    }

    /// Generate comprehensive performance report
    pub async fn generate_performance_report(&self) -> PerformanceReport {
        let benchmarks = self.benchmarks.read().await;
        let comparisons = self.compare_with_baseline("baseline").await;

        PerformanceReport {
            benchmarks: benchmarks.clone(),
            comparisons,
            generated_at: std::time::SystemTime::now(),
            summary: self.generate_summary(&benchmarks).await,
        }
    }

    async fn generate_summary(&self, benchmarks: &[PerformanceBenchmark]) -> PerformanceSummary {
        if benchmarks.is_empty() {
            return PerformanceSummary {
                total_benchmarks: 0,
                average_ops_per_sec: 0.0,
                slowest_benchmark: None,
                fastest_benchmark: None,
                total_memory_usage: None,
            };
        }

        let total_ops_per_sec: f64 = benchmarks.iter().map(|b| b.operations_per_second).sum();
        let avg_ops_per_sec = total_ops_per_sec / benchmarks.len() as f64;

        let slowest = benchmarks
            .iter()
            .min_by_key(|b| b.average_latency)
            .map(|b| (b.name.clone(), b.average_latency));

        let fastest = benchmarks
            .iter()
            .max_by(|a, b| a.operations_per_second.partial_cmp(&b.operations_per_second).unwrap_or(std::cmp::Ordering::Equal))
            .map(|b| (b.name.clone(), b.operations_per_second));

        PerformanceSummary {
            total_benchmarks: benchmarks.len(),
            average_ops_per_sec: avg_ops_per_sec,
            slowest_benchmark: slowest,
            fastest_benchmark: fastest,
            total_memory_usage: None,
        }
    }

    /// Set baseline results for comparison
    pub async fn set_baseline(&self, benchmarks: Vec<PerformanceBenchmark>) {
        let mut baseline_results = self.baseline_results.write().await;
        for benchmark in benchmarks {
            baseline_results.insert(benchmark.name.clone(), benchmark);
        }
    }
}

/// Performance comparison with baseline
#[derive(Debug, Clone)]
pub struct PerformanceComparison {
    pub benchmark_name: String,
    pub ops_per_sec_change: f64,
    pub avg_latency_change: f64,
    pub baseline_ops_per_sec: f64,
    pub current_ops_per_sec: f64,
    pub baseline_avg_latency: Duration,
    pub current_avg_latency: Duration,
}

/// Comprehensive performance report
#[derive(Debug, Clone)]
pub struct PerformanceReport {
    pub benchmarks: Vec<PerformanceBenchmark>,
    pub comparisons: HashMap<String, PerformanceComparison>,
    pub generated_at: std::time::SystemTime,
    pub summary: PerformanceSummary,
}

/// Performance summary statistics
#[derive(Debug, Clone)]
pub struct PerformanceSummary {
    pub total_benchmarks: usize,
    pub average_ops_per_sec: f64,
    pub slowest_benchmark: Option<(String, Duration)>,
    pub fastest_benchmark: Option<(String, f64)>,
    pub total_memory_usage: Option<u64>,
}

impl PerformanceReport {
    pub fn print_detailed_report(&self) {
        println!("=== Performance Test Report ===");
        println!("Generated at: {:?}", self.generated_at);
        println!("Total benchmarks: {}", self.benchmarks.len());
        println!();

        println!("=== Benchmark Results ===");
        for benchmark in &self.benchmarks {
            println!("Benchmark: {}", benchmark.name);
            println!("  Operations/sec: {:.2}", benchmark.operations_per_second);
            println!(
                "  Average latency: {:.2}ms",
                benchmark.average_latency.as_millis()
            );
            println!("  P50 latency: {:.2}ms", benchmark.p50_latency.as_millis());
            println!("  P95 latency: {:.2}ms", benchmark.p95_latency.as_millis());
            println!("  P99 latency: {:.2}ms", benchmark.p99_latency.as_millis());
            println!("  Total operations: {}", benchmark.total_operations);
            println!(
                "  Total duration: {:.2}s",
                benchmark.total_duration.as_secs_f64()
            );
            println!("  Metadata: {:?}", benchmark.metadata);
            println!();
        }

        if !self.comparisons.is_empty() {
            println!("=== Performance Comparison with Baseline ===");
            for comparison in self.comparisons.values() {
                println!("Benchmark: {}", comparison.benchmark_name);
                println!("  Ops/sec change: {:.2}%", comparison.ops_per_sec_change);
                println!("  Latency change: {:.2}%", comparison.avg_latency_change);
                println!("  Baseline ops/sec: {:.2}", comparison.baseline_ops_per_sec);
                println!("  Current ops/sec: {:.2}", comparison.current_ops_per_sec);
                println!(
                    "  Baseline latency: {:.2}ms",
                    comparison.baseline_avg_latency.as_millis()
                );
                println!(
                    "  Current latency: {:.2}ms",
                    comparison.current_avg_latency.as_millis()
                );
                println!();
            }
        }

        println!("=== Summary ===");
        println!("Total benchmarks: {}", self.summary.total_benchmarks);
        println!("Average ops/sec: {:.2}", self.summary.average_ops_per_sec);

        if let Some((name, latency)) = &self.summary.slowest_benchmark {
            println!(
                "Slowest benchmark: {} ({:.2}ms avg latency)",
                name,
                latency.as_millis()
            );
        }

        if let Some((name, ops_per_sec)) = &self.summary.fastest_benchmark {
            println!("Fastest benchmark: {} ({:.2} ops/sec)", name, ops_per_sec);
        }
    }
}

/// Memory profiling utilities
pub mod memory_profiling {
    use super::*;

    /// Track memory usage during benchmark
    pub async fn track_memory_usage<F, Fut, T>(f: F) -> (T, MemoryStats)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        // Get initial memory stats
        let initial_stats = get_memory_stats();

        let result = f().await;

        // Get final memory stats
        let final_stats = get_memory_stats();

        let memory_stats = MemoryStats {
            initial_rss: initial_stats.initial_rss,
            final_rss: final_stats.final_rss,
            peak_rss: final_stats.peak_rss,
            memory_growth: final_stats.memory_growth,
        };

        (result, memory_stats)
    }

    /// Get current memory statistics
    pub fn get_memory_stats() -> MemoryStats {
        // In a real implementation, this would read from /proc/self/statm or similar
        // For now, return placeholder values
        MemoryStats {
            initial_rss: 0,
            final_rss: 0,
            peak_rss: 0,
            memory_growth: 0,
        }
    }

    #[derive(Debug, Clone)]
    pub struct MemoryStats {
        pub initial_rss: u64,
        pub final_rss: u64,
        pub peak_rss: u64,
        pub memory_growth: u64,
    }
}

/// Load testing with performance monitoring
pub mod load_testing {
    use super::*;

    /// Comprehensive load test with performance monitoring
    pub async fn run_comprehensive_load_test(
        _suite: &PerformanceTestSuite,
        test_name: &str,
        concurrent_users: usize,
        duration_secs: u64,
    ) -> Result<LoadTestPerformanceReport, String> {
        info!("Starting comprehensive load test: {}", test_name);

        let start_time = Instant::now();
        let end_time = start_time + Duration::from_secs(duration_secs);

        let mut operation_count = 0;
        let mut total_latency = Duration::default();
        let mut latencies = Vec::new();

        // Run concurrent operations until time expires
        let handles: Vec<_> = (0..concurrent_users)
            .map(|user_id| {
                tokio::spawn(async move {
                    let mut local_operations = 0;
                    let mut local_latencies = Vec::new();
                    let mut local_total_latency = Duration::default();

                    while Instant::now() < end_time {
                        let op_start = Instant::now();

                        // Simulate authentication operation
                        simulate_auth_operation(user_id, local_operations).await;

                        let latency = op_start.elapsed();
                        local_latencies.push(latency);
                        local_total_latency += latency;
                        local_operations += 1;

                        // Small delay to prevent overwhelming the system
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }

                    (local_operations, local_latencies, local_total_latency)
                })
            })
            .collect();

        // Collect results
        for handle in handles {
            match handle.await {
                Ok((ops, lats, total_lat)) => {
                    operation_count += ops;
                    latencies.extend(lats);
                    total_latency += total_lat;
                }
                Err(e) => return Err(format!("Load test task failed: {}", e)),
            }
        }

        let actual_duration = start_time.elapsed();

        // Calculate percentiles
        latencies.sort();
        let p50_idx = (latencies.len() as f64 * 0.5) as usize;
        let p95_idx = (latencies.len() as f64 * 0.95) as usize;
        let p99_idx = (latencies.len() as f64 * 0.99) as usize;

        Ok(LoadTestPerformanceReport {
            test_name: test_name.to_string(),
            concurrent_users,
            total_operations: operation_count,
            operations_per_second: operation_count as f64 / actual_duration.as_secs_f64(),
            average_latency: if operation_count > 0 {
                total_latency / operation_count as u32
            } else {
                Duration::default()
            },
            p50_latency: latencies
                .get(p50_idx)
                .copied()
                .unwrap_or(Duration::default()),
            p95_latency: latencies
                .get(p95_idx)
                .copied()
                .unwrap_or(Duration::default()),
            p99_latency: latencies
                .get(p99_idx)
                .copied()
                .unwrap_or(Duration::default()),
            test_duration: actual_duration,
            requested_duration: Duration::from_secs(duration_secs),
        })
    }

    async fn simulate_auth_operation(_user_id: usize, operation_id: usize) {
        // Simulate various authentication operations
        match operation_id % 4 {
            0 => {
                // Token validation
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
            1 => {
                // User authentication
                tokio::time::sleep(Duration::from_micros(200)).await;
            }
            2 => {
                // Session validation
                tokio::time::sleep(Duration::from_micros(50)).await;
            }
            3 => {
                // Permission check
                tokio::time::sleep(Duration::from_micros(75)).await;
            }
            _ => unreachable!(),
        }
    }

    #[derive(Debug, Clone)]
    pub struct LoadTestPerformanceReport {
        pub test_name: String,
        pub concurrent_users: usize,
        pub total_operations: usize,
        pub operations_per_second: f64,
        pub average_latency: Duration,
        pub p50_latency: Duration,
        pub p95_latency: Duration,
        pub p99_latency: Duration,
        pub test_duration: Duration,
        pub requested_duration: Duration,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_test_suite() {
        let suite = PerformanceTestSuite::new();

        // Test token cache benchmark
        let config = TokenCacheConfig::default();
        let result = suite
            .benchmark_token_cache(
                "test_cache",
                config,
                2,  // concurrent users
                10, // operations per user
            )
            .await;

        assert!(result.is_ok(), "Token cache benchmark should succeed");

        let report = suite.generate_performance_report().await;
        assert_eq!(report.benchmarks.len(), 1);
        assert_eq!(report.benchmarks[0].name, "test_cache");
    }

    #[tokio::test]
    async fn test_session_store_benchmark() {
        let suite = PerformanceTestSuite::new();

        let result = suite
            .benchmark_session_store(
                "test_session",
                2,  // concurrent sessions
                10, // operations per session
            )
            .await;

        assert!(result.is_ok(), "Session store benchmark should succeed");

        let report = suite.generate_performance_report().await;
        assert!(!report.benchmarks.is_empty());
    }

    #[tokio::test]
    async fn test_load_comprehensive_test() {
        let suite = PerformanceTestSuite::new();

        let result = load_testing::run_comprehensive_load_test(
            &suite,
            "test_load",
            2, // concurrent users
            1, // duration in seconds
        )
        .await;

        assert!(result.is_ok(), "Load test should succeed");

        let report = result.unwrap();
        assert_eq!(report.test_name, "test_load");
        assert_eq!(report.concurrent_users, 2);
        assert!(report.total_operations > 0);
        assert!(report.operations_per_second > 0.0);
    }
}
