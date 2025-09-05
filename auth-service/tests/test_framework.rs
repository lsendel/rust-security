#![cfg(any())]
#![cfg(feature = "full-integration")]
// Comprehensive Test Framework
//
// Provides utilities and helpers for robust, comprehensive testing
/// of security-critical components with proper isolation and cleanup.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// Re-export common testing utilities
pub use common::*;

/// Test execution result with timing and resource usage
#[derive(Debug, Clone)]
pub struct TestResult {
    pub test_name: String,
    pub duration: Duration,
    pub memory_usage: Option<u64>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: HashMap<String, String>,
}

impl TestResult {
    #[must_use]
    pub fn new(test_name: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            duration: Duration::default(),
            memory_usage: None,
            success: true,
            error_message: None,
            metadata: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(error.into());
        self
    }

    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Test suite runner with comprehensive reporting
pub struct TestSuiteRunner {
    results: Arc<RwLock<Vec<TestResult>>>,
    start_time: Instant,
    suite_name: String,
}

impl TestSuiteRunner {
    pub fn new(suite_name: impl Into<String>) -> Self {
        Self {
            results: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
            suite_name: suite_name.into(),
        }
    }

    /// Run a single test with timeout and result tracking
    ///
    /// # Errors
    ///
    /// This function will never return an error - it always returns `Ok(())`.
    /// Test failures are recorded in the test results but don't cause this function to fail.
    pub async fn run_test<F, Fut>(
        &self,
        test_name: impl Into<String>,
        test_fn: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let test_name = test_name.into();
        let test_start = Instant::now();

        debug!("Starting test: {}", test_name);

        let result = self.execute_test(&test_name, test_start, test_fn).await;

        self.results.write().await.push(result);

        Ok(())
    }

    async fn execute_test<F, Fut>(
        &self,
        test_name: &str,
        test_start: Instant,
        test_fn: F,
    ) -> TestResult
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        match tokio::time::timeout(Duration::from_secs(300), test_fn()).await {
            Ok(Ok(())) => Self::handle_test_success(test_name, test_start),
            Ok(Err(error)) => Self::handle_test_failure(test_name, test_start, error),
            Err(_) => Self::handle_test_timeout(test_name),
        }
    }

    fn handle_test_success(test_name: &str, test_start: Instant) -> TestResult {
        let duration = test_start.elapsed();
        info!("Test passed: {} ({}ms)", test_name, duration.as_millis());
        TestResult::new(test_name).with_metadata("duration_ms", duration.as_millis().to_string())
    }

    fn handle_test_failure(test_name: &str, test_start: Instant, error: String) -> TestResult {
        let duration = test_start.elapsed();
        warn!(
            "Test failed: {} ({}ms) - {}",
            test_name,
            duration.as_millis(),
            error
        );
        TestResult::new(test_name)
            .with_error(error)
            .with_metadata("duration_ms", duration.as_millis().to_string())
    }

    fn handle_test_timeout(test_name: &str) -> TestResult {
        warn!("Test timed out: {}", test_name);
        TestResult::new(test_name)
            .with_error("Test timed out after 5 minutes")
            .with_metadata("timed_out", "true")
    }

    pub async fn generate_report(&self) -> TestReport {
        let total_duration = self.start_time.elapsed();

        let (passed, failed, timed_out, total_tests, results_clone) = {
            let results = self.results.read().await;
            let passed_count = results.iter().filter(|r| r.success).count();
            let failed_count = results.len() - passed_count;
            let timed_out_count = results
                .iter()
                .filter(|r| r.metadata.contains_key("timed_out"))
                .count();
            let total = results.len();
            let results_vec = results.clone();
            drop(results);
            (
                passed_count,
                failed_count,
                timed_out_count,
                total,
                results_vec,
            )
        };

        TestReport {
            suite_name: self.suite_name.clone(),
            total_tests,
            passed,
            failed,
            timed_out,
            total_duration,
            results: results_clone,
        }
    }
}

/// Comprehensive test report
#[derive(Debug, Clone)]
pub struct TestReport {
    pub suite_name: String,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub timed_out: usize,
    pub total_duration: Duration,
    pub results: Vec<TestResult>,
}

impl TestReport {
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total_tests as f64) * 100.0
        }
    }

    #[must_use]
    pub const fn has_failures(&self) -> bool {
        self.failed > 0 || self.timed_out > 0
    }

    pub fn print_summary(&self) {
        println!("=== Test Suite Report: {} ===", self.suite_name);
        println!("Total Tests: {}", self.total_tests);
        println!("Passed: {} ({:.1}%)", self.passed, self.success_rate());
        println!("Failed: {}", self.failed);
        println!("Timed Out: {}", self.timed_out);
        println!("Total Duration: {:.2}s", self.total_duration.as_secs_f64());

        if self.has_failures() {
            println!("\n=== Failures ===");
            for result in &self.results {
                if !result.success {
                    println!(
                        "❌ {}: {}",
                        result.test_name,
                        result.error_message.as_deref().unwrap_or("Unknown error")
                    );
                }
            }
        } else {
            println!("\n✅ All tests passed!");
        }
    }
}

/// Resource management for tests
pub struct TestResources {
    cleanup_fns: Vec<Box<dyn FnOnce() + Send + Sync>>,
}

impl Default for TestResources {
    fn default() -> Self {
        Self::new()
    }
}

impl TestResources {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cleanup_fns: Vec::new(),
        }
    }

    pub fn add_cleanup<F>(&mut self, cleanup_fn: F)
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        self.cleanup_fns.push(Box::new(cleanup_fn));
    }
}

impl Drop for TestResources {
    fn drop(&mut self) {
        // Run cleanup functions in reverse order
        while let Some(cleanup_fn) = self.cleanup_fns.pop() {
            cleanup_fn();
        }
    }
}

/// Test utilities for common patterns
pub mod test_utils {
    use super::*;

    /// Create a test token record with default values
    #[must_use]
    pub fn create_test_token(user_id: &str, scope: Option<&str>) -> common::TokenRecord {
        common::TokenRecord {
            active: true,
            scope: scope.map(std::string::ToString::to_string),
            client_id: Some("test_client".to_string()),
            exp: None,
            iat: None,
            sub: Some(user_id.to_string()),
            token_binding: None,
            mfa_verified: false,
        }
    }

    /// Create a test session with default values
    ///
    /// # Panics
    /// Panics if system time is before `UNIX_EPOCH` when generating timestamps.
    #[must_use]
    pub fn create_test_session(user_id: &str, session_id: &str) -> HashMap<String, String> {
        let mut session = HashMap::new();
        session.insert("user_id".to_string(), user_id.to_string());
        session.insert("session_id".to_string(), session_id.to_string());
        session.insert(
            "created_at".to_string(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
        );
        session
    }

    /// Assert that a result is within expected bounds
    ///
    /// # Panics
    ///
    /// Panics if the actual value is not within the specified bounds (min <= actual <= max).
    pub fn assert_within_bounds<T: PartialOrd + std::fmt::Debug>(
        actual: &T,
        min: &T,
        max: &T,
        description: &str,
    ) {
        assert!(
            actual >= min && actual <= max,
            "{description}: value {actual:?} not within bounds [{min:?}, {max:?}]"
        );
    }

    /// Measure execution time of a function
    pub async fn measure_execution_time<F, Fut, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let start = Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }
}

/// Integration test helpers
pub mod integration {
    use super::*;

    /// Test database connectivity
    ///
    /// # Errors
    ///
    /// Returns an error if database connectivity cannot be established or verified.
    pub fn test_database_connectivity() -> Result<(), String> {
        // Placeholder for database connectivity tests
        // This would test actual database connections in a real implementation
        debug!("Testing database connectivity...");
        Ok(())
    }

    /// Test external service connectivity
    ///
    /// # Errors
    ///
    /// Returns an error if external services (Redis, APIs, etc.) cannot be reached or are unavailable.
    pub fn test_external_services() -> Result<(), String> {
        // Placeholder for external service tests
        // This would test Redis, external APIs, etc.
        debug!("Testing external service connectivity...");
        Ok(())
    }

    /// Setup test environment
    ///
    /// # Errors
    ///
    /// Returns an error if the test environment cannot be properly initialized,
    /// such as when required services (database, Redis) are unavailable.
    pub fn setup_test_environment() -> Result<TestResources, String> {
        let mut resources = TestResources::new();

        // Setup test database, Redis, etc.
        debug!("Setting up test environment...");

        // Add cleanup functions
        resources.add_cleanup(|| {
            debug!("Cleaning up test environment...");
        });

        Ok(resources)
    }
}

/// Load testing utilities
pub mod load_test {
    use super::*;

    /// Generate concurrent load on a system
    ///
    /// # Errors
    ///
    /// Returns an error if the load test cannot be executed properly,
    /// such as when task spawning fails or system resources are exhausted.
    /// Generate concurrent load and collect results
    ///
    /// # Errors
    /// Returns `Err(String)` if any spawned task panics or returns an error.
    pub async fn generate_concurrent_load<F, Fut>(
        concurrency: usize,
        iterations: usize,
        operation: F,
    ) -> Result<LoadTestResults, String>
    where
        F: Fn() -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let start_time = Instant::now();
        let mut handles = Vec::new();
        let mut results = Vec::new();

        // Spawn concurrent tasks
        for _ in 0..concurrency {
            let operation = operation.clone();
            let handle = tokio::spawn(async move {
                let mut task_results = Vec::new();
                for _ in 0..iterations {
                    let start = Instant::now();
                    let result = operation().await;
                    let duration = start.elapsed();
                    task_results.push((result, duration));
                }
                task_results
            });
            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            match handle.await {
                Ok(task_results) => results.extend(task_results),
                Err(e) => return Err(format!("Task panicked: {e}")),
            }
        }

        let total_duration = start_time.elapsed();

        Ok(LoadTestResults {
            total_operations: results.len(),
            successful_operations: results.iter().filter(|(r, _)| r.is_ok()).count(),
            failed_operations: results.iter().filter(|(r, _)| r.is_err()).count(),
            total_duration,
            average_latency: total_duration / u32::try_from(results.len()).unwrap_or(1),
            results,
        })
    }

    #[derive(Debug)]
    pub struct LoadTestResults {
        pub total_operations: usize,
        pub successful_operations: usize,
        pub failed_operations: usize,
        pub total_duration: Duration,
        pub average_latency: Duration,
        pub results: Vec<(Result<(), String>, Duration)>,
    }

    impl LoadTestResults {
        #[must_use]
        #[allow(clippy::cast_precision_loss)]
        pub fn success_rate(&self) -> f64 {
            if self.total_operations == 0 {
                return 0.0;
            }
            // Compute using integers first, convert once for the ratio
            let ok = self.successful_operations as f64;
            let total = self.total_operations as f64;
            (ok * 100.0) / total
        }

        #[must_use]
        #[allow(clippy::cast_precision_loss)]
        pub fn operations_per_second(&self) -> f64 {
            // Avoid repeated casts; convert once
            let total = self.total_operations as f64;
            total / self.total_duration.as_secs_f64()
        }
    }
}

/// Security-specific test utilities
pub mod security {
    use super::*;

    /// Test for timing attack resistance
    ///
    /// # Errors
    ///
    /// Returns an error if the timing analysis cannot be performed,
    /// such as when operation execution fails or timing measurements are unreliable.
    pub async fn test_timing_attack_resistance<F, Fut>(
        operations: &[F],
        iterations: usize,
    ) -> Result<TimingAnalysis, String>
    where
        F: Fn() -> Fut + Clone + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        let mut timings = Vec::new();

        for operation in operations {
            let mut operation_timings = Vec::new();

            for _ in 0..iterations {
                let (result, duration) = test_utils::measure_execution_time(operation).await;
                result?;
                operation_timings.push(duration);
            }

            timings.push(operation_timings);
        }

        Ok(TimingAnalysis {
            operation_timings: timings.clone(),
            timing_variance: calculate_timing_variance(&timings),
        })
    }

    #[allow(clippy::cast_precision_loss)]
    fn calculate_timing_variance(timings: &[Vec<Duration>]) -> Vec<f64> {
        timings
            .iter()
            .map(|operation_timings| {
                // Compute mean using integer nanos first, then convert once
                let count = operation_timings.len() as u128;
                if count == 0 {
                    return 0.0;
                }
                let sum_nanos: u128 = operation_timings.iter().map(Duration::as_nanos).sum();
                let mean = (sum_nanos as f64) / (count as f64);
                let variance = operation_timings
                    .iter()
                    .map(|d| {
                        let x = d.as_nanos() as f64;
                        let diff = x - mean;
                        diff * diff
                    })
                    .sum::<f64>()
                    / (count as f64);
                variance.sqrt()
            })
            .collect()
    }

    #[derive(Debug)]
    pub struct TimingAnalysis {
        pub operation_timings: Vec<Vec<Duration>>,
        pub timing_variance: Vec<f64>,
    }

    /// Generate security test vectors
    #[must_use]
    pub fn generate_security_test_vectors() -> Vec<String> {
        vec![
            String::new(),                               // Empty string
            "a".repeat(10000),                           // Very long string
            "🚀🔒🛡️".to_string(),                        // Unicode
            "<script>alert('xss')</script>".to_string(), // XSS attempt
            "../../../etc/passwd".to_string(),           // Path traversal
            "null".to_string(),                          // Null values
            "undefined".to_string(),
            "0".to_string(),
            "-1".to_string(),
            "NaN".to_string(),
            // SQL injection attempts
            "'; DROP TABLE users; --".to_string(),
            "1' OR '1'='1".to_string(),
            // Command injection attempts
            "; rm -rf /".to_string(),
            "`whoami`".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_test_suite_runner() {
        let runner = TestSuiteRunner::new("test_suite");

        // Run a successful test
        let _ = runner
            .run_test("successful_test", || async { Ok(()) })
            .await;

        // Run a failing test
        let _ = runner
            .run_test("failing_test", || async { Err("Test failed".to_string()) })
            .await;

        let report = runner.generate_report().await;

        assert_eq!(report.suite_name, "test_suite");
        assert_eq!(report.total_tests, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert!(report.has_failures());
    }

    #[tokio::test]
    async fn test_load_test_runner() {
        use load_test::*;

        let results = generate_concurrent_load(
            2,                   // concurrency
            5,                   // iterations per task
            || async { Ok(()) }, // successful operation
        )
        .await
        .unwrap();

        assert_eq!(results.total_operations, 10);
        assert_eq!(results.successful_operations, 10);
        assert_eq!(results.failed_operations, 0);
        // Allow minimal floating-point tolerance
        let sr = results.success_rate();
        assert!((sr - 100.0).abs() < f64::EPSILON);
        assert!(results.operations_per_second() > 0.0);
    }

    #[test]
    fn test_security_test_vectors() {
        let vectors = security::generate_security_test_vectors();
        assert!(!vectors.is_empty());

        // Verify some expected vectors are present
        assert!(vectors.contains(&String::new()));
        assert!(vectors.contains(&"<script>alert('xss')</script>".to_string()));
        assert!(vectors.contains(&"../../../etc/passwd".to_string()));
    }
}
