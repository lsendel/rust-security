//! Test Categorization System
//!
//! Provides clear categorization and execution control for different types of tests:
//! - Unit tests: Fast, isolated component testing
//! - Integration tests: Component interaction testing
//! - End-to-end tests: Full system workflow testing

use std::collections::HashMap;
use std::time::Duration;

/// Test category enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestCategory {
    Unit,
    Integration,
    EndToEnd,
    Performance,
    Security,
    PropertyBased,
}

impl std::fmt::Display for TestCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestCategory::Unit => write!(f, "unit"),
            TestCategory::Integration => write!(f, "integration"),
            TestCategory::EndToEnd => write!(f, "e2e"),
            TestCategory::Performance => write!(f, "performance"),
            TestCategory::Security => write!(f, "security"),
            TestCategory::PropertyBased => write!(f, "property"),
        }
    }
}

/// Test metadata for categorization and execution control
#[derive(Debug, Clone)]
pub struct TestMetadata {
    pub category: TestCategory,
    pub timeout_seconds: u64,
    pub required_features: Vec<String>,
    pub description: String,
    pub tags: Vec<String>,
}

impl Default for TestMetadata {
    fn default() -> Self {
        Self {
            category: TestCategory::Unit,
            timeout_seconds: 30,
            required_features: Vec::new(),
            description: String::new(),
            tags: Vec::new(),
        }
    }
}

/// Test suite configuration
#[derive(Debug, Clone)]
pub struct TestSuiteConfig {
    pub enabled_categories: Vec<TestCategory>,
    pub timeout_multiplier: f64,
    pub parallel_execution: bool,
    pub fail_fast: bool,
    pub verbose_output: bool,
}

impl Default for TestSuiteConfig {
    fn default() -> Self {
        Self {
            enabled_categories: vec![
                TestCategory::Unit,
                TestCategory::Integration,
                TestCategory::Security,
            ],
            timeout_multiplier: 1.0,
            parallel_execution: true,
            fail_fast: false,
            verbose_output: false,
        }
    }
}

/// Test registry for managing categorized tests
pub struct TestRegistry {
    tests: HashMap<String, TestMetadata>,
    config: TestSuiteConfig,
}

impl Default for TestRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tests: HashMap::new(),
            config: TestSuiteConfig::default(),
        }
    }

    /// Register a test with metadata
    pub fn register(&mut self, name: impl Into<String>, metadata: TestMetadata) {
        self.tests.insert(name.into(), metadata);
    }

    /// Get test metadata
    #[must_use]
    pub fn get_metadata(&self, name: &str) -> Option<&TestMetadata> {
        self.tests.get(name)
    }

    /// Check if a test category is enabled
    #[must_use]
    pub fn is_category_enabled(&self, category: TestCategory) -> bool {
        self.config.enabled_categories.contains(&category)
    }

    /// Get all tests for a specific category
    #[must_use]
    pub fn tests_by_category(&self, category: TestCategory) -> Vec<(&String, &TestMetadata)> {
        self.tests
            .iter()
            .filter(|(_, metadata)| metadata.category == category)
            .collect()
    }

    /// Get execution timeout for a test
    #[must_use]
    pub fn get_timeout(&self, test_name: &str) -> u64 {
        if let Some(metadata) = self.tests.get(test_name) {
            (metadata.timeout_seconds as f64 * self.config.timeout_multiplier) as u64
        } else {
            (30.0 * self.config.timeout_multiplier) as u64
        }
    }

    /// Configure the test suite
    pub fn configure(&mut self, config: TestSuiteConfig) {
        self.config = config;
    }
}

/// Macros for easy test categorization
#[macro_export]
macro_rules! unit_test {
    ($test_name:ident, $($body:tt)*) => {
        #[test]
        #[cfg_attr(feature = "test-categories", test_category = "unit")]
        fn $test_name() {
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! integration_test {
    ($test_name:ident, $($body:tt)*) => {
        #[tokio::test]
        #[cfg_attr(feature = "test-categories", test_category = "integration")]
        fn $test_name() {
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! e2e_test {
    ($test_name:ident, $($body:tt)*) => {
        #[tokio::test]
        #[cfg_attr(feature = "test-categories", test_category = "e2e")]
        fn $test_name() {
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! security_test {
    ($test_name:ident, $($body:tt)*) => {
        #[tokio::test]
        #[cfg_attr(feature = "test-categories", test_category = "security")]
        fn $test_name() {
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! performance_test {
    ($test_name:ident, $($body:tt)*) => {
        #[tokio::test]
        #[cfg_attr(feature = "test-categories", test_category = "performance")]
        fn $test_name() {
            $($body)*
        }
    };
}

#[macro_export]
macro_rules! property_test {
    ($test_name:ident, $($body:tt)*) => {
        #[cfg(feature = "full-integration")]
        #[test]
        #[cfg_attr(feature = "test-categories", test_category = "property")]
        fn $test_name() {
            $($body)*
        }
    };
}

/// Test execution utilities
pub mod execution {
    use super::*;
    use std::time::{Duration, Instant};

    /// Execute tests by category with proper isolation
    pub async fn execute_category_tests(
        registry: &TestRegistry,
        category: TestCategory,
    ) -> TestExecutionResult {
        let start_time = Instant::now();
        let mut results = Vec::new();

        let category_tests = registry.tests_by_category(category);

        for (test_name, metadata) in category_tests {
            let test_start = Instant::now();
            let timeout = registry.get_timeout(test_name);

            // Execute test with timeout
            let result = tokio::time::timeout(
                Duration::from_secs(timeout),
                execute_single_test(test_name, metadata),
            )
            .await;

            let execution_time = test_start.elapsed();
            let test_result = match result {
                Ok(Ok(())) => TestResult::Passed,
                Ok(Err(e)) => TestResult::Failed(e),
                Err(_) => TestResult::TimedOut,
            };

            results.push(TestExecution {
                name: test_name.clone(),
                category,
                result: test_result,
                execution_time,
                timeout,
            });
        }

        let total_time = start_time.elapsed();
        TestExecutionResult {
            category,
            results,
            total_time,
        }
    }

    async fn execute_single_test(_test_name: &str, _metadata: &TestMetadata) -> Result<(), String> {
        // In a real implementation, this would dynamically execute the test
        // For now, this is a placeholder
        Ok(())
    }

    #[derive(Debug, Clone)]
    pub enum TestResult {
        Passed,
        Failed(String),
        TimedOut,
        Skipped(String),
    }

    #[derive(Debug, Clone)]
    pub struct TestExecution {
        pub name: String,
        pub category: TestCategory,
        pub result: TestResult,
        pub execution_time: Duration,
        pub timeout: u64,
    }

    #[derive(Debug)]
    pub struct TestExecutionResult {
        pub category: TestCategory,
        pub results: Vec<TestExecution>,
        pub total_time: Duration,
    }

    impl TestExecutionResult {
        #[must_use]
        pub fn passed_count(&self) -> usize {
            self.results
                .iter()
                .filter(|r| matches!(r.result, TestResult::Passed))
                .count()
        }

        #[must_use]
        pub fn failed_count(&self) -> usize {
            self.results
                .iter()
                .filter(|r| matches!(r.result, TestResult::Failed(_)))
                .count()
        }

        #[must_use]
        pub fn success_rate(&self) -> f64 {
            if self.results.is_empty() {
                0.0
            } else {
                (self.passed_count() as f64 / self.results.len() as f64) * 100.0
            }
        }
    }
}

/// Test environment utilities
pub mod environment {
    use super::*;

    /// Test environment configuration
    #[derive(Debug, Clone)]
    pub struct TestEnvironment {
        pub database_url: String,
        pub redis_url: String,
        pub external_api_url: String,
        pub test_timeout: Duration,
        pub cleanup_on_failure: bool,
    }

    impl Default for TestEnvironment {
        fn default() -> Self {
            Self {
                database_url: "sqlite::memory:".to_string(),
                redis_url: "redis://localhost:6379".to_string(),
                external_api_url: "http://localhost:8080".to_string(),
                test_timeout: Duration::from_secs(30),
                cleanup_on_failure: true,
            }
        }
    }

    /// Setup test environment based on category
    #[must_use]
    pub fn setup_environment(category: TestCategory) -> TestEnvironment {
        let mut env = TestEnvironment::default();

        match category {
            TestCategory::Unit => {
                // Minimal setup for unit tests
                env.database_url = "sqlite::memory:".to_string();
                env.test_timeout = Duration::from_secs(5);
            }
            TestCategory::Integration => {
                // Full setup for integration tests
                env.database_url = std::env::var("TEST_DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://test:test@localhost:5432/test_db".to_string());
                env.redis_url = std::env::var("TEST_REDIS_URL")
                    .unwrap_or_else(|_| "redis://localhost:6379".to_string());
                env.test_timeout = Duration::from_secs(60);
            }
            TestCategory::EndToEnd => {
                // Complete environment for e2e tests
                env.test_timeout = Duration::from_secs(300);
            }
            TestCategory::Performance => {
                // Optimized for performance testing
                env.database_url = std::env::var("PERF_DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://perf:perf@localhost:5433/perf_db".to_string());
                env.test_timeout = Duration::from_secs(600);
            }
            TestCategory::Security => {
                // Security-focused configuration
                env.test_timeout = Duration::from_secs(120);
                env.cleanup_on_failure = false; // Keep evidence for security analysis
            }
            TestCategory::PropertyBased => {
                // Configuration for property-based testing
                env.test_timeout = Duration::from_secs(180);
            }
        }

        env
    }

    /// Cleanup test environment
    pub async fn cleanup_environment(_env: &TestEnvironment) -> Result<(), String> {
        // Implementation would clean up test data, connections, etc.
        // For now, this is a placeholder
        Ok(())
    }
}

/// Test data isolation utilities
pub mod isolation {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

    /// Generate unique test identifier
    #[must_use]
    pub fn generate_test_id(prefix: &str) -> String {
        let id = TEST_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        format!("{prefix}_{id}")
    }

    /// Test isolation context
    pub struct TestIsolation {
        pub test_id: String,
        pub database_schema: Option<String>,
        pub redis_namespace: String,
        pub cleanup_actions: Vec<Box<dyn FnOnce() + Send + Sync>>,
    }

    impl TestIsolation {
        #[must_use]
        pub fn new(test_name: &str) -> Self {
            let test_id = generate_test_id(test_name);
            Self {
                test_id: test_id.clone(),
                database_schema: Some(format!("test_{test_id}")),
                redis_namespace: format!("test:{test_id}"),
                cleanup_actions: Vec::new(),
            }
        }

        /// Add cleanup action
        pub fn add_cleanup<F>(&mut self, cleanup: F)
        where
            F: FnOnce() + Send + Sync + 'static,
        {
            self.cleanup_actions.push(Box::new(cleanup));
        }

        /// Execute cleanup actions
        pub fn cleanup(&mut self) {
            while let Some(cleanup) = self.cleanup_actions.pop() {
                cleanup();
            }
        }
    }

    impl Drop for TestIsolation {
        fn drop(&mut self) {
            // Ensure cleanup runs even if not explicitly called
            while let Some(cleanup) = self.cleanup_actions.pop() {
                cleanup();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_registry() {
        let mut registry = TestRegistry::new();

        let metadata = TestMetadata {
            category: TestCategory::Unit,
            timeout_seconds: 60,
            description: "Test token validation".to_string(),
            ..Default::default()
        };

        registry.register("test_token_validation", metadata.clone());

        let retrieved = registry.get_metadata("test_token_validation").unwrap();
        assert_eq!(retrieved.category, TestCategory::Unit);
        assert_eq!(retrieved.timeout_seconds, 60);
    }

    #[test]
    fn test_category_filtering() {
        let mut registry = TestRegistry::new();

        registry.register(
            "unit_test",
            TestMetadata {
                category: TestCategory::Unit,
                ..Default::default()
            },
        );

        registry.register(
            "integration_test",
            TestMetadata {
                category: TestCategory::Integration,
                ..Default::default()
            },
        );

        let unit_tests = registry.tests_by_category(TestCategory::Unit);
        assert_eq!(unit_tests.len(), 1);

        let integration_tests = registry.tests_by_category(TestCategory::Integration);
        assert_eq!(integration_tests.len(), 1);
    }

    #[test]
    fn test_test_isolation() {
        let isolation = isolation::TestIsolation::new("test_example");

        assert!(isolation.test_id.starts_with("test_example_"));
        assert!(isolation
            .database_schema
            .as_ref()
            .unwrap()
            .starts_with("test_test_example_"));
        assert!(isolation.redis_namespace.starts_with("test:test_example_"));
    }

    #[test]
    fn test_environment_setup() {
        let unit_env = environment::setup_environment(TestCategory::Unit);
        assert_eq!(unit_env.database_url, "sqlite::memory:");
        assert_eq!(unit_env.test_timeout, Duration::from_secs(5));

        let perf_env = environment::setup_environment(TestCategory::Performance);
        assert_eq!(perf_env.test_timeout, Duration::from_secs(600));
    }
}
