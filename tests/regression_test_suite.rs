use std::time::Duration;
use tokio::time::timeout;
use serde_json::{json, Value};
use reqwest::Client;
use std::collections::HashMap;

/// Comprehensive regression test suite for Rust Security Workspace
/// Tests all Phase 1 and Phase 2 features end-to-end
pub struct RegressionTestSuite {
    pub auth_base_url: String,
    pub policy_base_url: String,
    pub client: Client,
    pub test_results: HashMap<String, TestResult>,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration: Duration,
    pub error: Option<String>,
    pub details: Option<Value>,
}

impl RegressionTestSuite {
    pub fn new(auth_url: &str, policy_url: &str) -> Self {
        Self {
            auth_base_url: auth_url.to_string(),
            policy_base_url: policy_url.to_string(),
            client: Client::new(),
            test_results: HashMap::new(),
        }
    }

    /// Run all regression tests
    pub async fn run_all_tests(&mut self) -> Result<TestSummary, Box<dyn std::error::Error>> {
        println!("🚀 Starting Comprehensive Regression Test Suite");
        println!("Auth Service: {}", self.auth_base_url);
        println!("Policy Service: {}", self.policy_base_url);
        println!("{}", "=".repeat(80));

        // Phase 1 Tests - Critical Security Features
        self.test_health_endpoints().await;
        self.test_oauth_token_flow().await;
        self.test_token_introspection().await;
        self.test_token_revocation().await;
        self.test_openid_connect().await;
        self.test_jwks_endpoint().await;
        self.test_mfa_totp().await;
        self.test_scim_endpoints().await;
        self.test_rate_limiting().await;
        self.test_security_headers().await;
        self.test_request_signing().await;
        self.test_token_binding().await;
        self.test_pkce_flow().await;
        self.test_circuit_breaker().await;
        self.test_input_validation().await;
        self.test_audit_logging().await;

        // Phase 2 Tests - Operational Excellence
        self.test_performance_metrics().await;
        self.test_caching_functionality().await;
        self.test_distributed_tracing().await;
        self.test_monitoring_endpoints().await;
        self.test_key_rotation().await;

        // Policy Service Tests
        self.test_policy_evaluation().await;
        self.test_cedar_policies().await;
        self.test_policy_performance().await;

        // Integration Tests
        self.test_end_to_end_flow().await;
        self.test_concurrent_operations().await;
        self.test_error_handling().await;
        self.test_failover_scenarios().await;

        Ok(self.generate_summary())
    }

    pub async fn run_test<F, Fut>(&mut self, test_name: &str, test_fn: F)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>>>,
    {
        let start_time = std::time::Instant::now();
        print!("  {} ... ", test_name);

        match timeout(Duration::from_secs(30), test_fn()).await {
            Ok(Ok(details)) => {
                let duration = start_time.elapsed();
                println!("✅ PASS ({:.2}s)", duration.as_secs_f64());
                self.test_results.insert(test_name.to_string(), TestResult {
                    name: test_name.to_string(),
                    passed: true,
                    duration,
                    error: None,
                    details,
                });
            }
            Ok(Err(e)) => {
                let duration = start_time.elapsed();
                println!("❌ FAIL ({:.2}s): {}", duration.as_secs_f64(), e);
                self.test_results.insert(test_name.to_string(), TestResult {
                    name: test_name.to_string(),
                    passed: false,
                    duration,
                    error: Some(e.to_string()),
                    details: None,
                });
            }
            Err(_) => {
                let duration = start_time.elapsed();
                println!("⏰ TIMEOUT ({:.2}s)", duration.as_secs_f64());
                self.test_results.insert(test_name.to_string(), TestResult {
                    name: test_name.to_string(),
                    passed: false,
                    duration,
                    error: Some("Test timed out after 30 seconds".to_string()),
                    details: None,
                });
            }
        }
    }

    fn generate_summary(&self) -> TestSummary {
        let total_tests = self.test_results.len();
        let passed_tests = self.test_results.values().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;

        let total_duration: Duration = self.test_results.values()
            .map(|r| r.duration)
            .sum();

        let failed_test_names: Vec<String> = self.test_results.values()
            .filter(|r| !r.passed)
            .map(|r| r.name.clone())
            .collect();

        TestSummary {
            total_tests,
            passed_tests,
            failed_tests,
            total_duration,
            failed_test_names,
            success_rate: (passed_tests as f64 / total_tests as f64) * 100.0,
        }
    }
}

#[derive(Debug)]
pub struct TestSummary {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub total_duration: Duration,
    pub failed_test_names: Vec<String>,
    pub success_rate: f64,
}

impl TestSummary {
    pub fn print_summary(&self) {
        println!("\n{}", "=".repeat(80));
        println!("🧪 REGRESSION TEST SUMMARY");
        println!("{}", "=".repeat(80));
        println!("Total Tests:    {}", self.total_tests);
        println!("Passed:         {} ✅", self.passed_tests);
        println!("Failed:         {} ❌", self.failed_tests);
        println!("Success Rate:   {:.1}%", self.success_rate);
        println!("Total Duration: {:.2}s", self.total_duration.as_secs_f64());

        if !self.failed_test_names.is_empty() {
            println!("\n❌ Failed Tests:");
            for test_name in &self.failed_test_names {
                println!("  - {}", test_name);
            }
        }

        println!("\n🎯 Overall Status: {}",
            if self.success_rate >= 95.0 { "✅ EXCELLENT" }
            else if self.success_rate >= 90.0 { "⚠️  GOOD" }
            else if self.success_rate >= 80.0 { "⚠️  NEEDS ATTENTION" }
            else { "❌ CRITICAL ISSUES" }
        );
        println!("{}", "=".repeat(80));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regression_suite_creation() {
        let suite = RegressionTestSuite::new("http://localhost:8080", "http://localhost:8081");
        assert_eq!(suite.auth_base_url, "http://localhost:8080");
        assert_eq!(suite.policy_base_url, "http://localhost:8081");
        assert_eq!(suite.test_results.len(), 0);
    }

    #[test]
    fn test_summary_calculation() {
        let mut suite = RegressionTestSuite::new("http://localhost:8080", "http://localhost:8081");

        // Add some mock test results
        suite.test_results.insert("test1".to_string(), TestResult {
            name: "test1".to_string(),
            passed: true,
            duration: Duration::from_millis(100),
            error: None,
            details: None,
        });

        suite.test_results.insert("test2".to_string(), TestResult {
            name: "test2".to_string(),
            passed: false,
            duration: Duration::from_millis(200),
            error: Some("Test failed".to_string()),
            details: None,
        });

        let summary = suite.generate_summary();
        assert_eq!(summary.total_tests, 2);
        assert_eq!(summary.passed_tests, 1);
        assert_eq!(summary.failed_tests, 1);
        assert_eq!(summary.success_rate, 50.0);
    }
}
