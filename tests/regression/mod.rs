//! Regression Test Module Configuration

pub mod auth_regression;
pub mod security_regression;
pub mod performance_regression;
pub mod database_regression;
pub mod api_regression;

/// Regression test configuration
pub struct RegressionConfig {
    pub performance_threshold_percent: f64,
    pub security_scan_timeout_seconds: u64,
    pub max_test_duration_seconds: u64,
}

impl Default for RegressionConfig {
    fn default() -> Self {
        Self {
            performance_threshold_percent: 10.0,
            security_scan_timeout_seconds: 300,
            max_test_duration_seconds: 600,
        }
    }
}

/// Test result tracking
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub message: Option<String>,
}

impl TestResult {
    pub fn new(name: String, passed: bool, duration_ms: u64) -> Self {
        Self {
            name,
            passed,
            duration_ms,
            message: None,
        }
    }
    
    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }
}
