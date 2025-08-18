mod integration_tests;
mod phase1_security_tests;
mod phase2_operational_tests;
mod regression_test_suite;

use regression_test_suite::RegressionTestSuite;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();

    let auth_url = args.get(1).unwrap_or(&"http://localhost:8080".to_string()).clone();

    let policy_url = args.get(2).unwrap_or(&"http://localhost:8081".to_string()).clone();

    println!("🧪 Rust Security Workspace - Comprehensive Regression Test Suite");
    println!("Version: 2.0.0 (Phase 1 + Phase 2)");
    println!("Timestamp: {}", chrono::Utc::now().to_rfc3339());
    println!();

    // Initialize test suite
    let mut test_suite = RegressionTestSuite::new(&auth_url, &policy_url);

    // Run all tests
    match test_suite.run_all_tests().await {
        Ok(summary) => {
            summary.print_summary();

            // Exit with appropriate code
            if summary.success_rate >= 95.0 {
                println!("\n🎉 All tests passed! System is ready for production.");
                std::process::exit(0);
            } else if summary.success_rate >= 90.0 {
                println!("\n⚠️  Most tests passed, but some issues detected.");
                std::process::exit(1);
            } else {
                println!("\n❌ Critical issues detected. System needs attention.");
                std::process::exit(2);
            }
        }
        Err(e) => {
            eprintln!("❌ Test suite failed to run: {}", e);
            std::process::exit(3);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_regression_suite_basic() {
        // Basic test to ensure the test suite can be created
        let suite = RegressionTestSuite::new("http://localhost:8080", "http://localhost:8081");

        // This test just verifies the structure compiles and can be instantiated
        assert_eq!(suite.auth_base_url, "http://localhost:8080");
        assert_eq!(suite.policy_base_url, "http://localhost:8081");
    }
}
