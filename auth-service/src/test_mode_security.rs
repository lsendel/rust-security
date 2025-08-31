use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info, warn};

static TEST_MODE_ENABLED: std::sync::LazyLock<AtomicBool> = std::sync::LazyLock::new(|| {
    let enabled = is_test_mode_raw();
    if enabled {
        warn!("TEST_MODE is enabled - this should NEVER happen in production");

        // Log security implications
        warn!("TEST_MODE bypasses:");
        warn!("  - Client secret strength validation");
        warn!("  - Request signature validation");
        warn!("  - Client authentication for introspection");
        warn!("  - Rate limiting");
        warn!("  - Some SCIM authentication checks");
    }

    AtomicBool::new(enabled)
});

/// Counter for test mode usage tracking
static TEST_MODE_USAGE_COUNT: std::sync::LazyLock<std::sync::atomic::AtomicU64> =
    std::sync::LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));

/// Production safety check - prevents test mode in production environments
pub fn is_test_mode() -> bool {
    // First check if we're in production
    if is_production_environment() && is_test_mode_raw() {
        handle_production_violation();
        return false;
    }

    let enabled = TEST_MODE_ENABLED.load(Ordering::Relaxed);
    if enabled {
        track_test_mode_usage();
    }

    enabled
}

/// Handle test mode violation in production
fn handle_production_violation() {
    error!("CRITICAL SECURITY VIOLATION: TEST_MODE is enabled in production environment!");
    error!("This creates serious security vulnerabilities and MUST be disabled immediately");

    // Log to security audit trail
    audit_log_security_violation();
}

/// Track and log test mode usage
fn track_test_mode_usage() {
    // Track usage for monitoring
    TEST_MODE_USAGE_COUNT.fetch_add(1, Ordering::Relaxed);

    // Log each test mode usage for audit trail
    warn!(
        "Test mode bypass used (count: {})",
        TEST_MODE_USAGE_COUNT.load(Ordering::Relaxed)
    );
}

/// Raw check without production safeguards - for internal use only
fn is_test_mode_raw() -> bool {
    std::env::var("TEST_MODE").ok().as_deref() == Some("1")
}

/// Check if we're running in a production environment
fn is_production_environment() -> bool {
    // Check multiple common production environment indicators
    let rust_env = std::env::var("RUST_ENV").unwrap_or_default();
    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    let node_env = std::env::var("NODE_ENV").unwrap_or_default();

    rust_env == "production" ||
    environment == "production" ||
    app_env == "production" ||
    node_env == "production" ||
    // Also check for staging as production-like
    rust_env == "staging" ||
    environment == "staging" ||
    app_env == "staging"
}

/// Get comprehensive test mode status for monitoring
pub fn get_test_mode_status() -> TestModeStatus {
    TestModeStatus {
        test_mode_enabled: is_test_mode(),
        raw_test_mode_var: is_test_mode_raw(),
        is_production: is_production_environment(),
        usage_count: TEST_MODE_USAGE_COUNT.load(Ordering::Relaxed),
        security_violations: u64::from(is_production_environment() && is_test_mode_raw()),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TestModeStatus {
    pub test_mode_enabled: bool,
    pub raw_test_mode_var: bool,
    pub is_production: bool,
    pub usage_count: u64,
    pub security_violations: u64,
}

/// Force disable test mode (for emergency shutdown)
pub fn emergency_disable_test_mode() {
    warn!("Emergency test mode disable triggered");
    TEST_MODE_ENABLED.store(false, Ordering::SeqCst);
    std::env::remove_var("TEST_MODE");
}

/// Validate test mode is appropriate for current environment
///
/// # Errors
///
/// Returns a list of security issues found when test mode is inappropriately enabled
pub fn validate_test_mode_security() -> Result<(), Vec<String>> {
    let mut issues = Vec::new();

    // Check production environment
    if is_production_environment() && is_test_mode_raw() {
        issues.push("TEST_MODE is enabled in production environment".to_string());
    }

    // Check for long-running test mode (potential forgotten test environment)
    let usage_count = TEST_MODE_USAGE_COUNT.load(Ordering::Relaxed);
    if usage_count > 1000 {
        issues.push(format!(
            "Test mode has been used {usage_count} times - possible forgotten test environment"
        ));
    }

    // Check for test mode in CI/CD environments that should be production-like
    if std::env::var("CI").is_ok() && is_test_mode_raw() {
        let ci_env = std::env::var("CI_ENVIRONMENT_NAME").unwrap_or_default();
        if ci_env.contains("prod") || ci_env.contains("staging") {
            issues.push(format!("Test mode enabled in CI environment: {ci_env}"));
        }
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// Security audit logging for test mode violations
fn audit_log_security_violation() {
    // This would typically integrate with your security logging system
    error!("SECURITY_AUDIT: TEST_MODE_PRODUCTION_VIOLATION");
    error!(
        "Environment: RUST_ENV={}, ENVIRONMENT={}",
        std::env::var("RUST_ENV").unwrap_or_default(),
        std::env::var("ENVIRONMENT").unwrap_or_default()
    );
    error!("Process: PID={}", std::process::id());
    error!("Timestamp: {}", chrono::Utc::now().to_rfc3339());

    // Log to structured format for SIEM integration
    info!(
        target: "security_audit",
        event = "test_mode_production_violation",
        severity = "critical",
        pid = std::process::id(),
        timestamp = chrono::Utc::now().to_rfc3339(),
        "TEST_MODE enabled in production environment"
    );
}

/// Initialize test mode with security checks
pub fn initialize_test_mode_security() {
    info!("Initializing test mode security checks");

    // Force evaluation of test mode status
    let _enabled = TEST_MODE_ENABLED.load(Ordering::Relaxed);

    // Validate security posture
    if let Err(issues) = validate_test_mode_security() {
        for issue in issues {
            error!("Test mode security issue: {}", issue);
        }
    }

    info!("Test mode security initialization complete");
}

/// Conditional execution helper that respects production safety
pub fn if_test_mode<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R,
{
    if is_test_mode() {
        Some(f())
    } else {
        None
    }
}

/// Conditional execution with production override
pub fn if_test_mode_or_dev<F, R>(f: F) -> Option<R>
where
    F: FnOnce() -> R,
{
    if is_test_mode() || !is_production_environment() {
        Some(f())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_safety() {
        // Set production environment
        std::env::set_var("RUST_ENV", "production");
        std::env::set_var("TEST_MODE", "1");

        // Should return false despite TEST_MODE=1 due to production safety
        assert!(!is_test_mode());

        // Raw check should still see the variable
        assert!(is_test_mode_raw());

        // Cleanup
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_development_mode() {
        // Clear production env
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("ENVIRONMENT");

        // Set test mode
        std::env::set_var("TEST_MODE", "1");

        // Should work in development
        assert!(is_test_mode());

        // Cleanup
        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_security_validation() {
        // Test production violation detection
        std::env::set_var("RUST_ENV", "production");
        std::env::set_var("TEST_MODE", "1");

        let validation = validate_test_mode_security();
        assert!(validation.is_err());
        assert!(validation
            .unwrap_err()
            .iter()
            .any(|issue| issue.contains("production")));

        // Cleanup
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("TEST_MODE");
    }

    #[test]
    fn test_conditional_execution() {
        // Clear production env
        std::env::remove_var("RUST_ENV");
        std::env::set_var("TEST_MODE", "1");

        let result = if_test_mode(|| 42);
        assert_eq!(result, Some(42));

        std::env::remove_var("TEST_MODE");
        let result = if_test_mode(|| 42);
        assert_eq!(result, None);
    }
}
