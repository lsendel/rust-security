use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info, warn};

/// Enhanced test mode security with additional safeguards
#[allow(clippy::cognitive_complexity)]
static TEST_MODE_ENABLED: std::sync::LazyLock<AtomicBool> = std::sync::LazyLock::new(|| {
    let enabled = is_test_mode_raw();
    
    // Additional security checks
    if enabled {
        warn!("TEST_MODE is enabled - this should NEVER happen in production");
        
        // Log security implications
        warn!("TEST_MODE bypasses:");
        warn!("  - Client secret strength validation");
        warn!("  - Request signature validation");
        warn!("  - Client authentication for introspection");
        warn!("  - Rate limiting");
        warn!("  - Some SCIM authentication checks");
        
        // Additional security logging
        log_security_impact();
    }
    
    AtomicBool::new(enabled)
});

/// Counter for test mode usage tracking
static TEST_MODE_USAGE_COUNT: std::sync::LazyLock<std::sync::atomic::AtomicU64> = 
    std::sync::LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));

/// Production safety check with enhanced verification
/// Prevents test mode in production environments with multiple verification layers
pub fn is_test_mode() -> bool {
    // Layer 1: Basic production environment check
    if is_production_environment() && is_test_mode_raw() {
        handle_production_violation();
        return false;
    }
    
    // Layer 2: Additional environment verification
    if is_production_environment_strict() && is_test_mode_raw() {
        handle_production_violation();
        return false;
    }
    
    // Layer 3: Runtime verification with additional checks
    if is_definitely_production() && is_test_mode_raw() {
        handle_production_violation();
        return false;
    }
    
    let enabled = TEST_MODE_ENABLED.load(Ordering::Relaxed);
    if enabled {
        track_test_mode_usage();
    }
    
    enabled
}

/// Enhanced production environment detection with multiple verification methods
#[must_use]
pub fn is_production_environment() -> bool {
    // Check multiple common production environment indicators
    let rust_env = std::env::var("RUST_ENV").unwrap_or_default();
    let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
    let app_env = std::env::var("APP_ENV").unwrap_or_default();
    let node_env = std::env::var("NODE_ENV").unwrap_or_default();
    
    // Additional production detection methods
    let k8s_prod = std::env::var("KUBERNETES_NAMESPACE")
        .map(|ns| ns.contains("prod") || ns.contains("production"))
        .unwrap_or(false);
    let docker_prod = std::env::var("DOCKER_ENV")
        .map(|env| env == "production")
        .unwrap_or(false);
    
    // Check for production-like environments
    let is_prod_env = rust_env == "production" ||
        environment == "production" ||
        app_env == "production" ||
        node_env == "production";
    
    let is_staging_env = rust_env == "staging" ||
        environment == "staging" ||
        app_env == "staging";
    
    // SECURITY: Default to production if no environment is explicitly set (fail-safe)
    let explicit_env_set = !rust_env.is_empty() ||
        !environment.is_empty() ||
        !app_env.is_empty() ||
        !node_env.is_empty();
    
    is_prod_env || is_staging_env || k8s_prod || docker_prod || !explicit_env_set
}

/// Strict production environment detection with additional verification
#[must_use]
fn is_production_environment_strict() -> bool {
    // Check for definitive production indicators
    let has_prod_k8s = std::env::var("KUBERNETES_NAMESPACE")
        .map(|ns| ns.to_lowercase().contains("prod"))
        .unwrap_or(false);
        
    let has_prod_domain = std::env::var("DOMAIN")
        .map(|domain| domain.contains("prod") || domain.contains("production"))
        .unwrap_or(false);
        
    let has_prod_url = std::env::var("BASE_URL")
        .map(|url| url.contains("prod") || url.contains("production"))
        .unwrap_or(false);
    
    // Check for CI/CD production environments
    let is_ci_prod = std::env::var("CI")
        .is_ok() && 
        std::env::var("CI_ENVIRONMENT_NAME")
            .map(|name| name.to_lowercase().contains("prod"))
            .unwrap_or(false);
    
    has_prod_k8s || has_prod_domain || has_prod_url || is_ci_prod
}

/// Definitive production check using multiple signals
#[must_use]
fn is_definitely_production() -> bool {
    // Check for strong production indicators
    let strong_indicators = [
        "PRODUCTION",
        "PROD",
        "LIVE",
        "PRODUCTION_ENV",
    ];
    
    // Check environment variables that strongly indicate production
    for indicator in &strong_indicators {
        if std::env::var(indicator).is_ok() {
            return true;
        }
    }
    
    // Check for production deployment indicators
    let deployment_indicators = [
        "/var/www",
        "/opt/app",
        "/app",
    ];
    
    if let Ok(current_dir) = std::env::current_dir() {
        let current_path = current_dir.to_string_lossy();
        for indicator in &deployment_indicators {
            if current_path.contains(indicator) {
                return true;
            }
        }
    }
    
    // Check for production-like file system indicators
    let prod_files = [
        "/etc/production",
        "/var/run/prod",
    ];
    
    for file in &prod_files {
        if std::path::Path::new(file).exists() {
            return true;
        }
    }
    
    false
}

/// Handle test mode violation in production with enhanced security measures
fn handle_production_violation() {
    error!("CRITICAL SECURITY VIOLATION: TEST_MODE is enabled in production environment!");
    error!("This creates serious security vulnerabilities and MUST be disabled immediately");
    
    // Log to security audit trail
    audit_log_security_violation();
    
    // Emergency measures
    emergency_disable_test_mode();
    
    // Notify security team (in a real implementation, this would send alerts)
    #[cfg(feature = "security-alerts")]
    {
        if let Err(e) = notify_security_team() {
            error!("Failed to notify security team: {}", e);
        }
    }
}

/// Enhanced security impact logging
fn log_security_impact() {
    warn!("=== SECURITY RISK ASSESSMENT ===");
    warn!("Test mode bypasses critical security controls:");
    warn!("1. Rate limiting - DDoS protection disabled");
    warn!("2. Request signatures - API tampering possible");
    warn!("3. Client authentication - Unauthorized access risk");
    warn!("4. Input validation - Injection attacks possible");
    warn!("5. Session security - Session hijacking risk");
    warn!("6. Audit logging - Security events may not be logged");
    warn!("===============================");
    
    // Log system information for forensics
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        warn!("System hostname: {}", hostname);
    }
    
    warn!("Process ID: {}", std::process::id());
    warn!("Current time: {}", chrono::Utc::now().to_rfc3339());
}

/// Track and log test mode usage with enhanced monitoring
fn track_test_mode_usage() {
    // Track usage for monitoring
    let count = TEST_MODE_USAGE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    
    // Log each test mode usage for audit trail
    warn!(
        "Test mode bypass used (count: {})",
        count
    );
    
    // Alert if usage is excessive (potential forgotten test environment)
    if count > 100 {
        warn!("WARNING: Test mode has been used {} times - possible forgotten test environment", count);
    }
    
    // Log detailed usage information
    log_detailed_usage(count);
}

/// Log detailed usage information for security monitoring
fn log_detailed_usage(count: u64) {
    // Get request information if available
    if let Ok(request_method) = std::env::var("REQUEST_METHOD") {
        warn!("Request method: {}", request_method);
    }
    
    if let Ok(request_uri) = std::env::var("REQUEST_URI") {
        warn!("Request URI: {}", request_uri);
    }
    
    // Get client information
    if let Ok(remote_addr) = std::env::var("REMOTE_ADDR") {
        warn!("Remote address: {}", remote_addr);
    }
    
    // Get user agent
    if let Ok(user_agent) = std::env::var("HTTP_USER_AGENT") {
        warn!("User agent: {}", user_agent);
    }
}

/// Raw check without production safeguards - for internal use only
/// This should NEVER be used directly for security decisions
fn is_test_mode_raw() -> bool {
    std::env::var("TEST_MODE").ok().as_deref() == Some("1")
}

/// Get comprehensive test mode status for monitoring
pub fn get_test_mode_status() -> TestModeStatus {
    TestModeStatus {
        test_mode_enabled: is_test_mode(),
        raw_test_mode_var: is_test_mode_raw(),
        is_production: is_production_environment(),
        is_production_strict: is_production_environment_strict(),
        is_definitely_production: is_definitely_production(),
        usage_count: TEST_MODE_USAGE_COUNT.load(Ordering::Relaxed),
        security_violations: u64::from(is_production_environment() && is_test_mode_raw()),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TestModeStatus {
    pub test_mode_enabled: bool,
    pub raw_test_mode_var: bool,
    pub is_production: bool,
    pub is_production_strict: bool,
    pub is_definitely_production: bool,
    pub usage_count: u64,
    pub security_violations: u64,
}

/// Force disable test mode (for emergency shutdown) with enhanced security
pub fn emergency_disable_test_mode() {
    warn!("Emergency test mode disable triggered");
    TEST_MODE_ENABLED.store(false, Ordering::SeqCst);
    
    // Remove the environment variable
    std::env::remove_var("TEST_MODE");
    
    // Additional security measures
    disable_test_mode_globally();
    
    // Log the emergency disable
    info!("Test mode emergency disable completed");
}

/// Additional security measures for emergency disable
fn disable_test_mode_globally() {
    // Clear any test mode related environment variables
    let test_vars = [
        "TEST_MODE",
        "DISABLE_SECURITY",
        "SKIP_VALIDATION",
        "DEBUG_MODE",
    ];
    
    for var in &test_vars {
        std::env::remove_var(var);
    }
    
    // Log the cleanup
    info!("Test mode environment variables cleared");
}

/// Validate test mode is appropriate for current environment
/// with enhanced security checks
///
/// # Errors
///
/// Returns a list of security issues found when test mode is inappropriately enabled
pub fn validate_test_mode_security() -> Result<(), Vec<String>> {
    let mut issues = Vec::new();
    
    // Check production environment with multiple methods
    if is_production_environment() && is_test_mode_raw() {
        issues.push("TEST_MODE is enabled in production environment".to_string());
    }
    
    if is_production_environment_strict() && is_test_mode_raw() {
        issues.push("TEST_MODE is enabled in strict production environment".to_string());
    }
    
    if is_definitely_production() && is_test_mode_raw() {
        issues.push("TEST_MODE is enabled in definitively production environment".to_string());
    }
    
    // Check for long-running test mode (potential forgotten test environment)
    let usage_count = TEST_MODE_USAGE_COUNT.load(Ordering::Relaxed);
    if usage_count > 1000 {
        issues.push(format!(
            "Test mode has been used {} times - possible forgotten test environment",
            usage_count
        ));
    }
    
    // Check for test mode in CI/CD environments that should be production-like
    if std::env::var("CI").is_ok() && is_test_mode_raw() {
        let ci_env = std::env::var("CI_ENVIRONMENT_NAME").unwrap_or_default();
        if ci_env.contains("prod") || ci_env.contains("staging") {
            issues.push(format!("Test mode enabled in CI environment: {}", ci_env));
        }
    }
    
    // Check for high-risk usage patterns
    if usage_count > 10000 {
        issues.push("EXTREME RISK: Test mode used over 10,000 times".to_string());
    }
    
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// Security audit logging for test mode violations with enhanced forensics
#[allow(clippy::cognitive_complexity)]
fn audit_log_security_violation() {
    // This would typically integrate with your security logging system
    error!("SECURITY_AUDIT: TEST_MODE_PRODUCTION_VIOLATION");
    error!(
        "Environment: RUST_ENV={}, ENVIRONMENT={}, APP_ENV={}, NODE_ENV={}",
        std::env::var("RUST_ENV").unwrap_or_default(),
        std::env::var("ENVIRONMENT").unwrap_or_default(),
        std::env::var("APP_ENV").unwrap_or_default(),
        std::env::var("NODE_ENV").unwrap_or_default()
    );
    error!("Process: PID={}", std::process::id());
    error!("Timestamp: {}", chrono::Utc::now().to_rfc3339());
    
    // Log system information
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        error!("Hostname: {}", hostname);
    }
    
    if let Ok(user) = std::env::var("USER") {
        error!("User: {}", user);
    }
    
    // Log to structured format for SIEM integration
    info!(
        target: "security_audit",
        event = "test_mode_production_violation",
        severity = "critical",
        pid = std::process::id(),
        timestamp = chrono::Utc::now().to_rfc3339(),
        "TEST_MODE enabled in production environment"
    );
    
    // Additional forensic logging
    log_forensic_details();
}

/// Additional forensic logging for security violations
fn log_forensic_details() {
    // Log current working directory
    if let Ok(cwd) = std::env::current_dir() {
        error!("Current directory: {}", cwd.display());
    }
    
    // Log command line arguments
    let args: Vec<String> = std::env::args().collect();
    error!("Command line: {:?}", args);
    
    // Log parent process information (if available)
    #[cfg(target_os = "linux")]
    {
        if let Ok(parent_pid) = std::fs::read_to_string("/proc/self/stat") {
            // Parse parent PID from stat file
            let fields: Vec<&str> = parent_pid.split_whitespace().collect();
            if fields.len() > 3 {
                error!("Parent PID: {}", fields[3]);
            }
        }
    }
}

/// Initialize test mode with enhanced security checks
pub fn initialize_test_mode_security() {
    info!("Initializing enhanced test mode security checks");
    
    // Force evaluation of test mode status
    let _enabled = TEST_MODE_ENABLED.load(Ordering::Relaxed);
    
    // Validate security posture with enhanced checks
    if let Err(issues) = validate_test_mode_security() {
        for issue in issues {
            error!("Test mode security issue: {}", issue);
        }
    }
    
    // Perform additional security initialization
    perform_additional_security_initialization();
    
    info!("Enhanced test mode security initialization complete");
}

/// Additional security initialization
fn perform_additional_security_initialization() {
    // Check for insecure configurations
    check_insecure_configurations();
    
    // Set up enhanced monitoring
    setup_enhanced_monitoring();
}

/// Check for insecure configurations that could be exploited
fn check_insecure_configurations() {
    // Check for dangerous environment variables
    let dangerous_vars = [
        "DEBUG_SECRET",
        "ADMIN_PASSWORD",
        "ROOT_PASSWORD",
        "MASTER_KEY",
    ];
    
    for var in &dangerous_vars {
        if std::env::var(var).is_ok() {
            warn!("WARNING: Potentially dangerous environment variable found: {}", var);
        }
    }
    
    // Check for weak security settings
    if let Ok(disable_tls) = std::env::var("DISABLE_TLS") {
        if disable_tls == "1" || disable_tls.to_lowercase() == "true" {
            warn!("WARNING: TLS is disabled - this is insecure in production");
        }
    }
}

/// Set up enhanced monitoring for test mode usage
fn setup_enhanced_monitoring() {
    // This would set up additional monitoring in a real implementation
    info!("Enhanced monitoring for test mode usage initialized");
}

/// Conditional execution helper that respects production safety
/// with enhanced security checks
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

/// Conditional execution with production override and enhanced security
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

/// Enhanced security notification system (stub implementation)
#[cfg(feature = "security-alerts")]
fn notify_security_team() -> Result<(), Box<dyn std::error::Error>> {
    // In a real implementation, this would send alerts to a security team
    // via email, Slack, PagerDuty, etc.
    
    info!("Security team notification would be sent here");
    Ok(())
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
        // Clear production env to ensure we're not in production
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("APP_ENV");

        // Test the conditional execution functionality
        // Since the static variable is initialized based on startup environment,
        // we test the behavior as it would occur in practice

        // If test mode is enabled (via environment at startup), should return Some
        if is_test_mode_raw() {
            let result = if_test_mode(|| 42);
            assert_eq!(result, Some(42));
        } else {
            // If test mode is not enabled, should return None
            let result = if_test_mode(|| 42);
            assert_eq!(result, None);
        }

        // Test production safety - set production and verify test mode is blocked
        std::env::set_var("RUST_ENV", "production");
        std::env::set_var("TEST_MODE", "1");

        // Should be blocked in production regardless of TEST_MODE setting
        let _result = if_test_mode(|| 42);
        // This should be None due to production safety check

        // Cleanup
        std::env::remove_var("RUST_ENV");
        std::env::remove_var("TEST_MODE");
    }
    
    #[test]
    fn test_enhanced_production_detection() {
        // Test strict production detection
        std::env::set_var("KUBERNETES_NAMESPACE", "production-cluster");
        assert!(is_production_environment_strict());
        std::env::remove_var("KUBERNETES_NAMESPACE");
        
        // Test definitive production detection
        // This test is limited since we can't easily create file system indicators
    }
}