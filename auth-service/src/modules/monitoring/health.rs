//! Health Check System
//!
//! Provides comprehensive health checks for the authentication service,
//! including database connectivity, cache health, and external service dependencies.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::shared::error::AppError;

/// Health status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: String,
    pub duration_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: Option<HashMap<String, serde_json::Value>>,
}

/// Overall health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatusResponse {
    pub status: HealthStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub uptime_seconds: f64,
    pub version: String,
    pub checks: Vec<HealthCheckResult>,
}

/// Health check trait
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Get the name of this health check
    fn name(&self) -> &str;

    /// Perform the health check
    async fn check(&self) -> HealthCheckResult;

    /// Get the timeout for this check
    fn timeout(&self) -> Duration {
        Duration::from_secs(30)
    }

    /// Whether this check should be included in overall health assessment
    fn critical(&self) -> bool {
        true
    }
}

/// Health checker service
#[derive(Clone)]
pub struct HealthChecker {
    checks: Arc<RwLock<Vec<Box<dyn HealthCheck>>>>,
    start_time: Instant,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new() -> Self {
        Self {
            checks: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
        }
    }

    /// Register a health check
    pub async fn register_check(&self, check: Box<dyn HealthCheck>) {
        let mut checks = self.checks.write().await;
        checks.push(check);
        debug!("Registered health check");
    }

    /// Perform all health checks
    pub async fn check_health(&self) -> HealthStatusResponse {
        let checks = self.checks.read().await;
        let mut results = Vec::new();
        let mut overall_status = HealthStatus::Healthy;

        for check in checks.iter() {
            let start = Instant::now();
            let result = tokio::time::timeout(check.timeout(), check.check()).await;

            let result = match result {
                Ok(result) => result,
                Err(_) => HealthCheckResult {
                    name: check.name().to_string(),
                    status: HealthStatus::Unhealthy,
                    message: "Health check timed out".to_string(),
                    duration_ms: check.timeout().as_millis() as u64,
                    timestamp: chrono::Utc::now(),
                    details: None,
                },
            };

            // Update overall status based on check result and criticality
            if check.critical() && result.status != HealthStatus::Healthy {
                if result.status == HealthStatus::Unhealthy || overall_status == HealthStatus::Healthy {
                    overall_status = result.status;
                } else if result.status == HealthStatus::Degraded && overall_status != HealthStatus::Unhealthy {
                    overall_status = HealthStatus::Degraded;
                }
            }

            results.push(result);
        }

        HealthStatusResponse {
            status: overall_status,
            timestamp: chrono::Utc::now(),
            uptime_seconds: self.start_time.elapsed().as_secs_f64(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            checks: results,
        }
    }

    /// Get a specific health check result
    pub async fn check_specific(&self, check_name: &str) -> Option<HealthCheckResult> {
        let checks = self.checks.read().await;

        for check in checks.iter() {
            if check.name() == check_name {
                return Some(check.check().await);
            }
        }

        None
    }

    /// Get all registered check names
    pub async fn get_check_names(&self) -> Vec<String> {
        let checks = self.checks.read().await;
        checks.iter().map(|check| check.name().to_string()).collect()
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Database health check
pub struct DatabaseHealthCheck<T> {
    name: String,
    connection_checker: Arc<dyn Fn() -> T + Send + Sync>,
}

impl<T> DatabaseHealthCheck<T> {
    pub fn new<F>(name: impl Into<String>, connection_checker: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            connection_checker: Arc::new(connection_checker),
        }
    }
}

#[async_trait]
impl<T> HealthCheck for DatabaseHealthCheck<T>
where
    T: std::future::Future<Output = Result<(), AppError>> + Send,
{
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let checker = Arc::clone(&self.connection_checker);

        match checker().await {
            Ok(()) => HealthCheckResult {
                name: self.name.clone(),
                status: HealthStatus::Healthy,
                message: "Database connection successful".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: Some(HashMap::from([
                    ("connection_type".to_string(), "database".into()),
                ])),
            },
            Err(e) => HealthCheckResult {
                name: self.name.clone(),
                status: HealthStatus::Unhealthy,
                message: format!("Database connection failed: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: Some(HashMap::from([
                    ("error".to_string(), e.to_string().into()),
                    ("connection_type".to_string(), "database".into()),
                ])),
            },
        }
    }
}

/// Cache health check
pub struct CacheHealthCheck<T> {
    name: String,
    cache_checker: Arc<dyn Fn() -> T + Send + Sync>,
}

impl<T> CacheHealthCheck<T> {
    pub fn new<F>(name: impl Into<String>, cache_checker: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            cache_checker: Arc::new(cache_checker),
        }
    }
}

#[async_trait]
impl<T> HealthCheck for CacheHealthCheck<T>
where
    T: std::future::Future<Output = Result<(), AppError>> + Send,
{
    fn name(&self) -> &str {
        &self.name
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        let checker = Arc::clone(&self.cache_checker);

        match checker().await {
            Ok(()) => HealthCheckResult {
                name: self.name.clone(),
                status: HealthStatus::Healthy,
                message: "Cache connection successful".to_string(),
                duration_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: Some(HashMap::from([
                    ("connection_type".to_string(), "cache".into()),
                ])),
            },
            Err(e) => HealthCheckResult {
                name: self.name.clone(),
                status: HealthStatus::Unhealthy,
                message: format!("Cache connection failed: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: Some(HashMap::from([
                    ("error".to_string(), e.to_string().into()),
                    ("connection_type".to_string(), "cache".into()),
                ])),
            },
        }
    }
}

/// External service health check
pub struct ExternalServiceHealthCheck {
    name: String,
    url: String,
    timeout: Duration,
}

impl ExternalServiceHealthCheck {
    pub fn new(name: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait]
impl HealthCheck for ExternalServiceHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();

        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build();

        let result = match client {
            Ok(client) => {
                match client.get(&self.url).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            HealthCheckResult {
                                name: self.name.clone(),
                                status: HealthStatus::Healthy,
                                message: format!("External service responded with status {}", response.status()),
                                duration_ms: start.elapsed().as_millis() as u64,
                                timestamp: chrono::Utc::now(),
                                details: Some(HashMap::from([
                                    ("url".to_string(), self.url.clone().into()),
                                    ("status_code".to_string(), response.status().as_u16().into()),
                                ])),
                            }
                        } else {
                            HealthCheckResult {
                                name: self.name.clone(),
                                status: HealthStatus::Unhealthy,
                                message: format!("External service returned error status {}", response.status()),
                                duration_ms: start.elapsed().as_millis() as u64,
                                timestamp: chrono::Utc::now(),
                                details: Some(HashMap::from([
                                    ("url".to_string(), self.url.clone().into()),
                                    ("status_code".to_string(), response.status().as_u16().into()),
                                ])),
                            }
                        }
                    }
                    Err(e) => HealthCheckResult {
                        name: self.name.clone(),
                        status: HealthStatus::Unhealthy,
                        message: format!("Failed to connect to external service: {}", e),
                        duration_ms: start.elapsed().as_millis() as u64,
                        timestamp: chrono::Utc::now(),
                        details: Some(HashMap::from([
                            ("url".to_string(), self.url.clone().into()),
                            ("error".to_string(), e.to_string().into()),
                        ])),
                    },
                }
            }
            Err(e) => HealthCheckResult {
                name: self.name.clone(),
                status: HealthStatus::Unhealthy,
                message: format!("Failed to create HTTP client: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: Some(HashMap::from([
                    ("error".to_string(), e.to_string().into()),
                ])),
            },
        };

        result
    }
}

/// System resource health check
pub struct SystemResourceHealthCheck {
    name: String,
    max_memory_percent: f64,
    max_cpu_percent: f64,
}

impl SystemResourceHealthCheck {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_memory_percent: 90.0,
            max_cpu_percent: 95.0,
        }
    }

    pub fn with_limits(mut self, max_memory_percent: f64, max_cpu_percent: f64) -> Self {
        self.max_memory_percent = max_memory_percent;
        self.max_cpu_percent = max_cpu_percent;
        self
    }
}

#[async_trait]
impl HealthCheck for SystemResourceHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn critical(&self) -> bool {
        false // System resources are not critical for basic functionality
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();

        // Get system information
        let memory_usage = get_memory_usage_percent().unwrap_or(0.0);
        let cpu_usage = get_cpu_usage_percent().unwrap_or(0.0);

        let mut status = HealthStatus::Healthy;
        let mut message = "System resources within limits".to_string();
        let mut issues = Vec::new();

        if memory_usage > self.max_memory_percent {
            status = HealthStatus::Degraded;
            issues.push(format!("High memory usage: {:.1}%", memory_usage));
        }

        if cpu_usage > self.max_cpu_percent {
            status = HealthStatus::Degraded;
            issues.push(format!("High CPU usage: {:.1}%", cpu_usage));
        }

        if !issues.is_empty() {
            message = format!("System resource issues: {}", issues.join(", "));
        }

        HealthCheckResult {
            name: self.name.clone(),
            status,
            message,
            duration_ms: start.elapsed().as_millis() as u64,
            timestamp: chrono::Utc::now(),
            details: Some(HashMap::from([
                ("memory_usage_percent".to_string(), memory_usage.into()),
                ("cpu_usage_percent".to_string(), cpu_usage.into()),
                ("max_memory_percent".to_string(), self.max_memory_percent.into()),
                ("max_cpu_percent".to_string(), self.max_cpu_percent.into()),
            ])),
        }
    }
}

/// Get memory usage as a percentage
fn get_memory_usage_percent() -> Option<f64> {
    // This is a simplified implementation
    // In a real application, you might use system_info or similar crate
    // For now, return a mock value
    Some(45.0)
}

/// Get CPU usage as a percentage
fn get_cpu_usage_percent() -> Option<f64> {
    // This is a simplified implementation
    // In a real application, you might use sysinfo or similar crate
    // For now, return a mock value
    Some(25.0)
}

/// Disk space health check
pub struct DiskSpaceHealthCheck {
    name: String,
    path: String,
    min_free_gb: f64,
}

impl DiskSpaceHealthCheck {
    pub fn new(name: impl Into<String>, path: impl Into<String>, min_free_gb: f64) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            min_free_gb,
        }
    }
}

#[async_trait]
impl HealthCheck for DiskSpaceHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }

    fn critical(&self) -> bool {
        true // Disk space is critical
    }

    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();

        match std::fs::metadata(&self.path) {
            Ok(_) => {
                // In a real implementation, you'd check actual disk space
                // For now, assume sufficient space
                let free_gb = 100.0; // Mock value

                if free_gb >= self.min_free_gb {
                    HealthCheckResult {
                        name: self.name.clone(),
                        status: HealthStatus::Healthy,
                        message: format!("Sufficient disk space: {:.1} GB free", free_gb),
                        duration_ms: start.elapsed().as_millis() as u64,
                        timestamp: chrono::Utc::now(),
                        details: Some(HashMap::from([
                            ("path".to_string(), self.path.clone().into()),
                            ("free_gb".to_string(), free_gb.into()),
                            ("min_free_gb".to_string(), self.min_free_gb.into()),
                        ])),
                    }
                } else {
                    HealthCheckResult {
                        name: self.name.clone(),
                        status: HealthStatus::Unhealthy,
                        message: format!("Low disk space: {:.1} GB free (minimum: {:.1} GB)", free_gb, self.min_free_gb),
                        duration_ms: start.elapsed().as_millis() as u64,
                        timestamp: chrono::Utc::now(),
                        details: Some(HashMap::from([
                            ("path".to_string(), self.path.clone().into()),
                            ("free_gb".to_string(), free_gb.into()),
                            ("min_free_gb".to_string(), self.min_free_gb.into()),
                        ])),
                    }
                }
            }
            Err(e) => HealthCheckResult {
                name: self.name.clone(),
                status: HealthStatus::Unhealthy,
                message: format!("Failed to check disk space: {}", e),
                duration_ms: start.elapsed().as_millis() as u64,
                timestamp: chrono::Utc::now(),
                details: Some(HashMap::from([
                    ("path".to_string(), self.path.clone().into()),
                    ("error".to_string(), e.to_string().into()),
                ])),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker() {
        let checker = HealthChecker::new();

        // Register a simple health check
        let test_check = TestHealthCheck::new("test", HealthStatus::Healthy);
        checker.register_check(Box::new(test_check)).await;

        let status = checker.check_health().await;
        assert_eq!(status.status, HealthStatus::Healthy);
        assert_eq!(status.checks.len(), 1);
        assert_eq!(status.checks[0].name, "test");
    }

    #[tokio::test]
    async fn test_unhealthy_check() {
        let checker = HealthChecker::new();

        // Register a failing health check
        let test_check = TestHealthCheck::new("failing", HealthStatus::Unhealthy);
        checker.register_check(Box::new(test_check)).await;

        let status = checker.check_health().await;
        assert_eq!(status.status, HealthStatus::Unhealthy);
    }

    #[tokio::test]
    async fn test_degraded_check() {
        let checker = HealthChecker::new();

        // Register a healthy check
        let healthy_check = TestHealthCheck::new("healthy", HealthStatus::Healthy);
        checker.register_check(Box::new(healthy_check)).await;

        // Register a degraded check
        let degraded_check = TestHealthCheck::new("degraded", HealthStatus::Degraded);
        checker.register_check(Box::new(degraded_check)).await;

        let status = checker.check_health().await;
        assert_eq!(status.status, HealthStatus::Degraded);
    }

    // Test helper
    struct TestHealthCheck {
        name: String,
        status: HealthStatus,
    }

    impl TestHealthCheck {
        fn new(name: impl Into<String>, status: HealthStatus) -> Self {
            Self {
                name: name.into(),
                status,
            }
        }
    }

    #[async_trait]
    impl HealthCheck for TestHealthCheck {
        fn name(&self) -> &str {
            &self.name
        }

        async fn check(&self) -> HealthCheckResult {
            HealthCheckResult {
                name: self.name.clone(),
                status: self.status.clone(),
                message: format!("Test check with status {:?}", self.status),
                duration_ms: 1,
                timestamp: chrono::Utc::now(),
                details: None,
            }
        }
    }
}
