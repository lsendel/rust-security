use anyhow::Result;
use axum::{extract::State, http::StatusCode, response::Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info};

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Service version
    pub version: String,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Individual component health
    pub components: HashMap<String, ComponentHealth>,
    /// Performance metrics
    pub metrics: HealthMetrics,
    /// Timestamp of the health check
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component status
    pub status: HealthStatus,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Last check timestamp
    pub last_check: u64,
    /// Error message if unhealthy
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Memory usage in MB
    pub memory_usage_mb: u64,
    /// CPU usage percentage (estimated)
    pub cpu_usage_percent: f64,
    /// Active connections
    pub active_connections: u32,
    /// Request rate (requests per second)
    pub request_rate: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
}

/// Health checker service
pub struct HealthChecker {
    start_time: Instant,
    components: Arc<RwLock<HashMap<String, ComponentHealth>>>,
    metrics: Arc<RwLock<HealthMetrics>>,
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthChecker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            components: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(HealthMetrics::default())),
        }
    }

    /// Perform comprehensive health check
    pub async fn check_health(&self) -> Result<HealthResponse> {
        let start = Instant::now();

        // Execute all health checks concurrently
        let (db_result, redis_result, external_result, system_result) = tokio::join!(
            self.check_database(),
            self.check_redis(),
            self.check_external_services(),
            self.check_system_resources()
        );

        // Collect results
        let mut component_results = Vec::new();
        component_results.push(db_result);
        component_results.push(redis_result);
        component_results.push(external_result);
        component_results.push(system_result);

        // Update component statuses
        let mut components = self.components.write().await;
        for (name, health) in component_results.into_iter().flatten() {
            components.insert(name, health);
        }

        // Determine overall status
        let overall_status = self.determine_overall_status(&components);

        // Get current metrics
        let metrics = self.metrics.read().await.clone();

        let response = HealthResponse {
            status: overall_status,
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
            components: components.clone(),
            metrics,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let check_duration = start.elapsed();
        info!(
            duration_ms = check_duration.as_millis(),
            status = ?response.status,
            "Health check completed"
        );

        Ok(response)
    }

    /// Check database connectivity
    async fn check_database(&self) -> Result<(String, ComponentHealth)> {
        let start = Instant::now();
        let mut metadata = HashMap::new();

        // Simulate database check (replace with actual database ping)
        let result = self.simulate_component_check("database", 0.95).await;

        let health = match result {
            Ok(()) => {
                metadata.insert("connection_pool".to_string(), "healthy".to_string());
                metadata.insert("active_connections".to_string(), "5".to_string());
                ComponentHealth {
                    status: HealthStatus::Healthy,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    last_check: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    error: None,
                    metadata,
                }
            }
            Err(e) => ComponentHealth {
                status: HealthStatus::Unhealthy,
                response_time_ms: start.elapsed().as_millis() as u64,
                last_check: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                error: Some(e.to_string()),
                metadata,
            },
        };

        Ok(("database".to_string(), health))
    }

    /// Check Redis connectivity
    async fn check_redis(&self) -> Result<(String, ComponentHealth)> {
        let start = Instant::now();
        let mut metadata = HashMap::new();

        // Simulate Redis check (replace with actual Redis ping)
        let result = self.simulate_component_check("redis", 0.98).await;

        let health = match result {
            Ok(()) => {
                metadata.insert("memory_usage".to_string(), "45%".to_string());
                metadata.insert("connected_clients".to_string(), "12".to_string());
                ComponentHealth {
                    status: HealthStatus::Healthy,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    last_check: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    error: None,
                    metadata,
                }
            }
            Err(e) => ComponentHealth {
                status: HealthStatus::Unhealthy,
                response_time_ms: start.elapsed().as_millis() as u64,
                last_check: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                error: Some(e.to_string()),
                metadata,
            },
        };

        Ok(("redis".to_string(), health))
    }

    /// Check external services
    async fn check_external_services(&self) -> Result<(String, ComponentHealth)> {
        let start = Instant::now();
        let mut metadata = HashMap::new();

        // Check external dependencies (OIDC providers, etc.)
        let result = self
            .simulate_component_check("external_services", 0.92)
            .await;

        let health = match result {
            Ok(()) => {
                metadata.insert("oidc_providers".to_string(), "2 healthy".to_string());
                metadata.insert("saml_providers".to_string(), "1 healthy".to_string());
                ComponentHealth {
                    status: HealthStatus::Healthy,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    last_check: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    error: None,
                    metadata,
                }
            }
            Err(e) => {
                ComponentHealth {
                    status: HealthStatus::Degraded, // External services can be degraded
                    response_time_ms: start.elapsed().as_millis() as u64,
                    last_check: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    error: Some(e.to_string()),
                    metadata,
                }
            }
        };

        Ok(("external_services".to_string(), health))
    }

    /// Check system resources
    async fn check_system_resources(&self) -> Result<(String, ComponentHealth)> {
        let start = Instant::now();
        let mut metadata = HashMap::new();

        // Get system metrics
        let memory_usage = self.get_memory_usage();
        let cpu_usage = self.get_cpu_usage();

        metadata.insert("memory_mb".to_string(), memory_usage.to_string());
        metadata.insert("cpu_percent".to_string(), format!("{cpu_usage:.1}"));

        let status = if memory_usage > 400.0 || cpu_usage > 80.0 {
            HealthStatus::Degraded
        } else if memory_usage > 500.0 || cpu_usage > 90.0 {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Healthy
        };

        let health = ComponentHealth {
            status,
            response_time_ms: start.elapsed().as_millis() as u64,
            last_check: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            error: None,
            metadata,
        };

        Ok(("system_resources".to_string(), health))
    }

    /// Simulate component check (replace with actual implementations)
    async fn simulate_component_check(&self, component: &str, success_rate: f64) -> Result<()> {
        // Add realistic delay
        tokio::time::sleep(Duration::from_millis(10 + rand::random::<u64>() % 50)).await;

        if rand::random::<f64>() < success_rate {
            Ok(())
        } else {
            Err(anyhow::anyhow!("{} check failed", component))
        }
    }

    /// Get memory usage (simplified)
    fn get_memory_usage(&self) -> f64 {
        // In a real implementation, you would use system APIs
        // This is a simulation
        rand::random::<f64>().mul_add(100.0, 150.0)
    }

    /// Get CPU usage (simplified)
    fn get_cpu_usage(&self) -> f64 {
        // In a real implementation, you would use system APIs
        // This is a simulation
        rand::random::<f64>().mul_add(30.0, 10.0)
    }

    /// Determine overall health status
    fn determine_overall_status(
        &self,
        components: &HashMap<String, ComponentHealth>,
    ) -> HealthStatus {
        let mut _healthy_count = 0;
        let mut degraded_count = 0;
        let mut unhealthy_count = 0;

        for health in components.values() {
            match health.status {
                HealthStatus::Healthy => _healthy_count += 1,
                HealthStatus::Degraded => degraded_count += 1,
                HealthStatus::Unhealthy => unhealthy_count += 1,
            }
        }

        // Determine overall status based on component health
        if unhealthy_count > 0 {
            // Any unhealthy critical component makes the service unhealthy
            if components.get("database").map(|h| &h.status) == Some(&HealthStatus::Unhealthy) {
                HealthStatus::Unhealthy
            } else if degraded_count > 0 || unhealthy_count > 0 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Healthy
            }
        } else if degraded_count > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    /// Update metrics
    pub async fn update_metrics(&self, metrics: HealthMetrics) {
        let mut current_metrics = self.metrics.write().await;
        *current_metrics = metrics;
    }
}

impl Default for HealthMetrics {
    fn default() -> Self {
        Self {
            memory_usage_mb: 0,
            cpu_usage_percent: 0.0,
            active_connections: 0,
            request_rate: 0.0,
            error_rate_percent: 0.0,
        }
    }
}

/// Health check handler for HTTP endpoint
pub async fn health_handler(
    State(health_checker): State<Arc<HealthChecker>>,
) -> Result<(StatusCode, Json<HealthResponse>), (StatusCode, String)> {
    match health_checker.check_health().await {
        Ok(response) => {
            let status_code = match response.status {
                HealthStatus::Healthy => StatusCode::OK,
                HealthStatus::Degraded => StatusCode::OK, // Still serving traffic
                HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
            };
            Ok((status_code, Json(response)))
        }
        Err(e) => {
            error!(error = %e, "Health check failed");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Health check failed: {e}"),
            ))
        }
    }
}

/// Readiness check handler (simpler check for Kubernetes)
pub async fn readiness_handler(
    State(health_checker): State<Arc<HealthChecker>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    // Quick readiness check - just verify critical components
    let components = health_checker.components.read().await;

    let database_healthy = components
        .get("database")
        .is_some_and(|h| matches!(h.status, HealthStatus::Healthy));

    if database_healthy {
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "ready",
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })),
        ))
    } else {
        Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Service not ready".to_string(),
        ))
    }
}

/// Liveness check handler (basic check for Kubernetes)
pub fn liveness_handler() -> (StatusCode, Json<serde_json::Value>) {
    // Simple liveness check - if we can respond, we're alive
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "alive",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let checker = HealthChecker::new();
        assert!(checker.start_time.elapsed().as_secs() < 1);
    }

    #[tokio::test]
    async fn test_health_check() {
        let checker = HealthChecker::new();
        let response = checker.check_health().await.unwrap();

        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
        assert!(response.uptime_seconds < 10); // Should be very recent
        assert!(!response.components.is_empty());
    }

    #[tokio::test]
    async fn test_component_checks() {
        let checker = HealthChecker::new();

        let (name, health) = checker.check_database().await.unwrap();
        assert_eq!(name, "database");
        assert!(health.response_time_ms < 1000);

        let (name, health) = checker.check_redis().await.unwrap();
        assert_eq!(name, "redis");
        assert!(health.response_time_ms < 1000);
    }

    #[tokio::test]
    async fn test_metrics_update() {
        let checker = HealthChecker::new();

        let metrics = HealthMetrics {
            memory_usage_mb: 256,
            cpu_usage_percent: 25.0,
            active_connections: 10,
            request_rate: 100.0,
            error_rate_percent: 0.1,
        };

        checker.update_metrics(metrics.clone()).await;

        let stored_metrics = checker.metrics.read().await;
        assert_eq!(stored_metrics.memory_usage_mb, 256);
        assert_eq!(stored_metrics.cpu_usage_percent, 25.0);
    }
}
