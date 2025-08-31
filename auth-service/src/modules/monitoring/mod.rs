//! Monitoring Module
//!
//! This module handles system monitoring including metrics collection,
//! health checks, and performance monitoring.

pub mod metrics;
pub mod health;
pub mod performance;

// Re-export main types
pub use metrics::{MetricsCollector, MetricsMiddleware};
pub use health::{HealthChecker, HealthCheck, HealthStatus, HealthCheckResult, HealthStatusResponse, DatabaseHealthCheck, CacheHealthCheck, ExternalServiceHealthCheck, SystemResourceHealthCheck, DiskSpaceHealthCheck};
pub use performance::{PerformanceMonitor, PerformanceProfile, OperationMetrics, PerformanceSummary, PerformanceAlertManager, PerformanceAlert, PerformanceAlertType, AlertSeverity, PerformanceAlertConfig, PerformanceMonitoringMiddleware};
