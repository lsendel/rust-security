//! Monitoring and Observability Infrastructure
//!
//! Provides monitoring, tracing, and performance monitoring capabilities.

pub mod observability;
pub mod observability_init;
pub mod tracing_config;
// pub mod tracing_instrumentation;  // Temporarily disabled due to missing observability module
pub mod metrics;
pub mod non_human_monitoring;
pub mod performance_monitoring;
pub mod security_logging_enhanced;
pub mod security_metrics;

// Re-export with expected name
pub mod security_logging {
    pub use super::security_logging_enhanced::*;
}

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Metrics collector for application monitoring
#[derive(Debug, Clone)]
pub struct MetricsCollector {
    counters: Arc<RwLock<HashMap<String, u64>>>,
    gauges: Arc<RwLock<HashMap<String, f64>>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Increment a counter
    pub async fn increment_counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.write().await;
        *counters.entry(name.to_string()).or_insert(0) += value;
    }

    /// Set a gauge value
    pub async fn set_gauge(&self, name: &str, value: f64) {
        let mut gauges = self.gauges.write().await;
        gauges.insert(name.to_string(), value);
    }

    /// Get counter value
    pub async fn get_counter(&self, name: &str) -> Option<u64> {
        let counters = self.counters.read().await;
        counters.get(name).copied()
    }

    /// Get gauge value
    pub async fn get_gauge(&self, name: &str) -> Option<f64> {
        let gauges = self.gauges.read().await;
        gauges.get(name).copied()
    }

    /// Gather all metrics in a format suitable for monitoring
    pub async fn gather_metrics(
        &self,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let counters = self.counters.read().await;
        let gauges = self.gauges.read().await;

        Ok(serde_json::json!({
            "counters": *counters,
            "gauges": *gauges
        }))
    }
}

// Re-export the existing HealthChecker from the health_check module
pub use crate::health_check::HealthChecker;

// Re-export commonly used types
// TODO: Fix re-exports after architecture migration is complete
// pub use observability::ObservabilityService;
// pub use performance_monitoring::PerformanceMonitor;
