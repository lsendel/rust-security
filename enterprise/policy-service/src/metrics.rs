//! # Prometheus Metrics Module
//!
//! This module provides Prometheus metrics collection for the policy service.
//! Only included when the `prometheus-backend` feature is enabled.

use prometheus::{Histogram, IntCounter, Opts, Registry};
use std::sync::Arc;

/// Metrics collector for policy service operations
#[derive(Clone)]
pub struct PolicyMetrics {
    /// Total number of authorization requests
    pub authorization_requests_total: IntCounter,
    /// Authorization request latency histogram
    pub authorization_duration: Histogram,
    /// Policy evaluation errors
    pub policy_errors_total: IntCounter,
    /// Prometheus registry
    pub registry: Arc<Registry>,
}

impl PolicyMetrics {
    /// Create a new metrics collector
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let authorization_requests_total = IntCounter::with_opts(
            Opts::new(
                "authorization_requests_total",
                "Total authorization requests",
            )
            .namespace("policy_service"),
        )?;
        registry.register(Box::new(authorization_requests_total.clone()))?;

        let authorization_duration = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "authorization_duration_seconds",
                "Authorization request duration",
            )
            .namespace("policy_service"),
        )?;
        registry.register(Box::new(authorization_duration.clone()))?;

        let policy_errors_total = IntCounter::with_opts(
            Opts::new("policy_errors_total", "Total policy evaluation errors")
                .namespace("policy_service"),
        )?;
        registry.register(Box::new(policy_errors_total.clone()))?;

        Ok(Self {
            authorization_requests_total,
            authorization_duration,
            policy_errors_total,
            registry: Arc::new(registry),
        })
    }

    /// Get metrics as Prometheus format string
    pub fn gather(&self) -> String {
        let encoder = prometheus::TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder
            .encode_to_string(&metric_families)
            .unwrap_or_default()
    }
}

impl Default for PolicyMetrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
}
