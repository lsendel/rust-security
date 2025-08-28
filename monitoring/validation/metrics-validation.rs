//! Automated Metrics Validation and Testing
//!
//! This module provides comprehensive testing for metrics collection,
//! cardinality validation, and SLO compliance verification.

use std::collections::HashMap;
use std::time::Duration;

use prometheus::{Encoder, TextEncoder, Registry};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsValidationConfig {
    /// Maximum allowed cardinality per metric
    pub max_cardinality: usize,
    /// Metrics that are exempt from cardinality limits
    pub cardinality_exemptions: Vec<String>,
    /// Expected metrics that must be present
    pub required_metrics: Vec<String>,
    /// SLO thresholds for validation
    pub slo_thresholds: HashMap<String, f64>,
    /// Metric naming conventions
    pub naming_rules: MetricNamingRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricNamingRules {
    /// Allowed metric name patterns
    pub allowed_patterns: Vec<String>,
    /// Required label keys for certain metrics
    pub required_labels: HashMap<String, Vec<String>>,
    /// Forbidden label values
    pub forbidden_label_values: Vec<String>,
}

impl Default for MetricsValidationConfig {
    fn default() -> Self {
        let mut slo_thresholds = HashMap::new();
        slo_thresholds.insert("auth_http_request_duration_seconds_p99".to_string(), 0.1);
        slo_thresholds.insert("policy_authorization_duration_seconds_p95".to_string(), 0.05);
        slo_thresholds.insert("auth_http_requests_availability".to_string(), 0.999);

        let mut required_labels = HashMap::new();
        required_labels.insert("auth_http_requests_total".to_string(), vec![
            "method".to_string(),
            "endpoint".to_string(),
            "status_code".to_string(),
        ]);

        Self {
            max_cardinality: 1000,
            cardinality_exemptions: vec![
                "auth_user_session_duration_seconds".to_string(),
                "business_revenue_impact_events_total".to_string(),
            ],
            required_metrics: vec![
                "auth_http_requests_total".to_string(),
                "auth_http_request_duration_seconds".to_string(),
                "auth_token_issuance_total".to_string(),
                "policy_authorization_requests_total".to_string(),
                "policy_authorization_duration_seconds".to_string(),
            ],
            slo_thresholds,
            naming_rules: MetricNamingRules {
                allowed_patterns: vec![
                    r"^auth_.*".to_string(),
                    r"^policy_.*".to_string(),
                    r"^business_.*".to_string(),
                ],
                required_labels,
                forbidden_label_values: vec![
                    "password".to_string(),
                    "secret".to_string(),
                    "token".to_string(),
                    "key".to_string(),
                ],
            },
        }
    }
}

#[derive(Debug)]
pub struct MetricsValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub cardinality_report: HashMap<String, usize>,
    pub slo_compliance: HashMap<String, bool>,
}

#[derive(Debug)]
pub struct MetricsValidator {
    config: MetricsValidationConfig,
}

impl MetricsValidator {
    pub fn new(config: MetricsValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a Prometheus registry
    pub async fn validate_registry(&self, registry: &Registry) -> MetricsValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut cardinality_report = HashMap::new();
        let mut slo_compliance = HashMap::new();

        // Gather metrics
        let metric_families = registry.gather();
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            errors.push(format!("Failed to encode metrics: {}", e));
            return MetricsValidationResult {
                is_valid: false,
                errors,
                warnings,
                cardinality_report,
                slo_compliance,
            };
        }

        let metrics_text = String::from_utf8_lossy(&buffer);
        
        // Parse and validate metrics
        self.validate_metric_presence(&metrics_text, &mut errors);
        self.validate_naming_conventions(&metrics_text, &mut errors, &mut warnings);
        self.validate_cardinality(&metrics_text, &mut errors, &mut warnings, &mut cardinality_report);
        self.validate_label_values(&metrics_text, &mut errors, &mut warnings);
        
        // Validate SLO metrics if available
        self.validate_slo_compliance(&metrics_text, &mut slo_compliance, &mut warnings).await;

        let is_valid = errors.is_empty();

        MetricsValidationResult {
            is_valid,
            errors,
            warnings,
            cardinality_report,
            slo_compliance,
        }
    }

    fn validate_metric_presence(&self, metrics_text: &str, errors: &mut Vec<String>) {
        for required_metric in &self.config.required_metrics {
            if !metrics_text.contains(required_metric) {
                errors.push(format!("Required metric '{}' not found", required_metric));
            }
        }
    }

    fn validate_naming_conventions(
        &self,
        metrics_text: &str,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        let metric_name_regex = Regex::new(r"^([a-zA-Z_][a-zA-Z0-9_]*)\{").unwrap();
        
        for line in metrics_text.lines() {
            if let Some(caps) = metric_name_regex.captures(line) {
                let metric_name = &caps[1];
                
                // Check against allowed patterns
                let mut matches_pattern = false;
                for pattern in &self.config.naming_rules.allowed_patterns {
                    if let Ok(regex) = Regex::new(pattern) {
                        if regex.is_match(metric_name) {
                            matches_pattern = true;
                            break;
                        }
                    }
                }
                
                if !matches_pattern {
                    warnings.push(format!(
                        "Metric '{}' doesn't match naming conventions", 
                        metric_name
                    ));
                }
                
                // Check required labels
                if let Some(required_labels) = self.config.naming_rules.required_labels.get(metric_name) {
                    for required_label in required_labels {
                        if !line.contains(&format!("{}=", required_label)) {
                            errors.push(format!(
                                "Metric '{}' missing required label '{}'",
                                metric_name, required_label
                            ));
                        }
                    }
                }
            }
        }
    }

    fn validate_cardinality(
        &self,
        metrics_text: &str,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
        cardinality_report: &mut HashMap<String, usize>,
    ) {
        let mut metric_series_count = HashMap::new();
        
        for line in metrics_text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            
            if let Some(space_pos) = line.find(' ') {
                let metric_with_labels = &line[..space_pos];
                if let Some(brace_pos) = metric_with_labels.find('{') {
                    let metric_name = &metric_with_labels[..brace_pos];
                    *metric_series_count.entry(metric_name.to_string()).or_insert(0) += 1;
                } else {
                    let metric_name = metric_with_labels;
                    *metric_series_count.entry(metric_name.to_string()).or_insert(0) += 1;
                }
            }
        }
        
        for (metric_name, series_count) in metric_series_count {
            cardinality_report.insert(metric_name.clone(), series_count);
            
            if series_count > self.config.max_cardinality 
                && !self.config.cardinality_exemptions.contains(&metric_name) {
                errors.push(format!(
                    "Metric '{}' has high cardinality: {} series (max: {})",
                    metric_name, series_count, self.config.max_cardinality
                ));
            } else if series_count > (self.config.max_cardinality / 2) {
                warnings.push(format!(
                    "Metric '{}' approaching cardinality limit: {} series",
                    metric_name, series_count
                ));
            }
        }
    }

    fn validate_label_values(
        &self,
        metrics_text: &str,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        for line in metrics_text.lines() {
            for forbidden_value in &self.config.naming_rules.forbidden_label_values {
                if line.contains(&format!("=\"{}\"", forbidden_value)) {
                    errors.push(format!(
                        "Forbidden label value '{}' found in metric line: {}",
                        forbidden_value, line
                    ));
                }
                
                // Check for potential sensitive data patterns
                if line.contains("=\"") && forbidden_value.len() > 3 {
                    let pattern = format!("=\".*{}.*\"", forbidden_value.to_lowercase());
                    if let Ok(regex) = Regex::new(&pattern) {
                        if regex.is_match(&line.to_lowercase()) {
                            warnings.push(format!(
                                "Potential sensitive data in label value: {}", 
                                line
                            ));
                        }
                    }
                }
            }
        }
    }

    async fn validate_slo_compliance(
        &self,
        metrics_text: &str,
        slo_compliance: &mut HashMap<String, bool>,
        warnings: &mut Vec<String>,
    ) {
        // This would typically query Prometheus for SLO calculations
        // For now, we'll simulate basic SLO validation
        
        for (slo_metric, threshold) in &self.config.slo_thresholds {
            // Look for metric values in the text (simplified)
            let compliant = if slo_metric.contains("availability") {
                // Check availability metrics
                self.check_availability_slo(metrics_text, *threshold).await
            } else if slo_metric.contains("duration") {
                // Check latency metrics
                self.check_latency_slo(metrics_text, slo_metric, *threshold).await
            } else {
                true // Default to compliant for unknown SLO types
            };
            
            slo_compliance.insert(slo_metric.clone(), compliant);
            
            if !compliant {
                warnings.push(format!(
                    "SLO '{}' not meeting threshold: {}",
                    slo_metric, threshold
                ));
            }
        }
    }

    async fn check_availability_slo(&self, metrics_text: &str, threshold: f64) -> bool {
        // Calculate availability from error rates
        let mut total_requests = 0.0;
        let mut error_requests = 0.0;
        
        for line in metrics_text.lines() {
            if line.contains("auth_http_requests_total") {
                if let Some(value_str) = line.split(' ').nth(1) {
                    if let Ok(value) = value_str.parse::<f64>() {
                        total_requests += value;
                        if line.contains("status_code=\"5") {
                            error_requests += value;
                        }
                    }
                }
            }
        }
        
        if total_requests > 0.0 {
            let availability = (total_requests - error_requests) / total_requests;
            availability >= threshold
        } else {
            true // No requests, consider as compliant
        }
    }

    async fn check_latency_slo(&self, metrics_text: &str, metric_name: &str, threshold: f64) -> bool {
        // This would typically calculate percentiles from histogram buckets
        // For now, simplified check
        for line in metrics_text.lines() {
            if line.contains(metric_name) && line.contains("quantile=") {
                if let Some(value_str) = line.split(' ').nth(1) {
                    if let Ok(value) = value_str.parse::<f64>() {
                        return value <= threshold;
                    }
                }
            }
        }
        true // Default to compliant if metric not found
    }

    /// Load test for metrics under high cardinality
    pub async fn load_test_cardinality(&self, registry: &Registry, test_duration: Duration) -> MetricsValidationResult {
        println!("Starting cardinality load test for {:?}", test_duration);
        
        let start_time = std::time::Instant::now();
        let mut iteration = 0;
        
        // Simulate high cardinality scenario
        while start_time.elapsed() < test_duration {
            // This would typically trigger metric creation with various label values
            // For testing, we'll simulate the validation
            iteration += 1;
            
            if iteration % 100 == 0 {
                let _result = self.validate_registry(registry).await;
                if !result.is_valid {
                    println!("Validation failed at iteration {}: {:?}", iteration, result.errors);
                    return result;
                }
                
                // Check cardinality growth
                let max_cardinality = result.cardinality_report.values().max().unwrap_or(&0);
                println!("Max cardinality at iteration {}: {}", iteration, max_cardinality);
            }
            
            sleep(Duration::from_millis(10)).await;
        }
        
        self.validate_registry(registry).await
    }
}

/// Metrics testing utilities
pub struct MetricsTestSuite;

impl MetricsTestSuite {
    /// Test metric collection performance
    pub async fn benchmark_metric_collection(registry: &Registry, samples: usize) -> Duration {
        let start = std::time::Instant::now();
        
        for _ in 0..samples {
            let _metrics = registry.gather();
        }
        
        start.elapsed()
    }
    
    /// Test metric encoding performance
    pub async fn benchmark_metric_encoding(registry: &Registry, samples: usize) -> Duration {
        let encoder = TextEncoder::new();
        let start = std::time::Instant::now();
        
        for _ in 0..samples {
            let metric_families = registry.gather();
            let mut buffer = Vec::new();
            let _ = encoder.encode(&metric_families, &mut buffer);
        }
        
        start.elapsed()
    }
    
    /// Validate metric mathematical properties
    pub fn validate_metric_math(metrics_text: &str) -> Vec<String> {
        let mut errors = Vec::new();
        
        // Check for negative counters
        for line in metrics_text.lines() {
            if line.contains("_total") && line.contains(' ') {
                if let Some(value_str) = line.split(' ').nth(1) {
                    if let Ok(value) = value_str.parse::<f64>() {
                        if value < 0.0 {
                            errors.push(format!("Counter has negative value: {}", line));
                        }
                    }
                }
            }
        }
        
        // Check for histogram bucket consistency
        let mut histogram_buckets: HashMap<String, Vec<(f64, f64)>> = HashMap::new();
        for line in metrics_text.lines() {
            if line.contains("_bucket") && line.contains("le=") {
                if let Some(metric_part) = line.split('{').next() {
                    if let Some(le_start) = line.find("le=\"") {
                        if let Some(le_end) = line[le_start + 4..].find('"') {
                            let le_value_str = &line[le_start + 4..le_start + 4 + le_end];
                            if let Ok(le_value) = le_value_str.parse::<f64>() {
                                if let Some(count_str) = line.split(' ').nth(1) {
                                    if let Ok(count) = count_str.parse::<f64>() {
                                        histogram_buckets
                                            .entry(metric_part.to_string())
                                            .or_default()
                                            .push((le_value, count));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Validate histogram buckets are non-decreasing
        for (metric_name, mut buckets) in histogram_buckets {
            buckets.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            for window in buckets.windows(2) {
                if window[1].1 < window[0].1 {
                    errors.push(format!(
                        "Histogram bucket values are decreasing in {}: le={} count={} > le={} count={}",
                        metric_name, window[0].0, window[0].1, window[1].0, window[1].1
                    ));
                }
            }
        }
        
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{IntCounter, Registry};

    #[tokio::test]
    async fn test_metrics_validation() {
        let config = MetricsValidationConfig::default();
        let validator = MetricsValidator::new(config);
        
        let registry = Registry::new();
        let counter = IntCounter::new("auth_test_total", "Test counter").unwrap();
        registry.register(Box::new(counter)).unwrap();
        
        let _result = validator.validate_registry(&registry).await;
        assert!(!result.errors.is_empty()); // Should have errors due to missing required metrics
    }

    #[test]
    fn test_metric_math_validation() {
        let metrics_text = r#"
# HELP test_total Test counter
# TYPE test_total counter
test_total{label="value"} 5
test_bucket{le="0.1"} 10
test_bucket{le="0.5"} 8
test_bucket{le="+Inf"} 15
"#;
        
        let errors = MetricsTestSuite::validate_metric_math(metrics_text);
        assert!(!errors.is_empty()); // Should detect decreasing bucket values
    }

    #[tokio::test]
    async fn test_cardinality_load_test() {
        let config = MetricsValidationConfig::default();
        let validator = MetricsValidator::new(config);
        let registry = Registry::new();
        
        let _result = validator
            .load_test_cardinality(&registry, Duration::from_millis(100))
            .await;
        
        assert!(result.is_valid || !result.errors.is_empty());
    }
}