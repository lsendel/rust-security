//! Alert correlation engine for detecting patterns and relationships
//!
//! This module provides advanced alert correlation capabilities to identify
//! related security events and reduce alert fatigue through intelligent grouping.

use super::types::*;
use crate::security_monitoring::{AlertSeverity, SecurityAlert, SecurityAlertType};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Alert correlation engine
pub struct AlertCorrelationEngine {
    /// Correlation rules
    correlation_rules: Arc<RwLock<Vec<CorrelationRule>>>,

    /// Alert cache for correlation
    alert_cache: Arc<DashMap<String, Vec<SecurityAlert>>>,

    /// Correlation results
    correlation_results: Arc<DashMap<String, CorrelationResult>>,

    /// Configuration
    config: CorrelationConfig,

    /// Metrics
    metrics: Arc<tokio::sync::Mutex<CorrelationMetrics>>,
}

impl AlertCorrelationEngine {
    /// Create a new alert correlation engine
    pub async fn new(config: CorrelationConfig) -> Result<Self, CorrelationError> {
        Ok(Self {
            correlation_rules: Arc::new(RwLock::new(config.correlation_rules.clone())),
            alert_cache: Arc::new(DashMap::new()),
            correlation_results: Arc::new(DashMap::new()),
            config,
            metrics: Arc::new(tokio::sync::Mutex::new(CorrelationMetrics::default())),
        })
    }

    /// Start the correlation engine
    pub async fn start(&self) -> Result<(), CorrelationError> {
        info!("Starting alert correlation engine");

        // Start cleanup task for old alerts
        let engine_clone = self.clone();
        tokio::spawn(async move {
            engine_clone.cleanup_old_alerts().await;
        });

        info!("Alert correlation engine started successfully");
        Ok(())
    }

    /// Stop the correlation engine
    pub async fn stop(&self) -> Result<(), CorrelationError> {
        info!("Stopping alert correlation engine");
        Ok(())
    }

    /// Process an incoming alert for correlation
    pub async fn process_alert(
        &self,
        alert: SecurityAlert,
    ) -> Result<Option<CorrelationResult>, CorrelationError> {
        debug!("Processing alert for correlation: {}", alert.id);

        // Add alert to cache
        self.add_alert_to_cache(alert.clone()).await;

        // Check for correlations
        let correlation_result = self.correlate_alert(&alert).await?;

        // Update metrics
        {
            let mut metrics = self.metrics.lock().await;
            metrics.total_alerts_processed += 1;
            if correlation_operation_result.is_some() {
                metrics.correlations_found += 1;
            }
        }

        Ok(correlation_result)
    }

    /// Add correlation rule
    pub async fn add_correlation_rule(
        &self,
        rule: CorrelationRule,
    ) -> Result<(), CorrelationError> {
        let mut rules = self.correlation_rules.write().await;
        rules.push(rule);
        info!("Added new correlation rule");
        Ok(())
    }

    /// Remove correlation rule
    pub async fn remove_correlation_rule(&self, rule_id: &str) -> Result<bool, CorrelationError> {
        let mut rules = self.correlation_rules.write().await;
        let initial_len = rules.len();
        rules.retain(|rule| rule.id != rule_id);
        Ok(rules.len() < initial_len)
    }

    /// Get correlation results
    pub async fn get_correlation_results(&self) -> Vec<CorrelationResult> {
        self.correlation_results
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get correlation metrics
    pub async fn get_metrics(&self) -> CorrelationMetrics {
        self.metrics.lock().await.clone()
    }

    /// Add alert to correlation cache
    async fn add_alert_to_cache(&self, alert: SecurityAlert) {
        let cache_key = self.generate_cache_key(&alert);

        self.alert_cache
            .entry(cache_key)
            .or_insert_with(Vec::new)
            .push(alert);

        // Enforce cache size limit
        if self.alert_cache.len() > self.config.max_correlation_cache_size {
            self.cleanup_cache().await;
        }
    }

    /// Correlate an alert with existing alerts
    async fn correlate_alert(
        &self,
        alert: &SecurityAlert,
    ) -> Result<Option<CorrelationResult>, CorrelationError> {
        let rules = self.correlation_rules.read().await;

        for rule in rules.iter() {
            if let Some(correlation) = self.apply_correlation_rule(alert, rule).await? {
                // Store correlation result
                self.correlation_results
                    .insert(correlation.id.clone(), correlation.clone());
                return Ok(Some(correlation));
            }
        }

        Ok(None)
    }

    /// Apply a correlation rule to an alert
    async fn apply_correlation_rule(
        &self,
        alert: &SecurityAlert,
        rule: &CorrelationRule,
    ) -> Result<Option<CorrelationResult>, CorrelationError> {
        debug!(
            "Applying correlation rule: {} to alert: {}",
            rule.name, alert.id
        );

        // Get time window for correlation
        let time_window = Duration::minutes(rule.time_window_minutes as i64);
        let window_start = alert.timestamp - time_window;
        let window_end = alert.timestamp + time_window;

        // Find related alerts in time window
        let mut related_alerts = Vec::new();

        for cache_entry in self.alert_cache.iter() {
            for cached_alert in cache_entry.value() {
                if cached_alert.id != alert.id
                    && cached_alert.timestamp >= window_start
                    && cached_alert.timestamp <= window_end
                {
                    if self
                        .check_correlation_conditions(alert, cached_alert, &rule.conditions)
                        .await
                    {
                        related_alerts.push(cached_alert.clone());
                    }
                }
            }
        }

        // Check if we have enough events for correlation
        if related_alerts.len() + 1 < rule.min_events as usize {
            return Ok(None);
        }

        // Limit to max events
        if related_alerts.len() > rule.max_events as usize {
            related_alerts.truncate(rule.max_events as usize);
        }

        // Calculate confidence and risk scores
        let confidence_score = self.calculate_confidence_score(&related_alerts, rule).await;
        let risk_score = self.calculate_risk_score(alert, &related_alerts).await;

        // Create correlation result
        let correlation_result = CorrelationResult {
            id: Uuid::new_v4().to_string(),
            primary_alert_id: alert.id.clone(),
            correlated_alert_ids: related_alerts.iter().map(|a| a.id.clone()).collect(),
            correlation_rules_triggered: vec![rule.id.clone()],
            confidence_score,
            risk_score,
            created_at: Utc::now(),
        };

        // Execute correlation action if configured
        if let Some(_action) = &rule.action.trigger_playbook {
            // Trigger playbook execution
            debug!("Correlation would trigger playbook execution");
        }

        Ok(Some(correlation_result))
    }

    /// Check if correlation conditions are met between two alerts
    async fn check_correlation_conditions(
        &self,
        alert1: &SecurityAlert,
        alert2: &SecurityAlert,
        conditions: &[CorrelationCondition],
    ) -> bool {
        for condition in conditions {
            if !self
                .evaluate_correlation_condition(alert1, alert2, condition)
                .await
            {
                return false;
            }
        }
        true
    }

    /// Evaluate a single correlation condition
    async fn evaluate_correlation_condition(
        &self,
        alert1: &SecurityAlert,
        alert2: &SecurityAlert,
        condition: &CorrelationCondition,
    ) -> bool {
        match &condition.correlation_type {
            CorrelationType::ExactMatch => {
                self.get_alert_field_value(alert1, &condition.field)
                    == self.get_alert_field_value(alert2, &condition.field)
            }
            CorrelationType::SimilarValues => {
                // Implement similarity matching
                let val1 = self.get_alert_field_value(alert1, &condition.field);
                let val2 = self.get_alert_field_value(alert2, &condition.field);

                if let (Some(v1), Some(v2)) = (val1, val2) {
                    self.calculate_similarity(v1, v2) >= condition.threshold.unwrap_or(0.8)
                } else {
                    false
                }
            }
            CorrelationType::TimeProximity => {
                let time_diff = (alert1.timestamp - alert2.timestamp).num_minutes().abs();
                time_diff <= condition.threshold.unwrap_or(60.0) as i64
            }
            CorrelationType::IpAddressRange => {
                // Implement IP range correlation
                self.correlate_ip_addresses(alert1, alert2, &condition.field)
                    .await
            }
            CorrelationType::UserBehavior => {
                // Implement user behavior correlation
                self.correlate_user_behavior(alert1, alert2).await
            }
            CorrelationType::Custom(_) => {
                // Implement custom correlation logic
                warn!("Custom correlation type not implemented");
                false
            }
        }
    }

    /// Get field value from alert
    fn get_alert_field_value(&self, alert: &SecurityAlert, field: &str) -> Option<&str> {
        match field {
            "source_ip" => alert.source_ip.as_deref(),
            "destination_ip" => alert.destination_ip.as_deref(),
            "user_id" => alert.user_id.as_deref(),
            "alert_type" => Some(&format!("{:?}", alert.alert_type)),
            "severity" => Some(&format!("{:?}", alert.severity)),
            _ => {
                // Check metadata for custom fields
                alert.metadata.get(field).and_then(|v| v.as_str())
            }
        }
    }

    /// Calculate similarity between two string values
    fn calculate_similarity(&self, val1: &str, val2: &str) -> f64 {
        // Simple Levenshtein distance-based similarity
        let distance = levenshtein_distance(val1, val2);
        let max_len = val1.len().max(val2.len());

        if max_len == 0 {
            1.0
        } else {
            1.0 - (distance as f64 / max_len as f64)
        }
    }

    /// Correlate IP addresses (check if they're in the same subnet)
    async fn correlate_ip_addresses(
        &self,
        alert1: &SecurityAlert,
        alert2: &SecurityAlert,
        field: &str,
    ) -> bool {
        let ip1 = self.get_alert_field_value(alert1, field);
        let ip2 = self.get_alert_field_value(alert2, field);

        if let (Some(ip1_str), Some(ip2_str)) = (ip1, ip2) {
            // Simple subnet check (same /24 network)
            if let (Ok(ip1_addr), Ok(ip2_addr)) = (
                ip1_str.parse::<std::net::IpAddr>(),
                ip2_str.parse::<std::net::IpAddr>(),
            ) {
                match (ip1_addr, ip2_addr) {
                    (std::net::IpAddr::V4(ipv4_1), std::net::IpAddr::V4(ipv4_2)) => {
                        let octets1 = ipv4_1.octets();
                        let octets2 = ipv4_2.octets();
                        octets1[0] == octets2[0]
                            && octets1[1] == octets2[1]
                            && octets1[2] == octets2[2]
                    }
                    _ => false,
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Correlate user behavior patterns
    async fn correlate_user_behavior(
        &self,
        alert1: &SecurityAlert,
        alert2: &SecurityAlert,
    ) -> bool {
        // Check if alerts involve the same user
        if let (Some(user1), Some(user2)) = (&alert1.user_id, &alert2.user_id) {
            user1 == user2
        } else {
            false
        }
    }

    /// Calculate confidence score for correlation
    async fn calculate_confidence_score(
        &self,
        related_alerts: &[SecurityAlert],
        rule: &CorrelationRule,
    ) -> u8 {
        let mut score = 50u8; // Base score

        // Increase score based on number of related alerts
        score += (related_alerts.len() * 10).min(30) as u8;

        // Increase score based on rule priority
        score += (rule.priority * 5).min(20);

        // Cap at 100
        score.min(100)
    }

    /// Calculate risk score for correlation
    async fn calculate_risk_score(
        &self,
        primary_alert: &SecurityAlert,
        related_alerts: &[SecurityAlert],
    ) -> u8 {
        let mut score = match primary_alert.severity {
            AlertSeverity::Critical => 90,
            AlertSeverity::High => 70,
            AlertSeverity::Medium => 50,
            AlertSeverity::Low => 30,
        };

        // Increase score based on related alert severities
        for alert in related_alerts {
            score += match alert.severity {
                AlertSeverity::Critical => 10,
                AlertSeverity::High => 7,
                AlertSeverity::Medium => 5,
                AlertSeverity::Low => 2,
            };
        }

        // Cap at 100
        score.min(100)
    }

    /// Generate cache key for alert grouping
    fn generate_cache_key(&self, alert: &SecurityAlert) -> String {
        format!(
            "{}_{:?}_{:?}",
            alert.source_ip.as_deref().unwrap_or("unknown"),
            alert.alert_type,
            alert.severity
        )
    }

    /// Clean up old alerts from cache
    async fn cleanup_old_alerts(&self) {
        let cleanup_interval = tokio::time::Duration::from_secs(300); // 5 minutes
        let mut interval = tokio::time::interval(cleanup_interval);

        loop {
            interval.tick().await;

            let cutoff_time =
                Utc::now() - Duration::minutes(self.config.correlation_window_minutes as i64 * 2);

            // Remove old alerts
            let mut removed_count = 0;
            for mut entry in self.alert_cache.iter_mut() {
                let initial_len = entry.value().len();
                entry
                    .value_mut()
                    .retain(|alert| alert.timestamp > cutoff_time);
                removed_count += initial_len - entry.value().len();
            }

            // Remove empty cache entries
            self.alert_cache.retain(|_, alerts| !alerts.is_empty());

            if removed_count > 0 {
                debug!(
                    "Cleaned up {} old alerts from correlation cache",
                    removed_count
                );
            }
        }
    }

    /// Clean up cache when it gets too large
    async fn cleanup_cache(&self) {
        let target_size = self.config.max_correlation_cache_size * 3 / 4; // Reduce to 75%

        while self.alert_cache.len() > target_size {
            // Remove oldest cache entries
            if let Some(entry) = self.alert_cache.iter().next() {
                let key = entry.key().clone();
                self.alert_cache.remove(&key);
            } else {
                break;
            }
        }
    }
}

impl Clone for AlertCorrelationEngine {
    fn clone(&self) -> Self {
        Self {
            correlation_rules: Arc::clone(&self.correlation_rules),
            alert_cache: Arc::clone(&self.alert_cache),
            correlation_results: Arc::clone(&self.correlation_results),
            config: self.config.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Correlation metrics
#[derive(Debug, Clone, Default)]
pub struct CorrelationMetrics {
    pub total_alerts_processed: u64,
    pub correlations_found: u64,
    pub correlation_rate: f64,
    pub average_correlation_time_ms: f64,
}

/// Correlation error types
#[derive(Debug, thiserror::Error)]
pub enum CorrelationError {
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Rule evaluation error: {0}")]
    RuleEvaluationError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[len1][len2]
}
