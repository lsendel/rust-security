//! Scaling Security Controller
//!
//! This module implements adaptive security controls that scale with user load
//! and automatically adjust security policies based on current system state.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tokio::time::{interval, Interval};
use tracing::{debug, error, info, warn};

use crate::business_metrics::BusinessMetricsHelper;

/// Configuration for scaling security controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingSecurityConfig {
    /// Base rate limit per minute per user
    pub base_rate_limit: u32,
    /// Scale factor to apply when scaling up
    pub rate_limit_scale_factor: f64,
    /// Maximum rate limit per user
    pub max_rate_limit: u32,
    /// Base maximum sessions per instance
    pub base_max_sessions: u32,
    /// Session scaling factor
    pub session_scale_factor: f64,
    /// Failed login threshold scaling
    pub failed_login_base_threshold: u32,
    /// Threat level multipliers
    pub threat_level_multipliers: HashMap<String, f64>,
}

impl Default for ScalingSecurityConfig {
    fn default() -> Self {
        let mut threat_multipliers = HashMap::new();
        threat_multipliers.insert("low".to_string(), 1.0);
        threat_multipliers.insert("medium".to_string(), 1.2);
        threat_multipliers.insert("high".to_string(), 1.5);
        threat_multipliers.insert("critical".to_string(), 2.0);

        Self {
            base_rate_limit: 1000,
            rate_limit_scale_factor: 1.2,
            max_rate_limit: 10000,
            base_max_sessions: 10000,
            session_scale_factor: 1.5,
            failed_login_base_threshold: 5,
            threat_level_multipliers: threat_multipliers,
        }
    }
}

/// Current system metrics used for scaling decisions
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    /// Current number of active instances
    pub active_instances: u32,
    /// Current CPU utilization percentage
    pub cpu_utilization: f64,
    /// Current memory utilization percentage
    pub memory_utilization: f64,
    /// Current request rate per second
    pub request_rate: f64,
    /// Current error rate percentage
    pub error_rate: f64,
    /// Current threat level
    pub threat_level: String,
    /// Number of failed login attempts in last minute
    pub failed_logins_per_minute: u32,
    /// Last update timestamp
    pub last_updated: SystemTime,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            active_instances: 1,
            cpu_utilization: 0.0,
            memory_utilization: 0.0,
            request_rate: 0.0,
            error_rate: 0.0,
            threat_level: "low".to_string(),
            failed_logins_per_minute: 0,
            last_updated: SystemTime::now(),
        }
    }
}

/// Dynamic security controls that adjust based on system load
#[derive(Debug, Clone)]
pub struct DynamicSecurityControls {
    /// Current rate limit per user per minute
    pub current_rate_limit: u32,
    /// Current maximum sessions per instance
    pub current_max_sessions: u32,
    /// Current failed login threshold
    pub current_failed_login_threshold: u32,
    /// Enhanced monitoring enabled
    pub enhanced_monitoring_enabled: bool,
    /// Circuit breaker sensitivity level
    pub circuit_breaker_sensitivity: f64,
}

impl Default for DynamicSecurityControls {
    fn default() -> Self {
        Self {
            current_rate_limit: 1000,
            current_max_sessions: 10000,
            current_failed_login_threshold: 5,
            enhanced_monitoring_enabled: false,
            circuit_breaker_sensitivity: 1.0,
        }
    }
}

/// Scaling Security Controller manages adaptive security controls
pub struct ScalingSecurityController {
    config: ScalingSecurityConfig,
    current_metrics: Arc<RwLock<SystemMetrics>>,
    current_controls: Arc<RwLock<DynamicSecurityControls>>,
    update_interval: Interval,
}

impl ScalingSecurityController {
    /// Create a new scaling security controller
    pub fn new(config: Option<ScalingSecurityConfig>) -> Self {
        let config = config.unwrap_or_default();
        let update_interval = interval(Duration::from_secs(30)); // Update every 30 seconds

        Self {
            config,
            current_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            current_controls: Arc::new(RwLock::new(DynamicSecurityControls::default())),
            update_interval,
        }
    }

    /// Start the scaling controller loop
    pub async fn start(&mut self) {
        info!("Starting scaling security controller");

        loop {
            self.update_interval.tick().await;

            if let Err(e) = self.update_security_controls().await {
                error!("Failed to update security controls: {}", e);
            }

            // Record metrics about scaling decisions
            self.record_scaling_metrics().await;
        }
    }

    /// Update security controls based on current system state
    async fn update_security_controls(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Collect current system metrics
        let metrics = self.collect_system_metrics().await?;
        
        // Calculate new security controls
        let new_controls = self.calculate_security_controls(&metrics).await;

        // Apply the new controls if they've changed significantly
        let mut current_controls = self.current_controls.write().await;
        let controls_changed = self.apply_controls_if_changed(&mut current_controls, new_controls).await;

        if controls_changed {
            info!(
                rate_limit = current_controls.current_rate_limit,
                max_sessions = current_controls.current_max_sessions,
                failed_login_threshold = current_controls.current_failed_login_threshold,
                enhanced_monitoring = current_controls.enhanced_monitoring_enabled,
                "Updated scaling security controls"
            );
        }

        // Update stored metrics
        let mut current_metrics = self.current_metrics.write().await;
        *current_metrics = metrics;

        Ok(())
    }

    /// Collect current system metrics from various sources
    async fn collect_system_metrics(&self) -> Result<SystemMetrics, Box<dyn std::error::Error>> {
        // In a real implementation, these would come from:
        // - Kubernetes metrics API
        // - Prometheus queries
        // - Application metrics endpoints
        
        let mut metrics = SystemMetrics::default();
        metrics.last_updated = SystemTime::now();

        // Simulate metric collection (replace with real implementation)
        metrics.active_instances = self.get_active_instance_count().await?;
        metrics.cpu_utilization = self.get_cpu_utilization().await?;
        metrics.memory_utilization = self.get_memory_utilization().await?;
        metrics.request_rate = self.get_request_rate().await?;
        metrics.error_rate = self.get_error_rate().await?;
        metrics.threat_level = self.get_current_threat_level().await?;
        metrics.failed_logins_per_minute = self.get_failed_login_rate().await?;

        debug!("Collected system metrics: {:?}", metrics);
        Ok(metrics)
    }

    /// Calculate appropriate security controls based on system metrics
    async fn calculate_security_controls(&self, metrics: &SystemMetrics) -> DynamicSecurityControls {
        let mut controls = DynamicSecurityControls::default();

        // Calculate rate limit based on load and threat level
        let load_factor = if metrics.cpu_utilization > 80.0 || metrics.memory_utilization > 80.0 {
            0.7 // Tighter limits under high load
        } else if metrics.error_rate > 5.0 {
            0.5 // Much tighter limits if error rate is high
        } else {
            1.0 // Normal limits
        };

        let threat_multiplier = self.config.threat_level_multipliers
            .get(&metrics.threat_level)
            .copied()
            .unwrap_or(1.0);

        // Calculate new rate limit
        let base_limit = (self.config.base_rate_limit as f64 * load_factor) as u32;
        controls.current_rate_limit = ((base_limit as f64 * threat_multiplier) as u32)
            .min(self.config.max_rate_limit)
            .max(100); // Never go below 100 requests per minute

        // Calculate session limits
        controls.current_max_sessions = ((self.config.base_max_sessions as f64 
            * metrics.active_instances as f64 
            * self.config.session_scale_factor) as u32)
            .max(1000); // Minimum 1000 sessions per instance

        // Calculate failed login threshold (more sensitive under high threat)
        controls.current_failed_login_threshold = ((self.config.failed_login_base_threshold as f64 
            / threat_multiplier) as u32)
            .max(3) // Never go below 3 attempts
            .min(20); // Never go above 20 attempts

        // Enable enhanced monitoring during high load or high threat
        controls.enhanced_monitoring_enabled = 
            metrics.cpu_utilization > 70.0 
            || metrics.memory_utilization > 70.0 
            || metrics.error_rate > 2.0
            || metrics.threat_level != "low";

        // Adjust circuit breaker sensitivity
        controls.circuit_breaker_sensitivity = if metrics.error_rate > 5.0 {
            2.0 // More sensitive to failures
        } else if metrics.threat_level == "high" || metrics.threat_level == "critical" {
            1.5 // Moderately more sensitive
        } else {
            1.0 // Normal sensitivity
        };

        debug!("Calculated security controls: {:?}", controls);
        controls
    }

    /// Apply new controls if they represent a significant change
    async fn apply_controls_if_changed(
        &self,
        current: &mut DynamicSecurityControls,
        new: DynamicSecurityControls,
    ) -> bool {
        let rate_limit_changed = (current.current_rate_limit as i32 - new.current_rate_limit as i32).abs() > 100;
        let session_limit_changed = (current.current_max_sessions as i32 - new.current_max_sessions as i32).abs() > 1000;
        let threshold_changed = current.current_failed_login_threshold != new.current_failed_login_threshold;
        let monitoring_changed = current.enhanced_monitoring_enabled != new.enhanced_monitoring_enabled;

        if rate_limit_changed || session_limit_changed || threshold_changed || monitoring_changed {
            *current = new;
            true
        } else {
            false
        }
    }

    /// Record scaling metrics for monitoring
    async fn record_scaling_metrics(&self) {
        let controls = self.current_controls.read().await;
        let metrics = self.current_metrics.read().await;

        BusinessMetricsHelper::record_security_control_outcome(
            "adaptive_rate_limiting",
            &metrics.threat_level,
            "applied",
            "high",
        );

        // Record current control values as custom metrics
        debug!(
            current_rate_limit = controls.current_rate_limit,
            current_max_sessions = controls.current_max_sessions,
            current_failed_login_threshold = controls.current_failed_login_threshold,
            enhanced_monitoring = controls.enhanced_monitoring_enabled,
            threat_level = %metrics.threat_level,
            "Scaling security controls status"
        );
    }

    /// Get current security controls (for use by other components)
    pub async fn get_current_controls(&self) -> DynamicSecurityControls {
        self.current_controls.read().await.clone()
    }

    /// Get current system metrics (for monitoring)
    pub async fn get_current_metrics(&self) -> SystemMetrics {
        self.current_metrics.read().await.clone()
    }

    /// Force an immediate update of security controls
    ///
    /// # Errors
    ///
    /// Returns `Box<dyn std::error::Error>` if:
    /// - Metric collection fails
    /// - Security control updates fail
    /// - Configuration validation fails
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation.
    pub async fn force_update(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.update_security_controls().await
    }

    // Mock metric collection methods (replace with real implementations)
    
    async fn get_active_instance_count(&self) -> Result<u32, Box<dyn std::error::Error>> {
        // Query Kubernetes API or load balancer
        Ok(3) // Mock value
    }

    async fn get_cpu_utilization(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // Query Prometheus or system metrics
        Ok(45.0) // Mock value
    }

    async fn get_memory_utilization(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // Query Prometheus or system metrics  
        Ok(60.0) // Mock value
    }

    async fn get_request_rate(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // Query nginx/load balancer metrics
        Ok(150.0) // Mock value: requests per second
    }

    async fn get_error_rate(&self) -> Result<f64, Box<dyn std::error::Error>> {
        // Query application metrics
        Ok(2.0) // Mock value: percentage
    }

    async fn get_current_threat_level(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Query security monitoring system
        Ok("low".to_string()) // Mock value
    }

    async fn get_failed_login_rate(&self) -> Result<u32, Box<dyn std::error::Error>> {
        // Query security event logs
        Ok(10) // Mock value: failed logins per minute
    }
}

/// Global scaling security controller instance
use tokio::sync::OnceCell;
static SCALING_CONTROLLER: OnceCell<Arc<ScalingSecurityController>> = OnceCell::const_new();

/// Initialize the global scaling security controller
pub async fn init_scaling_controller(config: Option<ScalingSecurityConfig>) {
    let controller = Arc::new(ScalingSecurityController::new(config));
    let _ = SCALING_CONTROLLER.set(controller.clone());

    // Start the controller in a background task
    tokio::spawn(async move {
        let mut controller = (*controller).clone();
        controller.start().await;
    });

    info!("Scaling security controller initialized");
}

/// Get the current security controls from the global controller
pub async fn get_current_security_controls() -> Option<DynamicSecurityControls> {
    if let Some(controller) = SCALING_CONTROLLER.get() {
        Some(controller.get_current_controls().await)
    } else {
        None
    }
}

/// Force an update of security controls
pub async fn force_security_controls_update() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(controller) = SCALING_CONTROLLER.get() {
        controller.force_update().await
    } else {
        Err("Scaling controller not initialized".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_controls_calculation() {
        let controller = ScalingSecurityController::new(None);
        
        let mut metrics = SystemMetrics::default();
        metrics.threat_level = "high".to_string();
        metrics.cpu_utilization = 85.0;
        metrics.error_rate = 3.0;
        
        let controls = controller.calculate_security_controls(&metrics).await;
        
        // Should have tightened controls due to high threat and high CPU
        assert!(controls.current_rate_limit < 1000); // Less than base limit
        assert!(controls.enhanced_monitoring_enabled);
        assert!(controls.current_failed_login_threshold <= 5);
    }

    #[tokio::test]
    async fn test_controls_change_detection() {
        let controller = ScalingSecurityController::new(None);
        
        let mut current = DynamicSecurityControls::default();
        current.current_rate_limit = 1000;
        
        let mut new = current.clone();
        new.current_rate_limit = 950; // Small change, should not trigger update
        
        let changed = controller.apply_controls_if_changed(&mut current, new).await;
        assert!(!changed);
        
        let mut new = current.clone();
        new.current_rate_limit = 800; // Large change, should trigger update
        
        let changed = controller.apply_controls_if_changed(&mut current, new).await;
        assert!(changed);
        assert_eq!(current.current_rate_limit, 800);
    }
}