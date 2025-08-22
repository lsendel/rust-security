use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Real-time monitoring dashboard for the authentication service
pub struct MonitoringDashboard {
    /// System health metrics
    health_metrics: Arc<RwLock<HealthMetrics>>,
    /// Security event tracker
    security_events: Arc<RwLock<SecurityEventTracker>>,
    /// Performance analytics
    performance_analytics: Arc<RwLock<PerformanceAnalytics>>,
    /// Alert manager
    alert_manager: Arc<AlertManager>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Overall system health score (0-100)
    pub health_score: u8,
    /// Service uptime in seconds
    pub uptime_seconds: u64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Database connection health
    pub database_healthy: bool,
    /// Redis connection health
    pub redis_healthy: bool,
    /// External service dependencies
    pub external_services: HashMap<String, ServiceHealth>,
    /// Last updated timestamp
    pub last_updated: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub name: String,
    pub healthy: bool,
    pub response_time_ms: u64,
    pub last_check: u64,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventTracker {
    /// Failed authentication attempts in last hour
    pub failed_auth_attempts: u32,
    /// Blocked IPs in last hour
    pub blocked_ips: u32,
    /// Suspicious activities detected
    pub suspicious_activities: u32,
    /// Rate limit violations
    pub rate_limit_violations: u32,
    /// JWT validation failures
    pub jwt_failures: u32,
    /// Recent security events
    pub recent_events: Vec<SecurityEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: u64,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub source_ip: String,
    pub user_id: Option<String>,
    pub description: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    FailedAuthentication,
    SuspiciousActivity,
    RateLimitViolation,
    JwtValidationFailure,
    UnauthorizedAccess,
    BruteForceAttempt,
    AnomalousTraffic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAnalytics {
    /// Request metrics
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    /// Latency metrics
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    /// Throughput metrics
    pub requests_per_second: f64,
    pub peak_rps: f64,
    /// Error rates
    pub error_rate_percent: f64,
    /// Cache performance
    pub cache_hit_rate: f64,
    /// Time series data for charts
    pub response_time_history: Vec<TimeSeriesPoint>,
    pub request_rate_history: Vec<TimeSeriesPoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub health: HealthMetrics,
    pub security: SecurityEventTracker,
    pub performance: PerformanceAnalytics,
    pub alerts: Vec<Alert>,
    pub system_info: SystemInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub build_time: String,
    pub rust_version: String,
    pub environment: String,
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: AlertSeverity,
    pub timestamp: u64,
    pub acknowledged: bool,
    pub auto_resolve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

pub struct AlertManager {
    active_alerts: RwLock<HashMap<String, Alert>>,
    alert_rules: RwLock<Vec<AlertRule>>,
}

#[derive(Debug, Clone)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub cooldown_seconds: u64,
    pub last_triggered: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum AlertCondition {
    HighErrorRate(f64),
    HighLatency(f64),
    HighMemoryUsage(f64),
    HighCpuUsage(f64),
    ServiceDown(String),
    SecurityThreat(u32),
}

impl Default for HealthMetrics {
    fn default() -> Self {
        Self {
            health_score: 100,
            uptime_seconds: 0,
            memory_usage_percent: 0.0,
            cpu_usage_percent: 0.0,
            database_healthy: true,
            redis_healthy: true,
            external_services: HashMap::new(),
            last_updated: current_timestamp(),
        }
    }
}

impl Default for SecurityEventTracker {
    fn default() -> Self {
        Self {
            failed_auth_attempts: 0,
            blocked_ips: 0,
            suspicious_activities: 0,
            rate_limit_violations: 0,
            jwt_failures: 0,
            recent_events: Vec::new(),
        }
    }
}

impl Default for PerformanceAnalytics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_response_time_ms: 0.0,
            p95_response_time_ms: 0.0,
            p99_response_time_ms: 0.0,
            requests_per_second: 0.0,
            peak_rps: 0.0,
            error_rate_percent: 0.0,
            cache_hit_rate: 0.0,
            response_time_history: Vec::new(),
            request_rate_history: Vec::new(),
        }
    }
}

impl MonitoringDashboard {
    /// Create a new monitoring dashboard
    pub fn new() -> Self {
        let alert_manager = AlertManager::new();

        Self {
            health_metrics: Arc::new(RwLock::new(HealthMetrics::default())),
            security_events: Arc::new(RwLock::new(SecurityEventTracker::default())),
            performance_analytics: Arc::new(RwLock::new(PerformanceAnalytics::default())),
            alert_manager: Arc::new(alert_manager),
        }
    }

    /// Update health metrics
    pub async fn update_health(&self, metrics: HealthMetrics) {
        let mut health = self.health_metrics.write().await;
        *health = metrics;

        // Check for health-based alerts
        self.alert_manager.check_health_alerts(&health).await;
    }

    /// Record a security event
    pub async fn record_security_event(&self, event: SecurityEvent) {
        let mut tracker = self.security_events.write().await;

        // Update counters based on event type
        match event.event_type {
            SecurityEventType::FailedAuthentication => tracker.failed_auth_attempts += 1,
            SecurityEventType::RateLimitViolation => tracker.rate_limit_violations += 1,
            SecurityEventType::JwtValidationFailure => tracker.jwt_failures += 1,
            SecurityEventType::SuspiciousActivity => tracker.suspicious_activities += 1,
            _ => {}
        }

        // Add to recent events (keep last 100)
        tracker.recent_events.push(event.clone());
        if tracker.recent_events.len() > 100 {
            tracker.recent_events.remove(0);
        }

        // Check for security-based alerts
        self.alert_manager.check_security_alerts(&event).await;
    }

    /// Update performance metrics
    pub async fn update_performance(&self, analytics: PerformanceAnalytics) {
        let mut perf = self.performance_analytics.write().await;
        *perf = analytics;

        // Check for performance-based alerts
        self.alert_manager.check_performance_alerts(&perf).await;
    }

    /// Get complete dashboard data
    pub async fn get_dashboard_data(&self) -> Result<DashboardData> {
        let health = self.health_metrics.read().await.clone();
        let security = self.security_events.read().await.clone();
        let performance = self.performance_analytics.read().await.clone();
        let alerts = self.alert_manager.get_active_alerts().await;

        let system_info = SystemInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_time: "2024-01-01T00:00:00Z".to_string(), // Would be set at build time
            rust_version: "1.75.0".to_string(),             // Would be detected at runtime
            environment: std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string()),
            node_id: "node-1".to_string(), // Would be unique per instance
        };

        Ok(DashboardData {
            health,
            security,
            performance,
            alerts,
            system_info,
        })
    }

    /// Generate dashboard HTML
    pub async fn generate_dashboard_html(&self) -> Result<String> {
        let data = self.get_dashboard_data().await?;

        Ok(format!(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rust Security Platform - Monitoring Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .dashboard {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .metric-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric-title {{ font-size: 18px; font-weight: bold; margin-bottom: 15px; color: #2c3e50; }}
        .metric-value {{ font-size: 24px; font-weight: bold; margin-bottom: 5px; }}
        .health-good {{ color: #27ae60; }}
        .health-warning {{ color: #f39c12; }}
        .health-critical {{ color: #e74c3c; }}
        .alert {{ padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .alert-critical {{ background: #ffebee; border-left: 4px solid #e74c3c; }}
        .alert-warning {{ background: #fff8e1; border-left: 4px solid #f39c12; }}
        .alert-info {{ background: #e3f2fd; border-left: 4px solid #2196f3; }}
        .status-indicator {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        .status-healthy {{ background: #27ae60; }}
        .status-unhealthy {{ background: #e74c3c; }}
        .refresh-btn {{ background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>🦀 Rust Security Platform - Monitoring Dashboard</h1>
            <p>Real-time monitoring and analytics for enterprise authentication</p>
            <button class="refresh-btn" onclick="location.reload()">🔄 Refresh</button>
        </div>

        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-title">🏥 System Health</div>
                <div class="metric-value health-{}">{}%</div>
                <p>Overall system health score</p>
                <div>
                    <span class="status-indicator status-{}"></span>Database: {}
                </div>
                <div>
                    <span class="status-indicator status-{}"></span>Redis: {}
                </div>
                <div>Memory: {:.1}% | CPU: {:.1}%</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">🔒 Security Events</div>
                <div class="metric-value health-{}">{}⚠️</div>
                <p>Security events in last hour</p>
                <div>Failed Auth: {}</div>
                <div>Blocked IPs: {}</div>
                <div>Rate Limits: {}</div>
                <div>JWT Failures: {}</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">⚡ Performance</div>
                <div class="metric-value health-{}">{}ms</div>
                <p>Average response time</p>
                <div>P95: {:.1}ms | P99: {:.1}ms</div>
                <div>RPS: {:.1} | Peak: {:.1}</div>
                <div>Error Rate: {:.2}%</div>
                <div>Cache Hit: {:.1}%</div>
            </div>

            <div class="metric-card">
                <div class="metric-title">📊 Request Statistics</div>
                <div class="metric-value health-good">{}</div>
                <p>Total requests processed</p>
                <div>Successful: {} ({:.1}%)</div>
                <div>Failed: {} ({:.1}%)</div>
            </div>
        </div>

        <div class="metric-card" style="margin-top: 20px;">
            <div class="metric-title">🚨 Active Alerts</div>
            {}
        </div>

        <div class="metric-card" style="margin-top: 20px;">
            <div class="metric-title">ℹ️ System Information</div>
            <div>Version: {}</div>
            <div>Environment: {}</div>
            <div>Node ID: {}</div>
            <div>Uptime: {} seconds</div>
        </div>
    </div>

    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
    </script>
</body>
</html>
        "#,
            // Health metrics
            if data.health.health_score >= 80 {
                "good"
            } else if data.health.health_score >= 60 {
                "warning"
            } else {
                "critical"
            },
            data.health.health_score,
            if data.health.database_healthy {
                "healthy"
            } else {
                "unhealthy"
            },
            if data.health.database_healthy {
                "Healthy"
            } else {
                "Unhealthy"
            },
            if data.health.redis_healthy {
                "healthy"
            } else {
                "unhealthy"
            },
            if data.health.redis_healthy {
                "Healthy"
            } else {
                "Unhealthy"
            },
            data.health.memory_usage_percent,
            data.health.cpu_usage_percent,
            // Security events
            if data.security.failed_auth_attempts + data.security.suspicious_activities < 10 {
                "good"
            } else {
                "warning"
            },
            data.security.failed_auth_attempts + data.security.suspicious_activities,
            data.security.failed_auth_attempts,
            data.security.blocked_ips,
            data.security.rate_limit_violations,
            data.security.jwt_failures,
            // Performance
            if data.performance.avg_response_time_ms < 100.0 {
                "good"
            } else if data.performance.avg_response_time_ms < 500.0 {
                "warning"
            } else {
                "critical"
            },
            data.performance.avg_response_time_ms as u64,
            data.performance.p95_response_time_ms,
            data.performance.p99_response_time_ms,
            data.performance.requests_per_second,
            data.performance.peak_rps,
            data.performance.error_rate_percent,
            data.performance.cache_hit_rate,
            // Request statistics
            data.performance.total_requests,
            data.performance.successful_requests,
            if data.performance.total_requests > 0 {
                (data.performance.successful_requests as f64
                    / data.performance.total_requests as f64)
                    * 100.0
            } else {
                0.0
            },
            data.performance.failed_requests,
            if data.performance.total_requests > 0 {
                (data.performance.failed_requests as f64 / data.performance.total_requests as f64)
                    * 100.0
            } else {
                0.0
            },
            // Alerts
            if data.alerts.is_empty() {
                "<div style='color: #27ae60;'>✅ No active alerts</div>".to_string()
            } else {
                data.alerts
                    .iter()
                    .map(|alert| {
                        let class = match alert.severity {
                            AlertSeverity::Critical => "alert-critical",
                            AlertSeverity::Error => "alert-critical",
                            AlertSeverity::Warning => "alert-warning",
                            AlertSeverity::Info => "alert-info",
                        };
                        format!(
                            "<div class='alert {}'><strong>{}</strong>: {}</div>",
                            class, alert.title, alert.description
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("")
            },
            // System info
            data.system_info.version,
            data.system_info.environment,
            data.system_info.node_id,
            data.health.uptime_seconds,
        ))
    }
}

impl AlertManager {
    pub fn new() -> Self {
        let mut alert_rules = Vec::new();

        // Default alert rules
        alert_rules.push(AlertRule {
            id: "high_error_rate".to_string(),
            name: "High Error Rate".to_string(),
            condition: AlertCondition::HighErrorRate(5.0), // 5%
            severity: AlertSeverity::Warning,
            cooldown_seconds: 300, // 5 minutes
            last_triggered: None,
        });

        alert_rules.push(AlertRule {
            id: "high_latency".to_string(),
            name: "High Response Latency".to_string(),
            condition: AlertCondition::HighLatency(1000.0), // 1 second
            severity: AlertSeverity::Warning,
            cooldown_seconds: 300,
            last_triggered: None,
        });

        alert_rules.push(AlertRule {
            id: "high_memory".to_string(),
            name: "High Memory Usage".to_string(),
            condition: AlertCondition::HighMemoryUsage(80.0), // 80%
            severity: AlertSeverity::Warning,
            cooldown_seconds: 600, // 10 minutes
            last_triggered: None,
        });

        Self {
            active_alerts: RwLock::new(HashMap::new()),
            alert_rules: RwLock::new(alert_rules),
        }
    }

    pub async fn check_health_alerts(&self, health: &HealthMetrics) {
        let rules = self.alert_rules.read().await;
        let mut alerts = self.active_alerts.write().await;

        for rule in rules.iter() {
            let should_trigger = match &rule.condition {
                AlertCondition::HighMemoryUsage(threshold) => {
                    health.memory_usage_percent > *threshold
                }
                AlertCondition::HighCpuUsage(threshold) => health.cpu_usage_percent > *threshold,
                AlertCondition::ServiceDown(service) => {
                    if service == "database" {
                        !health.database_healthy
                    } else if service == "redis" {
                        !health.redis_healthy
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if should_trigger && !alerts.contains_key(&rule.id) {
                let alert = Alert {
                    id: rule.id.clone(),
                    title: rule.name.clone(),
                    description: format!("Health check failed: {:?}", rule.condition),
                    severity: rule.severity.clone(),
                    timestamp: current_timestamp(),
                    acknowledged: false,
                    auto_resolve: true,
                };
                alerts.insert(rule.id.clone(), alert);
                warn!("Alert triggered: {}", rule.name);
            }
        }
    }

    pub async fn check_security_alerts(&self, _event: &SecurityEvent) {
        // Implementation for security-based alerts
        info!("Security event processed for alerting");
    }

    pub async fn check_performance_alerts(&self, performance: &PerformanceAnalytics) {
        let rules = self.alert_rules.read().await;
        let mut alerts = self.active_alerts.write().await;

        for rule in rules.iter() {
            let should_trigger = match &rule.condition {
                AlertCondition::HighErrorRate(threshold) => {
                    performance.error_rate_percent > *threshold
                }
                AlertCondition::HighLatency(threshold) => {
                    performance.avg_response_time_ms > *threshold
                }
                _ => false,
            };

            if should_trigger && !alerts.contains_key(&rule.id) {
                let alert = Alert {
                    id: rule.id.clone(),
                    title: rule.name.clone(),
                    description: format!("Performance threshold exceeded: {:?}", rule.condition),
                    severity: rule.severity.clone(),
                    timestamp: current_timestamp(),
                    acknowledged: false,
                    auto_resolve: true,
                };
                alerts.insert(rule.id.clone(), alert);
                warn!("Performance alert triggered: {}", rule.name);
            }
        }
    }

    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.active_alerts.read().await;
        alerts.values().cloned().collect()
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dashboard_creation() {
        let dashboard = MonitoringDashboard::new();
        let data = dashboard.get_dashboard_data().await.unwrap();

        assert_eq!(data.health.health_score, 100);
        assert_eq!(data.security.failed_auth_attempts, 0);
        assert_eq!(data.performance.total_requests, 0);
    }

    #[tokio::test]
    async fn test_security_event_recording() {
        let dashboard = MonitoringDashboard::new();

        let event = SecurityEvent {
            timestamp: current_timestamp(),
            event_type: SecurityEventType::FailedAuthentication,
            severity: SecuritySeverity::Medium,
            source_ip: "192.168.1.1".to_string(),
            user_id: Some("user123".to_string()),
            description: "Invalid password".to_string(),
            metadata: HashMap::new(),
        };

        dashboard.record_security_event(event).await;

        let data = dashboard.get_dashboard_data().await.unwrap();
        assert_eq!(data.security.failed_auth_attempts, 1);
        assert_eq!(data.security.recent_events.len(), 1);
    }

    #[tokio::test]
    async fn test_dashboard_html_generation() {
        let dashboard = MonitoringDashboard::new();
        let html = dashboard.generate_dashboard_html().await.unwrap();

        assert!(html.contains("Rust Security Platform"));
        assert!(html.contains("System Health"));
        assert!(html.contains("Security Events"));
        assert!(html.contains("Performance"));
    }
}
