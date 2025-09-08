//! # Security Monitoring Dashboard
//!
//! Real-time security monitoring dashboard with metrics visualization.
//!
//! ## Usage
//!
//! ```bash
//! # Start dashboard server
//! cargo run --bin security_dashboard
//!
//! # Custom port and configuration
//! cargo run --bin security_dashboard -- --port 3000 --refresh-interval 5
//!
//! # Export metrics to file
//! cargo run --bin security_dashboard -- --export-metrics metrics.json
//! ```

use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration, Instant};
use tracing::{info, warn, error};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .json()
        .init();

    let args: Vec<String> = std::env::args().collect();
    let config = parse_dashboard_config(&args);

    info!("Starting security monitoring dashboard");
    info!("Configuration: {:?}", config);

    if let Some(export_file) = &config.export_file {
        // Export mode: collect and export metrics
        export_security_metrics(export_file).await;
        return;
    }

    // Dashboard mode: start web server
    let dashboard = Arc::new(SecurityDashboard::new(config.clone()));
    
    // Start metrics collection
    let metrics_collector = dashboard.clone();
    tokio::spawn(async move {
        metrics_collector.start_metrics_collection().await;
    });

    // Create web application
    let app = Router::new()
        .route("/", get(dashboard_home))
        .route("/api/metrics", get({
            let dashboard = dashboard.clone();
            move |query| get_metrics(dashboard, query)
        }))
        .route("/api/alerts", get({
            let dashboard = dashboard.clone();
            move || get_active_alerts(dashboard)
        }))
        .route("/health", get(health_check))
        .with_state(dashboard);

    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    info!("Security dashboard running on http://{}", addr);
    info!("Open your browser and navigate to the dashboard");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug, Clone)]
struct DashboardConfig {
    port: u16,
    refresh_interval_seconds: u64,
    export_file: Option<String>,
}

fn parse_dashboard_config(args: &[String]) -> DashboardConfig {
    let mut config = DashboardConfig {
        port: 8090,
        refresh_interval_seconds: 10,
        export_file: None,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                config.port = args[i + 1].parse().unwrap_or(8090);
                i += 2;
            }
            "--refresh-interval" if i + 1 < args.len() => {
                config.refresh_interval_seconds = args[i + 1].parse().unwrap_or(10);
                i += 2;
            }
            "--export-metrics" if i + 1 < args.len() => {
                config.export_file = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    config
}

#[derive(Debug, Clone)]
struct SecurityDashboard {
    config: DashboardConfig,
    metrics: Arc<RwLock<SecurityMetrics>>,
    alerts: Arc<RwLock<Vec<SecurityAlert>>>,
}

impl SecurityDashboard {
    fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RwLock::new(SecurityMetrics::new())),
            alerts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn start_metrics_collection(&self) {
        let mut interval = interval(Duration::from_secs(self.config.refresh_interval_seconds));
        
        loop {
            interval.tick().await;
            
            // Collect current metrics
            let current_metrics = collect_security_metrics().await;
            
            // Update stored metrics
            {
                let mut metrics = self.metrics.write().await;
                metrics.update(current_metrics);
            }
            
            // Check for alerts
            self.check_security_alerts().await;
        }
    }

    async fn check_security_alerts(&self) {
        let metrics = self.metrics.read().await;
        let mut alerts = self.alerts.write().await;
        
        // Clear old alerts
        alerts.clear();
        
        // Check for high rate limit violations
        if metrics.rate_limit_violations_per_minute > 100 {
            alerts.push(SecurityAlert {
                id: "rate_limit_high".to_string(),
                severity: AlertSeverity::High,
                title: "High Rate Limit Violations".to_string(),
                message: format!("Rate limit violations: {} per minute", metrics.rate_limit_violations_per_minute),
                timestamp: chrono::Utc::now(),
                resolved: false,
            });
        }
        
        // Check for failed authentication rate
        if metrics.authentication_failures_per_minute > 50 {
            alerts.push(SecurityAlert {
                id: "auth_failures_high".to_string(),
                severity: AlertSeverity::Critical,
                title: "High Authentication Failure Rate".to_string(),
                message: format!("Authentication failures: {} per minute", metrics.authentication_failures_per_minute),
                timestamp: chrono::Utc::now(),
                resolved: false,
            });
        }
        
        // Check for banned IPs
        if metrics.banned_ips_count > 10 {
            alerts.push(SecurityAlert {
                id: "banned_ips_high".to_string(),
                severity: AlertSeverity::Medium,
                title: "High Number of Banned IPs".to_string(),
                message: format!("Currently banned IPs: {}", metrics.banned_ips_count),
                timestamp: chrono::Utc::now(),
                resolved: false,
            });
        }

        // Check system performance
        if metrics.avg_response_time_ms > 1000.0 {
            alerts.push(SecurityAlert {
                id: "response_time_high".to_string(),
                severity: AlertSeverity::Medium,
                title: "High Response Times".to_string(),
                message: format!("Average response time: {:.2}ms", metrics.avg_response_time_ms),
                timestamp: chrono::Utc::now(),
                resolved: false,
            });
        }

        if !alerts.is_empty() {
            warn!("Security alerts detected: {} active alerts", alerts.len());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityMetrics {
    // Authentication metrics
    pub authentication_requests_per_minute: u64,
    pub authentication_failures_per_minute: u64,
    pub authentication_success_rate: f64,
    
    // Rate limiting metrics
    pub rate_limit_violations_per_minute: u64,
    pub banned_ips_count: u64,
    pub active_rate_limits: u64,
    
    // System performance metrics
    pub avg_response_time_ms: f64,
    pub requests_per_second: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    
    // Cryptographic metrics
    pub jwt_tokens_issued_per_minute: u64,
    pub jwt_validations_per_minute: u64,
    pub encryption_operations_per_minute: u64,
    pub crypto_error_rate: f64,
    
    // Security events
    pub security_events_per_minute: HashMap<String, u64>,
    pub threat_detection_triggers: u64,
    
    // Compliance metrics  
    pub audit_events_logged: u64,
    pub configuration_compliance_score: f64,
    
    // Timestamp of last update
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl SecurityMetrics {
    fn new() -> Self {
        Self {
            authentication_requests_per_minute: 0,
            authentication_failures_per_minute: 0,
            authentication_success_rate: 100.0,
            rate_limit_violations_per_minute: 0,
            banned_ips_count: 0,
            active_rate_limits: 0,
            avg_response_time_ms: 0.0,
            requests_per_second: 0.0,
            memory_usage_mb: 0.0,
            cpu_usage_percent: 0.0,
            jwt_tokens_issued_per_minute: 0,
            jwt_validations_per_minute: 0,
            encryption_operations_per_minute: 0,
            crypto_error_rate: 0.0,
            security_events_per_minute: HashMap::new(),
            threat_detection_triggers: 0,
            audit_events_logged: 0,
            configuration_compliance_score: 100.0,
            last_updated: chrono::Utc::now(),
        }
    }
    
    fn update(&mut self, new_metrics: SecurityMetrics) {
        *self = new_metrics;
        self.last_updated = chrono::Utc::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityAlert {
    pub id: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// Mock function to collect security metrics (in real implementation, this would query actual systems)
async fn collect_security_metrics() -> SecurityMetrics {
    // Simulate collecting metrics from various sources
    use fastrand::Rng;
    let rng = Rng::new();
    
    let mut security_events = HashMap::new();
    security_events.insert("AUTHENTICATION".to_string(), rng.u64(0..50));
    security_events.insert("RATE_LIMITING".to_string(), rng.u64(0..30));
    security_events.insert("THREAT_DETECTION".to_string(), rng.u64(0..10));
    
    SecurityMetrics {
        authentication_requests_per_minute: rng.u64(100..1000),
        authentication_failures_per_minute: rng.u64(0..100),
        authentication_success_rate: 100.0 - (rng.f64() * 10.0),
        rate_limit_violations_per_minute: rng.u64(0..200),
        banned_ips_count: rng.u64(0..50),
        active_rate_limits: rng.u64(10..100),
        avg_response_time_ms: rng.f64() * 500.0 + 50.0,
        requests_per_second: rng.f64() * 100.0 + 10.0,
        memory_usage_mb: rng.f64() * 500.0 + 100.0,
        cpu_usage_percent: rng.f64() * 80.0 + 5.0,
        jwt_tokens_issued_per_minute: rng.u64(50..500),
        jwt_validations_per_minute: rng.u64(100..1000),
        encryption_operations_per_minute: rng.u64(10..200),
        crypto_error_rate: rng.f64() * 2.0,
        security_events_per_minute: security_events,
        threat_detection_triggers: rng.u64(0..20),
        audit_events_logged: rng.u64(100..2000),
        configuration_compliance_score: 95.0 + (rng.f64() * 5.0),
        last_updated: chrono::Utc::now(),
    }
}

// Web handlers

async fn dashboard_home() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Monitoring Dashboard</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: #f5f5f5; 
            color: #333;
        }
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header h1 { 
            color: #2c3e50; 
            margin: 0;
        }
        .dashboard-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px;
        }
        .metric-card { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-card h3 { 
            margin: 0 0 15px 0; 
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .metric-value { 
            font-size: 2em; 
            font-weight: bold; 
            color: #27ae60;
        }
        .metric-label { 
            color: #7f8c8d; 
            margin-top: 5px;
        }
        .alerts-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .alert {
            padding: 15px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 5px solid;
        }
        .alert-critical { border-left-color: #e74c3c; background: #fdf2f2; }
        .alert-high { border-left-color: #f39c12; background: #fef9e7; }
        .alert-medium { border-left-color: #f1c40f; background: #fefdf7; }
        .alert-low { border-left-color: #3498db; background: #f2f8ff; }
        .alert-info { border-left-color: #95a5a6; background: #f8f9fa; }
        .refresh-info {
            text-align: center;
            color: #7f8c8d;
            margin-top: 20px;
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-good { background-color: #27ae60; }
        .status-warning { background-color: #f39c12; }
        .status-critical { background-color: #e74c3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Monitoring Dashboard</h1>
        <p>Real-time security metrics and alerts for authentication service</p>
    </div>

    <div class="alerts-section">
        <h2>🚨 Active Security Alerts</h2>
        <div id="alerts">Loading alerts...</div>
    </div>

    <div class="dashboard-grid">
        <div class="metric-card">
            <h3>🔐 Authentication</h3>
            <div class="metric-value" id="auth-rate">-</div>
            <div class="metric-label">Requests per minute</div>
            <div style="margin-top: 10px;">
                <span class="status-indicator status-good"></span>Success Rate: <span id="success-rate">-</span>%
            </div>
            <div style="margin-top: 5px;">
                <span class="status-indicator status-warning"></span>Failures: <span id="auth-failures">-</span>/min
            </div>
        </div>

        <div class="metric-card">
            <h3>🛡️ Rate Limiting</h3>
            <div class="metric-value" id="rate-violations">-</div>
            <div class="metric-label">Violations per minute</div>
            <div style="margin-top: 10px;">
                <span class="status-indicator status-critical"></span>Banned IPs: <span id="banned-ips">-</span>
            </div>
            <div style="margin-top: 5px;">
                <span class="status-indicator status-good"></span>Active Limits: <span id="active-limits">-</span>
            </div>
        </div>

        <div class="metric-card">
            <h3>⚡ Performance</h3>
            <div class="metric-value" id="response-time">-</div>
            <div class="metric-label">Avg response time (ms)</div>
            <div style="margin-top: 10px;">
                <span class="status-indicator status-good"></span>RPS: <span id="requests-per-sec">-</span>
            </div>
            <div style="margin-top: 5px;">
                <span class="status-indicator status-warning"></span>CPU: <span id="cpu-usage">-</span>%
            </div>
        </div>

        <div class="metric-card">
            <h3>🔑 Cryptography</h3>
            <div class="metric-value" id="jwt-issued">-</div>
            <div class="metric-label">JWT tokens issued/min</div>
            <div style="margin-top: 10px;">
                <span class="status-indicator status-good"></span>JWT Validations: <span id="jwt-validations">-</span>/min
            </div>
            <div style="margin-top: 5px;">
                <span class="status-indicator status-warning"></span>Crypto Errors: <span id="crypto-errors">-</span>%
            </div>
        </div>

        <div class="metric-card">
            <h3>🔍 Threat Detection</h3>
            <div class="metric-value" id="threat-triggers">-</div>
            <div class="metric-label">Detection triggers</div>
            <div style="margin-top: 10px;">
                <span class="status-indicator status-good"></span>Security Events: <span id="security-events">-</span>/min
            </div>
        </div>

        <div class="metric-card">
            <h3>📋 Compliance</h3>
            <div class="metric-value" id="compliance-score">-</div>
            <div class="metric-label">Configuration compliance %</div>
            <div style="margin-top: 10px;">
                <span class="status-indicator status-good"></span>Audit Events: <span id="audit-events">-</span>
            </div>
        </div>
    </div>

    <div class="refresh-info">
        <p>⏱️ Dashboard refreshes every 10 seconds</p>
        <p>Last updated: <span id="last-updated">-</span></p>
    </div>

    <script>
        function updateDashboard() {
            // Fetch metrics
            fetch('/api/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('auth-rate').textContent = data.authentication_requests_per_minute;
                    document.getElementById('success-rate').textContent = data.authentication_success_rate.toFixed(1);
                    document.getElementById('auth-failures').textContent = data.authentication_failures_per_minute;
                    
                    document.getElementById('rate-violations').textContent = data.rate_limit_violations_per_minute;
                    document.getElementById('banned-ips').textContent = data.banned_ips_count;
                    document.getElementById('active-limits').textContent = data.active_rate_limits;
                    
                    document.getElementById('response-time').textContent = data.avg_response_time_ms.toFixed(1);
                    document.getElementById('requests-per-sec').textContent = data.requests_per_second.toFixed(1);
                    document.getElementById('cpu-usage').textContent = data.cpu_usage_percent.toFixed(1);
                    
                    document.getElementById('jwt-issued').textContent = data.jwt_tokens_issued_per_minute;
                    document.getElementById('jwt-validations').textContent = data.jwt_validations_per_minute;
                    document.getElementById('crypto-errors').textContent = data.crypto_error_rate.toFixed(2);
                    
                    document.getElementById('threat-triggers').textContent = data.threat_detection_triggers;
                    
                    const totalSecurityEvents = Object.values(data.security_events_per_minute).reduce((a, b) => a + b, 0);
                    document.getElementById('security-events').textContent = totalSecurityEvents;
                    
                    document.getElementById('compliance-score').textContent = data.configuration_compliance_score.toFixed(1);
                    document.getElementById('audit-events').textContent = data.audit_events_logged;
                    
                    document.getElementById('last-updated').textContent = new Date(data.last_updated).toLocaleString();
                })
                .catch(error => console.error('Error fetching metrics:', error));

            // Fetch alerts
            fetch('/api/alerts')
                .then(response => response.json())
                .then(alerts => {
                    const alertsDiv = document.getElementById('alerts');
                    
                    if (alerts.length === 0) {
                        alertsDiv.innerHTML = '<div style="color: #27ae60; font-weight: bold;">✅ No active security alerts</div>';
                    } else {
                        alertsDiv.innerHTML = alerts.map(alert => `
                            <div class="alert alert-${alert.severity.toLowerCase()}">
                                <strong>${alert.title}</strong><br>
                                ${alert.message}<br>
                                <small>Detected: ${new Date(alert.timestamp).toLocaleString()}</small>
                            </div>
                        `).join('');
                    }
                })
                .catch(error => console.error('Error fetching alerts:', error));
        }

        // Update dashboard every 10 seconds
        updateDashboard();
        setInterval(updateDashboard, 10000);
    </script>
</body>
</html>
    "#)
}

#[derive(Deserialize)]
struct MetricsQuery {
    #[serde(default)]
    format: String,
}

async fn get_metrics(
    dashboard: Arc<SecurityDashboard>, 
    Query(query): Query<MetricsQuery>
) -> Json<SecurityMetrics> {
    let metrics = dashboard.metrics.read().await;
    Json(metrics.clone())
}

async fn get_active_alerts(dashboard: Arc<SecurityDashboard>) -> Json<Vec<SecurityAlert>> {
    let alerts = dashboard.alerts.read().await;
    Json(alerts.clone())
}

async fn health_check() -> &'static str {
    "OK"
}

async fn export_security_metrics(export_file: &str) {
    info!("Exporting security metrics to {}", export_file);
    
    let metrics = collect_security_metrics().await;
    
    match serde_json::to_string_pretty(&metrics) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(export_file, json).await {
                error!("Failed to write metrics file {}: {}", export_file, e);
                std::process::exit(1);
            }
            info!("Security metrics exported successfully to {}", export_file);
        }
        Err(e) => {
            error!("Failed to serialize metrics: {}", e);
            std::process::exit(1);
        }
    }
}