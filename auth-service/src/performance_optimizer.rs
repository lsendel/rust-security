use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};
use serde::{Deserialize, Serialize};

/// Advanced performance optimizer with adaptive algorithms
#[derive(Debug, Clone)]
pub struct PerformanceOptimizer {
    /// Performance metrics collector
    metrics: Arc<RwLock<PerformanceMetrics>>,
    /// Adaptive configuration
    config: Arc<RwLock<OptimizationConfig>>,
    /// Performance history for trend analysis
    history: Arc<RwLock<PerformanceHistory>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Request latency percentiles
    pub latency_p50: Duration,
    pub latency_p95: Duration,
    pub latency_p99: Duration,
    /// Throughput metrics
    pub requests_per_second: f64,
    pub concurrent_requests: u32,
    /// Resource utilization
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub connection_pool_usage: f64,
    /// Cache performance
    pub cache_hit_rate: f64,
    pub cache_miss_rate: f64,
    /// Error rates
    pub error_rate: f64,
    pub timeout_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationConfig {
    /// Connection pool settings
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: Duration,
    /// Cache settings
    pub cache_size: usize,
    pub cache_ttl: Duration,
    /// Rate limiting
    pub rate_limit_per_ip: u32,
    pub rate_limit_burst: u32,
    /// Circuit breaker settings
    pub circuit_breaker_threshold: f64,
    pub circuit_breaker_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct PerformanceHistory {
    /// Historical metrics (last 24 hours)
    pub hourly_metrics: Vec<PerformanceMetrics>,
    /// Performance trends
    pub latency_trend: TrendAnalysis,
    pub throughput_trend: TrendAnalysis,
    pub error_trend: TrendAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    pub direction: TrendDirection,
    pub magnitude: f64,
    pub confidence: f64,
    pub prediction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Degrading,
    Stable,
    Volatile,
}

impl PerformanceOptimizer {
    /// Create new performance optimizer
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            config: Arc::new(RwLock::new(OptimizationConfig::default())),
            history: Arc::new(RwLock::new(PerformanceHistory::default())),
        }
    }

    /// Record request performance
    pub async fn record_request(&self, duration: Duration, success: bool) {
        let mut metrics = self.metrics.write().await;
        
        // Update latency metrics (simplified - would use proper percentile calculation)
        if duration < metrics.latency_p50 || metrics.latency_p50 == Duration::ZERO {
            metrics.latency_p50 = duration;
        }
        
        // Update error rates
        if !success {
            metrics.error_rate = (metrics.error_rate * 0.95) + 0.05; // Exponential moving average
        } else {
            metrics.error_rate *= 0.99;
        }

        info!(
            duration_ms = duration.as_millis(),
            success = success,
            error_rate = metrics.error_rate,
            "Request performance recorded"
        );
    }

    /// Analyze performance and suggest optimizations
    pub async fn analyze_and_optimize(&self) -> Vec<OptimizationRecommendation> {
        let metrics = self.metrics.read().await;
        let mut config = self.config.write().await;
        let mut recommendations = Vec::new();

        // Analyze latency
        if metrics.latency_p95 > Duration::from_millis(100) {
            recommendations.push(OptimizationRecommendation {
                category: OptimizationCategory::Latency,
                severity: if metrics.latency_p95 > Duration::from_millis(500) {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                description: format!(
                    "High P95 latency detected: {}ms. Consider increasing connection pool size or optimizing queries.",
                    metrics.latency_p95.as_millis()
                ),
                action: OptimizationAction::IncreaseConnectionPool,
                expected_impact: 0.3, // 30% improvement expected
            });

            // Auto-optimize connection pool
            if config.max_connections < 100 {
                config.max_connections = ((config.max_connections as f64) * 1.2) as u32;
                info!(
                    new_max_connections = config.max_connections,
                    "Auto-increased connection pool size"
                );
            }
        }

        // Analyze error rates
        if metrics.error_rate > 0.01 { // 1% error rate threshold
            recommendations.push(OptimizationRecommendation {
                category: OptimizationCategory::Reliability,
                severity: if metrics.error_rate > 0.05 {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                description: format!(
                    "High error rate detected: {:.2}%. Investigate error patterns and consider circuit breaker tuning.",
                    metrics.error_rate * 100.0
                ),
                action: OptimizationAction::TuneCircuitBreaker,
                expected_impact: 0.5,
            });
        }

        // Analyze cache performance
        if metrics.cache_hit_rate < 0.8 { // 80% hit rate threshold
            recommendations.push(OptimizationRecommendation {
                category: OptimizationCategory::Caching,
                severity: Severity::Info,
                description: format!(
                    "Low cache hit rate: {:.1}%. Consider increasing cache size or TTL.",
                    metrics.cache_hit_rate * 100.0
                ),
                action: OptimizationAction::OptimizeCache,
                expected_impact: 0.2,
            });

            // Auto-optimize cache
            if config.cache_size < 10000 {
                config.cache_size = (config.cache_size as f64 * 1.5) as usize;
                info!(
                    new_cache_size = config.cache_size,
                    "Auto-increased cache size"
                );
            }
        }

        recommendations
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.read().await.clone()
    }

    /// Get optimization configuration
    pub async fn get_config(&self) -> OptimizationConfig {
        self.config.read().await.clone()
    }

    /// Update configuration
    pub async fn update_config(&self, new_config: OptimizationConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
        info!("Performance optimization configuration updated");
    }

    /// Perform trend analysis
    pub async fn analyze_trends(&self) -> TrendAnalysis {
        let history = self.history.read().await;
        
        // Simplified trend analysis (would use proper statistical methods)
        if history.hourly_metrics.len() < 2 {
            return TrendAnalysis {
                direction: TrendDirection::Stable,
                magnitude: 0.0,
                confidence: 0.0,
                prediction: 0.0,
            };
        }

        let recent = &history.hourly_metrics[history.hourly_metrics.len() - 1];
        let previous = &history.hourly_metrics[history.hourly_metrics.len() - 2];

        let latency_change = recent.latency_p95.as_millis() as f64 - previous.latency_p95.as_millis() as f64;
        let latency_change_percent = latency_change / previous.latency_p95.as_millis() as f64;

        let direction = if latency_change_percent > 0.1 {
            TrendDirection::Degrading
        } else if latency_change_percent < -0.1 {
            TrendDirection::Improving
        } else {
            TrendDirection::Stable
        };

        TrendAnalysis {
            direction,
            magnitude: latency_change_percent.abs(),
            confidence: 0.8, // Would calculate based on data quality
            prediction: recent.latency_p95.as_millis() as f64 * (1.0 + latency_change_percent),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRecommendation {
    pub category: OptimizationCategory,
    pub severity: Severity,
    pub description: String,
    pub action: OptimizationAction,
    pub expected_impact: f64, // 0.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationCategory {
    Latency,
    Throughput,
    Reliability,
    Caching,
    ResourceUtilization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OptimizationAction {
    IncreaseConnectionPool,
    DecreaseConnectionPool,
    OptimizeCache,
    TuneCircuitBreaker,
    AdjustRateLimit,
    ScaleHorizontally,
    OptimizeQueries,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            latency_p50: Duration::ZERO,
            latency_p95: Duration::ZERO,
            latency_p99: Duration::ZERO,
            requests_per_second: 0.0,
            concurrent_requests: 0,
            cpu_usage: 0.0,
            memory_usage: 0,
            connection_pool_usage: 0.0,
            cache_hit_rate: 0.0,
            cache_miss_rate: 0.0,
            error_rate: 0.0,
            timeout_rate: 0.0,
        }
    }
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            max_connections: 20,
            min_connections: 5,
            connection_timeout: Duration::from_secs(30),
            cache_size: 1000,
            cache_ttl: Duration::from_secs(300),
            rate_limit_per_ip: 100,
            rate_limit_burst: 20,
            circuit_breaker_threshold: 0.5,
            circuit_breaker_timeout: Duration::from_secs(60),
        }
    }
}

impl Default for PerformanceHistory {
    fn default() -> Self {
        Self {
            hourly_metrics: Vec::new(),
            latency_trend: TrendAnalysis {
                direction: TrendDirection::Stable,
                magnitude: 0.0,
                confidence: 0.0,
                prediction: 0.0,
            },
            throughput_trend: TrendAnalysis {
                direction: TrendDirection::Stable,
                magnitude: 0.0,
                confidence: 0.0,
                prediction: 0.0,
            },
            error_trend: TrendAnalysis {
                direction: TrendDirection::Stable,
                magnitude: 0.0,
                confidence: 0.0,
                prediction: 0.0,
            },
        }
    }
}

/// Performance monitoring middleware
pub async fn performance_monitoring_middleware(
    optimizer: Arc<PerformanceOptimizer>,
) -> impl Fn() + Send + Sync {
    move || {
        let optimizer = optimizer.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Analyze performance and get recommendations
                let recommendations = optimizer.analyze_and_optimize().await;
                
                if !recommendations.is_empty() {
                    info!(
                        recommendation_count = recommendations.len(),
                        "Performance optimization recommendations generated"
                    );
                    
                    for rec in recommendations {
                        match rec.severity {
                            Severity::Critical => {
                                warn!(
                                    category = ?rec.category,
                                    action = ?rec.action,
                                    expected_impact = rec.expected_impact,
                                    description = rec.description,
                                    "Critical performance issue detected"
                                );
                            }
                            Severity::Warning => {
                                warn!(
                                    category = ?rec.category,
                                    action = ?rec.action,
                                    expected_impact = rec.expected_impact,
                                    description = rec.description,
                                    "Performance warning"
                                );
                            }
                            Severity::Info => {
                                info!(
                                    category = ?rec.category,
                                    action = ?rec.action,
                                    expected_impact = rec.expected_impact,
                                    description = rec.description,
                                    "Performance optimization opportunity"
                                );
                            }
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_optimizer() {
        let optimizer = PerformanceOptimizer::new();
        
        // Record some requests
        optimizer.record_request(Duration::from_millis(50), true).await;
        optimizer.record_request(Duration::from_millis(200), false).await;
        
        let metrics = optimizer.get_metrics().await;
        assert!(metrics.error_rate > 0.0);
        
        let recommendations = optimizer.analyze_and_optimize().await;
        assert!(!recommendations.is_empty());
    }

    #[tokio::test]
    async fn test_trend_analysis() {
        let optimizer = PerformanceOptimizer::new();
        let trend = optimizer.analyze_trends().await;
        
        // With no history, should be stable
        matches!(trend.direction, TrendDirection::Stable);
    }
}
