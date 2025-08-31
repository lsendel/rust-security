//! Tests for the monitoring module.

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_http_metrics_recording() {
        let collector = MetricsCollector::new().unwrap();

        // Record some HTTP requests
        collector.record_http_request("GET", "/health", "200", Duration::from_millis(50));
        collector.record_http_request("POST", "/auth/login", "401", Duration::from_millis(150));
        collector.record_http_request("GET", "/health", "200", Duration::from_millis(25));

        // Get metrics output
        let metrics_output = collector.gather_metrics().await.unwrap();

        // Verify metrics are recorded
        assert!(metrics_output.contains("http_requests_total"));
        assert!(metrics_output.contains("http_request_duration_seconds"));
        assert!(metrics_output.contains("http_response_status_total"));

        // Verify summary contains data
        let summary = collector.get_summary().await;
        assert!(summary.contains_key("http_requests_total"));
        assert_eq!(summary["http_requests_total"], 3);
    }

    #[tokio::test]
    async fn test_authentication_metrics() {
        let collector = MetricsCollector::new().unwrap();

        // Record authentication attempts
        collector.record_auth_attempt(true, Duration::from_millis(100));
        collector.record_auth_attempt(false, Duration::from_millis(200));
        collector.record_auth_attempt(true, Duration::from_millis(80));

        let summary = collector.get_summary().await;
        assert_eq!(summary["auth_attempts_total"], 3);
        assert_eq!(summary["auth_success_total"], 2);
        assert_eq!(summary["auth_failures_total"], 1);
    }

    #[tokio::test]
    async fn test_authorization_metrics() {
        let collector = MetricsCollector::new().unwrap();

        // Record authorization requests
        collector.record_authz_request(true, Duration::from_millis(10));
        collector.record_authz_request(false, Duration::from_millis(25));
        collector.record_authz_request(true, Duration::from_millis(15));

        let summary = collector.get_summary().await;
        assert_eq!(summary["authz_requests_total"], 3);
        assert_eq!(summary["authz_allow_total"], 2);
        assert_eq!(summary["authz_deny_total"], 1);
    }

    #[tokio::test]
    async fn test_business_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_user_registered();
        collector.record_session_created();
        collector.record_token_issued();
        collector.record_token_revoked();

        let metrics_output = collector.gather_metrics().await.unwrap();
        assert!(metrics_output.contains("users_registered_total"));
        assert!(metrics_output.contains("sessions_created_total"));
        assert!(metrics_output.contains("tokens_issued_total"));
        assert!(metrics_output.contains("tokens_revoked_total"));
    }

    #[tokio::test]
    async fn test_security_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_suspicious_activity();
        collector.record_rate_limit_exceeded();
        collector.record_brute_force_attempt();

        let metrics_output = collector.gather_metrics().await.unwrap();
        assert!(metrics_output.contains("suspicious_activity_total"));
        assert!(metrics_output.contains("rate_limit_exceeded_total"));
        assert!(metrics_output.contains("brute_force_attempts_total"));
    }

    #[tokio::test]
    async fn test_database_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_db_query(Duration::from_millis(50));
        collector.record_db_error();

        let metrics_output = collector.gather_metrics().await.unwrap();
        assert!(metrics_output.contains("db_query_duration_seconds"));
        assert!(metrics_output.contains("db_errors_total"));
    }

    #[tokio::test]
    async fn test_cache_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.record_cache_hit();
        collector.record_cache_miss();
        collector.record_cache_eviction();

        let metrics_output = collector.gather_metrics().await.unwrap();
        assert!(metrics_output.contains("cache_hits_total"));
        assert!(metrics_output.contains("cache_misses_total"));
        assert!(metrics_output.contains("cache_evictions_total"));
    }

    #[tokio::test]
    async fn test_system_metrics() {
        let collector = MetricsCollector::new().unwrap();

        collector.update_memory_usage(1024 * 1024 * 100); // 100MB
        collector.update_cpu_usage(45.5);
        collector.update_active_connections(150);
        collector.update_db_connections(10);

        let metrics_output = collector.gather_metrics().await.unwrap();
        assert!(metrics_output.contains("memory_usage_bytes"));
        assert!(metrics_output.contains("cpu_usage_percent"));
        assert!(metrics_output.contains("active_connections"));
        assert!(metrics_output.contains("db_connections_active"));
    }

    #[tokio::test]
    async fn test_uptime_tracking() {
        let collector = MetricsCollector::new().unwrap();

        // Uptime should be very small (just created)
        let uptime = collector.uptime_seconds();
        assert!(uptime >= 0.0);
        assert!(uptime < 1.0); // Less than 1 second since creation
    }

    #[tokio::test]
    async fn test_custom_metrics() {
        let collector = MetricsCollector::new().unwrap();

        // Create a simple counter
        let counter = prometheus::Counter::new("test_custom_metric", "Test custom metric").unwrap();

        // Register custom metric
        let result = collector
            .register_custom_metric("test_metric".to_string(), Box::new(counter.clone()))
            .await;
        assert!(result.is_ok());

        // Increment the custom metric
        counter.inc();

        // Check that it's included in the output
        let metrics_output = collector.gather_metrics().await.unwrap();
        assert!(metrics_output.contains("test_custom_metric"));
    }

    #[tokio::test]
    async fn test_custom_metric_errors() {
        let collector = MetricsCollector::new().unwrap();

        let counter = prometheus::Counter::new("test_metric", "Test metric").unwrap();

        // Register metric first time - should succeed
        let result1 = collector
            .register_custom_metric("test_metric".to_string(), Box::new(counter.clone()))
            .await;
        assert!(result1.is_ok());

        let counter2 = prometheus::Counter::new("test_metric2", "Test metric 2").unwrap();

        // Try to register with same name - should fail
        let result2 = collector
            .register_custom_metric("test_metric".to_string(), Box::new(counter2))
            .await;
        assert!(result2.is_err());
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let checker = HealthChecker::new();
        assert!(checker.get_check_names().await.is_empty());
    }

    #[tokio::test]
    async fn test_health_status_enum() {
        let healthy = HealthStatus::Healthy;
        let degraded = HealthStatus::Degraded;
        let unhealthy = HealthStatus::Unhealthy;

        assert_eq!(healthy, HealthStatus::Healthy);
        assert_ne!(healthy, degraded);
        assert_ne!(healthy, unhealthy);
    }

    #[tokio::test]
    async fn test_health_check_result_creation() {
        let result = HealthCheckResult {
            name: "test_check".to_string(),
            status: HealthStatus::Healthy,
            message: "All good".to_string(),
            duration_ms: 100,
            timestamp: chrono::Utc::now(),
            details: Some(std::collections::HashMap::from([(
                "version".to_string(),
                "1.0.0".into(),
            )])),
        };

        assert_eq!(result.name, "test_check");
        assert_eq!(result.status, HealthStatus::Healthy);
        assert_eq!(result.message, "All good");
        assert_eq!(result.duration_ms, 100);
        assert!(result.details.is_some());
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_performance_monitor_creation() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(100));
        assert!(!monitor.get_all_metrics().await.is_empty()); // Default metrics
    }

    #[tokio::test]
    async fn test_operation_recording() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(100));

        monitor
            .record_operation("test_op", Duration::from_millis(50), true)
            .await;
        monitor
            .record_operation("test_op", Duration::from_millis(75), true)
            .await;
        monitor
            .record_operation("test_op", Duration::from_millis(200), false)
            .await;

        let metrics = monitor.get_operation_metrics("test_op").await.unwrap();
        assert_eq!(metrics.operation_name, "test_op");
        assert_eq!(metrics.count, 2); // Only successful operations
        assert_eq!(metrics.error_count, 1);
    }

    #[tokio::test]
    async fn test_slow_operations_detection() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(50));

        monitor
            .record_operation("slow_op", Duration::from_millis(100), true)
            .await;
        monitor
            .record_operation("fast_op", Duration::from_millis(10), true)
            .await;

        let slow_ops = monitor.get_slow_operations().await;
        assert_eq!(slow_ops.len(), 1);
        assert_eq!(slow_ops[0].operation_name, "slow_op");
    }

    #[tokio::test]
    async fn test_high_error_rate_detection() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(100));

        // Record 10 operations with 6 errors (60% error rate)
        for i in 0..10 {
            let success = i < 4; // 4 success, 6 failures
            monitor
                .record_operation("error_prone_op", Duration::from_millis(50), success)
                .await;
        }

        let high_error_ops = monitor.get_high_error_operations(0.5).await; // 50% threshold
        assert_eq!(high_error_ops.len(), 1);
        assert_eq!(high_error_ops[0].operation_name, "error_prone_op");
        assert_eq!(high_error_ops[0].error_count, 6);
    }

    #[test]
    fn test_performance_profile() {
        let mut profile = PerformanceProfile::new("test", 10);

        profile.record_sample(Duration::from_millis(10), true);
        profile.record_sample(Duration::from_millis(20), true);
        profile.record_sample(Duration::from_millis(30), false);

        let metrics = profile.get_metrics();

        assert_eq!(metrics.count, 2);
        assert_eq!(metrics.error_count, 1);
        assert_eq!(metrics.average_duration, Duration::from_millis(15));
        assert_eq!(metrics.min_duration, Duration::from_millis(10));
        assert_eq!(metrics.max_duration, Duration::from_millis(20));
    }

    #[tokio::test]
    async fn test_performance_summary() {
        let monitor = PerformanceMonitor::new(100, Duration::from_millis(100));

        monitor
            .record_operation("op1", Duration::from_millis(50), true)
            .await;
        monitor
            .record_operation("op2", Duration::from_millis(75), false)
            .await;

        let summary = monitor.get_summary().await;
        assert_eq!(summary.total_operations, 2);
        assert_eq!(summary.total_samples, 1); // Only successful operations
        assert_eq!(summary.total_errors, 1);
        assert_eq!(summary.slow_operations_count, 0); // Neither operation is slow
        assert_eq!(summary.high_error_operations_count, 1); // op2 has high error rate
    }
}
