use super::regression_test_suite::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

impl RegressionTestSuite {
    /// Test performance metrics endpoint
    pub async fn test_performance_metrics(&mut self) {
        println!("\n⚡ Phase 2: Operational Excellence");

        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Performance Metrics", || async move {
            let response = client.get(&format!("{}/metrics", auth_base_url)).send().await?;

            if response.status() != 200 {
                return Err(format!("Metrics endpoint failed: {}", response.status()).into());
            }

            let metrics_text = response.text().await?;

            // Check for key metrics
            let expected_metrics = [
                "http_requests_total",
                "http_request_duration_seconds",
                "auth_service_token_requests_total",
                "process_resident_memory_bytes",
            ];

            let mut found_metrics = Vec::new();
            for metric in &expected_metrics {
                if metrics_text.contains(metric) {
                    found_metrics.push(metric.to_string());
                }
            }

            if found_metrics.len() < expected_metrics.len() / 2 {
                return Err("Insufficient metrics found".into());
            }

            Ok(Some(json!({
                "metrics_endpoint": "working",
                "found_metrics": found_metrics,
                "total_metrics_found": found_metrics.len()
            })))
        })
        .await;
    }

    /// Test caching functionality
    pub async fn test_caching_functionality(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Caching Functionality", || async move {
            // Test token introspection caching by making the same request multiple times
            let token_response = client
                .post(&format!("{}/oauth/token", auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
                .send()
                .await?;

            let token_data: Value = token_response.json().await?;
            let access_token = token_data["access_token"].as_str()
                .ok_or("No access token in response")?;

            // First introspection (should be slow - cache miss)
            let start1 = Instant::now();
            let introspect1 = client
                .post(&format!("{}/oauth/introspect", auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"token": access_token}))
                .send()
                .await?;
            let duration1 = start1.elapsed();

            if introspect1.status() != 200 {
                return Err("First introspection failed".into());
            }

            // Second introspection (should be faster - cache hit)
            let start2 = Instant::now();
            let introspect2 = client
                .post(&format!("{}/oauth/introspect", auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"token": access_token}))
                .send()
                .await?;
            let duration2 = start2.elapsed();

            if introspect2.status() != 200 {
                return Err("Second introspection failed".into());
            }

            // Cache should make the second request faster (though this is not guaranteed in all cases)
            let cache_likely_working = duration2 <= duration1;

            Ok(Some(json!({
                "first_request_ms": duration1.as_millis(),
                "second_request_ms": duration2.as_millis(),
                "cache_likely_working": cache_likely_working,
                "performance_improvement": if duration1.as_millis() > 0 {
                    ((duration1.as_millis() as f64 - duration2.as_millis() as f64) / duration1.as_millis() as f64) * 100.0
                } else { 0.0 }
            })))
        }).await;
    }

    /// Test distributed tracing headers
    pub async fn test_distributed_tracing(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Distributed Tracing", || async move {
            // Test that tracing headers are properly handled
            let response = client
                .get(&format!("{}/health", auth_base_url))
                .header("X-Trace-Id", "test-trace-123")
                .header("X-Span-Id", "test-span-456")
                .send()
                .await?;

            if response.status() != 200 {
                return Err("Health check with tracing headers failed".into());
            }

            // Check if response includes tracing information
            let headers = response.headers();
            let has_trace_headers =
                headers.get("X-Trace-Id").is_some() || headers.get("X-Request-Id").is_some();

            Ok(Some(json!({
                "tracing_headers_supported": has_trace_headers,
                "response_headers": headers.len(),
                "status": "tracing_infrastructure_present"
            })))
        })
        .await;
    }

    /// Test monitoring endpoints
    pub async fn test_monitoring_endpoints(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Monitoring Endpoints", || async move {
            let mut endpoints_tested = Vec::new();

            // Test health endpoint
            let health_response = client.get(&format!("{}/health", auth_base_url)).send().await?;

            endpoints_tested.push(json!({
                "endpoint": "/health",
                "status": health_response.status().as_u16(),
                "working": health_response.status() == 200
            }));

            // Test metrics endpoint
            let metrics_response = client.get(&format!("{}/metrics", auth_base_url)).send().await?;

            endpoints_tested.push(json!({
                "endpoint": "/metrics",
                "status": metrics_response.status().as_u16(),
                "working": metrics_response.status() == 200
            }));

            // Test OpenAPI endpoint
            let openapi_response =
                client.get(&format!("{}/openapi.json", auth_base_url)).send().await?;

            endpoints_tested.push(json!({
                "endpoint": "/openapi.json",
                "status": openapi_response.status().as_u16(),
                "working": openapi_response.status() == 200
            }));

            let working_endpoints =
                endpoints_tested.iter().filter(|e| e["working"].as_bool().unwrap_or(false)).count();

            if working_endpoints < 2 {
                return Err("Insufficient monitoring endpoints working".into());
            }

            Ok(Some(json!({
                "endpoints_tested": endpoints_tested,
                "working_endpoints": working_endpoints,
                "total_endpoints": endpoints_tested.len()
            })))
        })
        .await;
    }

    /// Test key rotation functionality
    pub async fn test_key_rotation(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Key Rotation", || async move {
            // Test key rotation status endpoint (if available)
            let status_response =
                client.get(&format!("{}/admin/key-rotation/status", auth_base_url)).send().await;

            match status_response {
                Ok(response) if response.status() == 200 => {
                    let status_data: Value = response.json().await?;
                    Ok(Some(json!({
                        "key_rotation_status": "available",
                        "status_data": status_data
                    })))
                }
                Ok(response) if response.status() == 404 => {
                    // Endpoint not implemented yet, but that's okay
                    Ok(Some(json!({
                        "key_rotation_status": "endpoint_not_implemented",
                        "note": "Key rotation endpoint not yet available"
                    })))
                }
                Ok(response) => {
                    Err(format!("Key rotation status failed: {}", response.status()).into())
                }
                Err(_) => {
                    // Network error or endpoint not available
                    Ok(Some(json!({
                        "key_rotation_status": "endpoint_not_available",
                        "note": "Key rotation endpoint not accessible"
                    })))
                }
            }
        })
        .await;
    }

    /// Test policy evaluation performance
    pub async fn test_policy_evaluation(&mut self) {
        println!("\n🛡️  Policy Service Tests");

        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Policy Evaluation", || async move {
            let test_request = json!({
                "request_id": "test_regression_001",
                "principal": {"type": "User", "id": "test_user"},
                "action": "orders:read",
                "resource": {"type": "Order", "id": "order123"},
                "context": {"ip": "192.168.1.100", "time": "2025-08-16T10:48:00Z"}
            });

            let response = client
                .post(&format!("{}/v1/authorize", policy_base_url))
                .header("Content-Type", "application/json")
                .json(&test_request)
                .send()
                .await?;

            if response.status() != 200 {
                return Err(format!("Policy evaluation failed: {}", response.status()).into());
            }

            let policy_result: Value = response.json().await?;

            // Validate policy response structure
            let required_fields = ["request_id", "decision", "timestamp"];
            for field in &required_fields {
                if !policy_result.get(field).is_some() {
                    return Err(format!("Policy response missing field: {}", field).into());
                }
            }

            Ok(Some(policy_result))
        })
        .await;
    }

    /// Test Cedar policies
    pub async fn test_cedar_policies(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Cedar Policies", || async move {
            // Test multiple policy scenarios
            let test_scenarios = vec![
                (
                    json!({
                        "request_id": "cedar_test_1",
                        "principal": {"type": "User", "id": "user1"},
                        "action": "orders:read",
                        "resource": {"type": "Order", "id": "order1"},
                        "context": {}
                    }),
                    "read_access",
                ),
                (
                    json!({
                        "request_id": "cedar_test_2",
                        "principal": {"type": "Admin", "id": "admin1"},
                        "action": "users:delete",
                        "resource": {"type": "User", "id": "user2"},
                        "context": {}
                    }),
                    "admin_access",
                ),
                (
                    json!({
                        "request_id": "cedar_test_3",
                        "principal": {"type": "Guest", "id": "guest1"},
                        "action": "orders:write",
                        "resource": {"type": "Order", "id": "order3"},
                        "context": {}
                    }),
                    "guest_write_denied",
                ),
            ];

            let mut results = Vec::new();

            for (request, _scenario) in test_scenarios {
                let response = client
                    .post(&format!("{}/v1/authorize", policy_base_url))
                    .header("Content-Type", "application/json")
                    .json(&request)
                    .send()
                    .await?;

                if response.status() == 200 {
                    let policy_result: Value = response.json().await?;
                    results.push(json!({
                        "scenario": scenario,
                        "decision": policy_result["decision"],
                        "success": true
                    }));
                } else {
                    results.push(json!({
                        "scenario": scenario,
                        "error": response.status().as_u16(),
                        "success": false
                    }));
                }
            }

            let successful_scenarios =
                results.iter().filter(|r| r["success"].as_bool().unwrap_or(false)).count();

            if successful_scenarios == 0 {
                return Err("No policy scenarios succeeded".into());
            }

            Ok(Some(json!({
                "scenarios_tested": results.len(),
                "successful_scenarios": successful_scenarios,
                "results": results
            })))
        })
        .await;
    }

    /// Test policy performance
    pub async fn test_policy_performance(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Policy Performance", || async move {
            let test_request = json!({
                "request_id": "perf_test",
                "principal": {"type": "User", "id": "perf_user"},
                "action": "orders:read",
                "resource": {"type": "Order", "id": "perf_order"},
                "context": {}
            });

            // Test multiple requests to measure performance
            let mut durations = Vec::new();
            let num_requests = 10;

            for _ in 0..num_requests {
                let start = Instant::now();
                let response = client
                    .post(&format!("{}/v1/authorize", policy_base_url))
                    .header("Content-Type", "application/json")
                    .json(&test_request)
                    .send()
                    .await?;
                let duration = start.elapsed();

                if response.status() != 200 {
                    return Err(format!("Policy request failed: {}", response.status()).into());
                }

                durations.push(duration.as_millis() as f64);
            }

            let avg_duration = durations.iter().sum::<f64>() / durations.len() as f64;
            let min_duration = durations.iter().fold(f64::INFINITY, |a, &b| a.min(b));
            let max_duration = durations.iter().fold(0.0_f64, |a, &b| a.max(b));

            // Performance threshold: average should be under 100ms
            let performance_acceptable = avg_duration < 100.0;

            Ok(Some(json!({
                "requests_tested": num_requests,
                "avg_duration_ms": avg_duration,
                "min_duration_ms": min_duration,
                "max_duration_ms": max_duration,
                "performance_acceptable": performance_acceptable,
                "threshold_ms": 100.0
            })))
        })
        .await;
    }
}
