use super::regression_test_suite::*;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::time::timeout;

impl RegressionTestSuite {
    /// Test complete end-to-end flow
    pub async fn test_end_to_end_flow(&mut self) {
        println!("\n🔄 Integration & End-to-End Tests");

        self.run_test("End-to-End Flow", || async {
            // Step 1: Get OAuth token
            let token_response = self.client
                .post(&format!("{}/oauth/token", self.auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=orders:read")
                .send()
                .await?;

            if token_response.status() != 200 {
                return Err("Step 1 failed: Token generation".into());
            }

            let token_data: Value = token_response.json().await?;
            let access_token = token_data["access_token"].as_str()
                .ok_or("No access token in response")?;

            // Step 2: Introspect token
            let introspect_response = self.client
                .post(&format!("{}/oauth/introspect", self.auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"token": access_token}))
                .send()
                .await?;

            if introspect_response.status() != 200 {
                return Err("Step 2 failed: Token introspection".into());
            }

            let introspect_data: Value = introspect_response.json().await?;
            if introspect_data["active"] != true {
                return Err("Step 2 failed: Token not active".into());
            }

            // Step 3: Use token for policy evaluation
            let policy_request = json!({
                "request_id": "e2e_test",
                "principal": {"type": "User", "id": "test_user"},
                "action": "orders:read",
                "resource": {"type": "Order", "id": "order123"},
                "context": {
                    "token": access_token,
                    "client_id": introspect_data["client_id"]
                }
            });

            let policy_response = self.client
                .post(&format!("{}/v1/authorize", self.policy_base_url))
                .header("Content-Type", "application/json")
                .json(&policy_request)
                .send()
                .await?;

            if policy_response.status() != 200 {
                return Err("Step 3 failed: Policy evaluation".into());
            }

            let policy_result: Value = policy_response.json().await?;

            // Step 4: Revoke token
            let revoke_response = self.client
                .post(&format!("{}/oauth/revoke", self.auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(&format!("token={}", access_token))
                .send()
                .await?;

            if revoke_response.status() != 200 {
                return Err("Step 4 failed: Token revocation".into());
            }

            // Step 5: Verify token is revoked
            let final_introspect = self.client
                .post(&format!("{}/oauth/introspect", self.auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"token": access_token}))
                .send()
                .await?;

            let final_data: Value = final_introspect.json().await?;
            if final_data["active"] == true {
                return Err("Step 5 failed: Token still active after revocation".into());
            }

            Ok(Some(json!({
                "steps_completed": 5,
                "token_generated": true,
                "token_introspected": true,
                "policy_evaluated": true,
                "policy_decision": policy_result["decision"],
                "token_revoked": true,
                "revocation_verified": true
            })))
        }).await;
    }

    /// Test concurrent operations
    pub async fn test_concurrent_operations(&mut self) {
        self.run_test("Concurrent Operations", || async {
            let concurrent_requests = 10;
            let mut handles = Vec::new();

            // Launch concurrent token requests
            for i in 0..concurrent_requests {
                let client = self.client.clone();
                let auth_url = self.auth_base_url.clone();

                let handle = tokio::spawn(async move {
                    let response = client
                        .post(&format!("{}/oauth/token", auth_url))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .body(&format!("grant_type=client_credentials&client_id=test_client_{}&client_secret=test_secret&scope=read", i))
                        .send()
                        .await;

                    match response {
                        Ok(resp) if resp.status() == 200 => Ok(i),
                        Ok(resp) => Err(format!("Request {} failed with status {}", i, resp.status())),
                        Err(e) => Err(format!("Request {} failed: {}", i, e))
                    }
                });

                handles.push(handle);
            }

            // Wait for all requests to complete
            let mut successful_requests = 0;
            let mut failed_requests = 0;
            let mut errors = Vec::new();

            for handle in handles {
                match timeout(Duration::from_secs(10), handle).await {
                    Ok(Ok(Ok(_))) => successful_requests += 1,
                    Ok(Ok(Err(e))) => {
                        failed_requests += 1;
                        errors.push(e);
                    }
                    Ok(Err(e)) => {
                        failed_requests += 1;
                        errors.push(format!("Task error: {}", e));
                    }
                    Err(_) => {
                        failed_requests += 1;
                        errors.push("Request timeout".to_string());
                    }
                }
            }

            // At least 70% of requests should succeed
            let success_rate = (successful_requests as f64 / concurrent_requests as f64) * 100.0;
            if success_rate < 70.0 {
                return Err(format!("Concurrent operations success rate too low: {:.1}%", success_rate).into());
            }

            Ok(Some(json!({
                "concurrent_requests": concurrent_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": success_rate,
                "errors": errors
            })))
        }).await;
    }

    /// Test error handling
    pub async fn test_error_handling(&mut self) {
        self.run_test("Error Handling", || async {
            let error_scenarios = vec![
                // Invalid endpoint
                (format!("{}/invalid/endpoint", self.auth_base_url), "GET", None, 404),
                // Invalid method
                (format!("{}/oauth/token", self.auth_base_url), "GET", None, 405),
                // Invalid JSON
                (
                    format!("{}/oauth/introspect", self.auth_base_url),
                    "POST",
                    Some("{invalid json}"),
                    400,
                ),
                // Missing required fields
                (
                    format!("{}/oauth/token", self.auth_base_url),
                    "POST",
                    Some("grant_type=client_credentials"),
                    400,
                ),
            ];

            let mut error_results = Vec::new();

            for (url, method, body, expected_status) in error_scenarios {
                let request = match method {
                    "GET" => self.client.get(&url),
                    "POST" => {
                        let mut req = self.client.post(&url);
                        if let Some(body_content) = body {
                            req = req.header("Content-Type", "application/json").body(body_content);
                        }
                        req
                    }
                    _ => continue,
                };

                let response = request.send().await?;
                let actual_status = response.status().as_u16();

                error_results.push(json!({
                    "url": url,
                    "method": method,
                    "expected_status": expected_status,
                    "actual_status": actual_status,
                    "correct": actual_status == expected_status
                }));
            }

            let correct_errors =
                error_results.iter().filter(|r| r["correct"].as_bool().unwrap_or(false)).count();

            let error_handling_rate = (correct_errors as f64 / error_results.len() as f64) * 100.0;

            if error_handling_rate < 75.0 {
                return Err(
                    format!("Error handling rate too low: {:.1}%", error_handling_rate).into()
                );
            }

            Ok(Some(json!({
                "error_scenarios_tested": error_results.len(),
                "correct_error_responses": correct_errors,
                "error_handling_rate": error_handling_rate,
                "results": error_results
            })))
        })
        .await;
    }

    /// Test failover scenarios
    pub async fn test_failover_scenarios(&mut self) {
        self.run_test("Failover Scenarios", || async {
            // Test service resilience by making requests when one service might be under load
            let mut resilience_results = Vec::new();

            // Test auth service resilience
            let auth_start = Instant::now();
            let auth_response = self
                .client
                .get(&format!("{}/health", self.auth_base_url))
                .timeout(Duration::from_secs(5))
                .send()
                .await;

            match auth_response {
                Ok(resp) => {
                    resilience_results.push(json!({
                        "service": "auth",
                        "status": resp.status().as_u16(),
                        "response_time_ms": auth_start.elapsed().as_millis(),
                        "available": resp.status() == 200
                    }));
                }
                Err(e) => {
                    resilience_results.push(json!({
                        "service": "auth",
                        "error": e.to_string(),
                        "available": false
                    }));
                }
            }

            // Test policy service resilience
            let policy_start = Instant::now();
            let policy_response = self
                .client
                .get(&format!("{}/health", self.policy_base_url))
                .timeout(Duration::from_secs(5))
                .send()
                .await;

            match policy_response {
                Ok(resp) => {
                    resilience_results.push(json!({
                        "service": "policy",
                        "status": resp.status().as_u16(),
                        "response_time_ms": policy_start.elapsed().as_millis(),
                        "available": resp.status() == 200
                    }));
                }
                Err(e) => {
                    resilience_results.push(json!({
                        "service": "policy",
                        "error": e.to_string(),
                        "available": false
                    }));
                }
            }

            let available_services = resilience_results
                .iter()
                .filter(|r| r["available"].as_bool().unwrap_or(false))
                .count();

            // At least one service should be available
            if available_services == 0 {
                return Err("No services available during failover test".into());
            }

            Ok(Some(json!({
                "services_tested": resilience_results.len(),
                "available_services": available_services,
                "resilience_results": resilience_results
            })))
        })
        .await;
    }
}
