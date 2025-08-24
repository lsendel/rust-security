use super::regression_test_suite::*;
use serde_json::{json, Value};
use std::collections::HashMap;

impl RegressionTestSuite {
    /// Test health endpoints for both services
    pub async fn test_health_endpoints(&mut self) {
        println!("\n🔍 Phase 1: Critical Security Features");

        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Health Endpoints", || async move {
            // Test auth service health
            let auth_health = client.get(&format!("{}/health", auth_base_url)).send().await?;

            if auth_health.status() != 200 {
                return Err(
                    format!("Auth service health check failed: {}", auth_health.status()).into()
                );
            }

            // Test policy service health
            let policy_health = client.get(&format!("{}/health", policy_base_url)).send().await?;

            if policy_health.status() != 200 {
                return Err(format!(
                    "Policy service health check failed: {}",
                    policy_health.status()
                )
                .into());
            }

            Ok(Some(json!({
                "auth_status": auth_health.status().as_u16(),
                "policy_status": policy_health.status().as_u16()
            })))
        })
        .await;
    }

    /// Test OAuth2 token flow
    pub async fn test_oauth_token_flow(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("OAuth2 Token Flow", || async move {
            let response = client
                .post(&format!("{}/oauth/token", auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read write")
                .send()
                .await?;

            if response.status() != 200 {
                return Err(format!("Token request failed: {}", response.status()).into());
            }

            let token_data: Value = response.json().await?;

            // Validate token response structure
            let required_fields = ["access_token", "token_type", "expires_in"];
            for field in &required_fields {
                if !token_data.get(field).is_some() {
                    return Err(format!("Missing required field: {}", field).into());
                }
            }

            // Validate token type
            if token_data["token_type"] != "Bearer" {
                return Err("Invalid token type".into());
            }

            Ok(Some(token_data))
        }).await;
    }

    /// Test token introspection
    pub async fn test_token_introspection(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Token Introspection", || async move {
            // First get a token
            let token_response = client
                .post(&format!("{}/oauth/token", auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read")
                .send()
                .await?;

            let token_data: Value = token_response.json().await?;
            let access_token = token_data["access_token"].as_str()
                .ok_or("No access token in response")?;

            // Test introspection
            let introspect_response = client
                .post(&format!("{}/oauth/introspect", auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"token": access_token}))
                .send()
                .await?;

            if introspect_response.status() != 200 {
                return Err(format!("Introspection failed: {}", introspect_response.status()).into());
            }

            let introspect_data: Value = introspect_response.json().await?;

            // Validate introspection response
            if introspect_data["active"] != true {
                return Err("Token should be active".into());
            }

            Ok(Some(introspect_data))
        }).await;
    }

    /// Test token revocation
    pub async fn test_token_revocation(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Token Revocation", || async move {
            // Get a token first
            let token_response = client
                .post(&format!("{}/oauth/token", auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(
                    "grant_type=client_credentials&client_id=test_client&client_secret=test_secret",
                )
                .send()
                .await?;

            let token_data: Value = token_response.json().await?;
            let access_token =
                token_data["access_token"].as_str().ok_or("No access token in response")?;

            // Revoke the token
            let revoke_response = client
                .post(&format!("{}/oauth/revoke", auth_base_url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(format!("token={}", access_token))
                .send()
                .await?;

            if revoke_response.status() != 200 {
                return Err(format!("Token revocation failed: {}", revoke_response.status()).into());
            }

            // Verify token is now inactive
            let introspect_response = client
                .post(&format!("{}/oauth/introspect", auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"token": access_token}))
                .send()
                .await?;

            let introspect_data: Value = introspect_response.json().await?;
            if introspect_data["active"] == true {
                return Err("Token should be inactive after revocation".into());
            }

            Ok(Some(json!({"revoked": true, "verified_inactive": true})))
        })
        .await;
    }

    /// Test OpenID Connect endpoints
    pub async fn test_openid_connect(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("OpenID Connect", || async move {
            // Test OIDC discovery document
            let discovery_response = client
                .get(&format!("{}/.well-known/openid-configuration", auth_base_url))
                .send()
                .await?;

            if discovery_response.status() != 200 {
                return Err(
                    format!("OIDC discovery failed: {}", discovery_response.status()).into()
                );
            }

            let discovery_data: Value = discovery_response.json().await?;

            // Validate required OIDC fields
            let required_fields =
                ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"];
            for field in &required_fields {
                if !discovery_data.get(field).is_some() {
                    return Err(format!("Missing OIDC field: {}", field).into());
                }
            }

            // Test OAuth2 authorization server metadata
            let oauth_metadata_response = client
                .get(&format!("{}/.well-known/oauth-authorization-server", auth_base_url))
                .send()
                .await?;

            if oauth_metadata_response.status() != 200 {
                return Err(
                    format!("OAuth metadata failed: {}", oauth_metadata_response.status()).into()
                );
            }

            Ok(Some(discovery_data))
        })
        .await;
    }

    /// Test JWKS endpoint
    pub async fn test_jwks_endpoint(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("JWKS Endpoint", || async move {
            let jwks_response = client.get(&format!("{}/jwks.json", auth_base_url)).send().await?;

            if jwks_response.status() != 200 {
                return Err(format!("JWKS request failed: {}", jwks_response.status()).into());
            }

            let jwks_data: Value = jwks_response.json().await?;

            // Validate JWKS structure
            if !jwks_data.get("keys").is_some() {
                return Err("JWKS missing keys array".into());
            }

            let keys = jwks_data["keys"].as_array().ok_or("Keys should be an array")?;

            if keys.is_empty() {
                return Err("JWKS should contain at least one key".into());
            }

            // Validate key structure
            let key = &keys[0];
            let required_key_fields = ["kty", "use", "alg", "kid"];
            for field in &required_key_fields {
                if !key.get(field).is_some() {
                    return Err(format!("Key missing field: {}", field).into());
                }
            }

            Ok(Some(jwks_data))
        })
        .await;
    }

    /// Test MFA TOTP functionality
    pub async fn test_mfa_totp(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("MFA TOTP", || async move {
            // Test TOTP registration
            let register_response = client
                .post(&format!("{}/mfa/totp/register", auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"user_id": "test_user"}))
                .send()
                .await?;

            if register_response.status() != 200 {
                return Err(
                    format!("TOTP registration failed: {}", register_response.status()).into()
                );
            }

            let register_data: Value = register_response.json().await?;

            // Validate registration response
            if !register_data.get("secret").is_some() || !register_data.get("qr_code").is_some() {
                return Err("TOTP registration missing required fields".into());
            }

            // Test backup codes generation
            let backup_response = client
                .post(&format!("{}/mfa/totp/backup-codes/generate", auth_base_url))
                .header("Content-Type", "application/json")
                .json(&json!({"user_id": "test_user"}))
                .send()
                .await?;

            if backup_response.status() != 200 {
                return Err(format!(
                    "Backup codes generation failed: {}",
                    backup_response.status()
                )
                .into());
            }

            let backup_data: Value = backup_response.json().await?;
            if !backup_data.get("backup_codes").is_some() {
                return Err("Backup codes response missing codes".into());
            }

            Ok(Some(json!({
                "totp_registered": true,
                "backup_codes_generated": true,
                "secret_length": register_data["secret"].as_str().unwrap_or("").len()
            })))
        })
        .await;
    }

    /// Test SCIM endpoints
    pub async fn test_scim_endpoints(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("SCIM Endpoints", || async move {
            // Test SCIM Users endpoint
            let users_response =
                client.get(&format!("{}/scim/v2/Users", auth_base_url)).send().await?;

            if users_response.status() != 200 {
                return Err(
                    format!("SCIM Users request failed: {}", users_response.status()).into()
                );
            }

            let users_data: Value = users_response.json().await?;

            // Validate SCIM response structure
            let required_fields = ["schemas", "totalResults", "Resources"];
            for field in &required_fields {
                if !users_data.get(field).is_some() {
                    return Err(format!("SCIM Users missing field: {}", field).into());
                }
            }

            // Test SCIM Groups endpoint
            let groups_response =
                client.get(&format!("{}/scim/v2/Groups", auth_base_url)).send().await?;

            if groups_response.status() != 200 {
                return Err(
                    format!("SCIM Groups request failed: {}", groups_response.status()).into()
                );
            }

            Ok(Some(json!({
                "users_endpoint": "working",
                "groups_endpoint": "working",
                "total_users": users_data["totalResults"]
            })))
        })
        .await;
    }

    /// Test rate limiting
    pub async fn test_rate_limiting(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Rate Limiting", || async move {
            let mut successful_requests = 0;
            let mut rate_limited_requests = 0;

            // Send multiple requests rapidly to trigger rate limiting
            for _ in 0..20 {
                let response = client
                    .post(&format!("{}/oauth/token", auth_base_url))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
                    .send()
                    .await?;

                match response.status().as_u16() {
                    200 => successful_requests += 1,
                    429 => rate_limited_requests += 1,
                    _ => {}
                }

                // Small delay to avoid overwhelming the server
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }

            // We should see some rate limiting if the feature is working
            if rate_limited_requests == 0 && successful_requests > 15 {
                return Err("Rate limiting may not be working properly".into());
            }

            Ok(Some(json!({
                "successful_requests": successful_requests,
                "rate_limited_requests": rate_limited_requests,
                "rate_limiting_active": rate_limited_requests > 0
            })))
        }).await;
    }

    /// Test security headers
    pub async fn test_security_headers(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Security Headers", || async move {
            let response = client.get(&format!("{}/health", auth_base_url)).send().await?;

            let headers = response.headers();
            let mut found_headers = HashMap::new();

            // Check for important security headers
            let security_headers = [
                "x-content-type-options",
                "x-frame-options",
                "x-xss-protection",
                "strict-transport-security",
                "content-security-policy",
                "referrer-policy",
            ];

            for header_name in &security_headers {
                if let Some(header_value) = headers.get(*header_name) {
                    found_headers.insert(
                        header_name.to_string(),
                        header_value.to_str().unwrap_or("").to_string(),
                    );
                }
            }

            if found_headers.len() < 3 {
                return Err("Insufficient security headers found".into());
            }

            Ok(Some(json!({
                "security_headers_found": found_headers.len(),
                "headers": found_headers
            })))
        })
        .await;
    }

    /// Test request signing (placeholder - would need actual implementation)
    pub async fn test_request_signing(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Request Signing", || async move {
            // This is a placeholder test since request signing requires specific implementation
            // In a real scenario, you would test HMAC signature validation

            Ok(Some(json!({
                "request_signing": "placeholder_test",
                "note": "Requires specific HMAC implementation testing"
            })))
        })
        .await;
    }

    /// Test token binding (placeholder)
    pub async fn test_token_binding(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Token Binding", || async move {
            // Placeholder for token binding tests
            // Would test that tokens are bound to client characteristics

            Ok(Some(json!({
                "token_binding": "placeholder_test",
                "note": "Requires client characteristic validation testing"
            })))
        })
        .await;
    }

    /// Test PKCE flow (placeholder)
    pub async fn test_pkce_flow(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("PKCE Flow", || async move {
            // Placeholder for PKCE testing
            // Would test code verifier/challenge generation and validation

            Ok(Some(json!({
                "pkce_flow": "placeholder_test",
                "note": "Requires authorization code flow testing"
            })))
        })
        .await;
    }

    /// Test circuit breaker (placeholder)
    pub async fn test_circuit_breaker(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Circuit Breaker", || async move {
            // Placeholder for circuit breaker testing
            // Would test fault tolerance for external dependencies

            Ok(Some(json!({
                "circuit_breaker": "placeholder_test",
                "note": "Requires external dependency failure simulation"
            })))
        })
        .await;
    }

    /// Test input validation
    pub async fn test_input_validation(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Input Validation", || async move {
            // Test with invalid inputs
            let invalid_requests = vec![
                // Invalid grant type
                ("grant_type=invalid&client_id=test&client_secret=test", 400),
                // Missing client_id
                ("grant_type=client_credentials&client_secret=test", 400),
                // Invalid client credentials
                ("grant_type=client_credentials&client_id=invalid&client_secret=invalid", 401),
            ];

            let mut validation_results = Vec::new();

            for (body, _expected_status) in invalid_requests {
                let response = client
                    .post(&format!("{}/oauth/token", auth_base_url))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await?;

                validation_results.push(json!({
                    "request": body,
                    "expected_status": expected_status,
                    "actual_status": response.status().as_u16(),
                    "correct": response.status().as_u16() == expected_status
                }));
            }

            let all_correct =
                validation_results.iter().all(|r| r["correct"].as_bool().unwrap_or(false));

            if !all_correct {
                return Err("Some input validation tests failed".into());
            }

            Ok(Some(json!({
                "validation_tests": validation_results,
                "all_passed": all_correct
            })))
        })
        .await;
    }

    /// Test audit logging (placeholder)
    pub async fn test_audit_logging(&mut self) {
        let client = self.client.clone();
        let auth_base_url = self.auth_base_url.clone();
        let policy_base_url = self.policy_base_url.clone();

        self.run_test("Audit Logging", || async move {
            // Placeholder for audit logging tests
            // Would verify that security events are properly logged

            Ok(Some(json!({
                "audit_logging": "placeholder_test",
                "note": "Requires log analysis and verification"
            })))
        })
        .await;
    }
}
