//! Comprehensive `OpenAPI` Endpoints Test Suite
//! Tests all discovered API endpoints in the Rust Security Platform

use axum::http::StatusCode;
use reqwest::{Client, Response};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::timeout;

const BASE_URL: &str = "http://localhost:8080";
const POLICY_SERVICE_URL: &str = "http://localhost:8081";
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct TestResult {
    endpoint: String,
    method: String,
    status: StatusCode,
    success: bool,
    duration_ms: u128,
    error: Option<String>,
}

struct ApiTestClient {
    client: Client,
    auth_token: Option<String>,
}

impl ApiTestClient {
    fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            auth_token: None,
        }
    }

    async fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    async fn request(
        &self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> Result<Response, String> {
        let mut request = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "PATCH" => self.client.patch(url),
            "DELETE" => self.client.delete(url),
            _ => return Err(format!("Unsupported method: {method}")),
        };

        if let Some(token) = &self.auth_token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }

        if let Some(body) = body {
            request = request.json(&body);
        }

        request
            .send()
            .await
            .map_err(|e| format!("Request failed: {e}"))
    }
}

// AUTH SERVICE ENDPOINTS TESTS

#[tokio::test]
async fn test_auth_service_health() {
    let client = ApiTestClient::new();
    let response = client
        .request("GET", &format!("{BASE_URL}/health"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "rust-security-auth-service");
}

#[tokio::test]
async fn test_auth_service_status() {
    let client = ApiTestClient::new();
    let response = client
        .request("GET", &format!("{BASE_URL}/api/v1/status"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["service"], "rust-security-auth-service");
    assert_eq!(body["status"], "running");
}

#[tokio::test]
async fn test_user_registration() {
    let client = ApiTestClient::new();
    let test_user = json!({
        "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
        "password": "TestPassword123!",
        "name": "Test User"
    });

    let response = client
        .request(
            "POST",
            &format!("{BASE_URL}/api/v1/auth/register"),
            Some(test_user),
        )
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["user_id"].is_string());
    assert!(body["email"].is_string());
}

#[tokio::test]
async fn test_user_login() {
    let mut client = ApiTestClient::new();

    // First register a user
    let test_email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let test_password = "TestPassword123!";

    let register_payload = json!({
        "email": &test_email,
        "password": test_password,
        "name": "Test User"
    });

    client
        .request(
            "POST",
            &format!("{BASE_URL}/api/v1/auth/register"),
            Some(register_payload),
        )
        .await
        .expect("Failed to register user");

    // Now test login
    let login_payload = json!({
        "email": &test_email,
        "password": test_password
    });

    let response = client
        .request(
            "POST",
            &format!("{BASE_URL}/api/v1/auth/login"),
            Some(login_payload),
        )
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");

    // Store token for authenticated requests
    client
        .set_auth_token(body["access_token"].as_str().unwrap().to_string())
        .await;
}

#[tokio::test]
async fn test_user_info_endpoint() {
    let mut client = ApiTestClient::new();

    // Setup: Register and login
    let test_email = format!("test_{}@example.com", uuid::Uuid::new_v4());
    let test_password = "TestPassword123!";

    let register_payload = json!({
        "email": &test_email,
        "password": test_password,
        "name": "Test User"
    });

    client
        .request(
            "POST",
            &format!("{BASE_URL}/api/v1/auth/register"),
            Some(register_payload),
        )
        .await
        .expect("Failed to register user");

    let login_payload = json!({
        "email": &test_email,
        "password": test_password
    });

    let login_response = client
        .request(
            "POST",
            &format!("{BASE_URL}/api/v1/auth/login"),
            Some(login_payload),
        )
        .await
        .expect("Failed to login");

    let login_body: Value = login_response
        .json()
        .await
        .expect("Failed to parse login response");
    client
        .set_auth_token(login_body["access_token"].as_str().unwrap().to_string())
        .await;

    // Test /me endpoint
    let response = client
        .request("GET", &format!("{BASE_URL}/api/v1/auth/me"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["email"], test_email);
}

#[tokio::test]
async fn test_oauth_authorize_endpoint() {
    let client = ApiTestClient::new();

    let authorize_url = format!(
        "{}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&state={}",
        BASE_URL,
        "demo-client",
        "http://localhost:3000/callback",
        uuid::Uuid::new_v4()
    );

    let response = client
        .request("GET", &authorize_url, None)
        .await
        .expect("Failed to send request");

    // OAuth authorize typically redirects or returns auth page
    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::FOUND);
}

#[tokio::test]
async fn test_oauth_token_endpoint() {
    let client = ApiTestClient::new();

    let token_payload = json!({
        "grant_type": "client_credentials",
        "client_id": "demo-client",
        "client_secret": "demo-secret",
        "scope": "read write"
    });

    let response = client
        .request(
            "POST",
            &format!("{BASE_URL}/oauth/token"),
            Some(token_payload),
        )
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].is_number());
}

#[tokio::test]
async fn test_service_identity_registration() {
    let client = ApiTestClient::new();

    let service_payload = json!({
        "service_name": "test-service",
        "service_type": "backend",
        "environment": "test"
    });

    let response = client
        .request(
            "POST",
            &format!("{BASE_URL}/service/identity/register"),
            Some(service_payload),
        )
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["identity_id"].is_string());
    assert_eq!(body["service_name"], "test-service");
    assert_eq!(body["status"], "registered");
}

#[tokio::test]
async fn test_jit_token_request() {
    let client = ApiTestClient::new();

    // First register a service identity
    let service_payload = json!({
        "service_name": "test-service",
        "service_type": "backend",
        "environment": "test"
    });

    let service_response = client
        .request(
            "POST",
            &format!("{BASE_URL}/service/identity/register"),
            Some(service_payload),
        )
        .await
        .expect("Failed to register service");

    let service_body: Value = service_response
        .json()
        .await
        .expect("Failed to parse service response");
    let identity_id = service_body["identity_id"].as_str().unwrap();

    // Request JIT token
    let jit_payload = json!({
        "identity_id": identity_id,
        "requested_scopes": ["read", "write"],
        "ttl_seconds": 3600
    });

    let response = client
        .request("POST", &format!("{BASE_URL}/token/jit"), Some(jit_payload))
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].is_number());
}

// POLICY SERVICE ENDPOINTS TESTS

#[tokio::test]
async fn test_policy_service_health() {
    let client = ApiTestClient::new();
    let response = client
        .request("GET", &format!("{POLICY_SERVICE_URL}/health"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn test_policy_authorization() {
    let client = ApiTestClient::new();

    let auth_payload = json!({
        "subject": "user:test@example.com",
        "action": "read",
        "resource": "document:123",
        "context": {
            "ip_address": "127.0.0.1",
            "user_agent": "test-client"
        }
    });

    let response = client
        .request(
            "POST",
            &format!("{POLICY_SERVICE_URL}/v1/authorize"),
            Some(auth_payload),
        )
        .await
        .expect("Failed to send request");

    assert!(response.status() == StatusCode::OK || response.status() == StatusCode::FORBIDDEN);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["allowed"].is_boolean());
}

#[tokio::test]
async fn test_policy_metrics() {
    let client = ApiTestClient::new();
    let response = client
        .request("GET", &format!("{POLICY_SERVICE_URL}/metrics"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("Failed to get response text");
    assert!(body.contains("# TYPE") || body.contains("# HELP"));
}

#[tokio::test]
async fn test_openapi_documentation() {
    let client = ApiTestClient::new();
    let response = client
        .request("GET", &format!("{POLICY_SERVICE_URL}/openapi.json"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.expect("Failed to parse response");
    assert!(body["openapi"].is_string());
    assert!(body["info"]["title"].is_string());
    assert!(body["paths"].is_object());
}

// COMPREHENSIVE ENDPOINT TEST RUNNER

#[tokio::test]
async fn test_all_endpoints_comprehensive() {
    let mut results = Vec::new();

    // Define all endpoints to test
    let endpoints = vec![
        // Auth Service Endpoints
        ("GET", format!("{BASE_URL}/health"), None),
        ("GET", format!("{BASE_URL}/api/v1/status"), None),
        ("POST", format!("{BASE_URL}/api/v1/auth/register"), Some(json!({
            "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
            "password": "TestPassword123!",
            "name": "Test User"
        }))),
        ("POST", format!("{BASE_URL}/api/v1/auth/login"), Some(json!({
            "email": "demo@example.com",
            "password": "demo123"
        }))),
        ("GET", format!("{BASE_URL}/oauth/authorize?client_id=demo-client&redirect_uri=http://localhost:3000/callback&response_type=code&state=test"), None),
        ("POST", format!("{BASE_URL}/oauth/token"), Some(json!({
            "grant_type": "client_credentials",
            "client_id": "demo-client",
            "client_secret": "demo-secret"
        }))),
        ("POST", format!("{BASE_URL}/service/identity/register"), Some(json!({
            "service_name": "test-service"
        }))),
        ("POST", format!("{BASE_URL}/token/jit"), Some(json!({
            "identity_id": "test_id"
        }))),

        // Policy Service Endpoints  
        ("GET", format!("{POLICY_SERVICE_URL}/health"), None),
        ("POST", format!("{POLICY_SERVICE_URL}/v1/authorize"), Some(json!({
            "subject": "user:test",
            "action": "read",
            "resource": "doc:1"
        }))),
        ("GET", format!("{POLICY_SERVICE_URL}/metrics"), None),
        ("GET", format!("{POLICY_SERVICE_URL}/openapi.json"), None),
    ];

    let client = ApiTestClient::new();

    for (method, url, body) in endpoints {
        let start = std::time::Instant::now();

        let result = match timeout(TEST_TIMEOUT, client.request(method, &url, body.clone())).await
        {
            Ok(Ok(response)) => {
                let status = response.status();
                TestResult {
                    endpoint: url.clone(),
                    method: method.to_string(),
                    status: StatusCode::from_u16(status.as_u16()).unwrap(),
                    success: status.is_success() || status.is_redirection(),
                    duration_ms: start.elapsed().as_millis(),
                    error: None,
                }
            }
            Ok(Err(e)) => TestResult {
                endpoint: url.clone(),
                method: method.to_string(),
                status: StatusCode::INTERNAL_SERVER_ERROR,
                success: false,
                duration_ms: start.elapsed().as_millis(),
                error: Some(e),
            },
            Err(_) => TestResult {
                endpoint: url.clone(),
                method: method.to_string(),
                status: StatusCode::REQUEST_TIMEOUT,
                success: false,
                duration_ms: start.elapsed().as_millis(),
                error: Some("Request timeout".to_string()),
            },
        };

        results.push(result);
    }

    // Print test summary
    println!("\n=== OpenAPI Endpoints Test Summary ===\n");

    let total = results.len();
    let successful = results.iter().filter(|r| r.success).count();
    let failed = total - successful;

    for result in &results {
        let status_symbol = if result.success { "✅" } else { "❌" };
        println!(
            "{} {} {} -> {} ({}ms) {}",
            status_symbol,
            result.method,
            result.endpoint,
            result.status.as_u16(),
            result.duration_ms,
            result.error.as_ref().unwrap_or(&String::new())
        );
    }

    println!("\n=== Summary ===");
    println!("Total: {total}");
    println!(
        "Successful: {} ({:.1}%)",
        successful,
        (successful as f64 / total as f64) * 100.0
    );
    println!(
        "Failed: {} ({:.1}%)",
        failed,
        (failed as f64 / total as f64) * 100.0
    );

    // Assert that most endpoints work (allow for some services not running)
    assert!(
        successful as f64 / total as f64 >= 0.5,
        "Too many endpoints failed"
    );
}

// PERFORMANCE AND LOAD TESTING

#[tokio::test]
async fn test_endpoint_performance() {
    use std::time::Instant;

    let client = ApiTestClient::new();
    let mut response_times = Vec::new();

    // Test health endpoint performance
    for _ in 0..10 {
        let start = Instant::now();
        let _ = client
            .request("GET", &format!("{BASE_URL}/health"), None)
            .await;
        response_times.push(start.elapsed().as_millis());
    }

    let avg_time: u128 = response_times.iter().sum::<u128>() / response_times.len() as u128;
    let max_time = response_times.iter().max().unwrap();

    println!("Health endpoint performance:");
    println!("  Average response time: {avg_time}ms");
    println!("  Max response time: {max_time}ms");

    // Assert reasonable performance
    assert!(avg_time < 100, "Average response time too high");
    assert!(*max_time < 500, "Max response time too high");
}

#[tokio::test]
async fn test_concurrent_requests() {
    use tokio::task::JoinSet;

    let mut tasks = JoinSet::new();

    // Spawn 10 concurrent requests
    for i in 0..10 {
        tasks.spawn(async move {
            let client = ApiTestClient::new();
            let response = client
                .request("GET", &format!("{BASE_URL}/health"), None)
                .await;
            (i, response.is_ok())
        });
    }

    let mut successes = 0;
    while let Some(result) = tasks.join_next().await {
        if let Ok((_, success)) = result {
            if success {
                successes += 1;
            }
        }
    }

    println!("Concurrent requests: {successes}/10 successful");
    assert!(successes >= 8, "Too many concurrent requests failed");
}

// ERROR HANDLING TESTS

#[tokio::test]
async fn test_invalid_endpoint() {
    let client = ApiTestClient::new();
    let response = client
        .request("GET", &format!("{BASE_URL}/invalid/endpoint"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_malformed_request() {
    let client = ApiTestClient::new();

    // Send invalid JSON to registration endpoint
    let response = client
        .request(
            "POST",
            &format!("{BASE_URL}/api/v1/auth/register"),
            Some(json!({
                "invalid": "data"
            })),
        )
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_unauthorized_access() {
    let client = ApiTestClient::new();

    // Try to access protected endpoint without token
    let response = client
        .request("GET", &format!("{BASE_URL}/api/v1/auth/me"), None)
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
