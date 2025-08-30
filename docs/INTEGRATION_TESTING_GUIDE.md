# Integration Testing Guide

## Overview

This guide provides comprehensive instructions for testing integrations with the Rust Security Platform. It covers end-to-end testing, service integration testing, and validation of security workflows across the entire platform.

## Table of Contents

1. [Integration Testing Overview](#integration-testing-overview)
2. [Test Environment Setup](#test-environment-setup)
3. [Authentication Integration Tests](#authentication-integration-tests)
4. [Authorization Integration Tests](#authorization-integration-tests)
5. [Service-to-Service Integration Tests](#service-to-service-integration-tests)
6. [Security Integration Tests](#security-integration-tests)
7. [Performance Integration Tests](#performance-integration-tests)
8. [CI/CD Integration Testing](#cicd-integration-testing)
9. [Troubleshooting Integration Issues](#troubleshooting-integration-issues)

## Integration Testing Overview

### Test Categories

| Category | Scope | Frequency | Duration |
|----------|-------|-----------|----------|
| **Unit Tests** | Individual functions/methods | Continuous | <1 second |
| **Integration Tests** | Component interactions | Per commit | 1-30 seconds |
| **End-to-End Tests** | Complete user journeys | Daily | 1-5 minutes |
| **Performance Tests** | Load and stress testing | Weekly | 5-30 minutes |
| **Security Tests** | Vulnerability and compliance | Weekly | 2-10 minutes |

### Integration Testing Strategy

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Unit Tests    │ -> │ Integration     │ -> │ End-to-End      │
│                 │    │ Tests           │    │ Tests           │
│ • Function      │    │ • API calls     │    │ • User journeys │
│ • Method        │    │ • Database ops  │    │ • Workflows     │
│ • Class         │    │ • Cache ops     │    │ • Multi-service │
└─────────────────┘    └─────────────────┘    └─────────────────┘
       ▲                       ▲                       ▲
       │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Performance    │    │   Security      │    │   Contract      │
│   Tests         │    │   Tests         │    │   Tests         │
│ • Load testing  │    │ • Penetration   │    │ • API contracts │
│ • Stress tests  │    │ • Compliance    │    │ • Schema val.   │
│ • Benchmarks    │    │ • Audit trails  │    │ • Compatibility │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Test Environment Setup

### 1. Docker-Based Test Environment

```bash
# Start complete test environment
docker-compose -f docker-compose.test.yml up -d

# Verify services are running
docker-compose -f docker-compose.test.yml ps

# Check service health
curl http://localhost:8080/health
curl http://localhost:8081/health
```

### 2. Local Development Environment

```bash
# Install dependencies
cargo install cargo-nextest
cargo install cargo-tarpaulin

# Set up test database
./scripts/setup-test-database.sh

# Configure test environment variables
cp .env.example .env.test
export RUST_ENV=test
```

### 3. Test Data Setup

```bash
# Generate test users and tokens
./scripts/generate-test-data.sh

# Set up test policies
./scripts/setup-test-policies.sh

# Initialize test certificates
./scripts/setup-test-certificates.sh
```

## Authentication Integration Tests

### 1. OAuth 2.0 Flow Testing

```rust
#[cfg(test)]
mod oauth_integration_tests {
    use reqwest::Client;
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_complete_oauth_flow() {
        let client = Client::new();
        let base_url = "http://localhost:8080";

        // 1. Client Credentials Grant
        let token_response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
                ("scope", "read write"),
            ])
            .send()
            .await
            .expect("Failed to get token");

        assert_eq!(token_response.status(), 200);

        let token_data: serde_json::Value = token_response
            .json()
            .await
            .expect("Failed to parse token response");

        let access_token = token_data["access_token"]
            .as_str()
            .expect("No access token in response");

        // 2. Token Introspection
        let introspection_response = client
            .post(&format!("{}/oauth/introspect", base_url))
            .form(&[("token", access_token)])
            .send()
            .await
            .expect("Failed to introspect token");

        assert_eq!(introspection_response.status(), 200);

        let introspection_data: serde_json::Value = introspection_response
            .json()
            .await
            .expect("Failed to parse introspection response");

        assert_eq!(introspection_data["active"], true);
        assert_eq!(introspection_data["client_id"], "test_client");
    }

    #[tokio::test]
    async fn test_token_refresh_flow() {
        let client = Client::new();
        let base_url = "http://localhost:8080";

        // Get initial tokens
        let initial_response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "password"),
                ("username", "testuser"),
                ("password", "testpass"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .expect("Failed to get initial token");

        let initial_data: serde_json::Value = initial_response.json().await.unwrap();
        let refresh_token = initial_data["refresh_token"].as_str().unwrap();

        // Refresh token
        let refresh_response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .expect("Failed to refresh token");

        assert_eq!(refresh_response.status(), 200);

        let refresh_data: serde_json::Value = refresh_response.json().await.unwrap();
        assert!(refresh_data["access_token"].is_string());
        assert!(refresh_data["refresh_token"].is_string());
    }
}
```

### 2. Multi-Factor Authentication Testing

```rust
#[cfg(test)]
mod mfa_integration_tests {
    use reqwest::Client;
    use serde_json::json;

    #[tokio::test]
    async fn test_mfa_enrollment_flow() {
        let client = Client::new();
        let base_url = "http://localhost:8080";

        // 1. Initiate MFA enrollment
        let enrollment_response = client
            .post(&format!("{}/mfa/enroll", base_url))
            .header("Authorization", "Bearer <user_token>")
            .send()
            .await
            .expect("Failed to initiate MFA enrollment");

        assert_eq!(enrollment_response.status(), 200);

        let enrollment_data: serde_json::Value = enrollment_response.json().await.unwrap();
        let secret = enrollment_data["secret"].as_str().unwrap();
        let qr_code = enrollment_data["qr_code"].as_str().unwrap();

        // 2. Complete enrollment with TOTP code
        let totp_code = generate_totp_code(secret);

        let completion_response = client
            .post(&format!("{}/mfa/enroll/complete", base_url))
            .header("Authorization", "Bearer <user_token>")
            .json(&json!({
                "code": totp_code,
                "secret": secret
            }))
            .send()
            .await
            .expect("Failed to complete MFA enrollment");

        assert_eq!(completion_response.status(), 200);
    }

    #[tokio::test]
    async fn test_mfa_authentication_flow() {
        let client = Client::new();
        let base_url = "http://localhost:8080";

        // 1. Attempt authentication (should require MFA)
        let auth_response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "password"),
                ("username", "mfa_user"),
                ("password", "password"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .expect("Failed to authenticate");

        // Should get MFA required response
        assert_eq!(auth_response.status(), 401);

        let auth_data: serde_json::Value = auth_response.json().await.unwrap();
        assert_eq!(auth_data["error"], "mfa_required");

        // 2. Complete MFA
        let mfa_response = client
            .post(&format!("{}/oauth/token", base_url))
            .form(&[
                ("grant_type", "password"),
                ("username", "mfa_user"),
                ("password", "password"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
                ("mfa_code", "<valid_totp_code>"),
            ])
            .send()
            .await
            .expect("Failed to complete MFA authentication");

        assert_eq!(mfa_response.status(), 200);
    }
}
```

## Authorization Integration Tests

### 1. Policy Decision Point Testing

```rust
#[cfg(test)]
mod authorization_integration_tests {
    use reqwest::Client;
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_policy_evaluation_flow() {
        let client = Client::new();
        let auth_url = "http://localhost:8080";
        let policy_url = "http://localhost:8081";

        // 1. Get authentication token
        let token_response = client
            .post(&format!("{}/oauth/token", auth_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "test_client"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .expect("Failed to get token");

        let token_data: serde_json::Value = token_response.json().await.unwrap();
        let access_token = token_data["access_token"].as_str().unwrap();

        // 2. Test policy evaluation
        let policy_request = json!({
            "principal": {
                "id": "test_user",
                "roles": ["user", "developer"],
                "department": "engineering",
                "attributes": {
                    "clearance_level": "confidential",
                    "manager_approval": true
                }
            },
            "action": "read",
            "resource": {
                "type": "document",
                "id": "confidential_report.pdf",
                "classification": "confidential",
                "department": "engineering",
                "attributes": {
                    "sensitivity": "high",
                    "requires_approval": false
                }
            },
            "context": {
                "time": "2024-01-15T14:30:00Z",
                "ip_address": "192.168.1.100",
                "user_agent": "TestClient/1.0",
                "location": "office",
                "session_id": "test_session_123",
                "request_id": "test_request_456"
            }
        });

        let policy_response = client
            .post(&format!("{}/v1/authorize", policy_url))
            .header("Authorization", format!("Bearer {}", access_token))
            .header("X-Request-ID", "test_request_456")
            .header("X-Session-ID", "test_session_123")
            .json(&policy_request)
            .send()
            .await
            .expect("Failed to evaluate policy");

        assert_eq!(policy_response.status(), 200);

        let policy_result: serde_json::Value = policy_response.json().await.unwrap();

        // Verify decision structure
        assert!(policy_result["decision"].is_string());
        assert!(policy_result["policy_id"].is_string());

        // Check for obligations if present
        if let Some(obligations) = policy_result["obligations"].as_array() {
            for obligation in obligations {
                assert!(obligation["action"].is_string());
            }
        }
    }

    #[tokio::test]
    async fn test_bulk_authorization() {
        let client = Client::new();
        let policy_url = "http://localhost:8081";

        let bulk_request = json!({
            "requests": [
                {
                    "principal": {"id": "alice", "roles": ["user"]},
                    "action": "read",
                    "resource": {"type": "file", "path": "/docs/public/*"}
                },
                {
                    "principal": {"id": "alice", "roles": ["user"]},
                    "action": "write",
                    "resource": {"type": "file", "path": "/docs/private/*"}
                },
                {
                    "principal": {"id": "bob", "roles": ["admin"]},
                    "action": "delete",
                    "resource": {"type": "file", "path": "/docs/*"}
                }
            ]
        });

        let response = client
            .post(&format!("{}/v1/authorize/bulk", policy_url))
            .header("Authorization", "Bearer <service_token>")
            .json(&bulk_request)
            .send()
            .await
            .expect("Failed to perform bulk authorization");

        assert_eq!(response.status(), 200);

        let bulk_result: serde_json::Value = response.json().await.unwrap();
        let results = bulk_result["results"].as_array().unwrap();

        assert_eq!(results.len(), 3);

        // Verify each result has proper structure
        for result in results {
            assert!(result["decision"].is_string());
            assert!(result["request_index"].is_number());
        }
    }
}
```

## Service-to-Service Integration Tests

### 1. Cross-Service Authentication

```rust
#[cfg(test)]
mod service_integration_tests {
    use reqwest::Client;
    use serde_json::json;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_service_to_service_communication() {
        let client = Client::new();
        let auth_service = "http://localhost:8080";
        let api_service = "http://localhost:8082";

        // 1. Service authenticates with Auth Service
        let token_response = client
            .post(&format!("{}/oauth/token", auth_service))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "api_service"),
                ("client_secret", "service_secret"),
                ("scope", "api:read api:write"),
            ])
            .send()
            .await
            .expect("Service authentication failed");

        assert_eq!(token_response.status(), 200);

        let token_data: serde_json::Value = token_response.json().await.unwrap();
        let service_token = token_data["access_token"].as_str().unwrap();

        // 2. Service calls API Service with token
        let api_response = client
            .get(&format!("{}/api/data", api_service))
            .header("Authorization", format!("Bearer {}", service_token))
            .header("X-Service-Name", "test_service")
            .header("X-Request-ID", "test_req_123")
            .send()
            .await
            .expect("API call failed");

        assert_eq!(api_response.status(), 200);

        // 3. Verify service identity propagation
        let api_data: serde_json::Value = api_response.json().await.unwrap();
        assert_eq!(api_data["service"], "api_service");
        assert_eq!(api_data["request_id"], "test_req_123");
    }

    #[tokio::test]
    async fn test_token_refresh_integration() {
        let client = Client::new();
        let auth_service = "http://localhost:8080";

        // Get initial service token
        let initial_response = client
            .post(&format!("{}/oauth/token", auth_service))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "background_service"),
                ("client_secret", "bg_service_secret"),
            ])
            .send()
            .await
            .unwrap();

        let initial_data: serde_json::Value = initial_response.json().await.unwrap();
        let access_token = initial_data["access_token"].as_str().unwrap();
        let refresh_token = initial_data["refresh_token"].as_str().unwrap();

        // Simulate token expiration by waiting
        sleep(Duration::from_secs(2)).await;

        // Attempt API call (should work with valid token)
        let test_response = client
            .get("http://localhost:8082/api/health")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .unwrap();

        assert_eq!(test_response.status(), 200);

        // Refresh token before it expires
        let refresh_response = client
            .post(&format!("{}/oauth/token", auth_service))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", "background_service"),
                ("client_secret", "bg_service_secret"),
            ])
            .send()
            .await
            .unwrap();

        assert_eq!(refresh_response.status(), 200);

        let refresh_data: serde_json::Value = refresh_response.json().await.unwrap();
        let new_access_token = refresh_data["access_token"].as_str().unwrap();

        // Verify new token works
        let final_response = client
            .get("http://localhost:8082/api/health")
            .header("Authorization", format!("Bearer {}", new_access_token))
            .send()
            .await
            .unwrap();

        assert_eq!(final_response.status(), 200);
    }
}
```

## Security Integration Tests

### 1. Threat Detection Integration

```rust
#[cfg(test)]
mod security_integration_tests {
    use reqwest::Client;
    use serde_json::json;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_threat_detection_workflow() {
        let client = Client::new();
        let auth_url = "http://localhost:8080";
        let threat_url = "http://localhost:8083";

        // 1. Authenticate security service
        let token_response = client
            .post(&format!("{}/oauth/token", auth_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "threat_service"),
                ("client_secret", "threat_secret"),
            ])
            .send()
            .await
            .unwrap();

        let token_data: serde_json::Value = token_response.json().await.unwrap();
        let access_token = token_data["access_token"].as_str().unwrap();

        // 2. Submit suspicious activity for analysis
        let threat_data = json!({
            "event_type": "login_attempt",
            "ip_address": "192.168.1.100",
            "user_agent": "SuspiciousBot/1.0",
            "timestamp": "2024-01-15T14:30:00Z",
            "indicators": [
                {
                    "type": "ip_reputation",
                    "value": "192.168.1.100",
                    "severity": "medium"
                },
                {
                    "type": "user_agent_anomaly",
                    "value": "SuspiciousBot/1.0",
                    "severity": "high"
                }
            ],
            "context": {
                "geolocation": "Unknown",
                "vpn_detected": true,
                "tor_exit_node": false,
                "session_count": 15,
                "failure_count": 8
            }
        });

        let analysis_response = client
            .post(&format!("{}/api/threats/analyze", threat_url))
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&threat_data)
            .send()
            .await
            .unwrap();

        assert_eq!(analysis_response.status(), 200);

        let analysis_result: serde_json::Value = analysis_response.json().await.unwrap();

        // Verify threat analysis structure
        assert!(analysis_result["threat_score"].is_number());
        assert!(analysis_result["risk_level"].is_string());
        assert!(analysis_result["recommendations"].is_array());

        let threat_score = analysis_result["threat_score"].as_f64().unwrap();
        assert!(threat_score >= 0.0 && threat_score <= 1.0);

        // 3. Test threat response integration
        if threat_score > 0.7 {
            let response_request = json!({
                "threat_id": analysis_result["threat_id"],
                "response_actions": [
                    {
                        "action": "block_ip",
                        "parameters": {
                            "ip_address": "192.168.1.100",
                            "duration": "1h"
                        }
                    },
                    {
                        "action": "notify_security_team",
                        "parameters": {
                            "severity": "high",
                            "channels": ["email", "slack"]
                        }
                    }
                ]
            });

            let response_result = client
                .post(&format!("{}/api/threats/respond", threat_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .json(&response_request)
                .send()
                .await
                .unwrap();

            assert_eq!(response_result.status(), 202); // Accepted for processing
        }
    }
}
```

## Performance Integration Tests

### 1. Load Testing Integration

```rust
#[cfg(test)]
mod performance_integration_tests {
    use reqwest::Client;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;
    use tokio::task;

    #[tokio::test]
    async fn test_concurrent_authentication_load() {
        let client = Arc::new(Client::new());
        let auth_url = "http://localhost:8080";
        let num_concurrent_requests = 50;
        let semaphore = Arc::new(Semaphore::new(num_concurrent_requests));

        let start_time = Instant::now();
        let mut handles = vec![];

        // Spawn concurrent authentication requests
        for i in 0..num_concurrent_requests {
            let client = Arc::clone(&client);
            let auth_url = auth_url.to_string();
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            let handle = task::spawn(async move {
                let _permit = permit; // Hold permit until request completes

                let user_id = format!("load_test_user_{}", i);
                let response = client
                    .post(&format!("{}/oauth/token", auth_url))
                    .form(&[
                        ("grant_type", "client_credentials"),
                        ("client_id", &user_id),
                        ("client_secret", &format!("secret_{}", i)),
                    ])
                    .send()
                    .await;

                match response {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            Some(format!("Request {}: Success", i))
                        } else {
                            Some(format!("Request {}: Status {}", i, resp.status()))
                        }
                    }
                    Err(e) => Some(format!("Request {}: Error {}", i, e)),
                }
            });

            handles.push(handle);
        }

        // Wait for all requests to complete
        let mut results = vec![];
        for handle in handles {
            if let Ok(result) = handle.await {
                if let Some(msg) = result {
                    results.push(msg);
                }
            }
        }

        let total_time = start_time.elapsed();

        // Analyze results
        let success_count = results.iter()
            .filter(|r| r.contains("Success"))
            .count();

        let avg_response_time = total_time.as_millis() as f64 / num_concurrent_requests as f64;

        println!("Load test results:");
        println!("Total requests: {}", num_concurrent_requests);
        println!("Successful requests: {}", success_count);
        println!("Total time: {:?}", total_time);
        println!("Average response time: {:.2}ms", avg_response_time);

        // Performance assertions
        assert!(success_count >= num_concurrent_requests * 9 / 10, "Less than 90% success rate");
        assert!(avg_response_time < 500.0, "Average response time too high: {:.2}ms", avg_response_time);
        assert!(total_time < Duration::from_secs(30), "Total test time too long: {:?}", total_time);
    }

    #[tokio::test]
    async fn test_authorization_performance_under_load() {
        let client = Arc::new(Client::new());
        let policy_url = "http://localhost:8081";
        let num_requests = 100;

        let policy_request = json!({
            "principal": {
                "id": "perf_test_user",
                "roles": ["user"],
                "attributes": {"department": "engineering"}
            },
            "action": "read",
            "resource": {
                "type": "document",
                "id": "perf_test_doc.pdf",
                "attributes": {"classification": "internal"}
            }
        });

        let start_time = Instant::now();
        let mut handles = vec![];

        // Spawn concurrent authorization requests
        for i in 0..num_requests {
            let client = Arc::clone(&client);
            let policy_url = policy_url.to_string();
            let request_data = policy_request.clone();

            let handle = task::spawn(async move {
                let response = client
                    .post(&format!("{}/v1/authorize", policy_url))
                    .header("Authorization", "Bearer <service_token>")
                    .json(&request_data)
                    .send()
                    .await;

                match response {
                    Ok(resp) if resp.status().is_success() => {
                        let data: serde_json::Value = resp.json().await.unwrap_or_default();
                        if data["decision"] == "Allow" {
                            Some(format!("Request {}: Authorized", i))
                        } else {
                            Some(format!("Request {}: Denied", i))
                        }
                    }
                    Ok(resp) => Some(format!("Request {}: HTTP {}", i, resp.status())),
                    Err(e) => Some(format!("Request {}: Error {}", i, e)),
                }
            });

            handles.push(handle);
        }

        // Collect results
        let mut auth_count = 0;
        let mut deny_count = 0;
        let mut error_count = 0;

        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                if result.contains("Authorized") {
                    auth_count += 1;
                } else if result.contains("Denied") {
                    deny_count += 1;
                } else {
                    error_count += 1;
                }
            }
        }

        let total_time = start_time.elapsed();
        let avg_time_per_request = total_time.as_millis() as f64 / num_requests as f64;

        // Performance validation
        assert!(auth_count > 0, "No successful authorizations");
        assert!(avg_time_per_request < 100.0,
                "Average authorization time too high: {:.2}ms", avg_time_per_request);
        assert!(error_count == 0, "Found {} authorization errors", error_count);

        println!("Authorization performance test:");
        println!("Total requests: {}", num_requests);
        println!("Authorized: {}", auth_count);
        println!("Denied: {}", deny_count);
        println!("Errors: {}", error_count);
        println!("Total time: {:?}", total_time);
        println!("Avg time per request: {:.2}ms", avg_time_per_request);
    }
}
```

## CI/CD Integration Testing

### 1. Automated Test Pipeline

```yaml
# .github/workflows/integration-tests.yml
name: Integration Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  integration-tests:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test_password
        ports:
          - 5432:5432

      redis:
        image: redis:7
        ports:
          - 6379:6379

    steps:
    - uses: actions/checkout@v4

    - name: Setup Rust
      uses: dtolnay/rust-toolchain@stable

    - name: Cache dependencies
      uses: actions/cache@v4
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Run integration tests
      run: cargo test --test integration_tests -- --test-threads=4

    - name: Run cross-service tests
      run: cargo test --test auth_policy_cross_service_test

    - name: Run security integration tests
      run: cargo test --test advanced_security_testing

    - name: Run performance integration tests
      run: cargo test --test performance_integration_tests

    - name: Generate test report
      run: |
        echo "## Integration Test Results" > integration-report.md
        echo "| Test Suite | Status | Duration |" >> integration-report.md
        echo "|------------|--------|----------|" >> integration-report.md
        # Add test results to report

    - name: Upload test artifacts
      uses: actions/upload-artifact@v4
      with:
        name: integration-test-results
        path: |
          integration-report.md
          target/debug/deps/integration_tests-*
```

### 2. Test Data Management

```bash
#!/bin/bash
# scripts/setup-integration-test-data.sh

echo "Setting up integration test data..."

# Create test database
createdb rust_security_test

# Run migrations
sqlx migrate run --database-url="postgresql://test:test@localhost/rust_security_test"

# Load test fixtures
psql -d rust_security_test -f tests/fixtures/users.sql
psql -d rust_security_test -f tests/fixtures/policies.sql
psql -d rust_security_test -f tests/fixtures/clients.sql

# Set up Redis test data
redis-cli < tests/fixtures/redis_data.txt

# Generate test certificates
openssl req -x509 -newkey rsa:4096 -keyout test_key.pem -out test_cert.pem -days 365 -nodes -subj "/CN=test.local"

echo "Integration test data setup complete!"
```

## Troubleshooting Integration Issues

### 1. Service Connectivity Issues

```bash
# Check service health
curl -f http://localhost:8080/health || echo "Auth service down"
curl -f http://localhost:8081/health || echo "Policy service down"
curl -f http://localhost:8082/health || echo "API service down"

# Check database connectivity
psql -h localhost -U test -d rust_security_test -c "SELECT 1;" || echo "Database connection failed"

# Check Redis connectivity
redis-cli ping || echo "Redis connection failed"
```

### 2. Authentication Failures

```bash
# Debug token generation
curl -v -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret"

# Check token validation
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/oauth/introspect
```

### 3. Authorization Failures

```bash
# Test policy evaluation
curl -X POST http://localhost:8081/v1/authorize \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {"id": "test_user"},
    "action": "read",
    "resource": {"type": "document", "id": "test.pdf"}
  }'
```

### 4. Performance Issues

```bash
# Monitor response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080/health

# Check system resources
top -b -n 1 | head -20
df -h
free -h

# Monitor database performance
psql -d rust_security_test -c "SELECT * FROM pg_stat_activity;"
```

### 5. Common Integration Test Patterns

```rust
/// Test fixture for setting up test environment
struct TestFixture {
    auth_token: String,
    client: reqwest::Client,
    base_urls: HashMap<String, String>,
}

impl TestFixture {
    async fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let auth_token = Self::get_auth_token(&client).await;

        let mut base_urls = HashMap::new();
        base_urls.insert("auth".to_string(), "http://localhost:8080".to_string());
        base_urls.insert("policy".to_string(), "http://localhost:8081".to_string());
        base_urls.insert("api".to_string(), "http://localhost:8082".to_string());

        Self {
            auth_token,
            client,
            base_urls,
        }
    }

    async fn get_auth_token(client: &reqwest::Client) -> String {
        let response = client
            .post("http://localhost:8080/oauth/token")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "integration_test"),
                ("client_secret", "test_secret"),
            ])
            .send()
            .await
            .expect("Failed to get auth token");

        let data: serde_json::Value = response.json().await.unwrap();
        data["access_token"].as_str().unwrap().to_string()
    }

    async fn make_authenticated_request(
        &self,
        service: &str,
        path: &str,
        method: reqwest::Method,
        body: Option<serde_json::Value>,
    ) -> reqwest::Response {
        let url = format!("{}/{}", self.base_urls[service], path.trim_start_matches('/'));

        let mut request = self.client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("Content-Type", "application/json");

        if let Some(body) = body {
            request = request.json(&body);
        }

        request.send().await.unwrap()
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_complete_integration_flow() {
        let fixture = TestFixture::new().await;

        // Test authentication
        let auth_response = fixture
            .make_authenticated_request("auth", "/oauth/introspect", reqwest::Method::POST, None)
            .await;

        assert_eq!(auth_response.status(), 200);

        // Test authorization
        let policy_request = json!({
            "principal": {"id": "test_user", "roles": ["user"]},
            "action": "read",
            "resource": {"type": "document", "id": "test.pdf"}
        });

        let policy_response = fixture
            .make_authenticated_request("policy", "/v1/authorize", reqwest::Method::POST, Some(policy_request))
            .await;

        assert_eq!(policy_response.status(), 200);

        // Test API access
        let api_response = fixture
            .make_authenticated_request("api", "/data", reqwest::Method::GET, None)
            .await;

        assert_eq!(api_response.status(), 200);
    }
}
```

This comprehensive integration testing guide provides everything needed to thoroughly test integrations with the Rust Security Platform across all layers and components.
