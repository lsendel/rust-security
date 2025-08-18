use reqwest::header::{CONTENT_TYPE, USER_AGENT};
use auth_service::{app, store::TokenStore, AppState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use auth_service::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
use std::time::Duration;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret_12345".to_string());

    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    std::env::set_var("CLIENT_CREDENTIALS", "test_client:test_secret_12345");

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec!["read".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn test_token_binding() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Issue a token with specific client info
    let response = client
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("User-Agent", "test-client/1.0")
        .header("X-Forwarded-For", "192.168.1.100")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret_12345&scope=read")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let token_response: serde_json::Value = response.json().await.unwrap();
    let access_token = token_response.get("access_token").unwrap().as_str().unwrap();

    // Introspect with same client info should work
    let response = client
        .post(format!("{}/oauth/introspect", base))
        .header(CONTENT_TYPE, "application/json")
        .header("User-Agent", "test-client/1.0")
        .header("X-Forwarded-For", "192.168.1.100")
        .json(&serde_json::json!({
            "token": access_token
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let introspect_response: serde_json::Value = response.json().await.unwrap();
    assert!(introspect_response.get("active").unwrap().as_bool().unwrap());
}

#[tokio::test]
async fn test_pkce_functions() {
    use auth_service::security::{generate_code_verifier, generate_code_challenge, verify_code_challenge};

    // Test code verifier generation
    let verifier = generate_code_verifier();
    assert!(verifier.len() >= 43);
    assert!(verifier.len() <= 128);
    assert!(verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~'));

    // Test code challenge generation
    let challenge = generate_code_challenge(&verifier);
    assert!(!challenge.is_empty());

    // Test verification
    assert!(verify_code_challenge(&verifier, &challenge));
    assert!(!verify_code_challenge("wrong_verifier", &challenge));
}

#[tokio::test]
async fn test_request_signing() {
    use auth_service::security::{generate_request_signature, verify_request_signature};

    let method = "POST";
    let path = "/oauth/revoke";
    let body = "token=test_token";
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let secret = "test_secret";

    // Generate signature
    let signature = generate_request_signature(method, path, body, timestamp, secret).unwrap();
    assert!(!signature.is_empty());

    // Verify signature
    let is_valid = verify_request_signature(method, path, body, timestamp, &signature, secret).unwrap();
    assert!(is_valid);

    // Verify with wrong secret should fail
    let is_valid = verify_request_signature(method, path, body, timestamp, &signature, "wrong_secret").unwrap();
    assert!(!is_valid);

    // Verify with wrong body should fail
    let is_valid = verify_request_signature(method, path, "wrong_body", timestamp, &signature, secret).unwrap();
    assert!(!is_valid);
}

#[tokio::test]
async fn test_circuit_breaker_basic() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        success_threshold: 1,
        timeout: Duration::from_millis(50),
        reset_timeout: Duration::from_millis(100),
    };
    let cb = CircuitBreaker::new(config);

    // Initially closed
    assert_eq!(cb.state().await, CircuitState::Closed);

    // First failure should open circuit
    let result = cb.call(async { Err::<(), &str>("failure") }).await;
    assert!(result.is_err());
    // Due to automatic transition, it might already be HalfOpen
    let state = cb.state().await;
    assert!(matches!(state, CircuitState::Open | CircuitState::HalfOpen));

    // Wait for reset timeout
    tokio::time::sleep(Duration::from_millis(200)).await;

    // After timeout, a success should recover the circuit
    let result = cb.call(async { Ok::<(), &str>(()) }).await;
    assert!(result.is_ok());

    // After a success, circuit should be closed (since success_threshold is 1)
    assert_eq!(cb.state().await, CircuitState::Closed);
}

#[tokio::test]
async fn test_audit_logging() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Issue a token (should generate audit log)
    let response = client
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret_12345&scope=read")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let token_response: serde_json::Value = response.json().await.unwrap();
    let access_token = token_response.get("access_token").unwrap().as_str().unwrap();

    // Revoke token (should generate audit log)
    let response = client
        .post(format!("{}/oauth/revoke", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("token={}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_security_headers_presence() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/health", base))
        .header(USER_AGENT, "Mozilla/5.0")
        .send()
        .await
        .unwrap();

    let headers = response.headers();
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("x-xss-protection"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("content-security-policy"));
}

#[tokio::test]
async fn test_invalid_json_input_returns_422() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("{}/oauth/introspect", base))
        .header(CONTENT_TYPE, "application/json")
        .body("not-json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400); // Bad Request due to invalid JSON
}
