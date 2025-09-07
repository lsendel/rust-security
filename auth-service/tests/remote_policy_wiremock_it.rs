use axum::http::Method;
use serde_json::json;
use serial_test::serial;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod harness;
use harness::{make_auth_router, request};

#[tokio::test]
#[serial]
async fn login_respects_remote_policy_allow() {
    let mock_server = MockServer::start().await;

    // Mock policy-service allow decision
    Mock::given(method("POST"))
        .and(path("/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision":"Allow"})))
        .mount(&mock_server)
        .await;

    // Enable remote policy and point to mock
    std::env::set_var("ENABLE_REMOTE_POLICY", "1");
    std::env::set_var("POLICY_SERVICE_BASE_URL", mock_server.uri());

    let app = make_auth_router();
    let body = r#"{"email":"user@example.com","password":"Secret123!"}"#;
    let resp = request(&app, Method::POST, "/api/v1/auth/login", Some(body)).await;
    assert_eq!(resp.status(), 200);
    let received = mock_server.received_requests().await.unwrap();
    assert!(received.iter().any(|r| r.url.path() == "/v1/authorize"));
}

#[tokio::test]
#[serial]
async fn login_respects_remote_policy_deny() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"decision":"Deny"})))
        .mount(&mock_server)
        .await;

    std::env::set_var("ENABLE_REMOTE_POLICY", "1");
    std::env::set_var("POLICY_SERVICE_BASE_URL", mock_server.uri());
    std::env::remove_var("POLICY_FAIL_OPEN");

    let app = make_auth_router();
    let body = r#"{"email":"user@example.com","password":"Secret123!"}"#;
    let resp = request(&app, Method::POST, "/api/v1/auth/login", Some(body)).await;
    assert_eq!(resp.status(), 403, "expected 403 Deny, got different");
    let received = mock_server.received_requests().await.unwrap();
    assert!(received.iter().any(|r| r.url.path() == "/v1/authorize"));
}

#[tokio::test]
#[serial]
async fn login_fail_open_on_remote_error_when_configured() {
    let mock_server = MockServer::start().await;

    // Return 500 to simulate policy-service failure
    Mock::given(method("POST"))
        .and(path("/v1/authorize"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    std::env::set_var("ENABLE_REMOTE_POLICY", "1");
    std::env::set_var("POLICY_SERVICE_BASE_URL", mock_server.uri());
    std::env::set_var("POLICY_FAIL_OPEN", "1");

    let app = make_auth_router();
    let body = r#"{"email":"user@example.com","password":"Secret123!"}"#;
    let resp = request(&app, Method::POST, "/api/v1/auth/login", Some(body)).await;
    assert_eq!(resp.status(), 200);
    let received = mock_server.received_requests().await.unwrap();
    assert!(received.iter().any(|r| r.url.path() == "/v1/authorize"));
}
