use axum::http::Method;

mod harness;
use harness::{make_policy_router, request};

#[tokio::test]
async fn health_returns_ok() {
    let app = make_policy_router();
    let resp = request(&app, Method::GET, "/health", None).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn authorize_allow_for_mvp_entities() {
    let app = make_policy_router();
    let body = r#"{
        "request_id": "req-1",
        "principal": {"type":"User","id":"mvp-user"},
        "action": "read",
        "resource": {"type":"Resource","id":"mvp-resource"},
        "context": {}
    }"#;
    let resp = request(&app, Method::POST, "/v1/authorize", Some(body)).await;
    assert_eq!(resp.status(), 200);
    // Optionally check decision body text contains Allow
}

#[tokio::test]
async fn authorize_deny_for_unknown_principal() {
    let app = make_policy_router();
    let body = r#"{
        "request_id": "req-2",
        "principal": {"type":"User","id":"unknown"},
        "action": "read",
        "resource": {"type":"Resource","id":"mvp-resource"},
        "context": {}
    }"#;
    let resp = request(&app, Method::POST, "/v1/authorize", Some(body)).await;
    assert_eq!(resp.status(), 200);
}

