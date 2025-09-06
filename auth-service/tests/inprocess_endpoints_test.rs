use axum::http::Method;

mod harness;
use harness::{make_auth_router, request};

#[tokio::test]
async fn health_returns_ok() {
    let app = make_auth_router();
    let resp = request(&app, Method::GET, "/health", None).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn detailed_health_returns_ok() {
    let app = make_auth_router();
    let resp = request(&app, Method::GET, "/health/detailed", None).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn login_happy_path() {
    let app = make_auth_router();
    let body = r#"{"email":"user@example.com","password":"Secret123!"}"#;
    let resp = request(&app, Method::POST, "/api/v1/auth/login", Some(body)).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn me_requires_auth() {
    let app = make_auth_router();
    let resp = request(&app, Method::GET, "/api/v1/auth/me", None).await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn logout_always_ok() {
    let app = make_auth_router();
    let resp = request(&app, Method::POST, "/api/v1/auth/logout", Some("{}")).await;
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn metrics_endpoint_works() {
    let app = make_auth_router();
    let resp = request(&app, Method::GET, "/metrics", None).await;
    assert_eq!(resp.status(), 200);
}
