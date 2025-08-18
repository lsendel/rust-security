use auth_service::{app, store::TokenStore, AppState};
use reqwest::header::CONTENT_TYPE;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("valid_client".to_string(), "valid_secret".to_string());

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(auth_service::policy_cache::PolicyCacheConfig::default())),
        backpressure_state: std::sync::Arc::new(auth_service::backpressure::BackpressureState::new(auth_service::backpressure::BackpressureConfig::default())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn test_missing_client_credentials_returns_400() {
    let base = spawn_app().await;

    // Try to get token without client credentials
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400, "Should return 400 for missing client_id");
}

#[tokio::test]
async fn test_invalid_client_credentials_returns_401() {
    let base = spawn_app().await;

    // Try to get token with invalid credentials
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=invalid_client&client_secret=wrong_secret")
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        401,
        "Should return 401 for invalid credentials"
    );
}

#[tokio::test]
async fn test_invalid_grant_type_returns_400() {
    let base = spawn_app().await;

    // Try to get token with invalid grant type
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=invalid_grant&client_id=valid_client&client_secret=valid_secret")
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        400,
        "Should return 400 for invalid grant_type"
    );
    let body = res.text().await.unwrap();
    assert!(body.contains("unsupported grant_type"));
}

#[tokio::test]
async fn test_valid_client_credentials_returns_token() {
    let base = spawn_app().await;

    // Get token with valid credentials
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=valid_client&client_secret=valid_secret")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200, "Should return 200 for valid credentials");
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body.get("access_token").is_some(),
        "Should return access token"
    );
    assert!(
        body.get("refresh_token").is_some(),
        "Should return refresh token"
    );
}

#[tokio::test]
async fn test_no_error_details_exposed() {
    let base = spawn_app().await;

    // Try to trigger an internal error by sending malformed refresh token request
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=refresh_token&refresh_token=nonexistent_token")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
    let body = res.text().await.unwrap();
    // Should not expose internal error details
    assert!(
        !body.contains("anyhow"),
        "Should not expose internal error types"
    );
    assert!(
        !body.contains("redis"),
        "Should not expose implementation details"
    );
}
