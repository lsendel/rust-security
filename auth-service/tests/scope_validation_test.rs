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
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    // Enable test mode to relax client secret strength and bypass signature/rate limits
    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    // Ensure global client authenticator can find this client
    std::env::set_var("CLIENT_CREDENTIALS", "test_client:test_secret");

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(auth_service::policy_cache::PolicyCacheConfig::default())),
        backpressure_state: std::sync::Arc::new(auth_service::backpressure::BackpressureState::new(auth_service::backpressure::BackpressureConfig::default())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn test_valid_scope_accepted() {
    let base = spawn_app().await;

    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read write")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200, "Should accept valid scopes");
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("access_token").is_some());
    assert_eq!(body.get("scope").unwrap().as_str().unwrap(), "read write");
}

#[tokio::test]
async fn test_invalid_scope_rejected() {
    let base = spawn_app().await;

    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=invalid_scope")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400, "Should reject invalid scopes");
    let body = res.text().await.unwrap();
    assert!(body.contains("invalid_scope"));
}

#[tokio::test]
async fn test_mixed_valid_invalid_scope_rejected() {
    let base = spawn_app().await;

    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read invalid_scope")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 400, "Should reject if any scope is invalid");
    let body = res.text().await.unwrap();
    assert!(body.contains("invalid_scope"));
}

#[tokio::test]
async fn test_no_scope_accepted() {
    let base = spawn_app().await;

    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200, "Should accept requests without scope");
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("access_token").is_some());
    // Scope should be null when not provided
    assert!(body.get("scope").is_some() && body.get("scope").unwrap().is_null());
}

#[tokio::test]
async fn test_all_allowed_scopes() {
    let base = spawn_app().await;

    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read write admin")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200, "Should accept all allowed scopes");
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("access_token").is_some());
    assert_eq!(
        body.get("scope").unwrap().as_str().unwrap(),
        "read write admin"
    );
}
