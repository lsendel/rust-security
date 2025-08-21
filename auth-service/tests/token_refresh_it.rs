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

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: std::sync::Arc::new(
            auth_service::backpressure::BackpressureState::new(
                auth_service::backpressure::BackpressureConfig::default(),
            ),
        ),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn refresh_token_flow() {
    let base = spawn_app().await;

    // Issue initial token with refresh token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    let _access_token = v.get("access_token").unwrap().as_str().unwrap();
    let refresh_token = v.get("refresh_token").unwrap().as_str().unwrap();

    // Use refresh token to get new access token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            refresh_token
        ))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    assert!(v.get("access_token").is_some());
    assert!(v.get("refresh_token").is_some());

    // Try to use the same refresh token again - should fail
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            refresh_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}
