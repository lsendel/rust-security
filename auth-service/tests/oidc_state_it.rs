use auth_service::{app, store::TokenStore, AppState};
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Minimal state
    let app_state = AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(auth_service::policy_cache::PolicyCacheConfig::default())),
        backpressure_state: std::sync::Arc::new(auth_service::backpressure::BackpressureState::new(auth_service::backpressure::BackpressureConfig::default())),
    };

    let router = app(app_state);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn google_callback_invalid_state_returns_400_like_error() {
    let base = spawn_app().await;
    let client = Client::new();

    let resp = client
        .get(format!(
            "{}/oauth/google/callback?code=dummy&state=unknown_state",
            base
        ))
        .send()
        .await
        .unwrap();

    // Should not be a 500; body should include invalid_state
    let status = resp.status();
    assert!(status.is_client_error() || status.is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v.get("error").and_then(|e| e.as_str()), Some("invalid_state"));
}

#[tokio::test]
async fn microsoft_callback_invalid_state_returns_400_like_error() {
    let base = spawn_app().await;
    let client = Client::new();

    let resp = client
        .get(format!(
            "{}/oauth/microsoft/callback?code=dummy&state=unknown_state",
            base
        ))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    assert!(status.is_client_error() || status.is_success());
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v.get("error").and_then(|e| e.as_str()), Some("invalid_state"));
}


