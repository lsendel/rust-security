use auth_service::{app, AppState};
use common::TokenRecord;
use reqwest::Client;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Create minimal test state
    let store = Arc::new(auth_service::store::HybridStore::new().await);
    let session_store = Arc::new(
        auth_service::session_store::RedisSessionStore::new(
            None, // Use in-memory fallback for tests
        )
        .await,
    );

    let api_key_store = auth_service::api_key_store::ApiKeyStore::new(":memory:")
        .await
        .expect("Failed to create test API key store");

    let jwks_manager = Arc::new(
        auth_service::jwks_rotation::JwksManager::new(
            Default::default(),
            Arc::new(auth_service::jwks_rotation::InMemoryKeyStorage::new()),
        )
        .await
        .expect("Failed to create JWKS manager")
    );

    let app_state = AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(HashMap::new())),
        allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::from([
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    };

    let router = app(app_state);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{}", addr) // Using HTTP for local test server
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
    assert_eq!(
        v.get("error").and_then(|e| e.as_str()),
        Some("invalid_state")
    );
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
    assert_eq!(
        v.get("error").and_then(|e| e.as_str()),
        Some("invalid_state")
    );
}
