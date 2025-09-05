#![cfg(feature = "full-integration")]
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::storage::session::store::RedisSessionStore;
use auth_service::storage::store::hybrid::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use common::TokenRecord;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    std::env::set_var("CLIENT_CREDENTIALS", "test_client:test_secret");
    std::env::set_var("REQUEST_SIGNING_SECRET", "test_secret");

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();

    let store = Arc::new(HybridStore::new().await);
    let session_store = Arc::new(RedisSessionStore::new(None));
    let jwks_manager = Arc::new(
        JwksManager::new(
            auth_service::jwks_rotation::KeyRotationConfig::default(),
            Arc::new(InMemoryKeyStorage::new()),
        )
        .await
        .unwrap(),
    );

    let app_state = AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(HashMap::new())),
        allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::from(["admin".to_string()]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: Arc::new(
            auth_service::storage::cache::policy_cache::PolicyCache::new(
                auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
            ),
        ),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    };

    tokio::spawn(async move { axum::serve(listener, app(app_state)).await.unwrap() });

    format!("http://{addr}")
}

async fn get_admin_token(base_url: &str) -> String {
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/oauth/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
            ("scope", "admin"),
        ])
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    format!("Bearer {}", body["access_token"].as_str().unwrap())
}

#[tokio::test]
async fn test_create_api_key() {
    let base_url = spawn_app().await;
    let admin_token = get_admin_token(&base_url).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/admin/api-keys"))
        .header("Authorization", &admin_token)
        .json(&serde_json::json!({
            "client_id": "api_client_1",
            "permissions": "read,write"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["api_key"].as_str().is_some());
    assert_eq!(body["key_details"]["client_id"], "api_client_1");
}
