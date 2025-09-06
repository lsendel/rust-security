#![cfg(all(
    feature = "full-integration",
    feature = "api-keys",
    feature = "redis-sessions",
    feature = "crypto"
))]
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::storage::session::store::RedisSessionStore;
use auth_service::storage::store::hybrid::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use base64::Engine as _;
use common::TokenRecord;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    std::env::set_var("SCIM_BASIC_CREDENTIALS", "scimuser:scimpass");

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

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
        allowed_scopes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(
            auth_service::storage::cache::policy_cache::PolicyCache::new(
                auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
            ),
        ),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    };

    let router = app(app_state);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn scim_requires_basic_auth() {
    let base = spawn_app().await;
    let client = Client::new();

    // Missing auth
    let resp = client
        .get(format!("{base}/scim/v2/Users"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Valid auth
    let creds = base64::engine::general_purpose::STANDARD.encode("scimuser:scimpass");
    let resp2 = client
        .get(format!("{base}/scim/v2/Users"))
        .header("Authorization", format!("Basic {creds}"))
        .send()
        .await
        .unwrap();
    // List returns 200 with default empty list
    assert!(resp2.status().is_success());
}
