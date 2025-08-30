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

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();
    let store = Arc::new(HybridStore::new().await);
    let session_store = Arc::new(RedisSessionStore::new(None));
    let jwks_manager = Arc::new(
        JwksManager::new(Default::default(), Arc::new(InMemoryKeyStorage::new()))
            .await
            .unwrap(),
    );

    let app = app(AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(HashMap::new())),
        allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::from(["read".to_string()]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(auth_service::storage::cache::policy_cache::PolicyCache::new(
            auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn openid_metadata_and_jwks() {
    let base = spawn_app().await;

    let res = reqwest::get(format!("{}/.well-known/openid-configuration", base))
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("issuer").is_some());
    assert!(body.get("jwks_uri").is_some());
    assert!(body.get("token_endpoint").is_some());

    let res = reqwest::get(format!("{}/jwks.json", base)).await.unwrap();
    assert!(res.status().is_success());
    let jwks: serde_json::Value = res.json().await.unwrap();
    assert!(jwks.get("keys").is_some());
}
