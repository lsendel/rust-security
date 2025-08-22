use auth_service::jwks_rotation::{JwksManager, InMemoryKeyStorage};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{
    api_key_store::ApiKeyStore, app, store::TokenStore, AppState,
};
use ::common::Store;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();
    let store = Arc::new(HybridStore::new().await) as Arc<dyn Store>;
    let session_store = Arc::new(RedisSessionStore::new(None).await)
        as Arc<dyn auth_service::session_store::SessionStore>;
    let jwks_manager = Arc::new(JwksManager::new(
        Default::default(),
        Arc::new(InMemoryKeyStorage::new())
    ).await.unwrap());

    let app = app(AppState {
        store,
        session_store,
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec!["read".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: std::sync::Arc::new(
            auth_service::backpressure::BackpressureState::new(
                auth_service::backpressure::BackpressureConfig::default(),
            ),
        ),
        api_key_store,
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
