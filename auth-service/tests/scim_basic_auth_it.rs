use auth_service::jwks_rotation::{JwksManager, InMemoryKeyStorage};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{app, api_key_store::ApiKeyStore, store::TokenStore, AppState};
use base64::Engine as _;
use ::common::Store;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    std::env::set_var("SCIM_BASIC_CREDENTIALS", "scimuser:scimpass");

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

    let app_state = AppState {
        store,
        session_store,
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec![],
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
    };

    let router = app(app_state);
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn scim_requires_basic_auth() {
    let base = spawn_app().await;
    let client = Client::new();

    // Missing auth
    let resp = client
        .get(format!("{}/scim/v2/Users", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Valid auth
    let creds = base64::engine::general_purpose::STANDARD.encode("scimuser:scimpass");
    let resp2 = client
        .get(format!("{}/scim/v2/Users", base))
        .header("Authorization", format!("Basic {}", creds))
        .send()
        .await
        .unwrap();
    // List returns 200 with default empty list
    assert!(resp2.status().is_success());
}
