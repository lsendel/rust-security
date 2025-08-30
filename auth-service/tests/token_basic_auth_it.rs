use auth_service::{app, AppState};
use base64::Engine as _;
use common::TokenRecord;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("basic_client".to_string(), "basic_secret".to_string());

    let app = app(AppState {
        store: Arc::new(auth_service::storage::store::hybrid::HybridStore::new().await),
        session_store: Arc::new(auth_service::storage::session::store::RedisSessionStore::new(None)),
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),
        allowed_scopes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::from([
            "read".to_string(),
        ]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(auth_service::storage::cache::policy_cache::PolicyCache::new(
            auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(
            auth_service::api_key_store::ApiKeyStore::new(":memory:")
                .await
                .unwrap(),
        ),
        jwks_manager: Arc::new(
            auth_service::jwks_rotation::JwksManager::new(
                auth_service::jwks_rotation::KeyRotationConfig::default(),
                Arc::new(auth_service::jwks_rotation::InMemoryKeyStorage::new()),
            )
            .await
            .unwrap(),
        ),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn token_with_basic_auth_header() {
    let base = spawn_app().await;

    let creds = base64::engine::general_purpose::STANDARD.encode("basic_client:basic_secret");
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, format!("Basic {}", creds))
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    assert!(v.get("access_token").is_some());
}
