use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::storage::session::store::RedisSessionStore;
use auth_service::storage::store::hybrid::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use common::TokenRecord;
use reqwest::header::CONTENT_TYPE;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

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
        client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),
        allowed_scopes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::from([
            "read".to_string(),
            "write".to_string(),
        ]))),
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
