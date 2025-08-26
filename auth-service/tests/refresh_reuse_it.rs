use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use common::TokenRecord;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Register a test client via env
    std::env::set_var(
        "CLIENT_CREDENTIALS",
        "test_client:very_strong_secret_with_mixed_chars_123!@#",
    );
    std::env::set_var("TEST_MODE", "1");

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();

    let store = Arc::new(HybridStore::new().await);
    let session_store = Arc::new(RedisSessionStore::new(None).await);
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
        allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::from([
            "read".to_string(),
            "write".to_string(),
            "openid".to_string(),
        ]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn refresh_token_reuse_is_rejected() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Step 1: Mint tokens (client_credentials)
    let res = client
        .post(format!("{}/oauth/token", base))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=very_strong_secret_with_mixed_chars_123!@#&scope=openid")
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_success(),
        "token mint failed: {}",
        res.status()
    );
    let v: serde_json::Value = res.json().await.unwrap();
    let refresh_token = v
        .get("refresh_token")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string();

    // Step 2: Use refresh token once (should succeed)
    let res_ok = client
        .post(format!("{}/oauth/token", base))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            refresh_token
        ))
        .send()
        .await
        .unwrap();
    assert!(
        res_ok.status().is_success(),
        "first refresh failed: {}",
        res_ok.status()
    );

    // Step 3: Reuse the same refresh token (should be rejected)
    let res_reuse = client
        .post(format!("{}/oauth/token", base))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(format!(
            "grant_type=refresh_token&refresh_token={}",
            refresh_token
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res_reuse.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "expected 401 on reuse, got {}",
        res_reuse.status()
    );
}
