use ::common::Store;
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, store::TokenStore, AppState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Register a test client via env
    std::env::set_var(
        "CLIENT_CREDENTIALS",
        "test_client:very_strong_secret_with_mixed_chars_123!@#",
    );
    // Keep signature validation ON for this test to verify helper signing
    std::env::set_var("TEST_MODE", "0");

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();
    let store = Arc::new(HybridStore::new().await) as Arc<dyn Store>;
    let session_store = Arc::new(RedisSessionStore::new(None).await)
        as Arc<dyn auth_service::session_store::SessionStore>;
    let jwks_manager = Arc::new(
        JwksManager::new(Default::default(), Arc::new(InMemoryKeyStorage::new()))
            .await
            .unwrap(),
    );

    let app = app(AppState {
        store,
        session_store,
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec![
            "read".to_string(),
            "write".to_string(),
            "openid".to_string(),
            "admin".to_string(),
        ],
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

async fn mint_token(base: &str, scope: &str) -> String {
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("grant_type=client_credentials&client_id=test_client&client_secret=very_strong_secret_with_mixed_chars_123!@#&scope={}", scope))
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_success(),
        "token mint failed: {}",
        res.status()
    );
    let v: serde_json::Value = res.json().await.unwrap();
    v.get("access_token")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string()
}

mod common;
use common::sign_request;

#[tokio::test]
async fn admin_stats_requires_admin_scope() {
    let base = spawn_app().await;

    // Ensure signing secret for the test
    std::env::set_var("REQUEST_SIGNING_SECRET", "test_secret");

    // Token without admin scope (signed request)
    let token_user = mint_token(&base, "read write").await;
    let path = "/admin/rate-limit/stats";
    let (sig_user, ts_user) = sign_request("GET", path, "");
    let res_user = reqwest::Client::new()
        .get(format!("{}{}", base, path))
        .bearer_auth(&token_user)
        .header("x-signature", sig_user)
        .header("x-timestamp", ts_user)
        .send()
        .await
        .unwrap();
    assert_eq!(res_user.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Token with admin scope (signed request)
    let token_admin = mint_token(&base, "read write admin").await;
    let (sig_admin, ts_admin) = sign_request("GET", path, "");
    let res_admin = reqwest::Client::new()
        .get(format!("{}{}", base, path))
        .bearer_auth(&token_admin)
        .header("x-signature", sig_admin)
        .header("x-timestamp", ts_admin)
        .send()
        .await
        .unwrap();
    // Without signature headers, even admin-scoped requests may be rejected (400). For success,
    // proper request signing is required; here we just assert it is not inadvertently open.
    assert!(res_admin.status().is_success());
}
