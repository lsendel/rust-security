use ::common::{Store, TokenRecord};
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{
    api_key_store::ApiKeyStore, app, store::TokenStore, AppState, IntrospectRequest,
    IntrospectResponse,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Enable test mode to bypass client auth for introspection
    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");

    let mut token_store_map: HashMap<String, TokenRecord> = HashMap::new();
    token_store_map.insert(
        "valid_token".to_string(),
        TokenRecord {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test_client".to_string()),
            exp: None,
            iat: None,
            sub: None,
            token_binding: None,
            mfa_verified: false,
        },
    );

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

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
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(token_store_map))),
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
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
async fn health_check_works() {
    let base = spawn_app().await;
    let res = reqwest::get(format!("{}/health", base)).await.unwrap();
    assert!(res.status().is_success());
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body.get("status").unwrap().as_str().unwrap(), "ok");
}

#[tokio::test]
async fn introspect_valid_token() {
    let base = spawn_app().await;
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/introspect", base))
        .json(&IntrospectRequest {
            token: "valid_token".to_string(),
            token_type_hint: None,
        })
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: IntrospectResponse = res.json().await.unwrap();
    assert_eq!(
        body,
        IntrospectResponse {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test_client".to_string()),
            exp: None,
            iat: None,
            token_type: Some("access_token".to_string()),
            iss: None,
            sub: None,
        }
    );
}

#[tokio::test]
async fn introspect_invalid_token() {
    let base = spawn_app().await;
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/introspect", base))
        .json(&IntrospectRequest {
            token: "invalid_token".to_string(),
            token_type_hint: None,
        })
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: IntrospectResponse = res.json().await.unwrap();
    assert_eq!(
        body,
        IntrospectResponse {
            active: false,
            scope: None,
            client_id: None,
            exp: None,
            iat: None,
            token_type: Some("access_token".to_string()),
            iss: None,
            sub: None,
        }
    );
}
