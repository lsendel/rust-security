use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::session_store::RedisSessionStore;
use auth_service::{
    api_key_store::ApiKeyStore,
    app,
    sql_store::SqlStore,
    store::{HybridStore, TokenStore},
    AppState, IntrospectRequest, IntrospectResponse,
};
use common::TokenRecord;
use reqwest::header::CONTENT_TYPE;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app(store: Arc<HybridStore>) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();
    let session_store = Arc::new(RedisSessionStore::new(None).await);
    let jwks_manager = Arc::new(
        JwksManager::new(Default::default(), Arc::new(InMemoryKeyStorage::new()))
            .await
            .unwrap(),
    );

    let app_state = AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),
        allowed_scopes: Arc::new(std::sync::RwLock::new(HashSet::from(["read".to_string(), "write".to_string()]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    };

    let app = app(app_state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

async fn token_issue_and_revoke_flow_test(store: Arc<HybridStore>) {
    let base = spawn_app(store).await;

    // Issue a token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v.get("access_token").unwrap().as_str().unwrap().to_string();

    // Validate exp/iat presence and consistency
    let exp = v.get("exp").unwrap().as_i64().unwrap();
    let iat = v.get("iat").unwrap().as_i64().unwrap();
    assert!(exp > iat);
    assert_eq!(exp - iat, 3600);

    // Introspect -> active=true and matching exp/iat
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/introspect", base))
        .json(&IntrospectRequest {
            token: token.clone(),
            token_type_hint: None,
        })
        .send()
        .await
        .unwrap();
    let body: IntrospectResponse = res.json().await.unwrap();
    assert!(body.active);
    assert_eq!(body.exp, Some(exp));
    assert_eq!(body.iat, Some(iat));

    // Revoke token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/revoke", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("token={}", token))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    // Introspect -> active=false
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/introspect", base))
        .json(&IntrospectRequest {
            token,
            token_type_hint: None,
        })
        .send()
        .await
        .unwrap();
    let body: IntrospectResponse = res.json().await.unwrap();
    assert!(!body.active);
}

#[tokio::test]
async fn token_flow_with_hybrid_store() {
    let store = Arc::new(HybridStore::new().await);
    token_issue_and_revoke_flow_test(store).await;
}

#[tokio::test]
#[ignore] // Requires a running postgres database and TEST_DATABASE_URL env var
async fn token_flow_with_sql_store() {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://test:test@localhost/test".to_string());
    let store = SqlStore::new(&db_url)
        .await
        .expect("Failed to connect to DB");
    store
        .run_migrations()
        .await
        .expect("Failed to run migrations");
    let hybrid_store = HybridStore::new().await;
    token_issue_and_revoke_flow_test(Arc::new(hybrid_store)).await;
}
