use auth_service::{app, AppState};
use common::TokenRecord;
use reqwest::header::HeaderValue;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    let app = app(AppState {
        store: Arc::new(auth_service::store::HybridStore::new().await),
        session_store: Arc::new(auth_service::session_store::RedisSessionStore::new(None).await),
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),
        allowed_scopes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::from(["read".to_string(), "write".to_string()]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(auth_service::api_key_store::ApiKeyStore::new(":memory:")
            .await
            .unwrap()),
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
async fn request_id_propagation() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();
    let test_id = "test-request-id-123";

    let res = client
        .get(format!("{}/health", base))
        .header("x-request-id", test_id)
        .send()
        .await
        .unwrap();

    assert!(res.status().is_success());
    assert_eq!(
        res.headers().get("x-request-id"),
        Some(&HeaderValue::from_str(test_id).unwrap())
    );
}

#[tokio::test]
async fn request_id_generation() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let res = client.get(format!("{}/health", base)).send().await.unwrap();

    assert!(res.status().is_success());
    let request_id = res.headers().get("x-request-id");
    assert!(request_id.is_some());
    // UUID v4 format check
    let id_str = request_id.unwrap().to_str().unwrap();
    assert!(uuid::Uuid::parse_str(id_str).is_ok());
}
