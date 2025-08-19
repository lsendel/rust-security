use auth_service::{app, store::TokenStore, AppState, api_key_store::ApiKeyStore};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    std::env::set_var("CLIENT_CREDENTIALS", "test_client:test_secret");
    std::env::set_var("REQUEST_SIGNING_SECRET", "test_secret");

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();

    let app_state = AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec!["admin".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: Arc::new(auth_service::policy_cache::PolicyCache::new(Default::default())),
        backpressure_state: Arc::new(auth_service::backpressure::BackpressureState::new(Default::default())),
        api_key_store,
    };

    tokio::spawn(async move { axum::serve(listener, app(app_state)).await.unwrap() });

    format!("http://{}", addr)
}

async fn get_admin_token(base_url: &str) -> String {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/oauth/token", base_url))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", "test_client"),
            ("client_secret", "test_secret"),
            ("scope", "admin"),
        ])
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = response.json().await.unwrap();
    format!("Bearer {}", body["access_token"].as_str().unwrap())
}

#[tokio::test]
async fn test_create_api_key() {
    let base_url = spawn_app().await;
    let admin_token = get_admin_token(&base_url).await;

    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/admin/api-keys", base_url))
        .header("Authorization", &admin_token)
        .json(&serde_json::json!({
            "client_id": "api_client_1",
            "permissions": "read,write"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await.unwrap();
    assert!(body["api_key"].as_str().is_some());
    assert_eq!(body["key_details"]["client_id"], "api_client_1");
}
