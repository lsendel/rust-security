use auth_service::{app, store::TokenStore, AppState};
use reqwest::header::HeaderValue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
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
