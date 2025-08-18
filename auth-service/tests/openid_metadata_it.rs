use auth_service::{app, store::TokenStore, AppState};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec!["read".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(auth_service::policy_cache::PolicyCacheConfig::default())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn openid_metadata_and_jwks() {
    let base = spawn_app().await;

    let res = reqwest::get(format!("{}/.well-known/openid-configuration", base))
        .await
        .unwrap();
    assert!(res.status().is_success());
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body.get("issuer").is_some());
    assert!(body.get("jwks_uri").is_some());
    assert!(body.get("token_endpoint").is_some());

    let res = reqwest::get(format!("{}/jwks.json", base)).await.unwrap();
    assert!(res.status().is_success());
    let jwks: serde_json::Value = res.json().await.unwrap();
    assert!(jwks.get("keys").is_some());
}
