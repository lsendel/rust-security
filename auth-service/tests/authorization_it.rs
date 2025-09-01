use auth_service::{app, AppState};
use axum::{routing::post, Json, Router};
use common::TokenRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizeReq {
    action: String,
    resource: serde_json::Value,
    context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizeResp {
    decision: String,
}

async fn spawn_auth_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Use env-based client registration to bypass secret strength checks in secure authenticator
    std::env::set_var(
        "CLIENT_CREDENTIALS",
        "test_client:very_strong_secret_with_mixed_chars_123!@#",
    );

    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");

    let app = app(AppState {
        store: Arc::new(auth_service::storage::store::hybrid::HybridStore::new().await),
        session_store: Arc::new(
            auth_service::storage::session::store::RedisSessionStore::new(None),
        ),
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(HashMap::new())),
        allowed_scopes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::from([
            "read".to_string(),
            "write".to_string(),
        ]))),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(
            auth_service::storage::cache::policy_cache::PolicyCache::new(
                auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
            ),
        ),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(
            auth_service::api_key_store::ApiKeyStore::new(":memory:")
                .await
                .unwrap(),
        ),
        jwks_manager: Arc::new(
            auth_service::jwks_rotation::JwksManager::new(
                Default::default(),
                Arc::new(auth_service::jwks_rotation::InMemoryKeyStorage::new()),
            )
            .await
            .unwrap(),
        ),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

async fn spawn_mock_policy(_decision: &'static str) -> String {
    async fn handler() -> Json<AuthorizeResp> {
        Json(AuthorizeResp {
            decision: "Allow".to_string(),
        })
    }
    let app = Router::new().route("/v1/authorize", post(handler));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn authorize_allows_via_policy_service() {
    let base = spawn_auth_app().await;
    let policy_url = spawn_mock_policy("Allow").await;
    std::env::set_var("POLICY_SERVICE_URL", policy_url);

    // Mint a token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=very_strong_secret_with_mixed_chars_123!@#")
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        panic!("/oauth/token failed: {} body={} ", status, text);
    }
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string();

    // Call authorize
    let res = reqwest::Client::new()
        .post(format!("{}/v1/authorize", base))
        .bearer_auth(token)
        .header("x-policy-enforcement", "strict")
        .json(&AuthorizeReq {
            action: "orders:read".to_string(),
            resource: serde_json::json!({ "type": "Order", "id": "o1" }),
            context: None,
        })
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        panic!("/v1/authorize failed: {} body={}", status, text);
    }
    let body: AuthorizeResp = res.json().await.unwrap();
    assert_eq!(body.decision, "Allow");
}

#[tokio::test]
async fn authorize_permissive_fallback_when_service_unavailable() {
    std::env::set_var("POLICY_SERVICE_URL", "http://invalid.invalid");
    std::env::remove_var("POLICY_ENFORCEMENT");
    let base = spawn_auth_app().await;

    // Mint a token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=very_strong_secret_with_mixed_chars_123!@#")
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        panic!("/oauth/token failed: {} body={} ", status, text);
    }
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string();

    let res = reqwest::Client::new()
        .post(format!("{}/v1/authorize", base))
        .bearer_auth(token)
        .header("x-policy-url", "http://invalid.invalid")
        .json(&AuthorizeReq {
            action: "orders:read".to_string(),
            resource: serde_json::json!({ "type": "Order", "id": "o1" }),
            context: None,
        })
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        panic!("/v1/authorize failed: {} body={}", status, text);
    }
    let body: AuthorizeResp = res.json().await.unwrap();
    assert_eq!(body.decision, "Allow");
}

#[tokio::test]
async fn authorize_strict_mode_errors_when_service_unavailable() {
    std::env::set_var("POLICY_SERVICE_URL", "http://invalid.invalid");
    std::env::set_var("POLICY_ENFORCEMENT", "strict");
    let base = spawn_auth_app().await;

    // Mint a token
    let res = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=very_strong_secret_with_mixed_chars_123!@#")
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        panic!("/oauth/token failed: {} body={} ", status, text);
    }
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v
        .get("access_token")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string();

    let res = reqwest::Client::new()
        .post(format!("{}/v1/authorize", base))
        .bearer_auth(token)
        .header("x-policy-enforcement", "strict")
        .header("x-policy-url", "http://invalid.invalid")
        .json(&AuthorizeReq {
            action: "orders:read".to_string(),
            resource: serde_json::json!({ "type": "Order", "id": "o1" }),
            context: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
}
