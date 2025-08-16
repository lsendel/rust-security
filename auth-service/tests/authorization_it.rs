use auth_service::{app, store::TokenStore, AppState};
use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizeReq {
    action: String,
    resource: serde_json::Value,
    context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizeResp { decision: String }

async fn spawn_auth_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

async fn spawn_mock_policy(_decision: &'static str) -> String {
    async fn handler() -> Json<AuthorizeResp> { Json(AuthorizeResp { decision: "Allow".to_string() }) }
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
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v.get("access_token").and_then(|x| x.as_str()).unwrap().to_string();

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
    assert!(res.status().is_success());
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
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v.get("access_token").and_then(|x| x.as_str()).unwrap().to_string();

    let res = reqwest::Client::new()
        .post(format!("{}/v1/authorize", base))
        .bearer_auth(token)
        .json(&AuthorizeReq {
            action: "orders:read".to_string(),
            resource: serde_json::json!({ "type": "Order", "id": "o1" }),
            context: None,
        })
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
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
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let v: serde_json::Value = res.json().await.unwrap();
    let token = v.get("access_token").and_then(|x| x.as_str()).unwrap().to_string();

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
    assert_eq!(res.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
}


