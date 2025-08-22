use ::common::Store;
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::session_store::RedisSessionStore;
use auth_service::store::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, store::TokenStore, AppState};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizeReq {
    action: String,
    resource: serde_json::Value,
    #[serde(default)]
    context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizeResp {
    decision: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TotpRegisterRequest {
    user_id: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TotpRegisterResponse {
    secret_base32: String,
    otpauth_url: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TotpVerifyRequest {
    user_id: String,
    code: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TotpVerifyResponse {
    verified: bool,
}
#[derive(Serialize, Deserialize, Debug)]
struct MfaSessionVerifyRequest {
    user_id: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
}

async fn spawn_auth_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    std::env::set_var("MFA_VERIFIED_WINDOW_SECS", "300");

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

async fn spawn_policy() -> String {
    async fn handler(Json(body): Json<serde_json::Value>) -> Json<AuthorizeResp> {
        let mfa_verified = body
            .get("context")
            .and_then(|c| c.get("mfa_verified"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Support both string and cedar-EntityUid action encodings
        let action = body
            .get("action")
            .and_then(|a| a.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                body.get("action")
                    .and_then(|a| a.as_object())
                    .and_then(|o| o.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .unwrap_or_default();
        let decision = if action == "orders:refund" && !mfa_verified {
            "Deny"
        } else {
            "Allow"
        };
        Json(AuthorizeResp {
            decision: decision.to_string(),
        })
    }
    let app = axum::Router::new().route("/v1/authorize", axum::routing::post(handler));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn step_up_denied_then_allowed_after_mfa_session_verify() {
    let base = spawn_auth_app().await;
    let policy = spawn_policy().await;
    std::env::set_var("POLICY_SERVICE_URL", &policy);

    // Mint a token
    let tok_body: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/oauth/token", base))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = tok_body
        .get("access_token")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string();

    // Call authorize for a sensitive action: expect Deny
    let res1 = reqwest::Client::new()
        .post(format!("{}/v1/authorize", base))
        .bearer_auth(&token)
        .json(&AuthorizeReq {
            action: "orders:refund".to_string(),
            resource: serde_json::json!({"type":"Order","id":"o1"}),
            context: None,
        })
        .send()
        .await
        .unwrap();
    assert!(res1.status().is_success());
    let body1: AuthorizeResp = res1.json().await.unwrap();
    assert_eq!(body1.decision, "Deny");

    // Mark session mfa verified (skip factor verification for test brevity)
    let _ack: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/mfa/session/verify", base))
        .bearer_auth(&token)
        .json(&MfaSessionVerifyRequest {
            user_id: "user1".to_string(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Call authorize again: expect Allow
    let res2 = reqwest::Client::new()
        .post(format!("{}/v1/authorize", base))
        .bearer_auth(&token)
        .json(&AuthorizeReq {
            action: "orders:refund".to_string(),
            resource: serde_json::json!({"type":"Order","id":"o1"}),
            context: None,
        })
        .send()
        .await
        .unwrap();
    assert!(res2.status().is_success());
    let body2: AuthorizeResp = res2.json().await.unwrap();
    assert_eq!(body2.decision, "Allow");
}
