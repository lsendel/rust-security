#![cfg(feature = "full-integration")]
#![allow(clippy::too_many_lines)]
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::storage::session::store::RedisSessionStore;
use auth_service::storage::store::hybrid::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState, IntrospectRequest};
use base64::Engine as _;
use common::TokenRecord;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret_12345".to_string());
    client_credentials.insert("admin_client".to_string(), "admin_secret_67890".to_string());

    // Set test mode envs
    std::env::set_var("TEST_MODE", "1");
    std::env::remove_var("POLICY_ENFORCEMENT");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    std::env::set_var("EXTERNAL_BASE_URL", "http://localhost:8080");
    // Ensure global client authenticator loads these clients from env
    std::env::set_var(
        "CLIENT_CREDENTIALS",
        "test_client:test_secret_12345;admin_client:admin_secret_67890",
    );
    // Set Google envs to satisfy id_token flow where needed
    std::env::set_var("GOOGLE_CLIENT_ID", "test-client-id");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "test-client-secret");
    std::env::set_var(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:8080/oauth/google/callback",
    );

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();

    let store = Arc::new(HybridStore::new().await);
    let session_store = Arc::new(RedisSessionStore::new(None));
    let jwks_manager = Arc::new(
        JwksManager::new(
            auth_service::jwks_rotation::KeyRotationConfig::default(),
            Arc::new(InMemoryKeyStorage::new()),
        )
        .await
        .unwrap(),
    );

    let app = app(AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(client_credentials)),
        allowed_scopes: Arc::new(std::sync::RwLock::new({
            let mut scopes = std::collections::HashSet::new();
            scopes.insert("read".to_string());
            scopes.insert("write".to_string());
            scopes.insert("admin".to_string());
            scopes.insert("openid".to_string());
            scopes.insert("profile".to_string());
            scopes
        })),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::new())),
        policy_cache: std::sync::Arc::new(
            auth_service::storage::cache::policy_cache::PolicyCache::new(
                auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
            ),
        ),
        backpressure_state: std::sync::Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn test_complete_oauth_flow() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test 1: Health check
    let response = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(response.status(), 200);

    // Test 2: OAuth metadata endpoints
    let response = client
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let metadata: Value = response.json().await.unwrap();
    assert!(metadata.get("token_endpoint").is_some());

    // Test 3: JWKS endpoint
    let response = client
        .get(format!("{base}/jwks.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let jwks: Value = response.json().await.unwrap();
    assert!(jwks.get("keys").is_some());

    // Test 4: Token issuance with client credentials
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret_12345&scope=read%20write")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let token_response: Value = response.json().await.unwrap();
    let access_token = token_response
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap();
    let refresh_token = token_response
        .get("refresh_token")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(access_token.starts_with("tk_"));
    assert!(refresh_token.starts_with("rt_"));

    // Test 5: Introspection endpoint
    let response = client
        .post(format!("{base}/oauth/introspect"))
        .header(CONTENT_TYPE, "application/json")
        .json(&IntrospectRequest {
            token: access_token.to_string(),
            token_type_hint: Some("access_token".to_string()),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let introspect_response: Value = response.json().await.unwrap();
    assert!(introspect_response
        .get("active")
        .unwrap()
        .as_bool()
        .unwrap());
    assert_eq!(
        introspect_response.get("scope").unwrap().as_str().unwrap(),
        "read write"
    );

    // Test 6: Token refresh
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=refresh_token&refresh_token={refresh_token}"
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let new_token_response: Value = response.json().await.unwrap();
    let new_access_token = new_token_response
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(new_access_token.starts_with("tk_"));
    assert_ne!(new_access_token, access_token);

    // Test 7: Token revocation
    let response = client
        .post(format!("{base}/oauth/revoke"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("token={access_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // Test 8: Verify token is revoked
    let response = client
        .post(format!("{base}/oauth/introspect"))
        .header(CONTENT_TYPE, "application/json")
        .json(&IntrospectRequest {
            token: access_token.to_string(),
            token_type_hint: Some("access_token".to_string()),
        })
        .send()
        .await
        .unwrap();

    let introspect_response: Value = response.json().await.unwrap();
    assert!(!introspect_response
        .get("active")
        .unwrap()
        .as_bool()
        .unwrap());
}

#[tokio::test]
async fn test_security_features() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test 1: Invalid client credentials
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=invalid&client_secret=invalid")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);

    // Test 2: Missing client credentials
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    // Test 3: Invalid scope
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret_12345&scope=invalid_scope")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    // Test 4: Unsupported grant type
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=authorization_code&client_id=test_client&client_secret=test_secret_12345")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);

    // Test 5: HTTP Basic Authentication
    let credentials =
        base64::engine::general_purpose::STANDARD.encode("test_client:test_secret_12345");

    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, format!("Basic {credentials}"))
        .body("grant_type=client_credentials&scope=read")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_rate_limiting() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Generate a valid access token first
    let token_res = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret_12345&scope=read")
        .send()
        .await
        .unwrap();
    assert_eq!(token_res.status(), 200);
    let token_json: Value = token_res.json().await.unwrap();
    let access_token = token_json
        .get("access_token")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // Enable rate limit for this portion (disable TEST_MODE)
    std::env::set_var("TEST_MODE", "0");
    std::env::set_var("DISABLE_RATE_LIMIT", "0");
    std::env::set_var("RATE_LIMIT_REQUESTS_PER_MINUTE", "5");

    // Send multiple introspection requests with same client IP to trigger rate limiting
    let mut handles = vec![];
    for _ in 0..20 {
        let client = client.clone();
        let base = base.clone();
        let access_token = access_token.clone();
        handles.push(tokio::spawn(async move {
            let res = client
                .post(format!("{base}/oauth/introspect"))
                .header(CONTENT_TYPE, "application/json")
                .header("X-Forwarded-For", "1.2.3.4")
                .json(&IntrospectRequest {
                    token: access_token,
                    token_type_hint: Some("access_token".to_string()),
                })
                .send()
                .await
                .unwrap();
            res.status().as_u16()
        }));
    }

    let mut rate_limited_count = 0;
    for handle in handles {
        let status = handle.await.unwrap();
        if status == 429 {
            rate_limited_count += 1;
        }
    }

    assert!(
        rate_limited_count > 0,
        "Expected some requests to be rate limited"
    );

    // Disable again for other tests
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    std::env::set_var("TEST_MODE", "1");
}

#[tokio::test]
async fn test_openid_connect_features() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Request OpenID Connect token with openid scope
    let response = client
        .post(format!("{base}/oauth/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials&client_id=test_client&client_secret=test_secret_12345&scope=openid profile")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let token_response: Value = response.json().await.unwrap();

    // Should include an ID token when openid scope is requested (now RS256 JWT)
    assert!(token_response.get("id_token").is_some());
    let id_token = token_response.get("id_token").unwrap().as_str().unwrap();

    // ID token should be a JWT (3 parts separated by dots)
    assert_eq!(id_token.split('.').count(), 3);
}

#[tokio::test]
async fn test_mfa_endpoints() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test TOTP registration
    let response = client
        .post(format!("{base}/mfa/totp/register"))
        .header(CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({
            "user_id": "test_user"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let totp_response: Value = response.json().await.unwrap();
    assert!(totp_response.get("secret_base32").is_some());
    assert!(totp_response.get("otpauth_url").is_some());
}

#[tokio::test]
async fn test_scim_endpoints() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    // Test SCIM user creation with valid body
    let response = client
        .post(format!("{base}/scim/v2/Users"))
        .header(CONTENT_TYPE, "application/json")
        .json(&serde_json::json!({
            "userName": "test.user@example.com",
            "active": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let user_response: Value = response.json().await.unwrap();
    assert!(user_response.get("id").is_some());
    assert_eq!(
        user_response.get("userName").unwrap().as_str().unwrap(),
        "test.user@example.com"
    );
}

#[tokio::test]
async fn test_security_headers() {
    let base = spawn_app().await;
    let client = reqwest::Client::new();

    let response = client.get(format!("{base}/health")).send().await.unwrap();

    let headers = response.headers();

    // Check security headers are present
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("x-xss-protection"));
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("referrer-policy"));
    assert!(headers.contains_key("permissions-policy"));

    // Check header values
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
}
