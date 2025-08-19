use auth_service::{
    app, sql_store::SqlStore, store::HybridStore, AppState, IntrospectRequest,
    IntrospectResponse,
};
use common::Store;
use reqwest::header::CONTENT_TYPE;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;

async fn spawn_app(store: Arc<dyn Store>) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret".to_string());

    let app_state = AppState {
        store,
        client_credentials,
        allowed_scopes: vec!["read".to_string(), "write".to_string()],
        policy_cache: std::sync::Arc::new(auth_service::policy_cache::PolicyCache::new(
            auth_service::policy_cache::PolicyCacheConfig::default(),
        )),
        backpressure_state: std::sync::Arc::new(
            auth_service::backpressure::BackpressureState::new(
                auth_service::backpressure::BackpressureConfig::default(),
            ),
        ),
    };

    let app = app(app_state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

async fn token_issue_and_revoke_flow_test(store: Arc<dyn Store>) {
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
    let store = SqlStore::new(&db_url).await.expect("Failed to connect to DB");
    store.run_migrations().await.expect("Failed to run migrations");
    token_issue_and_revoke_flow_test(Arc::new(store)).await;
}
