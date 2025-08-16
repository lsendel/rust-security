use auth_service::{app, store::TokenStore, AppState, IntrospectRequest, IntrospectResponse};
use reqwest::header::CONTENT_TYPE;
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
async fn token_issue_and_revoke_flow() {
    let base = spawn_app().await;

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
