use auth_service::{app, store::TokenStore, AppState};
use reqwest::header::{CONTENT_TYPE, LOCATION};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use url::Url;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut client_credentials = HashMap::new();
    client_credentials.insert("test_client".to_string(), "test_secret_12345".to_string());

    // Set test mode envs
    std::env::set_var("TEST_MODE", "1");
    std::env::set_var("DISABLE_RATE_LIMIT", "1");
    std::env::set_var("EXTERNAL_BASE_URL", "http://localhost:8080");
    // Ensure client is registered and redirect URI is allowed for authorization flow
    std::env::set_var("CLIENT_CREDENTIALS", "test_client:any_secret_ok_in_test");
    std::env::set_var("CLIENT_REDIRECT_URIS", "test_client:http://localhost:3000/callback");

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials,
        allowed_scopes: vec![
            "read".to_string(),
            "write".to_string(),
            "openid".to_string(),
            "profile".to_string(),
        ],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[tokio::test]
async fn test_pkce_authorization_code_flow() {
    let base = spawn_app().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Step 1: Generate PKCE parameters (normally done by client)
    let code_verifier = auth_service::security::generate_code_verifier();
    let code_challenge = auth_service::security::generate_code_challenge(&code_verifier);

    // Step 2: Authorization request with PKCE
    let auth_url = format!(
        "{}/oauth/authorize?response_type=code&client_id=test_client&redirect_uri={}&scope=openid%20profile&code_challenge={}&code_challenge_method=S256&state=test_state",
        base,
        urlencoding::encode("http://localhost:3000/callback"),
        code_challenge
    );

    let response = client.get(&auth_url).send().await.unwrap();

    // Should get a redirect with authorization code
    assert_eq!(response.status(), 302);
    let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();

    // Parse the authorization code from redirect
    let redirect_url = Url::parse(location).unwrap();
    let mut auth_code = None;
    let mut state = None;

    for (key, value) in redirect_url.query_pairs() {
        match key.as_ref() {
            "code" => auth_code = Some(value.to_string()),
            "state" => state = Some(value.to_string()),
            _ => {}
        }
    }

    let auth_code = auth_code.expect("Authorization code should be present");
    assert_eq!(state.as_deref(), Some("test_state"));
    assert!(auth_code.starts_with("ac_"));

    // Step 3: Exchange authorization code for tokens with PKCE
    let token_response = client
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id=test_client&code_verifier={}",
            auth_code,
            urlencoding::encode("http://localhost:3000/callback"),
            code_verifier
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), 200);
    let token_json: Value = token_response.json().await.unwrap();

    // Verify token response
    assert!(token_json.get("access_token").is_some());
    assert!(token_json.get("refresh_token").is_some());
    assert_eq!(token_json.get("token_type").unwrap().as_str().unwrap(), "Bearer");

    // Check if ID token is present (may not be if subject is not set)
    if token_json.get("id_token").is_some() {
        println!("ID token present: {}", token_json.get("id_token").unwrap().as_str().unwrap());
    } else {
        println!("No ID token generated - this is expected for client credentials without user context");
    }

    let access_token = token_json.get("access_token").unwrap().as_str().unwrap();
    assert!(access_token.starts_with("tk_"));

    // Step 4: Use access token to call userinfo endpoint
    let userinfo_response = client
        .get(format!("{}/oauth/userinfo", base))
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();

    assert_eq!(userinfo_response.status(), 200);
    let userinfo: Value = userinfo_response.json().await.unwrap();
    assert!(userinfo.get("sub").is_some());
}

#[tokio::test]
async fn test_pkce_validation_failure() {
    let base = spawn_app().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Step 1: Generate PKCE parameters
    let code_verifier = auth_service::security::generate_code_verifier();
    let code_challenge = auth_service::security::generate_code_challenge(&code_verifier);

    // Step 2: Authorization request
    let auth_url = format!(
        "{}/oauth/authorize?response_type=code&client_id=test_client&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
        base,
        urlencoding::encode("http://localhost:3000/callback"),
        code_challenge
    );

    let response = client.get(&auth_url).send().await.unwrap();
    assert_eq!(response.status(), 302);
    let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();

    let redirect_url = Url::parse(location).unwrap();
    let auth_code = redirect_url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("Authorization code should be present");

    // Step 3: Try to exchange with wrong code verifier
    let wrong_verifier = auth_service::security::generate_code_verifier();

    let token_response = client
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id=test_client&code_verifier={}",
            auth_code,
            urlencoding::encode("http://localhost:3000/callback"),
            wrong_verifier
        ))
        .send()
        .await
        .unwrap();

    // Should fail PKCE validation
    assert_eq!(token_response.status(), 400);
    let error_text = token_response.text().await.unwrap();
    assert!(error_text.contains("PKCE validation failed"));
}

#[tokio::test]
async fn test_authorization_without_pkce() {
    let base = spawn_app().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Authorization request without PKCE (should still work for backward compatibility)
    let auth_url = format!(
        "{}/oauth/authorize?response_type=code&client_id=test_client&redirect_uri={}",
        base,
        urlencoding::encode("http://localhost:3000/callback")
    );

    let response = client.get(&auth_url).send().await.unwrap();
    assert_eq!(response.status(), 302);

    let location = response.headers().get(LOCATION).unwrap().to_str().unwrap();
    let redirect_url = Url::parse(location).unwrap();
    let auth_code = redirect_url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .expect("Authorization code should be present");

    // Exchange without PKCE (should work for non-PKCE flow)
    let token_response = client
        .post(format!("{}/oauth/token", base))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id=test_client",
            auth_code,
            urlencoding::encode("http://localhost:3000/callback")
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(token_response.status(), 200);
}
