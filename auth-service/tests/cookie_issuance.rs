use axum::extract::State;
use auth_service::auth_api::{AuthState, RegisterRequest};

#[tokio::test]
async fn register_sets_cookies_when_keys_available() {
    // Skip if RSA key is not provided
    if std::env::var("RSA_PRIVATE_KEY").is_err() && std::env::var("RSA_PRIVATE_KEY_PATH").is_err() {
        eprintln!("Skipping cookie issuance test: RSA_PRIVATE_KEY(_PATH) not set");
        return;
    }
    auth_service::infrastructure::crypto::keys::initialize_keys().await.expect("init keys");

    // Create state
    let state = AuthState::new("x".repeat(64));
    let req = RegisterRequest { email: "user@example.com".to_string(), password: "StrongP@ssw0rd1".to_string(), name: "User".to_string() };

    let (headers, json) = auth_service::auth_api::register(State(state), axum::Json(req)).await.expect("register ok");
    let cookies: Vec<_> = headers.get_all(axum::http::header::SET_COOKIE).iter().collect();
    assert!(cookies.iter().any(|h| h.to_str().unwrap().starts_with("access_token=")));
    assert!(cookies.iter().any(|h| h.to_str().unwrap().starts_with("csrf_token=")));

    // Response body still contains tokens for now (backward compatibility)
    let body = json.0;
    assert_eq!(body.token_type, "Bearer");
}

