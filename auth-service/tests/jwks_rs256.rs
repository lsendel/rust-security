use auth_service::infrastructure::crypto::keys::{
    current_signing_key, initialize_keys, jwks_document,
};
use jsonwebtoken::{encode, Algorithm, Header};

#[tokio::test]
async fn test_jwks_and_rs256_signing() {
    // Provide a development RSA key via env for tests
    // This should be a valid RSA private key PEM; here we use a minimal placeholder and expect env to supply in CI
    // If not provided, initialize_keys will return error; skip test in that case.
    if std::env::var("RSA_PRIVATE_KEY").is_err() && std::env::var("RSA_PRIVATE_KEY_PATH").is_err() {
        eprintln!("Skipping test: RSA_PRIVATE_KEY or RSA_PRIVATE_KEY_PATH not set");
        return;
    }

    initialize_keys().await.expect("init keys");
    let jwks = jwks_document().await;
    let keys = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .expect("jwks keys");
    assert!(!keys.is_empty(), "JWKS should contain at least one key");
    assert_eq!(
        keys[0].get("kty").and_then(|v| v.as_str()).unwrap_or(""),
        "RSA"
    );
    assert_eq!(
        keys[0].get("alg").and_then(|v| v.as_str()).unwrap_or(""),
        "RS256"
    );

    // Sign a token with RS256
    let (kid, enc) = current_signing_key().await.expect("signing key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.clone());
    let claims =
        serde_json::json!({"sub":"test-user","exp": chrono::Utc::now().timestamp() + 3600});
    let token = encode(&header, &claims, &enc).expect("encode");
    assert!(token.split('.').count() == 3);
}

#[tokio::test]
async fn test_jwks_document_remains_available() {
    if std::env::var("RSA_PRIVATE_KEY").is_err() && std::env::var("RSA_PRIVATE_KEY_PATH").is_err() {
        eprintln!("Skipping rotation test: RSA key env not set");
        return;
    }
    initialize_keys().await.expect("init keys");
    let jwks1 = jwks_document().await;
    let len1 = jwks1
        .get("keys")
        .and_then(|k| k.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    assert!(
        len1 >= 1,
        "JWKS should remain available with at least one key"
    );
}
