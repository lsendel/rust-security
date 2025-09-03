//! Core Authentication Tests
//!
//! Essential tests for core authentication functionality
//! These replace the deleted security-dependent test files

use auth_service::{
    domain::{
        entities::{Session, Token, TokenType, User},
        value_objects::{Email, PasswordHash, UserId},
    },
    shared::crypto::{CryptoService, CryptoServiceTrait},
};
use std::sync::Arc;

#[tokio::test]
async fn test_user_registration_flow() {
    // Test core user registration without security modules
    let crypto_service = Arc::new(CryptoService::new("test_secret".to_string()));

    // Create test user data
    let _email = Email::new("test@example.com".to_string()).unwrap();
    let password = "secure_password123".to_string();

    // Test password hashing
    let password_hash = crypto_service.hash_password(&password).await.unwrap();
    assert!(!password_hash.as_str().is_empty());

    // Test password verification
    let is_valid = crypto_service
        .verify_password(&password, &password_hash)
        .await
        .unwrap();
    assert!(is_valid);

    // Test wrong password
    let is_invalid = crypto_service
        .verify_password("wrong_password", &password_hash)
        .await
        .unwrap();
    assert!(!is_invalid);
}

#[tokio::test]
async fn test_token_creation_and_validation() {
    // Test token creation without security modules
    let user_id = UserId::new();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

    // Test access token
    let access_token =
        Token::new_access_token(user_id.clone(), "token_hash_123".to_string(), expires_at);

    assert_eq!(access_token.token_type, TokenType::Access);
    assert_eq!(access_token.user_id, user_id);
    assert!(!access_token.is_expired());
    assert!(access_token.is_active());

    // Test refresh token
    let refresh_token = Token::new_refresh_token(
        user_id,
        "refresh_hash_123".to_string(),
        expires_at,
        "session_123".to_string(),
    );

    assert_eq!(refresh_token.token_type, TokenType::Refresh);
    assert_eq!(refresh_token.session_id, Some("session_123".to_string()));
    assert!(refresh_token.is_active());
}

#[tokio::test]
async fn test_session_management() {
    // Test session creation and expiration
    let user_id = UserId::new();
    let session = Session::new(user_id.clone(), chrono::Utc::now());

    assert_eq!(session.user_id, user_id);
    assert!(!session.is_expired()); // Should not be expired immediately
    assert!(session.expires_at > chrono::Utc::now());
}

#[tokio::test]
async fn test_user_entity_validation() {
    // Test user entity creation and validation
    let user_id = UserId::new();
    let email = Email::new("user@test.com".to_string()).unwrap();
    let password_hash = PasswordHash::new("$argon2id$v=19$m=65536,t=3,p=4$abcdefghijklmnopqrstuvwxyz$hash123456789012345678901234567890".to_string()).unwrap();

    let user = User::new(
        user_id.clone(),
        email.clone(),
        password_hash,
        Some("Test User".to_string()),
    );

    assert_eq!(user.id, user_id);
    assert_eq!(user.email, email);
    assert_eq!(user.name, Some("Test User".to_string()));
    assert!(user.is_active);
    assert!(!user.email_verified); // Should start as unverified
    assert!(user.roles.is_empty()); // Should start with no roles
}

#[tokio::test]
async fn test_email_validation() {
    // Test email value object validation
    assert!(Email::new("valid@example.com".to_string()).is_ok());
    assert!(Email::new("user.name+tag@domain.co.uk".to_string()).is_ok());

    // Invalid emails should fail
    assert!(Email::new("invalid".to_string()).is_err());
    assert!(Email::new("@invalid.com".to_string()).is_err());
    assert!(Email::new("invalid@".to_string()).is_err());
    assert!(Email::new(String::new()).is_err());
}

#[tokio::test]
async fn test_user_id_generation() {
    // Test UserId generation and uniqueness
    let id1 = UserId::new();
    let id2 = UserId::new();

    assert_ne!(id1, id2); // Should be unique
    assert!(!id1.as_str().is_empty());
    assert!(!id2.as_str().is_empty());

    // Test round-trip conversion
    let id_string = id1.as_str().to_string();
    let restored_id = UserId::from_string(id_string).unwrap();
    assert_eq!(id1, restored_id);
}

#[tokio::test]
async fn test_password_hash_security() {
    // Test password hash creation and verification
    let password1 = "password123";
    let password2 = "password123";
    let different_password = "different456";

    let crypto = CryptoService::new("test_key".to_string());

    let hash1 = crypto.hash_password(password1).await.unwrap();
    let hash2 = crypto.hash_password(password2).await.unwrap();

    // Same password should produce different hashes (salted)
    assert_ne!(hash1.as_str(), hash2.as_str());

    // Both should verify correctly
    assert!(crypto.verify_password(password1, &hash1).await.unwrap());
    assert!(crypto.verify_password(password2, &hash2).await.unwrap());

    // Wrong password should fail
    assert!(!crypto
        .verify_password(different_password, &hash1)
        .await
        .unwrap());
}

/// Integration test for core authentication flow
#[tokio::test]
async fn test_complete_auth_flow_integration() {
    // This test ensures the core auth flow works end-to-end
    // without depending on security modules

    let crypto_service = Arc::new(CryptoService::new("integration_test_secret".to_string()));

    // 1. Create user credentials
    let email = Email::new("integration@test.com".to_string()).unwrap();
    let password = "test_integration_password";
    let password_hash = crypto_service.hash_password(password).await.unwrap();

    // 2. Create user
    let user_id = UserId::new();
    let user = User::new(
        user_id.clone(),
        email.clone(),
        password_hash.clone(),
        Some("Integration Test User".to_string()),
    );

    // 3. Verify user state
    assert!(user.is_active);
    assert!(!user.email_verified);

    // 4. Create session
    let session = Session::new(user_id.clone(), chrono::Utc::now());
    assert!(!session.is_expired());

    // 5. Create tokens
    let access_token = Token::new_access_token(
        user_id.clone(),
        "access_hash_integration".to_string(),
        chrono::Utc::now() + chrono::Duration::hours(1),
    );

    let refresh_token = Token::new_refresh_token(
        user_id.clone(),
        "refresh_hash_integration".to_string(),
        chrono::Utc::now() + chrono::Duration::days(30),
        session.id.clone(),
    );

    // 6. Verify token states
    assert!(access_token.is_active());
    assert!(refresh_token.is_active());
    assert_eq!(refresh_token.session_id, Some(session.id.clone()));

    // 7. Test password verification (simulating login)
    let login_valid = crypto_service
        .verify_password(password, &password_hash)
        .await
        .unwrap();
    assert!(login_valid);

    // 8. Test invalid login
    let login_invalid = crypto_service
        .verify_password("wrong_password", &password_hash)
        .await
        .unwrap();
    assert!(!login_invalid);
}
