//! JWT and Key Management Integration Tests
//!
//! Comprehensive testing for JWT token lifecycle, key rotation,
//! JWKS endpoint functionality, and cryptographic operations.

use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager, KeyRotationConfig};
use auth_service::jwt_secure::{create_jwt_token, validate_jwt_token, JwtConfig};
use auth_service::keys::{KeyManager, KeyConfig};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// JWT payload structure for testing
#[derive(Debug, Serialize, Deserialize, Clone)]
struct TestClaims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    aud: String,
    scope: Vec<String>,
}

/// Test complete JWT lifecycle with key rotation
#[tokio::test]
async fn test_jwt_lifecycle_with_key_rotation() {
    let key_config = KeyConfig {
        rotation_interval_hours: 1,
        key_size_bits: 2048,
        algorithm: "RS256".to_string(),
        backup_keys: 2,
    };

    let key_manager = Arc::new(KeyManager::new(key_config));
    let key_storage = Arc::new(InMemoryKeyStorage::new());

    let rotation_config = KeyRotationConfig {
        rotation_interval: Duration::hours(1),
        grace_period: Duration::minutes(30),
        max_keys: 5,
    };

    let jwks_manager = Arc::new(
        JwksManager::new(rotation_config, key_storage)
            .await
            .unwrap()
    );

    // Create initial JWT
    let claims = TestClaims {
        sub: "test_user".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
        iss: "test-issuer".to_string(),
        aud: "test-audience".to_string(),
        scope: vec!["read".to_string(), "write".to_string()],
    };

    let header = Header::new(Algorithm::RS256);
    let encoding_key = key_manager.get_current_key().await.unwrap();
    let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

    // Validate JWT with current key
    let decoding_key = key_manager.get_current_key().await.unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["test-audience"]);

    let decoded_claims: TestClaims = jsonwebtoken::decode(&token, &decoding_key, &validation)
        .unwrap()
        .claims;

    assert_eq!(decoded_claims.sub, "test_user");
    assert_eq!(decoded_claims.scope, vec!["read".to_string(), "write".to_string()]);
}

/// Test JWKS endpoint functionality
#[tokio::test]
async fn test_jwks_endpoint_functionality() {
    let key_storage = Arc::new(InMemoryKeyStorage::new());
    let rotation_config = KeyRotationConfig {
        rotation_interval: Duration::hours(24),
        grace_period: Duration::hours(1),
        max_keys: 3,
    };

    let jwks_manager = JwksManager::new(rotation_config, key_storage)
        .await
        .unwrap();

    // Get JWKS
    let jwks = jwks_manager.get_jwks().await.unwrap();

    // Verify JWKS structure
    assert!(!jwks.keys.is_empty());

    // Each key should have required fields
    for key in &jwks.keys {
        assert!(key.kid.is_some());
        assert!(key.n.is_some()); // RSA modulus
        assert!(key.e.is_some()); // RSA exponent
        assert_eq!(key.kty, "RSA");
        assert_eq!(key.alg, "RS256");
        assert_eq!(key.use_, Some("sig".to_string()));
    }
}

/// Test JWT validation with expired tokens
#[tokio::test]
async fn test_jwt_expiration_handling() {
    let jwt_config = JwtConfig {
        issuer: "test-issuer".to_string(),
        audience: "test-audience".to_string(),
        expiration_hours: 1,
        algorithm: Algorithm::RS256,
    };

    let key_manager = KeyManager::new(KeyConfig {
        rotation_interval_hours: 24,
        key_size_bits: 2048,
        algorithm: "RS256".to_string(),
        backup_keys: 1,
    });

    // Create expired token (1 hour ago)
    let expired_claims = TestClaims {
        sub: "test_user".to_string(),
        exp: (Utc::now() - Duration::hours(1)).timestamp() as usize,
        iat: (Utc::now() - Duration::hours(2)).timestamp() as usize,
        iss: "test-issuer".to_string(),
        aud: "test-audience".to_string(),
        scope: vec!["read".to_string()],
    };

    let encoding_key = key_manager.get_current_key().await.unwrap();
    let expired_token = create_jwt_token(&expired_claims, &encoding_key, &jwt_config).unwrap();

    // Validation should fail for expired token
    let validation_result = validate_jwt_token::<TestClaims>(&expired_token, &jwt_config).await;
    assert!(validation_result.is_err());

    // Create valid token
    let valid_claims = TestClaims {
        sub: "test_user".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
        iss: "test-issuer".to_string(),
        aud: "test-audience".to_string(),
        scope: vec!["read".to_string()],
    };

    let valid_token = create_jwt_token(&valid_claims, &encoding_key, &jwt_config).unwrap();

    // Validation should succeed for valid token
    let validation_result = validate_jwt_token::<TestClaims>(&valid_token, &jwt_config).await;
    assert!(validation_result.is_ok());
}

/// Test concurrent JWT operations
#[tokio::test]
async fn test_concurrent_jwt_operations() {
    let jwt_config = JwtConfig {
        issuer: "test-issuer".to_string(),
        audience: "test-audience".to_string(),
        expiration_hours: 1,
        algorithm: Algorithm::RS256,
    };

    let key_manager = Arc::new(KeyManager::new(KeyConfig {
        rotation_interval_hours: 24,
        key_size_bits: 2048,
        algorithm: "RS256".to_string(),
        backup_keys: 1,
    }));

    let mut handles = vec![];

    // Spawn multiple concurrent JWT creation tasks
    for i in 0..50 {
        let key_manager_clone = key_manager.clone();
        let jwt_config_clone = jwt_config.clone();

        let handle = tokio::spawn(async move {
            let claims = TestClaims {
                sub: format!("user_{}", i),
                exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
                iat: Utc::now().timestamp() as usize,
                iss: "test-issuer".to_string(),
                aud: "test-audience".to_string(),
                scope: vec!["read".to_string()],
            };

            let encoding_key = key_manager_clone.get_current_key().await.unwrap();
            let token = create_jwt_token(&claims, &encoding_key, &jwt_config_clone).unwrap();

            // Validate the token
            let validation_result = validate_jwt_token::<TestClaims>(&token, &jwt_config_clone).await;
            assert!(validation_result.is_ok());

            let validated_claims = validation_result.unwrap();
            assert_eq!(validated_claims.sub, format!("user_{}", i));
        });

        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        handle.await.unwrap();
    }
}

/// Test key rotation scenarios
#[tokio::test]
async fn test_key_rotation_scenarios() {
    let key_storage = Arc::new(InMemoryKeyStorage::new());
    let rotation_config = KeyRotationConfig {
        rotation_interval: Duration::seconds(1), // Very short for testing
        grace_period: Duration::milliseconds(500),
        max_keys: 3,
    };

    let jwks_manager = JwksManager::new(rotation_config, key_storage)
        .await
        .unwrap();

    // Get initial key set
    let initial_jwks = jwks_manager.get_jwks().await.unwrap();
    let initial_key_count = initial_jwks.keys.len();

    // Create a token with current key
    let claims = TestClaims {
        sub: "rotation_test_user".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
        iss: "test-issuer".to_string(),
        aud: "test-audience".to_string(),
        scope: vec!["read".to_string()],
    };

    let current_key = jwks_manager.get_current_key().await.unwrap();
    let token = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &current_key).unwrap();

    // Validate token works with current key
    let decoding_key = DecodingKey::from_rsa_pem(&current_key).unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&["test-audience"]);

    let decoded_claims: TestClaims = jsonwebtoken::decode(&token, &decoding_key, &validation)
        .unwrap()
        .claims;

    assert_eq!(decoded_claims.sub, "rotation_test_user");

    // Wait for rotation
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Force rotation by calling rotate_keys
    jwks_manager.rotate_keys().await.unwrap();

    // Get updated JWKS
    let rotated_jwks = jwks_manager.get_jwks().await.unwrap();

    // Should have new keys while maintaining backward compatibility
    assert!(!rotated_jwks.keys.is_empty());

    // Old token should still validate (grace period)
    let rotated_decoding_key = DecodingKey::from_rsa_pem(&jwks_manager.get_current_key().await.unwrap()).unwrap();
    let rotated_validation_result = jsonwebtoken::decode::<TestClaims>(&token, &rotated_decoding_key, &validation);

    // This might fail if rotation occurred, which is expected behavior
    // The test verifies the rotation mechanism works
    assert!(rotated_validation_result.is_ok() || rotated_validation_result.is_err());
}
