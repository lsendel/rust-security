// Comprehensive OAuth2/OIDC flow integration tests

use crate::test_utils::*;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::collections::HashMap;

mod test_utils;

#[tokio::test]
async fn test_client_credentials_flow_complete() {
    let fixture = TestFixture::new().await;
    
    // Test successful token issuance
    let response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body("grant_type=client_credentials&scope=read write")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let token_response: Value = response.json().await.unwrap();
    
    // Verify token response structure
    assert!(token_response.get("access_token").is_some());
    assert!(token_response.get("refresh_token").is_some());
    assert_eq!(token_response.get("token_type").unwrap(), "Bearer");
    assert!(token_response.get("expires_in").unwrap().as_u64().unwrap() > 0);
    assert_eq!(token_response.get("scope").unwrap(), "read write");
    
    let access_token = token_response["access_token"].as_str().unwrap();
    
    // Test token introspection
    let introspect_response = fixture.client
        .post(&format!("{}/oauth/introspect", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body(format!("token={}", access_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(introspect_response.status(), 200);
    let introspect_data: Value = introspect_response.json().await.unwrap();
    
    assert_eq!(introspect_data.get("active").unwrap(), true);
    assert_eq!(introspect_data.get("scope").unwrap(), "read write");
    assert_eq!(introspect_data.get("client_id").unwrap(), &fixture.valid_client_id);
    assert!(introspect_data.get("exp").unwrap().as_i64().unwrap() > 0);
    assert!(introspect_data.get("iat").unwrap().as_i64().unwrap() > 0);
    
    // Test token revocation
    let refresh_token = token_response["refresh_token"].as_str().unwrap();
    let revoke_response = fixture.client
        .post(&format!("{}/oauth/revoke", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body(format!("token={}&token_type_hint=refresh_token", refresh_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(revoke_response.status(), 200);
    let revoke_data: Value = revoke_response.json().await.unwrap();
    assert_eq!(revoke_data.get("revoked").unwrap(), true);
}

#[tokio::test]
async fn test_authorization_code_flow_with_pkce() {
    let fixture = TestFixture::new().await;
    let (code_verifier, code_challenge) = fixture.generate_pkce_challenge();
    
    // Step 1: Authorization request
    let auth_params = format!(
        "response_type=code&client_id={}&redirect_uri=https://example.com/callback&scope=openid profile&state=test_state&code_challenge={}&code_challenge_method=S256",
        fixture.valid_client_id,
        code_challenge
    );
    
    let auth_response = fixture.client
        .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
        .send()
        .await
        .unwrap();
    
    // Should redirect with authorization code
    assert_eq!(auth_response.status(), 302);
    let location = auth_response.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("code="));
    assert!(location.contains("state=test_state"));
    
    // Extract authorization code from redirect
    let url = url::Url::parse(location).unwrap();
    let code = url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .unwrap();
    
    // Step 2: Exchange authorization code for tokens
    let token_params = format!(
        "grant_type=authorization_code&code={}&redirect_uri=https://example.com/callback&client_id={}&code_verifier={}",
        code, fixture.valid_client_id, code_verifier
    );
    
    let token_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(token_params)
        .send()
        .await
        .unwrap();
    
    assert_eq!(token_response.status(), 200);
    let token_data: Value = token_response.json().await.unwrap();
    
    assert!(token_data.get("access_token").is_some());
    assert!(token_data.get("refresh_token").is_some());
    assert!(token_data.get("id_token").is_some()); // Because scope includes openid
    assert_eq!(token_data.get("token_type").unwrap(), "Bearer");
    
    // Test userinfo endpoint with the access token
    let access_token = token_data["access_token"].as_str().unwrap();
    let userinfo_response = fixture.client
        .get(&format!("{}/oauth/userinfo", fixture.base_url))
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(userinfo_response.status(), 200);
    let userinfo: Value = userinfo_response.json().await.unwrap();
    assert!(userinfo.get("sub").is_some());
    assert!(userinfo.get("scope").is_some());
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let fixture = TestFixture::new().await;
    
    // Get initial tokens
    let token_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body("grant_type=client_credentials&scope=read")
        .send()
        .await
        .unwrap();
    
    let initial_tokens: Value = token_response.json().await.unwrap();
    let refresh_token = initial_tokens["refresh_token"].as_str().unwrap();
    
    // Use refresh token to get new tokens
    let refresh_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("grant_type=refresh_token&refresh_token={}&scope=read", refresh_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(refresh_response.status(), 200);
    let new_tokens: Value = refresh_response.json().await.unwrap();
    
    assert!(new_tokens.get("access_token").is_some());
    assert!(new_tokens.get("refresh_token").is_some());
    assert_eq!(new_tokens.get("scope").unwrap(), "read");
    
    // Old refresh token should be invalidated
    let old_refresh_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("grant_type=refresh_token&refresh_token={}", refresh_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(old_refresh_response.status(), 401);
}

#[tokio::test]
async fn test_refresh_token_reuse_detection() {
    let fixture = TestFixture::new().await;
    
    // Get initial tokens
    let token_response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    
    let tokens: Value = token_response.json().await.unwrap();
    let refresh_token = tokens["refresh_token"].as_str().unwrap();
    
    // First refresh should succeed
    let first_refresh = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("grant_type=refresh_token&refresh_token={}", refresh_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(first_refresh.status(), 200);
    
    // Second attempt with same token should fail (reuse detection)
    let second_refresh = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("grant_type=refresh_token&refresh_token={}", refresh_token))
        .send()
        .await
        .unwrap();
    
    assert_eq!(second_refresh.status(), 401);
}

#[tokio::test]
async fn test_scope_validation() {
    let fixture = TestFixture::new().await;
    
    // Test valid scopes
    let valid_scopes = ["read", "write", "read write", "openid profile email"];
    
    for scope in valid_scopes {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("grant_type=client_credentials&scope={}", scope))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 200, "Valid scope '{}' should be accepted", scope);
        
        let token_response: Value = response.json().await.unwrap();
        assert_eq!(token_response.get("scope").unwrap(), scope);
    }
    
    // Test invalid scopes
    let invalid_scopes = ["invalid", "read invalid", "admin delete"];
    
    for scope in invalid_scopes {
        let response = fixture.client
            .post(&format!("{}/oauth/token", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("grant_type=client_credentials&scope={}", scope))
            .send()
            .await
            .unwrap();
        
        assert_eq!(response.status(), 400, "Invalid scope '{}' should be rejected", scope);
    }
}

#[tokio::test]
async fn test_openid_id_token_generation() {
    let fixture = TestFixture::new().await;
    
    // Request token with openid scope
    let response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body("grant_type=client_credentials&scope=openid profile")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let token_response: Value = response.json().await.unwrap();
    
    // Should include ID token when openid scope is requested
    assert!(token_response.get("id_token").is_some());
    let id_token = token_response["id_token"].as_str().unwrap();
    
    // Basic JWT format validation
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "ID token should be a valid JWT with 3 parts");
    
    // Decode header (without verification for test)
    let header_json = base64::decode_config(parts[0], base64::URL_SAFE_NO_PAD).unwrap();
    let header: Value = serde_json::from_slice(&header_json).unwrap();
    assert_eq!(header.get("alg").unwrap(), "RS256");
    assert!(header.get("kid").is_some());
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let fixture = TestFixture::new().await;
    
    let response = fixture.client
        .get(&format!("{}/jwks.json", fixture.base_url))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    let jwks: Value = response.json().await.unwrap();
    
    assert!(jwks.get("keys").is_some());
    let keys = jwks["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    
    for key in keys {
        assert_eq!(key.get("kty").unwrap(), "RSA");
        assert_eq!(key.get("use").unwrap(), "sig");
        assert_eq!(key.get("alg").unwrap(), "RS256");
        assert!(key.get("kid").is_some());
        assert!(key.get("n").is_some());
        assert!(key.get("e").is_some());
    }
}

#[tokio::test]
async fn test_well_known_endpoints() {
    let fixture = TestFixture::new().await;
    
    // Test OAuth authorization server metadata
    let oauth_response = fixture.client
        .get(&format!("{}/.well-known/oauth-authorization-server", fixture.base_url))
        .send()
        .await
        .unwrap();
    
    assert_eq!(oauth_response.status(), 200);
    let oauth_metadata: Value = oauth_response.json().await.unwrap();
    
    assert!(oauth_metadata.get("issuer").is_some());
    assert!(oauth_metadata.get("token_endpoint").is_some());
    assert!(oauth_metadata.get("authorization_endpoint").is_some());
    assert!(oauth_metadata.get("introspection_endpoint").is_some());
    assert!(oauth_metadata.get("revocation_endpoint").is_some());
    assert!(oauth_metadata.get("jwks_uri").is_some());
    
    let supported_grants = oauth_metadata["grant_types_supported"].as_array().unwrap();
    assert!(supported_grants.contains(&Value::String("client_credentials".to_string())));
    assert!(supported_grants.contains(&Value::String("authorization_code".to_string())));
    assert!(supported_grants.contains(&Value::String("refresh_token".to_string())));
    
    // Test OpenID Connect discovery
    let oidc_response = fixture.client
        .get(&format!("{}/.well-known/openid-configuration", fixture.base_url))
        .send()
        .await
        .unwrap();
    
    assert_eq!(oidc_response.status(), 200);
    let oidc_metadata: Value = oidc_response.json().await.unwrap();
    
    assert!(oidc_metadata.get("userinfo_endpoint").is_some());
    
    let supported_scopes = oidc_metadata["scopes_supported"].as_array().unwrap();
    assert!(supported_scopes.contains(&Value::String("openid".to_string())));
    assert!(supported_scopes.contains(&Value::String("profile".to_string())));
    assert!(supported_scopes.contains(&Value::String("email".to_string())));
    
    let supported_response_types = oidc_metadata["response_types_supported"].as_array().unwrap();
    assert!(supported_response_types.contains(&Value::String("code".to_string())));
    
    let supported_pkce_methods = oidc_metadata["code_challenge_methods_supported"].as_array().unwrap();
    assert!(supported_pkce_methods.contains(&Value::String("S256".to_string())));
}

#[tokio::test]
async fn test_invalid_authorization_requests() {
    let fixture = TestFixture::new().await;
    
    // Test missing response_type
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?client_id={}", fixture.base_url, fixture.valid_client_id))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    
    // Test invalid response_type
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?response_type=token&client_id={}&redirect_uri=https://example.com", 
            fixture.base_url, fixture.valid_client_id))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    
    // Test missing client_id
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?response_type=code&redirect_uri=https://example.com", fixture.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    
    // Test invalid redirect_uri
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?response_type=code&client_id={}&redirect_uri=javascript:alert(1)", 
            fixture.base_url, fixture.valid_client_id))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_pkce_security_requirements() {
    let fixture = TestFixture::new().await;
    
    // Test that plain PKCE method is rejected
    let auth_params = format!(
        "response_type=code&client_id={}&redirect_uri=https://example.com/callback&code_challenge=test&code_challenge_method=plain",
        fixture.valid_client_id
    );
    
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 400);
    
    // Test that S256 is required when challenge is provided
    let (_, code_challenge) = fixture.generate_pkce_challenge();
    let auth_params = format!(
        "response_type=code&client_id={}&redirect_uri=https://example.com/callback&code_challenge={}",
        fixture.valid_client_id, code_challenge
    );
    
    let response = fixture.client
        .get(&format!("{}/oauth/authorize?{}", fixture.base_url, auth_params))
        .send()
        .await
        .unwrap();
    
    // Should succeed with default S256 method
    assert_eq!(response.status(), 302);
}

#[tokio::test]
async fn test_token_endpoint_error_responses() {
    let fixture = TestFixture::new().await;
    
    // Test unsupported grant type
    let response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body("grant_type=password&username=test&password=test")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 400);
    let error_response = response.text().await.unwrap();
    assert!(error_response.contains("unsupported grant_type"));
    
    // Test invalid client credentials
    let response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.invalid_client_id, &fixture.invalid_client_secret))
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 401);
    
    // Test missing client credentials
    let response = fixture.client
        .post(&format!("{}/oauth/token", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("grant_type=client_credentials")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_concurrent_token_operations() {
    let fixture = TestFixture::new().await;
    
    // Test concurrent token issuance
    let mut handles = Vec::new();
    
    for i in 0..10 {
        let fixture_clone = &fixture;
        let client = fixture_clone.client.clone();
        let base_url = fixture_clone.base_url.clone();
        let auth_header = fixture_clone.basic_auth_header(&fixture_clone.valid_client_id, &fixture_clone.valid_client_secret);
        
        let handle = tokio::spawn(async move {
            let response = client
                .post(&format!("{}/oauth/token", base_url))
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(AUTHORIZATION, auth_header)
                .body(format!("grant_type=client_credentials&scope=read_{}", i))
                .send()
                .await
                .unwrap();
            
            assert_eq!(response.status(), 200);
            
            let token_response: Value = response.json().await.unwrap();
            assert!(token_response.get("access_token").is_some());
            
            token_response["access_token"].as_str().unwrap().to_string()
        });
        
        handles.push(handle);
    }
    
    // Collect all tokens
    let mut tokens = Vec::new();
    for handle in handles {
        tokens.push(handle.await.unwrap());
    }
    
    // All tokens should be unique
    let mut unique_tokens = std::collections::HashSet::new();
    for token in &tokens {
        assert!(unique_tokens.insert(token.clone()), "Token should be unique: {}", token);
    }
    
    assert_eq!(tokens.len(), 10);
    assert_eq!(unique_tokens.len(), 10);
}

#[tokio::test]
async fn test_token_expiration_validation() {
    let fixture = TestFixture::new().await;
    
    // Get a token
    let access_token = fixture.get_access_token().await;
    
    // Token should be active immediately
    let response = fixture.client
        .post(&format!("{}/oauth/introspect", fixture.base_url))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
        .body(format!("token={}", access_token))
        .send()
        .await
        .unwrap();
    
    let introspect_data: Value = response.json().await.unwrap();
    assert_eq!(introspect_data.get("active").unwrap(), true);
    
    // Check expiration time is in the future
    let exp = introspect_data.get("exp").unwrap().as_i64().unwrap();
    let now = chrono::Utc::now().timestamp();
    assert!(exp > now, "Token expiration should be in the future");
    
    // Check issued at time is in the past or present
    let iat = introspect_data.get("iat").unwrap().as_i64().unwrap();
    assert!(iat <= now, "Token issued at time should be in the past or present");
}

#[tokio::test]
async fn test_userinfo_endpoint_security() {
    let fixture = TestFixture::new().await;
    
    // Test without token
    let response = fixture.client
        .get(&format!("{}/oauth/userinfo", fixture.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    
    // Test with invalid token
    let response = fixture.client
        .get(&format!("{}/oauth/userinfo", fixture.base_url))
        .header(AUTHORIZATION, "Bearer invalid_token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    
    // Test with token without openid scope
    let token = fixture.get_access_token_with_scope(Some("read")).await;
    let response = fixture.client
        .get(&format!("{}/oauth/userinfo", fixture.base_url))
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401); // Insufficient scope
    
    // Test with valid openid token
    let token = fixture.get_access_token_with_scope(Some("openid profile")).await;
    let response = fixture.client
        .get(&format!("{}/oauth/userinfo", fixture.base_url))
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    
    let userinfo: Value = response.json().await.unwrap();
    assert!(userinfo.get("sub").is_some());
    assert!(userinfo.get("scope").is_some());
}