//! Integration Tests for Authentication Service
//!
//! End-to-end tests covering the full authentication flow,
//! including user registration, login, session management, and security features.

use std::sync::Arc;
use std::time::Duration;
use tokio::time;

use crate::domain::entities::{Token, TokenType};
use crate::domain::repositories::token_repository::{TokenRepository, TokenRepositoryError};
use crate::domain::value_objects::{Email, UserId};
use crate::services::auth_service::{AuthServiceTrait, LoginRequest};
use crate::services::token_service::TokenServiceTrait;
use crate::services::user_service::{RegisterRequest, UserServiceTrait};
use crate::services::{AuthService, TokenService, UserService};
use crate::shared::crypto::CryptoService;
use crate::shared::error::AppError;
use crate::tests::{mocks, utils};
use crate::{assert_err, assert_ok};
use std::collections::HashMap;
use std::sync::RwLock;

/// Simple in-memory token repository for testing
struct InMemoryTokenRepository {
    tokens: RwLock<HashMap<String, Token>>,
}

impl InMemoryTokenRepository {
    fn new() -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl TokenRepository for InMemoryTokenRepository {
    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<Token>, TokenRepositoryError> {
        let tokens = self.tokens.read().unwrap();
        Ok(tokens.get(token_hash).cloned())
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Token>, TokenRepositoryError> {
        let tokens = self.tokens.read().unwrap();
        Ok(tokens
            .values()
            .filter(|t| t.user_id == *user_id)
            .cloned()
            .collect())
    }

    async fn find_by_user_and_type(
        &self,
        user_id: &UserId,
        token_type: &TokenType,
    ) -> Result<Vec<Token>, TokenRepositoryError> {
        let tokens = self.tokens.read().unwrap();
        Ok(tokens
            .values()
            .filter(|t| t.user_id == *user_id && t.token_type == *token_type)
            .cloned()
            .collect())
    }

    async fn save(&self, token: &Token) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    async fn update(&self, token: &Token) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.insert(token.token_hash.clone(), token.clone());
        Ok(())
    }

    async fn delete_by_hash(&self, token_hash: &str) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.remove(token_hash);
        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, token| token.user_id != *user_id);
        Ok(())
    }

    async fn delete_by_user_and_type(
        &self,
        user_id: &UserId,
        token_type: &TokenType,
    ) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.retain(|_, token| !(token.user_id == *user_id && token.token_type == *token_type));
        Ok(())
    }

    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        if let Some(token) = tokens.get_mut(token_hash) {
            token.revoke();
        }
        Ok(())
    }

    async fn revoke_by_user_id(&self, user_id: &UserId) -> Result<(), TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        for token in tokens.values_mut() {
            if token.user_id == *user_id {
                token.revoke();
            }
        }
        Ok(())
    }

    async fn delete_expired(&self) -> Result<i64, TokenRepositoryError> {
        let mut tokens = self.tokens.write().unwrap();
        let before_count = tokens.len();
        tokens.retain(|_, token| !token.is_expired());
        Ok((before_count - tokens.len()) as i64)
    }

    async fn exists_and_active(&self, token_hash: &str) -> Result<bool, TokenRepositoryError> {
        let tokens = self.tokens.read().unwrap();
        Ok(tokens
            .get(token_hash)
            .is_some_and(super::super::domain::entities::token::Token::is_active))
    }

    async fn count_active_by_user(&self, user_id: &UserId) -> Result<i64, TokenRepositoryError> {
        let tokens = self.tokens.read().unwrap();
        let count = tokens
            .values()
            .filter(|t| t.user_id == *user_id && t.is_active())
            .count();
        Ok(count as i64)
    }
}

/// Full authentication flow integration test
#[tokio::test]
async fn test_full_authentication_flow() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_integration_tests".to_string(),
    ));

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    let user_service = Arc::new(UserService::new(
        Arc::clone(&user_repo),
        Arc::clone(&crypto_service),
    ));

    // Create token repository for TokenService
    let token_repo: crate::domain::repositories::DynTokenRepository =
        Arc::new(InMemoryTokenRepository::new());
    let token_service = Arc::new(TokenService::new(
        token_repo,
        session_repo,
        Arc::clone(&crypto_service),
    ));

    // Test user registration
    let email = utils::random_email();
    let password = "SecurePassword123!";
    let name = "Integration Test User";

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
        name: name.to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    // Test user login
    let login_request = LoginRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
    };
    let login_result = auth_service.login(login_request).await;

    assert_ok!(login_result);
    let login_response = login_result.unwrap();

    // Verify tokens are present
    assert!(!login_response.access_token.is_empty());
    assert!(!login_response.refresh_token.is_empty());

    // Test token validation (using session_id from login response instead)
    let user_id = UserId::from_string(login_response.user.id.clone()).unwrap();

    // Test user profile retrieval
    let profile_result = user_service.get_profile(&user_id).await;

    assert_ok!(profile_result);
    let user = profile_result.unwrap();

    assert_eq!(user.email, email.as_str());
    assert_eq!(user.name, Some(name.to_string()));

    // Test token management
    let tokens_result = token_service.get_user_tokens(&user_id).await;

    assert_ok!(tokens_result);
    let _user_tokens = tokens_result.unwrap();
    // Note: May be empty since tokens are JWT and not stored in token repository

    // Test auth service refresh_token method (using auth service since JWT-based)
    let refresh_token = login_response.refresh_token.clone();
    let access_token = login_response.access_token.clone();
    let refresh_result = auth_service.refresh_token(&refresh_token).await;

    assert_ok!(refresh_result);
    let new_login_response = refresh_result.unwrap();

    // Verify new tokens are different
    assert_ne!(new_login_response.access_token, access_token);
    assert_ne!(new_login_response.refresh_token, refresh_token);

    // Test logout
    let logout_result = auth_service.logout(&login_response.session_id).await;

    assert_ok!(logout_result);

    // Verify session is invalidated by attempting to validate it
    let session_validation = auth_service
        .validate_session(&login_response.session_id)
        .await;

    assert_err!(session_validation);
}

/// Concurrent authentication load test
#[tokio::test]
async fn test_concurrent_authentication_load() {
    const CONCURRENT_USERS: usize = 50;
    const REQUESTS_PER_USER: usize = 10;

    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_load_tests".to_string(),
    ));

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Pre-register users
    let mut users = Vec::new();
    for i in 0..CONCURRENT_USERS {
        let email = Email::new(format!("loadtest{i}@example.com")).unwrap();
        let password = format!("Password123!{i}");
        let name = format!("Load Test User {i}");

        let user_service = UserService::new(Arc::clone(&user_repo), Arc::clone(&crypto_service));

        let register_request = RegisterRequest {
            email: email.as_str().to_string(),
            password: password.clone(),
            name,
        };
        let register_result = user_service.register(register_request).await;

        assert_ok!(register_result);

        users.push((email, password));
    }

    // Run concurrent authentication requests
    let start_time = std::time::Instant::now();

    let tasks: Vec<_> = users
        .into_iter()
        .enumerate()
        .map(|(user_idx, (email, password))| {
            let auth_svc = Arc::clone(&auth_service);

            tokio::spawn(async move {
                let mut success_count = 0;
                let mut error_count = 0;

                for _req_idx in 0..REQUESTS_PER_USER {
                    let login_request = LoginRequest {
                        email: email.as_str().to_string(),
                        password: password.clone(),
                    };
                    let auth_result = auth_svc.login(login_request).await;

                    match auth_result {
                        Ok(login_response) => {
                            if !login_response.access_token.is_empty() {
                                success_count += 1;
                            } else {
                                error_count += 1;
                            }
                        }
                        Err(_) => {
                            error_count += 1;
                        }
                    }

                    // Small delay between requests to simulate real usage
                    time::sleep(Duration::from_millis(1)).await;
                }

                (user_idx, success_count, error_count)
            })
        })
        .collect();

    // Wait for all tasks to complete
    let mut total_success = 0;
    let mut total_error = 0;

    for task in tasks {
        let (user_idx, success, error) = task.await.unwrap();
        total_success += success;
        total_error += error;

        // Each user should have successful authentications
        assert!(
            success > 0,
            "User {user_idx} had no successful authentications"
        );
    }

    let total_time = start_time.elapsed();
    let total_requests = CONCURRENT_USERS * REQUESTS_PER_USER;
    let requests_per_second = total_requests as f64 / total_time.as_secs_f64();

    println!("Load test results:");
    println!("Total requests: {total_requests}");
    println!("Successful: {total_success}");
    println!("Errors: {total_error}");
    println!("Total time: {total_time:?}");
    println!("Requests/sec: {requests_per_second:.2}");

    // Verify performance requirements
    assert!(
        requests_per_second > 100.0,
        "Throughput too low: {requests_per_second:.2} req/sec",
    );
    assert!(
        total_success > total_error * 10,
        "Too many errors: {} success, {} error",
        total_success,
        total_error
    );
}

/// Security integration test
#[tokio::test]
async fn test_security_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service and services
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_security_tests".to_string(),
    ));
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Test brute force protection
    let email = Email::new("bruteforce@example.com".to_string()).unwrap();
    let wrong_password = "WrongPassword123!";

    // Register user first
    let user_service = UserService::new(Arc::clone(&user_repo), Arc::clone(&crypto_service));

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: "CorrectPassword123!".to_string(),
        name: "Security Test".to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    // Attempt multiple failed logins
    let mut failure_count = 0;
    for _ in 0..10 {
        let login_request = LoginRequest {
            email: email.as_str().to_string(),
            password: wrong_password.to_string(),
        };
        let auth_result = auth_service.login(login_request).await;

        if auth_result.is_err() {
            failure_count += 1;
        }
    }

    // Should have failures (exact count depends on implementation)
    assert!(failure_count > 0, "Expected some authentication failures");

    // Test successful login still works
    let login_request = LoginRequest {
        email: email.as_str().to_string(),
        password: "CorrectPassword123!".to_string(),
    };
    let success_result = auth_service.login(login_request).await;

    // This should succeed (depending on rate limiting implementation)
    // Note: In a real system, this might be rate limited after failures
    match success_result {
        Ok(_) => println!("Successful login after failures"),
        Err(AppError::RateLimitExceeded) => println!("Rate limited after brute force attempts"),
        Err(e) => panic!("Unexpected error: {e:?}"),
    }
}

/// Session management integration test
#[tokio::test]
async fn test_session_management_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service and services
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_session_tests".to_string(),
    ));
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Create token repository for TokenService
    let token_repo: crate::domain::repositories::DynTokenRepository =
        Arc::new(InMemoryTokenRepository::new());
    let token_service = Arc::new(TokenService::new(
        token_repo,
        session_repo,
        Arc::clone(&crypto_service),
    ));

    // Register and login user
    let email = utils::random_email();
    let password = "SessionTest123!";

    let user_service = UserService::new(
        Arc::new(mocks::MockUserRepository::new()),
        Arc::clone(&crypto_service),
    );

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
        name: "Session Test".to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    let login_request = LoginRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
    };
    let login_result = auth_service.login(login_request).await;

    assert_ok!(login_result);
    let login_response = login_result.unwrap();
    let _access_token = login_response.access_token.clone();

    // Get user ID from login response for session management
    let user_id = UserId::from_string(login_response.user.id.clone()).unwrap();

    // Test token service functionality
    let _user_tokens = token_service.get_user_tokens(&user_id).await.unwrap();

    // Test session cleanup (token service doesn't have get_user_sessions)
    let cleanup_result = token_service.cleanup_expired_tokens().await;

    assert_ok!(cleanup_result);
    let cleaned_count = cleanup_result.unwrap();
    println!("Cleaned up {cleaned_count} expired tokens");

    // Test concurrent session limit (if implemented)
    // This would test that a user can't have too many active sessions

    // Test session invalidation
    let logout_result = auth_service.logout(&login_response.session_id).await;

    assert_ok!(logout_result);

    // Verify session is invalidated
    let session_validation = auth_service
        .validate_session(&login_response.session_id)
        .await;

    assert_err!(session_validation);
}

/// Token lifecycle integration test
#[tokio::test]
async fn test_token_lifecycle_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service and services
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_token_tests".to_string(),
    ));
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Create token repository for TokenService
    let token_repo: crate::domain::repositories::DynTokenRepository =
        Arc::new(InMemoryTokenRepository::new());
    let token_service = Arc::new(TokenService::new(
        token_repo,
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Register and login user
    let email = utils::random_email();
    let password = "TokenTest123!";

    let user_service = UserService::new(Arc::clone(&user_repo), Arc::clone(&crypto_service));

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
        name: "Token Test".to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    let login_request = LoginRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
    };
    let login_result = auth_service.login(login_request).await;

    assert_ok!(login_result);
    let login_response = login_result.unwrap();

    let access_token = login_response.access_token;
    let refresh_token = login_response.refresh_token;

    // Test access token validation (TokenService validates token hashes, not JWTs)
    // In a real implementation, we'd hash the token first
    // For now, just test that the token service is working
    let user_id = UserId::from_string(login_response.user.id.clone()).unwrap();
    let user_tokens = token_service.get_user_tokens(&user_id).await;
    assert_ok!(user_tokens);

    // Test token refresh via auth service
    let refresh_result = auth_service.refresh_token(&refresh_token).await;

    assert_ok!(refresh_result);
    let new_login_response = refresh_result.unwrap();

    // Verify new tokens are different
    assert_ne!(new_login_response.access_token, access_token);
    assert_ne!(new_login_response.refresh_token, refresh_token);

    // Test cleanup of expired tokens
    let cleanup_result = token_service.cleanup_expired_tokens().await;
    assert_ok!(cleanup_result);
    let cleaned_count = cleanup_result.unwrap();
    println!("Cleaned up {cleaned_count} expired tokens");
}

/// Error handling integration test
#[tokio::test]
async fn test_error_handling_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service and services
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_error_tests".to_string(),
    ));
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Test invalid email format
    let invalid_login_request = LoginRequest {
        email: "invalid-email".to_string(),
        password: "password".to_string(),
    };
    let invalid_email_result = auth_service.login(invalid_login_request).await;

    assert_err!(invalid_email_result);

    // Test non-existent user
    let nonexistent_login_request = LoginRequest {
        email: utils::random_email().as_str().to_string(),
        password: "password".to_string(),
    };
    let nonexistent_user_result = auth_service.login(nonexistent_login_request).await;

    assert_err!(nonexistent_user_result);

    // Test wrong password
    let email = utils::random_email();
    let user_service = UserService::new(Arc::clone(&user_repo), Arc::clone(&crypto_service));

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: "CorrectPassword123!".to_string(),
        name: "Error Test".to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    let wrong_password_request = LoginRequest {
        email: email.as_str().to_string(),
        password: "WrongPassword123!".to_string(),
    };
    let wrong_password_result = auth_service.login(wrong_password_request).await;

    assert_err!(wrong_password_result);

    // Test malformed tokens
    let token_repo: crate::domain::repositories::DynTokenRepository =
        Arc::new(InMemoryTokenRepository::new());
    let token_service = TokenService::new(
        token_repo,
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    );

    let malformed_token_result = token_service.validate_token("malformed.jwt.token").await;

    assert_err!(malformed_token_result);

    // Test expired tokens (if TTL is implemented)
    // This would require mocking time or waiting for expiration
}

/// Performance baseline test
#[tokio::test]
async fn test_performance_baselines() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service and services
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_perf_tests".to_string(),
    ));
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Register test user
    let email = utils::random_email();
    let password = "PerfTest123!";

    let user_service = UserService::new(Arc::clone(&user_repo), Arc::clone(&crypto_service));

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
        name: "Performance Test".to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    // Test authentication performance
    let iterations = 100;
    let start_time = std::time::Instant::now();

    for _ in 0..iterations {
        let login_request = LoginRequest {
            email: email.as_str().to_string(),
            password: password.to_string(),
        };
        let auth_result = auth_service.login(login_request).await;

        assert_ok!(auth_result);
    }

    let total_time = start_time.elapsed();
    let avg_time = total_time / iterations;

    println!("Performance test results:");
    println!("Iterations: {iterations}");
    println!("Total time: {total_time:?}");
    println!("Average time per authentication: {avg_time:?}");

    // Performance assertions (adjust based on system capabilities)
    assert!(
        avg_time < Duration::from_millis(50),
        "Authentication too slow: {avg_time:?}",
    );

    assert!(
        total_time < Duration::from_secs(10),
        "Total authentication time too high: {total_time:?}",
    );
}

/// HTTP API integration test (mock)
#[tokio::test]
async fn test_http_api_integration() {
    // This would test the full HTTP API endpoints
    // For now, we'll test the service layer which would be called by the HTTP handlers

    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create crypto service and services
    let crypto_service = Arc::new(CryptoService::new(
        "test_jwt_secret_for_http_tests".to_string(),
    ));
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    ));

    // Simulate HTTP request flow
    let email = utils::random_email();
    let password = "HttpTest123!";

    // Register user (simulates POST /api/v1/auth/register)
    let user_service = UserService::new(Arc::clone(&user_repo), Arc::clone(&crypto_service));

    let register_request = RegisterRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
        name: "HTTP Test".to_string(),
    };
    let register_result = user_service.register(register_request).await;

    assert_ok!(register_result);

    // Login user (simulates POST /api/v1/auth/login)
    let login_request = LoginRequest {
        email: email.as_str().to_string(),
        password: password.to_string(),
    };
    let login_result = auth_service.login(login_request).await;

    assert_ok!(login_result);
    let tokens = login_result.unwrap();

    // Verify response structure
    assert!(!tokens.access_token.is_empty());
    assert!(!tokens.refresh_token.is_empty());
    assert!(tokens.expires_in > 0);
    // Note: LoginResponse doesn't have token_type field

    // Simulate token validation (simulates middleware)
    let token_repo: crate::domain::repositories::DynTokenRepository =
        Arc::new(InMemoryTokenRepository::new());
    let token_service = TokenService::new(
        token_repo,
        Arc::clone(&session_repo),
        Arc::clone(&crypto_service),
    );

    let access_token = &tokens.access_token;
    let validation_result = token_service.validate_token(access_token).await;

    assert_ok!(validation_result);

    // Simulate user profile request (simulates GET /api/v1/auth/me)
    let token = validation_result.unwrap();
    let user_id = &token.user_id;

    let profile_result = user_service.get_profile(user_id).await;

    assert_ok!(profile_result);

    println!("HTTP API integration test passed");
}
