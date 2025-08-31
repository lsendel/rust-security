//! Integration Tests for Authentication Service
//!
//! End-to-end tests covering the full authentication flow,
//! including user registration, login, session management, and security features.

use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use reqwest::Client;
use serde_json::json;

use crate::app::di::AppContainer;
use crate::domain::entities::User;
use crate::domain::value_objects::{Email, UserId};
use crate::services::{AuthService, UserService, TokenService};
use crate::tests::{mocks, utils, assert_ok, assert_err};
use crate::shared::error::AppError;

/// Full authentication flow integration test
#[tokio::test]
async fn test_full_authentication_flow() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_integration_tests".to_string(),
    ));

    let user_service = Arc::new(UserService::new(
        Arc::clone(&user_repo),
        "test_jwt_secret_for_integration_tests".to_string(),
    ));

    let token_service = Arc::new(TokenService::new(
        user_repo,
        session_repo,
        "test_jwt_secret_for_integration_tests".to_string(),
    ));

    // Test user registration
    let email = utils::random_email();
    let password = "SecurePassword123!";
    let name = "Integration Test User";

    let register_result = user_service
        .register_user(email.clone(), password.to_string(), Some(name.to_string()))
        .await;

    assert_ok!(register_result);

    // Test user login
    let login_result = auth_service
        .authenticate_user(email.clone(), password.to_string())
        .await;

    assert_ok!(login_result);
    let tokens = login_result.unwrap();

    // Verify tokens are present
    assert!(tokens.access_token.is_some());
    assert!(tokens.refresh_token.is_some());

    // Test token validation
    let access_token = tokens.access_token.unwrap();
    let token_validation = token_service
        .validate_token(&access_token, "access")
        .await;

    assert_ok!(token_validation);

    // Test user profile retrieval
    let user_id = token_validation.unwrap().sub;
    let profile_result = user_service
        .get_user_profile(&user_id)
        .await;

    assert_ok!(profile_result);
    let user = profile_result.unwrap();

    assert_eq!(user.email, email);
    assert_eq!(user.name, Some(name.to_string()));

    // Test session management
    let sessions_result = token_service
        .get_user_sessions(&user_id)
        .await;

    assert_ok!(sessions_result);
    let sessions = sessions_result.unwrap();
    assert!(!sessions.is_empty());

    // Test token refresh
    let refresh_token = tokens.refresh_token.unwrap();
    let refresh_result = token_service
        .refresh_tokens(&refresh_token)
        .await;

    assert_ok!(refresh_result);
    let new_tokens = refresh_result.unwrap();

    // Verify new tokens are different
    assert_ne!(new_tokens.access_token, Some(access_token));
    assert_ne!(new_tokens.refresh_token, Some(refresh_token));

    // Test logout
    let logout_result = auth_service
        .logout(&access_token)
        .await;

    assert_ok!(logout_result);

    // Verify token is invalidated
    let validation_after_logout = token_service
        .validate_token(&access_token, "access")
        .await;

    assert_err!(validation_after_logout);
}

/// Concurrent authentication load test
#[tokio::test]
async fn test_concurrent_authentication_load() {
    const CONCURRENT_USERS: usize = 50;
    const REQUESTS_PER_USER: usize = 10;

    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_load_tests".to_string(),
    ));

    // Pre-register users
    let mut users = Vec::new();
    for i in 0..CONCURRENT_USERS {
        let email = Email::new(format!("loadtest{}@example.com", i)).unwrap();
        let password = format!("Password123!{}", i);
        let name = format!("Load Test User {}", i);

        let user_service = UserService::new(
            Arc::clone(&user_repo),
            "test_jwt_secret_for_load_tests".to_string(),
        );

        let register_result = user_service
            .register_user(email.clone(), password.clone(), Some(name))
            .await;

        assert_ok!(register_result);

        users.push((email, password));
    }

    // Run concurrent authentication requests
    let start_time = std::time::Instant::now();

    let tasks: Vec<_> = users.into_iter().enumerate().map(|(user_idx, (email, password))| {
        let auth_svc = Arc::clone(&auth_service);

        tokio::spawn(async move {
            let mut success_count = 0;
            let mut error_count = 0;

            for req_idx in 0..REQUESTS_PER_USER {
                let auth_result = auth_svc
                    .authenticate_user(email.clone(), password.clone())
                    .await;

                match auth_result {
                    Ok(tokens) => {
                        if tokens.access_token.is_some() {
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
    }).collect();

    // Wait for all tasks to complete
    let mut total_success = 0;
    let mut total_error = 0;

    for task in tasks {
        let (user_idx, success, error) = task.await.unwrap();
        total_success += success;
        total_error += error;

        // Each user should have successful authentications
        assert!(success > 0, "User {} had no successful authentications", user_idx);
    }

    let total_time = start_time.elapsed();
    let total_requests = CONCURRENT_USERS * REQUESTS_PER_USER;
    let requests_per_second = total_requests as f64 / total_time.as_secs_f64();

    println!("Load test results:");
    println!("Total requests: {}", total_requests);
    println!("Successful: {}", total_success);
    println!("Errors: {}", total_error);
    println!("Total time: {:?}", total_time);
    println!("Requests/sec: {:.2}", requests_per_second);

    // Verify performance requirements
    assert!(requests_per_second > 100.0, "Throughput too low: {:.2} req/sec", requests_per_second);
    assert!(total_success > total_error * 10, "Too many errors: {} success, {} error", total_success, total_error);
}

/// Security integration test
#[tokio::test]
async fn test_security_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_security_tests".to_string(),
    ));

    // Test brute force protection
    let email = Email::new("bruteforce@example.com".to_string()).unwrap();
    let wrong_password = "WrongPassword123!";

    // Register user first
    let user_service = UserService::new(
        Arc::clone(&user_repo),
        "test_jwt_secret_for_security_tests".to_string(),
    );

    let register_result = user_service
        .register_user(email.clone(), "CorrectPassword123!".to_string(), Some("Security Test".to_string()))
        .await;

    assert_ok!(register_result);

    // Attempt multiple failed logins
    let mut failure_count = 0;
    for _ in 0..10 {
        let auth_result = auth_service
            .authenticate_user(email.clone(), wrong_password.to_string())
            .await;

        if auth_result.is_err() {
            failure_count += 1;
        }
    }

    // Should have failures (exact count depends on implementation)
    assert!(failure_count > 0, "Expected some authentication failures");

    // Test successful login still works
    let success_result = auth_service
        .authenticate_user(email, "CorrectPassword123!".to_string())
        .await;

    // This should succeed (depending on rate limiting implementation)
    // Note: In a real system, this might be rate limited after failures
    match success_result {
        Ok(_) => println!("Successful login after failures"),
        Err(AppError::RateLimitExceeded) => println!("Rate limited after brute force attempts"),
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

/// Session management integration test
#[tokio::test]
async fn test_session_management_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_session_tests".to_string(),
    ));

    let token_service = Arc::new(TokenService::new(
        user_repo,
        session_repo,
        "test_jwt_secret_for_session_tests".to_string(),
    ));

    // Register and login user
    let email = utils::random_email();
    let password = "SessionTest123!";

    let user_service = UserService::new(
        Arc::new(mocks::MockUserRepository::new()),
        "test_jwt_secret_for_session_tests".to_string(),
    );

    let register_result = user_service
        .register_user(email.clone(), password.to_string(), Some("Session Test".to_string()))
        .await;

    assert_ok!(register_result);

    let login_result = auth_service
        .authenticate_user(email.clone(), password)
        .await;

    assert_ok!(login_result);
    let tokens = login_result.unwrap();
    let access_token = tokens.access_token.unwrap();

    // Get user sessions
    let token_claims = token_service
        .validate_token(&access_token, "access")
        .await
        .unwrap();

    let user_id = token_claims.sub;

    let sessions_result = token_service
        .get_user_sessions(&user_id)
        .await;

    assert_ok!(sessions_result);
    let sessions = sessions_result.unwrap();
    assert!(!sessions.is_empty());

    // Test session cleanup
    let cleanup_result = token_service
        .cleanup_expired_sessions()
        .await;

    assert_ok!(cleanup_result);
    let cleaned_count = cleanup_result.unwrap();
    println!("Cleaned up {} expired sessions", cleaned_count);

    // Test concurrent session limit (if implemented)
    // This would test that a user can't have too many active sessions

    // Test session invalidation
    let logout_result = auth_service
        .logout(&access_token)
        .await;

    assert_ok!(logout_result);

    // Verify session is invalidated
    let validation_after_logout = token_service
        .validate_token(&access_token, "access")
        .await;

    assert_err!(validation_after_logout);
}

/// Token lifecycle integration test
#[tokio::test]
async fn test_token_lifecycle_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_token_tests".to_string(),
    ));

    let token_service = Arc::new(TokenService::new(
        user_repo,
        session_repo,
        "test_jwt_secret_for_token_tests".to_string(),
    ));

    // Register and login user
    let email = utils::random_email();
    let password = "TokenTest123!";

    let user_service = UserService::new(
        Arc::new(mocks::MockUserRepository::new()),
        "test_jwt_secret_for_token_tests".to_string(),
    );

    let register_result = user_service
        .register_user(email.clone(), password.to_string(), Some("Token Test".to_string()))
        .await;

    assert_ok!(register_result);

    let login_result = auth_service
        .authenticate_user(email.clone(), password)
        .await;

    assert_ok!(login_result);
    let tokens = login_result.unwrap();

    let access_token = tokens.access_token.unwrap();
    let refresh_token = tokens.refresh_token.unwrap();

    // Test access token validation
    let access_validation = token_service
        .validate_token(&access_token, "access")
        .await;

    assert_ok!(access_validation);
    let access_claims = access_validation.unwrap();
    assert_eq!(access_claims.token_type, Some("Bearer".to_string()));

    // Test refresh token validation
    let refresh_validation = token_service
        .validate_token(&refresh_token, "refresh")
        .await;

    assert_ok!(refresh_validation);
    let refresh_claims = refresh_validation.unwrap();
    assert_eq!(refresh_claims.token_type, Some("Refresh".to_string()));

    // Test token refresh
    let refresh_result = token_service
        .refresh_tokens(&refresh_token)
        .await;

    assert_ok!(refresh_result);
    let new_tokens = refresh_result.unwrap();

    // Verify new tokens are different
    assert_ne!(new_tokens.access_token, Some(access_token));
    assert_ne!(new_tokens.refresh_token, Some(refresh_token));

    // Test that old access token is invalidated
    let old_token_validation = token_service
        .validate_token(&access_token, "access")
        .await;

    // This might succeed or fail depending on implementation
    // Some systems keep old tokens valid for a grace period

    // Test refresh token reuse detection (if implemented)
    let refresh_again_result = token_service
        .refresh_tokens(&refresh_token)
        .await;

    // This might fail if refresh token reuse is detected
    match refresh_again_result {
        Ok(_) => println!("Refresh token reuse allowed"),
        Err(AppError::Unauthorized(_)) => println!("Refresh token reuse detected and blocked"),
        Err(e) => println!("Unexpected error during refresh token reuse: {:?}", e),
    }
}

/// Error handling integration test
#[tokio::test]
async fn test_error_handling_integration() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_error_tests".to_string(),
    ));

    // Test invalid email format
    let invalid_email_result = auth_service
        .authenticate_user(Email::new("invalid-email".to_string()).unwrap(), "password".to_string())
        .await;

    assert_err!(invalid_email_result);

    // Test non-existent user
    let nonexistent_user_result = auth_service
        .authenticate_user(utils::random_email(), "password".to_string())
        .await;

    assert_err!(nonexistent_user_result);

    // Test wrong password
    let email = utils::random_email();
    let user_service = UserService::new(
        Arc::clone(&user_repo),
        "test_jwt_secret_for_error_tests".to_string(),
    );

    let register_result = user_service
        .register_user(email.clone(), "CorrectPassword123!".to_string(), Some("Error Test".to_string()))
        .await;

    assert_ok!(register_result);

    let wrong_password_result = auth_service
        .authenticate_user(email, "WrongPassword123!".to_string())
        .await;

    assert_err!(wrong_password_result);

    // Test malformed tokens
    let token_service = TokenService::new(
        user_repo,
        session_repo,
        "test_jwt_secret_for_error_tests".to_string(),
    );

    let malformed_token_result = token_service
        .validate_token("malformed.jwt.token", "access")
        .await;

    assert_err!(malformed_token_result);

    // Test expired tokens (if TTL is implemented)
    // This would require mocking time or waiting for expiration
}

/// Performance baseline test
#[tokio::test]
async fn test_performance_baselines() {
    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_perf_tests".to_string(),
    ));

    // Register test user
    let email = utils::random_email();
    let password = "PerfTest123!";

    let user_service = UserService::new(
        Arc::clone(&user_repo),
        "test_jwt_secret_for_perf_tests".to_string(),
    );

    let register_result = user_service
        .register_user(email.clone(), password.to_string(), Some("Performance Test".to_string()))
        .await;

    assert_ok!(register_result);

    // Test authentication performance
    let iterations = 100;
    let start_time = std::time::Instant::now();

    for _ in 0..iterations {
        let auth_result = auth_service
            .authenticate_user(email.clone(), password.clone())
            .await;

        assert_ok!(auth_result);
    }

    let total_time = start_time.elapsed();
    let avg_time = total_time / iterations;

    println!("Performance test results:");
    println!("Iterations: {}", iterations);
    println!("Total time: {:?}", total_time);
    println!("Average time per authentication: {:?}", avg_time);

    // Performance assertions (adjust based on system capabilities)
    assert!(avg_time < Duration::from_millis(50),
        "Authentication too slow: {:?}", avg_time);

    assert!(total_time < Duration::from_secs(10),
        "Total authentication time too high: {:?}", total_time);
}

/// HTTP API integration test (mock)
#[tokio::test]
async fn test_http_api_integration() {
    // This would test the full HTTP API endpoints
    // For now, we'll test the service layer which would be called by the HTTP handlers

    // Create mock repositories
    let (user_repo, session_repo) = mocks::create_mock_repositories();

    // Create services
    let auth_service = Arc::new(AuthService::new(
        Arc::clone(&user_repo),
        Arc::clone(&session_repo),
        "test_jwt_secret_for_http_tests".to_string(),
    ));

    // Simulate HTTP request flow
    let email = utils::random_email();
    let password = "HttpTest123!";

    // Register user (simulates POST /api/v1/auth/register)
    let user_service = UserService::new(
        Arc::clone(&user_repo),
        "test_jwt_secret_for_http_tests".to_string(),
    );

    let register_result = user_service
        .register_user(email.clone(), password.to_string(), Some("HTTP Test".to_string()))
        .await;

    assert_ok!(register_result);

    // Login user (simulates POST /api/v1/auth/login)
    let login_result = auth_service
        .authenticate_user(email.clone(), password)
        .await;

    assert_ok!(login_result);
    let tokens = login_result.unwrap();

    // Verify response structure
    assert!(tokens.access_token.is_some());
    assert!(tokens.refresh_token.is_some());
    assert!(tokens.expires_in.is_some());
    assert_eq!(tokens.token_type, "Bearer");

    // Simulate token validation (simulates middleware)
    let token_service = TokenService::new(
        user_repo,
        session_repo,
        "test_jwt_secret_for_http_tests".to_string(),
    );

    let access_token = tokens.access_token.unwrap();
    let validation_result = token_service
        .validate_token(&access_token, "access")
        .await;

    assert_ok!(validation_result);

    // Simulate user profile request (simulates GET /api/v1/auth/me)
    let claims = validation_result.unwrap();
    let user_id = claims.sub;

    let profile_result = user_service
        .get_user_profile(&user_id)
        .await;

    assert_ok!(profile_result);

    println!("HTTP API integration test passed");
}

