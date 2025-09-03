//! Mock implementation of `AuthServiceTrait` for testing

use async_trait::async_trait;

use crate::services::auth_service::{AuthServiceTrait, LoginRequest, LoginResponse, UserInfo};
use crate::shared::error::AppError;

/// Mock auth service for testing
pub struct MockAuthService;

impl MockAuthService {
    /// Create a new mock auth service
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockAuthService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthServiceTrait for MockAuthService {
    async fn login(&self, _request: LoginRequest) -> Result<LoginResponse, AppError> {
        // Return a mock login response
        Ok(LoginResponse {
            user: UserInfo {
                id: "test-user-id".to_string(),
                email: "test@example.com".to_string(),
                name: "Test User".to_string(),
                roles: vec!["user".to_string()],
                verified: true,
                last_login: None,
            },
            session_id: "test-session-id".to_string(),
            access_token: "mock_access_token".to_string(),
            refresh_token: "mock_refresh_token".to_string(),
            expires_in: 3600,
        })
    }

    async fn logout(&self, _session_id: &str) -> Result<(), AppError> {
        // Mock logout - always succeed
        Ok(())
    }

    async fn refresh_token(&self, _refresh_token: &str) -> Result<LoginResponse, AppError> {
        // Return a mock login response for refresh
        Ok(LoginResponse {
            user: UserInfo {
                id: "test-user-id".to_string(),
                email: "test@example.com".to_string(),
                name: "Test User".to_string(),
                roles: vec!["user".to_string()],
                verified: true,
                last_login: None,
            },
            session_id: "refreshed-session-id".to_string(),
            access_token: "refreshed_access_token".to_string(),
            refresh_token: "refreshed_refresh_token".to_string(),
            expires_in: 3600,
        })
    }

    async fn validate_session(&self, _session_id: &str) -> Result<UserInfo, AppError> {
        // Return mock user info for valid sessions
        Ok(UserInfo {
            id: "test-user-id".to_string(),
            email: "test@example.com".to_string(),
            name: "Test User".to_string(),
            roles: vec!["user".to_string()],
            verified: true,
            last_login: None,
        })
    }
}
