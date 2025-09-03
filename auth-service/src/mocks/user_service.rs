//! Mock implementation of `UserServiceTrait` for testing

use async_trait::async_trait;

use crate::domain::value_objects::UserId;
use crate::services::user_service::{
    RegisterRequest, UpdateProfileRequest, UserError, UserResponse, UserServiceTrait,
};

/// Mock user service for testing
pub struct MockUserService;

impl MockUserService {
    /// Create a new mock user service
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockUserService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserServiceTrait for MockUserService {
    async fn register(&self, _request: RegisterRequest) -> Result<UserResponse, UserError> {
        // Return a mock user response
        Ok(UserResponse {
            id: "test-user-id".to_string(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            verified: true,
            created_at: chrono::Utc::now(),
        })
    }

    async fn get_profile(&self, _user_id: &UserId) -> Result<UserResponse, UserError> {
        // Return mock user profile
        Ok(UserResponse {
            id: "test-user-id".to_string(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            verified: true,
            created_at: chrono::Utc::now(),
        })
    }

    async fn update_profile(
        &self,
        _user_id: &UserId,
        _request: UpdateProfileRequest,
    ) -> Result<UserResponse, UserError> {
        // Return updated mock user profile
        Ok(UserResponse {
            id: "test-user-id".to_string(),
            email: "test@example.com".to_string(),
            name: Some("Test User Updated".to_string()),
            verified: true,
            created_at: chrono::Utc::now(),
        })
    }

    async fn delete_user(&self, _user_id: &UserId) -> Result<(), UserError> {
        Ok(())
    }
}
