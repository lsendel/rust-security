//! User Service
//!
//! Business logic for user management operations.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::domain::entities::User;
use crate::domain::repositories::UserRepository;
use crate::domain::value_objects::{Email, PasswordHash, UserId};
use crate::shared::crypto::{CryptoService, CryptoServiceTrait};

/// User service errors
#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("User not found")]
    NotFound,
    #[error("User already exists")]
    AlreadyExists,
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Invalid password")]
    InvalidPassword,
    #[error("Repository error: {0}")]
    Repository(#[from] crate::domain::repositories::RepositoryError),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

/// User registration request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: String,
}

/// User profile update request
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// User service response
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: String,
    pub verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// User service trait
#[async_trait]
pub trait UserServiceTrait: Send + Sync {
    async fn register(&self, request: RegisterRequest) -> Result<UserResponse, UserError>;
    async fn get_profile(&self, user_id: &UserId) -> Result<UserResponse, UserError>;
    async fn update_profile(
        &self,
        user_id: &UserId,
        request: UpdateProfileRequest,
    ) -> Result<UserResponse, UserError>;
    async fn delete_user(&self, user_id: &UserId) -> Result<(), UserError>;
}

/// User service implementation
pub struct UserService<R: UserRepository> {
    user_repo: Arc<R>,
    crypto_service: Arc<CryptoService>,
}

impl<R: UserRepository> UserService<R> {
    /// Create a new user service
    pub fn new(user_repo: Arc<R>, crypto_service: Arc<CryptoService>) -> Self {
        Self {
            user_repo,
            crypto_service,
        }
    }
}

#[async_trait]
impl<R: UserRepository> UserServiceTrait for UserService<R> {
    async fn register(&self, request: RegisterRequest) -> Result<UserResponse, UserError> {
        // Validate email
        let email = Email::new(request.email).map_err(|_| UserError::InvalidEmail)?;

        // Check if user already exists
        if self.user_repo.exists_by_email(&email).await? {
            return Err(UserError::AlreadyExists);
        }

        // Hash password
        let password_hash = self
            .crypto_service
            .hash_password(&request.password)
            .await
            .map_err(|e| UserError::Crypto(e.to_string()))?;

        // Create user
        let user = User::new(email, password_hash, request.name);

        // Save user
        self.user_repo.save(&user).await?;

        Ok(UserResponse {
            id: user.id.into_string(),
            email: user.email.into_string(),
            name: user.name,
            verified: user.is_verified,
            created_at: user.created_at,
        })
    }

    async fn get_profile(&self, user_id: &UserId) -> Result<UserResponse, UserError> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::NotFound)?;

        Ok(UserResponse {
            id: user.id.into_string(),
            email: user.email.into_string(),
            name: user.name,
            verified: user.is_verified,
            created_at: user.created_at,
        })
    }

    async fn update_profile(
        &self,
        user_id: &UserId,
        request: UpdateProfileRequest,
    ) -> Result<UserResponse, UserError> {
        // Get current user
        let mut user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::NotFound)?;

        // Update fields
        if let Some(name) = request.name {
            user.name = name;
        }

        if let Some(email_str) = request.email {
            let email = Email::new(email_str).map_err(|_| UserError::InvalidEmail)?;

            // Check if email is already taken by another user
            if let Some(existing) = self.user_repo.find_by_email(&email).await? {
                if existing.id != user.id {
                    return Err(UserError::AlreadyExists);
                }
            }

            user.email = email;
        }

        // Save updated user
        self.user_repo.save(&user).await?;

        Ok(UserResponse {
            id: user.id.into_string(),
            email: user.email.into_string(),
            name: user.name,
            verified: user.is_verified,
            created_at: user.created_at,
        })
    }

    async fn delete_user(&self, user_id: &UserId) -> Result<(), UserError> {
        self.user_repo.delete(user_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::repositories::user_repository::MockUserRepository;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_user_registration() {
        let user_repo = Arc::new(MockUserRepository::new());
        let crypto = Arc::new(crate::shared::crypto::CryptoService::new(
            "test".to_string(),
        ));
        let service = UserService::new(user_repo, crypto);

        let request = RegisterRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            name: "Test User".to_string(),
        };

        let result = service.register(request).await;
        assert!(result.is_ok());
    }
}
