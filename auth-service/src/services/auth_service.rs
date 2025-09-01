//! Authentication Service
//!
//! Core business logic for authentication operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

use crate::domain::entities::Session;
use crate::domain::repositories::{
    DynSessionRepository, DynUserRepository,
};
use crate::domain::Email;
use crate::shared::crypto::{CryptoService, CryptoServiceTrait};

/// Authentication service errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("User account is inactive")]
    UserInactive,
    #[error("User account not verified")]
    UserNotVerified,
    #[error("Repository error: {0}")]
    Repository(#[from] crate::domain::repositories::RepositoryError),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Session error: {0}")]
    Session(String),
}

/// Login request DTO
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login response DTO
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: UserInfo,
    pub session_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// User information DTO
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
    pub verified: bool,
    pub last_login: Option<DateTime<Utc>>,
}

/// Authentication service trait
#[async_trait]
pub trait AuthServiceTrait: Send + Sync {
    async fn login(
        &self,
        request: LoginRequest,
    ) -> Result<LoginResponse, crate::shared::error::AppError>;
    async fn logout(&self, session_id: &str) -> Result<(), crate::shared::error::AppError>;
    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<UserInfo, crate::shared::error::AppError>;
    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<LoginResponse, crate::shared::error::AppError>;
}

/// Authentication service implementation
pub struct AuthService {
    user_repo: DynUserRepository,
    session_repo: DynSessionRepository,
    crypto_service: Arc<CryptoService>,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(
        user_repo: DynUserRepository,
        session_repo: DynSessionRepository,
        crypto_service: Arc<CryptoService>,
    ) -> Self {
        Self {
            user_repo,
            session_repo,
            crypto_service,
        }
    }
}

#[async_trait]
impl AuthServiceTrait for AuthService {
    async fn login(
        &self,
        request: LoginRequest,
    ) -> Result<LoginResponse, crate::shared::error::AppError> {
        // 1. Validate input
        let email = Email::new(request.email)
            .map_err(|_| crate::shared::error::AppError::InvalidCredentials)?;

        // 2. Find user
        let user = self
            .user_repo
            .find_by_email(&email)
            .await?
            .ok_or(crate::shared::error::AppError::InvalidCredentials)?;

        // 3. Check if user is active and verified
        if !user.is_active {
            return Err(crate::shared::error::AppError::UserInactive);
        }

        if !user.email_verified {
            return Err(crate::shared::error::AppError::UserNotVerified);
        }

        // 4. Verify password
        let is_valid_password = self
            .crypto_service
            .verify_password(&request.password, &user.password_hash)
            .await
            .map_err(|_e| crate::shared::error::AppError::Crypto)?;

        if !is_valid_password {
            return Err(crate::shared::error::AppError::InvalidCredentials);
        }

        // 5. Update last login
        let now = Utc::now();
        self.user_repo.update_last_login(&user.id, now).await?;

        // 6. Create session
        let session = Session::new(user.id.clone(), now);
        self.session_repo.save(&session).await
            .map_err(|e| crate::shared::error::AppError::Internal(format!("Session error: {e}")))?;

        // 7. Generate tokens
        let access_token = self
            .crypto_service
            .generate_access_token(&user, &session)
            .await
            .map_err(|_e| crate::shared::error::AppError::Crypto)?;

        let refresh_token = self
            .crypto_service
            .generate_refresh_token(&user, &session)
            .await
            .map_err(|_e| crate::shared::error::AppError::Crypto)?;

        // 8. Return response
        Ok(LoginResponse {
            user: UserInfo {
                id: user.id.as_str().to_string(),
                email: user.email.as_str().to_string(),
                name: user.name.unwrap_or_default(),
                roles: user.roles.into_iter().collect(),
                verified: user.email_verified,
                last_login: user.last_login,
            },
            session_id: session.id,
            access_token,
            refresh_token,
            expires_in: 3600, // 1 hour
        })
    }

    async fn logout(&self, session_id: &str) -> Result<(), crate::shared::error::AppError> {
        self.session_repo
            .delete(session_id)
            .await
            .map_err(|_e| crate::shared::error::AppError::Session)?;
        Ok(())
    }

    async fn validate_session(
        &self,
        session_id: &str,
    ) -> Result<UserInfo, crate::shared::error::AppError> {
        let session = self
            .session_repo
            .find_by_id(session_id)
            .await
            .map_err(|_e| crate::shared::error::AppError::Session)?
            .ok_or(crate::shared::error::AppError::InvalidCredentials)?;

        // Check if session is expired
        if session.is_expired() {
            return Err(crate::shared::error::AppError::InvalidCredentials);
        }

        let user = self
            .user_repo
            .find_by_id(&session.user_id)
            .await?
            .ok_or(crate::shared::error::AppError::UserNotFound)?;

        Ok(UserInfo {
            id: user.id.as_str().to_string(),
            email: user.email.as_str().to_string(),
            name: user.name.unwrap_or_default(),
            roles: user.roles.into_iter().collect(),
            verified: user.email_verified,
            last_login: user.last_login,
        })
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<LoginResponse, crate::shared::error::AppError> {
        // Validate refresh token and get user/session info
        let (user, session) = self
            .crypto_service
            .validate_refresh_token(refresh_token)
            .await
            .map_err(|_e| crate::shared::error::AppError::Crypto)?;

        // Generate new tokens
        let access_token = self
            .crypto_service
            .generate_access_token(&user, &session)
            .await
            .map_err(|_e| crate::shared::error::AppError::Crypto)?;

        let new_refresh_token = self
            .crypto_service
            .generate_refresh_token(&user, &session)
            .await
            .map_err(|_e| crate::shared::error::AppError::Crypto)?;

        Ok(LoginResponse {
            user: UserInfo {
                id: user.id.as_str().to_string(),
                email: user.email.as_str().to_string(),
                name: user.name.unwrap_or_default(),
                roles: user.roles.into_iter().collect(),
                verified: user.email_verified,
                last_login: user.last_login,
            },
            session_id: session.id,
            access_token,
            refresh_token: new_refresh_token,
            expires_in: 3600,
        })
    }
}

#[cfg(test)]
mod tests {


    // Mock implementations would go here for comprehensive testing

    #[tokio::test]
    async fn test_auth_service_creation() {
        // This would test the service creation with mocks
        // Implementation depends on having mock repositories and crypto service
    }
}
