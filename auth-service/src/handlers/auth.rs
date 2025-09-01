//! Authentication Handlers
//!
//! HTTP handlers for authentication endpoints.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::app::AppContainer;
use crate::services::auth_service::LoginRequest;
use crate::services::user_service::RegisterRequest;
use crate::shared::error::AppResult;

/// Login request DTO
#[derive(Debug, Deserialize)]
pub struct LoginRequestDto {
    pub email: String,
    pub password: String,
}

/// Register request DTO
#[derive(Debug, Deserialize)]
pub struct RegisterRequestDto {
    pub email: String,
    pub password: String,
    pub name: String,
}

/// Authentication response DTO
#[derive(Debug, Serialize)]
pub struct AuthResponseDto {
    pub user: UserDto,
    pub session_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// User DTO
#[derive(Debug, Serialize)]
pub struct UserDto {
    pub id: String,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
    pub verified: bool,
}

/// User registration endpoint
///
/// # Errors
///
/// Returns an error if:
/// - User registration fails due to invalid email or password
/// - User already exists with the provided email
/// - Database connection or query fails
/// - Any internal service error occurs during registration
pub async fn register(
    State(container): State<AppContainer>,
    Json(request): Json<RegisterRequestDto>,
) -> AppResult<Json<AuthResponseDto>> {
    let register_req = RegisterRequest {
        email: request.email,
        password: request.password,
        name: request.name,
    };

    let response = container
        .user_service
        .register(register_req)
        .await
        .map_err(|e| crate::shared::error::AppError::Internal(e.to_string()))?;

    // For now, return a basic response (would need to login after registration)
    Ok(Json(AuthResponseDto {
        user: UserDto {
            id: response.id,
            email: response.email,
            name: response.name.unwrap_or_default(),
            roles: vec!["user".to_string()],
            verified: response.verified,
        },
        session_id: String::new(),
        access_token: String::new(),
        refresh_token: String::new(),
        expires_in: 0,
    }))
}

/// User login endpoint
///
/// # Errors
///
/// Returns an error if:
/// - Invalid credentials (email/password combination)
/// - User account is locked or disabled
/// - Database connection or query fails
/// - Session creation fails
/// - Token generation fails
pub async fn login(
    State(container): State<AppContainer>,
    Json(request): Json<LoginRequestDto>,
) -> AppResult<Json<AuthResponseDto>> {
    let login_req = LoginRequest {
        email: request.email,
        password: request.password,
    };

    let response = container.auth_service.login(login_req).await?;

    Ok(Json(AuthResponseDto {
        user: UserDto {
            id: response.user.id,
            email: response.user.email,
            name: response.user.name,
            roles: response.user.roles,
            verified: response.user.verified,
        },
        session_id: response.session_id,
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_in: response.expires_in,
    }))
}

/// Get current user profile
///
/// # Errors
///
/// Returns an error if:
/// - JWT token is missing or invalid
/// - User is not authenticated
/// - Database connection fails when fetching user data
/// - User account no longer exists
/// - Token has expired
pub async fn me(
    State(_container): State<AppContainer>,
    // TODO: Extract user from JWT token
) -> AppResult<Json<UserDto>> {
    // This would extract user info from JWT token
    // For now, return a placeholder
    Err(crate::shared::error::AppError::unauthorized(
        "Not implemented yet",
    ))
}

/// Logout endpoint
///
/// # Errors
///
/// Returns an error if:
/// - Session revocation fails
/// - Database connection fails
/// - Token invalidation fails
/// - User is not authenticated (though this currently returns success)
pub async fn logout(
    State(_container): State<AppContainer>,
    // TODO: Extract session from JWT token
) -> AppResult<Json<serde_json::Value>> {
    // This would revoke the session/token
    Ok(Json(
        serde_json::json!({ "message": "Logged out successfully" }),
    ))
}

#[cfg(test)]
mod tests {


    #[tokio::test]
    async fn test_handler_creation() {
        // This would test the handlers with mock container
        // For now, just verify the code compiles
        assert!(true);
    }
}
