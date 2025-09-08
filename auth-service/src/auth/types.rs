//! Authentication types and models
//!
//! Common types used across authentication modules

use crate::domain::value_objects::PasswordHash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

/// Application state for authentication
#[derive(Clone)]
pub struct AuthState {
    pub jwt_secret: String, // Fallback for legacy compatibility only
    pub users: Arc<tokio::sync::RwLock<HashMap<String, User>>>,
    pub oauth_clients: Arc<tokio::sync::RwLock<HashMap<String, OAuthClient>>>,
    pub authorization_codes: Arc<tokio::sync::RwLock<HashMap<String, AuthorizationCode>>>,
    pub pkce_manager: Arc<crate::pkce::PkceManager>,
    pub jwt_blacklist: Arc<crate::application::auth::jwt_blacklist::JwtBlacklist>,
}

impl AuthState {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            users: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            oauth_clients: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            authorization_codes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            pkce_manager: Arc::new(crate::pkce::PkceManager::new()),
            jwt_blacklist: Arc::new(crate::application::auth::jwt_blacklist::JwtBlacklist::new()),
        }
    }
}

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: PasswordHash,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub email_verified: bool,
    pub roles: Vec<String>,
}

/// Session model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// OAuth client model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub response_types: Vec<String>,
    pub grant_types: Vec<String>,
    pub scope: Vec<String>,
}

/// Authorization code for OAuth flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub expires_at: DateTime<Utc>,
    pub scope: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    pub scope: Option<String>,
    pub token_type: Option<String>,
    pub nonce: Option<String>,
    pub client_id: Option<String>,
}

// Request/Response types
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(
        length(min = 8, message = "Password must be at least 8 characters"),
        custom(function = "validate_password_strength", message = "Password too weak")
    )]
    pub password: String,
    pub confirm_password: String,
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    pub remember_me: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub message: String,
    pub user_id: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
    pub error_uri: Option<String>,
}

/// Password validation function
fn validate_password_strength(password: &str) -> Result<(), validator::ValidationError> {
    // Check for minimum complexity requirements
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if !(has_upper && has_lower && has_digit && has_special) {
        return Err(validator::ValidationError::new("weak_password"));
    }

    Ok(())
}
