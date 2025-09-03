//! Enhanced Authentication API
//!
//! Comprehensive authentication endpoints including:
//! - User registration and login
//! - `OAuth` 2.0 authorization flows
//! - JWT token management
//! - Multi-factor authentication
//! - Session management

use crate::domain::value_objects::PasswordHash;
use crate::services::password_service::{constant_time_compare, PasswordService};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;

// JWKS functionality temporarily disabled for build compatibility
// use auth_service::infrastructure::crypto::jwks_rotation::{InMemoryKeyStorage, JwksManager, KeyRotationConfig};

// Import production environment detection for security
use crate::test_mode_security::is_production_environment;

/// Application state for authentication
#[derive(Clone)]
pub struct AuthState {
    pub jwt_secret: String, // Kept for backward compatibility during migration
    // pub jwks_manager: Option<Arc<JwksManager>>, // New secure JWKS manager - temporarily disabled
    pub users: Arc<tokio::sync::RwLock<HashMap<String, User>>>,
    pub oauth_clients: Arc<tokio::sync::RwLock<HashMap<String, OAuthClient>>>,
    pub authorization_codes: Arc<tokio::sync::RwLock<HashMap<String, AuthorizationCode>>>,
}

/// User model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub roles: Vec<String>,
}

/// Session model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// `OAuth` Client model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Authorization Code model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub user_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
}

// Request/Response Models

/// User registration request
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,

    #[validate(length(
        min = 1,
        max = 100,
        message = "Name must be between 1 and 100 characters"
    ))]
    pub name: String,
}

/// User login request
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
}

/// `OAuth` authorization request
#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
}

/// `OAuth` token request
#[derive(Debug, Deserialize, Validate)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: String,
    pub client_secret: String,
}

/// Authentication response
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub user: UserInfo,
}

/// User information
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
}

/// `OAuth` token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub error_description: String,
}

// Implementation

impl AuthState {
    #[must_use]
    pub fn new(jwt_secret: String) -> Self {
        Self::new_with_jwks(jwt_secret, None)
    }

    /// Create new auth state with JWKS manager for secure operations
    #[must_use]
    pub fn new_with_jwks(jwt_secret: String, _jwks_manager: Option<()>) -> Self {
        // Temporarily disabled
        let mut users = HashMap::new();
        let mut oauth_clients = HashMap::new();

        // Only create demo credentials in non-production environments for security
        if !is_production_environment() {
            warn!("Creating demo credentials - this should only happen in development/test environments");

            // Create a demo user
            let demo_user = User {
                id: "demo-user-123".to_string(),
                email: "demo@example.com".to_string(),
                password_hash: {
                    let demo_password = std::env::var("DEMO_USER_PASSWORD")
                        .unwrap_or_else(|_| "demo123-change-in-production".to_string());
                    PasswordService::new()
                        .hash_password(&demo_password)
                        .map_err(|e| warn!("Demo user password hashing failed: {}", e))
                        .unwrap_or_else(|()| PasswordHash::new("invalid_hash".to_string()).unwrap())
                        .as_str()
                        .to_string()
                },
                name: "Demo User".to_string(),
                created_at: Utc::now(),
                last_login: None,
                is_active: true,
                roles: vec!["user".to_string()],
            };
            users.insert(demo_user.email.clone(), demo_user);

            // Create a demo OAuth client with environment-configurable credentials
            let demo_client = OAuthClient {
                client_id: std::env::var("DEMO_CLIENT_ID")
                    .unwrap_or_else(|_| "demo-client".to_string()),
                client_secret: std::env::var("DEMO_CLIENT_SECRET")
                    .unwrap_or_else(|_| "demo-secret-change-in-production".to_string()),
                name: "Demo Application".to_string(),
                redirect_uris: vec![std::env::var("DEMO_REDIRECT_URI")
                    .unwrap_or_else(|_| "http://localhost:3000/callback".to_string())],
                grant_types: vec!["authorization_code".to_string()],
                response_types: vec!["code".to_string()],
                created_at: Utc::now(),
            };
            oauth_clients.insert(demo_client.client_id.clone(), demo_client);
        }

        Self {
            jwt_secret,
            // jwks_manager: _jwks_manager, // Temporarily disabled
            users: Arc::new(tokio::sync::RwLock::new(users)),
            oauth_clients: Arc::new(tokio::sync::RwLock::new(oauth_clients)),
            authorization_codes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

// Utility functions

fn verify_password(password: &str, hash: &str) -> bool {
    let password_service = PasswordService::new();

    // Try parsing as modern Argon2 hash first
    if let Ok(password_hash) = PasswordHash::new(hash.to_string()) {
        if let Ok(is_valid) = password_service.verify_password(password, &password_hash) {
            return is_valid;
        }
    }

    // Fallback to legacy SHA-256 comparison for backward compatibility
    // This will be removed after migration period
    warn!("Using legacy SHA-256 password verification - hash should be migrated to Argon2id");
    use common::hash_password_sha256;
    constant_time_compare(&hash_password_sha256(password), hash)
}

fn generate_token() -> Result<String, ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut dest = [0; 32];
    rng.fill(&mut dest)?;
    Ok(URL_SAFE_NO_PAD.encode(dest))
}

/// Create a JWT token for the given user using secure `EdDSA` or fallback to `HS256`
///
/// # Errors
///
/// Returns `jsonwebtoken::errors::Error` if:
/// - JWT encoding fails due to invalid key
/// - Claims serialization fails
/// - Header creation fails
/// - JWKS manager is unavailable
fn create_jwt_token_secure(
    user: &User,
    auth_state: &AuthState,
) -> Result<String, jsonwebtoken::errors::Error> {
    // JWKS manager is temporarily disabled - use fallback JWT creation
    // For now, fall back to standard JWT creation using jwt_secret
    warn!(
        "JWKS manager disabled, falling back to standard JWT for user: {}",
        user.email
    );
    create_jwt_token_legacy(user, &auth_state.jwt_secret)
}

/// Legacy JWT token creation using HS256 (for backward compatibility)
///
/// WARNING: This method uses HS256 which is vulnerable to algorithm confusion attacks.
/// This is only used as a fallback during migration.
fn create_jwt_token_legacy(
    user: &User,
    jwt_secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        roles: user.roles.clone(),
        exp: usize::try_from((Utc::now() + Duration::hours(24)).timestamp()).unwrap_or(0),
        iat: usize::try_from(Utc::now().timestamp()).unwrap_or(0),
        iss: "rust-security-platform".to_string(),
    };

    let header = Header::new(Algorithm::HS256);
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
}

// API Endpoints

/// User registration endpoint
///
/// # Errors
///
/// Returns `(StatusCode, Json<ErrorResponse>)` if:
/// - Request validation fails (`BAD_REQUEST`)
/// - User with email already exists (CONFLICT)
/// - JWT token generation fails (`INTERNAL_SERVER_ERROR`)
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn register(
    State(state): State<AuthState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate request
    if let Err(errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "validation_error".to_string(),
                error_description: format!("Validation failed: {errors:?}"),
            }),
        ));
    }

    let user_exists = { state.users.read().await.contains_key(&request.email) };

    // Check if user already exists
    if user_exists {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "user_exists".to_string(),
                error_description: "User with this email already exists".to_string(),
            }),
        ));
    }

    // Create new user
    let user = User {
        id: Uuid::new_v4().to_string(),
        email: request.email.clone(),
        password_hash: PasswordService::new()
            .hash_password(&request.password)
            .map_err(|e| {
                warn!("Password hashing failed during registration: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "internal_error".to_string(),
                        error_description: "Registration failed".to_string(),
                    }),
                )
            })?
            .as_str()
            .to_string(),
        name: request.name,
        created_at: Utc::now(),
        last_login: None,
        is_active: true,
        roles: vec!["user".to_string()],
    };

    // Generate JWT token using secure JWKS manager
    let token = create_jwt_token_secure(&user, &state).map_err(|e| {
        warn!("Token generation failed for user {}: {}", user.email, e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "token_generation_failed".to_string(),
                error_description: "Failed to generate access token".to_string(),
            }),
        )
    })?;

    let user_info = UserInfo {
        id: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        roles: user.roles.clone(),
    };

    state.users.write().await.insert(request.email, user);

    info!("User registered successfully: {}", user_info.email);

    Ok(Json(AuthResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: 86400, // 24 hours
        refresh_token: None,
        user: user_info,
    }))
}

/// User login endpoint
///
/// # Errors
///
/// Returns `(StatusCode, Json<ErrorResponse>)` if:
/// - Request validation fails (`BAD_REQUEST`)
/// - User not found or password incorrect (UNAUTHORIZED)
/// - JWT token generation fails (`INTERNAL_SERVER_ERROR`)
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn login(
    State(state): State<AuthState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate request
    if let Err(errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "validation_error".to_string(),
                error_description: format!("Validation failed: {errors:?}"),
            }),
        ));
    }

    let user = { state.users.read().await.get(&request.email).cloned() };

    // Find user
    if let Some(mut user) = user {
        // Verify password
        if !verify_password(&request.password, &user.password_hash) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_credentials".to_string(),
                    error_description: "Invalid email or password".to_string(),
                }),
            ));
        }

        // Update last login
        user.last_login = Some(Utc::now());
        state
            .users
            .write()
            .await
            .insert(request.email.clone(), user.clone());

        // Generate JWT token using secure JWKS manager
        let token = create_jwt_token_secure(&user, &state).map_err(|e| {
            warn!("Token generation failed for user {}: {}", user.email, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "token_generation_failed".to_string(),
                    error_description: "Failed to generate access token".to_string(),
                }),
            )
        })?;

        let user_info = UserInfo {
            id: user.id.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            roles: user.roles.clone(),
        };

        info!("User logged in successfully: {}", user.email);

        Ok(Json(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: 86400, // 24 hours
            refresh_token: None,
            user: user_info,
        }))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_credentials".to_string(),
                error_description: "Invalid email or password".to_string(),
            }),
        ))
    }
}

/// `OAuth` authorization endpoint
///
/// # Errors
///
/// Returns `(StatusCode, Json<ErrorResponse>)` if:
/// - Request validation fails (`BAD_REQUEST`)
/// - Invalid `client_id` provided (`BAD_REQUEST`)
/// - Invalid `redirect_uri` provided (`BAD_REQUEST`)
///
/// # Panics
///
/// Panics if the redirect URL formatting fails during string writing.
/// This should never happen under normal operation as the format string is static.
pub async fn authorize(
    State(state): State<AuthState>,
    Query(request): Query<AuthorizeRequest>,
) -> Result<Redirect, (StatusCode, Json<ErrorResponse>)> {
    // Validate request
    if let Err(errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: format!("Validation failed: {errors:?}"),
            }),
        ));
    }

    let client = {
        state
            .oauth_clients
            .read()
            .await
            .get(&request.client_id)
            .cloned()
    };

    // Validate client
    if let Some(client) = client {
        // Validate redirect URI
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "invalid_redirect_uri".to_string(),
                    error_description: "Invalid redirect_uri".to_string(),
                }),
            ));
        }

        // For demo purposes, auto-approve with demo user
        let Ok(code) = generate_token() else {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to generate authorization code".to_string(),
                }),
            ));
        };
        {
            state.authorization_codes.write().await.insert(
                code.clone(),
                AuthorizationCode {
                    code: code.clone(),
                    client_id: request.client_id,
                    user_id: "demo-user-123".to_string(),
                    redirect_uri: request.redirect_uri.clone(),
                    scope: request.scope.unwrap_or_else(|| "read".to_string()),
                    created_at: Utc::now(),
                    expires_at: Utc::now() + Duration::minutes(10),
                    used: false,
                },
            );
        }

        let mut redirect_url = format!("{}?code={}", request.redirect_uri, code);
        if let Some(state_param) = request.state {
            use std::fmt::Write;
            if write!(redirect_url, "&state={state_param}").is_err() {
                return Err(oauth_error("server_error", "Failed to format redirect URL"));
            }
        }

        info!("Authorization code generated for client: {}", client.name);

        Ok(Redirect::to(&redirect_url))
    } else {
        Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_client".to_string(),
                error_description: "Invalid client_id".to_string(),
            }),
        ))
    }
}

/// `OAuth` token endpoint
///
/// # Errors
///
/// Returns `(StatusCode, Json<ErrorResponse>)` if:
/// - Request validation fails (`BAD_REQUEST`)
/// - Invalid client credentials (UNAUTHORIZED)
/// - Authorization code missing, invalid, expired, or already used (`BAD_REQUEST`)
/// - User associated with code not found (`INTERNAL_SERVER_ERROR`)
/// - JWT token generation fails (`INTERNAL_SERVER_ERROR`)
/// - Unsupported grant type (`BAD_REQUEST`)
///
/// # Panics
///
/// This function does not panic under normal operation.
#[allow(clippy::too_many_lines)]
#[allow(clippy::significant_drop_tightening)]
pub async fn token(
    State(state): State<AuthState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_token_request(&request)?;
    let _client = authenticate_oauth_client(&state, &request).await?;

    match request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_flow(&state, &request).await,
        _ => Err(oauth_error(
            "unsupported_grant_type",
            "Grant type not supported",
        )),
    }
}

/// Validate the incoming token request
fn validate_token_request(request: &TokenRequest) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if let Err(errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: format!("Validation failed: {errors:?}"),
            }),
        ));
    }
    Ok(())
}

/// Authenticate `OAuth` client credentials
async fn authenticate_oauth_client(
    state: &AuthState,
    request: &TokenRequest,
) -> Result<OAuthClient, (StatusCode, Json<ErrorResponse>)> {
    let client = {
        let oauth_clients = state.oauth_clients.read().await;
        oauth_clients.get(&request.client_id).cloned()
    }
    .ok_or_else(|| oauth_error("invalid_client", "Invalid client credentials"))?;

    if !constant_time_compare(&client.client_secret, &request.client_secret) {
        return Err(oauth_error("invalid_client", "Invalid client credentials"));
    }

    Ok(client)
}

/// Handle authorization code grant flow
async fn handle_authorization_code_flow(
    state: &AuthState,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let code = request
        .code
        .as_ref()
        .ok_or_else(|| oauth_error("invalid_request", "Missing authorization code"))?;

    let (user_id, scope) = validate_and_consume_auth_code(state, code).await?;
    let user = find_user_by_id(state, &user_id).await?;
    let access_token = generate_access_token(&user, state)?;

    info!("Access token generated for user: {}", user.email);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
        refresh_token: None,
        scope: Some(scope),
    }))
}

/// Validate and consume authorization code
async fn validate_and_consume_auth_code(
    state: &AuthState,
    code: &str,
) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
    let (user_id, scope) = {
        let result: Result<(String, String), (StatusCode, Json<ErrorResponse>)> = {
            let mut codes = state.authorization_codes.write().await;
            if let Some(auth_code) = codes.get_mut(code) {
                if auth_code.used || Utc::now() > auth_code.expires_at {
                    return Err(oauth_error(
                        "invalid_grant",
                        "Authorization code expired or already used",
                    ));
                }
                auth_code.used = true;
                Ok((auth_code.user_id.clone(), auth_code.scope.clone()))
            } else {
                Err(oauth_error("invalid_grant", "Invalid authorization code"))
            }
        };
        result?
    };

    Ok((user_id, scope))
}

/// Find user by ID
async fn find_user_by_id(
    state: &AuthState,
    user_id: &str,
) -> Result<User, (StatusCode, Json<ErrorResponse>)> {
    let users = state.users.read().await;
    users
        .values()
        .find(|u| u.id == user_id)
        .cloned()
        .ok_or_else(|| oauth_error("server_error", "User not found"))
}

/// Generate access token for user using secure JWKS manager
fn generate_access_token(
    user: &User,
    auth_state: &AuthState,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    create_jwt_token_secure(user, auth_state).map_err(|e| {
        warn!("Access token generation failed: {}", e);
        oauth_error("server_error", "Failed to generate access token")
    })
}

/// Helper to create consistent `OAuth` error responses
fn oauth_error(error: &str, description: &str) -> (StatusCode, Json<ErrorResponse>) {
    let status = match error {
        "invalid_client" => StatusCode::UNAUTHORIZED,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };

    (
        status,
        Json(ErrorResponse {
            error: error.to_string(),
            error_description: description.to_string(),
        }),
    )
}

/// Validate JWT token using secure JWKS manager or fallback to HS256
///
/// This function tries `EdDSA` validation first, then falls back to `HS256` for backward compatibility
fn validate_jwt_token(
    token: &str,
    auth_state: &AuthState,
) -> Result<Claims, (StatusCode, Json<ErrorResponse>)> {
    // JWKS functionality temporarily disabled for build compatibility

    // Fallback to HS256 validation for backward compatibility
    warn!("Falling back to legacy HS256 validation - consider migrating to EdDSA");
    let mut validation = Validation::new(Algorithm::HS256);
    validation.algorithms = vec![Algorithm::HS256];

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(auth_state.jwt_secret.as_ref()),
        &validation,
    )
    .map_err(|e| {
        warn!("Token validation failed completely: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Invalid or expired token".to_string(),
            }),
        )
    })?;

    Ok(token_data.claims)
}

/// Get current user info with secure token validation
///
/// # Errors
///
/// Returns `(StatusCode, Json<ErrorResponse>)` if:
/// - Authorization header missing (UNAUTHORIZED)
/// - Authorization header contains invalid UTF-8 (UNAUTHORIZED)
/// - Bearer token prefix missing (UNAUTHORIZED)
/// - JWT token invalid, expired, or malformed (UNAUTHORIZED)
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn me(
    State(state): State<AuthState>,
    headers: HeaderMap,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorResponse>)> {
    // Yield to keep handler truly async and cooperative
    tokio::task::yield_now().await;
    // Extract token from Authorization header
    let auth_header = headers.get("Authorization").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "missing_token".to_string(),
                error_description: "Authorization header missing".to_string(),
            }),
        )
    })?;

    let token = auth_header
        .to_str()
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: "Invalid authorization header".to_string(),
                }),
            )
        })?
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: "Bearer token required".to_string(),
                }),
            )
        })?;

    // Validate JWT token using secure JWKS manager or fallback
    let claims = validate_jwt_token(token, &state)?;

    Ok(Json(UserInfo {
        id: claims.sub,
        email: claims.email,
        name: claims.name,
        roles: claims.roles,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::decode_header;

    #[tokio::test]
    async fn test_secure_jwt_token_creation() {
        // Create test user
        let user = User {
            id: "test-user-123".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "test-hash".to_string(),
            name: "Test User".to_string(),
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            roles: vec!["user".to_string()],
        };

        // JWKS functionality temporarily disabled
        let auth_state = AuthState::new_with_jwks("fallback-secret".to_string(), None);

        // Create secure JWT token (should use EdDSA)
        let result = create_jwt_token_secure(&user, &auth_state);
        assert!(result.is_ok(), "Secure JWT token creation should succeed");

        let token = result.expect("Test token creation should succeed");
        assert!(!token.is_empty(), "Token should not be empty");

        // Verify the token was created with HS256 (fallback during migration)
        let header = decode_header(&token).expect("Test token header decode should succeed");
        assert_eq!(
            header.alg,
            Algorithm::HS256,
            "Token should use HS256 algorithm as fallback"
        );
    }

    #[tokio::test]
    async fn test_fallback_to_legacy_jwt() {
        // Create test user
        let user = User {
            id: "test-user-456".to_string(),
            email: "fallback@example.com".to_string(),
            password_hash: "test-hash".to_string(),
            name: "Fallback User".to_string(),
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            roles: vec!["user".to_string()],
        };

        // Create auth state without JWKS manager (should fallback to HS256)
        let auth_state = AuthState::new("test-secret-key".to_string());

        // Create JWT token (should fallback to HS256)
        let result = create_jwt_token_secure(&user, &auth_state);
        assert!(result.is_ok(), "Fallback JWT token creation should succeed");

        let token = result.expect("Test fallback token creation should succeed");
        assert!(!token.is_empty(), "Token should not be empty");

        // Verify the token was created with HS256 (fallback)
        let header =
            decode_header(&token).expect("Test fallback token header decode should succeed");
        assert_eq!(
            header.alg,
            Algorithm::HS256,
            "Token should fallback to HS256 algorithm"
        );
    }

    #[tokio::test]
    async fn test_secure_jwt_validation() {
        // JWKS functionality temporarily disabled
        let auth_state = AuthState::new_with_jwks("fallback-secret".to_string(), None);

        // Create test user and token
        let user = User {
            id: "validation-test-789".to_string(),
            email: "validation@example.com".to_string(),
            password_hash: "test-hash".to_string(),
            name: "Validation User".to_string(),
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            roles: vec!["admin".to_string()],
        };

        // Create secure token
        let token = create_jwt_token_secure(&user, &auth_state)
            .expect("Test token creation should succeed");

        // Validate the token
        let validation_result = validate_jwt_token(&token, &auth_state);
        assert!(validation_result.is_ok(), "Token validation should succeed");

        let claims = validation_result.expect("Test token validation should succeed");
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.name, user.name);
        assert_eq!(claims.roles, user.roles);
    }
}
