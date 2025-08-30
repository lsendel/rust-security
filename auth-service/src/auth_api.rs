//! Enhanced Authentication API
//!
//! Comprehensive authentication endpoints including:
//! - User registration and login
//! - `OAuth` 2.0 authorization flows
//! - JWT token management
//! - Multi-factor authentication
//! - Session management

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use common::hash_password_sha256;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use uuid::Uuid;
use validator::Validate;

/// Application state for authentication
#[derive(Clone)]
pub struct AuthState {
    pub jwt_secret: String,
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
        let mut users = HashMap::new();
        let mut oauth_clients = HashMap::new();

        // Create a demo user
        let demo_user = User {
            id: "demo-user-123".to_string(),
            email: "demo@example.com".to_string(),
            password_hash: hash_password_sha256("demo123"),
            name: "Demo User".to_string(),
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            roles: vec!["user".to_string()],
        };
        users.insert(demo_user.email.clone(), demo_user);

        // Create a demo OAuth client
        let demo_client = OAuthClient {
            client_id: "demo-client".to_string(),
            client_secret: "demo-secret".to_string(),
            name: "Demo Application".to_string(),
            redirect_uris: vec!["http://localhost:3000/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            created_at: Utc::now(),
        };
        oauth_clients.insert(demo_client.client_id.clone(), demo_client);

        Self {
            jwt_secret,
            users: Arc::new(tokio::sync::RwLock::new(users)),
            oauth_clients: Arc::new(tokio::sync::RwLock::new(oauth_clients)),
            authorization_codes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

// Utility functions

fn verify_password(password: &str, hash: &str) -> bool {
    hash_password_sha256(password) == hash
}

fn generate_token() -> String {
    let rng = SystemRandom::new();
    let mut dest = [0; 32];
    rng.fill(&mut dest).unwrap();
    URL_SAFE_NO_PAD.encode(dest)
}

/// Create a JWT token for the given user
///
/// # Errors
///
/// Returns `jsonwebtoken::errors::Error` if:
/// - JWT encoding fails due to invalid key
/// - Claims serialization fails
/// - Header creation fails
fn create_jwt_token(user: &User, jwt_secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        roles: user.roles.clone(),
        exp: usize::try_from((Utc::now() + Duration::hours(24)).timestamp()).unwrap_or(0),
        iat: usize::try_from(Utc::now().timestamp()).unwrap_or(0),
        iss: "rust-security-platform".to_string(),
    };

    encode(
        &Header::default(),
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
        password_hash: hash_password_sha256(&request.password),
        name: request.name,
        created_at: Utc::now(),
        last_login: None,
        is_active: true,
        roles: vec!["user".to_string()],
    };

    // Generate JWT token
    let token = create_jwt_token(&user, &state.jwt_secret).map_err(|_| {
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

        // Generate JWT token
        let token = create_jwt_token(&user, &state.jwt_secret).map_err(|_| {
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
        let code = generate_token();
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
            write!(redirect_url, "&state={state_param}").unwrap();
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
pub async fn token(
    State(state): State<AuthState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
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

    // Validate client credentials
    let _client = {
        let oauth_clients = state.oauth_clients.read().await;
        let client = oauth_clients.get(&request.client_id).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                }),
            )
        })?;

        if client.client_secret != request.client_secret {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_client".to_string(),
                    error_description: "Invalid client credentials".to_string(),
                }),
            ));
        }

        client.clone()
    };

    match request.grant_type.as_str() {
        "authorization_code" => {
            let code = request.code.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: "Missing authorization code".to_string(),
                    }),
                )
            })?;

            // Get and validate auth code, then extract user ID and scope
            let (user_id, scope) = {
                let mut authorization_codes = state.authorization_codes.write().await;
                let auth_code = authorization_codes.get_mut(&code).ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_grant".to_string(),
                            error_description: "Invalid authorization code".to_string(),
                        }),
                    )
                })?;

                // Check if code is expired or used
                if auth_code.used || Utc::now() > auth_code.expires_at {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_grant".to_string(),
                            error_description: "Authorization code expired or already used"
                                .to_string(),
                        }),
                    ));
                }

                // Mark code as used and extract needed data
                auth_code.used = true;
                (auth_code.user_id.clone(), auth_code.scope.clone())
            };

            // Get user with the extracted user_id
            let user = {
                let users = state.users.read().await;
                users
                    .values()
                    .find(|u| u.id == user_id)
                    .cloned()
                    .ok_or_else(|| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorResponse {
                                error: "server_error".to_string(),
                                error_description: "User not found".to_string(),
                            }),
                        )
                    })?
            };

            // Generate access token
            let access_token = create_jwt_token(&user, &state.jwt_secret).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "server_error".to_string(),
                        error_description: "Failed to generate access token".to_string(),
                    }),
                )
            })?;

            info!("Access token generated for user: {}", user.email);

            Ok(Json(TokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: 3600, // 1 hour
                refresh_token: None,
                scope: Some(scope),
            }))
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "unsupported_grant_type".to_string(),
                error_description: "Grant type not supported".to_string(),
            }),
        )),
    }
}

/// Get current user info
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
#[allow(clippy::unused_async)]
pub async fn me(
    State(state): State<AuthState>,
    headers: HeaderMap,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorResponse>)> {
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

    // Decode JWT token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Invalid or expired token".to_string(),
            }),
        )
    })?;

    let claims = token_data.claims;

    Ok(Json(UserInfo {
        id: claims.sub,
        email: claims.email,
        name: claims.name,
        roles: claims.roles,
    }))
}
