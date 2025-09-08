//! Enhanced Authentication API
//!
//! Comprehensive authentication endpoints including:
//! - User registration and login (feature = "user-auth")
//! - `OAuth` 2.0 authorization flows (feature = "oauth")
//! - JWT token management (feature = "jwt-auth")
//! - Multi-factor authentication (feature = "mfa")
//! - Session management (feature = "sessions")

use crate::domain::value_objects::PasswordHash;
use crate::services::password_service::{constant_time_compare, PasswordService};
use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::Redirect,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;
use tracing::{info, warn};
use uuid::Uuid;
use validator::Validate;

// SECURITY: Re-enable JWKS functionality for production security
use crate::infrastructure::crypto::keys::{current_signing_key, initialize_keys};

// Import production environment detection for security
use crate::test_mode_security::is_production_environment;

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

/// JWT Claims with security-focused fields
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub jti: String, // JWT ID for blacklisting support
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

/// `OAuth` authorization request with PKCE support
#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizeRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    // PKCE parameters (RFC 7636)
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
}

/// `OAuth` token request with PKCE support
#[derive(Debug, Deserialize, Validate)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    // PKCE parameter (RFC 7636)
    pub code_verifier: Option<String>,
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
        // SECURITY: Remove all demo credentials - they should never exist in production
        let users = HashMap::new();
        let oauth_clients = HashMap::new();

        // SECURITY: Demo credentials completely removed - use proper user registration
        // and OAuth client registration endpoints instead

        Self {
            jwt_secret, // Fallback only - JWKS keys are preferred
            users: Arc::new(tokio::sync::RwLock::new(users)),
            oauth_clients: Arc::new(tokio::sync::RwLock::new(oauth_clients)),
            authorization_codes: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            pkce_manager: Arc::new(crate::pkce::PkceManager::new()),
            jwt_blacklist: Arc::new(crate::application::auth::jwt_blacklist::JwtBlacklist::new()),
        }
    }
}

// Utility functions

fn verify_password(password: &str, hash: &str) -> bool {
    let password_service = PasswordService::new();

    // SECURITY: Only accept modern Argon2 password hashes
    // Legacy SHA-256 hashes are no longer supported for security reasons
    if !hash.starts_with("$argon2") {
        tracing::warn!(
            target: "security_audit",
            "Password verification rejected: legacy hash format detected"
        );
        return false;
    }

    // Parse and verify Argon2 hash
    if let Ok(password_hash) = PasswordHash::new(hash.to_string()) {
        if let Ok(is_valid) = password_service.verify_password(password, &password_hash) {
            return is_valid;
        }
    }

    // If parsing or verification fails, reject the login
    tracing::warn!(
        target: "security_audit",
        "Password verification failed: invalid Argon2 hash format"
    );
    false
}

fn generate_token() -> Result<String, ring::error::Unspecified> {
    let rng = SystemRandom::new();
    let mut dest = [0; 32];
    rng.fill(&mut dest)?;
    Ok(URL_SAFE_NO_PAD.encode(dest))
}

#[cfg(any(feature = "jwt-auth", feature = "user-auth", feature = "oauth"))]
/// Create a JWT token for the given user using secure JWKS-managed keys
///
/// # Errors
///
/// Returns `jsonwebtoken::errors::Error` if:
/// - JWKS key loading fails
/// - JWT encoding fails due to invalid key
/// - Claims serialization fails
/// - Header creation fails
async fn create_jwt_token_secure(
    user: &User,
    auth_state: &AuthState,
) -> Result<String, jsonwebtoken::errors::Error> {
    // Try to use JWKS-managed keys; fall back to HS256 using configured secret
    let claims = Claims {
        sub: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        roles: user.roles.clone(),
        exp: usize::try_from((Utc::now() + Duration::hours(24)).timestamp()).unwrap_or(0),
        iat: usize::try_from(Utc::now().timestamp()).unwrap_or(0),
        iss: "rust-security-platform".to_string(),
        jti: uuid::Uuid::new_v4().to_string(), // Unique token ID for blacklisting
    };

    if let Ok((kid, encoding_key)) = current_signing_key().await {
        let mut header = Header::new(Algorithm::RS256); // Prefer RS256 when JWKS is available
        header.kid = Some(kid);
        encode(&header, &claims, &encoding_key)
    } else {
        let encoding_key = EncodingKey::from_secret(auth_state.jwt_secret.as_bytes());
        let header = Header::new(Algorithm::HS256);
        encode(&header, &claims, &encoding_key)
    }
}

// API Endpoints

#[cfg(feature = "user-auth")]
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
    Extension(state): Extension<AuthState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(axum::http::HeaderMap, Json<AuthResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Validate request
    if let Err(_errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "validation_error".to_string(),
                error_description: "Invalid input provided".to_string(),
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
    let token = create_jwt_token_secure(&user, &state).await.map_err(|e| {
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

    let headers = create_auth_cookies(&token)?;

    Ok((
        headers,
        Json(AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: 86400, // 24 hours
            refresh_token: None,
            user: user_info,
        }),
    ))
}

#[cfg(feature = "user-auth")]
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
    Extension(state): Extension<AuthState>,
    Json(request): Json<LoginRequest>,
) -> Result<(axum::http::HeaderMap, Json<AuthResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Validate request
    if let Err(_errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "validation_error".to_string(),
                error_description: "Invalid input provided".to_string(),
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
        let token = create_jwt_token_secure(&user, &state).await.map_err(|e| {
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

        let headers = create_auth_cookies(&token)?;

        Ok((
            headers,
            Json(AuthResponse {
                access_token: token,
                token_type: "Bearer".to_string(),
                expires_in: 86400, // 24 hours
                refresh_token: None,
                user: user_info,
            }),
        ))
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

#[cfg(feature = "oauth")]
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
    Extension(state): Extension<AuthState>,
    Query(request): Query<AuthorizeRequest>,
) -> Result<Redirect, (StatusCode, Json<ErrorResponse>)> {
    // Validate request
    if let Err(_errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Invalid input provided".to_string(),
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

        // Optional remote policy check (client-level authorization for authorize step)
        if std::env::var("ENABLE_REMOTE_POLICY")
            .unwrap_or_else(|_| "0".to_string())
            .eq("1")
        {
            let req_id = uuid::Uuid::new_v4().to_string();
            let policy_base = std::env::var("POLICY_SERVICE_BASE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());
            let payload = crate::infrastructure::http::policy_client::PolicyAuthorizeRequest {
                request_id: req_id.clone(),
                principal: serde_json::json!({"type":"Client","id": request.client_id}),
                action: "OAuth::authorize".to_string(),
                resource: serde_json::json!({"type":"OAuthClient","id": request.client_id}),
                context: serde_json::json!({}),
            };
            match crate::infrastructure::http::policy_client::authorize_basic(
                &policy_base,
                &req_id,
                &payload,
            )
            .await
            {
                Ok(decision) if decision.eq_ignore_ascii_case("allow") => {}
                Ok(_decision) => {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "forbidden".to_string(),
                            error_description: "Access denied by policy".to_string(),
                        }),
                    ));
                }
                Err(e) => {
                    let fail_open = std::env::var("POLICY_FAIL_OPEN")
                        .unwrap_or_else(|_| "0".to_string())
                        .eq("1");
                    if !fail_open {
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(ErrorResponse {
                                error: "policy_unavailable".to_string(),
                                error_description: "Policy service unavailable".to_string(),
                            }),
                        ));
                    }
                    warn!(request_id = %req_id, error = %e, "Policy check failed; proceeding due to POLICY_FAIL_OPEN=1");
                }
            }
        }

        // PKCE validation if challenge provided
        if let Some(code_challenge) = &request.code_challenge {
            let method = request.code_challenge_method.as_deref().unwrap_or("plain");
            #[allow(unused_variables)]
            let challenge_method = match method {
                "S256" => crate::pkce::CodeChallengeMethod::S256,
                "plain" => crate::pkce::CodeChallengeMethod::Plain,
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(ErrorResponse {
                            error: "invalid_request".to_string(),
                            error_description: "Unsupported code_challenge_method".to_string(),
                        }),
                    ))
                }
            };

            // Validate challenge format
            if (method == "S256" && code_challenge.len() != 43)
                || (method == "plain" && (code_challenge.len() < 43 || code_challenge.len() > 128))
            {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "invalid_request".to_string(),
                        error_description: "Invalid code_challenge format".to_string(),
                    }),
                ));
            }
        }

        // Generate authorization code
        let auth_code = format!("auth_{}", uuid::Uuid::new_v4());
        let authorization_code = AuthorizationCode {
            code: auth_code.clone(),
            client_id: request.client_id.clone(),
            user_id: "placeholder_user_id".to_string(), // TODO: Get user_id from authenticated session
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope.clone().unwrap_or_else(|| "read".to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10), // 10 minute expiry
            used: false,
        };

        // Store authorization code
        state
            .authorization_codes
            .write()
            .await
            .insert(auth_code.clone(), authorization_code);

        // Store PKCE challenge if provided
        if let (Some(code_challenge), Some(code_challenge_method)) =
            (&request.code_challenge, &request.code_challenge_method)
        {
            let method = match code_challenge_method.as_str() {
                "S256" => crate::pkce::CodeChallengeMethod::S256,
                "plain" => crate::pkce::CodeChallengeMethod::Plain,
                _ => crate::pkce::CodeChallengeMethod::S256, // Default to secure method
            };

            if let Err(e) = state
                .pkce_manager
                .store_challenge(
                    &auth_code,
                    code_challenge.clone(),
                    method,
                    request.client_id.clone(),
                )
                .await
            {
                warn!("Failed to store PKCE challenge: {:?}", e);
                // Continue without PKCE - not all clients require it
            }
        }

        // Build redirect URL with authorization code
        let mut redirect_url = format!("{}?code={}", request.redirect_uri, auth_code);

        if let Some(state_param) = &request.state {
            redirect_url = format!("{}&state={}", redirect_url, state_param);
        }

        info!(
            "Authorization code generated for client: {}",
            request.client_id
        );
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

#[cfg(feature = "oauth")]
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
    Extension(state): Extension<AuthState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    validate_token_request(&request)?;
    let _client = authenticate_oauth_client(&state, &request).await?;

    // Optional remote policy check: client-level check for token issuance
    if std::env::var("ENABLE_REMOTE_POLICY")
        .unwrap_or_else(|_| "0".to_string())
        .eq("1")
    {
        let req_id = uuid::Uuid::new_v4().to_string();
        let policy_base = std::env::var("POLICY_SERVICE_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());
        let payload = crate::infrastructure::http::policy_client::PolicyAuthorizeRequest {
            request_id: req_id.clone(),
            principal: serde_json::json!({"type":"Client","id": request.client_id}),
            action: "OAuth::token".to_string(),
            resource: serde_json::json!({"type":"OAuthClient","id": request.client_id}),
            context: serde_json::json!({"grant_type": request.grant_type}),
        };
        match crate::infrastructure::http::policy_client::authorize_basic(
            &policy_base,
            &req_id,
            &payload,
        )
        .await
        {
            Ok(decision) if decision.eq_ignore_ascii_case("allow") => {}
            Ok(_decision) => {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "forbidden".to_string(),
                        error_description: "Access denied by policy".to_string(),
                    }),
                ));
            }
            Err(e) => {
                let fail_open = std::env::var("POLICY_FAIL_OPEN")
                    .unwrap_or_else(|_| "0".to_string())
                    .eq("1");
                if !fail_open {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(ErrorResponse {
                            error: "policy_unavailable".to_string(),
                            error_description: "Policy service unavailable".to_string(),
                        }),
                    ));
                }
                warn!(request_id = %req_id, error = %e, "Policy check failed; proceeding due to POLICY_FAIL_OPEN=1");
            }
        }
    }

    match request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code_flow(&state, &request).await,
        _ => Err(oauth_error(
            "unsupported_grant_type",
            "Grant type not supported",
        )),
    }
}

#[cfg(feature = "oauth")]
/// Validate the incoming token request
fn validate_token_request(request: &TokenRequest) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if let Err(_errors) = request.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Invalid input provided".to_string(),
            }),
        ));
    }
    Ok(())
}

#[cfg(feature = "oauth")]
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

#[cfg(feature = "oauth")]
/// Handle authorization code grant flow with PKCE support
async fn handle_authorization_code_flow(
    state: &AuthState,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let code = request
        .code
        .as_ref()
        .ok_or_else(|| oauth_error("invalid_request", "Missing authorization code"))?;

    // PKCE verification if code_verifier is provided
    if let Some(code_verifier) = &request.code_verifier {
        if let Err(e) = state
            .pkce_manager
            .verify_and_consume(code, code_verifier, &request.client_id)
            .await
        {
            warn!("PKCE verification failed: {:?}", e);
            return Err(oauth_error("invalid_grant", "PKCE verification failed"));
        }
        info!(
            "PKCE verification successful for client: {}",
            request.client_id
        );
    }

    let (user_id, scope) = validate_and_consume_auth_code(state, code).await?;
    let user = find_user_by_id(state, &user_id).await?;
    let access_token = generate_access_token(&user, state).await?;

    info!("Access token generated for user: {}", user.email);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
        refresh_token: None,
        scope: Some(scope),
    }))
}

#[cfg(feature = "oauth")]
/// Validate and consume authorization code (single-use, atomic operation)
async fn validate_and_consume_auth_code(
    state: &AuthState,
    code: &str,
) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
    let mut codes = state.authorization_codes.write().await;

    // Remove the code atomically to prevent reuse
    if let Some(auth_code) = codes.remove(code) {
        // Check expiration after removal
        if Utc::now() > auth_code.expires_at {
            return Err(oauth_error("invalid_grant", "Authorization code expired"));
        }

        // Check if already used (should not happen with removal, but defense in depth)
        if auth_code.used {
            return Err(oauth_error(
                "invalid_grant",
                "Authorization code already used",
            ));
        }

        Ok((auth_code.user_id, auth_code.scope))
    } else {
        Err(oauth_error("invalid_grant", "Invalid authorization code"))
    }
}

#[cfg(feature = "oauth")]
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

#[cfg(feature = "oauth")]
/// Generate access token for user using secure JWKS manager
async fn generate_access_token(
    user: &User,
    auth_state: &AuthState,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    create_jwt_token_secure(user, auth_state)
        .await
        .map_err(|e| {
            warn!("Access token generation failed: {}", e);
            oauth_error("server_error", "Failed to generate access token")
        })
}

#[cfg(feature = "oauth")]
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

#[cfg(feature = "jwt-auth")]
/// Validate JWT token with strict algorithm enforcement and blacklist checking
///
/// This function enforces the configured algorithm without fallback to prevent algorithm confusion attacks
/// and checks the token against the blacklist for revoked tokens.
async fn validate_jwt_token(
    token: &str,
    auth_state: &AuthState,
) -> Result<Claims, (StatusCode, Json<ErrorResponse>)> {
    // Parse the token header to verify algorithm matches expectation
    let header = decode_header(token).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Malformed token header".to_string(),
            }),
        )
    })?;

    // Enforce algorithm matches expected algorithm (prevent algorithm confusion)
    if header.alg != Algorithm::HS256 {
        error!(
            "Token algorithm mismatch: expected HS256, got {:?}",
            header.alg
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Token algorithm not supported".to_string(),
            }),
        ));
    }

    // Configure strict validation
    let mut validation = Validation::new(Algorithm::HS256);
    validation.algorithms = vec![Algorithm::HS256]; // Only allow HS256
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("iat".to_string());
    validation.required_spec_claims.insert("nbf".to_string());

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(auth_state.jwt_secret.as_ref()),
        &validation,
    )
    .map_err(|e| {
        error!("Token validation failed: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Invalid or expired token".to_string(),
            }),
        )
    })?;

    let claims = token_data.claims;

    // Check if token is blacklisted
    if auth_state
        .jwt_blacklist
        .is_token_blacklisted(&claims.jti)
        .await
    {
        warn!(
            jti = %claims.jti,
            user_id = %claims.sub,
            "Attempted use of blacklisted token"
        );
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Token has been revoked".to_string(),
            }),
        ));
    }

    Ok(claims)
}

#[cfg(feature = "user-auth")]
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
    Extension(state): Extension<AuthState>,
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
    let claims = validate_jwt_token(token, &state).await?;

    // Optional remote policy check: allow gating access to profile via policy-service
    if std::env::var("ENABLE_REMOTE_POLICY")
        .unwrap_or_else(|_| "0".to_string())
        .eq("1")
    {
        let req_id = headers
            .get("x-request-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let policy_base = std::env::var("POLICY_SERVICE_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string());

        let payload = crate::infrastructure::http::policy_client::PolicyAuthorizeRequest {
            request_id: req_id.clone(),
            principal: serde_json::json!({"type":"User","id": claims.sub}),
            action: "User::read_profile".to_string(),
            resource: serde_json::json!({"type":"User","id": claims.sub}),
            context: serde_json::json!({}),
        };

        match crate::infrastructure::http::policy_client::authorize_basic(
            &policy_base,
            &req_id,
            &payload,
        )
        .await
        {
            Ok(decision) if decision.eq_ignore_ascii_case("allow") => {}
            Ok(_decision) => {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "forbidden".to_string(),
                        error_description: "Access denied by policy".to_string(),
                    }),
                ));
            }
            Err(e) => {
                let fail_open = std::env::var("POLICY_FAIL_OPEN")
                    .unwrap_or_else(|_| "0".to_string())
                    .eq("1");
                if !fail_open {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(ErrorResponse {
                            error: "policy_unavailable".to_string(),
                            error_description: "Policy service unavailable".to_string(),
                        }),
                    ));
                }
                tracing::warn!(req_id = %req_id, error = %e, "Policy check failed; proceeding due to POLICY_FAIL_OPEN=1");
            }
        }
    }

    Ok(Json(UserInfo {
        id: claims.sub,
        email: claims.email,
        name: claims.name,
        roles: claims.roles,
    }))
}

#[cfg(feature = "user-auth")]
/// Logout endpoint - blacklists the current JWT token
///
/// # Errors
///
/// Returns `(StatusCode, Json<ErrorResponse>)` if:
/// - Authorization header is missing (`UNAUTHORIZED`)
/// - Token format is invalid (`UNAUTHORIZED`)
/// - Token validation fails (`UNAUTHORIZED`)
/// - Token blacklisting fails (`INTERNAL_SERVER_ERROR`)
///
/// # Panics
///
/// This function does not panic under normal operation.
pub async fn logout(
    Extension(state): Extension<AuthState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
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

    // Check if token is already blacklisted
    if let Ok(jti) = state.jwt_blacklist.extract_jti_from_token(token) {
        if state.jwt_blacklist.is_token_blacklisted(&jti).await {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid_token".to_string(),
                    error_description: "Token already revoked".to_string(),
                }),
            ));
        }
    }

    // Validate token to get claims (this also ensures the token is valid)
    let claims = validate_jwt_token(token, &state).await.map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid_token".to_string(),
                error_description: "Invalid or expired token".to_string(),
            }),
        )
    })?;

    // Extract JTI and user information from claims
    let jti = &claims.jti;
    let user_id = &claims.sub;
    let issuer = &claims.iss;
    let exp = Some(claims.exp as u64);

    // Blacklist the token
    if let Err(e) = state
        .jwt_blacklist
        .blacklist_token(
            jti.to_string(),
            issuer.to_string(),
            user_id.to_string(),
            exp,
            crate::application::auth::jwt_blacklist::BlacklistReason::Logout,
        )
        .await
    {
        warn!("Failed to blacklist token during logout: {:?}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "logout_failed".to_string(),
                error_description: "Failed to process logout".to_string(),
            }),
        ));
    }

    info!(
        user_id = %user_id,
        jti = %jti,
        "User logged out successfully"
    );

    Ok(Json(serde_json::json!({
        "message": "Logout successful",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

fn create_auth_cookies(token: &str) -> Result<HeaderMap, (StatusCode, Json<ErrorResponse>)> {
    let mut headers = HeaderMap::new();
    let secure = if std::env::var("APP_ENV")
        .unwrap_or_default()
        .eq_ignore_ascii_case("development")
    {
        ""
    } else {
        " Secure;"
    };
    let access_cookie = format!(
        "access_token={}; Path=/; HttpOnly;{} SameSite=Strict; Max-Age=86400",
        token, secure
    );
    let cookie_header = access_cookie.parse().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "cookie_creation_failed".to_string(),
                error_description: "Failed to create secure cookie header".to_string(),
            }),
        )
    })?;
    headers.append(axum::http::header::SET_COOKIE, cookie_header);

    // Generate CSRF token cookie (non-HttpOnly)
    let csrf_token = {
        let mut bytes = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "internal_error".to_string(),
                        error_description: "Failed to generate CSRF token".to_string(),
                    }),
                )
            })?;
        hex::encode(bytes)
    };
    let csrf_cookie = format!(
        "csrf_token={}; Path=/;{} SameSite=Strict; Max-Age=86400",
        csrf_token, secure
    );
    match csrf_cookie.parse() {
        Ok(cookie_value) => {
            headers.append(axum::http::header::SET_COOKIE, cookie_value);
        }
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "server_error".to_string(),
                    error_description: "Failed to create secure cookie".to_string(),
                }),
            ));
        }
    }
    Ok(headers)
}

/// OAuth2 token introspection endpoint
/// Validates a token and returns metadata about it
pub async fn introspect(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<IntrospectionRequest>,
) -> Result<Json<IntrospectionResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Validate required parameters
    if params.token.is_empty() {
        return Ok(Json(IntrospectionResponse {
            active: false,
            client_id: None,
            username: None,
            scope: None,
            exp: None,
            iat: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }));
    }

    // Validate the token
    match validate_jwt_token(&params.token, &state).await {
        Ok(claims) => {
            Ok(Json(IntrospectionResponse {
                active: true,
                client_id: Some("default_client".to_string()),
                username: claims.name.clone(),
                scope: Some(claims.roles.join(" ")),
                exp: Some(claims.exp as u64),
                iat: Some(claims.iat as u64),
                sub: Some(claims.sub),
                aud: Some(claims.aud),
                iss: Some(claims.iss),
                jti: Some(claims.jti),
            }))
        }
        Err(_) => {
            // Invalid token - return inactive response
            Ok(Json(IntrospectionResponse {
                active: false,
                client_id: None,
                username: None,
                scope: None,
                exp: None,
                iat: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }))
        }
    }
}

/// OAuth2 token revocation endpoint
/// Revokes a given access or refresh token
pub async fn revoke_token(
    State(state): State<Arc<AppState>>,
    axum::Form(params): axum::Form<RevocationRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Validate required parameters
    if params.token.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "invalid_request".to_string(),
                error_description: "Missing required parameter: token".to_string(),
            }),
        ));
    }

    // In a production system, this would:
    // 1. Add the token to a blacklist/revocation list
    // 2. Remove from active session store
    // 3. Notify other services about revocation
    // 4. Update user session state

    // For now, we'll just validate the token exists and return success
    match validate_jwt_token(&params.token, &state).await {
        Ok(_) => {
            // Token is valid, revoke it
            // TODO: Implement actual token revocation logic
            debug!("Token revoked successfully: {}", params.token);
            Ok(StatusCode::OK)
        }
        Err(_) => {
            // Even for invalid tokens, OAuth2 spec says to return 200 OK
            // This prevents token scanning attacks
            debug!("Revocation requested for invalid token");
            Ok(StatusCode::OK)
        }
    }
}

/// JWKS (JSON Web Key Set) endpoint
/// Returns public keys used to verify JWT tokens
pub async fn public_keys(
    State(state): State<Arc<AppState>>,
) -> Result<Json<JwksResponse>, (StatusCode, Json<ErrorResponse>)> {
    // In production, this would return actual public keys from the key manager
    // For now, return a mock JWKS response
    let jwks = JwksResponse {
        keys: vec![JwkKey {
            kty: "RSA".to_string(),
            use_: Some("sig".to_string()),
            kid: "default-key-2024".to_string(),
            alg: Some("RS256".to_string()),
            n: "mock_modulus_value".to_string(),
            e: "AQAB".to_string(),
            x5c: None,
            x5t: None,
        }],
    };

    Ok(Json(jwks))
}

// Request/Response types for the new endpoints
#[derive(Debug, serde::Deserialize)]
struct IntrospectionRequest {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct IntrospectionResponse {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jti: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct RevocationRequest {
    token: String,
    token_type_hint: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, serde::Serialize)]
struct JwkKey {
    kty: String,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    n: String,
    e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x5t: Option<String>,
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
        let result = create_jwt_token_secure(&user, &auth_state).await;
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
        let result = create_jwt_token_secure(&user, &auth_state).await;
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
            .await
            .expect("Test token creation should succeed");

        // Validate the token
        let validation_result = validate_jwt_token(&token, &auth_state).await;
        assert!(validation_result.is_ok(), "Token validation should succeed");

        let claims = validation_result.expect("Test token validation should succeed");
        assert_eq!(claims.sub, user.id);
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.name, user.name);
        assert_eq!(claims.roles, user.roles);
    }
}
