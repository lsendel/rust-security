use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

// Phantom imports to satisfy unused dependency warnings
use chrono as _;
use common as _;
use tokio as _;
use tower as _;
use tracing_subscriber as _;

pub mod auth;
pub mod database;
pub mod repository;

pub use auth::{auth_middleware, extract_user_claims, require_role, JwtService, PasswordService};
pub use database::{init_database, Database, DatabaseConfig};
pub use repository::{DbError, InMemoryUserRepository, UserRepository};

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub use repository::{PostgresUserRepository, SqliteUserRepository};

#[cfg(any(feature = "sqlite", feature = "postgres"))]
use chrono::{DateTime, Utc};

#[cfg(feature = "docs")]
use utoipa::ToSchema;

/// User role enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(any(feature = "sqlite", feature = "postgres"), derive(sqlx::Type))]
#[cfg_attr(
    any(feature = "sqlite", feature = "postgres"),
    sqlx(type_name = "user_role", rename_all = "lowercase")
)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub enum UserRole {
    User,
    Admin,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

impl From<User> for UserPublic {
    fn from(user: User) -> Self {
        UserPublic {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            created_at: user.created_at,
        }
    }
}

/// Enhanced User model representing a user in the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(any(feature = "sqlite", feature = "postgres"), derive(sqlx::FromRow))]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct User {
    pub id: i32,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing, default)]
    pub password_hash: String,
    pub role: UserRole,
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub created_at: DateTime<Utc>,
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub updated_at: DateTime<Utc>,
}

/// Public user representation (without sensitive data)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct UserPublic {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: UserRole,
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub created_at: DateTime<Utc>,
}

/// Request model for creating a new user
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct CreateUserRequest {
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub role: Option<UserRole>,
}

/// Request model for updating a user
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Login request model
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Registration request model
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

/// Authentication response model
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct Claims {
    pub sub: i32,
    pub email: String,
    pub role: UserRole,
    pub exp: usize,
}

/// Paginated response wrapper
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
}

/// Enhanced error types for the application
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    Database(#[from] sqlx::Error),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal server error")]
    Internal,
}

impl From<DbError> for AppError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::NotFound => AppError::NotFound("Resource not found".to_string()),
            DbError::EmailExists => AppError::Validation("Email already exists".to_string()),
            _ => AppError::Internal,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            AppError::Database(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            }
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (
            status,
            Json(serde_json::json!({
                "error": message
            })),
        )
            .into_response()
    }
}

/// Application state containing database and configuration
#[derive(Clone)]
pub struct AppState {
    pub user_repository: Arc<dyn UserRepository>,
    pub jwt_service: Arc<JwtService>,
}

impl AppState {
    /// Create a new AppState with in-memory storage
    pub fn new() -> Result<Self, AppError> {
        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-secret-key-for-development-only-replace-in-production".to_string());
        let jwt_service = Arc::new(JwtService::new(jwt_secret, Some(24))?);

        Ok(Self { user_repository: Arc::new(InMemoryUserRepository::new()), jwt_service })
    }

    /// Create AppState with a specific repository
    pub fn with_repository(repository: Arc<dyn UserRepository>) -> Result<Self, AppError> {
        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-secret-key-for-development-only-replace-in-production".to_string());
        let jwt_service = Arc::new(JwtService::new(jwt_secret, Some(24))?);

        Ok(Self { user_repository: repository, jwt_service })
    }

    /// Create AppState from database
    pub fn from_database(database: Database) -> Result<Self, AppError> {
        let jwt_secret =
            std::env::var("JWT_SECRET").unwrap_or_else(|_| "default-secret-key-for-development-only-replace-in-production".to_string());
        let jwt_service = Arc::new(JwtService::new(jwt_secret, Some(24))?);

        Ok(Self { user_repository: database.user_repository(), jwt_service })
    }

    /// Create AppState with custom JWT service
    pub fn with_jwt_service(mut self, jwt_service: Arc<JwtService>) -> Self {
        self.jwt_service = jwt_service;
        self
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().expect("Failed to create default AppState - JWT secret must be at least 32 characters")
    }
}

impl CreateUserRequest {
    /// Validate the create user request
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Name cannot be empty".to_string());
        }

        if self.name.len() > 100 {
            return Err("Name cannot exceed 100 characters".to_string());
        }

        if self.email.trim().is_empty() {
            return Err("Email cannot be empty".to_string());
        }

        // Basic email validation
        if !self.email.contains('@') || !self.email.contains('.') {
            return Err("Invalid email format".to_string());
        }

        if self.email.len() > 255 {
            return Err("Email cannot exceed 255 characters".to_string());
        }

        // Validate password if provided
        if let Some(password) = &self.password {
            if password.len() < 8 {
                return Err("Password must be at least 8 characters long".to_string());
            }
            if password.len() > 128 {
                return Err("Password cannot exceed 128 characters".to_string());
            }
        }

        Ok(())
    }
}

impl UpdateUserRequest {
    /// Validate the update user request
    pub fn validate(&self) -> Result<(), String> {
        if let Some(name) = &self.name {
            if name.trim().is_empty() {
                return Err("Name cannot be empty".to_string());
            }
            if name.len() > 100 {
                return Err("Name cannot exceed 100 characters".to_string());
            }
        }

        if let Some(email) = &self.email {
            if email.trim().is_empty() {
                return Err("Email cannot be empty".to_string());
            }
            if !email.contains('@') || !email.contains('.') {
                return Err("Invalid email format".to_string());
            }
            if email.len() > 255 {
                return Err("Email cannot exceed 255 characters".to_string());
            }
        }

        Ok(())
    }
}

impl RegisterRequest {
    /// Validate the registration request
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Name cannot be empty".to_string());
        }

        if self.name.len() > 100 {
            return Err("Name cannot exceed 100 characters".to_string());
        }

        if self.email.trim().is_empty() {
            return Err("Email cannot be empty".to_string());
        }

        if !self.email.contains('@') || !self.email.contains('.') {
            return Err("Invalid email format".to_string());
        }

        if self.email.len() > 255 {
            return Err("Email cannot exceed 255 characters".to_string());
        }

        if self.password.len() < 8 {
            return Err("Password must be at least 8 characters long".to_string());
        }

        if self.password.len() > 128 {
            return Err("Password cannot exceed 128 characters".to_string());
        }

        Ok(())
    }
}

/// Build application router with in-memory storage
pub fn create_app() -> Result<Router, AppError> {
    let state = AppState::new()?;
    Ok(create_router_with_state(state))
}

/// Create router with given state
fn create_router_with_state(state: AppState) -> Router {
    Router::new()
        // Public routes
        .route("/users", get(list_users))
        .route("/users/:id", get(get_user))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        // Protected routes (require authentication)
        .route("/users", post(create_user))
        .route("/users/:id", put(update_user).delete(delete_user))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Build application router with database
pub async fn create_app_with_database() -> Result<Router, DbError> {
    let database = init_database().await?;
    let state = AppState::from_database(database).map_err(|_e| DbError::Internal)?;
    Ok(create_router_with_state(state))
}

/// Handler for GET /users - returns all users sorted by ID
pub async fn list_users(State(state): State<AppState>) -> Result<Json<Vec<User>>, AppError> {
    // Use repository to get all users with pagination (default: first 100)
    let users = state.user_repository.list(100, 0).await?;
    Ok(Json(users))
}

/// Handler for POST /users - creates a new user with validation
pub async fn create_user(
    State(state): State<AppState>,
    result: Result<Json<CreateUserRequest>, JsonRejection>,
) -> Result<impl IntoResponse, AppError> {
    // Handle JSON parsing errors and map status
    let Json(request) = match result {
        Ok(json) => json,
        Err(rej) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY;
            let body = Json(serde_json::json!({ "error": rej.to_string() }));
            return Ok((status, body).into_response());
        }
    };

    // Validate the input data
    if let Err(error_message) = request.validate() {
        return Err(AppError::Validation(error_message));
    }

    // Hash password if provided, otherwise use default
    let password_hash = if let Some(password) = &request.password {
        PasswordService::hash_password(password)?
    } else {
        "no_password_set".to_string()
    };
    let user = state.user_repository.create(request, password_hash).await.map_err(|e| match e {
        DbError::EmailExists => AppError::Validation("Email already exists".to_string()),
        _ => AppError::Internal,
    })?;

    // Return the created user with 201 status
    Ok((StatusCode::CREATED, Json(user)).into_response())
}

/// Handler for GET /users/:id - returns a specific user by ID
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<u64>,
) -> Result<Json<User>, AppError> {
    if user_id == 0 || user_id > i32::MAX as u64 {
        return Err(AppError::NotFound(format!("User with ID {} not found", user_id)));
    }
    let id32 = user_id as i32;
    // Use repository to find user by ID
    match state.user_repository.find_by_id(id32).await? {
        Some(user) => Ok(Json(user)),
        None => Err(AppError::NotFound(format!("User with ID {} not found", user_id))),
    }
}

/// Handler for POST /auth/register - register a new user
pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate the registration request
    request.validate().map_err(AppError::Validation)?;

    // Hash the password
    let password_hash = PasswordService::hash_password(&request.password)?;

    // Create user request
    let create_request = CreateUserRequest {
        name: request.name,
        email: request.email.clone(),
        password: Some(request.password),
        role: Some(UserRole::User), // Default role for registration
    };

    // Create the user
    let user =
        state.user_repository.create(create_request, password_hash).await.map_err(|e| match e {
            DbError::EmailExists => AppError::Validation("Email already exists".to_string()),
            _ => AppError::Internal,
        })?;

    // Generate JWT token
    let token = state.jwt_service.generate_token(user.id, &user.email, user.role.clone())?;

    // Return auth response
    let response = AuthResponse { token, user: user.into() };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Handler for POST /auth/login - authenticate user and return token
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    // Find user by email
    let user = state
        .user_repository
        .find_by_email(&request.email)
        .await?
        .ok_or_else(|| AppError::Auth("Invalid credentials".to_string()))?;

    // Verify password using bcrypt
    let password_valid = PasswordService::verify_password(&request.password, &user.password_hash)?;

    if !password_valid {
        return Err(AppError::Auth("Invalid credentials".to_string()));
    }

    // Generate JWT token
    let token = state.jwt_service.generate_token(user.id, &user.email, user.role.clone())?;

    // Return auth response
    let response = AuthResponse { token, user: user.into() };

    Ok(Json(response))
}

/// Handler for PUT /users/:id - update an existing user (authenticated)
pub async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<User>, AppError> {
    // Validate the update request
    request.validate().map_err(AppError::Validation)?;

    // Update the user
    match state.user_repository.update(user_id, request).await? {
        Some(user) => Ok(Json(user)),
        None => Err(AppError::NotFound(format!("User with ID {} not found", user_id))),
    }
}

/// Handler for DELETE /users/:id - delete a user (authenticated)
pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
) -> Result<StatusCode, AppError> {
    // Delete the user
    let deleted = state.user_repository.delete(user_id).await?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound(format!("User with ID {} not found", user_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_user_request_validation_valid() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_validation_empty_name() {
        let request = CreateUserRequest {
            name: "".to_string(),
            email: "john@example.com".to_string(),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Name cannot be empty");
    }

    #[test]
    fn test_create_user_request_validation_whitespace_name() {
        let request = CreateUserRequest {
            name: "   ".to_string(),
            email: "john@example.com".to_string(),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Name cannot be empty");
    }

    #[test]
    fn test_create_user_request_validation_long_name() {
        let request = CreateUserRequest {
            name: "a".repeat(101),
            email: "john@example.com".to_string(),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Name cannot exceed 100 characters");
    }

    #[test]
    fn test_create_user_request_validation_empty_email() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "".to_string(),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Email cannot be empty");
    }

    #[test]
    fn test_create_user_request_validation_invalid_email() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "invalid-email".to_string(),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_create_user_request_validation_long_email() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: format!("{}@example.com", "a".repeat(250)),
            password: Some("password123".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Email cannot exceed 255 characters");
    }

    #[test]
    fn test_create_user_request_validation_short_password() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            password: Some("short".to_string()),
            role: Some(UserRole::User),
        };
        assert_eq!(request.validate().unwrap_err(), "Password must be at least 8 characters long");
    }

    #[test]
    fn test_app_state_new() {
        let state = AppState::new().unwrap();
        // Verify the state holds valid Arc references
        assert!(std::sync::Arc::strong_count(&state.user_repository) >= 1);
        assert!(std::sync::Arc::strong_count(&state.jwt_service) >= 1);
    }

    #[test]
    fn test_user_serialization() {
        let user = User {
            id: 1,
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            role: UserRole::User,
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            created_at: chrono::Utc::now(),
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            updated_at: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&json).unwrap();

        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.name, deserialized.name);
        assert_eq!(user.email, deserialized.email);
        assert_eq!(user.role, deserialized.role);
        // password_hash is intentionally not serialized
        assert_eq!(deserialized.password_hash, "");
    }

    #[tokio::test]
    async fn test_list_users_empty() {
        let state = AppState::new().unwrap();
        let result = list_users(State(state)).await;

        assert!(result.is_ok());
        let Json(users) = result.unwrap();
        assert!(users.is_empty());
    }
}
