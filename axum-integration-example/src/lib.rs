use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower_http::trace::TraceLayer;

pub mod database;
pub mod repository;

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
#[derive(Debug, Deserialize)]
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
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Login request model
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Registration request model
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct RegisterRequest {
    pub name: String,
    pub email: String,
    pub password: String,
}

/// Authentication response model
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "docs", derive(ToSchema))]
pub struct AuthResponse {
    pub token: String,
    pub user: UserPublic,
}

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
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
    #[cfg(feature = "auth")]
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
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            ),
            #[cfg(feature = "auth")]
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
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
    #[cfg(feature = "auth")]
    pub jwt_secret: String,
}

impl AppState {
    /// Create a new AppState with in-memory storage
    pub fn new() -> Self {
        Self {
            user_repository: Arc::new(InMemoryUserRepository::new()),
            #[cfg(feature = "auth")]
            jwt_secret: "default-secret-key".to_string(),
        }
    }

    /// Create AppState with a specific repository
    pub fn with_repository(repository: Arc<dyn UserRepository>) -> Self {
        Self {
            user_repository: repository,
            #[cfg(feature = "auth")]
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "default-secret-key".to_string()),
        }
    }

    /// Create AppState from database
    pub fn from_database(database: Database) -> Self {
        Self {
            user_repository: database.user_repository(),
            #[cfg(feature = "auth")]
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "default-secret-key".to_string()),
        }
    }

    #[cfg(feature = "auth")]
    pub fn with_jwt_secret(mut self, secret: String) -> Self {
        self.jwt_secret = secret;
        self
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
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
pub fn create_app() -> Router {
    let state = AppState::new();
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/:id", get(get_user))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Build application router with database
pub async fn create_app_with_database() -> Result<Router, DbError> {
    let database = init_database().await?;
    let state = AppState::from_database(database);

    Ok(Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/:id", get(get_user))
        .layer(TraceLayer::new_for_http())
        .with_state(state))
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
            return Err(AppError::Validation(rej.to_string()));
        }
    };

    // Validate the input data
    if let Err(error_message) = request.validate() {
        return Err(AppError::Validation(error_message));
    }

    // Use repository to create user (password handling will be added in auth task)
    let password_hash = "placeholder_hash".to_string(); // TODO: Replace with actual password hashing
    let user = state
        .user_repository
        .create(request, password_hash)
        .await
        .map_err(|e| match e {
            DbError::EmailExists => AppError::Validation("Email already exists".to_string()),
            _ => AppError::Internal,
        })?;

    // Return the created user with 201 status
    Ok((StatusCode::CREATED, Json(user)))
}

/// Handler for GET /users/:id - returns a specific user by ID
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<i32>,
) -> Result<Json<User>, AppError> {
    // Use repository to find user by ID
    match state.user_repository.find_by_id(user_id).await? {
        Some(user) => Ok(Json(user)),
        None => Err(AppError::NotFound(format!(
            "User with ID {} not found",
            user_id
        ))),
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
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_user_request_validation_empty_name() {
        let request = CreateUserRequest {
            name: "".to_string(),
            email: "john@example.com".to_string(),
        };
        assert_eq!(request.validate().unwrap_err(), "Name cannot be empty");
    }

    #[test]
    fn test_create_user_request_validation_whitespace_name() {
        let request = CreateUserRequest {
            name: "   ".to_string(),
            email: "john@example.com".to_string(),
        };
        assert_eq!(request.validate().unwrap_err(), "Name cannot be empty");
    }

    #[test]
    fn test_create_user_request_validation_long_name() {
        let request = CreateUserRequest {
            name: "a".repeat(101),
            email: "john@example.com".to_string(),
        };
        assert_eq!(
            request.validate().unwrap_err(),
            "Name cannot exceed 100 characters"
        );
    }

    #[test]
    fn test_create_user_request_validation_empty_email() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "".to_string(),
        };
        assert_eq!(request.validate().unwrap_err(), "Email cannot be empty");
    }

    #[test]
    fn test_create_user_request_validation_invalid_email() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: "invalid-email".to_string(),
        };
        assert_eq!(request.validate().unwrap_err(), "Invalid email format");
    }

    #[test]
    fn test_create_user_request_validation_long_email() {
        let request = CreateUserRequest {
            name: "John Doe".to_string(),
            email: format!("{}@example.com", "a".repeat(250)),
        };
        assert_eq!(
            request.validate().unwrap_err(),
            "Email cannot exceed 255 characters"
        );
    }

    #[test]
    fn test_app_state_new() {
        let state = AppState::new();
        let users = state.users.lock().unwrap();
        let next_id = state.next_id.lock().unwrap();

        assert!(users.is_empty());
        assert_eq!(*next_id, 1);
    }

    #[test]
    fn test_user_serialization() {
        let user = User {
            id: 1,
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&json).unwrap();

        assert_eq!(user, deserialized);
    }

    #[tokio::test]
    async fn test_list_users_empty() {
        let state = AppState::new();
        let result = list_users(State(state)).await;

        assert!(result.is_ok());
        let Json(users) = result.unwrap();
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn test_list_users_with_data() {
        let state = AppState::new();

        // Add some test users
        {
            let mut users = state.users.lock().unwrap();
            users.insert(
                2,
                User {
                    id: 2,
                    name: "Jane Smith".to_string(),
                    email: "jane@example.com".to_string(),
                },
            );
            users.insert(
                1,
                User {
                    id: 1,
                    name: "John Doe".to_string(),
                    email: "john@example.com".to_string(),
                },
            );
            users.insert(
                3,
                User {
                    id: 3,
                    name: "Bob Wilson".to_string(),
                    email: "bob@example.com".to_string(),
                },
            );
        }

        let result = list_users(State(state)).await;

        assert!(result.is_ok());
        let Json(users) = result.unwrap();
        assert_eq!(users.len(), 3);

        // Verify users are sorted by ID
        assert_eq!(users[0].id, 1);
        assert_eq!(users[0].name, "John Doe");
        assert_eq!(users[1].id, 2);
        assert_eq!(users[1].name, "Jane Smith");
        assert_eq!(users[2].id, 3);
        assert_eq!(users[2].name, "Bob Wilson");
    }

    #[tokio::test]
    async fn test_list_users_single_user() {
        let state = AppState::new();

        // Add a single user
        {
            let mut users = state.users.lock().unwrap();
            users.insert(
                42,
                User {
                    id: 42,
                    name: "Test User".to_string(),
                    email: "test@example.com".to_string(),
                },
            );
        }

        let result = list_users(State(state)).await;

        assert!(result.is_ok());
        let Json(users) = result.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].id, 42);
        assert_eq!(users[0].name, "Test User");
        assert_eq!(users[0].email, "test@example.com");
    }
}
