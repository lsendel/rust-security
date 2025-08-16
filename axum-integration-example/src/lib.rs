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

/// User model representing a user in the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub email: String,
}

/// Request model for creating a new user
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub name: String,
    pub email: String,
}

/// Application state containing user storage and ID generation
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<Mutex<HashMap<u32, User>>>,
    pub next_id: Arc<Mutex<u32>>,
}

impl AppState {
    /// Create a new AppState with empty storage
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
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

        Ok(())
    }
}

/// Build application router
pub fn create_app() -> Router {
    let state = AppState::new();
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/:id", get(get_user))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Handler for GET /users - returns all users sorted by ID
pub async fn list_users(State(state): State<AppState>) -> Result<Json<Vec<User>>, StatusCode> {
    // Lock the users HashMap with proper error handling
    let users = match state.users.lock() {
        Ok(users) => users,
        Err(_) => {
            // Handle lock poisoning - this should rarely happen in practice
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Collect all users into a vector and sort by ID for consistent ordering
    let mut user_list: Vec<User> = users.values().cloned().collect();
    user_list.sort_by_key(|user| user.id);

    // Return JSON response with 200 OK status
    Ok(Json(user_list))
}

/// Handler for POST /users - creates a new user with validation
pub async fn create_user(
    State(state): State<AppState>,
    result: Result<Json<CreateUserRequest>, JsonRejection>,
) -> impl IntoResponse {
    // Handle JSON parsing errors and map status
    let Json(request) = match result {
        Ok(json) => json,
        Err(rej) => {
            use axum::extract::rejection::JsonRejection::*;
            let status = match rej {
                JsonDataError(_) | JsonSyntaxError(_) => StatusCode::UNPROCESSABLE_ENTITY,
                _ => StatusCode::BAD_REQUEST,
            };
            return (
                status,
                Json(serde_json::json!({
                    "error": rej.to_string()
                })),
            )
                .into_response();
        }
    };

    // Validate the input data
    if let Err(error_message) = request.validate() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": error_message
            })),
        )
            .into_response();
    }

    // Generate new unique ID atomically
    let new_id = {
        let mut next_id = match state.next_id.lock() {
            Ok(next_id) => next_id,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to generate user ID"
                    })),
                )
                    .into_response();
            }
        };

        let id = *next_id;
        *next_id += 1;
        id
    };

    // Create the new user
    let user = User {
        id: new_id,
        name: request.name.trim().to_string(),
        email: request.email.trim().to_string(),
    };

    // Store the user in the HashMap
    {
        let mut users = match state.users.lock() {
            Ok(users) => users,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "Failed to store user"
                    })),
                )
                    .into_response();
            }
        };

        users.insert(new_id, user.clone());
    }

    // Return the created user with 201 status
    (StatusCode::CREATED, Json(user)).into_response()
}

/// Handler for GET /users/:id - returns a specific user by ID
pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<u32>,
) -> impl IntoResponse {
    // Lock the users HashMap with proper error handling
    let users = match state.users.lock() {
        Ok(users) => users,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to access user data"
                })),
            )
                .into_response();
        }
    };

    // Look up the user by ID
    match users.get(&user_id) {
        Some(user) => {
            // Return the user with 200 OK status
            (StatusCode::OK, Json(user.clone())).into_response()
        }
        None => {
            // Return 404 Not Found for missing user
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("User with ID {} not found", user_id)
                })),
            )
                .into_response()
        }
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
