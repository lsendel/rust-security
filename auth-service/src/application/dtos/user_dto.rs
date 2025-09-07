//! User Data Transfer Objects

/// User registration request DTO
#[derive(Debug, serde::Deserialize)]
pub struct UserRegistrationRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

/// User login request DTO
#[derive(Debug, serde::Deserialize)]
pub struct UserLoginRequest {
    pub email: String,
    pub password: String,
}

/// User response DTO
#[derive(Debug, serde::Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
