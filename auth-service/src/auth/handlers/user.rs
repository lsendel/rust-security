//! User authentication handlers
//!
//! Contains handlers for user authentication endpoints.

use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub message: String,
}

pub async fn user_profile() -> Json<UserResponse> {
    Json(UserResponse {
        message: "User profile endpoint".to_string(),
    })
}
