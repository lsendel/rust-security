//! Session Data Transfer Objects

/// Session information DTO
#[derive(Debug, serde::Serialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub is_active: bool,
}

/// Session creation response DTO
#[derive(Debug, serde::Serialize)]
pub struct SessionResponse {
    pub session_id: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
