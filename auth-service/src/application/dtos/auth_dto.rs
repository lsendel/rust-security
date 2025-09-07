//! Authentication Data Transfer Objects

/// Authentication response DTO
#[derive(Debug, serde::Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
}

/// Token refresh request DTO
#[derive(Debug, serde::Deserialize)]
pub struct TokenRefreshRequest {
    pub refresh_token: String,
}

/// Token refresh response DTO
#[derive(Debug, serde::Serialize)]
pub struct TokenRefreshResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}
