//! OAuth authentication handlers
//!
//! Contains handlers for OAuth authentication endpoints.

use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthResponse {
    pub message: String,
}

pub async fn oauth_authorize() -> Json<OAuthResponse> {
    Json(OAuthResponse {
        message: "OAuth authorize endpoint".to_string(),
    })
}

pub async fn oauth_token() -> Json<OAuthResponse> {
    Json(OAuthResponse {
        message: "OAuth token endpoint".to_string(),
    })
}
