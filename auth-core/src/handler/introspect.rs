//! Token introspection endpoint

use axum::{extract::State, response::Json, Form};
use serde::{Deserialize, Serialize};

use crate::{error::Result, server::AppState};

#[derive(Debug, Deserialize)]
pub struct IntrospectRequest {
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

/// Token introspection endpoint (RFC 7662)
pub async fn token_introspect(
    State(state): State<AppState>,
    Form(request): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>> {
    // Clean up expired tokens first
    state.store.write().await.cleanup_expired();

    // Look up the token
    if let Some(token_data) = state.store.read().await.get_token(&request.token) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if token_data.active && token_data.expires_at > now {
            return Ok(Json(IntrospectResponse {
                active: true,
                client_id: Some(token_data.client_id.clone()),
                scope: token_data.scope.clone(),
                exp: Some(token_data.expires_at),
                token_type: Some("Bearer".to_string()),
            }));
        }
    }

    // Token not found or expired
    Ok(Json(IntrospectResponse {
        active: false,
        client_id: None,
        scope: None,
        exp: None,
        token_type: None,
    }))
}
