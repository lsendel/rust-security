//! OAuth token endpoint handler

use axum::{extract::State, response::Json, Form};
use rand::{rngs::OsRng, Rng};

use crate::{
    error::{AuthError, Result},
    server::AppState,
    store::TokenData,
    token::{TokenRequest, TokenResponse},
};

/// Handle client credentials flow
#[cfg(feature = "client-credentials")]
pub async fn client_credentials(
    State(state): State<AppState>,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    // Validate grant type
    if request.grant_type != "client_credentials" {
        return Err(AuthError::InvalidGrantType(request.grant_type));
    }

    // Validate client
    let client = state
        .config
        .clients
        .get(&request.client_id)
        .ok_or(AuthError::InvalidClient)?;

    if client.client_secret != request.client_secret {
        return Err(AuthError::InvalidClient);
    }

    // Generate token
    let token = generate_random_token();
    let expires_in = 3600; // 1 hour
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + expires_in;

    // Store token
    let token_data = TokenData {
        client_id: request.client_id,
        scope: request.scope.clone(),
        expires_at,
        active: true,
    };

    state.store.write().await.store_token(&token, token_data);

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in,
        scope: request.scope,
    }))
}

fn generate_random_token() -> String {
    let mut rng = OsRng;
    let token: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..62);
            match idx {
                0..=25 => (b'A' + idx) as char,
                26..=51 => (b'a' + (idx - 26)) as char,
                _ => (b'0' + (idx - 52)) as char,
            }
        })
        .collect();

    format!("auth_core_{}", token)
}
