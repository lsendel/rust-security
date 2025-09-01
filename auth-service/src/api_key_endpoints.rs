use crate::api_key_store::{ApiKey, ApiKeyDetails};
use crate::shared::error::AppError;
use crate::AppState;
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher};
use axum::{extract::State, routing::post, Json, Router};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub client_id: String,
    pub permissions: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String, // The full, unhashed key
    pub key_details: ApiKey,
}

use axum::extract::Path;

use axum::routing::get;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_api_key).get(list_api_keys))
        .route("/:prefix", get(get_api_key).delete(revoke_api_key))
}

/// Revoke an API key by its prefix
///
/// # Errors
///
/// Returns `crate::shared::error::AppError::NotFound` if the API key with the given prefix does not exist.
/// Returns `crate::shared::error::AppError::InternalError` if the revocation operation fails.
///
/// # Panics
///
/// This function does not panic under normal operation.
async fn revoke_api_key(
    State(state): State<AppState>,
    Path(prefix): Path<String>,
) -> Result<(), crate::shared::error::AppError> {
    state
        .api_key_store
        .revoke_api_key(&prefix)
        .await
        .map_err(|e| match e {
            crate::api_key_store::ApiKeyError::NotFound => {
                crate::shared::error::AppError::NotFound("API Key".to_string())
            }
            _ => AppError::internal("Failed to revoke API key"),
        })?;

    Ok(())
}

/// List all API keys
///
/// # Errors
///
/// Returns `crate::shared::error::AppError::InternalError` if the list operation fails due to:
/// - Database connection issues
/// - Serialization failures
/// - Storage backend errors
///
/// # Panics
///
/// This function does not panic under normal operation.
async fn list_api_keys(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiKeyDetails>>, crate::shared::error::AppError> {
    let keys = state
        .api_key_store
        .list_api_keys()
        .await
        .map_err(|e| AppError::internal(format!("Failed to list API keys: {e}")))?;

    Ok(Json(keys))
}

/// Get details of a specific API key by its prefix
///
/// # Errors
///
/// Returns `crate::shared::error::AppError::NotFound` if the API key with the given prefix does not exist.
/// Returns `crate::shared::error::AppError::InternalError` if the get operation fails due to storage backend errors.
///
/// # Panics
///
/// This function does not panic under normal operation.
async fn get_api_key(
    State(state): State<AppState>,
    Path(prefix): Path<String>,
) -> Result<Json<ApiKeyDetails>, crate::shared::error::AppError> {
    let api_key = state
        .api_key_store
        .get_api_key_by_prefix(&prefix)
        .await
        .map_err(|e| AppError::internal(format!("Failed to get API key: {e}")))?
        .ok_or(crate::shared::error::AppError::NotFound("API Key".to_string()))?;

    let details = ApiKeyDetails {
        id: api_key.id,
        prefix: api_key.prefix,
        client_id: api_key.client_id,
        permissions: api_key.permissions,
        created_at: api_key.created_at,
        expires_at: api_key.expires_at,
        last_used_at: api_key.last_used_at,
        status: api_key.status,
    };
    Ok(Json(details))
}

/// Create a new API key
///
/// # Errors
///
/// Returns `crate::shared::error::AppError::InternalError` if:
/// - Random key generation fails
/// - Password hashing with Argon2 fails
/// - API key storage operation fails
/// - Database constraints are violated
///
/// # Panics
///
/// This function does not panic under normal operation.
async fn create_api_key(
    State(state): State<AppState>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, crate::shared::error::AppError> {
    // 1. Generate a new secure API key string.
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let secret = general_purpose::STANDARD.encode(key_bytes);

    // 2. Generate a prefix for the key.
    let prefix = "sk_live_";
    let api_key_string = format!("{prefix}{secret}");

    // 3. Hash the key using Argon2.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_key = argon2
        .hash_password(api_key_string.as_bytes(), &salt)
        .map_err(|e| AppError::internal(format!("Failed to hash API key: {e}")))?
        .to_string();

    // 4. Store the hashed key, prefix, client_id, and other metadata in the database.
    let key_details = state
        .api_key_store
        .create_api_key(
            &payload.client_id,
            prefix,
            &hashed_key,
            payload.permissions.as_deref(),
            payload.expires_at,
        )
        .await
        .map_err(|e| AppError::internal(format!("Failed to create API key: {e}")))?;

    // 5. Return the full, unhashed key to the user.
    Ok(Json(CreateApiKeyResponse {
        api_key: api_key_string,
        key_details,
    }))
}
