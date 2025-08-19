use axum::{
    extract::{State},
    routing::{post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use crate::api_key_store::{ApiKey, ApiKeyStore, ApiKeyDetails};
use crate::errors::{AuthError, internal_error};
use rand::RngCore;
use base64::{Engine as _, engine::general_purpose};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher};


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

use axum::routing::{get, delete};

pub fn router(api_key_store: ApiKeyStore) -> Router {
    Router::new()
        .route("/", post(create_api_key).get(list_api_keys))
        .route("/:prefix", get(get_api_key).delete(revoke_api_key))
        .with_state(api_key_store)
}

async fn revoke_api_key(
    State(store): State<ApiKeyStore>,
    Path(prefix): Path<String>,
) -> Result<(), AuthError> {
    store.revoke_api_key(&prefix)
        .await
        .map_err(|e| match e {
            crate::api_key_store::ApiKeyError::NotFound => AuthError::NotFound { resource: "API Key".to_string() },
            _ => internal_error("Failed to revoke API key"),
        })?;

    Ok(())
}

async fn list_api_keys(
    State(store): State<ApiKeyStore>,
) -> Result<Json<Vec<ApiKeyDetails>>, AuthError> {
    let keys = store.list_api_keys()
        .await
        .map_err(|e| internal_error(&format!("Failed to list API keys: {}", e)))?;

    Ok(Json(keys))
}

async fn get_api_key(
    State(store): State<ApiKeyStore>,
    Path(prefix): Path<String>,
) -> Result<Json<ApiKey>, AuthError> {
    let api_key = store.get_api_key_by_prefix(&prefix)
        .await
        .map_err(|e| internal_error(&format!("Failed to get API key: {}", e)))?
        .ok_or(AuthError::NotFound { resource: "API Key".to_string() })?;

    Ok(Json(api_key))
}

async fn create_api_key(
    State(store): State<ApiKeyStore>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, AuthError> {
    // 1. Generate a new secure API key string.
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let secret = general_purpose::STANDARD.encode(&key_bytes);

    // 2. Generate a prefix for the key.
    let prefix = "sk_live_";
    let api_key_string = format!("{}{}", prefix, secret);

    // 3. Hash the key using Argon2.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hashed_key = argon2.hash_password(api_key_string.as_bytes(), &salt)
        .map_err(|e| internal_error(&format!("Failed to hash API key: {}", e)))?
        .to_string();

    // 4. Store the hashed key, prefix, client_id, and other metadata in the database.
    let key_details = store.create_api_key(
        &payload.client_id,
        prefix,
        &hashed_key,
        payload.permissions.as_deref(),
        payload.expires_at,
    ).await.map_err(|e| internal_error(&format!("Failed to create API key: {}", e)))?;

    // 5. Return the full, unhashed key to the user.
    Ok(Json(CreateApiKeyResponse {
        api_key: api_key_string,
        key_details,
    }))
}
