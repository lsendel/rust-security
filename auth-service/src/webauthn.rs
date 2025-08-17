use axum::{extract::State, Json};
// Removed unused import: use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginRegisterRequest { pub user_id: String, pub username: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginRegisterResponse { pub public_key: serde_json::Value }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishRegisterRequest { pub user_id: String, pub credential: serde_json::Value }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishRegisterResponse { pub registered: bool }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginAssertRequest { pub user_id: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginAssertResponse { pub public_key: serde_json::Value }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishAssertRequest { pub user_id: String, pub credential: serde_json::Value }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinishAssertResponse { pub verified: bool }

// In-memory stubs (replace with persistent store later)
static REGISTRATION_CHALLENGES: Lazy<RwLock<HashMap<String, serde_json::Value>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static ASSERTION_CHALLENGES: Lazy<RwLock<HashMap<String, serde_json::Value>>> = Lazy::new(|| RwLock::new(HashMap::new()));
static CREDENTIALS: Lazy<RwLock<HashMap<String, Vec<serde_json::Value>>>> = Lazy::new(|| RwLock::new(HashMap::new()));

pub async fn begin_register(State(_state): State<AppState>, Json(body): Json<BeginRegisterRequest>) -> Json<BeginRegisterResponse> {
    // Stub challenge (library to generate real challenge later)
    let challenge = serde_json::json!({ "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()) });
    REGISTRATION_CHALLENGES.write().await.insert(body.user_id.clone(), challenge.clone());
    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let origin = std::env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost".to_string());
    let pubkey = serde_json::json!({
        "rp": {"id": rp_id, "name": std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "auth-service".to_string())},
        "user": {"id": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body.user_id.as_bytes()), "name": body.username, "displayName": body.username},
        "challenge": challenge["challenge"],
        "pubKeyCredParams": [{"type":"public-key","alg": -7}],
        "timeout": 60000,
        "attestation": "none",
        "authenticatorSelection": {"userVerification": "preferred"},
        "extensions": {"appidExclude": origin}
    });
    Json(BeginRegisterResponse { public_key: pubkey })
}

pub async fn finish_register(State(_state): State<AppState>, Json(body): Json<FinishRegisterRequest>) -> Json<FinishRegisterResponse> {
    // Stub: accept any credential, store it
    let mut creds = CREDENTIALS.write().await;
    creds.entry(body.user_id.clone()).or_default().push(body.credential);
    Json(FinishRegisterResponse { registered: true })
}

pub async fn begin_assert(State(_state): State<AppState>, Json(body): Json<BeginAssertRequest>) -> Json<BeginAssertResponse> {
    let challenge = serde_json::json!({ "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()) });
    ASSERTION_CHALLENGES.write().await.insert(body.user_id.clone(), challenge.clone());
    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let allow = CREDENTIALS.read().await.get(&body.user_id).cloned().unwrap_or_default();
    let pubkey = serde_json::json!({
        "rpId": rp_id,
        "challenge": challenge["challenge"],
        "allowCredentials": allow,
        "timeout": 60000,
        "userVerification": "preferred"
    });
    Json(BeginAssertResponse { public_key: pubkey })
}

pub async fn finish_assert(State(_state): State<AppState>, Json(_body): Json<FinishAssertRequest>) -> Json<FinishAssertResponse> {
    // Stub: accept any assertion; mark session verified via set_mfa_verified
    let token_verified = true;
    if token_verified {
        // The caller should immediately call /mfa/session/verify; for convenience we don't auto-mark here
        return Json(FinishAssertResponse { verified: true });
    }
    Json(FinishAssertResponse { verified: false })
}


