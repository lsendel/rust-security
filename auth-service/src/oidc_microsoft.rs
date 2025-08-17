use axum::{extract::Query, response::IntoResponse, Json};
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::{mint_local_tokens_for_subject, AppState};
use once_cell::sync::Lazy;
use tokio::sync::RwLock;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
	pub code: String,
	pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthLoginUrl { pub url: String }

pub async fn microsoft_login() -> impl IntoResponse {
	let client_id = std::env::var("MICROSOFT_CLIENT_ID").unwrap_or_default();
	let redirect_uri = std::env::var("MICROSOFT_REDIRECT_URI")
		.unwrap_or_else(|_| "http://localhost:8080/oauth/microsoft/callback".to_string());
	let state = uuid::Uuid::new_v4().to_string();
	let nonce = uuid::Uuid::new_v4().to_string();
	store_ms_oauth_state(&state, &nonce).await;
	let scope = "openid email profile";
	let auth_url = format!(
		"https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
		urlencoding::encode(&client_id),
		urlencoding::encode(&redirect_uri),
		urlencoding::encode(scope),
		urlencoding::encode(&state),
		urlencoding::encode(&nonce)
	);
	Json(OAuthLoginUrl { url: auth_url })
}

pub async fn microsoft_callback(State(state): State<AppState>, Query(q): Query<OAuthCallbackQuery>) -> impl IntoResponse {
	let client_id = std::env::var("MICROSOFT_CLIENT_ID").unwrap_or_default();
	let client_secret = std::env::var("MICROSOFT_CLIENT_SECRET").unwrap_or_default();
	let redirect_uri = std::env::var("MICROSOFT_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:8080/oauth/microsoft/callback".to_string());

	// Validate state and get expected nonce
	let expected_nonce = match q.state.as_ref() {
		Some(st) => consume_ms_oauth_state(st).await.map(|(n, _)| n),
		None => None,
	};
	if expected_nonce.is_none() { return Json(serde_json::json!({ "error": "invalid_state" })).into_response(); }

	let resp = reqwest::Client::new()
		.post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
		.form(&[
			("code", q.code.as_str()),
			("client_id", client_id.as_str()),
			("client_secret", client_secret.as_str()),
			("redirect_uri", redirect_uri.as_str()),
			("grant_type", "authorization_code"),
		])
		.send()
		.await;

	match resp {
		Ok(rsp) => {
			if let Err(e) = rsp.error_for_status_ref() {
				return Json(serde_json::json!({ "error": e.to_string() })).into_response();
			}
			match rsp.json::<Value>().await {
				Ok(v) => {
					let mut result = serde_json::json!({ "token": v, "state": q.state });
					if let Some(id_token) = result.get("token").and_then(|t| t.get("id_token")).and_then(|x| x.as_str()) {
						let verified = validate_ms_id_token(id_token, &client_id, expected_nonce.as_deref()).await;
						result["id_token_verified"] = serde_json::json!(verified.0);
						if let Some(claims) = verified.1.clone() { result["claims"] = claims.clone(); }
						if verified.0 {
							let sub = result
								.get("claims")
								.and_then(|c| c.get("sub").or_else(|| c.get("oid")))
								.and_then(|s| s.as_str())
								.unwrap_or("unknown");
							let scope = Some("openid profile email".to_string());
							if let Ok(local) = mint_local_tokens_for_subject(&state, sub.to_string(), scope).await {
								result["local_tokens"] = serde_json::to_value(local).unwrap_or_else(|_| serde_json::json!({}));
							}
						}
					}
					Json(result).into_response()
				}
				Err(e) => Json(serde_json::json!({ "error": e.to_string() })).into_response(),
			}
		}
		Err(e) => Json(serde_json::json!({ "error": e.to_string() })).into_response(),
	}
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
enum AudField { One(String), Many(Vec<String>) }

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct MicrosoftClaims {
	iss: String,
	sub: Option<String>,
	oid: Option<String>,
	aud: AudField,
	exp: usize,
	iat: Option<usize>,
	email: Option<String>,
	name: Option<String>,
	#[serde(default)]
	nonce: Option<String>,
}

async fn validate_ms_id_token(id_token: &str, client_id: &str, expected_nonce: Option<&str>) -> (bool, Option<Value>) {
	let header = match jsonwebtoken::decode_header(id_token) { Ok(h) => h, Err(_) => return (false, None) };
	let kid = match header.kid { Some(k) => k, None => return (false, None) };
	let jwks_uri = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
	let jwks = match reqwest::get(jwks_uri).await.and_then(|r| r.error_for_status()) {
		Ok(resp) => resp.json::<Value>().await.ok(),
		Err(_) => None,
	};
	let Some(keys) = jwks.and_then(|v| v.get("keys").cloned()) else { return (false, None) };
	let Some(arr) = keys.as_array() else { return (false, None) };
	let mut n_e: Option<(String, String)> = None;
	for k in arr {
		if k.get("kid").and_then(|x| x.as_str()) == Some(kid.as_str()) {
			if let (Some(n), Some(e)) = (
				k.get("n").and_then(|x| x.as_str()),
				k.get("e").and_then(|x| x.as_str()),
			) {
				n_e = Some((n.to_string(), e.to_string()));
				break;
			}
		}
	}
	let Some((n, e)) = n_e else { return (false, None) };
	let key = match jsonwebtoken::DecodingKey::from_rsa_components(&n, &e) { Ok(k) => k, Err(_) => return (false, None) };
	let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
	validation.set_audience(&[client_id]);
	// Accept common Microsoft issuers
	validation.set_issuer(&[
		"https://login.microsoftonline.com/{tenantid}/v2.0",
		"https://login.microsoftonline.com/common/v2.0",
		"https://sts.windows.net/{tenantid}/",
	]);
	match jsonwebtoken::decode::<MicrosoftClaims>(id_token, &key, &validation) {
		Ok(data) => {
			if let Some(exp_nonce) = expected_nonce {
				if let Some(claims) = serde_json::to_value(&data.claims).ok() {
					if let Some(nonce_claim) = claims.get("nonce").and_then(|v| v.as_str()) {
						if nonce_claim != exp_nonce { return (false, None); }
					} else {
						return (false, None);
					}
				}
			}
			(true, serde_json::to_value(data.claims).ok())
		},
		Err(_) => (false, None),
	}
}

// Ephemeral state store with TTL for Microsoft OAuth
static MS_STATE_CACHE: Lazy<RwLock<HashMap<String, (String, u64)>>> = Lazy::new(|| RwLock::new(HashMap::new()));

async fn store_ms_oauth_state(state: &str, nonce: &str) {
    let mut guard = MS_STATE_CACHE.write().await;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    guard.insert(state.to_string(), (nonce.to_string(), now + 600));
}

async fn consume_ms_oauth_state(state: &str) -> Option<(String, u64)> {
    let mut guard = MS_STATE_CACHE.write().await;
    if let Some((nonce, exp)) = guard.remove(state) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        if now <= exp { return Some((nonce, exp)); }
    }
    None
}
