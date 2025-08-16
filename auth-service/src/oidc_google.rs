use axum::{extract::Query, response::IntoResponse, Json};
use crate::{mint_local_tokens_for_subject, AppState};
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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

pub async fn google_login() -> impl IntoResponse {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:8080/oauth/google/callback".to_string());
    let state = uuid::Uuid::new_v4().to_string();
    let scope = "openid email profile";
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        urlencoding::encode(&client_id), urlencoding::encode(&redirect_uri), urlencoding::encode(scope), urlencoding::encode(&state)
    );
    Json(OAuthLoginUrl { url: auth_url })
}

pub async fn google_callback(State(state): State<AppState>, Query(q): Query<OAuthCallbackQuery>) -> impl IntoResponse {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:8080/oauth/google/callback".to_string());

    let resp = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
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
                    // Validate id_token if present
                    let mut result = serde_json::json!({ "token": v, "state": q.state });
                    if let Some(id_token) = result.get("token").and_then(|t| t.get("id_token")).and_then(|x| x.as_str()) {
                        let verified = validate_google_id_token(id_token, &client_id).await;
                        result["id_token_verified"] = serde_json::json!(verified.0);
                        if let Some(claims) = verified.1.clone() { result["claims"] = claims.clone(); }
                        if verified.0 {
                            // derive subject
                            let sub = result
                                .get("claims")
                                .and_then(|c| c.get("sub"))
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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Jwk { kid: String, n: String, e: String, kty: String, alg: Option<String> }

type JwksMap = HashMap<String, (String, String)>;
#[allow(clippy::type_complexity)]
static GOOGLE_JWKS_CACHE: Lazy<RwLock<(u64, JwksMap)>> = Lazy::new(|| RwLock::new((0, HashMap::new())));

async fn fetch_google_jwks() -> HashMap<String, (String, String)> {
    let now = current_unix();
    {
        let guard = GOOGLE_JWKS_CACHE.read().await;
        if now.saturating_sub(guard.0) < 300 && !guard.1.is_empty() {
            return guard.1.clone();
        }
    }
    let url = "https://www.googleapis.com/oauth2/v3/certs";
    let map = match reqwest::get(url).await {
        Ok(r) => match r.error_for_status() {
            Ok(ok) => match ok.json::<Value>().await {
                Ok(v) => {
                    let mut m = HashMap::new();
                    if let Some(arr) = v.get("keys").and_then(|k| k.as_array()) {
                        for k in arr {
                            if let (Some(kid), Some(n), Some(e)) = (
                                k.get("kid").and_then(|x| x.as_str()),
                                k.get("n").and_then(|x| x.as_str()),
                                k.get("e").and_then(|x| x.as_str()),
                            ) {
                                m.insert(kid.to_string(), (n.to_string(), e.to_string()));
                            }
                        }
                    }
                    m
                }
                Err(_) => HashMap::new(),
            },
            Err(_) => HashMap::new(),
        },
        Err(_) => HashMap::new(),
    };
    let mut guard = GOOGLE_JWKS_CACHE.write().await;
    *guard = (now, map.clone());
    map
}

fn current_unix() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum AudField { One(String), Many(Vec<String>) }

#[derive(Debug, Deserialize, Serialize)]
struct GoogleClaims {
    iss: String,
    sub: String,
    aud: AudField,
    exp: usize,
    iat: Option<usize>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

async fn validate_google_id_token(id_token: &str, client_id: &str) -> (bool, Option<Value>) {
    let header = match jsonwebtoken::decode_header(id_token) { Ok(h) => h, Err(_) => return (false, None) };
    let kid = match header.kid { Some(k) => k, None => return (false, None) };
    let jwks = fetch_google_jwks().await;
    let (n, e) = match jwks.get(&kid) { Some(ne) => ne.clone(), None => return (false, None) };
    let key = match jsonwebtoken::DecodingKey::from_rsa_components(&n, &e) { Ok(k) => k, Err(_) => return (false, None) };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    match jsonwebtoken::decode::<GoogleClaims>(id_token, &key, &validation) {
        Ok(data) => (true, serde_json::to_value(data.claims).ok()),
        Err(_) => (false, None),
    }
}


