use axum::{extract::Query, response::IntoResponse, Json};
use crate::{mint_local_tokens_for_subject, AppState};
use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::resilient_http::OidcHttpClient;
use crate::pii_protection::redact_log;
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
    let nonce = uuid::Uuid::new_v4().to_string();
    // Store state->(nonce, timestamp) for CSRF and replay protection
    store_oauth_state(&state, &nonce).await;
    let scope = "openid email profile";
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
        urlencoding::encode(&client_id), urlencoding::encode(&redirect_uri), urlencoding::encode(scope), urlencoding::encode(&state), urlencoding::encode(&nonce)
    );

    // Log OAuth initiation
    SecurityLogger::log_event(&mut SecurityEvent::new(
        SecurityEventType::AuthenticationAttempt,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "Google OAuth login initiated".to_string(),
    )
    .with_actor(client_id.clone())
    .with_action("oauth_initiate".to_string())
    .with_target("google_oauth".to_string())
    .with_outcome("initiated".to_string())
    .with_reason("User redirected to Google OAuth authorization endpoint".to_string())
    .with_detail("provider".to_string(), "google")
    .with_detail("client_id".to_string(), client_id.clone())
    .with_detail("scope".to_string(), scope));

    Json(OAuthLoginUrl { url: auth_url })
}

pub async fn google_callback(State(state): State<AppState>, Query(q): Query<OAuthCallbackQuery>) -> impl IntoResponse {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:8080/oauth/google/callback".to_string());

    // Validate state parameter
    let (valid_state, expected_nonce) = match q.state.as_ref() {
        Some(st) => match consume_oauth_state(st).await {
            Some((nonce, _ts)) => (true, Some(nonce)),
            None => (false, None),
        },
        None => (false, None),
    };
    if !valid_state {
        return Json(serde_json::json!({
            "error": "invalid_state",
            "error_description": "Missing or unknown state",
        })).into_response();
    }

    // Log OAuth callback attempt
    SecurityLogger::log_event(&mut SecurityEvent::new(
        SecurityEventType::AuthenticationAttempt,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "Google OAuth callback received".to_string(),
    )
    .with_actor("google_oauth".to_string())
    .with_action("oauth_callback".to_string())
    .with_target("auth_service".to_string())
    .with_outcome("received".to_string())
    .with_reason("OAuth authorization code callback from Google".to_string())
    .with_detail("provider".to_string(), "google")
    .with_detail("has_code".to_string(), !q.code.is_empty())
    .with_detail("has_state".to_string(), q.state.is_some()));

    // Use resilient HTTP client for Google OAuth token exchange
    let http_client = match OidcHttpClient::new("google") {
        Ok(client) => client,
        Err(e) => {
            SecurityLogger::log_event(&mut SecurityEvent::new(
                SecurityEventType::AuthenticationFailure,
                SecuritySeverity::High,
                "auth-service".to_string(),
                "Failed to create Google OIDC HTTP client".to_string(),
            )
            .with_actor("system".to_string())
            .with_action("http_client_creation".to_string())
            .with_target("oidc_client".to_string())
            .with_outcome("failure".to_string())
            .with_reason("Unable to initialize resilient HTTP client for Google OIDC communication".to_string())
            .with_detail("error".to_string(), e.to_string()));
            
            return Json(serde_json::json!({
                "error": "server_error",
                "error_description": "Internal server error",
            })).into_response();
        }
    };

    let resp = http_client
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
            let rsp = match rsp.error_for_status() {
                Ok(response) => response,
                Err(e) => {
                    // Log token exchange failure
                    SecurityLogger::log_event(&mut SecurityEvent::new(
                        SecurityEventType::AuthenticationFailure,
                        SecuritySeverity::Medium,
                        "auth-service".to_string(),
                        "Google OAuth token exchange failed".to_string(),
                    )
                    .with_actor("google_oauth".to_string())
                    .with_action("oauth_token_exchange".to_string())
                    .with_target("oauth_token".to_string())
                    .with_outcome("failure".to_string())
                    .with_reason("Google OAuth server returned HTTP error during token exchange".to_string())
                    .with_detail("provider".to_string(), "google")
                    .with_detail("error".to_string(), redact_log(&e.to_string())));

                    return Json(serde_json::json!({ "error": redact_log(&e.to_string()) })).into_response();
                }
            };
            match rsp.json::<Value>().await {
                Ok(v) => {
                    // Validate id_token if present
                    let mut result = serde_json::json!({ "token": v, "state": q.state });
                    if let Some(id_token) = result.get("token").and_then(|t| t.get("id_token")).and_then(|x| x.as_str()) {
                        let verified = validate_google_id_token(id_token, &client_id, expected_nonce.as_deref()).await;
                        result["id_token_verified"] = serde_json::json!(verified.0);
                        if let Some(claims) = verified.1.clone() { result["claims"] = claims.clone(); }
                        if verified.0 {
                            // derive subject
                            let sub = result
                                .get("claims")
                                .and_then(|c| c.get("sub"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("unknown")
                                .to_string();
                            let scope = Some("openid profile email".to_string());
                            if let Ok(local) = mint_local_tokens_for_subject(&state, sub.clone(), scope).await {
                                result["local_tokens"] = serde_json::to_value(local).unwrap_or_else(|_| serde_json::json!({}));

                                // Log successful authentication
                                SecurityLogger::log_event(&mut SecurityEvent::new(
                                    SecurityEventType::AuthenticationSuccess,
                                    SecuritySeverity::Low,
                                    "auth-service".to_string(),
                                    "Google OAuth authentication successful".to_string(),
                                )
                                .with_actor("google_oauth".to_string())
                                .with_action("oauth_authentication".to_string())
                                .with_target("user".to_string())
                                .with_outcome("success".to_string())
                                .with_reason("Google ID token verified and local tokens minted successfully".to_string())
                                .with_detail("provider".to_string(), "google")
                                .with_user_id(sub)
                                .with_detail("id_token_verified".to_string(), verified.0));
                            }
                        } else {
                            // Log ID token verification failure
                            SecurityLogger::log_event(&mut SecurityEvent::new(
                                SecurityEventType::AuthenticationFailure,
                                SecuritySeverity::High,
                                "auth-service".to_string(),
                                "Google OAuth ID token verification failed".to_string(),
                            )
                            .with_actor("google_oauth".to_string())
                            .with_action("oauth_id_token_verification".to_string())
                            .with_target("id_token".to_string())
                            .with_outcome("failure".to_string())
                            .with_reason("Google ID token signature validation or claim verification failed".to_string())
                            .with_detail("provider".to_string(), "google"));
                        }
                    }
                    Json(result).into_response()
                }
                Err(e) => Json(serde_json::json!({ "error": redact_log(&e.to_string()) })).into_response(),
            }
        }
        Err(e) => Json(serde_json::json!({ "error": redact_log(&e.to_string()) })).into_response(),
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct Jwk { kid: String, n: String, e: String, kty: String, alg: Option<String> }

type JwksMap = HashMap<String, (String, String)>;
#[allow(clippy::type_complexity)]
static GOOGLE_JWKS_CACHE: Lazy<RwLock<(u64, JwksMap)>> = Lazy::new(|| RwLock::new((0, HashMap::new())));

// OAuth state storage with Redis fallback for multi-instance safety
static GOOGLE_STATE_CACHE: Lazy<RwLock<HashMap<String, (String, u64)>>> = Lazy::new(|| RwLock::new(HashMap::new()));

async fn redis_conn() -> Option<redis::aio::ConnectionManager> {
    let url = std::env::var("REDIS_URL").ok()?;
    let client = redis::Client::open(url).ok()?;
    client.get_connection_manager().await.ok()
}

async fn store_oauth_state(state: &str, nonce: &str) {
    let now = current_unix();
    if let Some(mut conn) = redis_conn().await {
        let key = format!("oidc:google:state:{}", state);
        let _: () = redis::Cmd::set_ex(&key, nonce, 600)
            .query_async(&mut conn)
            .await
            .unwrap_or(());
        return;
    }
    let mut guard = GOOGLE_STATE_CACHE.write().await;
    guard.insert(state.to_string(), (nonce.to_string(), now + 600));
}

async fn consume_oauth_state(state: &str) -> Option<(String, u64)> {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("oidc:google:state:{}", state);
        let val: Option<String> = redis::Cmd::get(&key).query_async(&mut conn).await.ok();
        let _: () = redis::Cmd::del(&key).query_async(&mut conn).await.unwrap_or(());
        if let Some(nonce) = val { return Some((nonce, current_unix() + 1)); }
    }
    let mut guard = GOOGLE_STATE_CACHE.write().await;
    if let Some((nonce, exp)) = guard.remove(state) {
        if current_unix() <= exp { return Some((nonce, exp)); }
    }
    None
}

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
    #[serde(default)]
    nonce: Option<String>,
}

async fn validate_google_id_token(id_token: &str, client_id: &str, expected_nonce: Option<&str>) -> (bool, Option<Value>) {
    let header = match jsonwebtoken::decode_header(id_token) { Ok(h) => h, Err(_) => return (false, None) };
    let kid = match header.kid { Some(k) => k, None => return (false, None) };
    let jwks = fetch_google_jwks().await;
    let (n, e) = match jwks.get(&kid) { Some(ne) => ne.clone(), None => return (false, None) };
    let key = match jsonwebtoken::DecodingKey::from_rsa_components(&n, &e) { Ok(k) => k, Err(_) => return (false, None) };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    match jsonwebtoken::decode::<GoogleClaims>(id_token, &key, &validation) {
        Ok(data) => {
            // If a nonce was provided, verify claim matches
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


