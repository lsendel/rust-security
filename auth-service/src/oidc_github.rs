use axum::{extract::Query, response::IntoResponse, Json};
use crate::{mint_local_tokens_for_subject, AppState};
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OAuthLoginUrl { pub url: String }

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    scope: String,
    token_type: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
    html_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    verified: bool,
    primary: bool,
}

pub async fn github_login() -> impl IntoResponse {
    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let redirect_uri = std::env::var("GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/oauth/github/callback".to_string());
    let state = uuid::Uuid::new_v4().to_string();
    let scope = "user:email read:user";
    
    let auth_url = format!(
        "https://github.com/login/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(scope),
        urlencoding::encode(&state)
    );
    
    Json(OAuthLoginUrl { url: auth_url })
}

pub async fn github_callback(
    State(state): State<AppState>, 
    Query(q): Query<OAuthCallbackQuery>
) -> impl IntoResponse {
    // Check for OAuth errors first
    if let Some(error) = q.error {
        let error_desc = q.error_description.unwrap_or_else(|| "Unknown error".to_string());
        return Json(serde_json::json!({
            "error": error,
            "error_description": error_desc,
            "state": q.state
        })).into_response();
    }

    // Get the authorization code
    let code = match q.code {
        Some(c) => c,
        None => {
            return Json(serde_json::json!({
                "error": "missing_code",
                "error_description": "Authorization code is required",
                "state": q.state
            })).into_response();
        }
    };

    let client_id = std::env::var("GITHUB_CLIENT_ID").unwrap_or_default();
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default();
    let redirect_uri = std::env::var("GITHUB_REDIRECT_URI")
        .unwrap_or_else(|_| "http://localhost:8080/oauth/github/callback".to_string());

    // Exchange authorization code for access token
    let token_response = exchange_code_for_token(&code, &client_id, &client_secret, &redirect_uri).await;

    match token_response {
        Ok(token_resp) => {
            // Get user information from GitHub API
            match get_github_user_info(&token_resp.access_token).await {
                Ok(user_info) => {
                    let mut result = serde_json::json!({
                        "token": {
                            "access_token": token_resp.access_token,
                            "scope": token_resp.scope,
                            "token_type": token_resp.token_type
                        },
                        "user_info": user_info,
                        "state": q.state
                    });

                    // GitHub uses user ID as the stable identifier
                    let sub = user_info.get("id")
                        .and_then(|id| id.as_u64())
                        .map(|id| format!("github:{}", id))
                        .unwrap_or_else(|| "unknown".to_string());

                    // Mint local tokens for the GitHub user
                    let scope = Some("openid profile email".to_string());
                    if let Ok(local) = mint_local_tokens_for_subject(&state, sub, scope).await {
                        result["local_tokens"] = serde_json::to_value(local)
                            .unwrap_or_else(|_| serde_json::json!({}));
                    }

                    Json(result).into_response()
                }
                Err(e) => {
                    Json(serde_json::json!({
                        "error": "user_info_failed",
                        "error_description": e.to_string(),
                        "state": q.state
                    })).into_response()
                }
            }
        }
        Err(e) => {
            Json(serde_json::json!({
                "error": "token_exchange_failed",
                "error_description": e.to_string(),
                "state": q.state
            })).into_response()
        }
    }
}

async fn exchange_code_for_token(
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<GitHubTokenResponse, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];

    let response = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("User-Agent", "auth-service/1.0")
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(format!("GitHub token exchange failed: {}", response.status()).into());
    }

    let token_response: GitHubTokenResponse = response.json().await?;
    
    // Check for errors in the response
    if let Some(error) = token_response.error {
        let description = token_response.error_description
            .unwrap_or_else(|| "Unknown error".to_string());
        return Err(format!("GitHub OAuth error: {} - {}", error, description).into());
    }

    Ok(token_response)
}

async fn get_github_user_info(
    access_token: &str,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    
    // Get basic user info
    let user_response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "auth-service/1.0")
        .send()
        .await?;

    if !user_response.status().is_success() {
        return Err(format!("Failed to get GitHub user info: {}", user_response.status()).into());
    }

    let mut user_info: GitHubUser = user_response.json().await?;

    // If email is not public, try to get it from the emails endpoint
    if user_info.email.is_none() {
        if let Ok(email) = get_primary_email(access_token).await {
            user_info.email = Some(email);
        }
    }

    // Convert to JSON value for consistent response format
    let user_json = serde_json::json!({
        "id": user_info.id,
        "login": user_info.login,
        "name": user_info.name,
        "email": user_info.email,
        "avatar_url": user_info.avatar_url,
        "html_url": user_info.html_url
    });

    Ok(user_json)
}

async fn get_primary_email(
    access_token: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::new();
    
    let emails_response = client
        .get("https://api.github.com/user/emails")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "auth-service/1.0")
        .send()
        .await?;

    if !emails_response.status().is_success() {
        return Err(format!("Failed to get GitHub user emails: {}", emails_response.status()).into());
    }

    let emails: Vec<GitHubEmail> = emails_response.json().await?;
    
    // Find primary verified email, fallback to first verified email, then first email
    for email in &emails {
        if email.primary && email.verified {
            return Ok(email.email.clone());
        }
    }
    
    for email in &emails {
        if email.verified {
            return Ok(email.email.clone());
        }
    }
    
    if let Some(first_email) = emails.first() {
        return Ok(first_email.email.clone());
    }
    
    Err("No email found for GitHub user".into())
}