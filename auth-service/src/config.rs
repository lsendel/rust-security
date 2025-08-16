use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind_addr: String,
    pub redis_url: Option<String>,
    pub client_credentials: HashMap<String, String>,
    pub allowed_scopes: Vec<String>,
    #[allow(dead_code)]
    pub jwt_secret: String,
    pub token_expiry_seconds: u64,
    pub rate_limit_requests_per_minute: u32,
}

#[derive(Deserialize)]
struct RawConfig {
    bind_addr: Option<String>,
    redis_url: Option<String>,
    client_credentials: Option<String>,
    allowed_scopes: Option<String>,
    jwt_secret: Option<String>,
    token_expiry_seconds: Option<u64>,
    rate_limit_requests_per_minute: Option<u32>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok(); // Load .env file if present

        let raw = envy::from_env::<RawConfig>()
            .context("Failed to parse configuration from environment")?;

        let bind_addr = raw
            .bind_addr
            .unwrap_or_else(|| "127.0.0.1:8080".to_string());

        let client_credentials = parse_client_credentials(
            raw.client_credentials
                .as_deref()
                .unwrap_or("test_client:test_secret"),
        )?;

        let allowed_scopes: Vec<String> = raw
            .allowed_scopes
            .as_deref()
            .unwrap_or("read,write")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();

        let jwt_secret = raw.jwt_secret.unwrap_or_else(generate_default_secret);

        Ok(AppConfig {
            bind_addr,
            redis_url: raw.redis_url,
            client_credentials,
            allowed_scopes,
            jwt_secret,
            token_expiry_seconds: raw.token_expiry_seconds.unwrap_or(3600), // 1 hour default
            rate_limit_requests_per_minute: raw.rate_limit_requests_per_minute.unwrap_or(60),
        })
    }
}

fn parse_client_credentials(creds_str: &str) -> Result<HashMap<String, String>> {
    let mut credentials = HashMap::new();

    for pair in creds_str.split(';') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid client credentials format. Expected 'client_id:client_secret'");
        }
        credentials.insert(parts[0].trim().to_string(), parts[1].trim().to_string());
    }

    Ok(credentials)
}

fn generate_default_secret() -> String {
    use std::env;

    // In production, this should come from a secure source
    env::var("JWT_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            "Using default JWT secret. Set JWT_SECRET environment variable in production!"
        );
        "default_jwt_secret_change_in_production".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_client_credentials() {
        let result = parse_client_credentials("client1:secret1;client2:secret2").unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("client1"));
        assert!(result.contains_key("client2"));
    }

    #[test]
    fn test_parse_invalid_client_credentials() {
        let result = parse_client_credentials("invalid_format");
        assert!(result.is_err());
    }
}
