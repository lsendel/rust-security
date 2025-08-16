use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use base64::Engine as _;

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

        // Validate bind address format
        if bind_addr.parse::<std::net::SocketAddr>().is_err() {
            anyhow::bail!("Invalid bind address format: {}", bind_addr);
        }

        let client_credentials = parse_client_credentials(
            raw.client_credentials
                .as_deref()
                .unwrap_or("test_client:test_secret"),
        )?;

        // Validate client credentials
        for (client_id, client_secret) in &client_credentials {
            if client_id.is_empty() || client_secret.is_empty() {
                anyhow::bail!("Client credentials cannot be empty");
            }
            if client_id.len() < 3 || client_secret.len() < 8 {
                anyhow::bail!("Client credentials too short (min 3 chars for ID, 8 for secret)");
            }
        }

        let allowed_scopes: Vec<String> = raw
            .allowed_scopes
            .as_deref()
            .unwrap_or("read,write")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<String>>();

        // Validate scopes
        if allowed_scopes.is_empty() {
            anyhow::bail!("At least one scope must be configured");
        }

        for scope in &allowed_scopes {
            if !scope.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                anyhow::bail!("Invalid scope format: {}", scope);
            }
        }

        let jwt_secret = raw.jwt_secret.unwrap_or_else(generate_default_secret);

        let token_expiry_seconds = raw.token_expiry_seconds.unwrap_or(3600);
        if !(60..=86400).contains(&token_expiry_seconds) {
            anyhow::bail!("Token expiry must be between 60 seconds and 24 hours");
        }

        let rate_limit_requests_per_minute = raw.rate_limit_requests_per_minute.unwrap_or(60);
        if rate_limit_requests_per_minute == 0 || rate_limit_requests_per_minute > 10000 {
            anyhow::bail!("Rate limit must be between 1 and 10000 requests per minute");
        }

        // Validate Redis URL if provided
        if let Some(redis_url) = &raw.redis_url {
            if !redis_url.starts_with("redis://") && !redis_url.starts_with("rediss://") {
                anyhow::bail!("Invalid Redis URL format");
            }
        }

        Ok(AppConfig {
            bind_addr,
            redis_url: raw.redis_url,
            client_credentials,
            allowed_scopes,
            jwt_secret,
            token_expiry_seconds,
            rate_limit_requests_per_minute,
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

    // Check if we're in production environment
    let is_production = env::var("ENVIRONMENT")
        .unwrap_or_else(|_| "development".to_string())
        .to_lowercase() == "production";

    match env::var("JWT_SECRET") {
        Ok(secret) => {
            // Validate secret strength in production
            if is_production {
                if secret.len() < 32 {
                    panic!("JWT_SECRET must be at least 32 characters long in production");
                }
                if secret == "default_jwt_secret_change_in_production"
                    || secret.contains("default")
                    || secret.contains("change") {
                    panic!("Default JWT_SECRET detected in production. Set a strong, unique JWT_SECRET environment variable.");
                }
            }
            secret
        }
        Err(_) => {
            if is_production {
                panic!("JWT_SECRET environment variable is required in production");
            }

            tracing::warn!(
                "Using default JWT secret. Set JWT_SECRET environment variable in production!"
            );

            // Generate a random secret for development
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let random_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            base64::engine::general_purpose::STANDARD.encode(random_bytes)
        }
    }
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
