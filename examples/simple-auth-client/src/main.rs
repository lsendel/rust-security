//! Simple authentication client example
//! 
//! This example demonstrates how to authenticate with the auth-service
//! and make authorized requests.
//!
//! Run with: cargo run --example simple_auth_client

use anyhow::{Context, Result};
use common::{ApiResponse, CommonError};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio;

#[derive(Debug, Serialize)]
struct AuthRequest {
    client_id: String,
    client_secret: String,
    grant_type: String,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::init();

    let client = Client::new();
    let auth_service_url = std::env::var("AUTH_SERVICE_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());

    println!("🔐 Auth Service Client Example");
    println!("Connecting to: {}", auth_service_url);

    // Health check
    let health_url = format!("{}/health", auth_service_url);
    match client.get(&health_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                println!("✅ Auth service is healthy");
            } else {
                println!("⚠️  Auth service returned: {}", response.status());
            }
        }
        Err(e) => {
            println!("❌ Failed to connect to auth service: {}", e);
            println!("Make sure the auth service is running at {}", auth_service_url);
            return Ok(());
        }
    }

    // Get token endpoint information
    let token_url = format!("{}/token", auth_service_url);
    println!("\\n🎫 Requesting access token...");

    let auth_request = AuthRequest {
        client_id: "demo-client".to_string(),
        client_secret: "demo-secret".to_string(),
        grant_type: "client_credentials".to_string(),
    };

    let response = client
        .post(&token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .form(&[
            ("client_id", &auth_request.client_id),
            ("client_secret", &auth_request.client_secret),
            ("grant_type", &auth_request.grant_type),
        ])
        .send()
        .await
        .context("Failed to send token request")?;

    if !response.status().is_success() {
        println!("❌ Token request failed: {}", response.status());
        let error_text = response.text().await.unwrap_or_default();
        println!("Error details: {}", error_text);
        return Ok(());
    }

    let auth_response: AuthResponse = response
        .json()
        .await
        .context("Failed to parse token response")?;

    println!("✅ Successfully obtained access token");
    println!("Token type: {}", auth_response.token_type);
    println!("Expires in: {} seconds", auth_response.expires_in);

    // Test introspection endpoint
    println!("\\n🔍 Testing token introspection...");
    let introspect_url = format!("{}/introspect", auth_service_url);
    
    let mut introspect_params = HashMap::new();
    introspect_params.insert("token", auth_response.access_token.clone());

    let introspect_response = client
        .post(&introspect_url)
        .header("authorization", format!("Bearer {}", auth_response.access_token))
        .form(&introspect_params)
        .send()
        .await
        .context("Failed to introspect token")?;

    if introspect_response.status().is_success() {
        println!("✅ Token introspection successful");
        let introspect_data: serde_json::Value = introspect_response.json().await?;
        println!("Token is active: {}", introspect_data.get("active").unwrap_or(&serde_json::Value::Bool(false)));
    } else {
        println!("❌ Token introspection failed: {}", introspect_response.status());
    }

    println!("\\n🎉 Example completed successfully!");
    Ok(())
}