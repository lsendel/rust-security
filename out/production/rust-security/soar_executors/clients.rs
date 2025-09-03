//! External Service Clients
//!
//! This module provides client implementations for integrating with external
//! security services including firewalls, identity providers, SIEM systems,
//! ticketing systems, and case management platforms.

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

// Configuration structures
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct IdentityProviderConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct SiemConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct TicketingConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct CaseManagerConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub timeout_seconds: u64,
}

// Case details structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseDetails {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: String,
    pub assignee: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Firewall client for IP blocking operations
pub struct FirewallClient {
    client: Client,
    config: FirewallConfig,
}

impl FirewallClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> FirewallConfig {
        FirewallConfig {
            api_endpoint: std::env::var("FIREWALL_API_ENDPOINT")
                .unwrap_or_else(|_| "https://firewall-api.example.com".to_string()),
            api_key: std::env::var("FIREWALL_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("FIREWALL_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn block_ip(
        &self,
        ip_address: &str,
        duration_minutes: u32,
        reason: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "action": "block",
                "ip_address": ip_address,
                "duration_minutes": duration_minutes,
                "reason": reason,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!("{}/rules/block", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let block_id = result["block_id"]
                    .as_str()
                    .unwrap_or(&format!("block_{}", Uuid::new_v4()))
                    .to_string();

                info!(
                    "Successfully blocked IP {} with ID {}",
                    ip_address, block_id
                );
                Ok(block_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Firewall API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Blocking IP {} for {} minutes (reason: {})",
                ip_address, duration_minutes, reason
            );
            tokio::time::sleep(Duration::from_millis(100)).await; // Simulate API call
            Ok(format!("block_{}", Uuid::new_v4()))
        }
    }
}

/// Identity provider client for account management operations
pub struct IdentityProviderClient {
    client: Client,
    config: IdentityProviderConfig,
}

impl IdentityProviderClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> IdentityProviderConfig {
        IdentityProviderConfig {
            api_endpoint: std::env::var("IDENTITY_PROVIDER_API_ENDPOINT")
                .unwrap_or_else(|_| "https://identity-api.example.com".to_string()),
            api_key: std::env::var("IDENTITY_PROVIDER_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("IDENTITY_PROVIDER_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn lock_account(
        &self,
        user_id: &str,
        duration_minutes: u32,
        reason: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "action": "lock",
                "user_id": user_id,
                "duration_minutes": duration_minutes,
                "reason": reason,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!("{}/users/lock", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let lock_id = result["lock_id"]
                    .as_str()
                    .unwrap_or(&format!("lock_{}", Uuid::new_v4()))
                    .to_string();

                info!(
                    "Successfully locked account {} with ID {}",
                    user_id, lock_id
                );
                Ok(lock_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Identity Provider API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Locking account {} for {} minutes (reason: {})",
                user_id, duration_minutes, reason
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(format!("lock_{}", Uuid::new_v4()))
        }
    }
}

/// SIEM client for security information and event management queries
pub struct SiemClient {
    client: Client,
    config: SiemConfig,
}

impl SiemClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> SiemConfig {
        SiemConfig {
            api_endpoint: std::env::var("SIEM_API_ENDPOINT")
                .unwrap_or_else(|_| "https://siem-api.example.com".to_string()),
            api_key: std::env::var("SIEM_API_KEY").unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("SIEM_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60), // SIEM queries might take longer
        }
    }

    pub async fn execute_query(
        &self,
        query: &str,
        time_range: &str,
        max_results: u32,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "query": query,
                "time_range": time_range,
                "max_results": max_results,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!("{}/query", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                info!(
                    "SIEM query executed successfully, {} results returned",
                    result
                        .get("results")
                        .and_then(|r| r.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0)
                );
                Ok(result)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("SIEM API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Executing SIEM query: {} (time_range: {}, max_results: {})",
                query, time_range, max_results
            );
            tokio::time::sleep(Duration::from_millis(500)).await; // Simulate query time

            // Return realistic mock results
            Ok(serde_json::json!([
                {
                    "timestamp": "2024-01-01T00:00:00Z",
                    "source_ip": "192.168.1.100",
                    "event_type": "authentication_failure",
                    "count": 5,
                    "user_agent": "Mozilla/5.0...",
                    "geo_location": "US"
                },
                {
                    "timestamp": "2024-01-01T00:05:00Z",
                    "source_ip": "192.168.1.101",
                    "event_type": "authentication_failure",
                    "count": 3,
                    "user_agent": "curl/7.68.0",
                    "geo_location": "CN"
                }
            ]))
        }
    }
}

/// Ticketing client for creating and managing incident tickets
pub struct TicketingClient {
    client: Client,
    config: TicketingConfig,
}

impl TicketingClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> TicketingConfig {
        TicketingConfig {
            api_endpoint: std::env::var("TICKETING_API_ENDPOINT")
                .unwrap_or_else(|_| "https://ticketing-api.example.com".to_string()),
            api_key: std::env::var("TICKETING_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("TICKETING_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn create_ticket(
        &self,
        title: &str,
        description: &str,
        priority: &str,
        assignee: Option<&str>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "title": title,
                "description": description,
                "priority": priority,
                "assignee": assignee,
                "timestamp": Utc::now().to_rfc3339(),
                "source": "soar_automation"
            });

            let response = self
                .client
                .post(&format!("{}/tickets", self.config.api_endpoint))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let ticket_id = result["ticket_id"]
                    .as_str()
                    .unwrap_or(&format!(
                        "TICKET-{}",
                        Uuid::new_v4()
                            .to_string()
                            .chars()
                            .take(8)
                            .collect::<String>()
                            .to_uppercase()
                    ))
                    .to_string();

                info!(
                    "Successfully created ticket {} with title '{}'",
                    ticket_id, title
                );
                Ok(ticket_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Ticketing API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            info!(
                "Mock: Creating ticket '{}' with priority {} (assignee: {:?})",
                title, priority, assignee
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(format!(
                "TICKET-{}",
                Uuid::new_v4()
                    .to_string()
                    .chars()
                    .take(8)
                    .collect::<String>()
                    .to_uppercase()
            ))
        }
    }
}

/// Case manager client for security case management operations
pub struct CaseManagerClient {
    client: Client,
    config: CaseManagerConfig,
}

impl CaseManagerClient {
    pub fn new() -> Self {
        let config = Self::load_config();
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_seconds))
                .build()
                .unwrap_or_else(|_| Client::new()),
            config,
        }
    }

    fn load_config() -> CaseManagerConfig {
        CaseManagerConfig {
            api_endpoint: std::env::var("CASE_MANAGER_API_ENDPOINT")
                .unwrap_or_else(|_| "https://case-manager-api.example.com".to_string()),
            api_key: std::env::var("CASE_MANAGER_API_KEY")
                .unwrap_or_else(|_| "mock-api-key".to_string()),
            timeout_seconds: std::env::var("CASE_MANAGER_TIMEOUT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30),
        }
    }

    pub async fn get_case_details(
        &self,
        case_id: &str,
    ) -> Result<Option<CaseDetails>, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let response = self
                .client
                .get(&format!("{}/cases/{}", self.config.api_endpoint, case_id))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .send()
                .await?;

            match response.status().as_u16() {
                200 => {
                    let case_details: CaseDetails = response.json().await?;
                    Ok(Some(case_details))
                }
                404 => Ok(None),
                _ => {
                    let error_body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string());
                    Err(format!("Case Manager API error: {}", error_body).into())
                }
            }
        } else {
            // Mock implementation for testing
            tokio::time::sleep(Duration::from_millis(50)).await;
            if case_id.starts_with("NONEXISTENT") {
                Ok(None)
            } else {
                Ok(Some(CaseDetails {
                    id: case_id.to_string(),
                    title: format!("Mock Case {}", case_id),
                    status: "in_progress".to_string(),
                    priority: "medium".to_string(),
                    assignee: Some("analyst@example.com".to_string()),
                    created_at: Utc::now() - chrono::Duration::hours(24),
                    updated_at: Utc::now() - chrono::Duration::minutes(30),
                }))
            }
        }
    }

    pub async fn update_case(
        &self,
        case_id: &str,
        fields: &HashMap<String, Value>,
    ) -> Result<HashMap<String, Value>, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let response = self
                .client
                .patch(&format!("{}/cases/{}", self.config.api_endpoint, case_id))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(fields)
                .send()
                .await?;

            if response.status().is_success() {
                let updated_case: HashMap<String, Value> = response.json().await?;
                info!("Successfully updated case {}", case_id);
                Ok(updated_case)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Case Manager API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            tokio::time::sleep(Duration::from_millis(100)).await;
            let mut updated_case = HashMap::new();
            updated_case.insert("id".to_string(), Value::String(case_id.to_string()));

            // Copy all the updated fields
            for (key, value) in fields {
                updated_case.insert(key.clone(), value.clone());
            }

            updated_case.insert(
                "updated_at".to_string(),
                Value::String(Utc::now().to_rfc3339()),
            );
            info!(
                "Mock: Updated case {} with fields: {:?}",
                case_id,
                fields.keys().collect::<Vec<_>>()
            );
            Ok(updated_case)
        }
    }

    pub async fn add_case_note(
        &self,
        case_id: &str,
        note: &str,
        author: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // If we have a real endpoint, make the API call
        if !self.config.api_endpoint.contains("example.com") {
            let payload = serde_json::json!({
                "note": note,
                "author": author,
                "timestamp": Utc::now().to_rfc3339()
            });

            let response = self
                .client
                .post(&format!(
                    "{}/cases/{}/notes",
                    self.config.api_endpoint, case_id
                ))
                .header("Authorization", &format!("Bearer {}", self.config.api_key))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let result: Value = response.json().await?;
                let note_id = result["note_id"]
                    .as_str()
                    .unwrap_or(&format!("note_{}", Uuid::new_v4()))
                    .to_string();
                Ok(note_id)
            } else {
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());
                Err(format!("Case Manager API error: {}", error_body).into())
            }
        } else {
            // Mock implementation for testing
            tokio::time::sleep(Duration::from_millis(50)).await;
            let note_id = format!("note_{}", Uuid::new_v4());
            info!(
                "Mock: Added note {} to case {} by author {}",
                note_id, case_id, author
            );
            Ok(note_id)
        }
    }
}

// Default implementations
impl Default for FirewallClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for IdentityProviderClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SiemClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TicketingClient {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CaseManagerClient {
    fn default() -> Self {
        Self::new()
    }
}
