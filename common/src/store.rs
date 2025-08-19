//! Defines the generic `Store` trait for data persistence.

use crate::types::{AuthCodeRecord, ScimGroup, ScimUser, TokenRecord};
use async_trait::async_trait;
use std::error::Error;

/// A generic trait for a pluggable storage backend.
///
/// This trait defines a comprehensive interface for all data persistence
/// operations required by the `auth-service`, including management of
/// users, groups, tokens, and authorization codes.
#[async_trait]
pub trait Store: Send + Sync {
    // === User Management (SCIM) ===
    async fn get_user(&self, id: &str) -> Result<Option<ScimUser>, Box<dyn Error + Send + Sync>>;
    async fn create_user(&self, user: &ScimUser) -> Result<ScimUser, Box<dyn Error + Send + Sync>>;
    async fn list_users(&self, filter: Option<&str>) -> Result<Vec<ScimUser>, Box<dyn Error + Send + Sync>>;
    async fn update_user(&self, user: &ScimUser) -> Result<ScimUser, Box<dyn Error + Send + Sync>>;
    async fn delete_user(&self, id: &str) -> Result<(), Box<dyn Error + Send + Sync>>;

    // === Group Management (SCIM) ===
    async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>, Box<dyn Error + Send + Sync>>;
    async fn create_group(&self, group: &ScimGroup) -> Result<ScimGroup, Box<dyn Error + Send + Sync>>;
    async fn list_groups(&self, filter: Option<&str>) -> Result<Vec<ScimGroup>, Box<dyn Error + Send + Sync>>;
    async fn update_group(&self, group: &ScimGroup) -> Result<ScimGroup, Box<dyn Error + Send + Sync>>;
    async fn delete_group(&self, id: &str) -> Result<(), Box<dyn Error + Send + Sync>>;

    // === Auth Code Management ===
    async fn set_auth_code(&self, code: &str, record: &AuthCodeRecord, ttl_secs: u64) -> Result<(), Box<dyn Error + Send + Sync>>;
    async fn consume_auth_code(&self, code: &str) -> Result<Option<AuthCodeRecord>, Box<dyn Error + Send + Sync>>;

    // === Token Management ===
    async fn get_token_record(&self, token: &str) -> Result<Option<TokenRecord>, Box<dyn Error + Send + Sync>>;
    async fn set_token_record(&self, token: &str, record: &TokenRecord, ttl_secs: Option<u64>) -> Result<(), Box<dyn Error + Send + Sync>>;
    async fn revoke_token(&self, token: &str) -> Result<(), Box<dyn Error + Send + Sync>>;

    // === Refresh Token Management ===
    async fn set_refresh_token_association(&self, refresh_token: &str, access_token: &str, ttl_secs: u64) -> Result<(), Box<dyn Error + Send + Sync>>;
    async fn consume_refresh_token(&self, refresh_token: &str) -> Result<Option<String>, Box<dyn Error + Send + Sync>>;
    async fn is_refresh_reused(&self, refresh_token: &str) -> Result<bool, Box<dyn Error + Send + Sync>>;

    // === Health Check ===
    async fn health_check(&self) -> Result<bool, Box<dyn Error + Send + Sync>>;

    // Metrics
    async fn get_metrics(&self) -> Result<crate::types::StoreMetrics, Box<dyn Error + Send + Sync>>;
}
