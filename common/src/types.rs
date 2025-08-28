//! Common types used across services

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Standard response wrapper for API endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub request_id: Option<Uuid>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: Utc::now(),
            request_id: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
            timestamp: Utc::now(),
            request_id: None,
        }
    }

    #[must_use]
    pub const fn with_request_id(mut self, request_id: Uuid) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: ServiceStatus,
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub uptime_seconds: u64,
    pub dependencies: Vec<DependencyHealth>,
}

/// Service status enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Dependency health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    pub name: String,
    pub status: ServiceStatus,
    pub response_time_ms: Option<u64>,
    pub last_checked: DateTime<Utc>,
    pub error: Option<String>,
}

/// Security alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security alert information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub id: Uuid,
    pub alert_type: String,
    pub severity: AlertSeverity,
    pub message: String,
    pub source_ip: Option<String>,
    pub user_id: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub limit: u64,
    pub remaining: u64,
    pub reset_time: DateTime<Utc>,
    pub window_seconds: u64,
}

/// Metrics collection point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
    pub tags: std::collections::HashMap<String, String>,
}

/// Configuration validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Service configuration trait
pub trait ServiceConfig {
    fn validate(&self) -> ValidationResult;
}

/// Pagination information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total: u64,
    pub pages: u32,
}

/// Paginated response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub pagination: PaginationInfo,
}

// === SCIM Data Models ===

/// Represents a SCIM User.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ScimUser {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub active: bool,
}

/// Represents a SCIM Group.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ScimGroup {
    #[serde(default)]
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub members: Vec<String>,
}

// === Store Data Models ===

/// Represents the data stored for an access or refresh token.
/// Based on the `IntrospectionRecord` from `auth-service`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenRecord {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
    pub token_binding: Option<String>,
    pub mfa_verified: bool,
}

/// Represents the data stored for an authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeRecord {
    pub client_id: String,
    pub redirect_uri: String,
    pub nonce: Option<String>,
    pub scope: String,
    pub pkce_challenge: Option<String>,
    pub pkce_method: Option<String>,
    pub user_id: Option<String>,
    pub exp: i64,
}

/// Represents a collection of metrics for a `Store` implementation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoreMetrics {
    pub users_total: u64,
    pub groups_total: u64,
    pub tokens_total: u64,
    pub active_tokens: u64,
    pub auth_codes_total: u64,
}
