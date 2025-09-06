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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_api_response_success() {
        let response = ApiResponse::success("test data");

        assert!(response.success);
        assert_eq!(response.data, Some("test data"));
        assert!(response.error.is_none());
        assert!(response.request_id.is_none());
    }

    #[test]
    fn test_api_response_error() {
        let response: ApiResponse<String> = ApiResponse::error("test error");

        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some("test error".to_string()));
        assert!(response.request_id.is_none());
    }

    #[test]
    fn test_api_response_with_request_id() {
        let request_id = Uuid::new_v4();
        let response = ApiResponse::success("data").with_request_id(request_id);

        assert_eq!(response.request_id, Some(request_id));
    }

    #[test]
    fn test_api_response_serialization() {
        let response = ApiResponse::success(42);
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"data\":42"));
    }

    #[test]
    fn test_service_status_serialization() {
        assert_eq!(
            serde_json::to_string(&ServiceStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&ServiceStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&ServiceStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    #[test]
    fn test_alert_severity_ordering() {
        assert!(AlertSeverity::Low < AlertSeverity::Medium);
        assert!(AlertSeverity::Medium < AlertSeverity::High);
        assert!(AlertSeverity::High < AlertSeverity::Critical);
    }

    #[test]
    fn test_alert_severity_equality() {
        assert_eq!(AlertSeverity::High, AlertSeverity::High);
        assert_ne!(AlertSeverity::High, AlertSeverity::Medium);
    }

    #[test]
    fn test_alert_severity_serialization() {
        assert_eq!(
            serde_json::to_string(&AlertSeverity::Low).unwrap(),
            "\"low\""
        );
        assert_eq!(
            serde_json::to_string(&AlertSeverity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn test_health_status_creation() {
        let health = HealthStatus {
            status: ServiceStatus::Healthy,
            version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            uptime_seconds: 3600,
            dependencies: vec![],
        };

        assert_eq!(health.version, "1.0.0");
        assert_eq!(health.uptime_seconds, 3600);
        assert!(health.dependencies.is_empty());
    }

    #[test]
    fn test_dependency_health_creation() {
        let dep = DependencyHealth {
            name: "database".to_string(),
            status: ServiceStatus::Healthy,
            response_time_ms: Some(50),
            last_checked: Utc::now(),
            error: None,
        };

        assert_eq!(dep.name, "database");
        assert_eq!(dep.response_time_ms, Some(50));
        assert!(dep.error.is_none());
    }

    #[test]
    fn test_security_alert_creation() {
        let alert = SecurityAlert {
            id: Uuid::new_v4(),
            alert_type: "login_failure".to_string(),
            severity: AlertSeverity::Medium,
            message: "Failed login attempt".to_string(),
            source_ip: Some("192.168.1.100".to_string()),
            user_id: Some("user123".to_string()),
            timestamp: Utc::now(),
            metadata: json!({"attempts": 3}),
        };

        assert_eq!(alert.alert_type, "login_failure");
        assert_eq!(alert.severity, AlertSeverity::Medium);
        assert_eq!(alert.source_ip, Some("192.168.1.100".to_string()));
        assert!(alert.metadata.get("attempts").is_some());
    }

    #[test]
    fn test_rate_limit_info() {
        let rate_limit = RateLimitInfo {
            limit: 100,
            remaining: 75,
            reset_time: Utc::now(),
            window_seconds: 3600,
        };

        assert_eq!(rate_limit.limit, 100);
        assert_eq!(rate_limit.remaining, 75);
        assert_eq!(rate_limit.window_seconds, 3600);
    }

    #[test]
    fn test_metric_point_creation() {
        let mut tags = std::collections::HashMap::new();
        tags.insert("service".to_string(), "auth".to_string());

        let metric = MetricPoint {
            name: "response_time".to_string(),
            value: 123.45,
            timestamp: Utc::now(),
            tags,
        };

        assert_eq!(metric.name, "response_time");
        assert_eq!(metric.value, 123.45);
        assert!(metric.tags.contains_key("service"));
    }

    #[test]
    fn test_validation_result_valid() {
        let result = ValidationResult {
            valid: true,
            errors: vec![],
            warnings: vec!["deprecated field".to_string()],
        };

        assert!(result.valid);
        assert!(result.errors.is_empty());
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_validation_result_invalid() {
        let result = ValidationResult {
            valid: false,
            errors: vec!["missing required field".to_string()],
            warnings: vec![],
        };

        assert!(!result.valid);
        assert_eq!(result.errors.len(), 1);
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_pagination_info() {
        let pagination = PaginationInfo {
            page: 2,
            per_page: 10,
            total: 100,
            pages: 10,
        };

        assert_eq!(pagination.page, 2);
        assert_eq!(pagination.per_page, 10);
        assert_eq!(pagination.total, 100);
        assert_eq!(pagination.pages, 10);
    }

    #[test]
    fn test_paginated_response() {
        let pagination = PaginationInfo {
            page: 1,
            per_page: 2,
            total: 5,
            pages: 3,
        };

        let response = PaginatedResponse {
            items: vec!["item1", "item2"],
            pagination,
        };

        assert_eq!(response.items.len(), 2);
        assert_eq!(response.pagination.total, 5);
    }

    #[test]
    fn test_scim_user_default() {
        let user = ScimUser::default();

        assert_eq!(user.id, "");
        assert_eq!(user.user_name, "");
        assert!(!user.active);
    }

    #[test]
    fn test_scim_user_creation() {
        let user = ScimUser {
            id: "user123".to_string(),
            user_name: "john.doe".to_string(),
            active: true,
        };

        assert_eq!(user.id, "user123");
        assert_eq!(user.user_name, "john.doe");
        assert!(user.active);
    }

    #[test]
    fn test_scim_user_serialization() {
        let user = ScimUser {
            id: "123".to_string(),
            user_name: "john".to_string(),
            active: true,
        };

        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"userName\":\"john\""));
        assert!(json.contains("\"active\":true"));
    }

    #[test]
    fn test_scim_group_default() {
        let group = ScimGroup::default();

        assert_eq!(group.id, "");
        assert_eq!(group.display_name, "");
        assert!(group.members.is_empty());
    }

    #[test]
    fn test_scim_group_creation() {
        let group = ScimGroup {
            id: "group123".to_string(),
            display_name: "Developers".to_string(),
            members: vec!["user1".to_string(), "user2".to_string()],
        };

        assert_eq!(group.id, "group123");
        assert_eq!(group.display_name, "Developers");
        assert_eq!(group.members.len(), 2);
    }

    #[test]
    fn test_scim_group_serialization() {
        let group = ScimGroup {
            id: "123".to_string(),
            display_name: "Admins".to_string(),
            members: vec![],
        };

        let json = serde_json::to_string(&group).unwrap();
        assert!(json.contains("\"displayName\":\"Admins\""));
    }

    #[test]
    fn test_token_record_default() {
        let token = TokenRecord::default();

        assert!(!token.active);
        assert!(token.scope.is_none());
        assert!(token.client_id.is_none());
        assert!(!token.mfa_verified);
    }

    #[test]
    fn test_token_record_creation() {
        let token = TokenRecord {
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("client123".to_string()),
            exp: Some(1640995200),
            iat: Some(1640991600),
            sub: Some("user123".to_string()),
            token_binding: Some("binding123".to_string()),
            mfa_verified: true,
        };

        assert!(token.active);
        assert_eq!(token.scope, Some("read write".to_string()));
        assert!(token.mfa_verified);
    }

    #[test]
    fn test_auth_code_record() {
        let auth_code = AuthCodeRecord {
            client_id: "client123".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            nonce: Some("nonce123".to_string()),
            scope: "openid profile".to_string(),
            pkce_challenge: Some("challenge123".to_string()),
            pkce_method: Some("S256".to_string()),
            user_id: Some("user123".to_string()),
            exp: 1640995200,
        };

        assert_eq!(auth_code.client_id, "client123");
        assert_eq!(auth_code.scope, "openid profile");
        assert_eq!(auth_code.pkce_method, Some("S256".to_string()));
    }

    #[test]
    fn test_store_metrics_default() {
        let metrics = StoreMetrics::default();

        assert_eq!(metrics.users_total, 0);
        assert_eq!(metrics.groups_total, 0);
        assert_eq!(metrics.tokens_total, 0);
        assert_eq!(metrics.active_tokens, 0);
        assert_eq!(metrics.auth_codes_total, 0);
    }

    #[test]
    fn test_store_metrics_creation() {
        let metrics = StoreMetrics {
            users_total: 100,
            groups_total: 10,
            tokens_total: 500,
            active_tokens: 450,
            auth_codes_total: 50,
        };

        assert_eq!(metrics.users_total, 100);
        assert_eq!(metrics.tokens_total, 500);
        assert_eq!(metrics.active_tokens, 450);
    }

    #[test]
    fn test_types_debug_formatting() {
        let user = ScimUser::default();
        let group = ScimGroup::default();
        let token = TokenRecord::default();
        let metrics = StoreMetrics::default();

        // Test that Debug is implemented correctly
        assert!(!format!("{:?}", user).is_empty());
        assert!(!format!("{:?}", group).is_empty());
        assert!(!format!("{:?}", token).is_empty());
        assert!(!format!("{:?}", metrics).is_empty());
    }

    #[test]
    fn test_types_clone() {
        let user = ScimUser {
            id: "123".to_string(),
            user_name: "test".to_string(),
            active: true,
        };

        let cloned = user.clone();
        assert_eq!(user.id, cloned.id);
        assert_eq!(user.user_name, cloned.user_name);
        assert_eq!(user.active, cloned.active);
    }

    #[test]
    fn test_types_equality() {
        let user1 = ScimUser {
            id: "123".to_string(),
            user_name: "test".to_string(),
            active: true,
        };

        let user2 = ScimUser {
            id: "123".to_string(),
            user_name: "test".to_string(),
            active: true,
        };

        let user3 = ScimUser {
            id: "456".to_string(),
            user_name: "test".to_string(),
            active: true,
        };

        assert_eq!(user1, user2);
        assert_ne!(user1, user3);
    }
}
