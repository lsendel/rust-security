//! Common types and data structures for API contracts

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use validator::{Validate, ValidationError};
use regex;

/// Standard API response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Response data
    pub data: Option<T>,
    /// Response metadata
    pub meta: ResponseMetadata,
    /// Error information if failed
    pub error: Option<ApiErrorDetail>,
}

impl<T> ApiResponse<T> {
    /// Create successful response
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            meta: ResponseMetadata::new(),
            error: None,
        }
    }
    
    /// Create success response with metadata
    pub fn success_with_meta(data: T, meta: ResponseMetadata) -> Self {
        Self {
            data: Some(data),
            meta,
            error: None,
        }
    }
    
    /// Create error response
    pub fn error(error: ApiErrorDetail) -> Self {
        Self {
            data: None,
            meta: ResponseMetadata::new(),
            error: Some(error),
        }
    }
}

/// Response metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    /// Request ID for tracing
    pub request_id: Uuid,
    /// Response timestamp
    pub timestamp: DateTime<Utc>,
    /// Processing time in milliseconds
    pub processing_time_ms: Option<u64>,
    /// API version used
    pub api_version: Option<String>,
    /// Pagination info if applicable
    pub pagination: Option<PaginationMetadata>,
    /// Rate limiting info
    pub rate_limit: Option<RateLimitMetadata>,
}

impl ResponseMetadata {
    pub fn new() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            processing_time_ms: None,
            api_version: None,
            pagination: None,
            rate_limit: None,
        }
    }
    
    pub fn with_request_id(mut self, request_id: Uuid) -> Self {
        self.request_id = request_id;
        self
    }
    
    pub fn with_processing_time(mut self, duration_ms: u64) -> Self {
        self.processing_time_ms = Some(duration_ms);
        self
    }
    
    pub fn with_api_version(mut self, version: String) -> Self {
        self.api_version = Some(version);
        self
    }
}

/// Pagination metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationMetadata {
    /// Current page number (1-based)
    pub page: u32,
    /// Items per page
    pub per_page: u32,
    /// Total number of items
    pub total_items: u64,
    /// Total number of pages
    pub total_pages: u32,
    /// Whether there are more pages
    pub has_next: bool,
    /// Whether there are previous pages
    pub has_previous: bool,
}

impl PaginationMetadata {
    pub fn new(page: u32, per_page: u32, total_items: u64) -> Self {
        let total_pages = ((total_items as f64) / (per_page as f64)).ceil() as u32;
        
        Self {
            page,
            per_page,
            total_items,
            total_pages,
            has_next: page < total_pages,
            has_previous: page > 1,
        }
    }
}

/// Rate limiting metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitMetadata {
    /// Maximum requests per window
    pub limit: u32,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Window reset time
    pub reset_at: DateTime<Utc>,
    /// Retry after seconds (if rate limited)
    pub retry_after: Option<u32>,
}

/// API error detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    /// Error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Additional error details
    pub details: Option<serde_json::Value>,
    /// Field-specific validation errors
    pub field_errors: Option<HashMap<String, Vec<String>>>,
    /// Help URL or documentation link
    pub help_url: Option<String>,
}

impl ApiErrorDetail {
    pub fn new(code: String, message: String) -> Self {
        Self {
            code,
            message,
            details: None,
            field_errors: None,
            help_url: None,
        }
    }
    
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
    
    pub fn with_field_errors(mut self, field_errors: HashMap<String, Vec<String>>) -> Self {
        self.field_errors = Some(field_errors);
        self
    }
    
    pub fn with_help_url(mut self, help_url: String) -> Self {
        self.help_url = Some(help_url);
        self
    }
}

/// Pagination request parameters
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PaginationRequest {
    /// Page number (1-based)
    #[validate(range(min = 1, max = 10000))]
    pub page: Option<u32>,
    
    /// Items per page
    #[validate(range(min = 1, max = 1000))]
    pub per_page: Option<u32>,
    
    /// Sort field
    #[validate(length(min = 1, max = 100))]
    pub sort_by: Option<String>,
    
    /// Sort direction
    pub sort_order: Option<SortOrder>,
}

impl Default for PaginationRequest {
    fn default() -> Self {
        Self {
            page: Some(1),
            per_page: Some(20),
            sort_by: None,
            sort_order: Some(SortOrder::Asc),
        }
    }
}

impl PaginationRequest {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1)
    }
    
    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(20)
    }
    
    pub fn offset(&self) -> u32 {
        (self.page() - 1) * self.per_page()
    }
}

/// Sort order enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    Asc,
    Desc,
}

/// Standard filter operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", content = "value")]
pub enum FilterOperation {
    /// Equals
    Eq(serde_json::Value),
    /// Not equals
    Ne(serde_json::Value),
    /// Greater than
    Gt(serde_json::Value),
    /// Greater than or equal
    Gte(serde_json::Value),
    /// Less than
    Lt(serde_json::Value),
    /// Less than or equal
    Lte(serde_json::Value),
    /// In list
    In(Vec<serde_json::Value>),
    /// Not in list
    NotIn(Vec<serde_json::Value>),
    /// Contains (for strings)
    Contains(String),
    /// Starts with (for strings)
    StartsWith(String),
    /// Ends with (for strings)
    EndsWith(String),
    /// Is null
    IsNull,
    /// Is not null
    IsNotNull,
    /// Between two values
    Between(serde_json::Value, serde_json::Value),
}

/// Generic filter for API endpoints
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ApiFilter {
    /// Field to filter on
    #[validate(length(min = 1, max = 100))]
    pub field: String,
    
    /// Filter operation
    pub operation: FilterOperation,
}

/// Search request with filtering and pagination
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct SearchRequest {
    /// Search query
    #[validate(length(max = 1000))]
    pub query: Option<String>,
    
    /// Filters to apply
    #[validate(length(max = 10))]
    pub filters: Vec<ApiFilter>,
    
    /// Pagination parameters
    #[validate(nested)]
    pub pagination: PaginationRequest,
}

/// Health check request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckRequest {
    /// Include dependency checks
    pub include_dependencies: Option<bool>,
    
    /// Include detailed metrics
    pub include_metrics: Option<bool>,
}

/// Batch operation request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct BatchRequest<T: Serialize> {
    /// Items to process
    #[validate(length(min = 1, max = 100))]
    pub items: Vec<T>,
    
    /// Whether to fail entire batch on first error
    pub fail_fast: Option<bool>,
    
    /// Batch operation timeout in seconds
    #[validate(range(min = 1, max = 300))]
    pub timeout_seconds: Option<u32>,
}

/// Batch operation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse<T, E> {
    /// Successful results
    pub success: Vec<BatchResult<T>>,
    
    /// Failed results
    pub errors: Vec<BatchError<E>>,
    
    /// Summary statistics
    pub summary: BatchSummary,
}

/// Individual batch result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult<T> {
    /// Index in original batch
    pub index: usize,
    
    /// Result data
    pub data: T,
}

/// Individual batch error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchError<E> {
    /// Index in original batch
    pub index: usize,
    
    /// Error information
    pub error: E,
}

/// Batch operation summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Total items processed
    pub total: usize,
    
    /// Number of successful operations
    pub success_count: usize,
    
    /// Number of failed operations
    pub error_count: usize,
    
    /// Processing time in milliseconds
    pub processing_time_ms: u64,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique entry ID
    pub id: Uuid,
    
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    
    /// User who performed the action
    pub user_id: Option<Uuid>,
    
    /// Service that logged the event
    pub service: String,
    
    /// Action performed
    pub action: String,
    
    /// Resource affected
    pub resource: Option<String>,
    
    /// Resource ID
    pub resource_id: Option<String>,
    
    /// Event outcome
    pub outcome: AuditOutcome,
    
    /// Additional event data
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Client IP address
    pub client_ip: Option<String>,
    
    /// User agent
    pub user_agent: Option<String>,
    
    /// Request ID for correlation
    pub request_id: Uuid,
}

/// Audit event outcome
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Failure,
    Partial,
}

/// Input validation utilities
pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .map_err(|_| ValidationError::new("invalid_regex"))?;
    
    if email_regex.is_match(email) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_email"))
    }
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    let username_regex = regex::Regex::new(r"^[a-zA-Z0-9_-]{3,50}$")
        .map_err(|_| ValidationError::new("invalid_regex"))?;
    
    if username_regex.is_match(username) {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_username"))
    }
}

pub fn validate_uuid(uuid_str: &str) -> Result<(), ValidationError> {
    Uuid::parse_str(uuid_str)
        .map(|_| ())
        .map_err(|_| ValidationError::new("invalid_uuid"))
}

/// Common HTTP status codes for API responses
pub mod status_codes {
    pub const OK: u16 = 200;
    pub const CREATED: u16 = 201;
    pub const ACCEPTED: u16 = 202;
    pub const NO_CONTENT: u16 = 204;
    pub const BAD_REQUEST: u16 = 400;
    pub const UNAUTHORIZED: u16 = 401;
    pub const FORBIDDEN: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const METHOD_NOT_ALLOWED: u16 = 405;
    pub const CONFLICT: u16 = 409;
    pub const UNPROCESSABLE_ENTITY: u16 = 422;
    pub const TOO_MANY_REQUESTS: u16 = 429;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response() {
        let response = ApiResponse::success("test data");
        assert!(response.data.is_some());
        assert!(response.error.is_none());
        
        let error_response = ApiResponse::<String>::error(
            ApiErrorDetail::new("TEST_ERROR".to_string(), "Test error message".to_string())
        );
        assert!(error_response.data.is_none());
        assert!(error_response.error.is_some());
    }

    #[test]
    fn test_pagination_metadata() {
        let pagination = PaginationMetadata::new(2, 10, 25);
        assert_eq!(pagination.page, 2);
        assert_eq!(pagination.total_pages, 3);
        assert!(pagination.has_previous);
        assert!(pagination.has_next);
        
        let last_page = PaginationMetadata::new(3, 10, 25);
        assert!(!last_page.has_next);
        assert!(last_page.has_previous);
    }

    #[test]
    fn test_pagination_request() {
        let request = PaginationRequest::default();
        assert_eq!(request.page(), 1);
        assert_eq!(request.per_page(), 20);
        assert_eq!(request.offset(), 0);
        
        let request2 = PaginationRequest {
            page: Some(3),
            per_page: Some(15),
            ..Default::default()
        };
        assert_eq!(request2.offset(), 30);
    }

    #[test]
    fn test_email_validation() {
        assert!(validate_email("test@example.com").is_ok());
        assert!(validate_email("invalid-email").is_err());
        assert!(validate_email("@example.com").is_err());
    }

    #[test]
    fn test_username_validation() {
        assert!(validate_username("valid_user123").is_ok());
        assert!(validate_username("ab").is_err()); // too short
        assert!(validate_username("invalid user").is_err()); // contains space
    }

    #[test]
    fn test_batch_request_validation() {
        let batch = BatchRequest {
            items: vec!["item1".to_string(), "item2".to_string()],
            fail_fast: Some(true),
            timeout_seconds: Some(60),
        };
        
        assert_eq!(batch.items.len(), 2);
        assert_eq!(batch.fail_fast, Some(true));
    }
}