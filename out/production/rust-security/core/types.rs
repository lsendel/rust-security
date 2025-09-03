//! Core type definitions and shared data structures
//!
//! This module contains common types and data structures used throughout
//! the authentication service for consistency and type safety.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

/// Unique identifier type for various entities
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Id(String);

impl Id {
    /// Create a new ID from a string
    #[must_use]
    pub const fn new(id: String) -> Self {
        Self(id)
    }

    /// Generate a new random ID
    #[must_use]
    pub fn generate() -> Self {
        use uuid::Uuid;
        Self(Uuid::new_v4().to_string())
    }

    /// Get the string representation
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to string
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Id {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Id {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

/// User identifier
pub type UserId = Id;

/// Session identifier
pub type SessionId = Id;

/// Token identifier
pub type TokenId = Id;

/// Request identifier
pub type RequestId = Id;

/// User information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: UserId,
    /// Username
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// User roles
    pub roles: Vec<String>,
    /// User groups
    pub groups: Vec<String>,
    /// User attributes
    pub attributes: HashMap<String, String>,
    /// Account status
    pub status: AccountStatus,
    /// Account creation time
    pub created_at: SystemTime,
    /// Last login time
    pub last_login: Option<SystemTime>,
    /// Password last changed
    pub password_changed_at: Option<SystemTime>,
    /// Account locked until
    pub locked_until: Option<SystemTime>,
}

impl User {
    /// Create a new user
    #[must_use]
    pub fn new(username: String, email: Option<String>) -> Self {
        Self {
            id: UserId::generate(),
            username,
            email,
            display_name: None,
            roles: Vec::new(),
            groups: Vec::new(),
            attributes: HashMap::new(),
            status: AccountStatus::Active,
            created_at: SystemTime::now(),
            last_login: None,
            password_changed_at: None,
            locked_until: None,
        }
    }

    /// Check if user has a specific role
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// Check if user is in a specific group
    #[must_use]
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.contains(&group.to_string())
    }

    /// Check if account is locked
    #[must_use]
    pub fn is_locked(&self) -> bool {
        matches!(self.status, AccountStatus::Locked)
            || self
                .locked_until
                .is_some_and(|until| SystemTime::now() < until)
    }

    /// Check if account is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, AccountStatus::Active) && !self.is_locked()
    }
}

/// Account status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    /// Account is active
    Active,
    /// Account is temporarily locked
    Locked,
    /// Account is disabled
    Disabled,
    /// Account is pending activation
    Pending,
    /// Account is suspended
    Suspended,
}

impl fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Locked => write!(f, "locked"),
            Self::Disabled => write!(f, "disabled"),
            Self::Pending => write!(f, "pending"),
            Self::Suspended => write!(f, "suspended"),
        }
    }
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub id: SessionId,
    /// User ID associated with this session
    pub user_id: UserId,
    /// Session creation time
    pub created_at: SystemTime,
    /// Session last accessed time
    pub last_accessed: SystemTime,
    /// Session expiration time
    pub expires_at: SystemTime,
    /// Client IP address
    pub client_ip: String,
    /// User agent string
    pub user_agent: String,
    /// Session attributes
    pub attributes: HashMap<String, String>,
    /// Session status
    pub status: SessionStatus,
}

impl Session {
    /// Create a new session
    #[must_use]
    pub fn new(user_id: UserId, client_ip: String, user_agent: String, duration: Duration) -> Self {
        let now = SystemTime::now();
        Self {
            id: SessionId::generate(),
            user_id,
            created_at: now,
            last_accessed: now,
            expires_at: now + duration,
            client_ip,
            user_agent,
            attributes: HashMap::new(),
            status: SessionStatus::Active,
        }
    }

    /// Check if session is expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Check if session is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, SessionStatus::Active) && !self.is_expired()
    }

    /// Update last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = SystemTime::now();
    }

    /// Extend session expiration
    pub fn extend(&mut self, additional_duration: Duration) {
        self.expires_at += additional_duration;
    }
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session is active
    Active,
    /// Session is terminated
    Terminated,
    /// Session is expired
    Expired,
    /// Session is invalidated
    Invalidated,
}

/// Permission structure for authorization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permission {
    /// Permission resource
    pub resource: String,
    /// Permission action
    pub action: String,
    /// Optional conditions
    pub conditions: Option<HashMap<String, String>>,
}

impl Permission {
    /// Create a new permission
    #[must_use]
    pub const fn new(resource: String, action: String) -> Self {
        Self {
            resource,
            action,
            conditions: None,
        }
    }

    /// Create a permission with conditions
    #[must_use]
    pub const fn with_conditions(
        resource: String,
        action: String,
        conditions: HashMap<String, String>,
    ) -> Self {
        Self {
            resource,
            action,
            conditions: Some(conditions),
        }
    }

    /// Check if this permission matches another permission
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.resource == other.resource && self.action == other.action
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

/// Role definition containing permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Role name
    pub name: String,
    /// Role description
    pub description: Option<String>,
    /// Permissions granted by this role
    pub permissions: Vec<Permission>,
    /// Role attributes
    pub attributes: HashMap<String, String>,
    /// Role creation time
    pub created_at: SystemTime,
}

impl Role {
    /// Create a new role
    #[must_use]
    pub fn new(name: String, permissions: Vec<Permission>) -> Self {
        Self {
            name,
            description: None,
            permissions,
            attributes: HashMap::new(),
            created_at: SystemTime::now(),
        }
    }

    /// Check if role has a specific permission
    #[must_use]
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.iter().any(|p| p.matches(permission))
    }
}

/// Request metadata for tracking and auditing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Request ID
    pub id: RequestId,
    /// Request timestamp
    pub timestamp: SystemTime,
    /// Request method
    pub method: String,
    /// Request path
    pub path: String,
    /// Request query parameters
    pub query_params: HashMap<String, String>,
    /// Request headers (filtered for security)
    pub headers: HashMap<String, String>,
    /// Client IP address
    pub client_ip: String,
    /// User agent
    pub user_agent: String,
    /// Request body size
    pub body_size: usize,
    /// Response status code
    pub response_status: Option<u16>,
    /// Response size
    pub response_size: Option<usize>,
    /// Request processing duration
    pub duration: Option<Duration>,
}

impl RequestMetadata {
    /// Create new request metadata
    #[must_use]
    pub fn new(method: String, path: String, client_ip: String, user_agent: String) -> Self {
        Self {
            id: RequestId::generate(),
            timestamp: SystemTime::now(),
            method,
            path,
            query_params: HashMap::new(),
            headers: HashMap::new(),
            client_ip,
            user_agent,
            body_size: 0,
            response_status: None,
            response_size: None,
            duration: None,
        }
    }

    /// Mark request as completed
    pub fn complete(&mut self, status: u16, response_size: usize) {
        self.response_status = Some(status);
        self.response_size = Some(response_size);
        self.duration = Some(self.timestamp.elapsed().unwrap_or_default());
    }
}

/// Configuration for various timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Authentication timeout
    pub auth_timeout: Duration,
    /// Session timeout
    pub session_timeout: Duration,
    /// Token lifetime
    pub token_lifetime: Duration,
    /// Refresh token lifetime
    pub refresh_token_lifetime: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            auth_timeout: Duration::from_secs(30),
            session_timeout: Duration::from_secs(3600), // 1 hour
            token_lifetime: Duration::from_secs(900),   // 15 minutes
            refresh_token_lifetime: Duration::from_secs(86400), // 24 hours
            request_timeout: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
        }
    }
}

/// Pagination information for list operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    /// Current page number (0-based)
    pub page: usize,
    /// Number of items per page
    pub limit: usize,
    /// Total number of items
    pub total: Option<usize>,
    /// Whether there are more pages
    pub has_more: bool,
}

impl Pagination {
    /// Create new pagination
    #[must_use]
    pub const fn new(page: usize, limit: usize) -> Self {
        Self {
            page,
            limit,
            total: None,
            has_more: false,
        }
    }

    /// Calculate offset for database queries
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.page * self.limit
    }

    /// Set total count and update `has_more`
    pub fn set_total(&mut self, total: usize) {
        self.total = Some(total);
        self.has_more = (self.page + 1) * self.limit < total;
    }
}

/// Audit log entry for tracking important events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID
    pub id: Id,
    /// Timestamp
    pub timestamp: SystemTime,
    /// User who performed the action (if applicable)
    pub user_id: Option<UserId>,
    /// Action performed
    pub action: String,
    /// Resource affected
    pub resource: String,
    /// Additional details
    pub details: HashMap<String, String>,
    /// Request metadata
    pub request_metadata: Option<RequestMetadata>,
    /// Result of the action
    pub result: AuditResult,
}

/// Result of an audited action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure { reason: String },
    PartialSuccess { warnings: Vec<String> },
}

impl AuditEntry {
    /// Create a new audit entry
    #[must_use]
    pub fn new(
        user_id: Option<UserId>,
        action: String,
        resource: String,
        result: AuditResult,
    ) -> Self {
        Self {
            id: Id::generate(),
            timestamp: SystemTime::now(),
            user_id,
            action,
            resource,
            details: HashMap::new(),
            request_metadata: None,
            result,
        }
    }

    /// Add additional detail
    pub fn add_detail(&mut self, key: String, value: String) {
        self.details.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation() {
        let id1 = Id::generate();
        let id2 = Id::generate();
        assert_ne!(id1, id2);
        assert!(!id1.as_str().is_empty());
    }

    #[test]
    fn test_user_creation() {
        let user = User::new("testuser".to_string(), Some("test@example.com".to_string()));
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, Some("test@example.com".to_string()));
        assert!(user.is_active());
        assert!(!user.is_locked());
    }

    #[test]
    fn test_session_creation() {
        let user_id = UserId::generate();
        let session = Session::new(
            user_id.clone(),
            "192.168.1.1".to_string(),
            "Test Agent".to_string(),
            Duration::from_secs(3600),
        );

        assert_eq!(session.user_id, user_id);
        assert!(session.is_active());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_permission_matching() {
        let perm1 = Permission::new("users".to_string(), "read".to_string());
        let perm2 = Permission::new("users".to_string(), "read".to_string());
        let perm3 = Permission::new("users".to_string(), "write".to_string());

        assert!(perm1.matches(&perm2));
        assert!(!perm1.matches(&perm3));
    }

    #[test]
    fn test_role_permissions() {
        let permissions = vec![
            Permission::new("users".to_string(), "read".to_string()),
            Permission::new("users".to_string(), "write".to_string()),
        ];
        let role = Role::new("admin".to_string(), permissions);

        assert!(role.has_permission(&Permission::new("users".to_string(), "read".to_string())));
        assert!(!role.has_permission(&Permission::new("posts".to_string(), "read".to_string())));
    }

    #[test]
    fn test_pagination() {
        let mut pagination = Pagination::new(0, 10);
        assert_eq!(pagination.offset(), 0);
        assert!(!pagination.has_more);

        pagination.set_total(25);
        assert!(pagination.has_more);
        assert_eq!(pagination.total, Some(25));
    }

    #[test]
    fn test_audit_entry() {
        let user_id = UserId::generate();
        let mut entry = AuditEntry::new(
            Some(user_id),
            "login".to_string(),
            "user_session".to_string(),
            AuditResult::Success,
        );

        entry.add_detail("ip".to_string(), "192.168.1.1".to_string());
        assert_eq!(entry.details.get("ip"), Some(&"192.168.1.1".to_string()));
    }
}
