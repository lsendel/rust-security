//! Session Entity
//!
//! Represents a user session in the authentication system.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::value_objects::UserId;

/// Session entity representing a user authentication session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,

    /// User ID this session belongs to
    pub user_id: UserId,

    /// Session creation timestamp
    pub created_at: DateTime<Utc>,

    /// Session expiration timestamp
    pub expires_at: DateTime<Utc>,

    /// IP address of the client that created the session
    pub ip_address: Option<String>,

    /// User agent string from the client
    pub user_agent: Option<String>,

    /// Whether the session is active
    pub is_active: bool,

    /// Device fingerprint for additional security
    pub device_fingerprint: Option<String>,
}

impl Session {
    /// Create a new session for a user
    #[must_use]
    pub fn new(user_id: UserId, created_at: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            created_at,
            expires_at: created_at + Duration::hours(24), // 24 hour sessions
            ip_address: None,
            user_agent: None,
            is_active: true,
            device_fingerprint: None,
        }
    }

    /// Create a session with custom expiration
    #[must_use]
    pub fn with_expiration(
        user_id: UserId,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            created_at,
            expires_at,
            ip_address: None,
            user_agent: None,
            is_active: true,
            device_fingerprint: None,
        }
    }

    /// Set the IP address for this session
    #[must_use]
    pub fn with_ip_address(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Set the user agent for this session
    #[must_use]
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Set the device fingerprint for this session
    #[must_use]
    pub fn with_device_fingerprint(mut self, fingerprint: String) -> Self {
        self.device_fingerprint = Some(fingerprint);
        self
    }

    /// Check if the session is expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.is_active && !self.is_expired()
    }

    /// Deactivate the session
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }

    /// Extend the session expiration
    pub fn extend(&mut self, duration: Duration) {
        // Extend from the current expiration time, not from now
        // This ensures the session is always extended, even if called immediately after creation
        self.expires_at += duration;
    }

    /// Get the time remaining until expiration
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        if self.is_expired() {
            Duration::zero()
        } else {
            self.expires_at - Utc::now()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::UserId;
    use chrono::Duration;

    #[test]
    fn test_session_creation() {
        let user_id = UserId::new();
        let created_at = Utc::now();
        let session = Session::new(user_id.clone(), created_at);

        assert_eq!(session.user_id, user_id);
        assert_eq!(session.created_at, created_at);
        assert!(session.is_active);
        assert!(!session.is_expired());
        assert!(session.time_remaining() > Duration::zero());
    }

    #[test]
    fn test_session_with_custom_expiration() {
        let user_id = UserId::new();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::hours(1);
        let session = Session::with_expiration(user_id, created_at, expires_at);

        assert_eq!(session.expires_at, expires_at);
    }

    #[test]
    fn test_session_metadata() {
        let user_id = UserId::new();
        let session = Session::new(user_id, Utc::now())
            .with_ip_address("192.168.1.1".to_string())
            .with_user_agent("Mozilla/5.0".to_string())
            .with_device_fingerprint("abc123".to_string());

        assert_eq!(session.ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(session.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(session.device_fingerprint, Some("abc123".to_string()));
    }

    #[test]
    fn test_session_deactivation() {
        let user_id = UserId::new();
        let mut session = Session::new(user_id, Utc::now());

        assert!(session.is_active());
        session.deactivate();
        assert!(!session.is_active);
    }

    #[test]
    fn test_session_extension() {
        let user_id = UserId::new();
        let mut session = Session::new(user_id, Utc::now());
        let original_expires = session.expires_at;

        session.extend(Duration::hours(2));

        assert!(session.expires_at > original_expires);
    }
}
