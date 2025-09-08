// Secure session management with Redis backend and security features
#[cfg(feature = "monitoring")]
use crate::infrastructure::monitoring::security_metrics::SECURITY_METRICS;
use crate::infrastructure::security::security_logging::{
    SecurityEvent, SecurityEventType, SecurityLogger, SecurityLoggerConfig, SecuritySeverity,
};
use crate::pii_protection::redact_log;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

// Performance constants
const DEFAULT_SESSION_CAPACITY: usize = 16;
const SESSION_KEY_PREFIX: &str = "session:";
const USER_SESSIONS_PREFIX: &str = "user_sessions:";

// Helper functions for key generation
#[inline]
fn session_key(session_id: &str) -> String {
    format!("{SESSION_KEY_PREFIX}{session_id}")
}

#[inline]
fn user_sessions_key(user_id: &str) -> String {
    format!("{USER_SESSIONS_PREFIX}{user_id}")
}

/// Session configuration
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Default session duration (seconds)
    pub default_duration: u64,
    /// Maximum session duration (seconds)
    pub max_duration: u64,
    /// Session inactivity timeout (seconds)
    pub inactivity_timeout: u64,
    /// Whether to regenerate session ID on privilege escalation
    pub regenerate_on_privilege_change: bool,
    /// Maximum number of concurrent sessions per user
    pub max_concurrent_sessions: u32,
    /// Cookie settings for session cookies
    pub cookie_config: SessionCookieConfig,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_duration: 24 * 60 * 60, // 24 hours
            max_duration: 7 * 24 * 60 * 60, // 7 days
            inactivity_timeout: 30 * 60,    // 30 minutes
            regenerate_on_privilege_change: true,
            max_concurrent_sessions: 5,
            cookie_config: SessionCookieConfig::default(),
        }
    }
}

/// Session cookie configuration
#[derive(Debug, Clone)]
pub struct SessionCookieConfig {
    pub name: String,
    pub domain: Option<String>,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
}

impl Default for SessionCookieConfig {
    fn default() -> Self {
        Self {
            name: "auth_session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Strict,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// Session data structure
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub client_id: Option<String>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub created_at: u64,
    pub last_accessed: u64,
    pub expires_at: u64,
    pub mfa_verified: bool,
    pub mfa_verified_at: Option<u64>,
    pub is_elevated: bool, // For privilege escalation
    pub attributes: HashMap<String, serde_json::Value>,
    pub csrf_token: String,
}

impl Session {
    #[must_use]
    pub fn new(
        user_id: String,
        client_id: Option<String>,
        ip_address: String,
        user_agent: Option<String>,
        duration: u64,
    ) -> Self {
        let now = current_timestamp();
        let session_id = generate_session_id();
        let csrf_token = generate_csrf_token();

        Self {
            id: session_id,
            user_id,
            client_id,
            ip_address,
            user_agent,
            created_at: now,
            last_accessed: now,
            expires_at: now + duration,
            mfa_verified: false,
            mfa_verified_at: None,
            is_elevated: false,
            attributes: HashMap::with_capacity(4), // Common attributes count
            csrf_token,
        }
    }

    pub fn is_expired(&self, now: Option<u64>) -> bool {
        let now = now.unwrap_or_else(current_timestamp);
        now > self.expires_at
    }

    pub fn is_inactive(&self, timeout: u64, now: Option<u64>) -> bool {
        let now = now.unwrap_or_else(current_timestamp);
        now > self.last_accessed + timeout
    }

    pub fn refresh(&mut self, duration: u64) {
        let now = current_timestamp();
        self.last_accessed = now;
        self.expires_at = now + duration;
    }

    pub fn regenerate_id(&mut self) {
        self.id = generate_session_id();
        self.csrf_token = generate_csrf_token();
    }

    pub fn set_mfa_verified(&mut self, verified: bool) {
        self.mfa_verified = verified;
        if verified {
            self.mfa_verified_at = Some(current_timestamp());
        } else {
            self.mfa_verified_at = None;
        }
    }

    pub fn elevate_privileges(&mut self) {
        self.is_elevated = true;
        // Regenerate session ID for security
        self.regenerate_id();
    }
}

/// Session manager with Redis backend
pub struct SessionManager {
    config: SessionConfig,
    #[cfg(feature = "redis-sessions")]
    redis_client: Option<redis::Client>,
    #[cfg(not(feature = "redis-sessions"))]
    redis_client: Option<()>,
    // Fallback in-memory store for when Redis is unavailable
    memory_store: Arc<RwLock<HashMap<String, Session>>>,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        #[cfg(feature = "redis-sessions")]
        let redis_client = if let Ok(redis_url) = std::env::var("REDIS_URL") {
            match redis::Client::open(redis_url) {
                Ok(client) => {
                    info!("Session manager using Redis backend");
                    Some(client)
                }
                Err(e) => {
                    warn!(error = %e, "Failed to connect to Redis, using in-memory session store");
                    None
                }
            }
        } else {
            info!("No Redis URL provided, using in-memory session store");
            None
        };

        #[cfg(not(feature = "redis-sessions"))]
        let redis_client = {
            info!("Redis feature not enabled, using in-memory session store only");
            None
        };

        Self {
            config,
            redis_client,
            memory_store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new session
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if:
    /// - Redis connection fails (when Redis is enabled)
    /// - Session ID generation fails
    /// - Session storage fails
    pub async fn create_session(
        &self,
        user_id: String,
        client_id: Option<String>,
        ip_address: String,
        user_agent: Option<String>,
        duration: Option<u64>,
    ) -> Result<Session, SessionError> {
        let duration = duration.unwrap_or(self.config.default_duration);

        // Enforce maximum session duration
        let duration = std::cmp::min(duration, self.config.max_duration);

        // Check concurrent session limit
        self.enforce_concurrent_session_limit(&user_id).await?;

        let session = Session::new(
            user_id.clone(),
            client_id.clone(),
            ip_address.clone(),
            user_agent.clone(),
            duration,
        );

        // Store session
        self.store_session(&session).await?;

        // Log session creation
        let mut event = SecurityEvent::new(
            SecurityEventType::AuthenticationSuccess,
            SecuritySeverity::Low,
            "auth-service".to_string(),
            "Session created".to_string(),
        )
        .with_actor(user_id.clone())
        .with_action("create".to_string())
        .with_target(format!("session:{}", session.id))
        .with_outcome("success".to_string())
        .with_reason("New session established after successful authentication".to_string())
        .with_user_id(user_id)
        .with_ip_address(ip_address)
        .with_session_id(session.id.clone())
        .with_detail(
            "duration_seconds".to_string(),
            serde_json::Value::Number(duration.into()),
        )
        .with_detail(
            "has_user_agent".to_string(),
            serde_json::Value::Bool(user_agent.is_some()),
        );

        if let Some(client_id) = &client_id {
            event = event.with_client_id(client_id.clone());
        }

        let logger = SecurityLogger::new(SecurityLoggerConfig::default());
        logger.log_event(&event);

        // Update metrics
        #[cfg(feature = "monitoring")]
        SECURITY_METRICS.record_security_event("session_created");

        Ok(session)
    }

    /// Get a session by ID
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if both Redis and memory store access fail
    pub async fn get_session(&self, session_id: &str) -> Result<Option<Session>, SessionError> {
        #[cfg(feature = "redis-sessions")]
        if let Some(client) = &self.redis_client {
            match self.get_session_from_redis(client, session_id).await {
                Ok(session) => return Ok(session),
                Err(e) => {
                    warn!(error = %redact_log(&e.to_string()), session_id = %redact_log(session_id), "Failed to get session from Redis, falling back to memory");
                }
            }
        }

        // Fallback to memory store
        let store = self.memory_store.read().await;
        Ok(store.get(session_id).cloned())
    }

    /// Update a session
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if session storage fails in both Redis and memory
    pub async fn update_session(&self, session: &Session) -> Result<(), SessionError> {
        self.store_session(session).await
    }

    /// Delete a session
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if session deletion fails from storage
    pub async fn delete_session(&self, session_id: &str) -> Result<(), SessionError> {
        // Try Redis first
        #[cfg(feature = "redis-sessions")]
        if let Some(client) = &self.redis_client {
            match self.delete_session_from_redis(client, session_id).await {
                Ok(()) => {
                    #[cfg(feature = "monitoring")]
                    SECURITY_METRICS.record_security_event("session_destroyed");
                    return Ok(());
                }
                Err(e) => {
                    warn!(error = %redact_log(&e.to_string()), session_id = %redact_log(session_id), "Failed to delete session from Redis, falling back to memory");
                }
            }
        }

        // Fallback to memory store
        let mut store = self.memory_store.write().await;
        if store.remove(session_id).is_some() {
            #[cfg(feature = "monitoring")]
            SECURITY_METRICS.record_security_event("session_removed");
        }
        Ok(())
    }

    /// Refresh a session's expiration
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if:
    /// - Session retrieval fails
    /// - Session storage fails after refresh
    /// - Session has expired and cannot be refreshed
    pub async fn refresh_session(
        &self,
        session_id: &str,
        duration: Option<u64>,
    ) -> Result<Option<Session>, SessionError> {
        if let Some(mut session) = self.get_session(session_id).await? {
            let duration = duration.unwrap_or(self.config.default_duration);
            let duration = std::cmp::min(duration, self.config.max_duration);

            session.refresh(duration);
            self.store_session(&session).await?;

            // Log session refresh
            let logger = SecurityLogger::new(SecurityLoggerConfig::default());
            let event = SecurityEvent::new(
                SecurityEventType::SystemEvent,
                SecuritySeverity::Low,
                "auth-service".to_string(),
                "Session refreshed".to_string(),
            )
            .with_actor(session.user_id.clone())
            .with_action("refresh".to_string())
            .with_target(format!("session:{}", session.id))
            .with_outcome("success".to_string())
            .with_reason("Session lifetime extended successfully".to_string())
            .with_session_id(session.id.clone())
            .with_user_id(session.user_id.clone())
            .with_ip_address(session.ip_address.clone())
            .with_detail(
                "new_expires_at".to_string(),
                serde_json::Value::Number(session.expires_at.into()),
            );
            logger.log_event(&event);

            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    /// Invalidate all sessions for a user
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if:
    /// - User session retrieval fails
    /// - Session deletion fails for any session
    pub async fn invalidate_user_sessions(&self, user_id: &str) -> Result<u32, SessionError> {
        let sessions = self.get_user_sessions(user_id).await?;
        let count = u32::try_from(sessions.len()).unwrap_or(u32::MAX);

        for session in sessions {
            self.delete_session(&session.id).await?;

            // Log session invalidation
            let logger = SecurityLogger::new(SecurityLoggerConfig::default());
            logger.log_event(
                &SecurityEvent::new(
                    SecurityEventType::AuthenticationFailure,
                    SecuritySeverity::Medium,
                    "auth-service".to_string(),
                    "Session invalidated".to_string(),
                )
                .with_actor("system".to_string())
                .with_action("invalidate".to_string())
                .with_target(format!("session:{}", session.id))
                .with_outcome("success".to_string())
                .with_reason("All user sessions invalidated on request".to_string())
                .with_session_id(session.id.clone())
                .with_user_id(session.user_id.clone())
                .with_ip_address(session.ip_address.clone())
                .with_detail(
                    "reason".to_string(),
                    serde_json::Value::String("user_session_invalidation".to_string()),
                ),
            );
        }

        Ok(count)
    }

    /// Clean up expired and inactive sessions
    ///
    /// # Errors
    ///
    /// Returns `SessionError` if Redis cleanup operations fail
    pub async fn cleanup_sessions(&self) -> Result<u32, SessionError> {
        let now = current_timestamp();
        let mut cleaned_count = 0;

        // Memory store cleanup
        {
            let mut store = self.memory_store.write().await;
            let before_count = store.len();
            store.retain(|_id, session| {
                !session.is_expired(Some(now))
                    && !session.is_inactive(self.config.inactivity_timeout, Some(now))
            });
            let after_count = store.len();
            cleaned_count += u32::try_from(before_count - after_count).unwrap_or(u32::MAX);
        }

        // Redis cleanup would need a background task with cursor iteration
        // For now, we rely on Redis TTL for cleanup

        if cleaned_count > 0 {
            #[cfg(feature = "monitoring")]
            SECURITY_METRICS.record_security_event("sessions_cleaned");
            info!(
                cleaned_sessions = cleaned_count,
                "Cleaned up expired sessions"
            );
        }

        Ok(cleaned_count)
    }

    /// Private helper methods
    async fn store_session(&self, session: &Session) -> Result<(), SessionError> {
        // Try Redis first
        #[cfg(feature = "redis-sessions")]
        if let Some(client) = &self.redis_client {
            match self.store_session_to_redis(client, session).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(error = %redact_log(&e.to_string()), session_id = %redact_log(&session.id), "Failed to store session to Redis, falling back to memory");
                }
            }
        }

        // Fallback to memory store
        let mut store = self.memory_store.write().await;
        store.insert(session.id.clone(), session.clone());
        Ok(())
    }

    #[cfg(feature = "redis-sessions")]
    async fn get_session_from_redis(
        &self,
        client: &redis::Client,
        session_id: &str,
    ) -> Result<Option<Session>, redis::RedisError> {
        let mut conn = client.get_connection_manager().await?;
        let key = session_key(session_id);
        let session_data: Option<String> =
            redis::cmd("GET").arg(&key).query_async(&mut conn).await?;

        if let Some(data) = session_data {
            match serde_json::from_str::<Session>(&data) {
                Ok(session) => Ok(Some(session)),
                Err(e) => {
                    error!(error = %redact_log(&e.to_string()), session_id = %redact_log(session_id), "Failed to deserialize session");
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "redis-sessions")]
    async fn store_session_to_redis(
        &self,
        client: &redis::Client,
        session: &Session,
    ) -> Result<(), redis::RedisError> {
        let mut conn = client.get_connection_manager().await?;
        let key = format!("session:{}", session.id);
        let user_key = format!("user_sessions:{}", session.user_id);
        let ttl = session.expires_at - current_timestamp();

        let session_data = serde_json::to_string(session).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Serialization error",
                e.to_string(),
            ))
        })?;

        // Store session with TTL
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(&session_data)
            .query_async::<()>(&mut conn)
            .await?;

        // Add to user sessions set
        redis::cmd("SADD")
            .arg(&user_key)
            .arg(&session.id)
            .query_async::<()>(&mut conn)
            .await?;

        // Set TTL on user sessions set
        redis::cmd("EXPIRE")
            .arg(&user_key)
            .arg(ttl)
            .query_async::<()>(&mut conn)
            .await?;

        Ok(())
    }

    #[cfg(feature = "redis-sessions")]
    async fn delete_session_from_redis(
        &self,
        client: &redis::Client,
        session_id: &str,
    ) -> Result<(), redis::RedisError> {
        let mut conn = client.get_connection_manager().await?;

        // Get session to find user_id
        if let Some(session) = self.get_session_from_redis(client, session_id).await? {
            let user_key = format!("user_sessions:{}", session.user_id);
            redis::cmd("SREM")
                .arg(&user_key)
                .arg(session_id)
                .query_async::<()>(&mut conn)
                .await?;
        }

        let key = session_key(session_id);
        redis::cmd("DEL")
            .arg(&key)
            .query_async::<()>(&mut conn)
            .await?;

        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, SessionError> {
        let mut sessions = Vec::with_capacity(DEFAULT_SESSION_CAPACITY);

        // Try Redis first
        #[cfg(feature = "redis-sessions")]
        if let Some(client) = &self.redis_client {
            match self.get_user_sessions_from_redis(client, user_id).await {
                Ok(redis_sessions) => return Ok(redis_sessions),
                Err(e) => {
                    warn!(error = %redact_log(&e.to_string()), user_id = %redact_log(user_id), "Failed to get user sessions from Redis, falling back to memory");
                }
            }
        }

        // Fallback to memory store
        let store = self.memory_store.read().await;
        for session in store.values() {
            if session.user_id == user_id {
                sessions.push(session.clone());
            }
        }

        Ok(sessions)
    }

    #[cfg(feature = "redis-sessions")]
    async fn get_user_sessions_from_redis(
        &self,
        client: &redis::Client,
        user_id: &str,
    ) -> Result<Vec<Session>, redis::RedisError> {
        let mut conn = client.get_connection_manager().await?;
        let user_key = format!("user_sessions:{user_id}");

        let session_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&user_key)
            .query_async(&mut conn)
            .await?;

        let mut sessions = Vec::with_capacity(session_ids.len());
        for session_id in session_ids {
            if let Ok(Some(session)) = self.get_session_from_redis(client, &session_id).await {
                sessions.push(session);
            }
        }

        Ok(sessions)
    }

    async fn enforce_concurrent_session_limit(&self, user_id: &str) -> Result<(), SessionError> {
        let sessions = self.get_user_sessions(user_id).await?;

        if sessions.len() >= self.config.max_concurrent_sessions as usize {
            // Remove oldest sessions
            let mut sessions = sessions;
            sessions.sort_by(|a, b| a.created_at.cmp(&b.created_at));

            let sessions_to_remove =
                sessions.len() - (self.config.max_concurrent_sessions as usize - 1);
            for session in sessions.iter().take(sessions_to_remove) {
                self.delete_session(&session.id).await?;

                // Log session eviction
                let logger = SecurityLogger::new(SecurityLoggerConfig::default());
                logger.log_event(
                    &SecurityEvent::new(
                        SecurityEventType::AuthenticationFailure,
                        SecuritySeverity::Low,
                        "auth-service".to_string(),
                        "Session evicted due to concurrent limit".to_string(),
                    )
                    .with_actor("system".to_string())
                    .with_action("evict".to_string())
                    .with_target(format!("session:{}", session.id))
                    .with_outcome("success".to_string())
                    .with_reason("Session removed to enforce concurrent session limit".to_string())
                    .with_session_id(session.id.clone())
                    .with_user_id(session.user_id.clone())
                    .with_ip_address(session.ip_address.clone())
                    .with_detail(
                        "reason".to_string(),
                        serde_json::Value::String("concurrent_session_limit".to_string()),
                    ),
                );
            }
        }

        Ok(())
    }
}

/// Session management errors
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Session not found")]
    NotFound,
    #[error("Session expired")]
    Expired,
    #[cfg(feature = "redis-sessions")]
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Invalid session data")]
    InvalidData,
}

/// Global session manager instance
pub static SESSION_MANAGER: std::sync::LazyLock<SessionManager> = std::sync::LazyLock::new(|| {
    let config = SessionConfig::default();
    SessionManager::new(config)
});

/// Helper functions
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_session_id() -> String {
    format!("sess_{}", Uuid::new_v4())
}

fn generate_csrf_token() -> String {
    format!("csrf_{}", Uuid::new_v4())
}

/// Start session cleanup background task
pub async fn start_session_cleanup_task() {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

    loop {
        interval.tick().await;

        match SESSION_MANAGER.cleanup_sessions().await {
            Ok(count) => {
                if count > 0 {
                    info!(cleaned_sessions = count, "Session cleanup completed");
                }
            }
            Err(e) => {
                error!(error = %redact_log(&e.to_string()), "Session cleanup failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);

        let session = manager
            .create_session(
                "test_user".to_string(),
                Some("test_client".to_string()),
                "192.168.1.1".to_string(),
                Some("TestAgent/1.0".to_string()),
                Some(3600),
            )
            .await
            .unwrap();

        assert_eq!(session.user_id, "test_user");
        assert_eq!(session.client_id, Some("test_client".to_string()));
        assert_eq!(session.ip_address, "192.168.1.1");
        assert!(!session.mfa_verified);
        assert!(!session.is_elevated);
    }

    #[tokio::test]
    async fn test_session_retrieval() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);

        let session = manager
            .create_session(
                "test_user".to_string(),
                None,
                "192.168.1.1".to_string(),
                None,
                Some(3600),
            )
            .await
            .unwrap();

        let retrieved = manager.get_session(&session.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, session.id);
    }

    #[tokio::test]
    async fn test_session_refresh() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);

        let session = manager
            .create_session(
                "test_user".to_string(),
                None,
                "192.168.1.1".to_string(),
                None,
                Some(3600),
            )
            .await
            .unwrap();

        let original_expires = session.expires_at;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let refreshed = manager
            .refresh_session(&session.id, Some(7200))
            .await
            .unwrap();
        assert!(refreshed.is_some());
        assert!(refreshed.unwrap().expires_at > original_expires);
    }

    #[tokio::test]
    async fn test_session_deletion() {
        let config = SessionConfig::default();
        let manager = SessionManager::new(config);

        let session = manager
            .create_session(
                "test_user".to_string(),
                None,
                "192.168.1.1".to_string(),
                None,
                Some(3600),
            )
            .await
            .unwrap();

        manager.delete_session(&session.id).await.unwrap();

        let retrieved = manager.get_session(&session.id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_session_expiration() {
        let mut session = Session::new(
            "test_user".to_string(),
            None,
            "192.168.1.1".to_string(),
            None,
            3600,
        );

        assert!(!session.is_expired(None));

        // Simulate expired session
        session.expires_at = current_timestamp() - 100;
        assert!(session.is_expired(None));
    }

    #[test]
    fn test_session_inactivity() {
        let mut session = Session::new(
            "test_user".to_string(),
            None,
            "192.168.1.1".to_string(),
            None,
            3600,
        );

        assert!(!session.is_inactive(1800, None)); // 30 min timeout

        // Simulate inactive session
        session.last_accessed = current_timestamp() - 2000; // 33+ minutes ago
        assert!(session.is_inactive(1800, None));
    }
}
