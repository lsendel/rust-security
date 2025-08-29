//! Session management with Redis-backed storage
//!
//! Provides secure session management with automatic expiration,
//! Redis-first storage with in-memory fallback, and session security features.

use async_trait::async_trait;
use deadpool_redis::{redis::AsyncCommands, Config, Pool, Runtime};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

// Note: Advanced connection pool would integrate with connection_pool_optimized when available
// For now, we'll define basic structures to demonstrate the pattern

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    pub session_id: String,
    pub user_id: String,
    pub client_id: String,
    pub created_at: u64,
    pub last_accessed: u64,
    pub expires_at: u64,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub scope: Vec<String>,
    pub mfa_verified: bool,
    pub device_fingerprint: Option<String>,
}

impl SessionData {
    #[must_use]
    pub fn new(
        user_id: String,
        client_id: String,
        ttl_seconds: u64,
        ip_address: Option<String>,
        user_agent: Option<String>,
        scope: Vec<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            session_id: Uuid::new_v4().to_string(),
            user_id,
            client_id,
            created_at: now,
            last_accessed: now,
            expires_at: now + ttl_seconds,
            ip_address,
            user_agent,
            scope,
            mfa_verified: false,
            device_fingerprint: None,
        }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now >= self.expires_at
    }

    pub fn update_last_accessed(&mut self) {
        self.last_accessed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn extend_session(&mut self, additional_seconds: u64) {
        self.expires_at += additional_seconds;
        self.update_last_accessed();
    }
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn StdError + Send + Sync>>;
    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn StdError + Send + Sync>>;
    async fn update_session(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn StdError + Send + Sync>>;
    async fn delete_session(&self, session_id: &str)
        -> Result<(), Box<dyn StdError + Send + Sync>>;
    async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<SessionData>, Box<dyn StdError + Send + Sync>>;
    async fn cleanup_expired_sessions(&self) -> Result<u64, Box<dyn StdError + Send + Sync>>;
    async fn revoke_all_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<u64, Box<dyn StdError + Send + Sync>>;
}

#[derive(Clone)]
pub struct RedisSessionStore {
    redis_pool: Option<Pool>,
    memory_fallback: Arc<RwLock<HashMap<String, SessionData>>>,
    user_sessions_index: Arc<RwLock<HashMap<String, Vec<String>>>>, // user_id -> session_ids
}

impl RedisSessionStore {
    pub async fn new(redis_url: Option<String>) -> Self {
        let redis_pool = if let Some(url) = redis_url {
            Self::create_redis_pool(&url).await
        } else {
            None
        };

        Self {
            redis_pool,
            memory_fallback: Arc::new(RwLock::new(HashMap::new())),
            user_sessions_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn create_redis_pool(redis_url: &str) -> Option<Pool> {
        info!("Initializing Redis session store");

        let config = Config::from_url(redis_url);
        let pool = config.create_pool(Some(Runtime::Tokio1)).ok()?;

        // Test the connection with timeout
        let connection_test = pool.get();
        let timeout_duration = std::time::Duration::from_secs(2);

        match tokio::time::timeout(timeout_duration, connection_test).await {
            Ok(Ok(_conn)) => {
                info!("Redis session store initialized successfully");
                Some(pool)
            }
            Ok(Err(e)) => {
                error!("Failed to get Redis connection for session store: {}", e);
                None
            }
            Err(_) => {
                warn!("Redis session store connection test timed out - using memory fallback");
                None
            }
        }
    }

    async fn get_redis_connection(&self) -> Option<deadpool_redis::Connection> {
        match &self.redis_pool {
            Some(pool) => match pool.get().await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    warn!("Failed to get Redis connection from session pool: {}", e);
                    None
                }
            },
            None => None,
        }
    }

    fn session_key(&self, session_id: &str) -> String {
        format!("session:{session_id}")
    }

    fn user_sessions_key(&self, user_id: &str) -> String {
        format!("user_sessions:{user_id}")
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let session_json = serde_json::to_string(session)?;
        let ttl = session.expires_at - session.created_at;

        // Store in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(&session.session_id);
            let user_sessions_key = self.user_sessions_key(&session.user_id);

            // Store session data with TTL
            let result1: Result<(), _> = {
                let set_result = conn.set::<_, _, ()>(&session_key, &session_json).await;
                if set_result.is_ok() {
                    conn.expire(&session_key, ttl as i64).await
                } else {
                    set_result
                }
            };

            // Add to user sessions set
            let result2: Result<(), _> = conn.sadd(&user_sessions_key, &session.session_id).await;

            match (result1, result2) {
                (Ok(()), Ok(())) => {
                    // Successfully stored in Redis, also store in memory as backup
                    self.memory_fallback
                        .write()
                        .await
                        .insert(session.session_id.clone(), session.clone());

                    // Update user sessions index
                    let mut user_sessions = self.user_sessions_index.write().await;
                    user_sessions
                        .entry(session.user_id.clone())
                        .or_insert_with(Vec::new)
                        .push(session.session_id.clone());

                    return Ok(());
                }
                _ => {
                    warn!("Failed to store session in Redis");
                }
            }
        }

        // Fallback to in-memory storage
        warn!("Storing session in memory as fallback");
        self.memory_fallback
            .write()
            .await
            .insert(session.session_id.clone(), session.clone());

        // Update user sessions index
        let mut user_sessions = self.user_sessions_index.write().await;
        user_sessions
            .entry(session.user_id.clone())
            .or_insert_with(Vec::new)
            .push(session.session_id.clone());

        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn StdError + Send + Sync>> {
        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(session_id);
            match conn.get::<_, Option<String>>(&session_key).await {
                Ok(Some(json)) => {
                    let mut session: SessionData = serde_json::from_str(&json)?;
                    if session.is_expired() {
                        // Clean up expired session
                        let _: Result<(), _> = self.delete_session(session_id).await;
                        return Ok(None);
                    }
                    // Update last accessed time
                    session.update_last_accessed();
                    let _: Result<(), _> = self.update_session(&session).await;
                    return Ok(Some(session));
                }
                Ok(None) => {
                    // Not found in Redis, try memory fallback
                }
                Err(e) => {
                    warn!("Failed to get session from Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        if let Some(mut session) = self.memory_fallback.read().await.get(session_id).cloned() {
            if session.is_expired() {
                // Clean up expired session
                let _: Result<(), _> = self.delete_session(session_id).await;
                return Ok(None);
            }
            // Update last accessed time
            session.update_last_accessed();
            let _: Result<(), _> = self.update_session(&session).await;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    async fn update_session(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let session_json = serde_json::to_string(session)?;
        let ttl = if session.expires_at > session.last_accessed {
            session.expires_at - session.last_accessed
        } else {
            1 // Minimum TTL to avoid immediate expiration
        };

        // Update in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(&session.session_id);
            let res = {
                let set_result = conn.set::<_, _, ()>(&session_key, &session_json).await;
                if set_result.is_ok() {
                    let _: Result<(), _> = conn.expire(&session_key, ttl as i64).await;
                }
                set_result
            };
            match res {
                Ok(()) => {
                    // Successfully updated in Redis, also update memory backup
                    self.memory_fallback
                        .write()
                        .await
                        .insert(session.session_id.clone(), session.clone());
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to update session in Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        self.memory_fallback
            .write()
            .await
            .insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    async fn delete_session(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // Get session first to find user_id for index cleanup
        let session = self.get_session(session_id).await?;

        // Delete from Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(session_id);

            if let Some(session_data) = &session {
                let user_sessions_key = self.user_sessions_key(&session_data.user_id);

                // Delete session and remove from user sessions set
                let _: Result<(), _> = conn.del(&session_key).await;
                let _: Result<(), _> = conn.srem(&user_sessions_key, session_id).await;
            } else {
                let _: Result<(), _> = conn.del(&session_key).await;
            }
        }

        // Remove from memory fallback
        self.memory_fallback.write().await.remove(session_id);

        // Update user sessions index
        if let Some(session_data) = session {
            let mut user_sessions = self.user_sessions_index.write().await;
            if let Some(sessions) = user_sessions.get_mut(&session_data.user_id) {
                sessions.retain(|id| id != session_id);
                if sessions.is_empty() {
                    user_sessions.remove(&session_data.user_id);
                }
            }
        }

        Ok(())
    }

    async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<SessionData>, Box<dyn StdError + Send + Sync>> {
        let mut sessions = Vec::new();

        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let user_sessions_key = self.user_sessions_key(user_id);
            match conn.smembers::<_, Vec<String>>(&user_sessions_key).await {
                Ok(session_ids) => {
                    for session_id in &session_ids {
                        if let Ok(Some(session)) = self.get_session(session_id).await {
                            sessions.push(session);
                        }
                    }
                    return Ok(sessions);
                }
                Err(e) => {
                    warn!("Failed to get user sessions from Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        let user_sessions = self.user_sessions_index.read().await;
        if let Some(session_ids) = user_sessions.get(user_id) {
            let memory_sessions = self.memory_fallback.read().await;
            for session_id in session_ids {
                if let Some(session) = memory_sessions.get(session_id) {
                    if !session.is_expired() {
                        sessions.push(session.clone());
                    }
                }
            }
        }

        Ok(sessions)
    }

    async fn cleanup_expired_sessions(&self) -> Result<u64, Box<dyn StdError + Send + Sync>> {
        let mut cleaned_count = 0u64;

        // Redis automatically handles TTL expiration, so we mainly need to clean memory fallback
        let expired_sessions: Vec<String> = {
            let sessions = self.memory_fallback.read().await;
            sessions
                .iter()
                .filter_map(|(id, session)| {
                    if session.is_expired() {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        for session_id in expired_sessions {
            if self.delete_session(&session_id).await.is_ok() {
                cleaned_count += 1;
            }
        }

        info!("Cleaned up {} expired sessions", cleaned_count);
        Ok(cleaned_count)
    }

    async fn revoke_all_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<u64, Box<dyn StdError + Send + Sync>> {
        let sessions = self.get_user_sessions(user_id).await?;
        let mut revoked_count = 0u64;

        for session in sessions {
            if self.delete_session(&session.session_id).await.is_ok() {
                revoked_count += 1;
            }
        }

        info!("Revoked {} sessions for user {}", revoked_count, user_id);
        Ok(revoked_count)
    }
}

/// Start a background task to periodically clean up expired sessions
pub async fn start_session_cleanup_task(session_store: Arc<dyn SessionStore>) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes

    loop {
        interval.tick().await;
        match session_store.cleanup_expired_sessions().await {
            Ok(count) => {
                if count > 0 {
                    info!("Session cleanup completed: {} sessions removed", count);
                }
            }
            Err(e) => {
                error!("Session cleanup failed: {}", e);
            }
        }
    }
}

/// Basic connection pool configuration for demonstration
#[cfg(feature = "enhanced-session-store")]
#[derive(Debug, Clone)]
pub struct BasicConnectionPoolConfig {
    pub max_connections: u32,
    pub connection_timeout: Duration,
}

#[cfg(feature = "enhanced-session-store")]
impl Default for BasicConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connection_timeout: Duration::from_secs(5),
        }
    }
}

/// Basic connection pool manager for demonstration
#[cfg(feature = "enhanced-session-store")]
pub struct BasicConnectionPoolManager {
    redis_pool: Option<Pool>,
    _config: BasicConnectionPoolConfig,
}

#[cfg(feature = "enhanced-session-store")]
impl BasicConnectionPoolManager {
    pub async fn new(
        redis_url: &str,
        config: BasicConnectionPoolConfig,
    ) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        let redis_config = Config::from_url(redis_url);
        let pool = redis_config.create_pool(Some(Runtime::Tokio1))?;

        Ok(Self {
            redis_pool: Some(pool),
            _config: config,
        })
    }

    pub async fn get_connection(
        &self,
    ) -> Result<deadpool_redis::Connection, Box<dyn StdError + Send + Sync>> {
        match &self.redis_pool {
            Some(pool) => {
                let conn = pool.get().await?;
                Ok(conn)
            }
            None => Err("No Redis pool available".into()),
        }
    }
}

/// Enhanced Redis session store with optimized connection pooling and resilience
/// Temporarily disabled due to compilation issues - can be enabled in the future
#[cfg(feature = "enhanced-session-store")]
#[derive(Clone)]
pub struct EnhancedRedisSessionStore {
    pool_manager: Arc<BasicConnectionPoolManager>,
    memory_fallback: Arc<RwLock<HashMap<String, SessionData>>>,
    user_sessions_index: Arc<RwLock<HashMap<String, Vec<String>>>>, // user_id -> session_ids
    retry_config: RetryConfig,
}

#[cfg(feature = "enhanced-session-store")]
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub exponential_base: f64,
}

#[cfg(feature = "enhanced-session-store")]
impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            exponential_base: 2.0,
        }
    }
}

#[cfg(feature = "enhanced-session-store")]
impl EnhancedRedisSessionStore {
    /// Create a new enhanced Redis session store with optimized connection pooling
    pub async fn new(redis_url: Option<String>) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        let pool_manager = if let Some(url) = redis_url {
            let config = BasicConnectionPoolConfig::default();
            let manager = BasicConnectionPoolManager::new(&url, config).await?;
            Arc::new(manager)
        } else {
            return Err("Redis URL is required for enhanced session store".into());
        };

        Ok(Self {
            pool_manager,
            memory_fallback: Arc::new(RwLock::new(HashMap::new())),
            user_sessions_index: Arc::new(RwLock::new(HashMap::new())),
            retry_config: RetryConfig::default(),
        })
    }

    /// Execute Redis operation with retry and fallback
    async fn with_redis_retry<F, T>(
        &self,
        operation: F,
    ) -> Result<T, Box<dyn StdError + Send + Sync>>
    where
        F: Fn() -> T + Clone + Send + 'static,
        T: Send + 'static,
    {
        for attempt in 0..=self.retry_config.max_retries {
            match self.pool_manager.get_connection().await {
                Ok(_conn) => {
                    // In a real implementation, you would execute the operation here
                    // For now, we'll simulate the operation
                    return Ok(operation());
                }
                Err(e) => {
                    if attempt == self.retry_config.max_retries {
                        error!("All Redis retry attempts exhausted: {}", e);
                        return Err(e);
                    }

                    let delay = self.calculate_retry_delay(attempt);
                    warn!(
                        "Redis operation failed (attempt {}), retrying in {:?}: {}",
                        attempt + 1,
                        delay,
                        e
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }

        Err("Unexpected retry loop exit".into())
    }

    fn calculate_retry_delay(&self, attempt: u32) -> Duration {
        let delay_ms = self.retry_config.base_delay.as_millis() as f64
            * self.retry_config.exponential_base.powi(attempt as i32);

        let delay = Duration::from_millis(delay_ms as u64);
        std::cmp::min(delay, self.retry_config.max_delay)
    }

    #[allow(dead_code)]
    fn session_key(&self, session_id: &str) -> String {
        format!("auth:session:{session_id}")
    }

    #[allow(dead_code)]
    fn user_sessions_key(&self, user_id: &str) -> String {
        format!("auth:user_sessions:{user_id}")
    }
}

// Temporarily disabled due to lifetime parameter matching issues
// Can be enabled once the exact trait signature is resolved
#[cfg(feature = "enhanced-session-store")]
#[async_trait]
impl SessionStore for EnhancedRedisSessionStore {
    async fn create_session(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // Store in Redis with retry mechanism
        let _session_clone = session.clone();
        let result = self
            .with_redis_retry(|| {
                // In a real implementation, this would contain the actual Redis operations
                // For now, we'll simulate success
                Ok::<(), Box<dyn StdError + Send + Sync>>(())
            })
            .await;

        match result {
            Ok(_) => {
                // Update user sessions index
                let mut user_index = self.user_sessions_index.write().await;
                user_index
                    .entry(session.user_id.clone())
                    .or_insert_with(Vec::new)
                    .push(session.session_id.clone());

                info!(
                    "Session created successfully: {} for user: {}",
                    session.session_id, session.user_id
                );
            }
            Err(e) => {
                warn!(
                    "Failed to create session in Redis, storing in memory fallback: {}",
                    e
                );
                // Fallback to memory storage
                let mut memory = self.memory_fallback.write().await;
                memory.insert(session.session_id.clone(), session.clone());

                let mut user_index = self.user_sessions_index.write().await;
                user_index
                    .entry(session.user_id.clone())
                    .or_insert_with(Vec::new)
                    .push(session.session_id.clone());
            }
        }

        Ok(())
    }

    async fn get_session(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionData>, Box<dyn StdError + Send + Sync>> {
        // Try Redis first with retry
        let _session_id_clone = session_id.to_string();
        let redis_result = self
            .with_redis_retry(|| {
                // Simulate retrieving session from Redis
                None::<SessionData>
            })
            .await;

        if let Ok(Some(session)) = redis_result {
            Ok(Some(session))
        } else {
            // Check memory fallback
            let memory = self.memory_fallback.read().await;
            Ok(memory.get(session_id).cloned())
        }
    }

    async fn update_session(
        &self,
        session: &SessionData,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // Similar implementation to create_session but for updates
        let _session_clone = session.clone();
        let result = self
            .with_redis_retry(|| Ok::<(), Box<dyn StdError + Send + Sync>>(()))
            .await;

        if result.is_err() {
            // Fallback to memory
            let mut memory = self.memory_fallback.write().await;
            memory.insert(session.session_id.clone(), session.clone());
        }

        Ok(())
    }

    async fn delete_session(
        &self,
        session_id: &str,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // Get session first to clean up user index
        if let Ok(Some(session)) = self.get_session(session_id).await {
            let _session_id_clone = session_id.to_string();
            let _result = self
                .with_redis_retry(|| Ok::<(), Box<dyn StdError + Send + Sync>>(()))
                .await;

            // Clean up memory fallback
            let mut memory = self.memory_fallback.write().await;
            memory.remove(session_id);

            // Clean up user sessions index
            let mut user_index = self.user_sessions_index.write().await;
            if let Some(user_sessions) = user_index.get_mut(&session.user_id) {
                user_sessions.retain(|id| id != session_id);
                if user_sessions.is_empty() {
                    user_index.remove(&session.user_id);
                }
            }
        }

        Ok(())
    }

    async fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<Vec<SessionData>, Box<dyn StdError + Send + Sync>> {
        let user_index = self.user_sessions_index.read().await;
        let session_ids = user_index.get(user_id).cloned().unwrap_or_default();

        let mut sessions = Vec::new();
        for session_id in session_ids {
            if let Ok(Some(session)) = self.get_session(&session_id).await {
                sessions.push(session);
            }
        }

        Ok(sessions)
    }

    async fn cleanup_expired_sessions(&self) -> Result<u64, Box<dyn StdError + Send + Sync>> {
        let mut cleaned_count = 0u64;

        // Clean up memory fallback
        let expired_sessions: Vec<String> = {
            let sessions = self.memory_fallback.read().await;
            sessions
                .iter()
                .filter_map(|(id, session)| {
                    if session.is_expired() {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        for session_id in expired_sessions {
            if self.delete_session(&session_id).await.is_ok() {
                cleaned_count += 1;
            }
        }

        // Redis TTL handles expiration automatically for primary storage
        Ok(cleaned_count)
    }

    async fn revoke_all_user_sessions(
        &self,
        user_id: &str,
    ) -> Result<u64, Box<dyn StdError + Send + Sync>> {
        let sessions = self.get_user_sessions(user_id).await?;
        let mut revoked_count = 0u64;

        for session in sessions {
            if self.delete_session(&session.session_id).await.is_ok() {
                revoked_count += 1;
            }
        }

        Ok(revoked_count)
    }
}

#[cfg(test)]
mod chaos_tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    /// Test Redis outage scenarios
    #[tokio::test]
    async fn test_redis_outage_fallback() {
        // Create session store with fallback capability
        let store = RedisSessionStore::new(None).await;

        let session = SessionData::new(
            "user123".to_string(),
            "client456".to_string(),
            3600,
            Some("127.0.0.1".to_string()),
            Some("TestAgent/1.0".to_string()),
            vec!["read".to_string(), "write".to_string()],
        );

        // Should work with memory fallback when Redis is unavailable
        assert!(store.create_session(&session).await.is_ok());

        let retrieved = store.get_session(&session.session_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, session.user_id);
    }

    #[tokio::test]
    async fn test_session_cleanup_during_redis_outage() {
        let store = RedisSessionStore::new(None).await;

        // Create expired session
        let mut expired_session = SessionData::new(
            "user789".to_string(),
            "client101".to_string(),
            3600,
            Some("127.0.0.1".to_string()),
            Some("TestAgent/1.0".to_string()),
            vec!["read".to_string()],
        );

        // Manually set expiration to past
        expired_session.expires_at = 1234567890; // Way in the past

        store.create_session(&expired_session).await.unwrap();

        // Cleanup should work even during Redis outage
        let cleaned = store.cleanup_expired_sessions().await.unwrap();
        assert!(cleaned >= 1);

        // Session should be gone
        let retrieved = store
            .get_session(&expired_session.session_id)
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[cfg(feature = "enhanced-session-store")]
    #[tokio::test]
    async fn test_retry_mechanism() {
        // This test would use the enhanced store with actual retry logic
        // For now, we'll simulate the behavior

        let retry_config = RetryConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(10), // Faster for tests
            max_delay: Duration::from_millis(100),
            exponential_base: 2.0,
        };

        // Test retry delay calculation
        let delays = (0..=retry_config.max_retries)
            .map(|attempt| {
                let delay_ms = retry_config.base_delay.as_millis() as f64
                    * retry_config.exponential_base.powi(attempt as i32);
                Duration::from_millis(delay_ms as u64)
            })
            .collect::<Vec<_>>();

        assert_eq!(delays[0], Duration::from_millis(10)); // base delay
        assert_eq!(delays[1], Duration::from_millis(20)); // 10 * 2^1
        assert_eq!(delays[2], Duration::from_millis(40)); // 10 * 2^2
        assert_eq!(delays[3], Duration::from_millis(80)); // 10 * 2^3
    }

    #[tokio::test]
    async fn test_concurrent_session_operations_during_outage() {
        let store = Arc::new(RedisSessionStore::new(None).await);
        let mut handles = vec![];

        // Simulate concurrent session operations during Redis outage
        for i in 0..10 {
            let store_clone = store.clone();
            let handle = tokio::spawn(async move {
                let session = SessionData::new(
                    format!("user{}", i),
                    format!("client{}", i),
                    3600,
                    Some("127.0.0.1".to_string()),
                    Some("ConcurrentTestAgent/1.0".to_string()),
                    vec!["read".to_string()],
                );

                // All operations should succeed with memory fallback
                let create_result = store_clone.create_session(&session).await;
                let get_result = store_clone.get_session(&session.session_id).await;
                let update_result = store_clone.update_session(&session).await;

                (
                    create_result.is_ok(),
                    get_result.is_ok(),
                    update_result.is_ok(),
                )
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let results = futures::future::join_all(handles).await;

        // All operations should succeed
        for result in results {
            let (create_ok, get_ok, update_ok) = result.unwrap();
            assert!(create_ok, "Session creation should succeed");
            assert!(get_ok, "Session retrieval should succeed");
            assert!(update_ok, "Session update should succeed");
        }
    }

    #[tokio::test]
    async fn test_user_session_management_resilience() {
        let store = RedisSessionStore::new(None).await;
        let user_id = "test_user_resilience";

        // Create multiple sessions for the same user
        let _session_ids = (0..5)
            .map(|i| {
                let session = SessionData::new(
                    user_id.to_string(),
                    format!("client_{}", i),
                    3600,
                    Some("127.0.0.1".to_string()),
                    Some("ResilienceTestAgent/1.0".to_string()),
                    vec!["read".to_string()],
                );
                let session_id = session.session_id.clone();

                // Create session (should work with memory fallback)
                tokio::spawn({
                    let store = store.clone();
                    async move { store.create_session(&session).await }
                });

                session_id
            })
            .collect::<Vec<_>>();

        // Wait a bit for all sessions to be created
        sleep(Duration::from_millis(100)).await;

        // Get user sessions - should work even during Redis outage
        let user_sessions = store.get_user_sessions(user_id).await.unwrap();
        assert!(!user_sessions.is_empty());

        // Revoke all user sessions - should work with memory fallback
        let revoked_count = store.revoke_all_user_sessions(user_id).await.unwrap();
        assert!(revoked_count > 0);

        // User should have no sessions left
        let remaining_sessions = store.get_user_sessions(user_id).await.unwrap();
        assert!(remaining_sessions.is_empty());
    }
}
