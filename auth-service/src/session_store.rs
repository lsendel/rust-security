//! Session management with Redis-backed storage
//! 
//! Provides secure session management with automatic expiration,
//! Redis-first storage with in-memory fallback, and session security features.

use async_trait::async_trait;
use deadpool_redis::{Config, Pool, Runtime, redis::AsyncCommands};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use uuid::Uuid;

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
    async fn create_session(&self, session: &SessionData) -> Result<(), Box<dyn StdError + Send + Sync>>;
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>, Box<dyn StdError + Send + Sync>>;
    async fn update_session(&self, session: &SessionData) -> Result<(), Box<dyn StdError + Send + Sync>>;
    async fn delete_session(&self, session_id: &str) -> Result<(), Box<dyn StdError + Send + Sync>>;
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>, Box<dyn StdError + Send + Sync>>;
    async fn cleanup_expired_sessions(&self) -> Result<u64, Box<dyn StdError + Send + Sync>>;
    async fn revoke_all_user_sessions(&self, user_id: &str) -> Result<u64, Box<dyn StdError + Send + Sync>>;
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
        
        // Test the connection
        match pool.get().await {
            Ok(_conn) => {
                info!("Redis session store initialized successfully");
                Some(pool)
            }
            Err(e) => {
                error!("Failed to get Redis connection for session store: {}", e);
                None
            }
        }
    }
    
    async fn get_redis_connection(&self) -> Option<deadpool_redis::Connection> {
        match &self.redis_pool {
            Some(pool) => {
                match pool.get().await {
                    Ok(conn) => Some(conn),
                    Err(e) => {
                        warn!("Failed to get Redis connection from session pool: {}", e);
                        None
                    }
                }
            }
            None => None,
        }
    }
    
    fn session_key(&self, session_id: &str) -> String {
        format!("session:{}", session_id)
    }
    
    fn user_sessions_key(&self, user_id: &str) -> String {
        format!("user_sessions:{}", user_id)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create_session(&self, session: &SessionData) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let session_json = serde_json::to_string(session)?;
        let ttl = session.expires_at - session.created_at;
        
        // Store in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(&session.session_id);
            let user_sessions_key = self.user_sessions_key(&session.user_id);
            
            // Store session data with TTL
            let result1: Result<(), _> = redis::cmd("SETEX")
                .arg(&session_key)
                .arg(ttl)
                .arg(&session_json)
                .query_async(&mut *conn)
                .await;
                
            // Add to user sessions set
            let result2: Result<(), _> = redis::cmd("SADD")
                .arg(&user_sessions_key)
                .arg(&session.session_id)
                .query_async(&mut *conn)
                .await;
            
            match (result1, result2) {
                (Ok(_), Ok(_)) => {
                    // Successfully stored in Redis, also store in memory as backup
                    self.memory_fallback.write().await.insert(session.session_id.clone(), session.clone());
                    
                    // Update user sessions index
                    let mut user_sessions = self.user_sessions_index.write().await;
                    user_sessions.entry(session.user_id.clone())
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
        self.memory_fallback.write().await.insert(session.session_id.clone(), session.clone());
        
        // Update user sessions index
        let mut user_sessions = self.user_sessions_index.write().await;
        user_sessions.entry(session.user_id.clone())
            .or_insert_with(Vec::new)
            .push(session.session_id.clone());
        
        Ok(())
    }
    
    async fn get_session(&self, session_id: &str) -> Result<Option<SessionData>, Box<dyn StdError + Send + Sync>> {
        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(session_id);
            match redis::cmd("GET").arg(&session_key).query_async::<_, Option<String>>(&mut *conn).await {
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
    
    async fn update_session(&self, session: &SessionData) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let session_json = serde_json::to_string(session)?;
        let ttl = if session.expires_at > session.last_accessed {
            session.expires_at - session.last_accessed
        } else {
            1 // Minimum TTL to avoid immediate expiration
        };
        
        // Update in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(&session.session_id);
            match conn.set_ex::<_, _, ()>(&session_key, &session_json, ttl as usize).await 
            {
                Ok(_) => {
                    // Successfully updated in Redis, also update memory backup
                    self.memory_fallback.write().await.insert(session.session_id.clone(), session.clone());
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to update session in Redis: {}", e);
                }
            }
        }
        
        // Fallback to in-memory storage
        self.memory_fallback.write().await.insert(session.session_id.clone(), session.clone());
        Ok(())
    }
    
    async fn delete_session(&self, session_id: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // Get session first to find user_id for index cleanup
        let session = self.get_session(session_id).await?;
        
        // Delete from Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let session_key = self.session_key(session_id);
            
            if let Some(session_data) = &session {
                let user_sessions_key = self.user_sessions_key(&session_data.user_id);
                
                // Use Redis pipeline for atomic operations
                let mut pipe = redis::pipe();
                pipe.del(&session_key);
                pipe.srem(&user_sessions_key, session_id);
                
                let _: Result<(), _> = pipe.query_async(&mut *conn).await;
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
    
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>, Box<dyn StdError + Send + Sync>> {
        let mut sessions = Vec::new();
        
        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let user_sessions_key = self.user_sessions_key(user_id);
            match conn.smembers::<_, Vec<String>>(&user_sessions_key).await 
            {
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
            sessions.iter()
                .filter_map(|(id, session)| {
                    if session.is_expired() { Some(id.clone()) } else { None }
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
    
    async fn revoke_all_user_sessions(&self, user_id: &str) -> Result<u64, Box<dyn StdError + Send + Sync>> {
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