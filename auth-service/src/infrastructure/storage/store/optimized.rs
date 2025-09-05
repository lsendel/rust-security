#![allow(clippy::unused_async)]
// Optimized token store implementation
// This file contains performance-optimized versions of the token store operations

use crate::IntrospectionRecord;
use anyhow::Result;
use dashmap::DashMap;
#[cfg(feature = "redis-sessions")]
use redis::aio::MultiplexedConnection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;

/// Optimized token store with improved performance characteristics
#[derive(Clone)]
pub enum OptimizedTokenStore {
    /// Optimized in-memory store using `DashMap` for better concurrency
    InMemory(Arc<DashMap<String, CachedTokenRecord>>),
    /// Optimized Redis store with hash-based storage and connection pooling
    #[cfg(feature = "redis-sessions")]
    Redis(OptimizedRedisStore),
}

/// Cached token record with expiration support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTokenRecord {
    pub record: IntrospectionRecord,
    pub expires_at: u64,
}

/// Optimized Redis store with connection pooling and batching
#[cfg(feature = "redis-sessions")]
#[derive(Clone)]
pub struct OptimizedRedisStore {
    connection_pool: Arc<OnceCell<MultiplexedConnection>>,
}

impl CachedTokenRecord {
    #[must_use]
    pub fn new(record: IntrospectionRecord, ttl_seconds: Option<u64>) -> Self {
        let expires_at = if let Some(ttl) = ttl_seconds {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + ttl
        } else {
            u64::MAX // Never expires
        };

        Self { record, expires_at }
    }

    #[must_use]
    pub fn is_expired(&self) -> bool {
        if self.expires_at == u64::MAX {
            return false;
        }

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            > self.expires_at
    }
}

#[cfg(feature = "redis-sessions")]
impl OptimizedRedisStore {
    /// Create a new optimized Redis store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Redis connection cannot be established
    /// - Connection pool initialization fails
    pub async fn new(_redis_url: &str) -> Result<Self> {
        let store = Self {
            connection_pool: Arc::new(OnceCell::new()),
        };

        // Initialize connection pool
        store.get_connection().await?;
        Ok(store)
    }

    async fn get_connection(&self) -> Result<MultiplexedConnection> {
        let conn = self
            .connection_pool
            .get_or_try_init(|| async {
                let client = redis::Client::open(
                    std::env::var("REDIS_URL")
                        .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
                )?;
                client.get_multiplexed_async_connection().await
            })
            .await?;

        Ok(conn.clone())
    }
}

impl OptimizedTokenStore {
    /// Create a new optimized in-memory token store
    #[must_use]
    pub fn new_in_memory() -> Self {
        Self::InMemory(Arc::new(DashMap::new()))
    }

    /// Create a new optimized Redis token store
    ///
    /// # Errors
    ///
    /// Returns an error if Redis store creation fails
    #[cfg(feature = "redis-sessions")]
    pub async fn new_redis(redis_url: &str) -> Result<Self> {
        let store = OptimizedRedisStore::new(redis_url).await?;
        Ok(Self::Redis(store))
    }

    #[cfg(not(feature = "redis-sessions"))]
    pub async fn new_redis(_redis_url: &str) -> Result<Self> {
        Err(anyhow::anyhow!(
            "Redis support not enabled. Enable 'redis-sessions' feature."
        ))
    }

    /// Get token record with optimized single operation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token is not found in storage
    /// - Redis connection fails
    /// - Deserialization of token data fails
    pub async fn get_record(&self, token: &str) -> Result<IntrospectionRecord> {
        match self {
            Self::InMemory(map) => {
                if let Some(cached) = map.get(token) {
                    if !cached.is_expired() {
                        return Ok(cached.record.clone());
                    }
                    // Remove expired entry
                    map.remove(token);
                }

                // Return default inactive record
                Ok(IntrospectionRecord {
                    token: token.to_string(),
                    active: false,
                    scope: None,
                    client_id: None,
                    username: None,
                    exp: None,
                    iat: None,
                    nbf: None,
                    sub: None,
                    aud: None,
                    iss: None,
                    jti: None,
                    mfa_verified: false,
                    token_type: None,
                    token_binding: None,
                })
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(redis_store) => {
                let mut conn = redis_store.get_connection().await?;
                let key = format!("token:{token}");

                // Single HGETALL operation instead of multiple GETs
                let fields: HashMap<String, String> = redis::cmd("HGETALL")
                    .arg(&key)
                    .query_async(&mut conn)
                    .await?;

                if fields.is_empty() {
                    return Ok(IntrospectionRecord {
                        token: token.to_string(),
                        active: false,
                        scope: None,
                        client_id: None,
                        username: None,
                        exp: None,
                        iat: None,
                        nbf: None,
                        sub: None,
                        aud: None,
                        iss: None,
                        jti: None,
                        mfa_verified: false,
                        token_type: None,
                        token_binding: None,
                    });
                }

                Ok(IntrospectionRecord {
                    token: token.to_string(),
                    active: fields.get("active").is_some_and(|v| v == "1"),
                    scope: fields.get("scope").cloned(),
                    client_id: fields.get("client_id").cloned(),
                    username: fields.get("username").cloned(),
                    exp: fields.get("exp").and_then(|v| v.parse().ok()),
                    iat: fields.get("iat").and_then(|v| v.parse().ok()),
                    nbf: fields.get("nbf").and_then(|v| v.parse().ok()),
                    sub: fields.get("sub").cloned(),
                    aud: fields.get("aud").cloned(),
                    iss: fields.get("iss").cloned(),
                    jti: fields.get("jti").cloned(),
                    mfa_verified: fields.get("mfa_verified").is_some_and(|v| v == "1"),
                    token_type: fields.get("token_type").cloned(),
                    token_binding: fields.get("token_binding").cloned(),
                })
            }
        }
    }

    /// Store complete token data in a single operation
    pub async fn store_token_data(
        &self,
        token: &str,
        record: &IntrospectionRecord,
        ttl_seconds: Option<u64>,
    ) -> Result<()> {
        match self {
            Self::InMemory(map) => {
                let cached = CachedTokenRecord::new(record.clone(), ttl_seconds);
                map.insert(token.to_string(), cached);
                Ok(())
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(redis_store) => {
                let mut conn = redis_store.get_connection().await?;
                let key = format!("token:{token}");

                // Single HMSET operation with all fields
                let mut pipe = redis::pipe();
                pipe.hset(&key, "active", if record.active { "1" } else { "0" });

                if let Some(ref scope) = record.scope {
                    pipe.hset(&key, "scope", scope);
                }
                if let Some(ref client_id) = record.client_id {
                    pipe.hset(&key, "client_id", client_id);
                }
                if let Some(exp) = record.exp {
                    pipe.hset(&key, "exp", exp.to_string());
                }
                if let Some(iat) = record.iat {
                    pipe.hset(&key, "iat", iat.to_string());
                }
                if let Some(ref sub) = record.sub {
                    pipe.hset(&key, "sub", sub);
                }
                if let Some(ref token_binding) = record.token_binding {
                    pipe.hset(&key, "token_binding", token_binding);
                }

                if let Some(ttl) = ttl_seconds {
                    pipe.expire(&key, ttl as i64);
                }

                pipe.query_async::<()>(&mut conn).await?;
                Ok(())
            }
        }
    }

    /// Batch operation for storing multiple tokens
    pub async fn store_tokens_batch(
        &self,
        tokens: &[(String, IntrospectionRecord, Option<u64>)],
    ) -> Result<()> {
        match self {
            Self::InMemory(map) => {
                for (token, record, ttl) in tokens {
                    let cached = CachedTokenRecord::new(record.clone(), *ttl);
                    map.insert(token.clone(), cached);
                }
                Ok(())
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(redis_store) => {
                let mut conn = redis_store.get_connection().await?;
                let mut pipe = redis::pipe();

                for (token, record, ttl) in tokens {
                    let key = format!("token:{token}");

                    pipe.hset(&key, "active", if record.active { "1" } else { "0" });

                    if let Some(ref scope) = record.scope {
                        pipe.hset(&key, "scope", scope);
                    }
                    if let Some(ref client_id) = record.client_id {
                        pipe.hset(&key, "client_id", client_id);
                    }
                    if let Some(exp) = record.exp {
                        pipe.hset(&key, "exp", exp.to_string());
                    }
                    if let Some(iat) = record.iat {
                        pipe.hset(&key, "iat", iat.to_string());
                    }
                    if let Some(ref sub) = record.sub {
                        pipe.hset(&key, "sub", sub);
                    }
                    if let Some(ref token_binding) = record.token_binding {
                        pipe.hset(&key, "token_binding", token_binding);
                    }

                    if let Some(ttl_secs) = ttl {
                        pipe.expire(&key, *ttl_secs as i64);
                    }
                }

                pipe.query_async::<()>(&mut conn).await?;
                Ok(())
            }
        }
    }

    /// Optimized revoke operation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Redis connection fails
    /// - Token update operation fails
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        match self {
            Self::InMemory(map) => {
                if let Some(mut cached) = map.get_mut(token) {
                    cached.record.active = false;
                }
                Ok(())
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(redis_store) => {
                let mut conn = redis_store.get_connection().await?;
                let key = format!("token:{token}");

                // Just set active to false instead of deleting
                redis::cmd("HSET")
                    .arg(&key)
                    .arg("active")
                    .arg("0")
                    .query_async::<()>(&mut conn)
                    .await?;

                Ok(())
            }
        }
    }

    /// Batch revoke operation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Redis connection fails
    /// - Batch token update operation fails
    pub async fn revoke_tokens_batch(&self, tokens: &[String]) -> Result<()> {
        match self {
            Self::InMemory(map) => {
                for token in tokens {
                    if let Some(mut cached) = map.get_mut(token) {
                        cached.record.active = false;
                    }
                }
                Ok(())
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(redis_store) => {
                let mut conn = redis_store.get_connection().await?;
                let mut pipe = redis::pipe();

                for token in tokens {
                    let key = format!("token:{token}");
                    pipe.hset(&key, "active", "0");
                }

                pipe.query_async::<()>(&mut conn).await?;
                Ok(())
            }
        }
    }

    /// Cleanup expired tokens (for in-memory store)
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup operation fails (Redis errors are ignored)
    pub async fn cleanup_expired(&self) -> Result<usize> {
        match self {
            Self::InMemory(map) => {
                let mut removed_count = 0;
                let _now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                map.retain(|_key, cached| {
                    if cached.is_expired() {
                        removed_count += 1;
                        false
                    } else {
                        true
                    }
                });

                Ok(removed_count)
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(_) => {
                // Redis handles expiration automatically
                Ok(0)
            }
        }
    }

    /// Get store statistics
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Redis connection fails
    /// - Statistics gathering operation fails
    pub async fn get_stats(&self) -> Result<TokenStoreStats> {
        match self {
            Self::InMemory(map) => {
                let total_tokens = map.len();
                let mut active_tokens = 0;
                let mut expired_tokens = 0;

                for entry in map.iter() {
                    if entry.is_expired() {
                        expired_tokens += 1;
                    } else if entry.record.active {
                        active_tokens += 1;
                    }
                }

                Ok(TokenStoreStats {
                    total_tokens,
                    active_tokens,
                    expired_tokens,
                    store_type: "in_memory".to_string(),
                })
            }
            #[cfg(feature = "redis-sessions")]
            Self::Redis(redis_store) => {
                let mut conn = redis_store.get_connection().await?;

                // Get approximate count of tokens
                let keys: Vec<String> = redis::cmd("KEYS")
                    .arg("token:*")
                    .query_async(&mut conn)
                    .await?;

                let total_tokens = keys.len();

                // Count active tokens (this is expensive, consider caching)
                let mut active_tokens = 0;
                for key in &keys {
                    if let Ok(active) = redis::cmd("HGET")
                        .arg(key)
                        .arg("active")
                        .query_async::<String>(&mut conn)
                        .await
                    {
                        if active == "1" {
                            active_tokens += 1;
                        }
                    }
                }

                Ok(TokenStoreStats {
                    total_tokens,
                    active_tokens,
                    expired_tokens: 0, // Redis auto-expires
                    store_type: "redis".to_string(),
                })
            }
        }
    }
}

/// Token store statistics
#[derive(Debug, Clone, Serialize)]
pub struct TokenStoreStats {
    pub total_tokens: usize,
    pub active_tokens: usize,
    pub expired_tokens: usize,
    pub store_type: String,
}

/// Background task for cleaning up expired tokens in in-memory store
pub async fn start_cleanup_task(store: OptimizedTokenStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // Every 5 minutes

    loop {
        interval.tick().await;

        if let Err(e) = store.cleanup_expired().await {
            tracing::warn!("Failed to cleanup expired tokens: {}", e);
        } else {
            tracing::debug!("Token cleanup completed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_optimized_in_memory_store() {
        let store = OptimizedTokenStore::new_in_memory();

        let record = IntrospectionRecord {
            token: "test_token".to_string(),
            active: true,
            scope: Some("read write".to_string()),
            client_id: Some("test-client".to_string()),
            username: Some("test-user".to_string()),
            exp: Some(1_234_567_890),
            iat: Some(1_234_567_890),
            nbf: None,
            sub: Some("test-user".to_string()),
            aud: None,
            iss: None,
            jti: None,
            mfa_verified: false,
            token_type: Some("Bearer".to_string()),
            token_binding: None,
        };

        // Test single storage
        store
            .store_token_data("test_token", &record, Some(3600))
            .await
            .unwrap();

        // Test retrieval
        let retrieved = store.get_record("test_token").await.unwrap();
        assert!(retrieved.active);
        assert_eq!(retrieved.client_id, Some("test-client".to_string()));

        // Test batch storage
        let batch = vec![
            ("batch_token_1".to_string(), record.clone(), Some(3600)),
            ("batch_token_2".to_string(), record.clone(), Some(3600)),
        ];
        store.store_tokens_batch(&batch).await.unwrap();

        // Test batch revoke
        store
            .revoke_tokens_batch(&["batch_token_1".to_string()])
            .await
            .unwrap();
        let revoked = store.get_record("batch_token_1").await.unwrap();
        assert!(!revoked.active);

        // Test stats
        let stats = store.get_stats().await.unwrap();
        assert!(stats.total_tokens >= 3);
    }

    #[tokio::test]
    async fn test_cached_token_record_expiration() {
        let record = IntrospectionRecord {
            token: "test_token".to_string(),
            active: true,
            scope: None,
            client_id: None,
            username: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            mfa_verified: false,
            token_type: None,
            token_binding: None,
        };

        // Test non-expiring record
        let non_expiring = CachedTokenRecord::new(record.clone(), None);
        assert!(!non_expiring.is_expired());

        // Test expiring record (1 second TTL)
        let expiring = CachedTokenRecord::new(record.clone(), Some(1));
        assert!(!expiring.is_expired());

        // Wait and check expiration
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(expiring.is_expired());
    }
}
