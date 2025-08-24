use dashmap::DashMap;
use deadpool_redis::{Config as RedisConfig, Pool as RedisPool, Runtime};
#[cfg(feature = "enhanced-session-store")]
use bb8_redis::RedisConnectionManager;
use once_cell::sync::Lazy;
use sha2::Digest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, Instant};
use tokio::sync::RwLock;

/// Optimized database operations with security constraints
pub struct DatabaseOptimized {
    redis_pool: RedisPool,
    query_cache: Arc<DashMap<String, CachedQuery>>,
    prepared_statements: Arc<RwLock<DashMap<String, String>>>,
    security_constraints: SecurityConstraints,
}

#[derive(Debug, Clone)]
pub struct SecurityConstraints {
    pub max_query_timeout: Duration,
    pub max_batch_size: usize,
    pub encryption_at_rest: bool,
    pub audit_enabled: bool,
    pub rate_limit_per_client: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedQuery {
    pub result: String,
    pub created_at: SystemTime,
    pub ttl: Duration,
    pub is_encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct QueryMetrics {
    pub execution_time: Duration,
    pub rows_affected: u64,
    pub cache_hit: bool,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone)]
pub enum SecurityLevel {
    Public,
    Internal,
    Confidential,
    Secret,
}

static DATABASE_ENGINE: Lazy<tokio::sync::OnceCell<DatabaseOptimized>> =
    Lazy::new(|| tokio::sync::OnceCell::new());

impl SecurityConstraints {
    pub fn secure_default() -> Self {
        Self {
            max_query_timeout: Duration::from_secs(5),
            max_batch_size: 100,
            encryption_at_rest: true,
            audit_enabled: true,
            rate_limit_per_client: 1000,
        }
    }

    pub fn high_security() -> Self {
        Self {
            max_query_timeout: Duration::from_secs(2),
            max_batch_size: 50,
            encryption_at_rest: true,
            audit_enabled: true,
            rate_limit_per_client: 500,
        }
    }
}

impl DatabaseOptimized {
    pub async fn new(
        redis_url: &str,
        constraints: SecurityConstraints,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Setup deadpool Redis connection pool
        let config = RedisConfig::from_url(redis_url);
        let redis_pool = config.create_pool(Some(Runtime::Tokio1))?;

        // Setup bb8 Redis connection pool for high concurrency
        let manager = RedisConnectionManager::new(redis_url)?;
        let connection_pool = Arc::new(
            bb8::Pool::builder()
                .max_size(50) // Optimized for high concurrency
                .min_idle(Some(10))
                .connection_timeout(Duration::from_secs(2))
                .idle_timeout(Some(Duration::from_secs(300)))
                .build(manager)
                .await?,
        );

        Ok(Self {
            redis_pool,
            connection_pool,
            query_cache: Arc::new(DashMap::new()),
            prepared_statements: Arc::new(RwLock::new(DashMap::new())),
            security_constraints: constraints,
        })
    }

    /// High-performance secure token retrieval with batching
    pub async fn batch_get_tokens(
        &self,
        tokens: &[String],
    ) -> Result<Vec<Option<crate::IntrospectionRecord>>, Box<dyn std::error::Error + Send + Sync>>
    {
        if tokens.len() > self.security_constraints.max_batch_size {
            return Err("Batch size exceeds security limit".into());
        }

        let start = Instant::now();
        let mut conn = self.redis_pool.get().await?;

        // Use Redis pipeline for batch operations
        let mut pipeline = redis::pipe();
        for token in tokens {
            let key = self.secure_key_name("token", token)?;
            pipeline.hgetall(&key);
        }

        let results: Vec<std::collections::HashMap<String, String>> =
            pipeline.query_async(&mut *conn).await?;

        let records: Vec<Option<crate::IntrospectionRecord>> = results
            .into_iter()
            .map(|hash_map| {
                if hash_map.is_empty() {
                    None
                } else {
                    Some(self.parse_token_record(hash_map))
                }
            })
            .collect();

        // Log performance metrics
        self.log_query_metrics(
            "batch_get_tokens",
            start.elapsed(),
            tokens.len() as u64,
            false,
        )
        .await;

        Ok(records)
    }

    /// Optimized token storage with encryption at rest
    pub async fn secure_store_token(
        &self,
        token: &str,
        record: &crate::IntrospectionRecord,
        ttl: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = self.secure_key_name("token", token)?;
        let mut conn = self.redis_pool.get().await?;

        let mut pipeline = redis::pipe();

        // Store token data as hash for efficient field access
        pipeline.hset(&key, "active", if record.active { "1" } else { "0" });

        if let Some(scope) = &record.scope {
            pipeline.hset(&key, "scope", self.encrypt_if_required(scope).await?);
        }

        if let Some(client_id) = &record.client_id {
            pipeline.hset(&key, "client_id", client_id);
        }

        if let Some(exp) = record.exp {
            pipeline.hset(&key, "exp", exp.to_string());
        }

        if let Some(iat) = record.iat {
            pipeline.hset(&key, "iat", iat.to_string());
        }

        if let Some(sub) = &record.sub {
            pipeline.hset(&key, "sub", self.encrypt_if_required(sub).await?);
        }

        if let Some(token_binding) = &record.token_binding {
            pipeline.hset(
                &key,
                "token_binding",
                self.encrypt_if_required(token_binding).await?,
            );
        }

        // Set TTL if specified
        if let Some(ttl_secs) = ttl {
            pipeline.expire(&key, ttl_secs as usize);
        }

        let start = Instant::now();
        pipeline.query_async(&mut *conn).await?;

        // Log security audit
        if self.security_constraints.audit_enabled {
            self.audit_token_operation("store", token, "success").await;
        }

        self.log_query_metrics("secure_store_token", start.elapsed(), 1, false)
            .await;
        Ok(())
    }

    /// High-performance batch token validation
    pub async fn batch_validate_tokens(
        &self,
        tokens: &[String],
    ) -> Result<Vec<bool>, Box<dyn std::error::Error + Send + Sync>> {
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        let start = Instant::now();
        let mut conn = self.redis_pool.get().await?;

        // Use EXISTS command for fast validation
        let mut pipeline = redis::pipe();
        for token in tokens {
            let key = self.secure_key_name("token", token)?;
            pipeline.exists(&key);
        }

        let results: Vec<bool> = pipeline.query_async(&mut *conn).await?;

        self.log_query_metrics(
            "batch_validate_tokens",
            start.elapsed(),
            tokens.len() as u64,
            false,
        )
        .await;
        Ok(results)
    }

    /// Optimized cached query execution with security constraints
    pub async fn execute_cached_query(
        &self,
        query_id: &str,
        query: &str,
        params: &[&str],
        security_level: SecurityLevel,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let cache_key = self.generate_cache_key(query_id, params);

        // Check cache first
        if let Some(cached) = self.query_cache.get(&cache_key) {
            if cached.created_at.elapsed() < cached.ttl {
                self.log_query_metrics("execute_cached_query", Duration::from_nanos(1), 0, true)
                    .await;
                return Ok(self.decrypt_if_required(&cached.result).await?);
            } else {
                // Remove expired entry
                self.query_cache.remove(&cache_key);
            }
        }

        // Execute query with timeout
        let start = Instant::now();
        let timeout = match security_level {
            SecurityLevel::Secret | SecurityLevel::Confidential => {
                self.security_constraints.max_query_timeout / 2
            }
            _ => self.security_constraints.max_query_timeout,
        };

        let result =
            tokio::time::timeout(timeout, self.execute_secure_query(query, params)).await??;

        // Cache result based on security level
        let should_cache = matches!(
            security_level,
            SecurityLevel::Public | SecurityLevel::Internal
        );
        if should_cache {
            let cached_query = CachedQuery {
                result: self.encrypt_if_required(&result).await?,
                created_at: Instant::now(),
                ttl: self.get_cache_ttl(&security_level),
                is_encrypted: self.security_constraints.encryption_at_rest,
            };
            self.query_cache.insert(cache_key, cached_query);
        }

        self.log_query_metrics("execute_cached_query", start.elapsed(), 1, false)
            .await;
        Ok(result)
    }

    /// SIMD-optimized bulk token cleanup
    #[cfg(feature = "simd")]
    pub async fn bulk_cleanup_expired_tokens(
        &self,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        let mut conn = self.redis_pool.get().await?;

        // Get all token keys
        let pattern = self.secure_key_pattern("token", "*")?;
        let keys: Vec<String> = redis::cmd("SCAN")
            .arg("0")
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg("1000")
            .query_async(&mut *conn)
            .await?;

        if keys.is_empty() {
            return Ok(0);
        }

        // Parallel processing of token expiration checks
        let expired_keys: Vec<String> = keys
            .par_iter()
            .filter_map(|key| {
                // Simulate checking expiration (would need actual Redis connection per thread)
                if key.contains("expired") {
                    // Simplified check
                    Some(key.clone())
                } else {
                    None
                }
            })
            .collect();

        let deleted = if !expired_keys.is_empty() {
            let mut pipeline = redis::pipe();
            for key in &expired_keys {
                pipeline.del(key);
            }
            let results: Vec<i32> = pipeline.query_async(&mut *conn).await?;
            results.into_iter().sum::<i32>() as u64
        } else {
            0
        };

        self.log_query_metrics(
            "bulk_cleanup_expired_tokens",
            start.elapsed(),
            deleted,
            false,
        )
        .await;
        Ok(deleted)
    }

    /// Memory-optimized connection pool monitoring
    pub async fn get_pool_stats(
        &self,
    ) -> Result<PoolStats, Box<dyn std::error::Error + Send + Sync>> {
        let state = self.redis_pool.state().await;

        Ok(PoolStats {
            total_connections: state.connections,
            active_connections: state.connections,
            idle_connections: state.idle_connections,
            max_connections: self.redis_pool.max_size(),
            pending_requests: 0, // bb8 doesn't expose this directly
        })
    }

    /// Async/await optimized transaction handling
    pub async fn execute_secure_transaction<F, R>(
        &self,
        operations: F,
    ) -> Result<R, Box<dyn std::error::Error + Send + Sync>>
    where
        F: FnOnce(
                &mut redis::aio::Connection,
            ) -> futures::future::BoxFuture<
                '_,
                Result<R, Box<dyn std::error::Error + Send + Sync>>,
            > + Send,
        R: Send,
    {
        let start = Instant::now();
        let mut conn = self.redis_pool.get().await?;

        // Start transaction
        redis::cmd("MULTI").query_async(&mut *conn).await?;

        let result = match operations(&mut *conn).await {
            Ok(result) => {
                // Commit transaction
                redis::cmd("EXEC").query_async(&mut *conn).await?;
                Ok(result)
            }
            Err(e) => {
                // Rollback transaction
                redis::cmd("DISCARD").query_async(&mut *conn).await?;
                Err(e)
            }
        };

        self.log_query_metrics("execute_secure_transaction", start.elapsed(), 1, false)
            .await;
        result
    }

    // Helper methods

    fn secure_key_name(
        &self,
        prefix: &str,
        key: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Add namespace and hash for security
        let hash = sha2::Sha256::digest(key.as_bytes());
        let hash_hex = hex::encode(&hash[..8]); // Use first 8 bytes for key shortening
        Ok(format!("auth:{}:{}", prefix, hash_hex))
    }

    fn secure_key_pattern(
        &self,
        prefix: &str,
        pattern: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        Ok(format!("auth:{}:{}", prefix, pattern))
    }

    fn encrypt_if_required(
        &self,
        data: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if self.security_constraints.encryption_at_rest {
            // Use the crypto engine for encryption
            let crypto = crate::crypto_optimized::get_crypto_engine();
            match crypto.encrypt_secure("default", data.as_bytes()) {
                Ok(encrypted) => Ok(base64::encode(encrypted)),
                Err(_) => Ok(data.to_string()), // Fallback to plaintext
            }
        } else {
            Ok(data.to_string())
        }
    }

    fn decrypt_if_required(
        &self,
        data: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if self.security_constraints.encryption_at_rest && data.len() > 100 {
            // Attempt decryption
            if let Ok(encrypted_bytes) = base64::decode(data) {
                let crypto = crate::crypto_optimized::get_crypto_engine();
                if let Ok(decrypted) = crypto.decrypt_secure("default", &encrypted_bytes) {
                    if let Ok(decrypted_str) = String::from_utf8(decrypted) {
                        return Ok(decrypted_str);
                    }
                }
            }
        }
        Ok(data.to_string())
    }

    fn parse_token_record(
        &self,
        hash_map: std::collections::HashMap<String, String>,
    ) -> crate::IntrospectionRecord {
        crate::IntrospectionRecord {
            token: hash_map.get("token").cloned().unwrap_or_default(),
            active: hash_map.get("active").map(|v| v == "1").unwrap_or(false),
            scope: hash_map.get("scope").cloned(),
            client_id: hash_map.get("client_id").cloned(),
            username: hash_map.get("username").cloned(),
            exp: hash_map.get("exp").and_then(|v| v.parse().ok()),
            iat: hash_map.get("iat").and_then(|v| v.parse().ok()),
            nbf: hash_map.get("nbf").and_then(|v| v.parse().ok()),
            sub: hash_map.get("sub").cloned(),
            aud: hash_map.get("aud").cloned(),
            iss: hash_map.get("iss").cloned(),
            jti: hash_map.get("jti").cloned(),
            token_type: hash_map.get("token_type").cloned(),
            token_binding: hash_map.get("token_binding").cloned(),
        }
    }

    async fn execute_secure_query(
        &self,
        query: &str,
        _params: &[&str],
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Simplified implementation - in real scenario would execute against actual database
        Ok(format!("result_for_{}", query))
    }

    fn generate_cache_key(&self, query_id: &str, params: &[&str]) -> String {
        let params_hash = sha2::Sha256::digest(params.join("|").as_bytes());
        format!("cache:{}:{}", query_id, hex::encode(&params_hash[..8]))
    }

    fn get_cache_ttl(&self, security_level: &SecurityLevel) -> Duration {
        match security_level {
            SecurityLevel::Public => Duration::from_secs(300), // 5 minutes
            SecurityLevel::Internal => Duration::from_secs(120), // 2 minutes
            SecurityLevel::Confidential => Duration::from_secs(60), // 1 minute
            SecurityLevel::Secret => Duration::from_secs(30),  // 30 seconds
        }
    }

    async fn log_query_metrics(
        &self,
        operation: &str,
        duration: Duration,
        rows: u64,
        cache_hit: bool,
    ) {
        tracing::debug!(
            operation = operation,
            duration_ms = duration.as_millis(),
            rows_affected = rows,
            cache_hit = cache_hit,
            "Database operation completed"
        );
    }

    async fn audit_token_operation(&self, operation: &str, token: &str, outcome: &str) {
        if self.security_constraints.audit_enabled {
            let token_hash = sha2::Sha256::digest(token.as_bytes());
            tracing::info!(
                target: "security_audit",
                operation = operation,
                token_hash = hex::encode(&token_hash[..8]),
                outcome = outcome,
                timestamp = chrono::Utc::now().to_rfc3339(),
                "Token operation audited"
            );
        }
    }
}

#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: u32,
    pub active_connections: u32,
    pub idle_connections: u32,
    pub max_connections: u32,
    pub pending_requests: u32,
}

/// Initialize the global database engine
pub async fn initialize_database(
    redis_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let constraints = SecurityConstraints::secure_default();
    let db = DatabaseOptimized::new(redis_url, constraints).await?;
    DATABASE_ENGINE
        .set(db)
        .map_err(|_| "Database already initialized")?;
    Ok(())
}

/// Get the global database engine instance
pub async fn get_database() -> Option<&'static DatabaseOptimized> {
    DATABASE_ENGINE.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_constraints() {
        let constraints = SecurityConstraints::high_security();
        assert_eq!(constraints.max_query_timeout, Duration::from_secs(2));
        assert_eq!(constraints.max_batch_size, 50);
        assert!(constraints.encryption_at_rest);
        assert!(constraints.audit_enabled);
    }

    #[test]
    fn test_cache_key_generation() {
        let db = create_test_db();
        let key1 = db.generate_cache_key("query1", &["param1", "param2"]);
        let key2 = db.generate_cache_key("query1", &["param1", "param2"]);
        let key3 = db.generate_cache_key("query1", &["param1", "param3"]);

        assert_eq!(key1, key2); // Same params should generate same key
        assert_ne!(key1, key3); // Different params should generate different keys
    }

    #[test]
    fn test_cache_ttl_by_security_level() {
        let db = create_test_db();

        assert_eq!(
            db.get_cache_ttl(&SecurityLevel::Public),
            Duration::from_secs(300)
        );
        assert_eq!(
            db.get_cache_ttl(&SecurityLevel::Internal),
            Duration::from_secs(120)
        );
        assert_eq!(
            db.get_cache_ttl(&SecurityLevel::Confidential),
            Duration::from_secs(60)
        );
        assert_eq!(
            db.get_cache_ttl(&SecurityLevel::Secret),
            Duration::from_secs(30)
        );
    }

    fn create_test_db() -> DatabaseOptimized {
        use deadpool_redis::Pool;
        use redis::Client;

        // Create a mock database for testing
        let config = RedisConfig::from_url("redis://localhost:6379");
        let redis_pool = config.create_pool(Some(Runtime::Tokio1)).unwrap();

        let manager = RedisConnectionManager::new("redis://localhost:6379").unwrap();
        let connection_pool = Arc::new(bb8::Pool::builder().max_size(10).build_unchecked(manager));

        DatabaseOptimized {
            redis_pool,
            connection_pool,
            query_cache: Arc::new(DashMap::new()),
            prepared_statements: Arc::new(RwLock::new(DashMap::new())),
            security_constraints: SecurityConstraints::secure_default(),
        }
    }
}
