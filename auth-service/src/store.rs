use async_trait::async_trait;
use common::{AuthCodeRecord, ScimGroup, ScimUser, Store, TokenRecord};
use deadpool_redis::{redis::AsyncCommands, Config, Pool, Runtime};
use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// This new struct encapsulates all storage logic.
// It maintains the original behavior: in-memory for users/groups,
// and a hybrid in-memory/Redis for tokens and auth codes.
#[derive(Clone)]
pub struct HybridStore {
    // Redis connection pool with deadpool for high performance
    redis_pool: Option<Pool>,
    // In-memory stores for users/groups (will migrate to SQL in production)
    users: Arc<RwLock<HashMap<String, ScimUser>>>,
    groups: Arc<RwLock<HashMap<String, ScimGroup>>>,
    // Fallback in-memory stores for when Redis is unavailable
    auth_codes: Arc<RwLock<HashMap<String, String>>>,
    tokens: Arc<RwLock<HashMap<String, TokenRecord>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, String>>>, // Maps refresh_token -> access_token
    refresh_reuse_markers: Arc<RwLock<HashMap<String, ()>>>, // To detect reuse
}

impl HybridStore {
    pub async fn new() -> Self {
        let redis_pool = Self::create_redis_pool().await;

        Self {
            redis_pool,
            users: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_reuse_markers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn create_redis_pool() -> Option<Pool> {
        let redis_url = std::env::var("REDIS_URL").ok()?;

        info!("Initializing Redis connection pool");

        let config = Config::from_url(&redis_url);
        let pool = config.create_pool(Some(Runtime::Tokio1)).ok()?;

        // Test the connection
        match pool.get().await {
            Ok(_conn) => {
                info!("Redis connection pool initialized successfully");
                Some(pool)
            }
            Err(e) => {
                error!("Failed to get Redis connection from pool: {}", e);
                None
            }
        }
    }

    async fn get_redis_connection(&self) -> Option<deadpool_redis::Connection> {
        match &self.redis_pool {
            Some(pool) => match pool.get().await {
                Ok(conn) => Some(conn),
                Err(e) => {
                    warn!("Failed to get Redis connection from pool: {}", e);
                    None
                }
            },
            None => None,
        }
    }
}

#[async_trait]
impl Store for HybridStore {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // === User Management (In-Memory) ===
    async fn get_user(
        &self,
        id: &str,
    ) -> Result<Option<ScimUser>, Box<dyn StdError + Send + Sync>> {
        Ok(self.users.read().await.get(id).cloned())
    }

    async fn create_user(
        &self,
        user: &ScimUser,
    ) -> Result<ScimUser, Box<dyn StdError + Send + Sync>> {
        let mut u = user.clone();
        if u.id.is_empty() {
            u.id = uuid::Uuid::new_v4().to_string();
        }
        self.users.write().await.insert(u.id.clone(), u.clone());
        Ok(u)
    }

    async fn list_users(
        &self,
        _filter: Option<&str>,
    ) -> Result<Vec<ScimUser>, Box<dyn StdError + Send + Sync>> {
        // Note: The original filter logic was complex and tied to the handler.
        // For this refactoring, we'll return all users and expect filtering to happen at a higher level.
        Ok(self.users.read().await.values().cloned().collect())
    }

    async fn update_user(
        &self,
        user: &ScimUser,
    ) -> Result<ScimUser, Box<dyn StdError + Send + Sync>> {
        self.users
            .write()
            .await
            .insert(user.id.clone(), user.clone());
        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
        self.users.write().await.remove(id);
        Ok(())
    }

    // === Group Management (In-Memory) ===
    async fn get_group(
        &self,
        id: &str,
    ) -> Result<Option<ScimGroup>, Box<dyn StdError + Send + Sync>> {
        Ok(self.groups.read().await.get(id).cloned())
    }

    async fn create_group(
        &self,
        group: &ScimGroup,
    ) -> Result<ScimGroup, Box<dyn StdError + Send + Sync>> {
        let mut g = group.clone();
        if g.id.is_empty() {
            g.id = uuid::Uuid::new_v4().to_string();
        }
        self.groups.write().await.insert(g.id.clone(), g.clone());
        Ok(g)
    }

    async fn list_groups(
        &self,
        _filter: Option<&str>,
    ) -> Result<Vec<ScimGroup>, Box<dyn StdError + Send + Sync>> {
        Ok(self.groups.read().await.values().cloned().collect())
    }

    async fn update_group(
        &self,
        group: &ScimGroup,
    ) -> Result<ScimGroup, Box<dyn StdError + Send + Sync>> {
        self.groups
            .write()
            .await
            .insert(group.id.clone(), group.clone());
        Ok(group.clone())
    }

    async fn delete_group(&self, id: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
        self.groups.write().await.remove(id);
        Ok(())
    }

    // === Auth Code Management (Hybrid) ===
    async fn set_auth_code(
        &self,
        code: &str,
        record: &AuthCodeRecord,
        ttl_secs: u64,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        let record_json = serde_json::to_string(record)?;

        // Store in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("authcode:{}", code);
            // Use the simpler Redis interface
            let result: Result<(), _> = {
                let set_result = conn.set::<_, _, ()>(&key, &record_json).await;
                if set_result.is_ok() {
                    conn.expire(&key, ttl_secs as i64).await
                } else {
                    set_result
                }
            };

            match result {
                Ok(_) => {
                    // Successfully stored in Redis, also store in memory as backup
                    self.auth_codes
                        .write()
                        .await
                        .insert(code.to_string(), record_json);
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to store auth code in Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        warn!("Storing auth code in memory as fallback");
        self.auth_codes
            .write()
            .await
            .insert(code.to_string(), record_json);
        Ok(())
    }

    async fn consume_auth_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthCodeRecord>, Box<dyn StdError + Send + Sync>> {
        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("authcode:{}", code);
            match conn.get::<_, Option<String>>(&key).await {
                Ok(Some(json)) => {
                    // Delete the key and remove from memory backup
                    let _: Result<(), _> = conn.del(&key).await;
                    self.auth_codes.write().await.remove(code);
                    return Ok(serde_json::from_str(&json)?);
                }
                Ok(None) => {
                    // Not found in Redis, try memory fallback
                }
                Err(e) => {
                    warn!("Failed to consume auth code from Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        if let Some(json) = self.auth_codes.write().await.remove(code) {
            Ok(serde_json::from_str(&json)?)
        } else {
            Ok(None)
        }
    }

    // === Token Management (Hybrid) ===
    async fn get_token_record(
        &self,
        token: &str,
    ) -> Result<Option<TokenRecord>, Box<dyn StdError + Send + Sync>> {
        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("token_record:{}", token);
            match conn.get::<_, Option<String>>(&key).await {
                Ok(Some(json)) => {
                    return Ok(serde_json::from_str(&json)?);
                }
                Ok(None) => {
                    // Not found in Redis, try memory fallback
                }
                Err(e) => {
                    warn!("Failed to get token record from Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory
        Ok(self.tokens.read().await.get(token).cloned())
    }

    async fn set_token_record(
        &self,
        token: &str,
        record: &TokenRecord,
        ttl_secs: Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let record_json = serde_json::to_string(record)?;

        // Store in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("token_record:{}", token);
            let redis_result = if let Some(ttl) = ttl_secs {
                {
                    let set_result = conn.set::<_, _, ()>(&key, &record_json).await;
                    if set_result.is_ok() {
                        let _: Result<(), _> = conn.expire(&key, ttl as i64).await;
                    }
                    set_result
                }
            } else {
                conn.set::<_, _, ()>(&key, &record_json).await
            };

            match redis_result {
                Ok(_) => {
                    // Successfully stored in Redis, also store in memory as backup
                    self.tokens
                        .write()
                        .await
                        .insert(token.to_string(), record.clone());
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to store token record in Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        warn!("Storing token record in memory as fallback");
        self.tokens
            .write()
            .await
            .insert(token.to_string(), record.clone());
        Ok(())
    }

    async fn revoke_token(
        &self,
        token: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(mut record) = self.get_token_record(token).await? {
            record.active = false;
            self.set_token_record(token, &record, None).await?;
        }
        Ok(())
    }

    // === Refresh Token Management (Hybrid) ===
    async fn set_refresh_token_association(
        &self,
        refresh_token: &str,
        access_token: &str,
        ttl_secs: u64,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // Store in Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("refresh_token:{}", refresh_token);
            match {
                let set_result = conn.set::<_, _, ()>(&key, access_token).await;
                if set_result.is_ok() {
                    let _: Result<(), _> = conn.expire(&key, ttl_secs as i64).await;
                }
                set_result
            } {
                Ok(_) => {
                    // Successfully stored in Redis, also store in memory as backup
                    self.refresh_tokens
                        .write()
                        .await
                        .insert(refresh_token.to_string(), access_token.to_string());
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to store refresh token in Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage
        warn!("Storing refresh token in memory as fallback");
        self.refresh_tokens
            .write()
            .await
            .insert(refresh_token.to_string(), access_token.to_string());
        Ok(())
    }

    async fn consume_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<String>, Box<dyn StdError + Send + Sync>> {
        let mut access_token: Option<String> = None;

        // Try Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("refresh_token:{}", refresh_token);
            match conn.get::<_, Option<String>>(&key).await {
                Ok(token) => {
                    if token.is_some() {
                        let _: Result<(), _> = conn.del(&key).await;
                    }
                    access_token = token;
                    // Also remove from memory backup
                    self.refresh_tokens.write().await.remove(refresh_token);
                }
                Err(e) => {
                    warn!("Failed to consume refresh token from Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory storage if Redis failed or returned None
        if access_token.is_none() {
            access_token = self.refresh_tokens.write().await.remove(refresh_token);
        }

        if access_token.is_some() {
            // Mark as reused for security monitoring
            self.refresh_reuse_markers
                .write()
                .await
                .insert(refresh_token.to_string(), ());

            if let Some(mut conn) = self.get_redis_connection().await {
                let key = format!("refresh_reused:{}", refresh_token);
                // Reuse detection window 10 minutes
                let _: Result<(), _> = {
                    let set_result = conn.set::<_, _, ()>(&key, 1).await;
                    if set_result.is_ok() {
                        let _: Result<(), _> = conn.expire(&key, 600i64).await;
                    }
                    set_result
                };
            }
        }

        Ok(access_token)
    }

    async fn is_refresh_reused(
        &self,
        refresh_token: &str,
    ) -> Result<bool, Box<dyn StdError + Send + Sync>> {
        // Check Redis first (primary storage)
        if let Some(mut conn) = self.get_redis_connection().await {
            let key = format!("refresh_reused:{}", refresh_token);
            match conn.exists::<_, bool>(&key).await {
                Ok(exists) => return Ok(exists),
                Err(e) => {
                    warn!("Failed to check refresh token reuse in Redis: {}", e);
                }
            }
        }

        // Fallback to in-memory check
        Ok(self
            .refresh_reuse_markers
            .read()
            .await
            .contains_key(refresh_token))
    }

    // === Health Check ===
    async fn health_check(&self) -> Result<bool, Box<dyn StdError + Send + Sync>> {
        if let Some(_conn) = self.get_redis_connection().await {
            Ok(true) // Successfully got Redis connection
        } else {
            // In-memory store is always healthy, but Redis is unavailable
            Ok(true)
        }
    }

    async fn get_metrics(&self) -> Result<common::StoreMetrics, Box<dyn StdError + Send + Sync>> {
        let users_total = self.users.read().await.len() as u64;
        let groups_total = self.groups.read().await.len() as u64;

        // Use in-memory counts for metrics (Redis SCAN has trait bound issues with deadpool)
        let tokens = self.tokens.read().await;
        let tokens_total = tokens.len() as u64;
        let active_tokens = tokens.values().filter(|r| r.active).count() as u64;
        let auth_codes_total = self.auth_codes.read().await.len() as u64;

        Ok(common::StoreMetrics {
            users_total,
            groups_total,
            tokens_total,
            active_tokens,
            auth_codes_total,
        })
    }
}
