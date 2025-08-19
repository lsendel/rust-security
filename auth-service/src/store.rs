use anyhow::Result;
use async_trait::async_trait;
use common::{AuthCodeRecord, ScimGroup, ScimUser, Store, TokenRecord};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// This new struct encapsulates all storage logic.
// It maintains the original behavior: in-memory for users/groups,
// and a hybrid in-memory/Redis for tokens and auth codes.
#[derive(Clone)]
pub struct HybridStore {
    // Redis connection, optional
    redis: Option<redis::aio::ConnectionManager>,
    // In-memory stores
    users: Arc<RwLock<HashMap<String, ScimUser>>>,
    groups: Arc<RwLock<HashMap<String, ScimGroup>>>,
    auth_codes: Arc<RwLock<HashMap<String, String>>>,
    tokens: Arc<RwLock<HashMap<String, TokenRecord>>>,
    refresh_tokens: Arc<RwLock<HashMap<String, String>>>, // Maps refresh_token -> access_token
    refresh_reuse_markers: Arc<RwLock<HashMap<String, ()>>>, // To detect reuse
}

impl HybridStore {
    pub async fn new() -> Self {
        let redis_url = std::env::var("REDIS_URL").ok();
        let redis = if let Some(url) = redis_url {
            if let Ok(client) = redis::Client::open(url) {
                client.get_connection_manager().await.ok()
            } else {
                None
            }
        } else {
            None
        };

        Self {
            redis,
            users: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            auth_codes: Arc::new(RwLock::new(HashMap::new())),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_reuse_markers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn redis_conn(&self) -> Option<redis::aio::ConnectionManager> {
        self.redis.clone()
    }
}

#[async_trait]
impl Store for HybridStore {
    // === User Management (In-Memory) ===
    async fn get_user(&self, id: &str) -> Result<Option<ScimUser>> {
        Ok(self.users.read().await.get(id).cloned())
    }

    async fn create_user(&self, user: &ScimUser) -> Result<ScimUser> {
        let mut u = user.clone();
        if u.id.is_empty() {
            u.id = uuid::Uuid::new_v4().to_string();
        }
        self.users.write().await.insert(u.id.clone(), u.clone());
        Ok(u)
    }

    async fn list_users(&self, _filter: Option<&str>) -> Result<Vec<ScimUser>> {
        // Note: The original filter logic was complex and tied to the handler.
        // For this refactoring, we'll return all users and expect filtering to happen at a higher level.
        Ok(self.users.read().await.values().cloned().collect())
    }

    async fn update_user(&self, user: &ScimUser) -> Result<ScimUser> {
        self.users.write().await.insert(user.id.clone(), user.clone());
        Ok(user.clone())
    }

    async fn delete_user(&self, id: &str) -> Result<()> {
        self.users.write().await.remove(id);
        Ok(())
    }

    // === Group Management (In-Memory) ===
    async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>> {
        Ok(self.groups.read().await.get(id).cloned())
    }

    async fn create_group(&self, group: &ScimGroup) -> Result<ScimGroup> {
        let mut g = group.clone();
        if g.id.is_empty() {
            g.id = uuid::Uuid::new_v4().to_string();
        }
        self.groups.write().await.insert(g.id.clone(), g.clone());
        Ok(g)
    }

    async fn list_groups(&self, _filter: Option<&str>) -> Result<Vec<ScimGroup>> {
        Ok(self.groups.read().await.values().cloned().collect())
    }

    async fn update_group(&self, group: &ScimGroup) -> Result<ScimGroup> {
        self.groups.write().await.insert(group.id.clone(), group.clone());
        Ok(group.clone())
    }

    async fn delete_group(&self, id: &str) -> Result<()> {
        self.groups.write().await.remove(id);
        Ok(())
    }

    // === Auth Code Management (Hybrid) ===
    async fn set_auth_code(&self, code: &str, record: &AuthCodeRecord, ttl_secs: u64) -> Result<()> {
        let record_json = serde_json::to_string(record)?;
        // In-memory
        self.auth_codes.write().await.insert(code.to_string(), record_json.clone());
        // Redis if available
        if let Some(mut conn) = self.redis_conn() {
            let key = format!("authcode:{}", code);
            let _: () = redis::Cmd::set_ex(&key, record_json, ttl_secs)
                .query_async(&mut conn)
                .await
                .unwrap_or(());
        }
        Ok(())
    }

    async fn consume_auth_code(&self, code: &str) -> Result<Option<AuthCodeRecord>> {
        let record_json: Option<String> = {
            // Try Redis first
            if let Some(mut conn) = self.redis_conn() {
                let key = format!("authcode:{}", code);
                let val: Option<String> = redis::Cmd::get_del(&key).query_async(&mut conn).await.ok();
                if val.is_some() {
                    val
                } else {
                    // Fallback to in-memory
                    self.auth_codes.write().await.remove(code)
                }
            } else {
                // In-memory only
                self.auth_codes.write().await.remove(code)
            }
        };

        if let Some(json) = record_json {
            Ok(serde_json::from_str(&json)?)
        } else {
            Ok(None)
        }
    }

    // === Token Management (Hybrid) ===
    async fn get_token_record(&self, token: &str) -> Result<Option<TokenRecord>> {
        // Try Redis first
        if let Some(mut conn) = self.redis_conn() {
            let key = format!("token_record:{}", token);
            let val: Option<String> = redis::Cmd::get(&key).query_async(&mut conn).await.ok();
            if let Some(json) = val {
                return Ok(serde_json::from_str(&json)?);
            }
        }
        // Fallback to in-memory
        Ok(self.tokens.read().await.get(token).cloned())
    }

    async fn set_token_record(&self, token: &str, record: &TokenRecord, ttl_secs: Option<u64>) -> Result<()> {
        // In-memory
        self.tokens.write().await.insert(token.to_string(), record.clone());
        // Redis if available
        if let Some(mut conn) = self.redis_conn() {
            let key = format!("token_record:{}", token);
            let record_json = serde_json::to_string(record)?;
            if let Some(ttl) = ttl_secs {
                let _: () = redis::Cmd::set_ex(&key, record_json, ttl).query_async(&mut conn).await?;
            } else {
                let _: () = redis::Cmd::set(&key, record_json).query_async(&mut conn).await?;
            }
        }
        Ok(())
    }

    async fn revoke_token(&self, token: &str) -> Result<()> {
        if let Some(mut record) = self.get_token_record(token).await? {
            record.active = false;
            self.set_token_record(token, &record, None).await?;
        }
        Ok(())
    }

    // === Refresh Token Management (Hybrid) ===
    async fn set_refresh_token_association(&self, refresh_token: &str, access_token: &str, ttl_secs: u64) -> Result<()> {
        // In-memory
        self.refresh_tokens.write().await.insert(refresh_token.to_string(), access_token.to_string());
        // Redis
        if let Some(mut conn) = self.redis_conn() {
            let key = format!("refresh_token:{}", refresh_token);
            let _: () = redis::Cmd::set_ex(&key, access_token, ttl_secs).query_async(&mut conn).await?;
        }
        Ok(())
    }

    async fn consume_refresh_token(&self, refresh_token: &str) -> Result<Option<String>> {
        let access_token: Option<String> = {
            if let Some(mut conn) = self.redis_conn() {
                let key = format!("refresh_token:{}", refresh_token);
                redis::Cmd::get_del(&key).query_async(&mut conn).await.ok()
            } else {
                self.refresh_tokens.write().await.remove(refresh_token)
            }
        };

        if access_token.is_some() {
             // Mark as reused
            self.refresh_reuse_markers.write().await.insert(refresh_token.to_string(), ());
            if let Some(mut conn) = self.redis_conn() {
                let key = format!("refresh_reused:{}", refresh_token);
                // Reuse detection window 10 minutes
                let _: () = redis::Cmd::set_ex(&key, 1, 600).query_async(&mut conn).await?;
            }
        }

        Ok(access_token)
    }

    async fn is_refresh_reused(&self, refresh_token: &str) -> Result<bool> {
        if let Some(mut conn) = self.redis_conn() {
            let key = format!("refresh_reused:{}", refresh_token);
            Ok(redis::Cmd::exists(&key).query_async(&mut conn).await?)
        } else {
            Ok(self.refresh_reuse_markers.read().await.contains_key(refresh_token))
        }
    }

    // === Health Check ===
    async fn health_check(&self) -> Result<bool> {
        if let Some(mut conn) = self.redis_conn() {
            let result: Result<String, _> = redis::cmd("PING").query_async(&mut conn).await;
            Ok(result.is_ok())
        } else {
            // In-memory store is always healthy
            Ok(true)
        }
    }
}
