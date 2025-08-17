use crate::IntrospectionRecord;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use once_cell::sync::Lazy;

// Simple in-memory auth code store (JSON-encoded records), with optional Redis fallback
static AUTH_CODES_MEM: Lazy<RwLock<HashMap<String, String>>> = Lazy::new(|| RwLock::new(HashMap::new()));
// Ephemeral in-memory MFA flags per access token
static MFA_FLAGS_MEM: Lazy<RwLock<HashMap<String, bool>>> = Lazy::new(|| RwLock::new(HashMap::new()));

async fn redis_conn() -> Option<redis::aio::ConnectionManager> {
    let url = std::env::var("REDIS_URL").ok()?;
    let client = redis::Client::open(url).ok()?;
    client.get_connection_manager().await.ok()
}

pub async fn set_auth_code(code: &str, record_json: String, ttl_secs: u64) -> anyhow::Result<()> {
    // In-memory
    {
        let mut m = AUTH_CODES_MEM.write().await;
        m.insert(code.to_string(), record_json.clone());
    }
    // Redis if available
    if let Some(mut conn) = redis_conn().await {
        let key = format!("authcode:{}", code);
        let _: () = redis::Cmd::set_ex(&key, record_json, ttl_secs)
            .query_async(&mut conn)
            .await
            .unwrap_or(());
    }
    Ok(())
}

pub async fn consume_auth_code(code: &str) -> anyhow::Result<Option<String>> {
    // Try Redis first
    if let Some(mut conn) = redis_conn().await {
        let key = format!("authcode:{}", code);
        // Use GETDEL if available; fallback to GET then DEL
        let val: Option<String> = redis::Cmd::get(&key).query_async(&mut conn).await.ok();
        let _: () = redis::Cmd::del(&key).query_async(&mut conn).await.unwrap_or(());
        if val.is_some() {
            return Ok(val);
        }
    }
    // Fallback to in-memory
    let mut m = AUTH_CODES_MEM.write().await;
    Ok(m.remove(code))
}

#[derive(Clone)]
pub enum TokenStore {
    InMemory(Arc<RwLock<HashMap<String, Arc<RwLock<IntrospectionRecord>>>>>),
    #[allow(dead_code)]
    Redis(redis::aio::ConnectionManager),
}

impl TokenStore {
    pub async fn get_record(&self, token: &str) -> anyhow::Result<crate::IntrospectionRecord> {
        match self {
            TokenStore::InMemory(map) => {
                let guard = map.read().await;
                let record = guard.get(token);
                if let Some(record) = record {
                    let record = record.read().await;
                    Ok(record.clone())
                } else {
                    Ok(crate::IntrospectionRecord {
                        active: false,
                        scope: None,
                        client_id: None,
                        exp: None,
                        iat: None,
                        sub: None,
                        token_binding: None,
                    })
                }
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key_active = format!("token:{}:active", token);
                let key_scope = format!("token:{}:scope", token);
                let key_client_id = format!("token:{}:client_id", token);
                let key_exp = format!("token:{}:exp", token);
                let key_iat = format!("token:{}:iat", token);
                let key_sub = format!("token:{}:sub", token);
                let key_token_binding = format!("token:{}:token_binding", token);
                let key_mfa_verified = format!("token:{}:mfa_verified", token);
                #[allow(clippy::type_complexity)]
                let (active, scope, client_id, exp, iat, sub, token_binding, _mfa_verified): (
                    Option<i64>,
                    Option<String>,
                    Option<String>,
                    Option<i64>,
                    Option<i64>,
                    Option<String>,
                    Option<String>,
                    Option<i64>,
                ) = redis::pipe()
                    .get(&key_active)
                    .get(&key_scope)
                    .get(&key_client_id)
                    .get(&key_exp)
                    .get(&key_iat)
                    .get(&key_sub)
                    .get(&key_token_binding)
                    .get(&key_mfa_verified)
                    .query_async(&mut conn)
                    .await?;
                Ok(crate::IntrospectionRecord {
                    active: active.unwrap_or(0) == 1,
                    scope,
                    client_id,
                    exp,
                    iat,
                    sub,
                    token_binding,
                    // Attach mfa flag in responses where relevant

                })
            }
        }
    }
    pub async fn get_active(&self, token: &str) -> anyhow::Result<bool> {
        match self {
            TokenStore::InMemory(map) => {
                let guard = map.read().await;
                if let Some(record) = guard.get(token) {
                    let record = record.read().await;
                    Ok(record.active)
                } else {
                    Ok(false)
                }
            }
            TokenStore::Redis(conn) => {
                let key = format!("token:{}:active", token);
                let mut conn = conn.clone();
                let val: i64 = redis::Cmd::get(&key).query_async(&mut conn).await?;
                Ok(val == 1)
            }
        }
    }

    pub async fn set_active(
        &self,
        token: &str,
        active: bool,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = IntrospectionRecord {
                    active,
                    scope: None,
                    client_id: None,
                    exp: None,
                    iat: None,
                    sub: None,
                    token_binding: None,

                };
                guard.insert(token.to_string(), Arc::new(RwLock::new(record)));
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:active", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, if active { 1 } else { 0 }, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, if active { 1 } else { 0 })
                        .query_async(&mut conn)
                        .await?;
                }
                Ok(())
            }
        }
    }

    pub async fn set_scope(
        &self,
        token: &str,
        scope: Option<String>,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = get_or_insert_in_memory(&mut guard, token);
                let mut record = record.write().await;
                record.scope = scope;
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:scope", token);
                if let Some(sc) = scope {
                    if let Some(ttl) = ttl_secs {
                        let _: () = redis::Cmd::set_ex(&key, sc, ttl)
                            .query_async(&mut conn)
                            .await?;
                    } else {
                        let _: () = redis::Cmd::set(&key, sc).query_async(&mut conn).await?;
                    }
                } else {
                    let _: () = redis::Cmd::del(&key).query_async(&mut conn).await?;
                }
                Ok(())
            }
        }
    }

    pub async fn set_client_id(
        &self,
        token: &str,
        client_id: String,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = get_or_insert_in_memory(&mut guard, token);
                let mut record = record.write().await;
                record.client_id = Some(client_id);
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:client_id", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, client_id, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, client_id)
                        .query_async(&mut conn)
                        .await?;
                }
                Ok(())
            }
        }
    }

    pub async fn revoke(&self, token: &str) -> anyhow::Result<()> {
        self.set_active(token, false, None).await
    }

    pub async fn set_exp(
        &self,
        token: &str,
        exp: i64,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = get_or_insert_in_memory(&mut guard, token);
                let mut record = record.write().await;
                record.exp = Some(exp);
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:exp", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, exp, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, exp).query_async(&mut conn).await?;
                }
                Ok(())
            }
        }
    }

    pub async fn set_subject(
        &self,
        token: &str,
        subject: String,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = get_or_insert_in_memory(&mut guard, token);
                let mut record = record.write().await;
                record.sub = Some(subject);
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:sub", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, subject, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, subject)
                        .query_async(&mut conn)
                        .await?;
                }
                Ok(())
            }
        }
    }

    pub async fn set_iat(
        &self,
        token: &str,
        iat: i64,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = get_or_insert_in_memory(&mut guard, token);
                let mut record = record.write().await;
                record.iat = Some(iat);
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:iat", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, iat, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, iat).query_async(&mut conn).await?;
                }
                Ok(())
            }
        }
    }

    pub async fn set_refresh(&self, refresh: &str, ttl_secs: u64) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = IntrospectionRecord {
                    active: true,
                    scope: None,
                    client_id: None,
                    exp: None,
                    iat: None,
                    sub: None,
                    token_binding: None,

                };
                guard.insert(format!("rt:{}", refresh), Arc::new(RwLock::new(record)));
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:refresh", refresh);
                let _: () = redis::Cmd::set_ex(&key, 1, ttl_secs)
                    .query_async(&mut conn)
                    .await?;
                Ok(())
            }
        }
    }

    pub async fn set_mfa_verified(
        &self,
        token: &str,
        verified: bool,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let _ = map; // keep type used
                let mut flags = MFA_FLAGS_MEM.write().await;
                flags.insert(token.to_string(), verified);
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:mfa_verified", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, if verified { 1 } else { 0 }, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, if verified { 1 } else { 0 })
                        .query_async(&mut conn)
                        .await?;
                }
                Ok(())
            }
        }
    }

    pub async fn get_mfa_verified(&self, token: &str) -> anyhow::Result<bool> {
        match self {
            TokenStore::InMemory(_) => {
                let flags = MFA_FLAGS_MEM.read().await;
                Ok(*flags.get(token).unwrap_or(&false))
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:mfa_verified", token);
                let val: Option<i64> = redis::Cmd::get(&key).query_async(&mut conn).await.unwrap_or(None);
                Ok(val.unwrap_or(0) == 1)
            }
        }
    }

    pub async fn set_token_binding(
        &self,
        token: &str,
        token_binding: String,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                let record = get_or_insert_in_memory(&mut guard, token);
                let mut record = record.write().await;
                record.token_binding = Some(token_binding);
                Ok(())
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:token_binding", token);
                if let Some(ttl) = ttl_secs {
                    let _: () = redis::Cmd::set_ex(&key, token_binding, ttl)
                        .query_async(&mut conn)
                        .await?;
                } else {
                    let _: () = redis::Cmd::set(&key, token_binding)
                        .query_async(&mut conn)
                        .await?;
                }
                Ok(())
            }
        }
    }

    pub async fn consume_refresh(&self, refresh: &str) -> anyhow::Result<bool> {
        match self {
            TokenStore::InMemory(map) => {
                let mut guard = map.write().await;
                if let Some(rec) = guard.get_mut(&format!("rt:{}", refresh)) {
                    let mut rec = rec.write().await;
                    if rec.active {
                        rec.active = false;
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            TokenStore::Redis(conn) => {
                let mut conn = conn.clone();
                let key = format!("token:{}:refresh", refresh);
                let deleted: i64 = redis::Cmd::del(&key).query_async(&mut conn).await?;
                Ok(deleted > 0)
            }
        }
    }
}

fn get_or_insert_in_memory<'a>(
    map: &'a mut HashMap<String, Arc<RwLock<IntrospectionRecord>>>,
    token: &str,
) -> &'a Arc<RwLock<IntrospectionRecord>> {
    map.entry(token.to_string()).or_insert_with(|| {
        Arc::new(RwLock::new(IntrospectionRecord {
            active: false,
            scope: None,
            client_id: None,
            exp: None,
            iat: None,
            sub: None,
            token_binding: None,
        }))
    })
}

pub async fn redis_store(url: &str) -> anyhow::Result<TokenStore> {
    let client = redis::Client::open(url)?;
    let conn = client.get_connection_manager().await?;
    Ok(TokenStore::Redis(conn))
}
