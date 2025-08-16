use crate::IntrospectionRecord;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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
                let (active, scope, client_id, exp, iat): (
                    i64,
                    Option<String>,
                    Option<String>,
                    Option<i64>,
                    Option<i64>,
                ) = redis::pipe()
                    .get(&key_active)
                    .get(&key_scope)
                    .get(&key_client_id)
                    .get(&key_exp)
                    .get(&key_iat)
                    .query_async(&mut conn)
                    .await?;
                Ok(crate::IntrospectionRecord {
                    active: active == 1,
                    scope,
                    client_id,
                    exp,
                    iat,
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
        }))
    })
}

pub async fn redis_store(url: &str) -> anyhow::Result<TokenStore> {
    let client = redis::Client::open(url)?;
    let conn = client.get_connection_manager().await?;
    Ok(TokenStore::Redis(conn))
}
