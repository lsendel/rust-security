use crate::scim_filter::{parse_scim_filter, ScimFilterError, ScimOperator};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use common::{AuthCodeRecord, ScimGroup, ScimUser, Store, TokenRecord};
use sqlx::{PgPool, Postgres, QueryBuilder};
use std::sync::Arc;

fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[derive(Clone)]
pub struct SqlStore {
    pool: Arc<PgPool>,
}

impl SqlStore {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool: Arc::new(pool) })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        sqlx::migrate!("./migrations").run(&*self.pool).await?;
        Ok(())
    }
}

#[async_trait]
impl Store for SqlStore {
    // User Management
    async fn get_user(&self, id: &str) -> Result<Option<ScimUser>> {
        let user = sqlx::query_as!(
            ScimUser,
            "SELECT id, user_name, active FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;
        Ok(user)
    }

    async fn create_user(&self, user: &ScimUser) -> Result<ScimUser> {
        let mut u = user.clone();
        if u.id.is_empty() {
            u.id = uuid::Uuid::new_v4().to_string();
        }
        sqlx::query("INSERT INTO users (id, user_name, active) VALUES ($1, $2, $3)")
            .bind(&u.id)
            .bind(&u.user_name)
            .bind(u.active)
            .execute(&*self.pool)
            .await?;
        Ok(u)
    }

    async fn list_users(&self, filter: Option<&str>) -> Result<Vec<ScimUser>> {
        let mut builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT id, user_name, active FROM users");

        if let Some(f) = filter {
            let parsed_filter =
                parse_scim_filter(f).map_err(|e| anyhow!("Filter parse error: {}", e))?;

            // This only supports simple filters, not complex ones (e.g., with AND/OR)
            builder.push(" WHERE ");

            let db_column = match parsed_filter.attribute.as_str() {
                "userName" => "user_name",
                "active" => "active",
                "id" => "id",
                _ => return Err(anyhow!("Unsupported filter attribute: {}", parsed_filter.attribute)),
            };
            builder.push(db_column);

            match parsed_filter.operator {
                ScimOperator::Eq => builder.push(" = "),
                ScimOperator::Ne => builder.push(" != "),
                ScimOperator::Co => builder.push(" LIKE "),
                ScimOperator::Sw => builder.push(" LIKE "),
                ScimOperator::Ew => builder.push(" LIKE "),
                _ => return Err(anyhow!("Unsupported filter operator for SQL: {:?}", parsed_filter.operator)),
            };

            if parsed_filter.attribute == "active" {
                let bool_val: bool = parsed_filter
                    .value
                    .as_deref()
                    .unwrap_or("false")
                    .parse()
                    .map_err(|_| anyhow!("Invalid boolean value for 'active' filter"))?;
                builder.push_bind(bool_val);
            } else {
                let value = parsed_filter.value.ok_or_else(|| anyhow!("Filter value is required"))?;
                let bind_value = match parsed_filter.operator {
                    ScimOperator::Co => format!("%{}%", value),
                    ScimOperator::Sw => format!("{}%", value),
                    ScimOperator::Ew => format!("%{}", value),
                    _ => value,
                };
                builder.push_bind(bind_value);
            }
        }

        let users = builder.build_query_as().fetch_all(&*self.pool).await?;
        Ok(users)
    }

    async fn update_user(&self, user: &ScimUser) -> Result<ScimUser> {
        sqlx::query("UPDATE users SET user_name = $2, active = $3 WHERE id = $1")
            .bind(&user.id)
            .bind(&user.user_name)
            .bind(user.active)
            .execute(&*self.pool)
            .await?;
        Ok(user.clone())
    }
    async fn delete_user(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // Group Management
    async fn get_group(&self, id: &str) -> Result<Option<ScimGroup>> {
        let mut group: Option<ScimGroup> = sqlx::query_as!(
            ScimGroup,
            "SELECT id, display_name, array[]::TEXT[] AS members FROM groups WHERE id = $1",
            id
        )
        .fetch_optional(&*self.pool)
        .await?;

        if let Some(g) = &mut group {
            let member_records =
                sqlx::query!("SELECT user_id FROM group_members WHERE group_id = $1", g.id)
                    .fetch_all(&*self.pool)
                    .await?;
            g.members = member_records.into_iter().map(|r| r.user_id).collect();
        }

        Ok(group)
    }
    async fn create_group(&self, group: &ScimGroup) -> Result<ScimGroup> {
        let mut g = group.clone();
        if g.id.is_empty() {
            g.id = uuid::Uuid::new_v4().to_string();
        }

        let mut tx = self.pool.begin().await?;

        sqlx::query("INSERT INTO groups (id, display_name) VALUES ($1, $2)")
            .bind(&g.id)
            .bind(&g.display_name)
            .execute(&mut *tx)
            .await?;

        for user_id in &g.members {
            sqlx::query("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)")
                .bind(&g.id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(g)
    }
    async fn list_groups(&self, filter: Option<&str>) -> Result<Vec<ScimGroup>> {
        let mut builder: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT id, display_name, array[]::TEXT[] AS members FROM groups");

        if let Some(f) = filter {
            let parsed_filter =
                parse_scim_filter(f).map_err(|e| anyhow!("Filter parse error: {}", e))?;

            builder.push(" WHERE ");

            let db_column = match parsed_filter.attribute.as_str() {
                "displayName" => "display_name",
                "id" => "id",
                _ => return Err(anyhow!("Unsupported filter attribute for groups: {}", parsed_filter.attribute)),
            };
            builder.push(db_column);

            match parsed_filter.operator {
                ScimOperator::Eq => builder.push(" = "),
                ScimOperator::Co => builder.push(" LIKE "),
                _ => return Err(anyhow!("Unsupported filter operator for groups: {:?}", parsed_filter.operator)),
            }

            let value = parsed_filter.value.ok_or_else(|| anyhow!("Filter value is required"))?;
            let bind_value = if parsed_filter.operator == ScimOperator::Co {
                format!("%{}%", value)
            } else {
                value
            };
            builder.push_bind(bind_value);
        }

        let mut groups: Vec<ScimGroup> = builder.build_query_as().fetch_all(&*self.pool).await?;

        for group in &mut groups {
            let member_records =
                sqlx::query!("SELECT user_id FROM group_members WHERE group_id = $1", group.id)
                    .fetch_all(&*self.pool)
                    .await?;
            group.members = member_records.into_iter().map(|r| r.user_id).collect();
        }

        Ok(groups)
    }
    async fn update_group(&self, group: &ScimGroup) -> Result<ScimGroup> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("UPDATE groups SET display_name = $2 WHERE id = $1")
            .bind(&group.id)
            .bind(&group.display_name)
            .execute(&mut *tx)
            .await?;

        // Easiest way to handle membership changes is to delete and re-insert.
        sqlx::query("DELETE FROM group_members WHERE group_id = $1")
            .bind(&group.id)
            .execute(&mut *tx)
            .await?;

        for user_id in &group.members {
            sqlx::query("INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)")
                .bind(&group.id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(group.clone())
    }
    async fn delete_group(&self, id: &str) -> Result<()> {
        // The ON DELETE CASCADE in the schema will handle cleaning up group_members
        sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // Auth Code Management
    async fn set_auth_code(
        &self,
        code: &str,
        record: &AuthCodeRecord,
        ttl_secs: u64,
    ) -> Result<()> {
        let exp = chrono::Utc::now().timestamp() + ttl_secs as i64;
        sqlx::query("INSERT INTO auth_codes (code, client_id, redirect_uri, nonce, scope, pkce_challenge, pkce_method, user_id, exp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
            .bind(code)
            .bind(&record.client_id)
            .bind(&record.redirect_uri)
            .bind(&record.nonce)
            .bind(&record.scope)
            .bind(&record.pkce_challenge)
            .bind(&record.pkce_method)
            .bind(&record.user_id)
            .bind(exp)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }
    async fn consume_auth_code(&self, code: &str) -> Result<Option<AuthCodeRecord>> {
        let record = sqlx::query_as!(AuthCodeRecord, "DELETE FROM auth_codes WHERE code = $1 RETURNING client_id, redirect_uri, nonce, scope, pkce_challenge, pkce_method, user_id, exp", code)
            .fetch_optional(&*self.pool)
            .await?;
        Ok(record)
    }

    // Token Management
    async fn get_token_record(&self, token: &str) -> Result<Option<TokenRecord>> {
        let token_hash = hash_token(token);
        let record = sqlx::query_as!(TokenRecord, "SELECT active, scope, client_id, exp, iat, sub, token_binding, mfa_verified FROM tokens WHERE token_hash = $1", &token_hash)
            .fetch_optional(&*self.pool)
            .await?;
        Ok(record)
    }
    async fn set_token_record(
        &self,
        token: &str,
        record: &TokenRecord,
        _ttl_secs: Option<u64>,
    ) -> Result<()> {
        // ttl_secs is used to calculate exp, which is already in the record.
        let token_hash = hash_token(token);
        let token_display = format!("{}...", &token[..4]); // For non-sensitive logging

        sqlx::query(
            "INSERT INTO tokens (token_hash, token_display, active, scope, client_id, exp, iat, sub, token_binding, mfa_verified)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT(token_hash) DO UPDATE SET
             active = $3, scope = $4, client_id = $5, exp = $6, iat = $7, sub = $8, token_binding = $9, mfa_verified = $10"
        )
        .bind(&token_hash)
        .bind(&token_display)
        .bind(record.active)
        .bind(&record.scope)
        .bind(&record.client_id)
        .bind(record.exp)
        .bind(record.iat)
        .bind(&record.sub)
        .bind(&record.token_binding)
        .bind(record.mfa_verified)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }
    async fn revoke_token(&self, token: &str) -> Result<()> {
        let token_hash = hash_token(token);
        sqlx::query("UPDATE tokens SET active = false WHERE token_hash = $1")
            .bind(&token_hash)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // Refresh Token Management
    async fn set_refresh_token_association(
        &self,
        refresh_token: &str,
        access_token: &str,
        ttl_secs: u64,
    ) -> Result<()> {
        let refresh_token_hash = hash_token(refresh_token);
        let access_token_hash = hash_token(access_token);
        let exp = chrono::Utc::now().timestamp() + ttl_secs as i64;

        sqlx::query(
            "INSERT INTO refresh_tokens (refresh_token_hash, access_token_hash, exp) VALUES ($1, $2, $3)",
        )
        .bind(&refresh_token_hash)
        .bind(&access_token_hash)
        .bind(exp)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }
    async fn consume_refresh_token(&self, refresh_token: &str) -> Result<Option<String>> {
        let refresh_token_hash = hash_token(refresh_token);

        let mut tx = self.pool.begin().await?;

        let result: Option<(String,)> = sqlx::query_as(
            "DELETE FROM refresh_tokens WHERE refresh_token_hash = $1 RETURNING access_token_hash",
        )
        .bind(&refresh_token_hash)
        .fetch_optional(&mut *tx)
        .await?;

        if result.is_some() {
            // Mark as reused
            let reuse_exp = chrono::Utc::now().timestamp() + 600; // 10 minute reuse detection window
            sqlx::query(
                "INSERT INTO refresh_token_reuse (refresh_token_hash, exp) VALUES ($1, $2)",
            )
            .bind(&refresh_token_hash)
            .bind(reuse_exp)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(result.map(|(access_token_hash,)| access_token_hash))
    }
    async fn is_refresh_reused(&self, refresh_token: &str) -> Result<bool> {
        let refresh_token_hash = hash_token(refresh_token);
        let exists: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM refresh_token_reuse WHERE refresh_token_hash = $1)",
        )
        .bind(&refresh_token_hash)
        .fetch_one(&*self.pool)
        .await?;
        Ok(exists.0)
    }

    // Health Check
    async fn health_check(&self) -> Result<bool> {
        sqlx::query("SELECT 1").fetch_one(&*self.pool).await?;
        Ok(true)
    }

    async fn get_metrics(&self) -> Result<common::StoreMetrics> {
        let users_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&*self.pool)
            .await?;
        let groups_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups")
            .fetch_one(&*self.pool)
            .await?;
        let tokens_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tokens")
            .fetch_one(&*self.pool)
            .await?;
        let active_tokens: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tokens WHERE active = true")
            .fetch_one(&*self.pool)
            .await?;
        let auth_codes_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM auth_codes")
            .fetch_one(&*self.pool)
            .await?;

        Ok(common::StoreMetrics {
            users_total: users_total.0 as u64,
            groups_total: groups_total.0 as u64,
            tokens_total: tokens_total.0 as u64,
            active_tokens: active_tokens.0 as u64,
            auth_codes_total: auth_codes_total.0 as u64,
        })
    }
}
