use crate::scim_filter::{parse_scim_filter, ScimOperator};
use anyhow::anyhow;
use async_trait::async_trait;
use common::{hash_token, AuthCodeRecord, ScimGroup, ScimUser, Store, TokenRecord};
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

#[derive(Debug)]
pub struct Migration {
    pub version: String,
    pub description: String,
    pub queries: Vec<String>,
}

#[derive(Clone)]
pub struct SqlStore {
    pool: Arc<PgPool>,
}

impl SqlStore {
    pub async fn new(database_url: &str) -> Result<Self, Box<dyn StdError + Send + Sync>> {
        info!("Initializing PostgreSQL connection pool");

        // Configure connection pool with optimal settings
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(50) // Max connections in pool
            .min_connections(5) // Minimum connections to maintain
            .max_lifetime(Duration::from_secs(1800)) // 30 minutes connection lifetime
            .idle_timeout(Duration::from_secs(600)) // 10 minutes idle timeout
            .acquire_timeout(Duration::from_secs(10)) // 10 seconds acquire timeout
            .test_before_acquire(true) // Test connections before use
            .connect(database_url)
            .await
            .map_err(|e| {
                error!("Failed to connect to PostgreSQL: {}", e);
                e
            })?;

        info!("PostgreSQL connection pool initialized successfully");
        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub async fn run_migrations(&self) -> Result<(), Box<dyn StdError + Send + Sync>> {
        info!("Running database migrations");

        // Create migration tracking table first
        self.create_migration_table().await?;

        let migrations = self.get_migrations();
        let applied_migrations = self.get_applied_migrations().await?;

        for migration in migrations {
            if applied_migrations.contains(&migration.version) {
                info!("Migration {} already applied, skipping", migration.version);
            } else {
                info!(
                    "Applying migration {}: {}",
                    migration.version, migration.description
                );

                let mut tx = self.pool.begin().await?;

                // Execute migration SQL
                for query in &migration.queries {
                    sqlx::query(query).execute(&mut *tx).await.map_err(|e| {
                        error!("Migration {} failed: {}", migration.version, e);
                        e
                    })?;
                }

                // Record migration as applied
                sqlx::query("INSERT INTO schema_migrations (version, description, applied_at) VALUES ($1, $2, NOW())")
                    .bind(&migration.version)
                    .bind(&migration.description)
                    .execute(&mut *tx)
                    .await?;

                tx.commit().await?;
                info!("Migration {} applied successfully", migration.version);
            }
        }

        info!("All migrations completed successfully");
        Ok(())
    }

    async fn create_migration_table(&self) -> Result<(), Box<dyn StdError + Send + Sync>> {
        sqlx::query(
            r"CREATE TABLE IF NOT EXISTS schema_migrations (
                version VARCHAR(255) PRIMARY KEY,
                description VARCHAR(255) NOT NULL,
                applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    async fn get_applied_migrations(&self) -> Result<Vec<String>, Box<dyn StdError + Send + Sync>> {
        let rows = sqlx::query("SELECT version FROM schema_migrations ORDER BY version")
            .fetch_all(&*self.pool)
            .await?;
        Ok(rows.into_iter().map(|row| row.get("version")).collect())
    }

    fn get_migrations(&self) -> Vec<Migration> {
        vec![
            Migration {
                version: "001_initial_schema".to_string(),
                description: "Create initial users and groups tables".to_string(),
                queries: vec![
                    r"CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        user_name TEXT NOT NULL UNIQUE,
                        display_name TEXT,
                        active BOOLEAN DEFAULT TRUE,
                        emails JSONB,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_users_user_name ON users(user_name)".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_users_active ON users(active)".to_string(),
                    r"CREATE TABLE IF NOT EXISTS groups (
                        id TEXT PRIMARY KEY,
                        display_name TEXT NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )".to_string(),
                    r"CREATE TABLE IF NOT EXISTS group_members (
                        group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        PRIMARY KEY (group_id, user_id)
                    )".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_group_members_user_id ON group_members(user_id)".to_string(),
                ],
            },
            Migration {
                version: "002_auth_tokens".to_string(),
                description: "Create authentication and token tables".to_string(),
                queries: vec![
                    r"CREATE TABLE IF NOT EXISTS auth_codes (
                        code TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        redirect_uri TEXT NOT NULL,
                        nonce TEXT,
                        scope TEXT,
                        pkce_challenge TEXT,
                        pkce_method TEXT,
                        user_id TEXT NOT NULL,
                        exp BIGINT NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_auth_codes_exp ON auth_codes(exp)".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON auth_codes(user_id)".to_string(),
                    r"CREATE TABLE IF NOT EXISTS tokens (
                        token_hash TEXT PRIMARY KEY,
                        token_display TEXT NOT NULL,
                        active BOOLEAN DEFAULT TRUE,
                        scope TEXT,
                        client_id TEXT NOT NULL,
                        exp BIGINT NOT NULL,
                        iat BIGINT NOT NULL,
                        sub TEXT NOT NULL,
                        token_binding TEXT,
                        mfa_verified BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_tokens_active ON tokens(active)".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_tokens_exp ON tokens(exp)".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_tokens_sub ON tokens(sub)".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens(client_id)".to_string(),
                ],
            },
            Migration {
                version: "003_refresh_tokens".to_string(),
                description: "Create refresh token tables".to_string(),
                queries: vec![
                    r"CREATE TABLE IF NOT EXISTS refresh_tokens (
                        refresh_token_hash TEXT PRIMARY KEY,
                        access_token_hash TEXT NOT NULL,
                        exp BIGINT NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_refresh_tokens_exp ON refresh_tokens(exp)".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_refresh_tokens_access_token ON refresh_tokens(access_token_hash)".to_string(),
                    r"CREATE TABLE IF NOT EXISTS refresh_token_reuse (
                        refresh_token_hash TEXT PRIMARY KEY,
                        exp BIGINT NOT NULL,
                        detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                    )".to_string(),
                    r"CREATE INDEX IF NOT EXISTS idx_refresh_token_reuse_exp ON refresh_token_reuse(exp)".to_string(),
                ],
            },
            Migration {
                version: "004_cleanup_jobs".to_string(),
                description: "Create stored procedures for cleanup".to_string(),
                queries: vec![
                    r"CREATE OR REPLACE FUNCTION cleanup_expired_tokens() RETURNS INTEGER AS $$
                    DECLARE
                        deleted_count INTEGER;
                    BEGIN
                        DELETE FROM tokens WHERE exp < EXTRACT(EPOCH FROM NOW());
                        GET DIAGNOSTICS deleted_count = ROW_COUNT;
                        RETURN deleted_count;
                    END;
                    $$ LANGUAGE plpgsql;".to_string(),
                    r"CREATE OR REPLACE FUNCTION cleanup_expired_auth_codes() RETURNS INTEGER AS $$
                    DECLARE
                        deleted_count INTEGER;
                    BEGIN
                        DELETE FROM auth_codes WHERE exp < EXTRACT(EPOCH FROM NOW());
                        GET DIAGNOSTICS deleted_count = ROW_COUNT;
                        RETURN deleted_count;
                    END;
                    $$ LANGUAGE plpgsql;".to_string(),
                    r"CREATE OR REPLACE FUNCTION cleanup_expired_refresh_tokens() RETURNS INTEGER AS $$
                    DECLARE
                        deleted_count INTEGER;
                    BEGIN
                        DELETE FROM refresh_tokens WHERE exp < EXTRACT(EPOCH FROM NOW());
                        GET DIAGNOSTICS deleted_count = ROW_COUNT;
                        DELETE FROM refresh_token_reuse WHERE exp < EXTRACT(EPOCH FROM NOW());
                        RETURN deleted_count;
                    END;
                    $$ LANGUAGE plpgsql;".to_string(),
                ],
            },
        ]
    }

    pub async fn cleanup_expired_data(&self) -> Result<(), Box<dyn StdError + Send + Sync>> {
        info!("Running expired data cleanup");

        let tokens_deleted: (i32,) = sqlx::query_as("SELECT cleanup_expired_tokens()")
            .fetch_one(&*self.pool)
            .await?;
        let codes_deleted: (i32,) = sqlx::query_as("SELECT cleanup_expired_auth_codes()")
            .fetch_one(&*self.pool)
            .await?;
        let refresh_deleted: (i32,) = sqlx::query_as("SELECT cleanup_expired_refresh_tokens()")
            .fetch_one(&*self.pool)
            .await?;

        info!(
            "Cleanup completed: {} tokens, {} auth codes, {} refresh tokens removed",
            tokens_deleted.0, codes_deleted.0, refresh_deleted.0
        );
        Ok(())
    }
}

#[async_trait]
impl Store for SqlStore {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    // User Management
    async fn get_user(
        &self,
        id: &str,
    ) -> Result<Option<ScimUser>, Box<dyn StdError + Send + Sync>> {
        let row = sqlx::query("SELECT id, user_name, active FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;
        let user = row.map(|r| ScimUser {
            id: r.get("id"),
            user_name: r.get("user_name"),
            active: r.get("active"),
        });
        Ok(user)
    }

    async fn create_user(
        &self,
        user: &ScimUser,
    ) -> Result<ScimUser, Box<dyn StdError + Send + Sync>> {
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

    async fn list_users(
        &self,
        filter: Option<&str>,
    ) -> Result<Vec<ScimUser>, Box<dyn StdError + Send + Sync>> {
        let mut builder: QueryBuilder<'_, Postgres> =
            QueryBuilder::new("SELECT id, user_name, active FROM users");

        if let Some(f) = filter {
            let parsed_filter = parse_scim_filter(f).map_err(|e| {
                Box::<dyn StdError + Send + Sync>::from(anyhow!("Filter parse error: {}", e))
            })?;

            // This only supports simple filters, not complex ones (e.g., with AND/OR)
            builder.push(" WHERE ");

            let db_column = match parsed_filter.attribute.as_str() {
                "userName" => "user_name",
                "active" => "active",
                "id" => "id",
                _ => {
                    return Err(Box::<dyn StdError + Send + Sync>::from(anyhow!(
                        "Unsupported filter attribute: {}",
                        parsed_filter.attribute
                    )))
                }
            };
            builder.push(db_column);

            match parsed_filter.operator {
                ScimOperator::Eq => builder.push(" = "),
                ScimOperator::Ne => builder.push(" != "),
                ScimOperator::Co => builder.push(" LIKE "),
                ScimOperator::Sw => builder.push(" LIKE "),
                ScimOperator::Ew => builder.push(" LIKE "),
                _ => {
                    return Err(Box::<dyn StdError + Send + Sync>::from(anyhow!(
                        "Unsupported filter operator for SQL: {:?}",
                        parsed_filter.operator
                    )))
                }
            };

            if parsed_filter.attribute == "active" {
                let bool_val: bool = parsed_filter
                    .value
                    .as_deref()
                    .unwrap_or("false")
                    .parse()
                    .map_err(|_| {
                        Box::<dyn StdError + Send + Sync>::from(anyhow!(
                            "Invalid boolean value for 'active' filter"
                        ))
                    })?;
                builder.push_bind(bool_val);
            } else {
                let value = parsed_filter.value.ok_or_else(|| {
                    Box::<dyn StdError + Send + Sync>::from(anyhow!("Filter value is required"))
                })?;
                let bind_value = match parsed_filter.operator {
                    ScimOperator::Co => format!("%{value}%"),
                    ScimOperator::Sw => format!("{value}%"),
                    ScimOperator::Ew => format!("%{value}"),
                    _ => value,
                };
                builder.push_bind(bind_value);
            }
        }

        let rows = builder.build().fetch_all(&*self.pool).await?;
        let users: Vec<ScimUser> = rows
            .into_iter()
            .map(|row| ScimUser {
                id: row.get("id"),
                user_name: row.get("user_name"),
                active: row.get("active"),
            })
            .collect();
        Ok(users)
    }

    async fn update_user(
        &self,
        user: &ScimUser,
    ) -> Result<ScimUser, Box<dyn StdError + Send + Sync>> {
        sqlx::query("UPDATE users SET user_name = $2, active = $3 WHERE id = $1")
            .bind(&user.id)
            .bind(&user.user_name)
            .bind(user.active)
            .execute(&*self.pool)
            .await?;
        Ok(user.clone())
    }
    async fn delete_user(&self, id: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    // Group Management
    async fn get_group(
        &self,
        id: &str,
    ) -> Result<Option<ScimGroup>, Box<dyn StdError + Send + Sync>> {
        let row = sqlx::query("SELECT id, display_name FROM groups WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await?;
        let mut group = row.map(|r| ScimGroup {
            id: r.get("id"),
            display_name: r.get("display_name"),
            members: Vec::new(), // Will be populated below
        });

        if let Some(g) = &mut group {
            let member_records: Vec<(String,)> =
                sqlx::query_as("SELECT user_id FROM group_members WHERE group_id = $1")
                    .bind(&g.id)
                    .fetch_all(&*self.pool)
                    .await?;
            g.members = member_records.into_iter().map(|r| r.0).collect();
        }

        Ok(group)
    }
    async fn create_group(
        &self,
        group: &ScimGroup,
    ) -> Result<ScimGroup, Box<dyn StdError + Send + Sync>> {
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
    async fn list_groups(
        &self,
        filter: Option<&str>,
    ) -> Result<Vec<ScimGroup>, Box<dyn StdError + Send + Sync>> {
        let mut builder: QueryBuilder<'_, Postgres> =
            QueryBuilder::new("SELECT id, display_name, array[]::TEXT[] AS members FROM groups");

        if let Some(f) = filter {
            let parsed_filter = parse_scim_filter(f).map_err(|e| {
                Box::<dyn StdError + Send + Sync>::from(anyhow!("Filter parse error: {}", e))
            })?;

            builder.push(" WHERE ");

            let db_column = match parsed_filter.attribute.as_str() {
                "displayName" => "display_name",
                "id" => "id",
                _ => {
                    return Err(Box::<dyn StdError + Send + Sync>::from(anyhow!(
                        "Unsupported filter attribute for groups: {}",
                        parsed_filter.attribute
                    )))
                }
            };
            builder.push(db_column);

            match parsed_filter.operator {
                ScimOperator::Eq => {
                    builder.push(" = ");
                }
                ScimOperator::Co => {
                    builder.push(" LIKE ");
                }
                _ => {
                    return Err(Box::<dyn StdError + Send + Sync>::from(anyhow!(
                        "Unsupported filter operator for groups: {:?}",
                        parsed_filter.operator
                    )))
                }
            }

            let value = parsed_filter.value.ok_or_else(|| {
                Box::<dyn StdError + Send + Sync>::from(anyhow!("Filter value is required"))
            })?;
            let bind_value = if parsed_filter.operator == ScimOperator::Co {
                format!("%{value}%")
            } else {
                value
            };
            builder.push_bind(bind_value);
        }

        let rows = builder.build().fetch_all(&*self.pool).await?;
        let mut groups: Vec<ScimGroup> = rows
            .into_iter()
            .map(|row| ScimGroup {
                id: row.get("id"),
                display_name: row.get("display_name"),
                members: Vec::new(), // Will be populated below
            })
            .collect();

        for group in &mut groups {
            let member_records: Vec<(String,)> =
                sqlx::query_as("SELECT user_id FROM group_members WHERE group_id = $1")
                    .bind(&group.id)
                    .fetch_all(&*self.pool)
                    .await?;
            group.members = member_records.into_iter().map(|r| r.0).collect();
        }

        Ok(groups)
    }
    async fn update_group(
        &self,
        group: &ScimGroup,
    ) -> Result<ScimGroup, Box<dyn StdError + Send + Sync>> {
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
    async fn delete_group(&self, id: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
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
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
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
    async fn consume_auth_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthCodeRecord>, Box<dyn StdError + Send + Sync>> {
        let row = sqlx::query("DELETE FROM auth_codes WHERE code = $1 RETURNING client_id, redirect_uri, nonce, scope, pkce_challenge, pkce_method, user_id, exp")
            .bind(code)
            .fetch_optional(&*self.pool)
            .await?;
        let record = row.map(|r| AuthCodeRecord {
            client_id: r.get("client_id"),
            redirect_uri: r.get("redirect_uri"),
            nonce: r.get("nonce"),
            scope: r.get("scope"),
            pkce_challenge: r.get("pkce_challenge"),
            pkce_method: r.get("pkce_method"),
            user_id: r.get("user_id"),
            exp: r.get("exp"),
        });
        Ok(record)
    }

    // Token Management
    async fn get_token_record(
        &self,
        token: &str,
    ) -> Result<Option<TokenRecord>, Box<dyn StdError + Send + Sync>> {
        let token_hash = hash_token(token);
        let row = sqlx::query("SELECT active, scope, client_id, exp, iat, sub, token_binding, mfa_verified FROM tokens WHERE token_hash = $1")
            .bind(&token_hash)
            .fetch_optional(&*self.pool)
            .await?;
        let record = row.map(|r| TokenRecord {
            active: r.get("active"),
            scope: r.get("scope"),
            client_id: r.get("client_id"),
            exp: r.get("exp"),
            iat: r.get("iat"),
            sub: r.get("sub"),
            token_binding: r.get("token_binding"),
            mfa_verified: r.get("mfa_verified"),
        });
        Ok(record)
    }
    async fn set_token_record(
        &self,
        token: &str,
        record: &TokenRecord,
        _ttl_secs: Option<u64>,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        // ttl_secs is used to calculate exp, which is already in the record.
        let token_hash = hash_token(token);
        let token_display = format!("{prefix}...", prefix = &token[..4]); // For non-sensitive logging

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
    async fn revoke_token(&self, token: &str) -> Result<(), Box<dyn StdError + Send + Sync>> {
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
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
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
    async fn consume_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<String>, Box<dyn StdError + Send + Sync>> {
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
    async fn is_refresh_reused(
        &self,
        refresh_token: &str,
    ) -> Result<bool, Box<dyn StdError + Send + Sync>> {
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
    async fn health_check(&self) -> Result<bool, Box<dyn StdError + Send + Sync>> {
        sqlx::query("SELECT 1").fetch_one(&*self.pool).await?;
        Ok(true)
    }

    async fn get_metrics(&self) -> Result<common::StoreMetrics, Box<dyn StdError + Send + Sync>> {
        let users_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&*self.pool)
            .await?;
        let groups_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM groups")
            .fetch_one(&*self.pool)
            .await?;
        let tokens_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tokens")
            .fetch_one(&*self.pool)
            .await?;
        let active_tokens: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM tokens WHERE active = true")
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
