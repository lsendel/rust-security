use crate::{CreateUserRequest, UpdateUserRequest, User, UserRole};
use async_trait::async_trait;
use thiserror::Error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[cfg(any(feature = "sqlite", feature = "postgres"))]
use sqlx::{AnyPool, Row};

/// Database error types
#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database connection error: {0}")]
    Connection(String),

    #[error("Query execution error: {0}")]
    Query(String),

    #[error("User not found")]
    NotFound,

    #[error("Email already exists")]
    EmailExists,

    #[error("Internal database error")]
    Internal,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl From<sqlx::Error> for DbError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => DbError::NotFound,
            sqlx::Error::Database(db_err) => {
                if db_err.message().contains("UNIQUE constraint failed")
                    || db_err.message().contains("duplicate key value")
                {
                    DbError::EmailExists
                } else {
                    DbError::Query(db_err.message().to_string())
                }
            }
            _ => DbError::Query(err.to_string()),
        }
    }
}

/// Repository trait for user operations
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: CreateUserRequest, password_hash: String)
        -> Result<User, DbError>;
    async fn find_by_id(&self, id: i32) -> Result<Option<User>, DbError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError>;
    async fn list(&self, limit: i32, offset: i32) -> Result<Vec<User>, DbError>;
    async fn update(&self, id: i32, user: UpdateUserRequest) -> Result<Option<User>, DbError>;
    async fn delete(&self, id: i32) -> Result<bool, DbError>;
    async fn count(&self) -> Result<i64, DbError>;
}

/// In-memory repository implementation for development/testing
pub struct InMemoryUserRepository {
    users: Arc<Mutex<HashMap<i32, User>>>,
    next_id: Arc<Mutex<i32>>,
}

impl InMemoryUserRepository {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for InMemoryUserRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn create(
        &self,
        user: CreateUserRequest,
        _password_hash: String,
    ) -> Result<User, DbError> {
        let mut users = self.users.lock().map_err(|_| DbError::Internal)?;
        let mut next_id = self.next_id.lock().map_err(|_| DbError::Internal)?;

        // Check if email already exists
        for existing_user in users.values() {
            if existing_user.email == user.email {
                return Err(DbError::EmailExists);
            }
        }

        let id = *next_id;
        *next_id += 1;

        let new_user = User {
            id,
            name: user.name.trim().to_string(),
            email: user.email.trim().to_string(),
            role: user.role.unwrap_or_default(),
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            created_at: chrono::Utc::now(),
            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            updated_at: chrono::Utc::now(),
        };

        users.insert(id, new_user.clone());
        Ok(new_user)
    }

    async fn find_by_id(&self, id: i32) -> Result<Option<User>, DbError> {
        let users = self.users.lock().map_err(|_| DbError::Internal)?;
        Ok(users.get(&id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
        let users = self.users.lock().map_err(|_| DbError::Internal)?;
        Ok(users.values().find(|u| u.email == email).cloned())
    }

    async fn list(&self, limit: i32, offset: i32) -> Result<Vec<User>, DbError> {
        let users = self.users.lock().map_err(|_| DbError::Internal)?;
        let mut user_list: Vec<User> = users.values().cloned().collect();
        user_list.sort_by_key(|user| user.id);

        let start = offset as usize;
        let end = (offset + limit) as usize;

        if start >= user_list.len() {
            Ok(vec![])
        } else {
            Ok(user_list[start..end.min(user_list.len())].to_vec())
        }
    }

    async fn update(
        &self,
        id: i32,
        user_update: UpdateUserRequest,
    ) -> Result<Option<User>, DbError> {
        let mut users = self.users.lock().map_err(|_| DbError::Internal)?;

        // Check email uniqueness if email is being updated
        if let Some(new_email) = &user_update.email {
            for (other_id, other_user) in users.iter() {
                if *other_id != id && other_user.email == *new_email {
                    return Err(DbError::EmailExists);
                }
            }
        }
        
        if let Some(existing_user) = users.get_mut(&id) {
            if let Some(new_email) = &user_update.email {
                existing_user.email = new_email.trim().to_string();
            }

            if let Some(new_name) = &user_update.name {
                existing_user.name = new_name.trim().to_string();
            }

            #[cfg(any(feature = "sqlite", feature = "postgres"))]
            {
                existing_user.updated_at = chrono::Utc::now();
            }

            Ok(Some(existing_user.clone()))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, id: i32) -> Result<bool, DbError> {
        let mut users = self.users.lock().map_err(|_| DbError::Internal)?;
        Ok(users.remove(&id).is_some())
    }

    async fn count(&self) -> Result<i64, DbError> {
        let users = self.users.lock().map_err(|_| DbError::Internal)?;
        Ok(users.len() as i64)
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
/// PostgreSQL repository implementation
pub struct PostgresUserRepository {
    pool: AnyPool,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl PostgresUserRepository {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create(
        &self,
        user: CreateUserRequest,
        password_hash: String,
    ) -> Result<User, DbError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO users (name, email, password_hash, role)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, email, role as "role: UserRole", created_at, updated_at
            "#,
            user.name.trim(),
            user.email.trim(),
            password_hash,
            user.role.unwrap_or_default() as UserRole
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(User {
            id: row.id,
            name: row.name,
            email: row.email,
            role: row.role,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn find_by_id(&self, id: i32) -> Result<Option<User>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, name, email, role as "role: UserRole", created_at, updated_at
            FROM users WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            name: r.name,
            email: r.email,
            role: r.role,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
        let row = sqlx::query!(
            r#"
            SELECT id, name, email, role as "role: UserRole", created_at, updated_at
            FROM users WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            name: r.name,
            email: r.email,
            role: r.role,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn list(&self, limit: i32, offset: i32) -> Result<Vec<User>, DbError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, email, role as "role: UserRole", created_at, updated_at
            FROM users ORDER BY id LIMIT $1 OFFSET $2
            "#,
            limit as i64,
            offset as i64
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| User {
                id: r.id,
                name: r.name,
                email: r.email,
                role: r.role,
                created_at: r.created_at,
                updated_at: r.updated_at,
            })
            .collect())
    }

    async fn update(
        &self,
        id: i32,
        user_update: UpdateUserRequest,
    ) -> Result<Option<User>, DbError> {
        let mut query = "UPDATE users SET updated_at = NOW()".to_string();
        let mut params = vec![];
        let mut param_count = 1;

        if let Some(name) = &user_update.name {
            query.push_str(&format!(", name = ${}", param_count));
            params.push(name.trim());
            param_count += 1;
        }

        if let Some(email) = &user_update.email {
            query.push_str(&format!(", email = ${}", param_count));
            params.push(email.trim());
            param_count += 1;
        }

        query.push_str(&format!(" WHERE id = ${} RETURNING id, name, email, role as \"role: UserRole\", created_at, updated_at", param_count));

        // This is a simplified version - in practice, you'd use a query builder or dynamic query construction
        let result = if let (Some(name), Some(email)) = (&user_update.name, &user_update.email) {
            sqlx::query!(
                r#"
                UPDATE users SET name = $1, email = $2, updated_at = NOW()
                WHERE id = $3
                RETURNING id, name, email, role as "role: UserRole", created_at, updated_at
                "#,
                name.trim(),
                email.trim(),
                id
            )
            .fetch_optional(&self.pool)
            .await?
        } else if let Some(name) = &user_update.name {
            sqlx::query!(
                r#"
                UPDATE users SET name = $1, updated_at = NOW()
                WHERE id = $2
                RETURNING id, name, email, role as "role: UserRole", created_at, updated_at
                "#,
                name.trim(),
                id
            )
            .fetch_optional(&self.pool)
            .await?
        } else if let Some(email) = &user_update.email {
            sqlx::query!(
                r#"
                UPDATE users SET email = $1, updated_at = NOW()
                WHERE id = $2
                RETURNING id, name, email, role as "role: UserRole", created_at, updated_at
                "#,
                email.trim(),
                id
            )
            .fetch_optional(&self.pool)
            .await?
        } else {
            return Ok(None);
        };

        Ok(result.map(|r| User {
            id: r.id,
            name: r.name,
            email: r.email,
            role: r.role,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn delete(&self, id: i32) -> Result<bool, DbError> {
        let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count(&self) -> Result<i64, DbError> {
        let row = sqlx::query!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.pool)
            .await?;

        Ok(row.count.unwrap_or(0))
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
/// SQLite repository implementation
pub struct SqliteUserRepository {
    pool: AnyPool,
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
impl SqliteUserRepository {
    pub fn new(pool: AnyPool) -> Self {
        Self { pool }
    }
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn create(
        &self,
        user: CreateUserRequest,
        password_hash: String,
    ) -> Result<User, DbError> {
        let role_str = match user.role.unwrap_or_default() {
            UserRole::User => "user",
            UserRole::Admin => "admin",
        };

        let row = sqlx::query!(
            r#"
            INSERT INTO users (name, email, password_hash, role)
            VALUES (?, ?, ?, ?)
            RETURNING id, name, email, role, created_at, updated_at
            "#,
            user.name.trim(),
            user.email.trim(),
            password_hash,
            role_str
        )
        .fetch_one(&self.pool)
        .await?;

        let role = match row.role.as_str() {
            "admin" => UserRole::Admin,
            _ => UserRole::User,
        };

        Ok(User {
            id: row.id,
            name: row.name,
            email: row.email,
            role,
            created_at: chrono::DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|_| DbError::Internal)?
                .with_timezone(&chrono::Utc),
            updated_at: chrono::DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|_| DbError::Internal)?
                .with_timezone(&chrono::Utc),
        })
    }

    async fn find_by_id(&self, id: i32) -> Result<Option<User>, DbError> {
        let row = sqlx::query!(
            "SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = ?",
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let role = match r.role.as_str() {
                "admin" => UserRole::Admin,
                _ => UserRole::User,
            };

            User {
                id: r.id,
                name: r.name,
                email: r.email,
                role,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                    .unwrap_or_else(|_| chrono::Utc::now().into())
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.updated_at)
                    .unwrap_or_else(|_| chrono::Utc::now().into())
                    .with_timezone(&chrono::Utc),
            }
        }))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
        let row = sqlx::query!(
            "SELECT id, name, email, role, created_at, updated_at FROM users WHERE email = ?",
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let role = match r.role.as_str() {
                "admin" => UserRole::Admin,
                _ => UserRole::User,
            };

            User {
                id: r.id,
                name: r.name,
                email: r.email,
                role,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                    .unwrap_or_else(|_| chrono::Utc::now().into())
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.updated_at)
                    .unwrap_or_else(|_| chrono::Utc::now().into())
                    .with_timezone(&chrono::Utc),
            }
        }))
    }

    async fn list(&self, limit: i32, offset: i32) -> Result<Vec<User>, DbError> {
        let rows = sqlx::query!(
            "SELECT id, name, email, role, created_at, updated_at FROM users ORDER BY id LIMIT ? OFFSET ?",
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let role = match r.role.as_str() {
                    "admin" => UserRole::Admin,
                    _ => UserRole::User,
                };

                User {
                    id: r.id,
                    name: r.name,
                    email: r.email,
                    role,
                    created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                    updated_at: chrono::DateTime::parse_from_rfc3339(&r.updated_at)
                        .unwrap_or_else(|_| chrono::Utc::now().into())
                        .with_timezone(&chrono::Utc),
                }
            })
            .collect())
    }

    async fn update(
        &self,
        id: i32,
        user_update: UpdateUserRequest,
    ) -> Result<Option<User>, DbError> {
        // Similar to PostgreSQL but with SQLite syntax
        let result = if let (Some(name), Some(email)) = (&user_update.name, &user_update.email) {
            sqlx::query!(
                r#"
                UPDATE users SET name = ?, email = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                RETURNING id, name, email, role, created_at, updated_at
                "#,
                name.trim(),
                email.trim(),
                id
            )
            .fetch_optional(&self.pool)
            .await?
        } else if let Some(name) = &user_update.name {
            sqlx::query!(
                r#"
                UPDATE users SET name = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                RETURNING id, name, email, role, created_at, updated_at
                "#,
                name.trim(),
                id
            )
            .fetch_optional(&self.pool)
            .await?
        } else if let Some(email) = &user_update.email {
            sqlx::query!(
                r#"
                UPDATE users SET email = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                RETURNING id, name, email, role, created_at, updated_at
                "#,
                email.trim(),
                id
            )
            .fetch_optional(&self.pool)
            .await?
        } else {
            return Ok(None);
        };

        Ok(result.map(|r| {
            let role = match r.role.as_str() {
                "admin" => UserRole::Admin,
                _ => UserRole::User,
            };

            User {
                id: r.id,
                name: r.name,
                email: r.email,
                role,
                created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                    .unwrap_or_else(|_| chrono::Utc::now().into())
                    .with_timezone(&chrono::Utc),
                updated_at: chrono::DateTime::parse_from_rfc3339(&r.updated_at)
                    .unwrap_or_else(|_| chrono::Utc::now().into())
                    .with_timezone(&chrono::Utc),
            }
        }))
    }

    async fn delete(&self, id: i32) -> Result<bool, DbError> {
        let result = sqlx::query!("DELETE FROM users WHERE id = ?", id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count(&self) -> Result<i64, DbError> {
        let row = sqlx::query!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&self.pool)
            .await?;

        Ok(row.count)
    }
}
