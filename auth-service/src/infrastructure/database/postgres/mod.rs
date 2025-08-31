//! PostgreSQL Database Implementation
//!
//! PostgreSQL implementations of repository interfaces.

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;

use crate::domain::entities::{Session, Token, TokenType, User};
use crate::domain::repositories::{
    RepositoryError, SessionRepository, TokenRepository, UserRepository,
};
use crate::domain::value_objects::{Email, UserId};

/// PostgreSQL implementation of UserRepository
pub struct PostgresUserRepository {
    pool: Arc<PgPool>,
}

impl PostgresUserRepository {
    /// Create a new PostgreSQL user repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, RepositoryError> {
        let result = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, name, created_at, last_login, is_active, roles
             FROM users WHERE email = $1"
        )
        .bind(email.as_str())
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, RepositoryError> {
        let result = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, name, created_at, last_login, is_active, roles
             FROM users WHERE id = $1"
        )
        .bind(id.as_str())
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn save(&self, user: &User) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, name, created_at, is_active, roles)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO UPDATE SET
               password_hash = EXCLUDED.password_hash,
               last_login = EXCLUDED.last_login,
               is_active = EXCLUDED.is_active,
               updated_at = NOW()"
        )
        .bind(user.id.as_str())
        .bind(user.email.as_str())
        .bind(user.password_hash.as_str())
        .bind(&user.name)
        .bind(user.created_at)
        .bind(user.is_active)
        .bind(&user.roles)
        .execute(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn update_last_login(
        &self,
        id: &UserId,
        login_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET last_login = $1, updated_at = NOW() WHERE id = $2"
        )
        .bind(login_time)
        .bind(id.as_str())
        .execute(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn delete(&self, id: &UserId) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id.as_str())
            .execute(&*self.pool)
            .await
            .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn exists_by_email(&self, email: &Email) -> Result<bool, RepositoryError> {
        let result = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"
        )
        .bind(email.as_str())
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn find_by_role(&self, role: &str) -> Result<Vec<User>, RepositoryError> {
        let result = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, name, created_at, last_login, is_active, roles
             FROM users WHERE $1 = ANY(roles)"
        )
        .bind(role)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn find_all(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<User>, RepositoryError> {
        let limit = limit.unwrap_or(100);
        let offset = offset.unwrap_or(0);

        let result = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, name, created_at, last_login, is_active, roles
             FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn update_profile(
        &self,
        id: &UserId,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET name = COALESCE($1, name), avatar_url = COALESCE($2, avatar_url), updated_at = NOW()
             WHERE id = $3"
        )
        .bind(name.as_ref())
        .bind(avatar_url.as_ref())
        .bind(id.as_str())
        .execute(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn set_active_status(&self, id: &UserId, is_active: bool) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2"
        )
        .bind(is_active)
        .bind(id.as_str())
        .execute(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn add_role(&self, id: &UserId, role: String) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET roles = array_append(roles, $1), updated_at = NOW() WHERE id = $2"
        )
        .bind(role)
        .bind(id.as_str())
        .execute(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn remove_role(&self, id: &UserId, role: &str) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE users SET roles = array_remove(roles, $1), updated_at = NOW() WHERE id = $2"
        )
        .bind(role)
        .bind(id.as_str())
        .execute(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(())
    }

    async fn count(&self) -> Result<i64, RepositoryError> {
        let result = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(&*self.pool)
            .await
            .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn find_created_between(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<User>, RepositoryError> {
        let result = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, name, created_at, last_login, is_active, roles
             FROM users WHERE created_at BETWEEN $1 AND $2"
        )
        .bind(start)
        .bind(end)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }

    async fn find_inactive_users(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<User>, RepositoryError> {
        let result = sqlx::query_as::<_, User>(
            "SELECT id, email, password_hash, name, created_at, last_login, is_active, roles
             FROM users WHERE last_login IS NULL OR last_login < $1"
        )
        .bind(since)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| RepositoryError::Database(Box::new(e)))?;

        Ok(result)
    }
}

/// PostgreSQL implementation of SessionRepository
pub struct PostgresSessionRepository {
    pool: Arc<PgPool>,
}

impl PostgresSessionRepository {
    /// Create a new PostgreSQL session repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn find_by_id(
        &self,
        session_id: &str,
    ) -> Result<Option<Session>, crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(None)
    }

    async fn find_by_user_id(
        &self,
        _user_id: &UserId,
    ) -> Result<Vec<Session>, crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(vec![])
    }

    async fn save(
        &self,
        _session: &Session,
    ) -> Result<(), crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(())
    }

    async fn update(
        &self,
        _session: &Session,
    ) -> Result<(), crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(())
    }

    async fn delete(
        &self,
        _session_id: &str,
    ) -> Result<(), crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(())
    }

    async fn delete_by_user_id(
        &self,
        _user_id: &UserId,
    ) -> Result<(), crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(())
    }

    async fn delete_expired(
        &self,
    ) -> Result<i64, crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(0)
    }

    async fn count_by_user_id(
        &self,
        _user_id: &UserId,
    ) -> Result<i64, crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(0)
    }

    async fn extend_session(
        &self,
        _session_id: &str,
        _new_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(())
    }

    async fn exists_and_active(
        &self,
        _session_id: &str,
    ) -> Result<bool, crate::domain::repositories::SessionRepositoryError> {
        // TODO: Implement session storage in PostgreSQL
        Ok(false)
    }
}

/// PostgreSQL implementation of TokenRepository
pub struct PostgresTokenRepository {
    pool: Arc<PgPool>,
}

impl PostgresTokenRepository {
    /// Create a new PostgreSQL token repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenRepository for PostgresTokenRepository {
    async fn find_by_hash(
        &self,
        _token_hash: &str,
    ) -> Result<Option<Token>, crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(None)
    }

    async fn find_by_user_id(
        &self,
        _user_id: &UserId,
    ) -> Result<Vec<Token>, crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(vec![])
    }

    async fn find_by_user_and_type(
        &self,
        _user_id: &UserId,
        _token_type: &TokenType,
    ) -> Result<Vec<Token>, crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(vec![])
    }

    async fn save(
        &self,
        _token: &Token,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn update(
        &self,
        _token: &Token,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn delete_by_hash(
        &self,
        _token_hash: &str,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn delete_by_user_id(
        &self,
        _user_id: &UserId,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn delete_by_user_and_type(
        &self,
        _user_id: &UserId,
        _token_type: &TokenType,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn revoke_by_hash(
        &self,
        _token_hash: &str,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn revoke_by_user_id(
        &self,
        _user_id: &UserId,
    ) -> Result<(), crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(())
    }

    async fn delete_expired(
        &self,
    ) -> Result<i64, crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(0)
    }

    async fn exists_and_active(
        &self,
        _token_hash: &str,
    ) -> Result<bool, crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(false)
    }

    async fn count_active_by_user(
        &self,
        _user_id: &UserId,
    ) -> Result<i64, crate::domain::repositories::TokenRepositoryError> {
        // TODO: Implement token storage in PostgreSQL
        Ok(0)
    }
}
