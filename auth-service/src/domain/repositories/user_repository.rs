//! User Repository Interface
//!
//! Defines the contract for user data access operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::domain::entities::User;
use crate::domain::value_objects::{Email, UserId};

/// Repository operation errors
#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("Entity not found")]
    NotFound,
    #[error("Entity already exists")]
    AlreadyExists,
    #[error("Database error: {0}")]
    Database(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// User repository trait defining the contract for user data access
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Find a user by their email address
    async fn find_by_email(&self, email: &Email) -> Result<Option<User>, RepositoryError>;

    /// Find a user by their unique ID
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, RepositoryError>;

    /// Save a new user or update an existing one
    async fn save(&self, user: &User) -> Result<(), RepositoryError>;

    /// Update a user's last login timestamp
    async fn update_last_login(
        &self,
        id: &UserId,
        login_time: DateTime<Utc>,
    ) -> Result<(), RepositoryError>;

    /// Delete a user by their ID
    async fn delete(&self, id: &UserId) -> Result<(), RepositoryError>;

    /// Check if a user exists with the given email
    async fn exists_by_email(&self, email: &Email) -> Result<bool, RepositoryError>;

    /// Find users by role
    async fn find_by_role(&self, role: &str) -> Result<Vec<User>, RepositoryError>;

    /// Get all users (with pagination for large datasets)
    async fn find_all(
        &self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> Result<Vec<User>, RepositoryError>;

    /// Update user profile information
    async fn update_profile(
        &self,
        id: &UserId,
        name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<(), RepositoryError>;

    /// Activate or deactivate a user account
    async fn set_active_status(&self, id: &UserId, is_active: bool) -> Result<(), RepositoryError>;

    /// Add a role to a user
    async fn add_role(&self, id: &UserId, role: String) -> Result<(), RepositoryError>;

    /// Remove a role from a user
    async fn remove_role(&self, id: &UserId, role: &str) -> Result<(), RepositoryError>;

    /// Count total users
    async fn count(&self) -> Result<i64, RepositoryError>;

    /// Find users created within a date range
    async fn find_created_between(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<User>, RepositoryError>;

    /// Find users who haven't logged in recently
    async fn find_inactive_users(&self, since: DateTime<Utc>)
        -> Result<Vec<User>, RepositoryError>;
}

// Type alias moved to mod.rs to avoid duplication

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::value_objects::{Email, PasswordHash};

    // Mock implementation for testing
    pub(crate) struct MockUserRepository {
        users: std::sync::RwLock<std::collections::HashMap<String, User>>,
    }

    impl MockUserRepository {
        pub fn new() -> Self {
            Self {
                users: std::sync::RwLock::new(std::collections::HashMap::new()),
            }
        }

        pub fn add_user(&self, user: User) {
            let mut users = self.users.write().unwrap();
            users.insert(user.email.as_str().to_string(), user);
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_email(&self, email: &Email) -> Result<Option<User>, RepositoryError> {
            let users = self.users.read().unwrap();
            Ok(users.get(email.as_str()).cloned())
        }

        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, RepositoryError> {
            let users = self.users.read().unwrap();
            Ok(users.values().find(|u| u.id == *id).cloned())
        }

        async fn save(&self, user: &User) -> Result<(), RepositoryError> {
            let mut users = self.users.write().unwrap();
            if users.contains_key(user.email.as_str()) {
                return Err(RepositoryError::AlreadyExists);
            }
            users.insert(user.email.as_str().to_string(), user.clone());
            Ok(())
        }

        async fn update_last_login(
            &self,
            id: &UserId,
            login_time: DateTime<Utc>,
        ) -> Result<(), RepositoryError> {
            let mut users = self.users.write().unwrap();
            for user in users.values_mut() {
                if user.id == *id {
                    user.last_login = Some(login_time);
                    return Ok(());
                }
            }
            Err(RepositoryError::NotFound)
        }

        async fn delete(&self, _id: &UserId) -> Result<(), RepositoryError> {
            // Simplified implementation
            Ok(())
        }

        async fn exists_by_email(&self, email: &Email) -> Result<bool, RepositoryError> {
            let users = self.users.read().unwrap();
            Ok(users.contains_key(email.as_str()))
        }

        async fn find_by_role(&self, _role: &str) -> Result<Vec<User>, RepositoryError> {
            // Simplified implementation
            Ok(vec![])
        }

        async fn find_all(
            &self,
            _limit: Option<i64>,
            _offset: Option<i64>,
        ) -> Result<Vec<User>, RepositoryError> {
            let users = self.users.read().unwrap();
            Ok(users.values().cloned().collect())
        }

        async fn update_profile(
            &self,
            _id: &UserId,
            _name: Option<String>,
            _avatar_url: Option<String>,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }

        async fn set_active_status(
            &self,
            _id: &UserId,
            _is_active: bool,
        ) -> Result<(), RepositoryError> {
            Ok(())
        }

        async fn add_role(&self, _id: &UserId, _role: String) -> Result<(), RepositoryError> {
            Ok(())
        }

        async fn remove_role(&self, _id: &UserId, _role: &str) -> Result<(), RepositoryError> {
            Ok(())
        }

        async fn count(&self) -> Result<i64, RepositoryError> {
            let users = self.users.read().unwrap();
            Ok(users.len() as i64)
        }

        async fn find_created_between(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
        ) -> Result<Vec<User>, RepositoryError> {
            Ok(vec![])
        }

        async fn find_inactive_users(
            &self,
            _since: DateTime<Utc>,
        ) -> Result<Vec<User>, RepositoryError> {
            Ok(vec![])
        }
    }
}
