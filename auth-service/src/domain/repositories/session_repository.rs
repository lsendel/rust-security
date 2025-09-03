//! Session Repository Interface
//!
//! Defines the contract for session data access operations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::domain::entities::Session;
use crate::domain::value_objects::UserId;

/// Session repository errors
#[derive(Debug, thiserror::Error)]
pub enum SessionRepositoryError {
    #[error("Session not found")]
    NotFound,
    #[error("Session already exists")]
    AlreadyExists,
    #[error("Database error: {0}")]
    Database(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("Connection error: {0}")]
    Connection(String),
}

/// Session repository trait
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Find a session by its ID
    async fn find_by_id(&self, session_id: &str)
        -> Result<Option<Session>, SessionRepositoryError>;

    /// Find all active sessions for a user
    async fn find_by_user_id(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<Session>, SessionRepositoryError>;

    /// Save a new session
    async fn save(&self, session: &Session) -> Result<(), SessionRepositoryError>;

    /// Update an existing session
    async fn update(&self, session: &Session) -> Result<(), SessionRepositoryError>;

    /// Delete a session by ID
    async fn delete(&self, session_id: &str) -> Result<(), SessionRepositoryError>;

    /// Delete all sessions for a user
    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), SessionRepositoryError>;

    /// Delete expired sessions
    async fn delete_expired(&self) -> Result<i64, SessionRepositoryError>;

    /// Count active sessions for a user
    async fn count_by_user_id(&self, user_id: &UserId) -> Result<i64, SessionRepositoryError>;

    /// Extend session expiration
    async fn extend_session(
        &self,
        session_id: &str,
        new_expires_at: DateTime<Utc>,
    ) -> Result<(), SessionRepositoryError>;

    /// Check if session exists and is active
    async fn exists_and_active(&self, session_id: &str) -> Result<bool, SessionRepositoryError>;
}

/// Type alias for session repository trait object
pub type DynSessionRepository = Box<dyn SessionRepository>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::entities::Session;
    use crate::domain::value_objects::UserId;
    use std::collections::HashMap;
    use std::sync::RwLock;

    // Mock implementation for testing
    #[allow(dead_code)]
    pub struct MockSessionRepository {
        sessions: RwLock<HashMap<String, Session>>,
    }

    impl MockSessionRepository {
        #[allow(dead_code)]
        pub fn new() -> Self {
            Self {
                sessions: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl SessionRepository for MockSessionRepository {
        async fn find_by_id(
            &self,
            session_id: &str,
        ) -> Result<Option<Session>, SessionRepositoryError> {
            let sessions = self.sessions.read().unwrap();
            Ok(sessions.get(session_id).cloned())
        }

        async fn find_by_user_id(
            &self,
            user_id: &UserId,
        ) -> Result<Vec<Session>, SessionRepositoryError> {
            let sessions = self.sessions.read().unwrap();
            let user_sessions = sessions
                .values()
                .filter(|s| s.user_id == *user_id)
                .cloned()
                .collect();
            Ok(user_sessions)
        }

        async fn save(&self, session: &Session) -> Result<(), SessionRepositoryError> {
            let mut sessions = self.sessions.write().unwrap();
            if sessions.contains_key(&session.id) {
                return Err(SessionRepositoryError::AlreadyExists);
            }
            sessions.insert(session.id.clone(), session.clone());
            Ok(())
        }

        async fn update(&self, session: &Session) -> Result<(), SessionRepositoryError> {
            let mut sessions = self.sessions.write().unwrap();
            if !sessions.contains_key(&session.id) {
                return Err(SessionRepositoryError::NotFound);
            }
            sessions.insert(session.id.clone(), session.clone());
            Ok(())
        }

        async fn delete(&self, session_id: &str) -> Result<(), SessionRepositoryError> {
            let mut sessions = self.sessions.write().unwrap();
            if sessions.remove(session_id).is_none() {
                return Err(SessionRepositoryError::NotFound);
            }
            Ok(())
        }

        async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), SessionRepositoryError> {
            let mut sessions = self.sessions.write().unwrap();
            sessions.retain(|_, session| session.user_id != *user_id);
            Ok(())
        }

        async fn delete_expired(&self) -> Result<i64, SessionRepositoryError> {
            let mut sessions = self.sessions.write().unwrap();
            let before_count = sessions.len();
            let _now = Utc::now();
            sessions.retain(|_, session| !session.is_expired());
            let deleted_count = before_count - sessions.len();
            Ok(deleted_count as i64)
        }

        async fn count_by_user_id(&self, user_id: &UserId) -> Result<i64, SessionRepositoryError> {
            let sessions = self.sessions.read().unwrap();
            let count = sessions
                .values()
                .filter(|s| s.user_id == *user_id && s.is_active())
                .count();
            Ok(count as i64)
        }

        async fn extend_session(
            &self,
            session_id: &str,
            new_expires_at: DateTime<Utc>,
        ) -> Result<(), SessionRepositoryError> {
            let mut sessions = self.sessions.write().unwrap();
            if let Some(session) = sessions.get_mut(session_id) {
                session.expires_at = new_expires_at;
                Ok(())
            } else {
                Err(SessionRepositoryError::NotFound)
            }
        }

        async fn exists_and_active(
            &self,
            session_id: &str,
        ) -> Result<bool, SessionRepositoryError> {
            let sessions = self.sessions.read().unwrap();
            sessions
                .get(session_id)
                .map_or_else(|| Ok(false), |session| Ok(session.is_active()))
        }
    }
}
