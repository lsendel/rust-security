use chrono::{DateTime, Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Secure session data with comprehensive security controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureSessionData {
    pub user_id: String,
    pub client_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub client_ip: String,
    pub user_agent_hash: String, // Store hash instead of full user agent
    pub is_authenticated: bool,
    pub requires_mfa: bool,
    pub mfa_completed: bool,
    pub csrf_token: String,
    pub session_version: u32, // For session rotation
    pub access_count: u64,
    pub last_rotation: DateTime<Utc>,
}

/// Session configuration with security defaults
#[derive(Debug, Clone)]
pub struct SecureSessionConfig {
    pub ttl_seconds: u64,
    pub rotation_interval_seconds: u64,
    pub max_concurrent_sessions: u32,
    pub require_ip_binding: bool,
    pub require_user_agent_binding: bool,
    pub max_idle_time_seconds: u64,
    pub secure_cookies: bool,
    pub same_site_strict: bool,
}

impl Default for SecureSessionConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: 1800,                // 30 minutes
            rotation_interval_seconds: 900,   // 15 minutes
            max_concurrent_sessions: 5,       // Limit concurrent sessions
            require_ip_binding: true,         // Prevent session hijacking
            require_user_agent_binding: true, // Additional binding
            max_idle_time_seconds: 600,       // 10 minutes idle timeout
            secure_cookies: true,             // HTTPS only
            same_site_strict: true,           // CSRF protection
        }
    }
}

/// Secure session manager with comprehensive security controls
pub struct SecureSessionManager {
    sessions: Arc<RwLock<HashMap<String, SecureSessionData>>>,
    user_sessions: Arc<RwLock<HashMap<String, Vec<String>>>>, // Track sessions per user
    rng: SystemRandom,
    config: SecureSessionConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("Random generation failed")]
    RandomGenerationFailed,
    #[error("Session not found")]
    SessionNotFound,
    #[error("Session expired")]
    SessionExpired,
    #[error("Session hijacking detected")]
    SessionHijackingDetected,
    #[error("Too many concurrent sessions")]
    TooManyConcurrentSessions,
    #[error("Session idle timeout")]
    SessionIdleTimeout,
    #[error("MFA required")]
    MfaRequired,
    #[error("Invalid session state")]
    InvalidSessionState,
}

impl SecureSessionManager {
    pub fn new(config: SecureSessionConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            rng: SystemRandom::new(),
            config,
        }
    }

    /// Generate cryptographically secure session ID
    pub fn generate_session_id(&self) -> Result<String, SessionError> {
        let mut bytes = [0u8; 32]; // 256 bits of entropy
        self.rng
            .fill(&mut bytes)
            .map_err(|_| SessionError::RandomGenerationFailed)?;

        // Use base64url encoding for URL safety
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Generate secure CSRF token
    pub fn generate_csrf_token(&self) -> Result<String, SessionError> {
        let mut bytes = [0u8; 24]; // 192 bits of entropy
        self.rng
            .fill(&mut bytes)
            .map_err(|_| SessionError::RandomGenerationFailed)?;

        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Hash user agent for privacy while maintaining binding
    fn hash_user_agent(&self, user_agent: &str) -> String {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, user_agent.as_bytes());
        hex::encode(digest.as_ref())
    }

    /// Create new session with comprehensive security controls
    pub async fn create_session(
        &self,
        user_id: String,
        client_id: Option<String>,
        client_ip: String,
        user_agent: String,
        requires_mfa: bool,
    ) -> Result<String, SessionError> {
        // Check concurrent session limit
        {
            let user_sessions = self.user_sessions.read().await;
            if let Some(existing_sessions) = user_sessions.get(&user_id) {
                if existing_sessions.len() >= self.config.max_concurrent_sessions as usize {
                    return Err(SessionError::TooManyConcurrentSessions);
                }
            }
        }

        let session_id = self.generate_session_id()?;
        let csrf_token = self.generate_csrf_token()?;
        let now = Utc::now();

        let session_data = SecureSessionData {
            user_id: user_id.clone(),
            client_id,
            created_at: now,
            last_accessed: now,
            expires_at: now + Duration::seconds(self.config.ttl_seconds as i64),
            client_ip,
            user_agent_hash: self.hash_user_agent(&user_agent),
            is_authenticated: !requires_mfa, // Not authenticated until MFA complete
            requires_mfa,
            mfa_completed: !requires_mfa,
            csrf_token,
            session_version: 1,
            access_count: 1,
            last_rotation: now,
        };

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session_data);
        }

        // Track user sessions
        {
            let mut user_sessions = self.user_sessions.write().await;
            user_sessions
                .entry(user_id)
                .or_insert_with(Vec::new)
                .push(session_id.clone());
        }

        tracing::info!(
            session_id = %session_id,
            user_id = %session_data.user_id,
            requires_mfa = requires_mfa,
            "New session created"
        );

        Ok(session_id)
    }

    /// Validate session with comprehensive security checks
    pub async fn validate_session(
        &self,
        session_id: &str,
        client_ip: &str,
        user_agent: &str,
    ) -> Result<SecureSessionData, SessionError> {
        let mut sessions = self.sessions.write().await;

        let session = sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)?;

        let now = Utc::now();

        // Check expiration
        if now > session.expires_at {
            sessions.remove(session_id);
            self.cleanup_user_session(&session.user_id, session_id)
                .await;
            return Err(SessionError::SessionExpired);
        }

        // Check idle timeout
        let idle_duration = now - session.last_accessed;
        if idle_duration.num_seconds() > self.config.max_idle_time_seconds as i64 {
            sessions.remove(session_id);
            self.cleanup_user_session(&session.user_id, session_id)
                .await;
            return Err(SessionError::SessionIdleTimeout);
        }

        // Validate client binding (prevent session hijacking)
        if self.config.require_ip_binding && session.client_ip != client_ip {
            tracing::warn!(
                session_id = %session_id,
                original_ip = %session.client_ip,
                current_ip = %client_ip,
                user_id = %session.user_id,
                "Session IP mismatch detected - possible hijacking attempt"
            );

            sessions.remove(session_id);
            self.cleanup_user_session(&session.user_id, session_id)
                .await;
            return Err(SessionError::SessionHijackingDetected);
        }

        // Validate user agent binding
        if self.config.require_user_agent_binding {
            let current_ua_hash = self.hash_user_agent(user_agent);
            if session.user_agent_hash != current_ua_hash {
                tracing::warn!(
                    session_id = %session_id,
                    user_id = %session.user_id,
                    "Session user agent mismatch detected"
                );

                sessions.remove(session_id);
                self.cleanup_user_session(&session.user_id, session_id)
                    .await;
                return Err(SessionError::SessionHijackingDetected);
            }
        }

        // Check MFA requirements
        if session.requires_mfa && !session.mfa_completed {
            return Err(SessionError::MfaRequired);
        }

        // Update session activity
        session.last_accessed = now;
        session.access_count += 1;

        // Check if session rotation is needed
        let rotation_due = now - session.last_rotation;
        if rotation_due.num_seconds() > self.config.rotation_interval_seconds as i64 {
            return self.rotate_session(session_id, sessions).await;
        }

        Ok(session.clone())
    }

    /// Rotate session ID for security
    async fn rotate_session(
        &self,
        old_session_id: &str,
        mut sessions: tokio::sync::RwLockWriteGuard<'_, HashMap<String, SecureSessionData>>,
    ) -> Result<SecureSessionData, SessionError> {
        let old_session = sessions
            .get(old_session_id)
            .ok_or(SessionError::SessionNotFound)?
            .clone();

        // Generate new session ID
        let new_session_id = self.generate_session_id()?;
        let new_csrf_token = self.generate_csrf_token()?;
        let now = Utc::now();

        let mut new_session = old_session.clone();
        new_session.csrf_token = new_csrf_token;
        new_session.session_version += 1;
        new_session.last_rotation = now;
        new_session.last_accessed = now;

        // Replace old session with new one
        sessions.remove(old_session_id);
        sessions.insert(new_session_id.clone(), new_session.clone());

        // Update user session tracking
        {
            let mut user_sessions = self.user_sessions.write().await;
            if let Some(user_session_list) = user_sessions.get_mut(&old_session.user_id) {
                if let Some(pos) = user_session_list.iter().position(|id| id == old_session_id) {
                    user_session_list[pos] = new_session_id.clone();
                }
            }
        }

        tracing::info!(
            old_session_id = %old_session_id,
            new_session_id = %new_session_id,
            user_id = %old_session.user_id,
            "Session rotated for security"
        );

        Ok(new_session)
    }

    /// Complete MFA for session
    pub async fn complete_mfa(&self, session_id: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;

        let session = sessions
            .get_mut(session_id)
            .ok_or(SessionError::SessionNotFound)?;

        if !session.requires_mfa {
            return Err(SessionError::InvalidSessionState);
        }

        session.mfa_completed = true;
        session.is_authenticated = true;
        session.last_accessed = Utc::now();

        tracing::info!(
            session_id = %session_id,
            user_id = %session.user_id,
            "MFA completed for session"
        );

        Ok(())
    }

    /// Invalidate session
    pub async fn invalidate_session(&self, session_id: &str) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.remove(session_id) {
            self.cleanup_user_session(&session.user_id, session_id)
                .await;

            tracing::info!(
                session_id = %session_id,
                user_id = %session.user_id,
                "Session invalidated"
            );
        }

        Ok(())
    }

    /// Invalidate all sessions for a user
    pub async fn invalidate_user_sessions(&self, user_id: &str) -> Result<u32, SessionError> {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        let mut invalidated_count = 0;

        if let Some(session_ids) = user_sessions.remove(user_id) {
            for session_id in session_ids {
                if sessions.remove(&session_id).is_some() {
                    invalidated_count += 1;
                }
            }
        }

        tracing::info!(
            user_id = %user_id,
            count = invalidated_count,
            "All user sessions invalidated"
        );

        Ok(invalidated_count)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> u32 {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        let mut expired_sessions = Vec::new();

        // Find expired sessions
        for (session_id, session) in sessions.iter() {
            if now > session.expires_at {
                expired_sessions.push((session_id.clone(), session.user_id.clone()));
            }
        }

        // Remove expired sessions
        for (session_id, user_id) in &expired_sessions {
            sessions.remove(session_id);
            self.cleanup_user_session(user_id, session_id).await;
        }

        let count = expired_sessions.len() as u32;
        if count > 0 {
            tracing::info!(count = count, "Expired sessions cleaned up");
        }

        count
    }

    /// Helper to clean up user session tracking
    async fn cleanup_user_session(&self, user_id: &str, session_id: &str) {
        let mut user_sessions = self.user_sessions.write().await;
        if let Some(session_list) = user_sessions.get_mut(user_id) {
            session_list.retain(|id| id != session_id);
            if session_list.is_empty() {
                user_sessions.remove(user_id);
            }
        }
    }

    /// Get session statistics
    pub async fn get_session_stats(&self) -> SessionStats {
        let sessions = self.sessions.read().await;
        let user_sessions = self.user_sessions.read().await;

        SessionStats {
            total_sessions: sessions.len(),
            active_users: user_sessions.len(),
            authenticated_sessions: sessions.values().filter(|s| s.is_authenticated).count(),
            mfa_pending_sessions: sessions
                .values()
                .filter(|s| s.requires_mfa && !s.mfa_completed)
                .count(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionStats {
    pub total_sessions: usize,
    pub active_users: usize,
    pub authenticated_sessions: usize,
    pub mfa_pending_sessions: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_creation_and_validation() {
        let config = SecureSessionConfig::default();
        let manager = SecureSessionManager::new(config);

        let session_id = manager
            .create_session(
                "user123".to_string(),
                Some("client456".to_string()),
                "192.168.1.1".to_string(),
                "Mozilla/5.0".to_string(),
                false,
            )
            .await
            .unwrap();

        let session = manager
            .validate_session(&session_id, "192.168.1.1", "Mozilla/5.0")
            .await
            .unwrap();

        assert_eq!(session.user_id, "user123");
        assert!(session.is_authenticated);
    }

    #[tokio::test]
    async fn test_session_hijacking_detection() {
        let config = SecureSessionConfig::default();
        let manager = SecureSessionManager::new(config);

        let session_id = manager
            .create_session(
                "user123".to_string(),
                None,
                "192.168.1.1".to_string(),
                "Mozilla/5.0".to_string(),
                false,
            )
            .await
            .unwrap();

        // Try to use session from different IP
        let result = manager
            .validate_session(&session_id, "192.168.1.2", "Mozilla/5.0")
            .await;

        assert!(matches!(
            result,
            Err(SessionError::SessionHijackingDetected)
        ));
    }

    #[tokio::test]
    async fn test_concurrent_session_limit() {
        let mut config = SecureSessionConfig::default();
        config.max_concurrent_sessions = 2;
        let manager = SecureSessionManager::new(config);

        // Create maximum allowed sessions
        for i in 0..2 {
            manager
                .create_session(
                    "user123".to_string(),
                    None,
                    format!("192.168.1.{}", i + 1),
                    "Mozilla/5.0".to_string(),
                    false,
                )
                .await
                .unwrap();
        }

        // Try to create one more - should fail
        let result = manager
            .create_session(
                "user123".to_string(),
                None,
                "192.168.1.3".to_string(),
                "Mozilla/5.0".to_string(),
                false,
            )
            .await;

        assert!(matches!(
            result,
            Err(SessionError::TooManyConcurrentSessions)
        ));
    }
}
