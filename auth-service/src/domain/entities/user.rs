//! User entity representing a registered user in the system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::domain::value_objects::{Email, PasswordHash, UserId};

/// User entity representing a registered user in the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub password_hash: PasswordHash,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub roles: HashSet<String>,
    pub email_verified: bool,
    pub email_verification_token: Option<String>,
    pub password_reset_token: Option<String>,
    pub password_reset_expires: Option<DateTime<Utc>>,
}

impl User {
    /// Create a new user
    pub fn new(
        id: UserId,
        email: Email,
        password_hash: PasswordHash,
        name: Option<String>,
    ) -> Self {
        Self {
            id,
            email,
            password_hash,
            name,
            avatar_url: None,
            created_at: Utc::now(),
            last_login: None,
            is_active: true,
            roles: HashSet::new(),
            email_verified: false,
            email_verification_token: None,
            password_reset_token: None,
            password_reset_expires: None,
        }
    }

    /// Update user's last login time
    pub fn update_last_login(&mut self) {
        self.last_login = Some(Utc::now());
    }

    /// Add a role to the user
    pub fn add_role(&mut self, role: String) {
        self.roles.insert(role);
    }

    /// Remove a role from the user
    pub fn remove_role(&mut self, role: &str) {
        self.roles.remove(role);
    }

    /// Check if user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Check if user has any of the specified roles
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|role| self.has_role(role))
    }

    /// Deactivate the user
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }

    /// Activate the user
    pub fn activate(&mut self) {
        self.is_active = true;
    }

    /// Verify user's email
    pub fn verify_email(&mut self) {
        self.email_verified = true;
        self.email_verification_token = None;
    }

    /// Set password reset token
    pub fn set_password_reset_token(&mut self, token: String, expires_at: DateTime<Utc>) {
        self.password_reset_token = Some(token);
        self.password_reset_expires = Some(expires_at);
    }

    /// Clear password reset token
    pub fn clear_password_reset_token(&mut self) {
        self.password_reset_token = None;
        self.password_reset_expires = None;
    }

    /// Check if password reset token is valid
    pub fn is_password_reset_token_valid(&self) -> bool {
        if let (Some(_), Some(expires)) = (&self.password_reset_token, self.password_reset_expires) {
            Utc::now() < expires
        } else {
            false
        }
    }

    /// Update user's profile
    pub fn update_profile(&mut self, name: Option<String>, avatar_url: Option<String>) {
        if let Some(name) = name {
            self.name = Some(name);
        }
        if let Some(avatar_url) = avatar_url {
            self.avatar_url = Some(avatar_url);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_user_creation() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let user = User::new(user_id.clone(), email.clone(), password_hash.clone(), Some("Test User".to_string()));

        assert_eq!(user.id, user_id);
        assert_eq!(user.email, email);
        assert_eq!(user.password_hash, password_hash);
        assert_eq!(user.name, Some("Test User".to_string()));
        assert!(user.is_active);
        assert!(user.roles.is_empty());
        assert!(!user.email_verified);
    }

    #[test]
    fn test_user_role_management() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        user.add_role("admin".to_string());
        user.add_role("user".to_string());

        assert!(user.has_role("admin"));
        assert!(user.has_role("user"));
        assert!(!user.has_role("moderator"));

        assert!(user.has_any_role(&["admin", "moderator"]));
        assert!(!user.has_any_role(&["moderator", "guest"]));

        user.remove_role("admin");
        assert!(!user.has_role("admin"));
        assert!(user.has_role("user"));
    }

    #[test]
    fn test_user_activation() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        assert!(user.is_active);

        user.deactivate();
        assert!(!user.is_active);

        user.activate();
        assert!(user.is_active);
    }

    #[test]
    fn test_email_verification() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        assert!(!user.email_verified);

        user.verify_email();
        assert!(user.email_verified);
        assert!(user.email_verification_token.is_none());
    }

    #[test]
    fn test_password_reset_token() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        let future_time = Utc::now() + chrono::Duration::hours(1);
        user.set_password_reset_token("reset-token".to_string(), future_time);

        assert!(user.password_reset_token.is_some());
        assert!(user.password_reset_expires.is_some());
        assert!(user.is_password_reset_token_valid());

        user.clear_password_reset_token();
        assert!(user.password_reset_token.is_none());
        assert!(user.password_reset_expires.is_none());
        assert!(!user.is_password_reset_token_valid());
    }

    #[test]
    fn test_expired_password_reset_token() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        let past_time = Utc::now() - chrono::Duration::hours(1);
        user.set_password_reset_token("reset-token".to_string(), past_time);

        assert!(!user.is_password_reset_token_valid());
    }

    #[test]
    fn test_profile_update() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        assert!(user.name.is_none());
        assert!(user.avatar_url.is_none());

        user.update_profile(Some("Updated Name".to_string()), Some("avatar.jpg".to_string()));

        assert_eq!(user.name, Some("Updated Name".to_string()));
        assert_eq!(user.avatar_url, Some("avatar.jpg".to_string()));

        // Test partial update
        user.update_profile(None, Some("new-avatar.jpg".to_string()));
        assert_eq!(user.name, Some("Updated Name".to_string()));
        assert_eq!(user.avatar_url, Some("new-avatar.jpg".to_string()));
    }

    #[test]
    fn test_user_last_login() {
        let user_id = UserId::new();
        let email = Email::new("test@example.com".to_string()).unwrap();
        let password_hash = PasswordHash::new("$argon2id$v=19$m=4096,t=3,p=1$test".to_string()).unwrap();

        let mut user = User::new(user_id, email, password_hash, None);

        assert!(user.last_login.is_none());

        user.update_last_login();
        assert!(user.last_login.is_some());
    }
}
