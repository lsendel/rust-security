//! User ID value object with validation.

use serde::{Deserialize, Serialize};
use std::str::FromStr;
use uuid::Uuid;

/// User ID value object with validation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// Create a new user ID from a UUID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create a user ID from a string with validation
    pub fn from_string(id: String) -> Result<Self, String> {
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the ID as a UUID (if valid)
    pub fn as_uuid(&self) -> Option<Uuid> {
        Uuid::from_str(&self.0).ok()
    }

    /// Validate the user ID format
    fn validate(id: &str) -> Result<(), String> {
        if id.is_empty() {
            return Err("User ID cannot be empty".to_string());
        }

        if id.len() > 100 {
            return Err("User ID is too long (maximum 100 characters)".to_string());
        }

        // Try to parse as UUID first
        if Uuid::from_str(id).is_ok() {
            return Ok(());
        }

        // Allow other ID formats (like database auto-increment IDs)
        // Basic validation: alphanumeric, hyphens, underscores only
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err("User ID contains invalid characters".to_string());
        }

        Ok(())
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid.to_string())
    }
}

impl FromStr for UserId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s.to_string())
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use uuid::Uuid;

    #[test]
    fn test_user_id_creation() {
        let user_id = UserId::new();
        assert!(!user_id.as_str().is_empty());
        assert!(user_id.as_uuid().is_some());
    }

    #[test]
    fn test_user_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let user_id: UserId = uuid.into();
        assert_eq!(user_id.as_str(), uuid.to_string());
        assert_eq!(user_id.as_uuid(), Some(uuid));
    }

    #[test]
    fn test_user_id_from_string_uuid() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let user_id = UserId::from_string(uuid_str.to_string());
        assert!(user_id.is_ok());
        assert_eq!(user_id.unwrap().as_str(), uuid_str);
    }

    #[test]
    fn test_user_id_from_str() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let user_id = UserId::from_str(uuid_str);
        assert!(user_id.is_ok());
        assert_eq!(user_id.unwrap().as_str(), uuid_str);
    }

    #[test]
    fn test_user_id_display() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let user_id = UserId::from_string(uuid_str.to_string()).unwrap();
        assert_eq!(format!("{}", user_id), uuid_str);
    }

    #[test]
    fn test_valid_user_id_formats() {
        let valid_ids = vec![
            "550e8400-e29b-41d4-a716-446655440000", // UUID v4
            "123e4567-e89b-12d3-a456-426614174000", // UUID v3
            "user_123", // alphanumeric with underscore
            "user-123", // alphanumeric with hyphen
            "USER123", // uppercase
            "user123", // lowercase
            "123", // numeric only
            "a", // single character
        ];

        for valid_id in valid_ids {
            let user_id = UserId::from_string(valid_id.to_string());
            assert!(user_id.is_ok(), "ID '{}' should be valid", valid_id);
        }
    }

    #[test]
    fn test_invalid_user_id_formats() {
        let invalid_ids = vec![
            "", // empty
            " ", // space only
            "user@domain.com", // email format
            "user name", // space
            "user.name", // dot
            "user/name", // slash
            "user\\name", // backslash
            "user:name", // colon
            "user;name", // semicolon
            "user\"name", // quote
            "user'name", // apostrophe
        ];

        for invalid_id in invalid_ids {
            let user_id = UserId::from_string(invalid_id.to_string());
            assert!(user_id.is_err(), "ID '{}' should be invalid", invalid_id);
        }
    }

    #[test]
    fn test_user_id_too_long() {
        let long_id = "a".repeat(101);
        let user_id = UserId::from_string(long_id);
        assert!(user_id.is_err());
        assert!(user_id.unwrap_err().contains("too long"));
    }

    #[test]
    fn test_user_id_equality() {
        let id1 = UserId::from_string("550e8400-e29b-41d4-a716-446655440000".to_string()).unwrap();
        let id2 = UserId::from_string("550e8400-e29b-41d4-a716-446655440000".to_string()).unwrap();
        let id3 = UserId::from_string("650e8400-e29b-41d4-a716-446655440000".to_string()).unwrap();

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_user_id_hash() {
        use std::collections::HashMap;

        let mut map = HashMap::new();
        let id1 = UserId::from_string("550e8400-e29b-41d4-a716-446655440000".to_string()).unwrap();
        let id2 = UserId::from_string("550e8400-e29b-41d4-a716-446655440000".to_string()).unwrap();

        map.insert(id1, "value");

        assert_eq!(map.get(&id2), Some(&"value"));
    }

    #[test]
    fn test_uuid_parsing() {
        let uuid = Uuid::new_v4();
        let user_id = UserId::from_string(uuid.to_string()).unwrap();

        assert_eq!(user_id.as_uuid(), Some(uuid));
    }

    #[test]
    fn test_non_uuid_but_valid_id() {
        let user_id = UserId::from_string("custom_user_123".to_string()).unwrap();

        // Non-UUID format should return None for as_uuid
        assert_eq!(user_id.as_uuid(), None);
        assert_eq!(user_id.as_str(), "custom_user_123");
    }

    #[test]
    fn test_max_length_boundary() {
        let max_length_id = "a".repeat(100);
        let user_id = UserId::from_string(max_length_id.clone());
        assert!(user_id.is_ok());
        assert_eq!(user_id.unwrap().as_str(), max_length_id);
    }

    #[test]
    fn test_edge_cases() {
        // Test with various UUID versions
        let uuid_v1 = "550e8400-e29b-11d4-a716-446655440000";
        let uuid_v3 = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
        let uuid_v5 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";

        for uuid in &[uuid_v1, uuid_v3, uuid_v5] {
            let user_id = UserId::from_string(uuid.to_string());
            assert!(user_id.is_ok(), "UUID {} should be valid", uuid);
        }
    }
}
