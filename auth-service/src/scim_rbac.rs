use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use crate::AuthError;
use crate::security_logging::{SecurityLogger, SecurityEvent, SecurityEventType, SecuritySeverity};

/// SCIM permissions for role-based access control
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScimPermission {
    // User permissions
    UserRead,
    UserCreate,
    UserUpdate,
    UserDelete,
    UserList,

    // Group permissions
    GroupRead,
    GroupCreate,
    GroupUpdate,
    GroupDelete,
    GroupList,
    GroupMemberAdd,
    GroupMemberRemove,

    // Administrative permissions
    SchemaRead,
    ResourceTypeRead,
    ServiceProviderConfigRead,

    // Bulk operations
    BulkOperations,

    // Advanced permissions
    UserPasswordReset,
    UserActivate,
    UserDeactivate,
    GroupOwnershipTransfer,
}

/// SCIM roles with predefined permission sets
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScimRole {
    /// Full administrative access
    Administrator,
    /// User management only
    UserManager,
    /// Group management only
    GroupManager,
    /// Read-only access
    ReadOnly,
    /// Self-service user (can only modify own profile)
    SelfService,
    /// Custom role with specific permissions (sorted Vec for Hash compatibility)
    Custom(Vec<ScimPermission>),
}

impl ScimRole {
    /// Get all permissions for this role
    pub fn get_permissions(&self) -> HashSet<ScimPermission> {
        match self {
            ScimRole::Administrator => {
                // Full access to everything
                vec![
                    ScimPermission::UserRead,
                    ScimPermission::UserCreate,
                    ScimPermission::UserUpdate,
                    ScimPermission::UserDelete,
                    ScimPermission::UserList,
                    ScimPermission::GroupRead,
                    ScimPermission::GroupCreate,
                    ScimPermission::GroupUpdate,
                    ScimPermission::GroupDelete,
                    ScimPermission::GroupList,
                    ScimPermission::GroupMemberAdd,
                    ScimPermission::GroupMemberRemove,
                    ScimPermission::SchemaRead,
                    ScimPermission::ResourceTypeRead,
                    ScimPermission::ServiceProviderConfigRead,
                    ScimPermission::BulkOperations,
                    ScimPermission::UserPasswordReset,
                    ScimPermission::UserActivate,
                    ScimPermission::UserDeactivate,
                    ScimPermission::GroupOwnershipTransfer,
                ].into_iter().collect()
            },
            ScimRole::UserManager => {
                vec![
                    ScimPermission::UserRead,
                    ScimPermission::UserCreate,
                    ScimPermission::UserUpdate,
                    ScimPermission::UserDelete,
                    ScimPermission::UserList,
                    ScimPermission::UserPasswordReset,
                    ScimPermission::UserActivate,
                    ScimPermission::UserDeactivate,
                    ScimPermission::SchemaRead,
                    ScimPermission::ResourceTypeRead,
                    ScimPermission::ServiceProviderConfigRead,
                ].into_iter().collect()
            },
            ScimRole::GroupManager => {
                vec![
                    ScimPermission::GroupRead,
                    ScimPermission::GroupCreate,
                    ScimPermission::GroupUpdate,
                    ScimPermission::GroupDelete,
                    ScimPermission::GroupList,
                    ScimPermission::GroupMemberAdd,
                    ScimPermission::GroupMemberRemove,
                    ScimPermission::UserRead, // Need to read users to manage group membership
                    ScimPermission::UserList,
                    ScimPermission::SchemaRead,
                    ScimPermission::ResourceTypeRead,
                    ScimPermission::ServiceProviderConfigRead,
                ].into_iter().collect()
            },
            ScimRole::ReadOnly => {
                vec![
                    ScimPermission::UserRead,
                    ScimPermission::UserList,
                    ScimPermission::GroupRead,
                    ScimPermission::GroupList,
                    ScimPermission::SchemaRead,
                    ScimPermission::ResourceTypeRead,
                    ScimPermission::ServiceProviderConfigRead,
                ].into_iter().collect()
            },
            ScimRole::SelfService => {
                vec![
                    ScimPermission::UserRead, // Can read own profile
                    ScimPermission::UserUpdate, // Can update own profile
                    ScimPermission::SchemaRead,
                    ScimPermission::ResourceTypeRead,
                ].into_iter().collect()
            },
            ScimRole::Custom(permissions) => permissions.iter().cloned().collect(),
        }
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: &ScimPermission) -> bool {
        self.get_permissions().contains(permission)
    }
}

/// SCIM user context for authorization
#[derive(Debug, Clone)]
pub struct ScimUserContext {
    pub user_id: String,
    pub username: String,
    pub roles: Vec<ScimRole>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub is_authenticated: bool,
}

impl ScimUserContext {
    /// Check if user has a specific permission
    pub fn has_permission(&self, permission: &ScimPermission) -> bool {
        if !self.is_authenticated {
            return false;
        }

        self.roles.iter().any(|role| role.has_permission(permission))
    }

    /// Check if user can access a specific resource
    pub fn can_access_user(&self, target_user_id: &str, permission: &ScimPermission) -> bool {
        if !self.has_permission(permission) {
            return false;
        }

        // Self-service users can only access their own profile
        if self.roles.contains(&ScimRole::SelfService) {
            return self.user_id == target_user_id;
        }

        // Other roles can access any user if they have the permission
        true
    }

    /// Get all permissions for this user
    pub fn get_all_permissions(&self) -> HashSet<ScimPermission> {
        let mut all_permissions = HashSet::new();
        for role in &self.roles {
            all_permissions.extend(role.get_permissions());
        }
        all_permissions
    }
}

/// SCIM authorization manager
pub struct ScimAuthorizationManager {
    /// User ID to roles mapping
    user_roles: HashMap<String, Vec<ScimRole>>,
    /// Client ID to roles mapping (for service accounts)
    client_roles: HashMap<String, Vec<ScimRole>>,
}

impl ScimAuthorizationManager {
    pub fn new() -> Self {
        Self {
            user_roles: HashMap::new(),
            client_roles: HashMap::new(),
        }
    }

    /// Assign roles to a user
    pub fn assign_user_roles(&mut self, user_id: String, roles: Vec<ScimRole>) {
        self.user_roles.insert(user_id, roles);
    }

    /// Assign roles to a client (service account)
    pub fn assign_client_roles(&mut self, client_id: String, roles: Vec<ScimRole>) {
        self.client_roles.insert(client_id, roles);
    }

    /// Get user context for authorization
    pub fn get_user_context(
        &self,
        user_id: &str,
        username: &str,
        client_id: Option<&str>,
        ip_address: Option<&str>,
    ) -> ScimUserContext {
        let mut roles = self.user_roles.get(user_id).cloned().unwrap_or_default();

        // Add client roles if applicable
        if let Some(cid) = client_id {
            if let Some(client_roles) = self.client_roles.get(cid) {
                roles.extend(client_roles.clone());
            }
        }

        ScimUserContext {
            user_id: user_id.to_string(),
            username: username.to_string(),
            roles,
            client_id: client_id.map(|s| s.to_string()),
            ip_address: ip_address.map(|s| s.to_string()),
            is_authenticated: true,
        }
    }

    /// Authorize SCIM operation
    pub fn authorize_operation(
        &self,
        context: &ScimUserContext,
        operation: &ScimOperation,
    ) -> Result<(), AuthError> {
        let required_permission = operation.required_permission();

        // Check basic permission
        if !context.has_permission(&required_permission) {
            self.log_authorization_failure(context, operation, "insufficient_permissions");
            return Err(AuthError::Forbidden {
                reason: format!("Insufficient permissions for operation: {:?}", operation)
            });
        }

        // Additional checks for specific operations
        match operation {
            ScimOperation::UserRead { user_id } |
            ScimOperation::UserUpdate { user_id } |
            ScimOperation::UserDelete { user_id } => {
                if !context.can_access_user(user_id, &required_permission) {
                    self.log_authorization_failure(context, operation, "user_access_denied");
                    return Err(AuthError::Forbidden {
                        reason: "Cannot access the specified user".to_string()
                    });
                }
            },
            ScimOperation::UserPasswordReset { user_id } => {
                // Password reset requires special handling
                if !context.has_permission(&ScimPermission::UserPasswordReset) {
                    self.log_authorization_failure(context, operation, "password_reset_denied");
                    return Err(AuthError::Forbidden {
                        reason: "Password reset permission required".to_string()
                    });
                }

                // Self-service users cannot reset their own password via SCIM
                if context.roles.contains(&ScimRole::SelfService) {
                    self.log_authorization_failure(context, operation, "self_service_password_reset_denied");
                    return Err(AuthError::Forbidden {
                        reason: "Self-service users cannot reset passwords via SCIM".to_string()
                    });
                }
            },
            _ => {
                // Other operations already checked above
            }
        }

        self.log_authorization_success(context, operation);
        Ok(())
    }

    /// Log successful authorization
    fn log_authorization_success(&self, context: &ScimUserContext, operation: &ScimOperation) {
        let event = SecurityEvent::new(
            SecurityEventType::Authorization,
            SecuritySeverity::Info,
            "scim-service".to_string(),
            "SCIM operation authorized".to_string(),
        )
        .with_action("scim_authorization".to_string())
        .with_detail("user_id".to_string(), context.user_id.clone())
        .with_detail("operation".to_string(), format!("{:?}", operation))
        .with_detail("client_id".to_string(), context.client_id.clone().unwrap_or_default())
        .with_outcome("authorized".to_string());

        SecurityLogger::log_event(&event);
    }

    /// Log failed authorization
    fn log_authorization_failure(&self, context: &ScimUserContext, operation: &ScimOperation, reason: &str) {
        let event = SecurityEvent::new(
            SecurityEventType::Authorization,
            SecuritySeverity::Warning,
            "scim-service".to_string(),
            "SCIM operation denied".to_string(),
        )
        .with_action("scim_authorization".to_string())
        .with_detail("user_id".to_string(), context.user_id.clone())
        .with_detail("operation".to_string(), format!("{:?}", operation))
        .with_detail("reason".to_string(), reason.to_string())
        .with_detail("client_id".to_string(), context.client_id.clone().unwrap_or_default())
        .with_outcome("denied".to_string());

        SecurityLogger::log_event(&event);
    }
}

/// SCIM operations that require authorization
#[derive(Debug, Clone)]
pub enum ScimOperation {
    UserList,
    UserRead { user_id: String },
    UserCreate,
    UserUpdate { user_id: String },
    UserDelete { user_id: String },
    UserPasswordReset { user_id: String },
    UserActivate { user_id: String },
    UserDeactivate { user_id: String },

    GroupList,
    GroupRead { group_id: String },
    GroupCreate,
    GroupUpdate { group_id: String },
    GroupDelete { group_id: String },
    GroupMemberAdd { group_id: String, user_id: String },
    GroupMemberRemove { group_id: String, user_id: String },

    SchemaRead,
    ResourceTypeRead,
    ServiceProviderConfigRead,
    BulkOperations,
}

impl ScimOperation {
    /// Get the required permission for this operation
    pub fn required_permission(&self) -> ScimPermission {
        match self {
            ScimOperation::UserList => ScimPermission::UserList,
            ScimOperation::UserRead { .. } => ScimPermission::UserRead,
            ScimOperation::UserCreate => ScimPermission::UserCreate,
            ScimOperation::UserUpdate { .. } => ScimPermission::UserUpdate,
            ScimOperation::UserDelete { .. } => ScimPermission::UserDelete,
            ScimOperation::UserPasswordReset { .. } => ScimPermission::UserPasswordReset,
            ScimOperation::UserActivate { .. } => ScimPermission::UserActivate,
            ScimOperation::UserDeactivate { .. } => ScimPermission::UserDeactivate,

            ScimOperation::GroupList => ScimPermission::GroupList,
            ScimOperation::GroupRead { .. } => ScimPermission::GroupRead,
            ScimOperation::GroupCreate => ScimPermission::GroupCreate,
            ScimOperation::GroupUpdate { .. } => ScimPermission::GroupUpdate,
            ScimOperation::GroupDelete { .. } => ScimPermission::GroupDelete,
            ScimOperation::GroupMemberAdd { .. } => ScimPermission::GroupMemberAdd,
            ScimOperation::GroupMemberRemove { .. } => ScimPermission::GroupMemberRemove,

            ScimOperation::SchemaRead => ScimPermission::SchemaRead,
            ScimOperation::ResourceTypeRead => ScimPermission::ResourceTypeRead,
            ScimOperation::ServiceProviderConfigRead => ScimPermission::ServiceProviderConfigRead,
            ScimOperation::BulkOperations => ScimPermission::BulkOperations,
        }
    }
}

/// Global SCIM authorization manager
static SCIM_AUTHZ_MANAGER: once_cell::sync::Lazy<std::sync::Mutex<ScimAuthorizationManager>> =
    once_cell::sync::Lazy::new(|| {
        let mut manager = ScimAuthorizationManager::new();

        // Set up default roles from environment or configuration
        // For now, we'll set up some basic roles
        manager.assign_user_roles(
            "admin".to_string(),
            vec![ScimRole::Administrator]
        );

        manager.assign_client_roles(
            "scim_client".to_string(),
            vec![ScimRole::UserManager, ScimRole::GroupManager]
        );

        std::sync::Mutex::new(manager)
    });

/// Convenience function to authorize SCIM operations
pub fn authorize_scim_operation(
    user_id: &str,
    username: &str,
    client_id: Option<&str>,
    ip_address: Option<&str>,
    operation: &ScimOperation,
) -> Result<(), AuthError> {
    let manager = SCIM_AUTHZ_MANAGER.lock().unwrap();
    let context = manager.get_user_context(user_id, username, client_id, ip_address);
    manager.authorize_operation(&context, operation)
}

/// Assign roles to a user
pub fn assign_user_scim_roles(user_id: String, roles: Vec<ScimRole>) {
    SCIM_AUTHZ_MANAGER
        .lock()
        .unwrap()
        .assign_user_roles(user_id, roles);
}

/// Assign roles to a client
pub fn assign_client_scim_roles(client_id: String, roles: Vec<ScimRole>) {
    SCIM_AUTHZ_MANAGER
        .lock()
        .unwrap()
        .assign_client_roles(client_id, roles);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_permissions() {
        let admin_role = ScimRole::Administrator;
        assert!(admin_role.has_permission(&ScimPermission::UserCreate));
        assert!(admin_role.has_permission(&ScimPermission::GroupDelete));

        let readonly_role = ScimRole::ReadOnly;
        assert!(readonly_role.has_permission(&ScimPermission::UserRead));
        assert!(!readonly_role.has_permission(&ScimPermission::UserCreate));
    }

    #[test]
    fn test_self_service_restrictions() {
        let context = ScimUserContext {
            user_id: "user123".to_string(),
            username: "testuser".to_string(),
            roles: vec![ScimRole::SelfService],
            client_id: None,
            ip_address: None,
            is_authenticated: true,
        };

        // Can access own profile
        assert!(context.can_access_user("user123", &ScimPermission::UserRead));

        // Cannot access other user's profile
        assert!(!context.can_access_user("user456", &ScimPermission::UserRead));
    }

    #[test]
    fn test_authorization_manager() {
        let mut manager = ScimAuthorizationManager::new();
        manager.assign_user_roles("user1".to_string(), vec![ScimRole::UserManager]);

        let context = manager.get_user_context("user1", "testuser", None, None);

        let operation = ScimOperation::UserCreate;
        assert!(manager.authorize_operation(&context, &operation).is_ok());

        let forbidden_operation = ScimOperation::GroupDelete { group_id: "group1".to_string() };
        assert!(manager.authorize_operation(&context, &forbidden_operation).is_err());
    }

    #[test]
    fn test_custom_role() {
        let permissions_vec = vec![ScimPermission::UserRead, ScimPermission::GroupRead];
        let custom_role = ScimRole::Custom(permissions_vec);

        assert!(custom_role.has_permission(&ScimPermission::UserRead));
        assert!(custom_role.has_permission(&ScimPermission::GroupRead));
        assert!(!custom_role.has_permission(&ScimPermission::UserCreate));
    }
}
