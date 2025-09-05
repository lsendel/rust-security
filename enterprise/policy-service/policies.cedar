// MVP Policy Service Default Policies

// Allow authenticated users to perform read operations
permit(
    principal,
    action == Action::"read",
    resource
) when {
    principal has authenticated && 
    principal.authenticated == true
};

// Allow admins to perform any action
permit(
    principal,
    action,
    resource
) when {
    principal has role && 
    principal.role == "admin"
};

// Allow users to access their own resources
permit(
    principal,
    action == Action::"read",
    resource
) when {
    principal has authenticated && 
    principal.authenticated == true &&
    resource has owner &&
    principal.id == resource.owner
};

// Deny access to sensitive resources without proper clearance
forbid(
    principal,
    action,
    resource
) when {
    resource has sensitive && 
    resource.sensitive == true &&
!(principal has clearance && principal.clearance == "high")
};

// =====================
// Admin Policies (Granular)
// =====================

// Superadmin blanket allow
permit(principal, action, resource)
when { principal has roles && "superadmin" in principal.roles };

// Read-only admin: allow read-only ops
permit(principal,
    action,
    resource
)
when { principal has roles && "readonly" in principal.roles && (
    context has action_name && (
        context.action_name == "Admin_users_read" ||
        context.action_name == "Admin_users_read_one" ||
        context.action_name == "Admin_metrics_read" ||
        context.action_name == "Admin_health_read" ||
        context.action_name == "Admin_pq_metrics" ||
        context.action_name == "Admin_pq_health" ||
        context.action_name == "Admin_pq_migration_timeline"
    )
)};

// Billing role: billing CRUD
permit(principal, action, resource)
when { principal has roles && "billing" in principal.roles && (
    context has action_name && (
        context.action_name == "Admin_billing_read" ||
        context.action_name == "Admin_billing_update" ||
        context.action_name == "Admin_billing_delete"
    )
)};

// Security operations: keys and PQ keys
permit(principal, action, resource)
when { principal has roles && "secops" in principal.roles && (
    context has action_name && (
        context.action_name == "Admin_keys_read" ||
        context.action_name == "Admin_keys_rotate" ||
        context.action_name == "Admin_pq_keys_stats" ||
        context.action_name == "Admin_pq_keys_rotate"
    )
)};

// Users item update/delete operations (granular)
permit(principal, action, resource)
when { principal has roles && "user-admin" in principal.roles && (
    context has action_name && (
        context.action_name == "Admin_users_update_one" ||
        context.action_name == "Admin_users_delete_one"
    )
)};

// PQ emergency rollback requires MFA and POST
permit(principal, Action::"Admin_pq_emergency_rollback", resource)
when { principal has mfa_verified && principal.mfa_verified == true && context.method == "POST" };

// Forbid destructive user deletes unless superadmin
forbid(principal, action, resource)
when { !(principal has roles && "superadmin" in principal.roles) && (
    context has action_name && (
        context.action_name == "Admin_users_delete" || context.action_name == "Admin_users_delete_one"
    )
)};

// =====================
// Auth & OAuth Examples
// =====================

// Allow a user to read their own profile
permit(principal, Action::"User_read_profile", resource)
when { principal == resource };

// Allow OAuth client flows (authorize + token) for any registered client
permit(principal, Action::"OAuth_authorize", resource)
when { principal is Client && resource is OAuthClient };

permit(principal, Action::"OAuth_token", resource)
when { principal is Client && resource is OAuthClient &&
       (! (context has grant_type) ||
         (context.grant_type == "authorization_code" || context.grant_type == "client_credentials")) };
