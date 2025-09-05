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