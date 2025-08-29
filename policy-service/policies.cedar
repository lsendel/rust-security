// Allow users to read orders if they belong to the same tenant and brand
permit(
    principal,
    action == Action::"orders:read",
    resource
) when {
    principal.tenant == resource.tenant &&
    principal.brand == resource.brand
};

// Allow users to read orders if they belong to the same tenant and have location access
permit(
    principal,
    action == Action::"orders:read",
    resource
) when {
    principal.tenant == resource.tenant &&
    principal.location == resource.location
};
