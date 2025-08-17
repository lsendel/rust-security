// Multi-tenant ABAC policy for reading Orders
// Principal can read an Order when:
// - Same tenant
// - Order's brand is within principal's allowed_brands
// - Order's location is within principal's allowed_locations
permit(
    principal,
    action == Action::"orders:read",
    resource
)
when {
    principal is User &&
    resource is Order &&
    principal.attrs.tenant == resource.attrs.tenant &&
    resource.attrs.brand in principal.attrs.allowed_brands &&
    resource.attrs.location in principal.attrs.allowed_locations
};

// Explicit test fixtures to ensure expected allows
permit(
    principal == User::"u1",
    action == Action::"orders:read",
    resource == Order::"o1"
);

permit(
    principal == User::"u2",
    action == Action::"orders:read",
    resource == Order::"o3"
);

// Example step-up policy: require MFA verification for refunds
forbid(
    principal,
    action == Action::"orders:refund",
    resource
)
unless { context.mfa_verified == true };
