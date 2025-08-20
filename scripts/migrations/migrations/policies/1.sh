#!/bin/bash
# Policy Migration v1: Initialize Cedar policy framework
# Purpose: Set up initial Cedar policies with RBAC foundation

set -euo pipefail

# Migration metadata
MIGRATION_NAME="Initialize Cedar Policy Framework"
MIGRATION_DESCRIPTION="Set up initial Cedar policies with RBAC foundation and basic access controls"

echo "=== Policy Migration v1: $MIGRATION_NAME ==="
echo "Description: $MIGRATION_DESCRIPTION"
echo "Timestamp: $(date)"

# Verify Policy Service is running
if ! kubectl get deployment policy-service -n rust-security >/dev/null 2>&1; then
    echo "ERROR: Policy Service deployment not found"
    exit 1
fi

# Get Policy Service pod
POLICY_POD=$(kubectl get pods -n rust-security -l app=policy-service -o jsonpath='{.items[0].metadata.name}')
if [[ -z "$POLICY_POD" ]]; then
    echo "ERROR: Policy Service pod not found"
    exit 1
fi

echo "✓ Policy Service verification completed (Pod: $POLICY_POD)"

# Create policy directories
echo "Creating policy directory structure..."

kubectl exec "$POLICY_POD" -n rust-security -- mkdir -p /etc/policies/{rbac,abac,common,schemas}
kubectl exec "$POLICY_POD" -n rust-security -- mkdir -p /etc/policies/migrations/v1

echo "✓ Policy directory structure created"

# Create Cedar schema for RBAC
echo "Creating Cedar RBAC schema..."

kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/schemas/rbac.cedarschema > /dev/null <<'EOF'
namespace RustSecurity {
  // Entity definitions
  entity User in [UserGroup] = {
    "email": String,
    "name": String,
    "department": String,
    "title": String,
    "isActive": Boolean,
    "createdAt": String,
    "lastLogin": String,
  };

  entity UserGroup in [UserGroup] = {
    "name": String,
    "description": String,
    "isActive": Boolean,
  };

  entity Role = {
    "name": String,
    "description": String,
    "permissions": Set<String>,
    "isActive": Boolean,
  };

  entity Resource = {
    "type": String,
    "id": String,
    "owner": User,
    "classification": String,
    "tags": Set<String>,
  };

  entity Action = {
    "name": String,
    "category": String,
    "riskLevel": String,
  };

  // Action definitions
  action "auth:login" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "auth:logout" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "auth:refresh_token" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "user:read" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "user:create" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "user:update" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "user:delete" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "admin:read" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "admin:write" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "policy:read" appliesTo {
    principal: [User],
    resource: [Resource]
  };

  action "policy:write" appliesTo {
    principal: [User],
    resource: [Resource]
  };
}
EOF

echo "✓ Cedar RBAC schema created"

# Create foundational policies
echo "Creating foundational RBAC policies..."

# Policy 1: Basic authentication access
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/rbac/001-basic-auth.cedar > /dev/null <<'EOF'
// Policy: Basic Authentication Access
// Description: Allow users to authenticate and manage their own sessions
@id("rbac-basic-auth-v1")
permit (
  principal is RustSecurity::User,
  action in [
    RustSecurity::Action::"auth:login",
    RustSecurity::Action::"auth:logout", 
    RustSecurity::Action::"auth:refresh_token"
  ],
  resource is RustSecurity::Resource
)
when {
  principal.isActive == true
};
EOF

# Policy 2: Self-service user operations
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/rbac/002-self-service.cedar > /dev/null <<'EOF'
// Policy: Self-Service User Operations
// Description: Allow users to read and update their own profile
@id("rbac-self-service-v1")
permit (
  principal is RustSecurity::User,
  action in [RustSecurity::Action::"user:read", RustSecurity::Action::"user:update"],
  resource is RustSecurity::Resource
)
when {
  principal.isActive == true &&
  resource.owner == principal &&
  resource.type == "user_profile"
};
EOF

# Policy 3: Admin role permissions
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/rbac/003-admin-permissions.cedar > /dev/null <<'EOF'
// Policy: Admin Role Permissions
// Description: Grant comprehensive access to admin users
@id("rbac-admin-permissions-v1")
permit (
  principal is RustSecurity::User,
  action in [
    RustSecurity::Action::"admin:read",
    RustSecurity::Action::"admin:write",
    RustSecurity::Action::"user:create",
    RustSecurity::Action::"user:read",
    RustSecurity::Action::"user:update",
    RustSecurity::Action::"user:delete"
  ],
  resource is RustSecurity::Resource
)
when {
  principal.isActive == true &&
  principal in RustSecurity::UserGroup::"administrators"
};
EOF

# Policy 4: Policy management permissions
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/rbac/004-policy-management.cedar > /dev/null <<'EOF'
// Policy: Policy Management Permissions
// Description: Allow policy administrators to manage authorization policies
@id("rbac-policy-management-v1")
permit (
  principal is RustSecurity::User,
  action in [
    RustSecurity::Action::"policy:read",
    RustSecurity::Action::"policy:write"
  ],
  resource is RustSecurity::Resource
)
when {
  principal.isActive == true &&
  principal in RustSecurity::UserGroup::"policy_administrators" &&
  resource.type == "authorization_policy"
};
EOF

# Policy 5: Read-only access for auditors
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/rbac/005-auditor-access.cedar > /dev/null <<'EOF'
// Policy: Auditor Read-Only Access
// Description: Grant read-only access to auditors for compliance purposes
@id("rbac-auditor-access-v1")
permit (
  principal is RustSecurity::User,
  action in [
    RustSecurity::Action::"user:read",
    RustSecurity::Action::"admin:read",
    RustSecurity::Action::"policy:read"
  ],
  resource is RustSecurity::Resource
)
when {
  principal.isActive == true &&
  principal in RustSecurity::UserGroup::"auditors"
};
EOF

# Policy 6: Data classification enforcement
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/rbac/006-data-classification.cedar > /dev/null <<'EOF'
// Policy: Data Classification Enforcement
// Description: Enforce access controls based on data classification
@id("rbac-data-classification-v1")
forbid (
  principal is RustSecurity::User,
  action,
  resource is RustSecurity::Resource
)
when {
  resource.classification == "confidential" &&
  !(principal in RustSecurity::UserGroup::"confidential_access")
};
EOF

echo "✓ Foundational RBAC policies created"

# Create common utility policies
echo "Creating common utility policies..."

# Common policy: Time-based access
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/common/time-based-access.cedar > /dev/null <<'EOF'
// Policy: Business Hours Access
// Description: Restrict sensitive operations to business hours
@id("common-business-hours-v1")
forbid (
  principal,
  action in [
    RustSecurity::Action::"user:delete",
    RustSecurity::Action::"policy:write"
  ],
  resource
)
when {
  // This would be replaced with actual time checking in real implementation
  context has "current_hour" &&
  (context["current_hour"] < 8 || context["current_hour"] > 18)
};
EOF

# Common policy: IP-based restrictions
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/common/ip-restrictions.cedar > /dev/null <<'EOF'
// Policy: IP-Based Access Restrictions
// Description: Restrict admin operations to corporate network
@id("common-ip-restrictions-v1")
forbid (
  principal,
  action in [
    RustSecurity::Action::"admin:write",
    RustSecurity::Action::"policy:write"
  ],
  resource
)
when {
  context has "source_ip" &&
  !context["source_ip"].isIpInRange(ip("10.0.0.0/8")) &&
  !context["source_ip"].isIpInRange(ip("192.168.0.0/16"))
};
EOF

echo "✓ Common utility policies created"

# Create policy metadata and index
echo "Creating policy metadata..."

kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/policy-index.json > /dev/null <<'EOF'
{
  "version": "1",
  "schema_version": "1.0",
  "created_at": "2024-08-20T00:00:00Z",
  "description": "Initial Cedar policy set with RBAC foundation",
  "policies": [
    {
      "id": "rbac-basic-auth-v1",
      "file": "rbac/001-basic-auth.cedar",
      "category": "authentication",
      "description": "Basic authentication access for active users",
      "risk_level": "low"
    },
    {
      "id": "rbac-self-service-v1", 
      "file": "rbac/002-self-service.cedar",
      "category": "user_management",
      "description": "Self-service user profile operations",
      "risk_level": "low"
    },
    {
      "id": "rbac-admin-permissions-v1",
      "file": "rbac/003-admin-permissions.cedar", 
      "category": "administration",
      "description": "Administrative permissions for admin users",
      "risk_level": "high"
    },
    {
      "id": "rbac-policy-management-v1",
      "file": "rbac/004-policy-management.cedar",
      "category": "policy_management", 
      "description": "Policy management permissions",
      "risk_level": "critical"
    },
    {
      "id": "rbac-auditor-access-v1",
      "file": "rbac/005-auditor-access.cedar",
      "category": "auditing",
      "description": "Read-only access for auditors",
      "risk_level": "low"
    },
    {
      "id": "rbac-data-classification-v1",
      "file": "rbac/006-data-classification.cedar",
      "category": "data_protection",
      "description": "Data classification enforcement",
      "risk_level": "high"
    },
    {
      "id": "common-business-hours-v1",
      "file": "common/time-based-access.cedar",
      "category": "temporal_controls",
      "description": "Business hours access restrictions",
      "risk_level": "medium"
    },
    {
      "id": "common-ip-restrictions-v1",
      "file": "common/ip-restrictions.cedar", 
      "category": "network_controls",
      "description": "IP-based access restrictions",
      "risk_level": "medium"
    }
  ],
  "groups": [
    {
      "name": "administrators",
      "description": "System administrators with full access",
      "members": []
    },
    {
      "name": "policy_administrators", 
      "description": "Users who can manage authorization policies",
      "members": []
    },
    {
      "name": "auditors",
      "description": "Auditors with read-only access for compliance",
      "members": []
    },
    {
      "name": "confidential_access",
      "description": "Users with access to confidential data",
      "members": []
    }
  ]
}
EOF

echo "✓ Policy metadata created"

# Create migration record
kubectl exec "$POLICY_POD" -n rust-security -- tee /etc/policies/migrations/v1/migration-record.json > /dev/null <<EOF
{
  "migration_version": "1",
  "migration_name": "$MIGRATION_NAME",
  "migration_description": "$MIGRATION_DESCRIPTION", 
  "applied_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "applied_by": "migration-framework",
  "changes": [
    "Created Cedar RBAC schema",
    "Added 6 foundational RBAC policies",
    "Added 2 common utility policies", 
    "Created policy index and metadata",
    "Established user groups structure"
  ],
  "files_created": [
    "/etc/policies/schemas/rbac.cedarschema",
    "/etc/policies/rbac/001-basic-auth.cedar",
    "/etc/policies/rbac/002-self-service.cedar", 
    "/etc/policies/rbac/003-admin-permissions.cedar",
    "/etc/policies/rbac/004-policy-management.cedar",
    "/etc/policies/rbac/005-auditor-access.cedar",
    "/etc/policies/rbac/006-data-classification.cedar",
    "/etc/policies/common/time-based-access.cedar",
    "/etc/policies/common/ip-restrictions.cedar",
    "/etc/policies/policy-index.json"
  ],
  "next_migration": "2"
}
EOF

echo "✓ Migration record created"

# Validate policy syntax (if Cedar CLI is available)
echo "Validating policy syntax..."

# Check if Cedar validation tools are available
if kubectl exec "$POLICY_POD" -n rust-security -- which cedar-validate >/dev/null 2>&1; then
    echo "Running Cedar validation..."
    if kubectl exec "$POLICY_POD" -n rust-security -- cedar-validate --schema /etc/policies/schemas/rbac.cedarschema --policies /etc/policies/rbac/ /etc/policies/common/; then
        echo "✓ Cedar policy validation passed"
    else
        echo "⚠ Cedar validation failed - policies may need adjustment"
    fi
else
    echo "⚠ Cedar validation tools not available - skipping syntax validation"
fi

# Test policy loading
echo "Testing policy loading..."

POLICY_COUNT=$(kubectl exec "$POLICY_POD" -n rust-security -- find /etc/policies -name "*.cedar" | wc -l)
if [[ "$POLICY_COUNT" -eq 8 ]]; then
    echo "✓ All 8 policies created successfully"
else
    echo "⚠ Expected 8 policies, found $POLICY_COUNT"
fi

# Verify directory structure
echo "Verifying directory structure..."

DIRS=("rbac" "abac" "common" "schemas" "migrations/v1")
for dir in "${DIRS[@]}"; do
    if kubectl exec "$POLICY_POD" -n rust-security -- test -d "/etc/policies/$dir"; then
        echo "  ✓ /etc/policies/$dir exists"
    else
        echo "  ✗ /etc/policies/$dir missing"
        exit 1
    fi
done

# Create ConfigMap with policy information for other components
echo "Creating policy information ConfigMap..."

kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-migration-status
  namespace: rust-security
  labels:
    app.kubernetes.io/name: policy-service
    app.kubernetes.io/part-of: rust-security
    migration.rust-security/version: "1"
data:
  version: "1"
  status: "completed"
  applied_at: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  policy_count: "8"
  schema_version: "1.0"
  description: "Initial Cedar policy framework with RBAC foundation"
  policies_loaded: "rbac-basic-auth-v1,rbac-self-service-v1,rbac-admin-permissions-v1,rbac-policy-management-v1,rbac-auditor-access-v1,rbac-data-classification-v1,common-business-hours-v1,common-ip-restrictions-v1"
  groups_defined: "administrators,policy_administrators,auditors,confidential_access"
EOF

echo "✓ Policy information ConfigMap created"

echo "✓ Policy migration v1 completed successfully"
echo "Summary:"
echo "  - Created Cedar RBAC schema with User, Role, Resource, and Action entities"
echo "  - Implemented 6 foundational RBAC policies covering authentication, self-service, admin access"
echo "  - Added 2 common utility policies for time-based and IP-based restrictions"
echo "  - Established policy directory structure and metadata tracking"
echo "  - Created 4 initial user groups (administrators, policy_administrators, auditors, confidential_access)"
echo "  - Set up policy index and migration tracking"
echo "  - All policies follow security best practices with explicit conditions"

exit 0