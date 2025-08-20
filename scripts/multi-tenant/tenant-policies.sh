#!/bin/bash
# Multi-Tenant Cedar Policy Management System
# Handles tenant-specific policy isolation and management

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="$SCRIPT_DIR/policies"
TEMPLATES_DIR="$SCRIPT_DIR/policy-templates"

# Create directories
mkdir -p "$POLICIES_DIR" "$TEMPLATES_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Create policy templates
create_policy_templates() {
    info "Creating Cedar policy templates for multi-tenant isolation..."
    
    # Tenant isolation policy template
    cat > "$TEMPLATES_DIR/tenant-isolation.cedar" <<'EOF'
// Tenant Isolation Policy Template
// Prevents cross-tenant access and enforces tenant boundaries

// Deny cross-tenant access to resources
forbid (
    principal in TenantUsers::"TENANT_ID",
    action,
    resource
) when {
    resource has tenant_id &&
    resource.tenant_id != "TENANT_ID"
};

// Deny cross-tenant user operations
forbid (
    principal in TenantUsers::"TENANT_ID",
    action,
    resource in TenantUsers
) when {
    resource.tenant_id != "TENANT_ID"
};

// Deny access to system resources for non-admin users
forbid (
    principal in TenantUsers::"TENANT_ID",
    action,
    resource in SystemResources
) unless {
    principal.role == "admin" &&
    action in [Action::"read", Action::"list"]
};

// Tenant data isolation - users can only access their tenant's data
permit (
    principal in TenantUsers::"TENANT_ID",
    action in [
        Action::"read",
        Action::"write", 
        Action::"list",
        Action::"create"
    ],
    resource in TenantData::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.tenant_id == "TENANT_ID"
};

// Tenant admin permissions
permit (
    principal in TenantUsers::"TENANT_ID",
    action in [
        Action::"admin:read",
        Action::"admin:write",
        Action::"admin:manage_users",
        Action::"admin:manage_roles"
    ],
    resource in TenantData::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    principal.role == "admin" &&
    resource.tenant_id == "TENANT_ID"
};

// Audit trail access - tenant admins can read their audit logs
permit (
    principal in TenantUsers::"TENANT_ID",
    action == Action::"read",
    resource in AuditLogs::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    principal.role == "admin" &&
    resource.tenant_id == "TENANT_ID"
};
EOF

    # Tenant user management policy template
    cat > "$TEMPLATES_DIR/tenant-user-management.cedar" <<'EOF'
// Tenant User Management Policy Template
// Controls user management within tenant boundaries

// Tenant admins can manage users within their tenant
permit (
    principal in TenantUsers::"TENANT_ID",
    action in [
        Action::"create_user",
        Action::"update_user",
        Action::"delete_user",
        Action::"assign_role",
        Action::"revoke_role"
    ],
    resource in TenantUsers::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    principal.role == "admin" &&
    resource.tenant_id == "TENANT_ID"
};

// Users can update their own profile
permit (
    principal in TenantUsers::"TENANT_ID",
    action == Action::"update_user",
    resource in TenantUsers::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    principal.user_id == resource.user_id &&
    resource.tenant_id == "TENANT_ID"
};

// Users can read their own profile and other users in their tenant
permit (
    principal in TenantUsers::"TENANT_ID",
    action == Action::"read",
    resource in TenantUsers::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.tenant_id == "TENANT_ID"
};

// Prevent elevation to system admin
forbid (
    principal in TenantUsers::"TENANT_ID",
    action == Action::"assign_role",
    resource in TenantUsers::"TENANT_ID"
) when {
    resource.target_role == "system_admin"
};

// Role-based permissions within tenant
permit (
    principal in TenantUsers::"TENANT_ID",
    action,
    resource in TenantData::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.tenant_id == "TENANT_ID" &&
    (
        (principal.role == "admin") ||
        (principal.role == "editor" && action in [Action::"read", Action::"write", Action::"create"]) ||
        (principal.role == "viewer" && action == Action::"read")
    )
};
EOF

    # Tenant resource management policy template
    cat > "$TEMPLATES_DIR/tenant-resource-management.cedar" <<'EOF'
// Tenant Resource Management Policy Template
// Controls access to tenant-specific resources and quotas

// Resource quota enforcement
forbid (
    principal in TenantUsers::"TENANT_ID",
    action == Action::"create",
    resource
) when {
    resource has resource_type &&
    principal has tenant_quota &&
    principal.tenant_quota[resource.resource_type] <= principal.tenant_usage[resource.resource_type]
};

// Tenant storage access
permit (
    principal in TenantUsers::"TENANT_ID",
    action in [Action::"read", Action::"write", Action::"list"],
    resource in TenantStorage::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.tenant_id == "TENANT_ID" &&
    resource.path.startsWith("/tenant/TENANT_ID/")
};

// Tenant configuration management
permit (
    principal in TenantUsers::"TENANT_ID",
    action in [Action::"read", Action::"update"],
    resource in TenantConfig::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    principal.role == "admin" &&
    resource.tenant_id == "TENANT_ID"
};

// API rate limiting per tenant
permit (
    principal in TenantUsers::"TENANT_ID",
    action == Action::"api_call",
    resource in APIEndpoints
) when {
    principal.tenant_id == "TENANT_ID" &&
    principal.api_rate_limit > principal.current_api_usage
};

// Feature access based on tenant plan
permit (
    principal in TenantUsers::"TENANT_ID",
    action,
    resource in Features
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.feature_name in principal.tenant_plan.features
};

// Database access isolation
permit (
    principal in TenantUsers::"TENANT_ID",
    action in [Action::"read", Action::"write", Action::"delete"],
    resource in DatabaseRecords::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.tenant_id == "TENANT_ID" &&
    resource.database_name == "tenant_" + "TENANT_ID"
};
EOF

    # Network isolation policy template
    cat > "$TEMPLATES_DIR/tenant-network-isolation.cedar" <<'EOF'
// Tenant Network Isolation Policy Template
// Controls network access between tenants and external resources

// Deny cross-tenant network communication
forbid (
    principal in TenantServices::"TENANT_ID",
    action == Action::"network_call",
    resource in TenantServices
) when {
    resource.tenant_id != "TENANT_ID"
};

// Allow tenant services to communicate within tenant namespace
permit (
    principal in TenantServices::"TENANT_ID",
    action == Action::"network_call",
    resource in TenantServices::"TENANT_ID"
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.tenant_id == "TENANT_ID" &&
    principal.namespace == "rust-security-TENANT_ID" &&
    resource.namespace == "rust-security-TENANT_ID"
};

// Allow access to shared system services
permit (
    principal in TenantServices::"TENANT_ID",
    action == Action::"network_call",
    resource in SystemServices
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.service_type in ["monitoring", "logging", "auth", "dns"]
};

// External API access based on tenant plan
permit (
    principal in TenantServices::"TENANT_ID",
    action == Action::"external_api_call",
    resource in ExternalAPIs
) when {
    principal.tenant_id == "TENANT_ID" &&
    resource.api_name in principal.tenant_plan.external_apis
};

// Ingress traffic must match tenant domain
permit (
    principal in ExternalClients,
    action == Action::"http_request",
    resource in TenantServices::"TENANT_ID"
) when {
    resource.tenant_id == "TENANT_ID" &&
    principal.host_header.endsWith(".TENANT_ID.example.com")
};
EOF

    success "Policy templates created successfully"
}

# Generate tenant-specific policies
generate_tenant_policies() {
    local tenant_id=$1
    local tenant_plan=${2:-"standard"}
    
    info "Generating Cedar policies for tenant: $tenant_id"
    
    # Create tenant-specific policy directory
    local tenant_policy_dir="$POLICIES_DIR/$tenant_id"
    mkdir -p "$tenant_policy_dir"
    
    # Process each template
    for template in "$TEMPLATES_DIR"/*.cedar; do
        if [[ -f "$template" ]]; then
            local policy_name=$(basename "$template")
            local output_file="$tenant_policy_dir/$policy_name"
            
            # Replace TENANT_ID placeholder with actual tenant ID
            sed "s/TENANT_ID/$tenant_id/g" "$template" > "$output_file"
            
            info "Generated policy: $output_file"
        fi
    done
    
    # Create tenant-specific plan-based policy
    cat > "$tenant_policy_dir/tenant-plan-restrictions.cedar" <<EOF
// Tenant Plan-Based Restrictions for $tenant_id
// Generated for plan: $tenant_plan

$(generate_plan_policies "$tenant_id" "$tenant_plan")
EOF

    # Create policy bundle metadata
    cat > "$tenant_policy_dir/policy-metadata.json" <<EOF
{
  "tenant_id": "$tenant_id",
  "tenant_plan": "$tenant_plan",
  "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "policy_version": "1.0",
  "policies": [
$(find "$tenant_policy_dir" -name "*.cedar" -exec basename {} \; | jq -R '.' | paste -sd, -)
  ],
  "features": $(get_plan_features "$tenant_plan"),
  "quotas": $(get_plan_quotas "$tenant_plan")
}
EOF

    success "Tenant policies generated for: $tenant_id"
}

# Generate plan-specific policies
generate_plan_policies() {
    local tenant_id=$1
    local plan=$2
    
    case "$plan" in
        "starter")
            cat <<EOF
// Starter Plan Restrictions
forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"create",
    resource in TenantData::"$tenant_id"
) when {
    principal.tenant_usage["storage_mb"] >= 100
};

forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"api_call",
    resource
) when {
    principal.current_api_usage >= 1000
};

forbid (
    principal in TenantUsers::"$tenant_id",
    action,
    resource in Features
) when {
    resource.feature_name in ["advanced_analytics", "custom_integrations", "priority_support"]
};
EOF
            ;;
        "standard")
            cat <<EOF
// Standard Plan Restrictions
forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"create",
    resource in TenantData::"$tenant_id"
) when {
    principal.tenant_usage["storage_mb"] >= 1000
};

forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"api_call",
    resource
) when {
    principal.current_api_usage >= 10000
};

forbid (
    principal in TenantUsers::"$tenant_id",
    action,
    resource in Features
) when {
    resource.feature_name in ["custom_integrations", "priority_support"]
};
EOF
            ;;
        "premium")
            cat <<EOF
// Premium Plan Restrictions
forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"create",
    resource in TenantData::"$tenant_id"
) when {
    principal.tenant_usage["storage_mb"] >= 10000
};

forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"api_call",
    resource
) when {
    principal.current_api_usage >= 100000
};

// Premium has access to all features except enterprise-specific ones
forbid (
    principal in TenantUsers::"$tenant_id",
    action,
    resource in Features
) when {
    resource.feature_name in ["enterprise_sso", "dedicated_support"]
};
EOF
            ;;
        "enterprise")
            cat <<EOF
// Enterprise Plan - Minimal Restrictions
forbid (
    principal in TenantUsers::"$tenant_id",
    action == Action::"create",
    resource in TenantData::"$tenant_id"
) when {
    principal.tenant_usage["storage_mb"] >= 100000
};

// Enterprise has access to all features
permit (
    principal in TenantUsers::"$tenant_id",
    action,
    resource in Features
) when {
    principal.tenant_id == "$tenant_id"
};
EOF
            ;;
        *)
            echo "// Unknown plan: $plan - applying default restrictions"
            ;;
    esac
}

# Get plan features
get_plan_features() {
    local plan=$1
    
    case "$plan" in
        "starter")
            echo '["basic_auth", "basic_policies", "audit_logs"]'
            ;;
        "standard")
            echo '["basic_auth", "basic_policies", "audit_logs", "advanced_analytics", "api_access"]'
            ;;
        "premium")
            echo '["basic_auth", "basic_policies", "audit_logs", "advanced_analytics", "api_access", "custom_integrations", "advanced_reporting"]'
            ;;
        "enterprise")
            echo '["basic_auth", "basic_policies", "audit_logs", "advanced_analytics", "api_access", "custom_integrations", "advanced_reporting", "enterprise_sso", "dedicated_support", "priority_support"]'
            ;;
        *)
            echo '["basic_auth", "basic_policies"]'
            ;;
    esac
}

# Get plan quotas
get_plan_quotas() {
    local plan=$1
    
    case "$plan" in
        "starter")
            echo '{"storage_mb": 100, "api_calls_per_hour": 1000, "users": 5, "policies": 10}'
            ;;
        "standard")
            echo '{"storage_mb": 1000, "api_calls_per_hour": 10000, "users": 25, "policies": 50}'
            ;;
        "premium")
            echo '{"storage_mb": 10000, "api_calls_per_hour": 100000, "users": 100, "policies": 200}'
            ;;
        "enterprise")
            echo '{"storage_mb": 100000, "api_calls_per_hour": 1000000, "users": -1, "policies": -1}'
            ;;
        *)
            echo '{"storage_mb": 50, "api_calls_per_hour": 500, "users": 1, "policies": 5}'
            ;;
    esac
}

# Deploy tenant policies to Cedar policy store
deploy_tenant_policies() {
    local tenant_id=$1
    local policy_dir="$POLICIES_DIR/$tenant_id"
    
    if [[ ! -d "$policy_dir" ]]; then
        error "Policy directory not found for tenant: $tenant_id"
        return 1
    fi
    
    info "Deploying Cedar policies for tenant: $tenant_id"
    
    # Create policy store namespace for tenant
    local policy_store_namespace="tenant-policies-$tenant_id"
    
    # Create ConfigMap with tenant policies
    kubectl create namespace "$policy_store_namespace" --dry-run=client -o yaml | kubectl apply -f -
    
    # Create ConfigMap with all tenant policies
    kubectl create configmap "tenant-policies-$tenant_id" \
        --from-file="$policy_dir" \
        --namespace="$policy_store_namespace" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Cedar policy service for tenant
    cat > "/tmp/tenant-policy-service-$tenant_id.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cedar-policy-service-$tenant_id
  namespace: $policy_store_namespace
  labels:
    app: cedar-policy-service
    tenant: $tenant_id
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cedar-policy-service
      tenant: $tenant_id
  template:
    metadata:
      labels:
        app: cedar-policy-service
        tenant: $tenant_id
    spec:
      containers:
      - name: cedar-policy-engine
        image: cedar-policy-engine:latest
        ports:
        - containerPort: 8080
        env:
        - name: TENANT_ID
          value: "$tenant_id"
        - name: POLICY_STORE_PATH
          value: "/policies"
        volumeMounts:
        - name: tenant-policies
          mountPath: /policies
          readOnly: true
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
      volumes:
      - name: tenant-policies
        configMap:
          name: tenant-policies-$tenant_id
---
apiVersion: v1
kind: Service
metadata:
  name: cedar-policy-service-$tenant_id
  namespace: $policy_store_namespace
  labels:
    app: cedar-policy-service
    tenant: $tenant_id
spec:
  selector:
    app: cedar-policy-service
    tenant: $tenant_id
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
EOF

    # Apply the policy service
    kubectl apply -f "/tmp/tenant-policy-service-$tenant_id.yaml"
    
    # Wait for deployment to be ready
    kubectl wait --for=condition=available --timeout=300s \
        deployment/cedar-policy-service-$tenant_id -n "$policy_store_namespace"
    
    # Update tenant manager with policy service endpoint
    local policy_service_endpoint="cedar-policy-service-$tenant_id.$policy_store_namespace.svc.cluster.local:8080"
    kubectl patch configmap "tenant-config-$tenant_id" \
        --namespace="rust-security-$tenant_id" \
        --patch="{\"data\":{\"policy_service_endpoint\":\"$policy_service_endpoint\"}}"
    
    success "Cedar policies deployed for tenant: $tenant_id"
    rm -f "/tmp/tenant-policy-service-$tenant_id.yaml"
}

# Validate tenant policies
validate_tenant_policies() {
    local tenant_id=$1
    local policy_dir="$POLICIES_DIR/$tenant_id"
    
    if [[ ! -d "$policy_dir" ]]; then
        error "Policy directory not found for tenant: $tenant_id"
        return 1
    fi
    
    info "Validating Cedar policies for tenant: $tenant_id"
    
    local validation_errors=0
    
    # Validate each policy file
    for policy_file in "$policy_dir"/*.cedar; do
        if [[ -f "$policy_file" ]]; then
            info "Validating policy file: $(basename "$policy_file")"
            
            # Simple syntax validation (in a real implementation, use Cedar CLI)
            if ! grep -q "permit\|forbid" "$policy_file"; then
                error "Policy file contains no permit/forbid statements: $policy_file"
                ((validation_errors++))
            fi
            
            # Check for proper tenant ID usage
            if ! grep -q "$tenant_id" "$policy_file"; then
                warn "Policy file may not be tenant-specific: $policy_file"
            fi
            
            # Check for balanced braces
            local open_braces=$(grep -o '{' "$policy_file" | wc -l)
            local close_braces=$(grep -o '}' "$policy_file" | wc -l)
            if [[ $open_braces -ne $close_braces ]]; then
                error "Unbalanced braces in policy file: $policy_file"
                ((validation_errors++))
            fi
        fi
    done
    
    # Validate metadata
    local metadata_file="$policy_dir/policy-metadata.json"
    if [[ -f "$metadata_file" ]]; then
        if ! jq . "$metadata_file" >/dev/null 2>&1; then
            error "Invalid JSON in metadata file: $metadata_file"
            ((validation_errors++))
        fi
    else
        error "Missing policy metadata file: $metadata_file"
        ((validation_errors++))
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        success "All policies validated successfully for tenant: $tenant_id"
        return 0
    else
        error "Found $validation_errors validation errors for tenant: $tenant_id"
        return 1
    fi
}

# Update tenant policies
update_tenant_policies() {
    local tenant_id=$1
    local plan=${2:-""}
    
    info "Updating policies for tenant: $tenant_id"
    
    # Get current plan if not provided
    if [[ -z "$plan" ]]; then
        local metadata_file="$POLICIES_DIR/$tenant_id/policy-metadata.json"
        if [[ -f "$metadata_file" ]]; then
            plan=$(jq -r '.tenant_plan' "$metadata_file")
        else
            error "Cannot determine tenant plan for: $tenant_id"
            return 1
        fi
    fi
    
    # Regenerate policies
    generate_tenant_policies "$tenant_id" "$plan"
    
    # Validate new policies
    if validate_tenant_policies "$tenant_id"; then
        # Deploy updated policies
        deploy_tenant_policies "$tenant_id"
        success "Policies updated successfully for tenant: $tenant_id"
    else
        error "Policy validation failed, deployment aborted"
        return 1
    fi
}

# Remove tenant policies
remove_tenant_policies() {
    local tenant_id=$1
    
    info "Removing policies for tenant: $tenant_id"
    
    # Remove policy service
    local policy_store_namespace="tenant-policies-$tenant_id"
    kubectl delete namespace "$policy_store_namespace" --ignore-not-found=true
    
    # Remove local policy files
    local policy_dir="$POLICIES_DIR/$tenant_id"
    if [[ -d "$policy_dir" ]]; then
        rm -rf "$policy_dir"
        success "Local policy files removed for tenant: $tenant_id"
    fi
    
    success "Policies removed for tenant: $tenant_id"
}

# List tenant policies
list_tenant_policies() {
    local tenant_id=${1:-""}
    
    if [[ -n "$tenant_id" ]]; then
        info "Policies for tenant: $tenant_id"
        local policy_dir="$POLICIES_DIR/$tenant_id"
        if [[ -d "$policy_dir" ]]; then
            echo "Policy files:"
            find "$policy_dir" -name "*.cedar" -exec basename {} \;
            echo ""
            echo "Metadata:"
            local metadata_file="$policy_dir/policy-metadata.json"
            if [[ -f "$metadata_file" ]]; then
                jq . "$metadata_file"
            fi
        else
            warn "No policies found for tenant: $tenant_id"
        fi
    else
        info "All tenant policies:"
        if [[ -d "$POLICIES_DIR" ]]; then
            for tenant_dir in "$POLICIES_DIR"/*; do
                if [[ -d "$tenant_dir" ]]; then
                    local tid=$(basename "$tenant_dir")
                    local metadata_file="$tenant_dir/policy-metadata.json"
                    if [[ -f "$metadata_file" ]]; then
                        local plan=$(jq -r '.tenant_plan' "$metadata_file")
                        echo "- $tid (plan: $plan)"
                    else
                        echo "- $tid (plan: unknown)"
                    fi
                fi
            done
        else
            warn "No tenant policies found"
        fi
    fi
}

# Usage information
usage() {
    cat << EOF
Multi-Tenant Cedar Policy Management System

Usage: $0 <command> [arguments]

Commands:
    create-templates                        - Create Cedar policy templates
    generate <tenant_id> [plan]             - Generate policies for tenant
    deploy <tenant_id>                      - Deploy policies to Kubernetes
    validate <tenant_id>                    - Validate tenant policies
    update <tenant_id> [plan]               - Update tenant policies
    remove <tenant_id>                      - Remove tenant policies
    list [tenant_id]                        - List policies

Tenant Plans:
    starter     - Basic features, minimal quotas
    standard    - Standard features and quotas
    premium     - Advanced features, higher quotas
    enterprise  - All features, unlimited quotas

Examples:
    $0 create-templates                     # Create policy templates
    $0 generate acme-corp standard          # Generate policies for ACME Corp
    $0 deploy acme-corp                     # Deploy policies to Kubernetes
    $0 validate acme-corp                   # Validate ACME Corp policies
    $0 list                                 # List all tenant policies

EOF
}

# Main execution
main() {
    local command=${1:-""}
    
    case "$command" in
        "create-templates")
            create_policy_templates
            ;;
        "generate")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            generate_tenant_policies "$2" "${3:-standard}"
            ;;
        "deploy")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            deploy_tenant_policies "$2"
            ;;
        "validate")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            validate_tenant_policies "$2"
            ;;
        "update")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            update_tenant_policies "$2" "${3:-}"
            ;;
        "remove")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            remove_tenant_policies "$2"
            ;;
        "list")
            list_tenant_policies "${2:-}"
            ;;
        "help"|"-h"|"--help"|"")
            usage
            ;;
        *)
            error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi