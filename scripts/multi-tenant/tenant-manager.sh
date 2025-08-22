#!/bin/bash
# Multi-Tenant Management System for Rust Security Platform
# Provides complete tenant isolation with namespace, RBAC, and data separation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT_CONFIG_DIR="$SCRIPT_DIR/tenant-configs"
TENANT_MANIFESTS_DIR="$SCRIPT_DIR/manifests"
TENANT_STATE_DIR="$SCRIPT_DIR/state"

# Create directories
mkdir -p "$TENANT_CONFIG_DIR" "$TENANT_MANIFESTS_DIR" "$TENANT_STATE_DIR"

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
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$TENANT_STATE_DIR/tenant-manager.log"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Validate tenant name
validate_tenant_name() {
    local tenant_id=$1
    
    # Check format: lowercase alphanumeric with hyphens, 3-50 chars
    if [[ ! "$tenant_id" =~ ^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$ ]]; then
        error "Invalid tenant ID format: $tenant_id"
        error "Must be 3-50 chars, lowercase alphanumeric with hyphens, start/end with alphanumeric"
        return 1
    fi
    
    # Check for reserved names
    local reserved_names=("default" "kube-system" "kube-public" "kube-node-lease" "monitoring" "ingress-nginx" "cert-manager")
    for reserved in "${reserved_names[@]}"; do
        if [[ "$tenant_id" == "$reserved" ]]; then
            error "Tenant ID '$tenant_id' is reserved"
            return 1
        fi
    done
    
    return 0
}

# Generate tenant configuration
generate_tenant_config() {
    local tenant_id=$1
    local display_name=$2
    local admin_email=$3
    local plan=${4:-"standard"}
    
    local config_file="$TENANT_CONFIG_DIR/${tenant_id}.json"
    
    info "Generating tenant configuration for $tenant_id..."
    
    cat > "$config_file" <<EOF
{
  "tenant_id": "$tenant_id",
  "display_name": "$display_name",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "admin_email": "$admin_email",
  "plan": "$plan",
  "status": "active",
  "configuration": {
    "namespace": "tenant-$tenant_id",
    "resource_quotas": {
      "cpu_limit": "$(get_plan_cpu_limit "$plan")",
      "memory_limit": "$(get_plan_memory_limit "$plan")",
      "storage_limit": "$(get_plan_storage_limit "$plan")",
      "pod_limit": "$(get_plan_pod_limit "$plan")",
      "service_limit": "$(get_plan_service_limit "$plan")"
    },
    "network_policies": {
      "isolation_enabled": true,
      "allow_internet": true,
      "allow_cross_tenant": false
    },
    "security": {
      "pod_security_standard": "restricted",
      "network_isolation": "strict",
      "rbac_enabled": true,
      "audit_logging": true
    },
    "data_isolation": {
      "redis_db": $(get_tenant_redis_db "$tenant_id"),
      "encryption_key_id": "tenant-$tenant_id-key",
      "backup_retention_days": 30
    },
    "features": {
      "auth_service": true,
      "policy_service": true,
      "audit_logging": true,
      "monitoring": true,
      "external_integrations": $(get_plan_feature "$plan" "external_integrations")
    }
  },
  "limits": {
    "max_users": $(get_plan_limit "$plan" "max_users"),
    "max_policies": $(get_plan_limit "$plan" "max_policies"),
    "max_sessions": $(get_plan_limit "$plan" "max_sessions"),
    "api_rate_limit": $(get_plan_limit "$plan" "api_rate_limit")
  },
  "metadata": {
    "creation_method": "tenant-manager",
    "version": "1.0",
    "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  }
}
EOF

    success "Tenant configuration generated: $config_file"
    echo "$config_file"
}

# Get plan-specific resource limits
get_plan_cpu_limit() {
    case $1 in
        "starter") echo "2" ;;
        "standard") echo "4" ;;
        "premium") echo "8" ;;
        "enterprise") echo "16" ;;
        *) echo "4" ;;
    esac
}

get_plan_memory_limit() {
    case $1 in
        "starter") echo "4Gi" ;;
        "standard") echo "8Gi" ;;
        "premium") echo "16Gi" ;;
        "enterprise") echo "32Gi" ;;
        *) echo "8Gi" ;;
    esac
}

get_plan_storage_limit() {
    case $1 in
        "starter") echo "10Gi" ;;
        "standard") echo "50Gi" ;;
        "premium") echo "100Gi" ;;
        "enterprise") echo "500Gi" ;;
        *) echo "50Gi" ;;
    esac
}

get_plan_pod_limit() {
    case $1 in
        "starter") echo "10" ;;
        "standard") echo "20" ;;
        "premium") echo "50" ;;
        "enterprise") echo "100" ;;
        *) echo "20" ;;
    esac
}

get_plan_service_limit() {
    case $1 in
        "starter") echo "5" ;;
        "standard") echo "10" ;;
        "premium") echo "25" ;;
        "enterprise") echo "50" ;;
        *) echo "10" ;;
    esac
}

get_plan_limit() {
    local plan=$1
    local limit_type=$2
    
    case "$plan:$limit_type" in
        "starter:max_users") echo "100" ;;
        "standard:max_users") echo "500" ;;
        "premium:max_users") echo "2000" ;;
        "enterprise:max_users") echo "10000" ;;
        "starter:max_policies") echo "50" ;;
        "standard:max_policies") echo "200" ;;
        "premium:max_policies") echo "1000" ;;
        "enterprise:max_policies") echo "5000" ;;
        "starter:max_sessions") echo "500" ;;
        "standard:max_sessions") echo "2000" ;;
        "premium:max_sessions") echo "10000" ;;
        "enterprise:max_sessions") echo "50000" ;;
        "starter:api_rate_limit") echo "100" ;;
        "standard:api_rate_limit") echo "500" ;;
        "premium:api_rate_limit") echo "2000" ;;
        "enterprise:api_rate_limit") echo "10000" ;;
        *) echo "0" ;;
    esac
}

get_plan_feature() {
    local plan=$1
    local feature=$2
    
    case "$plan:$feature" in
        "starter:external_integrations") echo "false" ;;
        "standard:external_integrations") echo "true" ;;
        "premium:external_integrations") echo "true" ;;
        "enterprise:external_integrations") echo "true" ;;
        *) echo "false" ;;
    esac
}

# Allocate Redis database for tenant
get_tenant_redis_db() {
    local tenant_id=$1
    local hash_value=$(echo -n "$tenant_id" | md5sum | cut -d' ' -f1)
    local db_number=$((0x${hash_value:0:8} % 14 + 1))  # Use DBs 1-14 (0 reserved)
    echo "$db_number"
}

# Create tenant namespace and RBAC
create_tenant_namespace() {
    local tenant_id=$1
    local config_file="$TENANT_CONFIG_DIR/${tenant_id}.json"
    
    if [[ ! -f "$config_file" ]]; then
        error "Tenant configuration not found: $config_file"
        return 1
    fi
    
    local namespace="tenant-$tenant_id"
    local manifest_file="$TENANT_MANIFESTS_DIR/${tenant_id}-namespace.yaml"
    
    info "Creating namespace and RBAC for tenant: $tenant_id"
    
    # Extract configuration values
    local cpu_limit=$(jq -r '.configuration.resource_quotas.cpu_limit' "$config_file")
    local memory_limit=$(jq -r '.configuration.resource_quotas.memory_limit' "$config_file")
    local storage_limit=$(jq -r '.configuration.resource_quotas.storage_limit' "$config_file")
    local pod_limit=$(jq -r '.configuration.resource_quotas.pod_limit' "$config_file")
    local service_limit=$(jq -r '.configuration.resource_quotas.service_limit' "$config_file")
    
    # Generate namespace manifest
    cat > "$manifest_file" <<EOF
---
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    tenant.rust-security.io/isolation: "strict"
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
  annotations:
    tenant.rust-security.io/created-at: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tenant.rust-security.io/admin-email: "$(jq -r '.admin_email' "$config_file")"
    tenant.rust-security.io/plan: "$(jq -r '.plan' "$config_file")"

---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-resource-quota
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
spec:
  hard:
    requests.cpu: "$cpu_limit"
    requests.memory: "$memory_limit"
    limits.cpu: "$(echo "$cpu_limit * 2" | bc)"
    limits.memory: "$(echo "$memory_limit" | sed 's/Gi/*2Gi/' | bc -l | cut -d. -f1)Gi"
    requests.storage: "$storage_limit"
    persistentvolumeclaims: "10"
    pods: "$pod_limit"
    services: "$service_limit"
    secrets: "20"
    configmaps: "20"
    replicationcontrollers: "0"
    count/deployments.apps: "10"
    count/statefulsets.apps: "5"
    count/jobs.batch: "10"

---
apiVersion: v1
kind: LimitRange
metadata:
  name: tenant-limit-range
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
spec:
  limits:
  - type: Container
    default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    max:
      cpu: "2000m"
      memory: "4Gi"
    min:
      cpu: "50m"
      memory: "64Mi"
  - type: Pod
    max:
      cpu: "4000m"
      memory: "8Gi"
  - type: PersistentVolumeClaim
    max:
      storage: "50Gi"
    min:
      storage: "1Gi"

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tenant-admin
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    tenant.rust-security.io/role: "admin"
  annotations:
    tenant.rust-security.io/admin-email: "$(jq -r '.admin_email' "$config_file")"

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tenant-user
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    tenant.rust-security.io/role: "user"

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tenant-admin
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: ["apps"]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch", "create", "update", "patch"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tenant-user
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenant-admin-binding
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
subjects:
- kind: ServiceAccount
  name: tenant-admin
  namespace: $namespace
roleRef:
  kind: Role
  name: tenant-admin
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenant-user-binding
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
subjects:
- kind: ServiceAccount
  name: tenant-user
  namespace: $namespace
roleRef:
  kind: Role
  name: tenant-user
  apiGroup: rbac.authorization.k8s.io
EOF

    # Apply the manifest
    if kubectl apply -f "$manifest_file"; then
        success "Namespace and RBAC created for tenant: $tenant_id"
    else
        error "Failed to create namespace for tenant: $tenant_id"
        return 1
    fi
    
    echo "$namespace"
}

# Create tenant network policies
create_tenant_network_policies() {
    local tenant_id=$1
    local namespace="tenant-$tenant_id"
    local manifest_file="$TENANT_MANIFESTS_DIR/${tenant_id}-network-policies.yaml"
    
    info "Creating network policies for tenant: $tenant_id"
    
    cat > "$manifest_file" <<EOF
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: tenant-isolation
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    tenant.rust-security.io/type: "isolation"
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Allow ingress from ingress controller
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  # Allow ingress from monitoring
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 8080
  # Allow ingress within tenant namespace
  - from:
    - namespaceSelector:
        matchLabels:
          tenant.rust-security.io/id: "$tenant_id"
  egress:
  # Allow DNS resolution
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
  # Allow access to shared Redis (with tenant DB isolation)
  - to:
    - namespaceSelector:
        matchLabels:
          name: rust-security
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  # Allow HTTPS egress for external integrations
  - to: []
    ports:
    - protocol: TCP
      port: 443
  # Allow egress within tenant namespace
  - to:
    - namespaceSelector:
        matchLabels:
          tenant.rust-security.io/id: "$tenant_id"

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-cross-tenant
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    tenant.rust-security.io/type: "security"
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  # Explicitly deny ingress from other tenant namespaces
  - from:
    - namespaceSelector:
        matchExpressions:
        - key: tenant.rust-security.io/id
          operator: Exists
        - key: tenant.rust-security.io/id
          operator: NotIn
          values: ["$tenant_id"]
  egress:
  # Explicitly deny egress to other tenant namespaces
  - to:
    - namespaceSelector:
        matchExpressions:
        - key: tenant.rust-security.io/id
          operator: Exists
        - key: tenant.rust-security.io/id
          operator: NotIn
          values: ["$tenant_id"]
EOF

    # Apply network policies
    if kubectl apply -f "$manifest_file"; then
        success "Network policies created for tenant: $tenant_id"
    else
        error "Failed to create network policies for tenant: $tenant_id"
        return 1
    fi
}

# Deploy tenant services
deploy_tenant_services() {
    local tenant_id=$1
    local config_file="$TENANT_CONFIG_DIR/${tenant_id}.json"
    local namespace="tenant-$tenant_id"
    local manifest_file="$TENANT_MANIFESTS_DIR/${tenant_id}-services.yaml"
    
    info "Deploying services for tenant: $tenant_id"
    
    # Extract configuration values
    local redis_db=$(jq -r '.configuration.data_isolation.redis_db' "$config_file")
    local cpu_request=$(jq -r '.configuration.resource_quotas.cpu_limit' "$config_file" | sed 's/$/m/' | sed 's/m$//' | awk '{print $1/4}')m
    local memory_request=$(jq -r '.configuration.resource_quotas.memory_limit' "$config_file" | sed 's/Gi$//' | awk '{print $1/4}')Gi
    local max_users=$(jq -r '.limits.max_users' "$config_file")
    local api_rate_limit=$(jq -r '.limits.api_rate_limit' "$config_file")
    
    cat > "$manifest_file" <<EOF
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tenant-auth-config
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    app.kubernetes.io/name: auth-service
data:
  tenant_id: "$tenant_id"
  redis_db: "$redis_db"
  max_users: "$max_users"
  api_rate_limit: "$api_rate_limit"
  bind_addr: "0.0.0.0:8080"
  log_level: "info"
  token_expiry_seconds: "3600"
  
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tenant-policy-config
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    app.kubernetes.io/name: policy-service
data:
  tenant_id: "$tenant_id"
  redis_db: "$redis_db"
  bind_addr: "0.0.0.0:8080"
  log_level: "info"
  policy_cache_size: "1000"
  authorization_timeout_ms: "100"

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    app.kubernetes.io/name: auth-service
    app.kubernetes.io/part-of: rust-security
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: auth-service
      tenant.rust-security.io/id: "$tenant_id"
  template:
    metadata:
      labels:
        app.kubernetes.io/name: auth-service
        tenant.rust-security.io/id: "$tenant_id"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: tenant-user
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: auth-service
        image: rust-security/auth-service:latest
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        env:
        - name: TENANT_ID
          valueFrom:
            configMapKeyRef:
              name: tenant-auth-config
              key: tenant_id
        - name: REDIS_DB
          valueFrom:
            configMapKeyRef:
              name: tenant-auth-config
              key: redis_db
        - name: REDIS_URL
          value: "redis://redis.rust-security.svc.cluster.local:6379"
        - name: MAX_USERS
          valueFrom:
            configMapKeyRef:
              name: tenant-auth-config
              key: max_users
        - name: API_RATE_LIMIT
          valueFrom:
            configMapKeyRef:
              name: tenant-auth-config
              key: api_rate_limit
        envFrom:
        - configMapRef:
            name: tenant-auth-config
        - secretRef:
            name: tenant-secrets
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        resources:
          requests:
            cpu: $cpu_request
            memory: $memory_request
          limits:
            cpu: "1000m"
            memory: "1Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policy-service
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    app.kubernetes.io/name: policy-service
    app.kubernetes.io/part-of: rust-security
spec:
  replicas: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: policy-service
      tenant.rust-security.io/id: "$tenant_id"
  template:
    metadata:
      labels:
        app.kubernetes.io/name: policy-service
        tenant.rust-security.io/id: "$tenant_id"
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: tenant-user
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: policy-service
        image: rust-security/policy-service:latest
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        env:
        - name: TENANT_ID
          valueFrom:
            configMapKeyRef:
              name: tenant-policy-config
              key: tenant_id
        - name: REDIS_DB
          valueFrom:
            configMapKeyRef:
              name: tenant-policy-config
              key: redis_db
        - name: REDIS_URL
          value: "redis://redis.rust-security.svc.cluster.local:6379"
        envFrom:
        - configMapRef:
            name: tenant-policy-config
        - secretRef:
            name: tenant-secrets
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop:
            - ALL
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
        resources:
          requests:
            cpu: $cpu_request
            memory: $memory_request
          limits:
            cpu: "1000m"
            memory: "1Gi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: policies
          mountPath: /etc/policies
      volumes:
      - name: tmp
        emptyDir: {}
      - name: policies
        configMap:
          name: tenant-policies

---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    app.kubernetes.io/name: auth-service
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app.kubernetes.io/name: auth-service
    tenant.rust-security.io/id: "$tenant_id"

---
apiVersion: v1
kind: Service
metadata:
  name: policy-service
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
    app.kubernetes.io/name: policy-service
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app.kubernetes.io/name: policy-service
    tenant.rust-security.io/id: "$tenant_id"
EOF

    # Apply services manifest
    if kubectl apply -f "$manifest_file"; then
        success "Services deployed for tenant: $tenant_id"
    else
        error "Failed to deploy services for tenant: $tenant_id"
        return 1
    fi
}

# Create tenant secrets
create_tenant_secrets() {
    local tenant_id=$1
    local namespace="tenant-$tenant_id"
    local manifest_file="$TENANT_MANIFESTS_DIR/${tenant_id}-secrets.yaml"
    
    info "Creating secrets for tenant: $tenant_id"
    
    # Generate tenant-specific secrets
    local jwt_secret=$(openssl rand -base64 32)
    local encryption_key=$(openssl rand -base64 32)
    local api_key=$(openssl rand -hex 32)
    
    cat > "$manifest_file" <<EOF
---
apiVersion: v1
kind: Secret
metadata:
  name: tenant-secrets
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
  annotations:
    tenant.rust-security.io/encryption-key-id: "tenant-$tenant_id-key"
type: Opaque
data:
  jwt-secret: $(echo -n "$jwt_secret" | base64 -w 0)
  encryption-key: $(echo -n "$encryption_key" | base64 -w 0)
  api-key: $(echo -n "$api_key" | base64 -w 0)
  tenant-id: $(echo -n "$tenant_id" | base64 -w 0)
EOF

    # Apply secrets
    if kubectl apply -f "$manifest_file"; then
        success "Secrets created for tenant: $tenant_id"
    else
        error "Failed to create secrets for tenant: $tenant_id"
        return 1
    fi
}

# Create tenant ingress
create_tenant_ingress() {
    local tenant_id=$1
    local domain=${2:-"example.com"}
    local namespace="tenant-$tenant_id"
    local manifest_file="$TENANT_MANIFESTS_DIR/${tenant_id}-ingress.yaml"
    
    info "Creating ingress for tenant: $tenant_id"
    
    cat > "$manifest_file" <<EOF
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tenant-ingress
  namespace: $namespace
  labels:
    tenant.rust-security.io/id: "$tenant_id"
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "$(jq -r '.limits.api_rate_limit' "$TENANT_CONFIG_DIR/${tenant_id}.json")"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header X-Tenant-ID "$tenant_id" always;
      add_header X-Frame-Options "DENY" always;
      add_header X-Content-Type-Options "nosniff" always;
spec:
  tls:
  - hosts:
    - auth-$tenant_id.$domain
    - policy-$tenant_id.$domain
    secretName: tenant-$tenant_id-tls
  rules:
  - host: auth-$tenant_id.$domain
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 8080
  - host: policy-$tenant_id.$domain
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: policy-service
            port:
              number: 8080
EOF

    # Apply ingress
    if kubectl apply -f "$manifest_file"; then
        success "Ingress created for tenant: $tenant_id"
        info "Auth Service URL: https://auth-$tenant_id.$domain"
        info "Policy Service URL: https://policy-$tenant_id.$domain"
    else
        error "Failed to create ingress for tenant: $tenant_id"
        return 1
    fi
}

# Create complete tenant
create_tenant() {
    local tenant_id=$1
    local display_name=$2
    local admin_email=$3
    local plan=${4:-"standard"}
    local domain=${5:-"example.com"}
    
    info "Creating tenant: $tenant_id ($display_name)"
    
    # Validate inputs
    if ! validate_tenant_name "$tenant_id"; then
        return 1
    fi
    
    if [[ -z "$display_name" ]] || [[ -z "$admin_email" ]]; then
        error "Display name and admin email are required"
        return 1
    fi
    
    # Check if tenant already exists
    if [[ -f "$TENANT_CONFIG_DIR/${tenant_id}.json" ]]; then
        error "Tenant $tenant_id already exists"
        return 1
    fi
    
    # Generate tenant configuration
    local config_file
    if ! config_file=$(generate_tenant_config "$tenant_id" "$display_name" "$admin_email" "$plan"); then
        return 1
    fi
    
    # Create namespace and RBAC
    if ! create_tenant_namespace "$tenant_id"; then
        error "Failed to create namespace for tenant: $tenant_id"
        return 1
    fi
    
    # Create network policies
    if ! create_tenant_network_policies "$tenant_id"; then
        error "Failed to create network policies for tenant: $tenant_id"
        return 1
    fi
    
    # Create secrets
    if ! create_tenant_secrets "$tenant_id"; then
        error "Failed to create secrets for tenant: $tenant_id"
        return 1
    fi
    
    # Deploy services
    if ! deploy_tenant_services "$tenant_id"; then
        error "Failed to deploy services for tenant: $tenant_id"
        return 1
    fi
    
    # Create ingress
    if ! create_tenant_ingress "$tenant_id" "$domain"; then
        error "Failed to create ingress for tenant: $tenant_id"
        return 1
    fi
    
    # Update tenant state
    local state_file="$TENANT_STATE_DIR/${tenant_id}.state"
    cat > "$state_file" <<EOF
{
  "tenant_id": "$tenant_id",
  "status": "active",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "namespace": "tenant-$tenant_id",
  "endpoints": {
    "auth_service": "https://auth-$tenant_id.$domain",
    "policy_service": "https://policy-$tenant_id.$domain"
  },
  "redis_db": $(jq -r '.configuration.data_isolation.redis_db' "$config_file")
}
EOF

    success "Tenant $tenant_id created successfully!"
    echo ""
    echo "Tenant Details:"
    echo "  ID: $tenant_id"
    echo "  Display Name: $display_name"
    echo "  Plan: $plan"
    echo "  Namespace: tenant-$tenant_id"
    echo "  Auth Service: https://auth-$tenant_id.$domain"
    echo "  Policy Service: https://policy-$tenant_id.$domain"
    echo "  Redis DB: $(jq -r '.configuration.data_isolation.redis_db' "$config_file")"
    echo ""
    echo "Next steps:"
    echo "  1. Configure DNS for auth-$tenant_id.$domain and policy-$tenant_id.$domain"
    echo "  2. Wait for SSL certificates to be issued"
    echo "  3. Initialize tenant policies and users"
}

# Delete tenant
delete_tenant() {
    local tenant_id=$1
    local confirm=${2:-"false"}
    
    if [[ "$confirm" != "true" ]]; then
        echo "This will permanently delete tenant $tenant_id and all associated data."
        echo "To confirm, run: $0 delete-tenant $tenant_id true"
        return 1
    fi
    
    info "Deleting tenant: $tenant_id"
    
    local namespace="tenant-$tenant_id"
    
    # Delete namespace (this cascades to all resources)
    if kubectl delete namespace "$namespace" --ignore-not-found=true; then
        success "Namespace deleted: $namespace"
    else
        warn "Failed to delete namespace: $namespace"
    fi
    
    # Clean up local files
    rm -f "$TENANT_CONFIG_DIR/${tenant_id}.json"
    rm -f "$TENANT_STATE_DIR/${tenant_id}.state"
    rm -f "$TENANT_MANIFESTS_DIR/${tenant_id}-"*.yaml
    
    success "Tenant $tenant_id deleted successfully"
}

# List tenants
list_tenants() {
    info "Listing all tenants..."
    echo ""
    printf "%-20s %-30s %-15s %-10s %-20s\n" "TENANT ID" "DISPLAY NAME" "PLAN" "STATUS" "CREATED"
    echo "$(printf '%.0s-' {1..100})"
    
    for config_file in "$TENANT_CONFIG_DIR"/*.json; do
        if [[ -f "$config_file" ]]; then
            local tenant_id=$(jq -r '.tenant_id' "$config_file")
            local display_name=$(jq -r '.display_name' "$config_file")
            local plan=$(jq -r '.plan' "$config_file")
            local status=$(jq -r '.status' "$config_file")
            local created_at=$(jq -r '.created_at' "$config_file" | cut -d'T' -f1)
            
            printf "%-20s %-30s %-15s %-10s %-20s\n" "$tenant_id" "$display_name" "$plan" "$status" "$created_at"
        fi
    done
}

# Get tenant info
get_tenant_info() {
    local tenant_id=$1
    local config_file="$TENANT_CONFIG_DIR/${tenant_id}.json"
    local state_file="$TENANT_STATE_DIR/${tenant_id}.state"
    
    if [[ ! -f "$config_file" ]]; then
        error "Tenant $tenant_id not found"
        return 1
    fi
    
    info "Tenant Information: $tenant_id"
    echo ""
    
    # Display configuration
    echo "Configuration:"
    jq -r '
      "  Display Name: " + .display_name,
      "  Admin Email: " + .admin_email,
      "  Plan: " + .plan,
      "  Status: " + .status,
      "  Created: " + .created_at,
      "  Namespace: " + .configuration.namespace,
      "  Redis DB: " + (.configuration.data_isolation.redis_db | tostring)
    ' "$config_file"
    
    echo ""
    echo "Resource Limits:"
    jq -r '
      "  CPU: " + .configuration.resource_quotas.cpu_limit,
      "  Memory: " + .configuration.resource_quotas.memory_limit,
      "  Storage: " + .configuration.resource_quotas.storage_limit,
      "  Pods: " + (.configuration.resource_quotas.pod_limit | tostring),
      "  Max Users: " + (.limits.max_users | tostring),
      "  API Rate Limit: " + (.limits.api_rate_limit | tostring) + " req/min"
    ' "$config_file"
    
    if [[ -f "$state_file" ]]; then
        echo ""
        echo "Endpoints:"
        jq -r '
          "  Auth Service: " + .endpoints.auth_service,
          "  Policy Service: " + .endpoints.policy_service
        ' "$state_file"
    fi
    
    # Check namespace status
    echo ""
    echo "Kubernetes Status:"
    local namespace="tenant-$tenant_id"
    if kubectl get namespace "$namespace" >/dev/null 2>&1; then
        echo "  Namespace: Active"
        local pods=$(kubectl get pods -n "$namespace" --no-headers 2>/dev/null | wc -l)
        local running_pods=$(kubectl get pods -n "$namespace" --no-headers 2>/dev/null | grep Running | wc -l)
        echo "  Pods: $running_pods/$pods running"
    else
        echo "  Namespace: Not Found"
    fi
}

# Usage information
usage() {
    cat << EOF
Multi-Tenant Management System for Rust Security Platform

Usage: $0 <command> [arguments]

Commands:
    create-tenant <tenant-id> <display-name> <admin-email> [plan] [domain]
                                            - Create new tenant
    delete-tenant <tenant-id> [confirm]     - Delete tenant (requires confirmation)
    list-tenants                           - List all tenants
    get-info <tenant-id>                   - Get detailed tenant information
    validate-name <tenant-id>              - Validate tenant name format
    
Plans:
    starter     - Basic plan (2 CPU, 4Gi RAM, 100 users)
    standard    - Standard plan (4 CPU, 8Gi RAM, 500 users) [default]
    premium     - Premium plan (8 CPU, 16Gi RAM, 2000 users)
    enterprise  - Enterprise plan (16 CPU, 32Gi RAM, 10000 users)

Examples:
    $0 create-tenant acme-corp "ACME Corporation" admin@acme.com standard
    $0 list-tenants
    $0 get-info acme-corp
    $0 delete-tenant acme-corp true

EOF
}

# Main execution
main() {
    local command=${1:-""}
    
    case "$command" in
        "create-tenant")
            if [[ $# -lt 4 ]]; then
                error "Tenant ID, display name, and admin email required"
                usage
                exit 1
            fi
            create_tenant "$2" "$3" "$4" "${5:-standard}" "${6:-example.com}"
            ;;
        "delete-tenant")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            delete_tenant "$2" "${3:-false}"
            ;;
        "list-tenants")
            list_tenants
            ;;
        "get-info")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            get_tenant_info "$2"
            ;;
        "validate-name")
            if [[ $# -lt 2 ]]; then
                error "Tenant ID required"
                usage
                exit 1
            fi
            if validate_tenant_name "$2"; then
                success "Tenant name '$2' is valid"
            else
                exit 1
            fi
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