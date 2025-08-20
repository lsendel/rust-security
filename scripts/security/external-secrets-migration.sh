#!/bin/bash

# External Secrets Migration Script
# This script helps migrate from static Kubernetes secrets to External Secrets Operator

set -euo pipefail

# Configuration
NAMESPACE="rust-security"
SECRET_NAME="auth-service-secret"
BACKUP_DIR="./secret-backups"
VAULT_PREFIX="auth-service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if external-secrets operator is installed
    if ! kubectl get crd externalsecrets.external-secrets.io &> /dev/null; then
        log_error "External Secrets Operator is not installed"
        log_info "Install with: helm repo add external-secrets https://charts.external-secrets.io && helm install external-secrets external-secrets/external-secrets -n external-secrets-system --create-namespace"
        exit 1
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace $NAMESPACE does not exist"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Backup existing secrets
backup_secrets() {
    log_info "Backing up existing secrets..."
    
    mkdir -p "$BACKUP_DIR"
    
    if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" &> /dev/null; then
        kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o yaml > "$BACKUP_DIR/${SECRET_NAME}-$(date +%Y%m%d-%H%M%S).yaml"
        log_success "Secret backed up to $BACKUP_DIR"
    else
        log_warning "Secret $SECRET_NAME not found in namespace $NAMESPACE"
    fi
}

# Extract secret values for migration
extract_secret_values() {
    log_info "Extracting secret values for migration..."
    
    if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" &> /dev/null; then
        local secret_file="$BACKUP_DIR/extracted-secrets.env"
        
        echo "# Extracted secret values for migration" > "$secret_file"
        echo "# Store these values in your external secret store" >> "$secret_file"
        echo "" >> "$secret_file"
        
        # Extract each secret key
        for key in jwt-secret client-credentials request-signing-secret google-client-secret redis-password; do
            if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath="{.data.$key}" &> /dev/null; then
                local value=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath="{.data.$key}" | base64 -d)
                echo "# $key" >> "$secret_file"
                echo "$key=\"$value\"" >> "$secret_file"
                echo "" >> "$secret_file"
            fi
        done
        
        log_success "Secret values extracted to $secret_file"
        log_warning "Remember to securely store these values in your external secret store and then delete this file"
    fi
}

# Store secrets in Vault (if vault CLI is available)
store_secrets_in_vault() {
    if ! command -v vault &> /dev/null; then
        log_warning "Vault CLI not available, skipping automatic secret storage"
        return
    fi
    
    log_info "Storing secrets in Vault..."
    
    local secret_file="$BACKUP_DIR/extracted-secrets.env"
    if [[ ! -f "$secret_file" ]]; then
        log_error "Secret values file not found. Run extract_secret_values first."
        return 1
    fi
    
    # Source the secret values
    source "$secret_file"
    
    # Store in Vault
    if [[ -n "${jwt-secret:-}" ]]; then
        vault kv put "secret/$VAULT_PREFIX/jwt" secret="$jwt-secret"
        log_success "JWT secret stored in Vault"
    fi
    
    if [[ -n "${client-credentials:-}" ]]; then
        vault kv put "secret/$VAULT_PREFIX/clients" credentials="$client-credentials"
        log_success "Client credentials stored in Vault"
    fi
    
    if [[ -n "${request-signing-secret:-}" ]]; then
        vault kv put "secret/$VAULT_PREFIX/signing" secret="$request-signing-secret"
        log_success "Request signing secret stored in Vault"
    fi
    
    if [[ -n "${google-client-secret:-}" ]]; then
        vault kv put "secret/$VAULT_PREFIX/oauth/google" client_secret="$google-client-secret"
        log_success "Google client secret stored in Vault"
    fi
    
    if [[ -n "${redis-password:-}" ]]; then
        vault kv put "secret/$VAULT_PREFIX/redis" password="$redis-password"
        log_success "Redis password stored in Vault"
    fi
}

# Deploy External Secrets configuration
deploy_external_secrets() {
    local backend="${1:-vault}"
    
    log_info "Deploying External Secrets configuration for $backend..."
    
    case "$backend" in
        vault)
            kubectl apply -f k8s/vault-external-secrets.yaml
            ;;
        aws)
            kubectl apply -f k8s/aws-external-secrets.yaml
            ;;
        gcp)
            kubectl apply -f k8s/gcp-external-secrets.yaml
            ;;
        *)
            log_error "Unsupported backend: $backend. Use 'vault', 'aws', or 'gcp'"
            exit 1
            ;;
    esac
    
    log_success "External Secrets configuration deployed"
}

# Verify External Secrets are working
verify_external_secrets() {
    log_info "Verifying External Secrets deployment..."
    
    # Wait for ExternalSecret to be ready
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if kubectl get externalsecret -n "$NAMESPACE" -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}' | grep -q "True"; then
            log_success "ExternalSecret is ready"
            break
        fi
        
        log_info "Waiting for ExternalSecret to be ready (attempt $attempt/$max_attempts)..."
        sleep 10
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        log_error "ExternalSecret failed to become ready within timeout"
        kubectl describe externalsecret -n "$NAMESPACE"
        exit 1
    fi
    
    # Verify secret was created
    if kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" &> /dev/null; then
        log_success "Secret $SECRET_NAME was created by External Secrets"
        
        # Check secret keys
        local keys=$(kubectl get secret "$SECRET_NAME" -n "$NAMESPACE" -o jsonpath='{.data}' | jq -r 'keys[]')
        log_info "Secret contains keys: $keys"
    else
        log_error "Secret $SECRET_NAME was not created"
        exit 1
    fi
}

# Test application connectivity
test_application() {
    log_info "Testing application connectivity..."
    
    # Check if auth-service pods are running
    local pod_count=$(kubectl get pods -n "$NAMESPACE" -l app.kubernetes.io/name=auth-service --field-selector=status.phase=Running -o jsonpath='{.items}' | jq length)
    
    if [[ $pod_count -gt 0 ]]; then
        log_success "Auth service pods are running"
        
        # Try to access health endpoint
        if kubectl port-forward -n "$NAMESPACE" service/auth-service 8080:8080 &
        then
            local port_forward_pid=$!
            sleep 5
            
            if curl -s http://localhost:8080/health | grep -q "ok\|healthy"; then
                log_success "Application health check passed"
            else
                log_warning "Application health check failed"
            fi
            
            kill $port_forward_pid 2>/dev/null || true
        fi
    else
        log_warning "No auth service pods are running"
    fi
}

# Cleanup old secrets
cleanup_old_secrets() {
    log_info "Cleaning up old static secrets..."
    
    read -p "Are you sure you want to delete the old static secret? This cannot be undone. (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Create a backup first
        backup_secrets
        
        # Delete the old secret (it will be recreated by External Secrets)
        kubectl delete secret "$SECRET_NAME" -n "$NAMESPACE" || true
        
        log_success "Old static secret deleted"
        log_info "External Secrets will recreate the secret automatically"
    else
        log_info "Cleanup cancelled"
    fi
}

# Enable External Secrets in Helm
enable_external_secrets_helm() {
    local backend="${1:-vault}"
    
    log_info "Updating Helm deployment to use External Secrets..."
    
    # Create values override file
    cat > "$BACKUP_DIR/external-secrets-values.yaml" << EOF
externalSecrets:
  enabled: true
  provider:
    type: $backend

# Disable static secrets
secrets:
  jwtSecret: ""
  clientCredentials: ""
  requestSigningSecret: ""
  redisPassword: ""
  googleClientSecret: ""
EOF
    
    log_info "Created Helm values override file: $BACKUP_DIR/external-secrets-values.yaml"
    log_info "Apply with: helm upgrade auth-service ./helm/auth-service -f $BACKUP_DIR/external-secrets-values.yaml"
}

# Rollback function
rollback() {
    log_warning "Rolling back to static secrets..."
    
    # Find the most recent backup
    local latest_backup=$(ls -t "$BACKUP_DIR"/*.yaml 2>/dev/null | head -1)
    
    if [[ -n "$latest_backup" ]]; then
        kubectl apply -f "$latest_backup"
        log_success "Rollback completed using $latest_backup"
    else
        log_error "No backup found for rollback"
        exit 1
    fi
}

# Main function
main() {
    local action="${1:-help}"
    local backend="${2:-vault}"
    
    case "$action" in
        backup)
            check_prerequisites
            backup_secrets
            ;;
        extract)
            check_prerequisites
            backup_secrets
            extract_secret_values
            ;;
        vault-store)
            check_prerequisites
            backup_secrets
            extract_secret_values
            store_secrets_in_vault
            ;;
        deploy)
            check_prerequisites
            deploy_external_secrets "$backend"
            ;;
        verify)
            check_prerequisites
            verify_external_secrets
            ;;
        test)
            check_prerequisites
            test_application
            ;;
        migrate)
            check_prerequisites
            backup_secrets
            extract_secret_values
            if [[ "$backend" == "vault" ]]; then
                store_secrets_in_vault
            fi
            deploy_external_secrets "$backend"
            verify_external_secrets
            enable_external_secrets_helm "$backend"
            test_application
            log_success "Migration completed successfully!"
            log_info "Next steps:"
            log_info "1. Update Helm deployment: helm upgrade auth-service ./helm/auth-service -f $BACKUP_DIR/external-secrets-values.yaml"
            log_info "2. Test the application thoroughly"
            log_info "3. Run '$0 cleanup' to remove old static secrets"
            ;;
        cleanup)
            check_prerequisites
            cleanup_old_secrets
            ;;
        rollback)
            rollback
            ;;
        help|*)
            echo "External Secrets Migration Script"
            echo ""
            echo "Usage: $0 <action> [backend]"
            echo ""
            echo "Actions:"
            echo "  backup        - Backup existing secrets"
            echo "  extract       - Extract secret values for migration"
            echo "  vault-store   - Store secrets in Vault (requires vault CLI)"
            echo "  deploy        - Deploy External Secrets configuration"
            echo "  verify        - Verify External Secrets are working"
            echo "  test          - Test application connectivity"
            echo "  migrate       - Full migration process"
            echo "  cleanup       - Remove old static secrets"
            echo "  rollback      - Rollback to static secrets"
            echo "  help          - Show this help message"
            echo ""
            echo "Backends: vault, aws, gcp (default: vault)"
            echo ""
            echo "Examples:"
            echo "  $0 migrate vault     - Migrate to Vault backend"
            echo "  $0 migrate aws       - Migrate to AWS Secrets Manager"
            echo "  $0 backup           - Backup current secrets"
            echo "  $0 rollback         - Emergency rollback"
            ;;
    esac
}

# Run main function with all arguments
main "$@"