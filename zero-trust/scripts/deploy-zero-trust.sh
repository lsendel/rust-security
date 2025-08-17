#!/bin/bash

# Zero-Trust Architecture Deployment Script
# This script deploys the complete zero-trust infrastructure

set -euo pipefail

# Configuration
NAMESPACE_ZT="zero-trust-system"
NAMESPACE_APP="rust-security-zt"
NAMESPACE_SPIRE="spire-system"
NAMESPACE_POLICY="policy-system"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZT_DIR="$(dirname "$SCRIPT_DIR")"

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
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is required but not installed"
        exit 1
    fi
    
    # Check if istioctl is available
    if ! command -v istioctl &> /dev/null; then
        log_error "istioctl is required but not installed"
        exit 1
    fi
    
    # Check if helm is available
    if ! command -v helm &> /dev/null; then
        log_error "helm is required but not installed"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Wait for deployment to be ready
wait_for_deployment() {
    local namespace=$1
    local deployment=$2
    local timeout=${3:-300}
    
    log_info "Waiting for deployment $deployment in namespace $namespace to be ready..."
    
    if kubectl wait --for=condition=available --timeout=${timeout}s deployment/$deployment -n $namespace; then
        log_success "Deployment $deployment is ready"
    else
        log_error "Deployment $deployment failed to become ready within ${timeout}s"
        return 1
    fi
}

# Wait for pods to be ready
wait_for_pods() {
    local namespace=$1
    local label_selector=$2
    local timeout=${3:-300}
    
    log_info "Waiting for pods with selector $label_selector in namespace $namespace to be ready..."
    
    if kubectl wait --for=condition=ready --timeout=${timeout}s pods -l $label_selector -n $namespace; then
        log_success "Pods with selector $label_selector are ready"
    else
        log_error "Pods with selector $label_selector failed to become ready within ${timeout}s"
        return 1
    fi
}

# Phase 1: Deploy Infrastructure
deploy_infrastructure() {
    log_info "Phase 1: Deploying infrastructure..."
    
    # Create namespaces
    log_info "Creating namespaces..."
    kubectl apply -f "$ZT_DIR/infrastructure/namespace.yaml"
    
    # Install Istio
    log_info "Installing Istio..."
    istioctl install -f "$ZT_DIR/istio/istio-installation.yaml" -y
    
    # Wait for Istio to be ready
    wait_for_deployment istio-system istiod
    wait_for_deployment istio-system istio-ingressgateway
    
    log_success "Phase 1 completed - Infrastructure deployed"
}

# Phase 2: Deploy SPIRE
deploy_spire() {
    log_info "Phase 2: Deploying SPIRE..."
    
    # Deploy SPIRE RBAC
    kubectl apply -f "$ZT_DIR/spire/rbac.yaml"
    
    # Deploy SPIRE Server
    kubectl apply -f "$ZT_DIR/spire/spire-server.yaml"
    wait_for_pods $NAMESPACE_SPIRE "app=spire-server"
    
    # Deploy SPIRE Agent
    kubectl apply -f "$ZT_DIR/spire/spire-agent.yaml"
    wait_for_pods $NAMESPACE_SPIRE "app=spire-agent"
    
    log_success "Phase 2 completed - SPIRE deployed"
}

# Phase 3: Deploy Policy Engine
deploy_policy_engine() {
    log_info "Phase 3: Deploying policy engine..."
    
    # Deploy OPA
    kubectl apply -f "$ZT_DIR/policy-engine/opa-policies.yaml"
    kubectl apply -f "$ZT_DIR/policy-engine/opa-deployment.yaml"
    
    wait_for_deployment $NAMESPACE_POLICY opa
    
    log_success "Phase 3 completed - Policy engine deployed"
}

# Phase 4: Deploy Security Components
deploy_security_components() {
    log_info "Phase 4: Deploying security components..."
    
    # Deploy security monitoring
    kubectl apply -f "$ZT_DIR/monitoring/security-monitoring.yaml"
    wait_for_deployment $NAMESPACE_ZT security-monitor
    
    # Deploy device trust service
    kubectl apply -f "$ZT_DIR/device-trust/device-trust-service.yaml"
    wait_for_deployment $NAMESPACE_ZT device-trust-service
    
    log_success "Phase 4 completed - Security components deployed"
}

# Phase 5: Configure Service Mesh
configure_service_mesh() {
    log_info "Phase 5: Configuring service mesh..."
    
    # Apply peer authentication (permissive mode initially)
    kubectl apply -f "$ZT_DIR/istio/peerauthentication.yaml"
    
    # Apply authorization policies
    kubectl apply -f "$ZT_DIR/istio/authorization-policies.yaml"
    
    # Deploy gateway configuration
    kubectl apply -f "$ZT_DIR/gateway/zero-trust-gateway.yaml"
    
    log_success "Phase 5 completed - Service mesh configured"
}

# Phase 6: Deploy Applications
deploy_applications() {
    log_info "Phase 6: Deploying zero-trust applications..."
    
    # Deploy Redis with zero-trust configuration
    kubectl apply -f "$ZT_DIR/applications/redis-zero-trust.yaml"
    wait_for_pods $NAMESPACE_APP "app=redis"
    
    # Deploy policy service
    kubectl apply -f "$ZT_DIR/applications/policy-service-zero-trust.yaml"
    wait_for_deployment $NAMESPACE_APP policy-service
    
    # Deploy auth service
    kubectl apply -f "$ZT_DIR/applications/auth-service-zero-trust.yaml"
    wait_for_deployment $NAMESPACE_APP auth-service
    
    log_success "Phase 6 completed - Applications deployed"
}

# Validation
validate_deployment() {
    log_info "Validating deployment..."
    
    # Check all pods are running
    log_info "Checking pod status..."
    kubectl get pods -n $NAMESPACE_ZT
    kubectl get pods -n $NAMESPACE_APP
    kubectl get pods -n $NAMESPACE_SPIRE
    kubectl get pods -n $NAMESPACE_POLICY
    kubectl get pods -n istio-system
    
    # Check Istio proxy status
    log_info "Checking Istio proxy status..."
    istioctl proxy-status
    
    # Check SPIFFE identities
    log_info "Checking SPIFFE identities..."
    kubectl exec -n $NAMESPACE_SPIRE deployment/spire-server -- \
        /opt/spire/bin/spire-server entry show
    
    # Test OPA policies
    log_info "Testing OPA policies..."
    kubectl exec -n $NAMESPACE_POLICY deployment/opa -- \
        curl -s localhost:8181/health
    
    log_success "Validation completed"
}

# Enable strict mode
enable_strict_mode() {
    log_info "Enabling strict zero-trust mode..."
    
    # Update PeerAuthentication to STRICT
    kubectl patch peerauthentication default -n istio-system --type='merge' -p='{"spec":{"mtls":{"mode":"STRICT"}}}'
    kubectl patch peerauthentication rust-security-mtls -n $NAMESPACE_APP --type='merge' -p='{"spec":{"mtls":{"mode":"STRICT"}}}'
    
    # Wait for configuration to propagate
    sleep 30
    
    # Validate strict mTLS
    istioctl authn tls-check auth-service.$NAMESPACE_APP.svc.cluster.local
    
    log_success "Strict zero-trust mode enabled"
}

# Cleanup function
cleanup() {
    log_warning "Cleaning up zero-trust deployment..."
    
    # Delete applications
    kubectl delete -f "$ZT_DIR/applications/" --ignore-not-found=true
    
    # Delete security components
    kubectl delete -f "$ZT_DIR/device-trust/" --ignore-not-found=true
    kubectl delete -f "$ZT_DIR/monitoring/" --ignore-not-found=true
    
    # Delete policy engine
    kubectl delete -f "$ZT_DIR/policy-engine/" --ignore-not-found=true
    
    # Delete SPIRE
    kubectl delete -f "$ZT_DIR/spire/" --ignore-not-found=true
    
    # Delete Istio configuration
    kubectl delete -f "$ZT_DIR/istio/" --ignore-not-found=true
    kubectl delete -f "$ZT_DIR/gateway/" --ignore-not-found=true
    
    # Uninstall Istio
    istioctl uninstall --purge -y
    
    # Delete namespaces
    kubectl delete -f "$ZT_DIR/infrastructure/namespace.yaml" --ignore-not-found=true
    
    log_success "Cleanup completed"
}

# Main deployment function
deploy() {
    log_info "Starting zero-trust architecture deployment..."
    
    check_prerequisites
    deploy_infrastructure
    deploy_spire
    deploy_policy_engine
    deploy_security_components
    configure_service_mesh
    deploy_applications
    validate_deployment
    
    log_success "Zero-trust architecture deployment completed successfully!"
    log_info "To enable strict mode, run: $0 --strict"
    log_info "To cleanup, run: $0 --cleanup"
}

# Parse command line arguments
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    --strict)
        enable_strict_mode
        ;;
    --cleanup)
        cleanup
        ;;
    --validate)
        validate_deployment
        ;;
    --help)
        echo "Usage: $0 [deploy|--strict|--cleanup|--validate|--help]"
        echo "  deploy    : Deploy zero-trust architecture (default)"
        echo "  --strict  : Enable strict zero-trust mode"
        echo "  --cleanup : Remove zero-trust deployment"
        echo "  --validate: Validate deployment"
        echo "  --help    : Show this help"
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Run '$0 --help' for usage information"
        exit 1
        ;;
esac