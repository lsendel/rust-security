#!/bin/bash

# Production Deployment Script for Rust Security Platform
# This script handles secure, zero-downtime deployment to production

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
NAMESPACE="${NAMESPACE:-rust-security}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-your-registry.com}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD)}"

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
    log_info "Checking deployment prerequisites..."
    
    # Check required tools
    local required_tools=("docker" "kubectl" "helm" "git")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE does not exist, creating..."
        kubectl create namespace "$NAMESPACE"
    fi
    
    log_success "Prerequisites check passed"
}

# Run security scans
run_security_scans() {
    log_info "Running security scans..."
    
    cd "$PROJECT_ROOT"
    
    # Cargo audit for known vulnerabilities
    if command -v cargo-audit &> /dev/null; then
        log_info "Running cargo audit..."
        cargo audit
    else
        log_warning "cargo-audit not installed, skipping vulnerability scan"
    fi
    
    # Clippy for code quality
    log_info "Running clippy security lints..."
    cargo clippy --all-targets --all-features -- -D warnings
    
    # Check for secrets in code
    if command -v gitleaks &> /dev/null; then
        log_info "Scanning for secrets with gitleaks..."
        gitleaks detect --source . --verbose
    else
        log_warning "gitleaks not installed, skipping secret scan"
    fi
    
    log_success "Security scans completed"
}

# Build and test
build_and_test() {
    log_info "Building and testing application..."
    
    cd "$PROJECT_ROOT"
    
    # Clean build
    cargo clean
    
    # Build in release mode
    log_info "Building release binary..."
    cargo build --release --all-features
    
    # Run tests
    log_info "Running test suite..."
    cargo test --release --all-features
    
    # Run integration tests
    if [ -d "tests" ]; then
        log_info "Running integration tests..."
        cargo test --release --test '*'
    fi
    
    log_success "Build and test completed"
}

# Build Docker images
build_docker_images() {
    log_info "Building Docker images..."
    
    cd "$PROJECT_ROOT"
    
    # Build auth-service image
    log_info "Building auth-service image..."
    docker build \
        -f docker/auth-service/Dockerfile \
        -t "${DOCKER_REGISTRY}/rust-security/auth-service:${IMAGE_TAG}" \
        -t "${DOCKER_REGISTRY}/rust-security/auth-service:latest" \
        .
    
    # Build policy-service image
    log_info "Building policy-service image..."
    docker build \
        -f docker/policy-service/Dockerfile \
        -t "${DOCKER_REGISTRY}/rust-security/policy-service:${IMAGE_TAG}" \
        -t "${DOCKER_REGISTRY}/rust-security/policy-service:latest" \
        .
    
    # Scan images for vulnerabilities
    if command -v trivy &> /dev/null; then
        log_info "Scanning Docker images for vulnerabilities..."
        trivy image "${DOCKER_REGISTRY}/rust-security/auth-service:${IMAGE_TAG}"
        trivy image "${DOCKER_REGISTRY}/rust-security/policy-service:${IMAGE_TAG}"
    else
        log_warning "trivy not installed, skipping image vulnerability scan"
    fi
    
    log_success "Docker images built successfully"
}

# Push Docker images
push_docker_images() {
    log_info "Pushing Docker images to registry..."
    
    # Push auth-service
    docker push "${DOCKER_REGISTRY}/rust-security/auth-service:${IMAGE_TAG}"
    docker push "${DOCKER_REGISTRY}/rust-security/auth-service:latest"
    
    # Push policy-service
    docker push "${DOCKER_REGISTRY}/rust-security/policy-service:${IMAGE_TAG}"
    docker push "${DOCKER_REGISTRY}/rust-security/policy-service:latest"
    
    log_success "Docker images pushed successfully"
}

# Deploy to Kubernetes
deploy_to_kubernetes() {
    log_info "Deploying to Kubernetes..."
    
    cd "$PROJECT_ROOT"
    
    # Create secrets if they don't exist
    create_secrets
    
    # Deploy with Helm
    if [ -f "helm/rust-security/Chart.yaml" ]; then
        log_info "Deploying with Helm..."
        helm upgrade --install rust-security ./helm/rust-security \
            --namespace "$NAMESPACE" \
            --set image.tag="$IMAGE_TAG" \
            --set environment="$DEPLOYMENT_ENV" \
            --wait \
            --timeout=10m
    else
        # Deploy with kubectl
        log_info "Deploying with kubectl..."
        
        # Apply ConfigMaps
        kubectl apply -f k8s/configmaps/ -n "$NAMESPACE"
        
        # Apply Services
        kubectl apply -f k8s/services/ -n "$NAMESPACE"
        
        # Apply Deployments
        envsubst < k8s/deployments/auth-service.yaml | kubectl apply -f - -n "$NAMESPACE"
        envsubst < k8s/deployments/policy-service.yaml | kubectl apply -f - -n "$NAMESPACE"
        
        # Apply Ingress
        kubectl apply -f k8s/ingress/ -n "$NAMESPACE"
    fi
    
    log_success "Kubernetes deployment completed"
}

# Create Kubernetes secrets
create_secrets() {
    log_info "Creating Kubernetes secrets..."
    
    # Check if secrets already exist
    if kubectl get secret rust-security-secrets -n "$NAMESPACE" &> /dev/null; then
        log_info "Secrets already exist, skipping creation"
        return
    fi
    
    # Create secrets from environment variables or files
    kubectl create secret generic rust-security-secrets \
        --from-literal=database-url="${DATABASE_URL:-postgresql://user:pass@localhost/auth}" \
        --from-literal=redis-url="${REDIS_URL:-redis://localhost:6379}" \
        --from-literal=jwt-secret="${JWT_SECRET:-$(openssl rand -base64 32)}" \
        --from-literal=encryption-key="${ENCRYPTION_KEY:-$(openssl rand -base64 32)}" \
        -n "$NAMESPACE"
    
    log_success "Secrets created successfully"
}

# Health check
health_check() {
    log_info "Performing health checks..."
    
    # Wait for deployments to be ready
    kubectl wait --for=condition=available --timeout=300s deployment/auth-service -n "$NAMESPACE"
    kubectl wait --for=condition=available --timeout=300s deployment/policy-service -n "$NAMESPACE"
    
    # Get service endpoints
    local auth_service_ip=$(kubectl get service auth-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    local auth_service_port=$(kubectl get service auth-service -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
    
    if [ -n "$auth_service_ip" ]; then
        local health_url="http://${auth_service_ip}:${auth_service_port}/health"
        log_info "Checking health endpoint: $health_url"
        
        # Wait for service to be healthy
        local max_attempts=30
        local attempt=1
        
        while [ $attempt -le $max_attempts ]; do
            if curl -f -s "$health_url" > /dev/null; then
                log_success "Health check passed"
                return 0
            fi
            
            log_info "Health check attempt $attempt/$max_attempts failed, retrying in 10s..."
            sleep 10
            ((attempt++))
        done
        
        log_error "Health check failed after $max_attempts attempts"
        return 1
    else
        log_warning "Could not determine service IP, skipping external health check"
        
        # Check pod health instead
        local healthy_pods=$(kubectl get pods -n "$NAMESPACE" -l app=auth-service --field-selector=status.phase=Running -o name | wc -l)
        if [ "$healthy_pods" -gt 0 ]; then
            log_success "Pod health check passed ($healthy_pods healthy pods)"
        else
            log_error "No healthy pods found"
            return 1
        fi
    fi
}

# Rollback function
rollback() {
    log_warning "Rolling back deployment..."
    
    if [ -f "helm/rust-security/Chart.yaml" ]; then
        helm rollback rust-security -n "$NAMESPACE"
    else
        kubectl rollout undo deployment/auth-service -n "$NAMESPACE"
        kubectl rollout undo deployment/policy-service -n "$NAMESPACE"
    fi
    
    log_info "Rollback completed"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary resources..."
    
    # Remove temporary files
    rm -f /tmp/rust-security-*
    
    # Clean up Docker images locally (optional)
    if [ "${CLEANUP_LOCAL_IMAGES:-false}" = "true" ]; then
        docker rmi "${DOCKER_REGISTRY}/rust-security/auth-service:${IMAGE_TAG}" || true
        docker rmi "${DOCKER_REGISTRY}/rust-security/policy-service:${IMAGE_TAG}" || true
    fi
    
    log_success "Cleanup completed"
}

# Main deployment function
main() {
    log_info "Starting production deployment for Rust Security Platform"
    log_info "Environment: $DEPLOYMENT_ENV"
    log_info "Namespace: $NAMESPACE"
    log_info "Image Tag: $IMAGE_TAG"
    
    # Trap to handle errors and cleanup
    trap 'log_error "Deployment failed"; cleanup; exit 1' ERR
    trap 'cleanup' EXIT
    
    # Deployment steps
    check_prerequisites
    run_security_scans
    build_and_test
    build_docker_images
    push_docker_images
    deploy_to_kubernetes
    
    # Health check with rollback on failure
    if ! health_check; then
        log_error "Health check failed, initiating rollback"
        rollback
        exit 1
    fi
    
    log_success "🎉 Production deployment completed successfully!"
    log_info "Services are now available in the $NAMESPACE namespace"
    
    # Display service information
    kubectl get services -n "$NAMESPACE"
    kubectl get pods -n "$NAMESPACE"
}

# Script options
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "rollback")
        rollback
        ;;
    "health-check")
        health_check
        ;;
    "cleanup")
        cleanup
        ;;
    *)
        echo "Usage: $0 [deploy|rollback|health-check|cleanup]"
        echo "  deploy      - Full production deployment (default)"
        echo "  rollback    - Rollback to previous version"
        echo "  health-check - Check service health"
        echo "  cleanup     - Clean up temporary resources"
        exit 1
        ;;
esac
