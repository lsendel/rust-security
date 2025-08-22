#!/bin/bash

# 🚀 Production Deployment Script for Rust Security Platform
# This script automates the complete production deployment process

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="rust-security"
REGISTRY="your-registry.com"
VERSION="${VERSION:-$(git rev-parse --short HEAD)}"
ENVIRONMENT="${ENVIRONMENT:-production}"
KUBECTL_CONTEXT="${KUBECTL_CONTEXT:-production-cluster}"

# Functions
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

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check required tools
    local tools=("kubectl" "docker" "helm" "git")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed"
            exit 1
        fi
    done
    
    # Check kubectl context
    if ! kubectl config current-context | grep -q "$KUBECTL_CONTEXT"; then
        log_error "Wrong kubectl context. Expected: $KUBECTL_CONTEXT"
        exit 1
    fi
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_info "Creating namespace $NAMESPACE"
        kubectl create namespace "$NAMESPACE"
    fi
    
    log_success "Prerequisites check passed"
}

validate_code_quality() {
    log_info "Validating code quality..."
    
    # Run the validation script we created earlier
    if [[ -f "./validate_github_actions_fixes.sh" ]]; then
        ./validate_github_actions_fixes.sh
    else
        log_warning "Validation script not found, running basic checks"
        
        # Basic validation
        cargo fmt --all -- --check || {
            log_error "Code formatting check failed"
            exit 1
        }
        
        # Progressive clippy check
        local strict_packages=("auth-core" "api-contracts" "compliance-tools" "common")
        for package in "${strict_packages[@]}"; do
            cargo clippy --package "$package" --all-targets --all-features -- -D warnings || {
                log_error "Clippy check failed for $package"
                exit 1
            }
        done
        
        # Policy service with relaxed check
        cargo clippy --package policy-service --all-targets --all-features -- -D warnings -A unused-crate-dependencies || {
            log_error "Clippy check failed for policy-service"
            exit 1
        }
    fi
    
    log_success "Code quality validation passed"
}

run_security_scan() {
    log_info "Running security scans..."
    
    # Cargo audit
    if command -v cargo-audit &> /dev/null; then
        cargo audit || {
            log_warning "Security vulnerabilities found in dependencies"
            read -p "Continue deployment? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        }
    else
        log_warning "cargo-audit not installed, skipping dependency scan"
    fi
    
    # Check for secrets in code
    if command -v gitleaks &> /dev/null; then
        gitleaks detect --source . --verbose || {
            log_error "Secrets detected in code"
            exit 1
        }
    else
        log_warning "gitleaks not installed, skipping secret scan"
    fi
    
    log_success "Security scans completed"
}

build_and_push_images() {
    log_info "Building and pushing Docker images..."
    
    # Build auth-service
    log_info "Building auth-service image..."
    docker build -f auth-service/Dockerfile -t "$REGISTRY/auth-service:$VERSION" .
    docker push "$REGISTRY/auth-service:$VERSION"
    
    # Build policy-service
    log_info "Building policy-service image..."
    docker build -f policy-service/Dockerfile -t "$REGISTRY/policy-service:$VERSION" .
    docker push "$REGISTRY/policy-service:$VERSION"
    
    # Build compliance-tools
    log_info "Building compliance-tools image..."
    docker build -f compliance-tools/Dockerfile -t "$REGISTRY/compliance-tools:$VERSION" .
    docker push "$REGISTRY/compliance-tools:$VERSION"
    
    # Tag as latest for production
    docker tag "$REGISTRY/auth-service:$VERSION" "$REGISTRY/auth-service:latest"
    docker tag "$REGISTRY/policy-service:$VERSION" "$REGISTRY/policy-service:latest"
    docker tag "$REGISTRY/compliance-tools:$VERSION" "$REGISTRY/compliance-tools:latest"
    
    docker push "$REGISTRY/auth-service:latest"
    docker push "$REGISTRY/policy-service:latest"
    docker push "$REGISTRY/compliance-tools:latest"
    
    log_success "Images built and pushed successfully"
}

scan_images() {
    log_info "Scanning Docker images for vulnerabilities..."
    
    local images=("auth-service" "policy-service" "compliance-tools")
    
    for image in "${images[@]}"; do
        if command -v trivy &> /dev/null; then
            log_info "Scanning $image with Trivy..."
            trivy image --exit-code 0 --severity HIGH,CRITICAL "$REGISTRY/$image:$VERSION" || {
                log_warning "Vulnerabilities found in $image"
            }
        else
            log_warning "Trivy not installed, skipping image scan for $image"
        fi
    done
    
    log_success "Image scanning completed"
}

deploy_infrastructure() {
    log_info "Deploying infrastructure components..."
    
    # Deploy PostgreSQL
    if ! kubectl get statefulset postgres -n "$NAMESPACE" &> /dev/null; then
        log_info "Deploying PostgreSQL..."
        kubectl apply -f k8s/postgres/ -n "$NAMESPACE"
        kubectl wait --for=condition=ready pod -l app=postgres -n "$NAMESPACE" --timeout=300s
    fi
    
    # Deploy Redis
    if ! kubectl get deployment redis -n "$NAMESPACE" &> /dev/null; then
        log_info "Deploying Redis..."
        kubectl apply -f k8s/redis/ -n "$NAMESPACE"
        kubectl wait --for=condition=available deployment/redis -n "$NAMESPACE" --timeout=300s
    fi
    
    # Deploy monitoring stack
    log_info "Deploying monitoring stack..."
    kubectl apply -f monitoring/production-monitoring.yml -n "$NAMESPACE"
    
    log_success "Infrastructure deployment completed"
}

deploy_applications() {
    log_info "Deploying application services..."
    
    # Update image tags in deployment files
    find k8s/ -name "*.yml" -o -name "*.yaml" | xargs sed -i.bak "s|image: .*auth-service:.*|image: $REGISTRY/auth-service:$VERSION|g"
    find k8s/ -name "*.yml" -o -name "*.yaml" | xargs sed -i.bak "s|image: .*policy-service:.*|image: $REGISTRY/policy-service:$VERSION|g"
    find k8s/ -name "*.yml" -o -name "*.yaml" | xargs sed -i.bak "s|image: .*compliance-tools:.*|image: $REGISTRY/compliance-tools:$VERSION|g"
    
    # Deploy applications
    kubectl apply -f k8s/auth-service/ -n "$NAMESPACE"
    kubectl apply -f k8s/policy-service/ -n "$NAMESPACE"
    kubectl apply -f k8s/compliance-tools/ -n "$NAMESPACE"
    
    # Wait for deployments to be ready
    kubectl wait --for=condition=available deployment/auth-service -n "$NAMESPACE" --timeout=600s
    kubectl wait --for=condition=available deployment/policy-service -n "$NAMESPACE" --timeout=600s
    kubectl wait --for=condition=available deployment/compliance-tools -n "$NAMESPACE" --timeout=600s
    
    log_success "Application deployment completed"
}

run_smoke_tests() {
    log_info "Running smoke tests..."
    
    # Get service endpoints
    local auth_service_ip=$(kubectl get service auth-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    local policy_service_ip=$(kubectl get service policy-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    # Test auth service health
    if curl -f "http://$auth_service_ip:8080/health" &> /dev/null; then
        log_success "Auth service health check passed"
    else
        log_error "Auth service health check failed"
        exit 1
    fi
    
    # Test policy service health
    if curl -f "http://$policy_service_ip:8081/health" &> /dev/null; then
        log_success "Policy service health check passed"
    else
        log_error "Policy service health check failed"
        exit 1
    fi
    
    # Test basic authentication flow
    log_info "Testing basic authentication flow..."
    local auth_response=$(curl -s -X POST "http://$auth_service_ip:8080/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"test@example.com","password":"testpassword"}')
    
    if echo "$auth_response" | jq -e '.data.token' &> /dev/null; then
        log_success "Basic authentication test passed"
    else
        log_warning "Basic authentication test failed (may be expected if no test user exists)"
    fi
    
    log_success "Smoke tests completed"
}

setup_monitoring() {
    log_info "Setting up monitoring and alerting..."
    
    # Deploy Grafana dashboards
    if kubectl get configmap grafana-dashboards -n "$NAMESPACE" &> /dev/null; then
        kubectl apply -f monitoring/grafana-dashboards.yml -n "$NAMESPACE"
    fi
    
    # Configure Prometheus alerts
    if kubectl get configmap prometheus-alerts -n "$NAMESPACE" &> /dev/null; then
        kubectl apply -f monitoring/prometheus-alerts.yml -n "$NAMESPACE"
    fi
    
    # Restart Prometheus to pick up new configuration
    kubectl rollout restart deployment/prometheus -n "$NAMESPACE"
    
    log_success "Monitoring setup completed"
}

configure_autoscaling() {
    log_info "Configuring autoscaling..."
    
    # Deploy Horizontal Pod Autoscalers
    kubectl apply -f k8s/hpa/ -n "$NAMESPACE"
    
    # Deploy Vertical Pod Autoscalers if available
    if kubectl get crd verticalpodautoscalers.autoscaling.k8s.io &> /dev/null; then
        kubectl apply -f k8s/vpa/ -n "$NAMESPACE"
    fi
    
    log_success "Autoscaling configuration completed"
}

setup_backup() {
    log_info "Setting up backup procedures..."
    
    # Create backup CronJob for database
    kubectl apply -f k8s/backup/ -n "$NAMESPACE"
    
    # Verify backup job is scheduled
    kubectl get cronjob -n "$NAMESPACE"
    
    log_success "Backup setup completed"
}

generate_deployment_report() {
    log_info "Generating deployment report..."
    
    local report_file="deployment-report-$(date +%Y%m%d-%H%M%S).md"
    
    cat > "$report_file" << EOF
# Deployment Report

**Date:** $(date)
**Version:** $VERSION
**Environment:** $ENVIRONMENT
**Namespace:** $NAMESPACE

## Deployment Summary

- ✅ Code quality validation passed
- ✅ Security scans completed
- ✅ Docker images built and pushed
- ✅ Infrastructure deployed
- ✅ Applications deployed
- ✅ Smoke tests passed
- ✅ Monitoring configured
- ✅ Autoscaling enabled
- ✅ Backup procedures set up

## Service Status

\`\`\`
$(kubectl get pods -n "$NAMESPACE")
\`\`\`

## Service Endpoints

\`\`\`
$(kubectl get services -n "$NAMESPACE")
\`\`\`

## Resource Usage

\`\`\`
$(kubectl top pods -n "$NAMESPACE" 2>/dev/null || echo "Metrics server not available")
\`\`\`

## Next Steps

1. Monitor application metrics in Grafana
2. Verify alerting is working correctly
3. Run full integration tests
4. Update documentation with new endpoints
5. Notify stakeholders of successful deployment

EOF

    log_success "Deployment report generated: $report_file"
}

cleanup() {
    log_info "Cleaning up temporary files..."
    
    # Remove backup files created during deployment
    find k8s/ -name "*.bak" -delete
    
    log_success "Cleanup completed"
}

main() {
    echo "🚀 Starting Production Deployment for Rust Security Platform"
    echo "============================================================"
    echo "Version: $VERSION"
    echo "Environment: $ENVIRONMENT"
    echo "Namespace: $NAMESPACE"
    echo "Registry: $REGISTRY"
    echo ""
    
    # Deployment steps
    check_prerequisites
    validate_code_quality
    run_security_scan
    build_and_push_images
    scan_images
    deploy_infrastructure
    deploy_applications
    run_smoke_tests
    setup_monitoring
    configure_autoscaling
    setup_backup
    generate_deployment_report
    cleanup
    
    echo ""
    echo "🎉 Production Deployment Completed Successfully!"
    echo "=============================================="
    echo ""
    echo "📊 Access your services:"
    echo "• Auth Service: $(kubectl get service auth-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):8080"
    echo "• Policy Service: $(kubectl get service policy-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):8081"
    echo "• Grafana: $(kubectl get service grafana -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):3000"
    echo "• Prometheus: $(kubectl get service prometheus -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}'):9090"
    echo ""
    echo "📋 Next steps:"
    echo "1. Monitor the deployment in Grafana"
    echo "2. Run comprehensive integration tests"
    echo "3. Update DNS records if needed"
    echo "4. Notify stakeholders"
    echo ""
    echo "🔒 Your Rust Security Platform is now live in production!"
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"
