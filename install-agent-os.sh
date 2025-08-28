#!/bin/bash

# Agent OS Installation Script for Rust Security Platform
# Version: 1.0.0
# Last Updated: 2025-08-28

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="rust-security"
AGENT_OS_VERSION="latest"
TIMEOUT_SECONDS=300

# Helper functions
print_header() {
    echo -e "${PURPLE}================================================================================${NC}"
    echo -e "${PURPLE}                         $1${NC}"
    echo -e "${PURPLE}================================================================================${NC}"
    echo
}

print_section() {
    echo -e "${BLUE}🔧 $1${NC}"
    echo "--------------------------------------------------------------------------------"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    print_success "kubectl is available"
    
    # Check cluster connection
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    print_success "Connected to Kubernetes cluster"
    
    # Check helm (optional but recommended)
    if command -v helm &> /dev/null; then
        print_success "helm is available"
    else
        print_warning "helm is not available (optional)"
    fi
    
    echo
}

# Create namespace
create_namespace() {
    print_section "Creating Namespace"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_info "Namespace '$NAMESPACE' already exists"
    else
        kubectl create namespace "$NAMESPACE"
        print_success "Created namespace '$NAMESPACE'"
    fi
    
    # Label namespace for monitoring
    kubectl label namespace "$NAMESPACE" name="$NAMESPACE" --overwrite
    kubectl label namespace "$NAMESPACE" monitoring="enabled" --overwrite
    
    echo
}

# Install Agent OS integration
install_agent_os() {
    print_section "Installing Agent OS Integration"
    
    # Apply integration configuration
    if [[ -f "agent-os-integration.yaml" ]]; then
        print_info "Applying Agent OS integration configuration..."
        kubectl apply -f agent-os-integration.yaml -n "$NAMESPACE"
        print_success "Agent OS integration configuration applied"
    else
        print_error "agent-os-integration.yaml not found"
        exit 1
    fi
    
    # Apply monitoring configuration
    if [[ -f "agent-os-monitoring.yaml" ]]; then
        print_info "Applying Agent OS monitoring configuration..."
        kubectl apply -f agent-os-monitoring.yaml -n "$NAMESPACE"
        print_success "Agent OS monitoring configuration applied"
    else
        print_warning "agent-os-monitoring.yaml not found - skipping monitoring setup"
    fi
    
    # Apply service discovery configuration
    if [[ -f "agent-os-service-discovery.yaml" ]]; then
        print_info "Applying Agent OS service discovery configuration..."
        kubectl apply -f agent-os-service-discovery.yaml -n "$NAMESPACE"
        print_success "Agent OS service discovery configuration applied"
    else
        print_warning "agent-os-service-discovery.yaml not found - skipping service discovery setup"
    fi
    
    echo
}

# Wait for deployments
wait_for_deployments() {
    print_section "Waiting for Deployments"
    
    local deployments=(
        "agent-os-coordinator"
        "consul-agent"
    )
    
    for deployment in "${deployments[@]}"; do
        print_info "Waiting for deployment '$deployment' to be ready..."
        if kubectl wait --for=condition=available --timeout="${TIMEOUT_SECONDS}s" deployment/"$deployment" -n "$NAMESPACE" 2>/dev/null; then
            print_success "Deployment '$deployment' is ready"
        else
            print_warning "Deployment '$deployment' not found or not ready within timeout"
        fi
    done
    
    echo
}

# Verify installation
verify_installation() {
    print_section "Verifying Installation"
    
    # Check pods
    print_info "Checking pod status..."
    kubectl get pods -n "$NAMESPACE" -l app=agent-os
    
    # Check services
    print_info "Checking service status..."
    kubectl get services -n "$NAMESPACE" -l app=agent-os
    
    # Test Agent OS coordinator health
    print_info "Testing Agent OS coordinator health..."
    if kubectl exec -n "$NAMESPACE" deployment/agent-os-coordinator -- curl -f -s -o /dev/null "http://localhost:8090/health" 2>/dev/null; then
        print_success "Agent OS coordinator is healthy"
    else
        print_warning "Agent OS coordinator health check failed or not accessible"
    fi
    
    # Test service discovery
    print_info "Testing service discovery..."
    if kubectl get endpoints -n "$NAMESPACE" rust-security-services &>/dev/null; then
        print_success "Service discovery endpoints are configured"
    else
        print_warning "Service discovery endpoints not found"
    fi
    
    echo
}

# Setup monitoring (if Prometheus is available)
setup_monitoring() {
    print_section "Setting Up Monitoring"
    
    # Check if Prometheus operator is available
    if kubectl get crd servicemonitors.monitoring.coreos.com &>/dev/null; then
        print_info "Prometheus operator detected - ServiceMonitors will be created"
        print_success "Monitoring setup completed"
    else
        print_warning "Prometheus operator not found - ServiceMonitors will not function"
        print_info "To enable monitoring, install Prometheus operator first"
    fi
    
    # Check if Grafana is available
    if kubectl get configmap -n "$NAMESPACE" agent-os-grafana-dashboard &>/dev/null; then
        print_success "Grafana dashboard configuration is available"
        print_info "Import the dashboard JSON from the ConfigMap to Grafana"
    fi
    
    echo
}

# Show next steps
show_next_steps() {
    print_section "Next Steps"
    
    print_info "Agent OS integration has been installed successfully!"
    echo
    print_info "To access Agent OS coordinator:"
    echo "  kubectl port-forward -n $NAMESPACE svc/agent-os-coordinator 8090:8090"
    echo "  Then visit: http://localhost:8090/health"
    echo
    
    print_info "To view logs:"
    echo "  kubectl logs -n $NAMESPACE deployment/agent-os-coordinator -f"
    echo
    
    print_info "To check service discovery:"
    echo "  kubectl get endpoints -n $NAMESPACE"
    echo
    
    print_info "To access monitoring (if Prometheus is installed):"
    echo "  kubectl port-forward -n monitoring svc/prometheus 9090:9090"
    echo "  Then visit: http://localhost:9090"
    echo
    
    print_info "Configuration files created:"
    echo "  - agent-os-integration.yaml (main configuration)"
    echo "  - agent-os-monitoring.yaml (monitoring setup)"
    echo "  - agent-os-service-discovery.yaml (service discovery)"
    echo
    
    print_info "For troubleshooting:"
    echo "  kubectl describe pods -n $NAMESPACE -l app=agent-os"
    echo "  kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp'"
    echo
}

# Uninstall function
uninstall_agent_os() {
    print_section "Uninstalling Agent OS"
    
    print_warning "This will remove all Agent OS components from namespace '$NAMESPACE'"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Remove resources
        for file in agent-os-integration.yaml agent-os-monitoring.yaml agent-os-service-discovery.yaml; do
            if [[ -f "$file" ]]; then
                kubectl delete -f "$file" -n "$NAMESPACE" --ignore-not-found=true
                print_success "Removed resources from $file"
            fi
        done
        
        # Remove any remaining Agent OS resources
        kubectl delete all -n "$NAMESPACE" -l app=agent-os --ignore-not-found=true
        kubectl delete configmaps -n "$NAMESPACE" -l app=agent-os --ignore-not-found=true
        kubectl delete secrets -n "$NAMESPACE" -l app=agent-os --ignore-not-found=true
        kubectl delete serviceaccounts -n "$NAMESPACE" -l app=agent-os --ignore-not-found=true
        
        print_success "Agent OS uninstalled successfully"
    else
        print_info "Uninstall cancelled"
    fi
}

# Main function
main() {
    print_header "Agent OS Integration Installer"
    print_info "Installing Agent OS integration for Rust Security Platform"
    print_info "Namespace: $NAMESPACE"
    print_info "Version: $AGENT_OS_VERSION"
    echo
    
    case "${1:-install}" in
        "install")
            check_prerequisites
            create_namespace
            install_agent_os
            wait_for_deployments
            verify_installation
            setup_monitoring
            show_next_steps
            ;;
        "uninstall")
            uninstall_agent_os
            ;;
        "verify")
            verify_installation
            ;;
        "status")
            print_section "Agent OS Status"
            kubectl get all -n "$NAMESPACE" -l app=agent-os
            ;;
        *)
            echo "Usage: $0 [install|uninstall|verify|status]"
            echo
            echo "Commands:"
            echo "  install   - Install Agent OS integration (default)"
            echo "  uninstall - Remove Agent OS integration"
            echo "  verify    - Verify current installation"
            echo "  status    - Show status of Agent OS components"
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"