#!/bin/bash

# Comprehensive Monitoring Stack Deployment Script
# Deploys production-grade monitoring with Prometheus, Grafana, and Alertmanager

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MONITORING_DIR="$PROJECT_ROOT/monitoring"
NAMESPACE="monitoring"
ENVIRONMENT="${ENVIRONMENT:-production}"
CLUSTER_NAME="${CLUSTER_NAME:-security-platform}"

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
    
    local missing_tools=()
    
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi
    
    if ! command -v helm &> /dev/null && [[ "${USE_HELM:-false}" == "true" ]]; then
        missing_tools+=("helm")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    log_success "All prerequisites satisfied"
}

# Create namespace and basic resources
create_namespace() {
    log_info "Creating monitoring namespace..."
    
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    kubectl label namespace "$NAMESPACE" name="$NAMESPACE" --overwrite
    
    log_success "Namespace $NAMESPACE created/updated"
}

# Deploy Prometheus rules
deploy_prometheus_rules() {
    log_info "Deploying Prometheus alerting rules..."
    
    local rules_configmap="prometheus-rules"
    
    # Remove existing configmap
    kubectl delete configmap "$rules_configmap" -n "$NAMESPACE" --ignore-not-found
    
    # Create new configmap with all rule files
    kubectl create configmap "$rules_configmap" -n "$NAMESPACE" \
        --from-file="$MONITORING_DIR/prometheus/security-alerts.yml" \
        --from-file="$MONITORING_DIR/prometheus/security-anomaly-rules.yml" \
        --from-file="$MONITORING_DIR/prometheus/sla-rules.yml" \
        --from-file="$MONITORING_DIR/prometheus/infrastructure-rules.yml" \
        --from-file="$MONITORING_DIR/prometheus/threat-intel-rules.yml"
    
    log_success "Prometheus rules deployed"
}

# Deploy Grafana dashboards
deploy_grafana_dashboards() {
    log_info "Deploying Grafana dashboards..."
    
    local dashboards_configmap="grafana-dashboards"
    
    # Remove existing configmap
    kubectl delete configmap "$dashboards_configmap" -n "$NAMESPACE" --ignore-not-found
    
    # Create new configmap with all dashboard files
    kubectl create configmap "$dashboards_configmap" -n "$NAMESPACE" \
        --from-file="$MONITORING_DIR/grafana/dashboards/auth-service-dashboard.json" \
        --from-file="$MONITORING_DIR/grafana/dashboards/policy-service-dashboard.json" \
        --from-file="$MONITORING_DIR/grafana/dashboards/security/security-overview.json"
    
    log_success "Grafana dashboards deployed"
}

# Generate secrets
generate_secrets() {
    log_info "Generating monitoring secrets..."
    
    # Generate Grafana admin password
    local grafana_password
    grafana_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    
    # Create Grafana secrets
    kubectl create secret generic grafana-secrets -n "$NAMESPACE" \
        --from-literal=admin-password="$grafana_password" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Store password in a secure location (in production, use proper secret management)
    echo "$grafana_password" > "/tmp/grafana-admin-password-$CLUSTER_NAME"
    chmod 600 "/tmp/grafana-admin-password-$CLUSTER_NAME"
    
    log_warning "Grafana admin password stored in /tmp/grafana-admin-password-$CLUSTER_NAME"
    log_warning "Please move this to your secret management system and delete the temporary file"
    
    # Create TLS secrets for HTTPS (if certificates exist)
    if [[ -f "$MONITORING_DIR/certs/tls.crt" ]] && [[ -f "$MONITORING_DIR/certs/tls.key" ]]; then
        kubectl create secret tls monitoring-tls -n "$NAMESPACE" \
            --cert="$MONITORING_DIR/certs/tls.crt" \
            --key="$MONITORING_DIR/certs/tls.key" \
            --dry-run=client -o yaml | kubectl apply -f -
        log_success "TLS certificates deployed"
    fi
    
    log_success "Secrets generated and deployed"
}

# Deploy monitoring stack
deploy_monitoring_stack() {
    log_info "Deploying monitoring stack infrastructure..."
    
    # Apply the main monitoring stack
    kubectl apply -f "$MONITORING_DIR/infrastructure/monitoring-stack.yaml"
    
    # Wait for deployments to be ready
    log_info "Waiting for deployments to be ready..."
    
    kubectl wait --for=condition=available --timeout=300s deployment/prometheus -n "$NAMESPACE"
    kubectl wait --for=condition=available --timeout=300s deployment/alertmanager -n "$NAMESPACE"
    kubectl wait --for=condition=available --timeout=300s deployment/grafana -n "$NAMESPACE"
    
    log_success "Monitoring stack deployed and ready"
}

# Configure service monitors
configure_service_monitors() {
    log_info "Configuring service monitors..."
    
    # Apply service monitors for applications
    cat <<EOF | kubectl apply -f -
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: auth-service-monitor
  namespace: $NAMESPACE
  labels:
    app: auth-service
spec:
  selector:
    matchLabels:
      app: auth-service
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
    honorLabels: true
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: policy-service-monitor
  namespace: $NAMESPACE
  labels:
    app: policy-service
spec:
  selector:
    matchLabels:
      app: policy-service
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
    honorLabels: true
EOF
    
    log_success "Service monitors configured"
}

# Validate deployment
validate_deployment() {
    log_info "Validating monitoring deployment..."
    
    local validation_errors=0
    
    # Check pod status
    log_info "Checking pod status..."
    local pods
    pods=$(kubectl get pods -n "$NAMESPACE" --no-headers)
    
    while IFS= read -r line; do
        local pod_name
        local status
        pod_name=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | awk '{print $3}')
        
        if [[ "$status" != "Running" ]]; then
            log_error "Pod $pod_name is not running (status: $status)"
            ((validation_errors++))
        fi
    done <<< "$pods"
    
    # Check service endpoints
    log_info "Checking service endpoints..."
    local services=("prometheus" "alertmanager" "grafana")
    for service in "${services[@]}"; do
        local endpoints
        endpoints=$(kubectl get endpoints "$service" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo "")
        
        if [[ -z "$endpoints" ]]; then
            log_error "Service $service has no endpoints"
            ((validation_errors++))
        else
            log_success "Service $service has endpoints: $endpoints"
        fi
    done
    
    # Test Prometheus targets
    log_info "Checking Prometheus targets..."
    if command -v curl &> /dev/null; then
        local prometheus_port
        prometheus_port=$(kubectl get svc prometheus -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].port}')
        
        # Port forward to check targets (run in background)
        kubectl port-forward svc/prometheus "$prometheus_port:$prometheus_port" -n "$NAMESPACE" &
        local port_forward_pid=$!
        
        sleep 5
        
        local targets_response
        if targets_response=$(curl -s "http://localhost:$prometheus_port/api/v1/targets" 2>/dev/null); then
            local active_targets
            active_targets=$(echo "$targets_response" | jq -r '.data.activeTargets | length' 2>/dev/null || echo "0")
            log_info "Prometheus has $active_targets active targets"
        else
            log_warning "Could not check Prometheus targets"
        fi
        
        # Clean up port forward
        kill $port_forward_pid 2>/dev/null || true
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Deployment validation passed"
        return 0
    else
        log_error "Deployment validation failed with $validation_errors errors"
        return 1
    fi
}

# Get access information
get_access_info() {
    log_info "Getting access information..."
    
    echo ""
    echo "=== Monitoring Stack Access Information ==="
    echo ""
    
    # Grafana access
    local grafana_service_type
    grafana_service_type=$(kubectl get svc grafana -n "$NAMESPACE" -o jsonpath='{.spec.type}')
    
    if [[ "$grafana_service_type" == "LoadBalancer" ]]; then
        local grafana_ip
        grafana_ip=$(kubectl get svc grafana -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        if [[ -n "$grafana_ip" ]]; then
            echo "Grafana URL: http://$grafana_ip:3000"
        else
            echo "Grafana LoadBalancer IP is pending..."
        fi
    else
        echo "Grafana: kubectl port-forward svc/grafana 3000:3000 -n $NAMESPACE"
    fi
    
    # Prometheus access
    echo "Prometheus: kubectl port-forward svc/prometheus 9090:9090 -n $NAMESPACE"
    
    # Alertmanager access
    echo "Alertmanager: kubectl port-forward svc/alertmanager 9093:9093 -n $NAMESPACE"
    
    echo ""
    echo "=== Credentials ==="
    echo "Grafana Admin Username: admin"
    echo "Grafana Admin Password: stored in /tmp/grafana-admin-password-$CLUSTER_NAME"
    echo ""
    
    # SLO Dashboard URLs
    echo "=== Important Dashboards ==="
    echo "Auth Service Dashboard: /d/auth-service"
    echo "Policy Service Dashboard: /d/policy-service"
    echo "Security Overview Dashboard: /d/security-overview"
    echo ""
}

# Cleanup function
cleanup() {
    log_info "Cleaning up temporary resources..."
    # Add any cleanup logic here
}

# Main deployment function
main() {
    log_info "Starting monitoring stack deployment..."
    log_info "Environment: $ENVIRONMENT"
    log_info "Cluster: $CLUSTER_NAME"
    log_info "Namespace: $NAMESPACE"
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Run deployment steps
    check_prerequisites
    create_namespace
    deploy_prometheus_rules
    deploy_grafana_dashboards
    generate_secrets
    deploy_monitoring_stack
    
    # Configure additional components if available
    if kubectl get crd servicemonitors.monitoring.coreos.com &> /dev/null; then
        configure_service_monitors
    else
        log_warning "ServiceMonitor CRD not found, skipping service monitor configuration"
    fi
    
    # Validate deployment
    if validate_deployment; then
        get_access_info
        log_success "Monitoring stack deployment completed successfully!"
    else
        log_error "Deployment validation failed, please check the logs"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "validate")
        validate_deployment
        ;;
    "cleanup")
        log_info "Cleaning up monitoring stack..."
        kubectl delete namespace "$NAMESPACE" --ignore-not-found
        log_success "Cleanup completed"
        ;;
    "status")
        kubectl get all -n "$NAMESPACE"
        ;;
    "logs")
        service="${2:-prometheus}"
        kubectl logs -l app="$service" -n "$NAMESPACE" --tail=100 -f
        ;;
    "help")
        echo "Usage: $0 {deploy|validate|cleanup|status|logs [service]|help}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Deploy the complete monitoring stack (default)"
        echo "  validate - Validate the current deployment"
        echo "  cleanup  - Remove the monitoring stack"
        echo "  status   - Show status of all monitoring components"
        echo "  logs     - Show logs for a service (default: prometheus)"
        echo "  help     - Show this help message"
        ;;
    *)
        log_error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac