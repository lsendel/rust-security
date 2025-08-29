#!/bin/bash

# Phase 1: Service Mesh Deployment Script
# Deploys optimized Istio service mesh for Rust Security Platform

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="rust-security"
ISTIO_VERSION="${ISTIO_VERSION:-1.20.0}"
CLUSTER_NAME="${CLUSTER_NAME:-rust-security-cluster}"

echo -e "${BLUE}🚀 Phase 1: Service Mesh Deployment${NC}"
echo "========================================"
echo "Namespace: $NAMESPACE"
echo "Istio Version: $ISTIO_VERSION"
echo "Cluster: $CLUSTER_NAME"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}✗ kubectl not found. Please install kubectl.${NC}"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}✗ Cannot connect to Kubernetes cluster.${NC}"
        echo "Please ensure your cluster is running and kubectl is configured."
        exit 1
    fi
    
    # Check istioctl
    if ! command -v istioctl &> /dev/null; then
        echo -e "${YELLOW}⚠ istioctl not found. Installing...${NC}"
        install_istioctl
    fi
    
    echo -e "${GREEN}✓ Prerequisites checked${NC}"
}

# Function to install istioctl
install_istioctl() {
    echo -e "${YELLOW}Installing istioctl...${NC}"
    
    # Download and install istioctl
    curl -L https://istio.io/downloadIstio | ISTIO_VERSION=$ISTIO_VERSION sh -
    
    # Add to PATH
    export PATH="$PWD/istio-$ISTIO_VERSION/bin:$PATH"
    
    # Verify installation
    if istioctl version --remote=false; then
        echo -e "${GREEN}✓ istioctl installed successfully${NC}"
    else
        echo -e "${RED}✗ Failed to install istioctl${NC}"
        exit 1
    fi
}

# Function to create namespace
create_namespace() {
    echo -e "${YELLOW}Creating namespace...${NC}"
    
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    kubectl label namespace $NAMESPACE istio-injection=enabled --overwrite
    
    echo -e "${GREEN}✓ Namespace $NAMESPACE created and labeled for Istio injection${NC}"
}

# Function to install Istio
install_istio() {
    echo -e "${YELLOW}Installing Istio control plane...${NC}"
    
    # Install Istio with our optimized configuration
    kubectl apply -f k8s/service-mesh/istio-optimization.yaml
    
    # Wait for Istio to be ready
    echo "Waiting for Istio control plane to be ready..."
    kubectl wait --for=condition=Ready pods -l app=istiod -n istio-system --timeout=300s
    
    echo -e "${GREEN}✓ Istio control plane installed${NC}"
}

# Function to deploy optimized services
deploy_optimized_services() {
    echo -e "${YELLOW}Deploying optimized services...${NC}"
    
    # Deploy optimized auth service
    kubectl apply -f k8s/optimized-auth-service.yaml
    
    # Deploy policy service with optimizations
    if [[ -f "k8s/optimized-policy-service.yaml" ]]; then
        kubectl apply -f k8s/optimized-policy-service.yaml
    else
        echo -e "${YELLOW}⚠ Optimized policy service config not found, using existing${NC}"
        kubectl apply -f k8s/policy-service.yaml
    fi
    
    # Deploy Redis with optimizations
    kubectl apply -f k8s/redis.yaml
    
    echo -e "${GREEN}✓ Services deployed${NC}"
}

# Function to configure traffic policies
configure_traffic_policies() {
    echo -e "${YELLOW}Configuring traffic policies...${NC}"
    
    # Apply destination rules and virtual services from our optimization config
    # These are included in the istio-optimization.yaml file
    
    # Wait for services to be ready
    echo "Waiting for services to be ready..."
    kubectl wait --for=condition=Ready pods -l app=auth-service -n $NAMESPACE --timeout=300s
    
    echo -e "${GREEN}✓ Traffic policies configured${NC}"
}

# Function to setup monitoring
setup_monitoring() {
    echo -e "${YELLOW}Setting up monitoring...${NC}"
    
    # Install Prometheus for Istio metrics
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/prometheus.yaml
    
    # Install Grafana for visualization
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/grafana.yaml
    
    # Install Jaeger for tracing
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/jaeger.yaml
    
    # Install Kiali for service mesh visualization
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.20/samples/addons/kiali.yaml
    
    echo -e "${GREEN}✓ Monitoring stack deployed${NC}"
}

# Function to validate deployment
validate_deployment() {
    echo -e "${YELLOW}Validating deployment...${NC}"
    
    # Check Istio installation
    if istioctl analyze -n $NAMESPACE; then
        echo -e "${GREEN}✓ Istio configuration validated${NC}"
    else
        echo -e "${RED}✗ Istio configuration issues detected${NC}"
        return 1
    fi
    
    # Check pod status
    echo "Checking pod status..."
    kubectl get pods -n $NAMESPACE
    kubectl get pods -n istio-system
    
    # Check services
    echo "Checking services..."
    kubectl get svc -n $NAMESPACE
    kubectl get svc -n istio-system
    
    # Check virtual services and destination rules
    echo "Checking traffic policies..."
    kubectl get virtualservices -n $NAMESPACE
    kubectl get destinationrules -n $NAMESPACE
    
    echo -e "${GREEN}✓ Deployment validated${NC}"
}

# Function to run performance tests
run_performance_tests() {
    echo -e "${YELLOW}Running initial performance tests...${NC}"
    
    # Wait for services to be fully ready
    sleep 30
    
    # Get the ingress gateway external IP
    local ingress_ip=$(kubectl get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    
    if [[ -z "$ingress_ip" ]]; then
        ingress_ip="localhost"
        echo -e "${YELLOW}⚠ Using localhost for testing (no external IP found)${NC}"
    fi
    
    # Run basic connectivity test
    echo "Testing service connectivity..."
    if curl -s -f "http://$ingress_ip/health" > /dev/null; then
        echo -e "${GREEN}✓ Service connectivity test passed${NC}"
    else
        echo -e "${RED}✗ Service connectivity test failed${NC}"
        echo "This might be expected if services are still starting up."
    fi
    
    # Run the comprehensive performance test script
    if [[ -f "./test_service_architecture_performance.sh" ]]; then
        echo "Running comprehensive performance tests..."
        AUTH_SERVICE_URL="http://$ingress_ip" ./test_service_architecture_performance.sh
    else
        echo -e "${YELLOW}⚠ Performance test script not found${NC}"
    fi
}

# Function to display access information
display_access_info() {
    echo -e "${PURPLE}📊 Service Mesh Access Information${NC}"
    echo "=================================="
    
    # Get ingress gateway info
    local ingress_ip=$(kubectl get svc istio-ingressgateway -n istio-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
    local ingress_port=$(kubectl get svc istio-ingressgateway -n istio-system -o jsonpath='{.spec.ports[?(@.name=="http2")].port}')
    
    if [[ -n "$ingress_ip" ]]; then
        echo "🌐 External Access:"
        echo "   Auth Service: http://$ingress_ip:$ingress_port"
        echo "   Policy Service: http://$ingress_ip:$ingress_port/policy"
    fi
    
    echo ""
    echo "📈 Monitoring Dashboards:"
    echo "   Grafana: kubectl port-forward -n istio-system svc/grafana 3000:3000"
    echo "   Kiali: kubectl port-forward -n istio-system svc/kiali 20001:20001"
    echo "   Jaeger: kubectl port-forward -n istio-system svc/tracing 16686:16686"
    echo "   Prometheus: kubectl port-forward -n istio-system svc/prometheus 9090:9090"
    
    echo ""
    echo "🔍 Useful Commands:"
    echo "   View mesh status: istioctl proxy-status"
    echo "   View proxy config: istioctl proxy-config cluster <pod-name> -n $NAMESPACE"
    echo "   View metrics: kubectl top pods -n $NAMESPACE"
    echo "   View logs: kubectl logs -f deployment/auth-service-optimized -n $NAMESPACE"
    
    echo ""
    echo "🎯 Performance Targets:"
    echo "   Auth Latency P95: < 5ms (improved from 10ms)"
    echo "   Policy Eval P95: < 8ms"
    echo "   Throughput: > 2000 RPS (improved from ~500 RPS)"
    echo "   Service Mesh Overhead: < 2ms"
}

# Function to create monitoring script
create_monitoring_script() {
    cat > monitor_service_mesh.sh << 'EOF'
#!/bin/bash

# Service Mesh Monitoring Script
echo "🔍 Service Mesh Status Monitor"
echo "=============================="

echo "📊 Istio Control Plane Status:"
kubectl get pods -n istio-system

echo ""
echo "🚀 Application Pods Status:"
kubectl get pods -n rust-security

echo ""
echo "📈 Resource Usage:"
kubectl top pods -n rust-security

echo ""
echo "🌐 Service Mesh Configuration:"
istioctl proxy-status

echo ""
echo "⚡ Performance Metrics (last 5 minutes):"
kubectl exec -n istio-system deployment/prometheus -- promtool query instant \
  'histogram_quantile(0.95, sum(rate(istio_request_duration_milliseconds_bucket[5m])) by (le))'

echo ""
echo "🔄 Circuit Breaker Status:"
kubectl exec -n istio-system deployment/prometheus -- promtool query instant \
  'envoy_cluster_upstream_cx_connect_fail'

echo ""
echo "💾 Cache Hit Rate:"
kubectl exec -n istio-system deployment/prometheus -- promtool query instant \
  'rate(cache_hits_total[5m]) / (rate(cache_hits_total[5m]) + rate(cache_misses_total[5m]))'
EOF

    chmod +x monitor_service_mesh.sh
    echo -e "${GREEN}✓ Monitoring script created: monitor_service_mesh.sh${NC}"
}

# Main execution function
main() {
    echo -e "${BLUE}Starting Phase 1: Service Mesh Deployment...${NC}"
    echo ""
    
    # Execute deployment steps
    check_prerequisites
    create_namespace
    install_istio
    deploy_optimized_services
    configure_traffic_policies
    setup_monitoring
    validate_deployment
    
    echo ""
    echo -e "${GREEN}✅ Phase 1 Deployment Complete!${NC}"
    echo ""
    
    # Display access information
    display_access_info
    
    # Create monitoring script
    create_monitoring_script
    
    echo ""
    echo -e "${PURPLE}🎉 Service Mesh Successfully Deployed!${NC}"
    echo ""
    echo "Next Steps:"
    echo "1. Monitor service performance with: ./monitor_service_mesh.sh"
    echo "2. Run performance tests: ./test_service_architecture_performance.sh"
    echo "3. Access monitoring dashboards using the port-forward commands above"
    echo "4. Proceed to Phase 2: Communication Optimization when ready"
    echo ""
    echo "Expected Performance Improvements:"
    echo "• 50% reduction in authentication latency (10ms → 5ms)"
    echo "• 4x increase in throughput (500 → 2000+ RPS)"
    echo "• Advanced circuit breaking and fault tolerance"
    echo "• Comprehensive observability and monitoring"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "validate")
        validate_deployment
        ;;
    "monitor")
        if [[ -f "monitor_service_mesh.sh" ]]; then
            ./monitor_service_mesh.sh
        else
            echo -e "${RED}Monitoring script not found. Run deployment first.${NC}"
        fi
        ;;
    "cleanup")
        echo -e "${YELLOW}Cleaning up service mesh...${NC}"
        kubectl delete -f k8s/service-mesh/istio-optimization.yaml || true
        kubectl delete -f k8s/optimized-auth-service.yaml || true
        istioctl uninstall --purge -y || true
        kubectl delete namespace istio-system || true
        echo -e "${GREEN}✓ Cleanup complete${NC}"
        ;;
    *)
        echo "Usage: $0 [deploy|validate|monitor|cleanup]"
        echo "  deploy   - Deploy the service mesh (default)"
        echo "  validate - Validate existing deployment"
        echo "  monitor  - Show service mesh status"
        echo "  cleanup  - Remove service mesh"
        exit 1
        ;;
esac
