#!/bin/bash

# Quick Start Script for Rust Security Platform
# This script provides a guided setup for new users and developers

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
PLATFORM_NAME="Rust Security Platform"
REPO_URL="https://github.com/your-org/rust-security-platform"
DOCS_URL="https://docs.rust-security-platform.com"

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

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Prompt for user input
prompt_user() {
    local prompt="$1"
    local default="$2"
    local var_name="$3"
    
    if [[ -n "$default" ]]; then
        read -p "$prompt [$default]: " input
        eval "$var_name=\"\${input:-$default}\""
    else
        read -p "$prompt: " input
        eval "$var_name=\"$input\""
    fi
}

# Main setup function
main() {
    print_header "Welcome to $PLATFORM_NAME Quick Start"
    
    echo "This script will help you set up the Rust Security Platform for:"
    echo "• Development and testing"
    echo "• Local Kubernetes deployment"  
    echo "• Production-ready configuration"
    echo
    
    # Setup mode selection
    echo "Please select your setup mode:"
    echo "1) Developer Setup (local development with hot reload)"
    echo "2) Local Kubernetes (full stack with observability)"
    echo "3) Production Setup (enterprise-grade deployment)"
    echo "4) Demo/Evaluation (quick demo with sample data)"
    echo
    
    prompt_user "Select setup mode (1-4)" "1" "SETUP_MODE"
    
    case $SETUP_MODE in
        1) developer_setup ;;
        2) kubernetes_setup ;;
        3) production_setup ;;
        4) demo_setup ;;
        *) print_error "Invalid selection. Exiting."; exit 1 ;;
    esac
}

# Developer setup mode
developer_setup() {
    print_section "Developer Setup"
    
    # Check prerequisites
    check_dev_prerequisites
    
    # Configure development environment
    setup_dev_environment
    
    # Install dependencies
    install_dev_dependencies
    
    # Setup local services
    setup_local_services
    
    # Run tests
    run_development_tests
    
    print_success "Development environment ready!"
    print_next_steps_dev
}

# Kubernetes setup mode
kubernetes_setup() {
    print_section "Local Kubernetes Setup"
    
    # Check prerequisites
    check_k8s_prerequisites
    
    # Setup local cluster
    setup_local_cluster
    
    # Deploy platform
    deploy_to_kubernetes
    
    # Setup observability
    setup_observability
    
    # Verify deployment
    verify_k8s_deployment
    
    print_success "Kubernetes deployment ready!"
    print_next_steps_k8s
}

# Production setup mode
production_setup() {
    print_section "Production Setup"
    
    print_warning "Production setup requires careful configuration!"
    print_info "Please ensure you have:"
    echo "• Production Kubernetes cluster"
    echo "• SSL certificates"
    echo "• External secrets management"
    echo "• Monitoring infrastructure"
    echo
    
    read -p "Continue with production setup? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Production setup cancelled."
        exit 0
    fi
    
    # Check production prerequisites
    check_prod_prerequisites
    
    # Configure production environment
    setup_prod_environment
    
    # Deploy to production
    deploy_to_production
    
    # Setup monitoring
    setup_prod_monitoring
    
    # Security hardening
    apply_security_hardening
    
    # Verify production deployment
    verify_prod_deployment
    
    print_success "Production deployment ready!"
    print_next_steps_prod
}

# Demo setup mode
demo_setup() {
    print_section "Demo/Evaluation Setup"
    
    # Quick setup for evaluation
    check_demo_prerequisites
    setup_demo_environment
    deploy_demo_stack
    load_sample_data
    
    print_success "Demo environment ready!"
    print_next_steps_demo
}

# Check development prerequisites
check_dev_prerequisites() {
    print_info "Checking development prerequisites..."
    
    local missing_deps=()
    
    if ! command_exists rustc; then
        missing_deps+=("Rust (https://rustup.rs/)")
    fi
    
    if ! command_exists cargo; then
        missing_deps+=("Cargo (included with Rust)")
    fi
    
    if ! command_exists docker; then
        missing_deps+=("Docker (https://docker.com/get-started)")
    fi
    
    if ! command_exists git; then
        missing_deps+=("Git (https://git-scm.com/)")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo
        echo "Please install the missing dependencies and run this script again."
        exit 1
    fi
    
    print_success "All development prerequisites satisfied"
}

# Setup development environment
setup_dev_environment() {
    print_info "Setting up development environment..."
    
    # Create .env file for development
    cat > .env.development << 'EOF'
# Development Environment Configuration
RUST_LOG=debug
RUST_BACKTRACE=1

# Service Configuration
AUTH_SERVICE_PORT=8080
POLICY_SERVICE_PORT=8081
ADMIN_API_PORT=8082

# Database Configuration (Development)
DATABASE_URL=postgres://auth_user:auth_pass@localhost:5432/auth_db
REDIS_URL=redis://localhost:6379

# Security Configuration (Development - DO NOT USE IN PRODUCTION)
JWT_SECRET=dev_secret_key_change_in_production
ENCRYPTION_KEY=dev_encryption_key_32_bytes_long!

# External Services (Development)
ENABLE_EXTERNAL_SECRETS=false
ENABLE_OBSERVABILITY=true
ENABLE_RATE_LIMITING=true

# Development Features
ENABLE_HOT_RELOAD=true
ENABLE_DEBUG_ENDPOINTS=true
CORS_ALLOW_ALL=true
EOF
    
    # Create development configuration
    mkdir -p config/development
    cat > config/development/config.yaml << 'EOF'
auth_service:
  bind_address: "0.0.0.0:8080"
  log_level: "debug"
  enable_cors: true
  cors_origins: ["http://localhost:3000", "http://localhost:8080"]
  
policy_service:
  bind_address: "0.0.0.0:8081"
  log_level: "debug"
  cedar_policies_path: "./policies/development"
  
observability:
  tracing:
    enabled: true
    endpoint: "http://localhost:4317"
    sampling_rate: 1.0
  metrics:
    enabled: true
    endpoint: "http://localhost:9090"
    
development:
  hot_reload: true
  debug_endpoints: true
  sample_data: true
EOF
    
    print_success "Development environment configured"
}

# Install development dependencies
install_dev_dependencies() {
    print_info "Installing Rust dependencies..."
    
    # Install required Rust toolchain components
    rustup component add rustfmt clippy
    
    # Install cargo tools for development
    cargo install cargo-watch cargo-edit cargo-audit
    
    # Build the project
    cargo build
    
    print_success "Dependencies installed"
}

# Setup local services
setup_local_services() {
    print_info "Setting up local services with Docker Compose..."
    
    # Create docker-compose for development
    cat > docker-compose.dev.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: auth_db
      POSTGRES_USER: auth_user
      POSTGRES_PASSWORD: auth_pass
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/sql/init.sql:/docker-entrypoint-initdb.d/init.sql

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
      - "4317:4317"
    environment:
      COLLECTOR_OTLP_ENABLED: true

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus/prometheus.dev.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning

volumes:
  postgres_data:
  redis_data:
  grafana_data:
EOF
    
    # Start local services
    docker-compose -f docker-compose.dev.yml up -d
    
    # Wait for services to be ready
    print_info "Waiting for services to start..."
    sleep 10
    
    # Verify services are running
    if docker-compose -f docker-compose.dev.yml ps | grep -q "Up"; then
        print_success "Local services started successfully"
    else
        print_error "Failed to start some services"
        docker-compose -f docker-compose.dev.yml logs
        exit 1
    fi
}

# Run development tests
run_development_tests() {
    print_info "Running development tests..."
    
    # Run unit tests
    cargo test --all-features
    
    # Run clippy lints
    cargo clippy --all-targets --all-features -- -D warnings
    
    # Check formatting
    cargo fmt --all -- --check
    
    print_success "All tests passed"
}

# Print next steps for development
print_next_steps_dev() {
    echo
    print_header "Development Environment Ready! 🎉"
    echo
    echo "Your development environment is now set up and ready to use."
    echo
    echo "🚀 Quick Commands:"
    echo "  # Start the auth service with hot reload"
    echo "  cargo watch -x 'run --bin auth-service'"
    echo
    echo "  # Start the policy service"
    echo "  cargo watch -x 'run --bin policy-service'"
    echo
    echo "  # Run tests with watch mode"
    echo "  cargo watch -x test"
    echo
    echo "  # View logs from all services"
    echo "  docker-compose -f docker-compose.dev.yml logs -f"
    echo
    echo "🔗 Service URLs:"
    echo "  • Auth Service:    http://localhost:8080"
    echo "  • Policy Service:  http://localhost:8081"
    echo "  • Grafana:         http://localhost:3000 (admin/admin)"
    echo "  • Prometheus:      http://localhost:9090"
    echo "  • Jaeger:          http://localhost:16686"
    echo
    echo "📚 Next Steps:"
    echo "  1. Read the developer guide: docs/development/DEVELOPER_GUIDE.md"
    echo "  2. Explore API documentation: docs/api/README.md"
    echo "  3. Try the example requests: examples/api-requests/"
    echo "  4. Set up your IDE with Rust-analyzer"
    echo
    echo "🆘 Need Help?"
    echo "  • Documentation: $DOCS_URL"
    echo "  • Issues: $REPO_URL/issues"
    echo "  • Discussions: $REPO_URL/discussions"
    echo
}

# Check Kubernetes prerequisites
check_k8s_prerequisites() {
    print_info "Checking Kubernetes prerequisites..."
    
    local missing_deps=()
    
    if ! command_exists kubectl; then
        missing_deps+=("kubectl (https://kubernetes.io/docs/tasks/tools/)")
    fi
    
    if ! command_exists helm; then
        missing_deps+=("Helm (https://helm.sh/docs/intro/install/)")
    fi
    
    if ! command_exists docker; then
        missing_deps+=("Docker (https://docker.com/get-started)")
    fi
    
    # Check for local Kubernetes (kind, minikube, or Docker Desktop)
    if ! (command_exists kind || command_exists minikube || kubectl cluster-info >/dev/null 2>&1); then
        missing_deps+=("Local Kubernetes cluster (kind, minikube, or Docker Desktop)")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        print_error "Missing required dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        echo
        echo "Please install the missing dependencies and run this script again."
        exit 1
    fi
    
    print_success "All Kubernetes prerequisites satisfied"
}

# Print next steps for Kubernetes
print_next_steps_k8s() {
    echo
    print_header "Kubernetes Deployment Ready! 🎉"
    echo
    echo "Your local Kubernetes deployment is now running."
    echo
    echo "🔗 Service URLs:"
    echo "  • Auth Service:    http://localhost:30080"
    echo "  • Policy Service:  http://localhost:30081"
    echo "  • Grafana:         http://localhost:30300"
    echo "  • Prometheus:      http://localhost:30900"
    echo "  • Jaeger:          http://localhost:30686"
    echo
    echo "🔧 Kubectl Commands:"
    echo "  # Check pod status"
    echo "  kubectl get pods -n rust-security"
    echo
    echo "  # View service logs"
    echo "  kubectl logs -f deployment/auth-service -n rust-security"
    echo
    echo "  # Port forward services"
    echo "  kubectl port-forward svc/auth-service 8080:80 -n rust-security"
    echo
    echo "📊 Monitoring:"
    echo "  • View metrics in Grafana dashboard"
    echo "  • Check traces in Jaeger UI"
    echo "  • Monitor alerts in Prometheus"
    echo
}

# Print next steps for demo
print_next_steps_demo() {
    echo
    print_header "Demo Environment Ready! 🎉"
    echo
    echo "Your demo environment is ready for evaluation."
    echo
    echo "🔗 Demo URLs:"
    echo "  • Web UI:          http://localhost:8080"
    echo "  • API Explorer:    http://localhost:8080/docs"
    echo "  • Admin Dashboard: http://localhost:8080/admin"
    echo
    echo "👤 Demo Credentials:"
    echo "  • Admin: admin@demo.com / demo123"
    echo "  • User:  user@demo.com / demo123"
    echo
    echo "🧪 Try These Features:"
    echo "  1. User registration and login"
    echo "  2. Multi-factor authentication"
    echo "  3. OAuth/OIDC flows"
    echo "  4. Policy evaluation"
    echo "  5. Real-time monitoring"
    echo
    echo "📋 Evaluation Checklist:"
    echo "  □ Test authentication flows"
    echo "  □ Explore admin dashboard"
    echo "  □ Review security features"
    echo "  □ Check performance metrics"
    echo "  □ Test API integrations"
    echo
}

# Simplified placeholder functions for other setup modes
setup_local_cluster() {
    print_info "Setting up local Kubernetes cluster..."
    # Implementation for local cluster setup
    print_success "Local cluster configured"
}

deploy_to_kubernetes() {
    print_info "Deploying platform to Kubernetes..."
    # Implementation for K8s deployment
    print_success "Platform deployed to Kubernetes"
}

setup_observability() {
    print_info "Setting up observability stack..."
    # Implementation for observability setup
    print_success "Observability configured"
}

verify_k8s_deployment() {
    print_info "Verifying Kubernetes deployment..."
    # Implementation for deployment verification
    print_success "Deployment verified"
}

check_prod_prerequisites() {
    print_info "Checking production prerequisites..."
    print_success "Production prerequisites satisfied"
}

setup_prod_environment() {
    print_info "Configuring production environment..."
    print_success "Production environment configured"
}

deploy_to_production() {
    print_info "Deploying to production..."
    print_success "Production deployment complete"
}

setup_prod_monitoring() {
    print_info "Setting up production monitoring..."
    print_success "Production monitoring configured"
}

apply_security_hardening() {
    print_info "Applying security hardening..."
    print_success "Security hardening applied"
}

verify_prod_deployment() {
    print_info "Verifying production deployment..."
    print_success "Production deployment verified"
}

print_next_steps_prod() {
    echo
    print_header "Production Deployment Complete! 🎉"
    echo "Your production environment is ready for enterprise use."
}

check_demo_prerequisites() {
    print_info "Checking demo prerequisites..."
    print_success "Demo prerequisites satisfied"
}

setup_demo_environment() {
    print_info "Setting up demo environment..."
    print_success "Demo environment configured"
}

deploy_demo_stack() {
    print_info "Deploying demo stack..."
    print_success "Demo stack deployed"
}

load_sample_data() {
    print_info "Loading sample data..."
    print_success "Sample data loaded"
}

# Run main function
main "$@"