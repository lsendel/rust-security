#!/bin/bash
# Start monitoring stack for production deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is required but not installed"
        exit 1
    fi
    
    # Check if secrets exist
    if [[ ! -d "./secrets" ]]; then
        log_warn "Secrets directory not found. Run ./scripts/generate-production-secrets.sh first"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Validate monitoring configuration
validate_config() {
    log_info "Validating monitoring configuration..."
    
    # Check Prometheus config
    if [[ ! -f "./monitoring/prometheus/prometheus.yml" ]]; then
        log_error "Prometheus configuration not found"
        exit 1
    fi
    
    # Check Alertmanager config
    if [[ ! -f "./monitoring/alertmanager/alertmanager.yml" ]]; then
        log_error "Alertmanager configuration not found"
        exit 1
    fi
    
    # Check Grafana provisioning
    if [[ ! -d "./monitoring/grafana/provisioning" ]]; then
        log_warn "Grafana provisioning directory not found"
    fi
    
    log_info "Configuration validation passed"
}

# Start monitoring services
start_monitoring() {
    log_info "Starting monitoring stack..."
    
    # Start core services first if not running
    log_info "Ensuring core services are running..."
    docker-compose -f docker-compose.production.yml up -d postgres redis auth-service policy-service dashboard
    
    # Wait for core services to be healthy
    log_info "Waiting for core services to be healthy..."
    sleep 30
    
    # Start monitoring services
    log_info "Starting monitoring services..."
    docker-compose -f docker-compose.production.yml --profile monitoring up -d
    
    # Wait for monitoring services to start
    log_info "Waiting for monitoring services to initialize..."
    sleep 30
    
    log_info "Monitoring stack started successfully!"
}

# Check service health
check_health() {
    log_info "Checking monitoring service health..."
    
    local failed_services=()
    
    # Check Prometheus
    if curl -f http://localhost:9090/-/ready &>/dev/null; then
        log_info "✓ Prometheus is ready"
    else
        log_error "✗ Prometheus health check failed"
        failed_services+=("Prometheus")
    fi
    
    # Check Alertmanager
    if curl -f http://localhost:9093/-/ready &>/dev/null; then
        log_info "✓ Alertmanager is ready"
    else
        log_error "✗ Alertmanager health check failed"
        failed_services+=("Alertmanager")
    fi
    
    # Check Grafana
    if curl -f http://localhost:3001/api/health &>/dev/null; then
        log_info "✓ Grafana is ready"
    else
        log_error "✗ Grafana health check failed"
        failed_services+=("Grafana")
    fi
    
    # Check Node Exporter
    if curl -f http://localhost:9100/metrics &>/dev/null; then
        log_info "✓ Node Exporter is ready"
    else
        log_error "✗ Node Exporter health check failed"
        failed_services+=("Node Exporter")
    fi
    
    # Check Redis Exporter
    if curl -f http://localhost:9121/metrics &>/dev/null; then
        log_info "✓ Redis Exporter is ready"
    else
        log_error "✗ Redis Exporter health check failed"
        failed_services+=("Redis Exporter")
    fi
    
    if [ ${#failed_services[@]} -eq 0 ]; then
        log_info "All monitoring services are healthy!"
        return 0
    else
        log_error "Some monitoring services failed health checks: ${failed_services[*]}"
        return 1
    fi
}

# Show monitoring endpoints
show_endpoints() {
    log_info "Monitoring services are available at:"
    echo
    echo "📊 Core Dashboards:"
    echo "   Grafana:        http://localhost:3001"
    echo "   Prometheus:     http://localhost:9090"
    echo "   Alertmanager:   http://localhost:9093"
    echo
    echo "📈 Metrics Endpoints:"
    echo "   Node Exporter:  http://localhost:9100/metrics"
    echo "   Redis Exporter: http://localhost:9121/metrics"
    echo "   Auth Service:   http://localhost:8080/metrics"
    echo "   Policy Service: http://localhost:8081/metrics"
    echo
    echo "🔐 Default Credentials:"
    echo "   Grafana: admin / (see secrets/grafana_password.txt)"
    echo
    echo "📋 Quick Links:"
    echo "   Security Dashboard: http://localhost:3001/d/security-overview"
    echo "   Auth Service Dashboard: http://localhost:3001/d/auth-service"
    echo "   Infrastructure Dashboard: http://localhost:3001/d/infrastructure"
}

# Show logs for troubleshooting
show_logs() {
    local service="${1:-}"
    
    if [[ -z "$service" ]]; then
        log_info "Available monitoring services for log viewing:"
        echo "  - prometheus"
        echo "  - alertmanager"
        echo "  - grafana"
        echo "  - node-exporter"
        echo "  - redis-exporter"
        echo
        echo "Usage: $0 logs <service_name>"
        return 0
    fi
    
    log_info "Showing logs for $service..."
    docker-compose -f docker-compose.production.yml logs -f "$service"
}

# Stop monitoring services
stop_monitoring() {
    log_info "Stopping monitoring services..."
    docker-compose -f docker-compose.production.yml --profile monitoring stop
    log_info "Monitoring services stopped"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [COMMAND]

Commands:
    start       Start monitoring stack (default)
    stop        Stop monitoring services
    restart     Restart monitoring services
    status      Check monitoring service status
    health      Run health checks
    logs        Show logs for a specific service
    endpoints   Show available endpoints

Examples:
    $0                    # Start monitoring stack
    $0 health            # Check service health
    $0 logs prometheus   # Show Prometheus logs
    $0 stop              # Stop monitoring services
EOF
}

# Main execution
main() {
    local command="${1:-start}"
    
    case "$command" in
        "start")
            check_prerequisites
            validate_config
            start_monitoring
            sleep 10
            check_health
            show_endpoints
            ;;
        "stop")
            stop_monitoring
            ;;
        "restart")
            stop_monitoring
            sleep 5
            check_prerequisites
            validate_config
            start_monitoring
            sleep 10
            check_health
            ;;
        "status")
            docker-compose -f docker-compose.production.yml --profile monitoring ps
            ;;
        "health")
            check_health
            ;;
        "logs")
            show_logs "${2:-}"
            ;;
        "endpoints")
            show_endpoints
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"