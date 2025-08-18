#!/bin/bash
set -euo pipefail

# Deploy Monitoring Stack Script
# This script deploys the complete monitoring infrastructure

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🚀 Deploying Security Monitoring Stack..."

# Function to check if a service is healthy
check_service_health() {
    local service_name=$1
    local health_endpoint=$2
    local max_attempts=30
    local attempt=1

    echo "Checking health of $service_name..."
    
    while [ $attempt -le $max_attempts ]; do
        if curl -sf "$health_endpoint" > /dev/null 2>&1; then
            echo "✅ $service_name is healthy"
            return 0
        fi
        
        echo "⏳ Waiting for $service_name to be healthy (attempt $attempt/$max_attempts)..."
        sleep 10
        ((attempt++))
    done
    
    echo "❌ $service_name failed to become healthy"
    return 1
}

# Function to setup monitoring directories
setup_directories() {
    echo "📁 Setting up monitoring directories..."
    
    # Create necessary directories
    mkdir -p "$PROJECT_ROOT/monitoring/"{prometheus,alertmanager,grafana,filebeat,elasticsearch,kibana}
    mkdir -p "$PROJECT_ROOT/logs/"{auth-service,policy-service,security-audit}
    
    # Set proper permissions
    chmod 755 "$PROJECT_ROOT/monitoring"/*
    chmod 755 "$PROJECT_ROOT/logs"/*
    
    echo "✅ Directories created successfully"
}

# Function to validate configuration files
validate_configs() {
    echo "🔍 Validating configuration files..."
    
    # Check Prometheus config
    if [ -f "$PROJECT_ROOT/monitoring/prometheus/prometheus.yml" ]; then
        echo "✅ Prometheus config found"
    else
        echo "❌ Prometheus config missing"
        exit 1
    fi
    
    # Check Alertmanager config
    if [ -f "$PROJECT_ROOT/monitoring/alertmanager/alertmanager.yml" ]; then
        echo "✅ Alertmanager config found"
    else
        echo "❌ Alertmanager config missing"
        exit 1
    fi
    
    # Check alert rules
    local rules_count=$(find "$PROJECT_ROOT/monitoring/prometheus" -name "*-rules.yml" | wc -l)
    echo "✅ Found $rules_count alert rule files"
    
    echo "✅ Configuration validation complete"
}

# Function to deploy infrastructure
deploy_infrastructure() {
    echo "🛠️ Deploying monitoring infrastructure..."
    
    cd "$PROJECT_ROOT"
    
    # Start monitoring stack
    docker-compose -f docker-compose.monitoring.yml up -d
    
    # Wait for services to be ready
    echo "⏳ Waiting for services to start..."
    sleep 30
    
    # Check service health
    check_service_health "Prometheus" "http://localhost:9090/-/healthy"
    check_service_health "Alertmanager" "http://localhost:9093/-/healthy"
    check_service_health "Grafana" "http://localhost:3000/api/health"
    check_service_health "Elasticsearch" "http://localhost:9200/_cluster/health"
    
    echo "✅ Monitoring infrastructure deployed successfully"
}

# Function to setup Grafana
setup_grafana() {
    echo "📊 Setting up Grafana dashboards..."
    
    # Wait for Grafana to be fully ready
    sleep 60
    
    # The dashboards will be automatically provisioned via the volume mount
    echo "✅ Grafana setup complete"
}

# Function to setup index templates in Elasticsearch
setup_elasticsearch() {
    echo "🔍 Setting up Elasticsearch index templates..."
    
    # Wait for Elasticsearch to be ready
    sleep 30
    
    # Create security logs index template
    curl -X PUT "localhost:9200/_index_template/security-logs" \
        -H "Content-Type: application/json" \
        -d '{
            "index_patterns": ["security-logs-*"],
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index.mapping.total_fields.limit": 2000
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "level": {"type": "keyword"},
                        "message": {"type": "text"},
                        "security.event_type": {"type": "keyword"},
                        "security.severity": {"type": "keyword"},
                        "security.client_id": {"type": "keyword"},
                        "source.ip": {"type": "ip"},
                        "security.risk_score": {"type": "integer"},
                        "event.type": {"type": "keyword"},
                        "event.category": {"type": "keyword"},
                        "threat.indicator.type": {"type": "keyword"},
                        "threat.indicator.ip": {"type": "ip"}
                    }
                }
            }
        }' || echo "⚠️ Index template may already exist"
    
    echo "✅ Elasticsearch setup complete"
}

# Function to verify deployment
verify_deployment() {
    echo "🧪 Verifying deployment..."
    
    # Check if all containers are running
    local running_containers=$(docker-compose -f docker-compose.monitoring.yml ps --services --filter status=running | wc -l)
    local total_containers=$(docker-compose -f docker-compose.monitoring.yml config --services | wc -l)
    
    echo "Running containers: $running_containers/$total_containers"
    
    if [ "$running_containers" -eq "$total_containers" ]; then
        echo "✅ All containers are running"
    else
        echo "❌ Some containers are not running"
        docker-compose -f docker-compose.monitoring.yml ps
        return 1
    fi
    
    # Test Prometheus targets
    local prometheus_targets=$(curl -s "http://localhost:9090/api/v1/targets" | grep -o '"health":"up"' | wc -l)
    echo "Prometheus healthy targets: $prometheus_targets"
    
    # Test Grafana API
    if curl -sf "http://localhost:3000/api/health" > /dev/null; then
        echo "✅ Grafana API is responding"
    else
        echo "❌ Grafana API is not responding"
        return 1
    fi
    
    echo "✅ Deployment verification complete"
}

# Function to print access information
print_access_info() {
    echo ""
    echo "🎉 Monitoring Stack Deployed Successfully!"
    echo ""
    echo "Access URLs:"
    echo "  📊 Grafana:      http://localhost:3000 (admin/admin123)"
    echo "  📈 Prometheus:   http://localhost:9090"
    echo "  🚨 Alertmanager: http://localhost:9093"
    echo "  🔍 Kibana:       http://localhost:5601"
    echo "  📋 Elasticsearch: http://localhost:9200"
    echo "  🔗 Jaeger:       http://localhost:16686"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure notification channels in Alertmanager"
    echo "  2. Import additional Grafana dashboards"
    echo "  3. Set up log shipping from applications"
    echo "  4. Configure threat intelligence feeds"
    echo "  5. Run security validation tests"
    echo ""
}

# Main deployment workflow
main() {
    echo "Starting monitoring stack deployment..."
    
    setup_directories
    validate_configs
    deploy_infrastructure
    setup_elasticsearch
    setup_grafana
    verify_deployment
    print_access_info
    
    echo "🏁 Deployment complete!"
}

# Run main function
main "$@"
