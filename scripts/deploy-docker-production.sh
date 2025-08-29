#!/bin/bash
# Docker Production deployment script

set -euo pipefail

log_info() {
    echo -e "\033[0;32m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[0;31m[ERROR]\033[0m $1"
}

# Check requirements
check_requirements() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required but not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is required but not installed"
        exit 1
    fi
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker-compose -f deployment/docker-compose.production.yml exec -T postgres pg_isready -U auth_service -d auth_service &>/dev/null; then
            break
        fi
        sleep 2
        ((timeout-=2))
    done
    
    if [ $timeout -le 0 ]; then
        log_error "PostgreSQL failed to become ready within timeout"
        exit 1
    fi
    
    # Run migrations using our migration script
    DB_HOST=localhost DB_PORT=5432 DB_NAME=auth_service DB_USER=auth_service \
        PGPASSWORD="$(cat ./secrets/postgres_password.txt)" \
        ./scripts/run-migrations.sh
    
    log_info "Database migrations completed"
}

# Deploy services
deploy() {
    log_info "Starting production deployment..."
    
    # Generate secrets if they don't exist
    if [[ ! -d "./secrets" ]]; then
        log_info "Generating production secrets..."
        ./scripts/generate-production-secrets.sh
    fi
    
    # Build and deploy services
    log_info "Building and starting services..."
    docker-compose -f deployment/docker-compose.production.yml up -d --build
    
    # Wait for PostgreSQL to be ready before running migrations
    log_info "Waiting for services to start..."
    sleep 30
    
    # Run database migrations
    run_migrations
    
    # Wait for all services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 30
    
    # Check health
    log_info "Checking service health..."
    docker-compose -f deployment/docker-compose.production.yml ps
    
    # Test service endpoints
    log_info "Testing service endpoints..."
    
    # Test auth service health
    if curl -f http://localhost:8080/health &>/dev/null; then
        log_info "✓ Auth service health check passed"
    else
        log_error "✗ Auth service health check failed"
    fi
    
    # Test policy service health
    if curl -f http://localhost:8081/health &>/dev/null; then
        log_info "✓ Policy service health check passed"
    else
        log_error "✗ Policy service health check failed"
    fi
    
    # Test dashboard
    if curl -f http://localhost:3000/health &>/dev/null; then
        log_info "✓ Dashboard health check passed"
    else
        log_error "✗ Dashboard health check failed"
    fi
    
    # Start monitoring services
    log_info "Starting monitoring services..."
    if ./scripts/start-monitoring.sh; then
        log_info "✓ Monitoring services started successfully"
    else
        log_error "✗ Monitoring services failed to start (continuing without monitoring)"
    fi
    
    log_info "Production deployment completed successfully!"
    log_info "Services available at:"
    log_info "  - Dashboard: http://localhost:3000"
    log_info "  - Auth API: http://localhost:8080"
    log_info "  - Policy API: http://localhost:8081"
    log_info ""
    log_info "Monitoring services:"
    log_info "  - Prometheus: http://localhost:9090"
    log_info "  - Grafana: http://localhost:3001"
    log_info "  - Alertmanager: http://localhost:9093"
    log_info ""
    log_info "Default Grafana credentials: admin / (see secrets/grafana_password.txt)"
}

main() {
    check_requirements
    deploy
}

main "$@"