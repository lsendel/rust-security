#!/bin/bash
# Migration Validation Script
# Tests database migrations in a temporary Docker container

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
CONTAINER_NAME="auth-migration-test-$(date +%s)"
TEST_DB_PASSWORD="test_password_$(openssl rand -hex 8)"
MIGRATIONS_DIR="$(dirname "$(realpath "$0")")/../auth-service/migrations"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up test container..."
    docker rm -f "$CONTAINER_NAME" &>/dev/null || true
}

trap cleanup EXIT

validate_migrations() {
    log_info "Starting migration validation..."
    
    # Start a temporary PostgreSQL container
    log_info "Starting test PostgreSQL container..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        -e POSTGRES_DB=auth_service \
        -e POSTGRES_USER=auth_service \
        -e POSTGRES_PASSWORD="$TEST_DB_PASSWORD" \
        -p 15432:5432 \
        postgres:15-alpine
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    for i in {1..30}; do
        if docker exec "$CONTAINER_NAME" pg_isready -U auth_service -d auth_service &>/dev/null; then
            break
        fi
        if [[ $i -eq 30 ]]; then
            log_error "PostgreSQL failed to start within 30 seconds"
            exit 1
        fi
        sleep 1
    done
    
    log_info "PostgreSQL is ready"
    
    # Run database initialization
    log_info "Testing database initialization..."
    if [[ -f "$MIGRATIONS_DIR/000_init_database.sql" ]]; then
        if ! docker exec -i "$CONTAINER_NAME" psql -U postgres -d postgres < "$MIGRATIONS_DIR/000_init_database.sql"; then
            log_error "Database initialization failed"
            exit 1
        fi
        log_info "Database initialization successful"
    else
        log_warn "No database initialization file found"
    fi
    
    # Test each migration file
    local migration_count=0
    for migration_file in "$MIGRATIONS_DIR"/*.sql; do
        [[ "$migration_file" == *"000_init_database.sql" ]] && continue
        [[ ! -f "$migration_file" ]] && continue
        
        local filename
        filename=$(basename "$migration_file")
        log_info "Testing migration: $filename"
        
        if ! docker exec -i "$CONTAINER_NAME" psql -U auth_service -d auth_service -v ON_ERROR_STOP=1 < "$migration_file"; then
            log_error "Migration failed: $filename"
            exit 1
        fi
        
        ((migration_count++))
    done
    
    # Verify schema structure
    log_info "Validating schema structure..."
    local table_count
    table_count=$(docker exec "$CONTAINER_NAME" psql -U auth_service -d auth_service -tAc \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE';")
    
    if [[ $table_count -lt 10 ]]; then
        log_error "Expected at least 10 tables, found $table_count"
        exit 1
    fi
    
    log_info "Schema validation successful ($table_count tables found)"
    
    # Test cleanup function
    log_info "Testing cleanup function..."
    local cleanup_result
    cleanup_result=$(docker exec "$CONTAINER_NAME" psql -U auth_service -d auth_service -tAc \
        "SELECT cleanup_expired_data();")
    
    log_info "Cleanup function test successful (deleted $cleanup_result records)"
    
    # Test some basic queries
    log_info "Testing basic queries..."
    
    # Test user creation
    docker exec "$CONTAINER_NAME" psql -U auth_service -d auth_service -c \
        "INSERT INTO users (user_name, email) VALUES ('test_user', 'test@example.com');" || {
        log_error "Failed to insert test user"
        exit 1
    }
    
    # Test user lookup
    local user_count
    user_count=$(docker exec "$CONTAINER_NAME" psql -U auth_service -d auth_service -tAc \
        "SELECT COUNT(*) FROM users WHERE user_name = 'test_user';")
    
    if [[ $user_count -ne 1 ]]; then
        log_error "User lookup test failed"
        exit 1
    fi
    
    log_info "Basic query tests successful"
    
    log_info "All migration validation tests passed!"
    log_info "Processed $migration_count migration files"
}

# Check prerequisites
if ! command -v docker &> /dev/null; then
    log_error "Docker is required but not installed"
    exit 1
fi

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
    log_error "Migrations directory not found: $MIGRATIONS_DIR"
    exit 1
fi

# Run validation
validate_migrations

log_info "Migration validation completed successfully!"