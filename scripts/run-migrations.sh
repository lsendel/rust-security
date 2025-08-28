#!/bin/bash
# Production Database Migration Runner
# This script runs database migrations in the correct order for production deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-auth_service}"
DB_USER="${DB_USER:-auth_service}"
DB_PASSWORD="${DB_PASSWORD:-}"
MIGRATIONS_DIR="$(dirname "$(realpath "$0")")/../auth-service/migrations"
DRY_RUN="${DRY_RUN:-false}"

# Functions
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

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run database migrations for auth-service production deployment.

Options:
    -h, --help              Show this help message
    -d, --dry-run          Show migrations that would be applied without executing them
    -i, --init-only        Only run database initialization (000_init_database.sql)
    --host HOST            Database host (default: localhost)
    --port PORT            Database port (default: 5432)
    --database DB          Database name (default: auth_service)
    --username USER        Database username (default: auth_service)
    --password PASS        Database password (default: prompt)

Environment Variables:
    DB_HOST                Database host
    DB_PORT                Database port  
    DB_NAME                Database name
    DB_USER                Database username
    DB_PASSWORD            Database password (not recommended, use prompt)
    DRY_RUN                Set to 'true' for dry run mode

Examples:
    $0                                          # Run all migrations
    $0 --dry-run                               # Show what would be migrated
    $0 --init-only                             # Only initialize database
    $0 --host prod-db --database auth_service  # Connect to production database
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -d|--dry-run)
                DRY_RUN="true"
                shift
                ;;
            -i|--init-only)
                INIT_ONLY="true"
                shift
                ;;
            --host)
                DB_HOST="$2"
                shift 2
                ;;
            --port)
                DB_PORT="$2"
                shift 2
                ;;
            --database)
                DB_NAME="$2"
                shift 2
                ;;
            --username)
                DB_USER="$2"
                shift 2
                ;;
            --password)
                DB_PASSWORD="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v psql &> /dev/null; then
        log_error "psql is required but not installed"
        exit 1
    fi
    
    if [[ ! -d "$MIGRATIONS_DIR" ]]; then
        log_error "Migrations directory not found: $MIGRATIONS_DIR"
        exit 1
    fi
    
    # Check if we can find migration files
    if [[ $(find "$MIGRATIONS_DIR" -name "*.sql" | wc -l) -eq 0 ]]; then
        log_error "No SQL migration files found in $MIGRATIONS_DIR"
        exit 1
    fi
    
    log_info "Prerequisites check passed"
}

# Prompt for database password if not provided
get_db_password() {
    if [[ -z "$DB_PASSWORD" ]]; then
        echo -n "Enter database password for $DB_USER: "
        read -s DB_PASSWORD
        echo
        export PGPASSWORD="$DB_PASSWORD"
    else
        export PGPASSWORD="$DB_PASSWORD"
    fi
}

# Test database connection
test_connection() {
    log_info "Testing database connection..."
    
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "SELECT 1;" &>/dev/null; then
        log_error "Cannot connect to database server"
        log_error "Please check your connection settings and credentials"
        exit 1
    fi
    
    log_info "Database connection successful"
}

# Get checksum of a file
get_file_checksum() {
    local file="$1"
    if command -v sha256sum &> /dev/null; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        # Fallback to file size and modification time
        stat -c "%s-%Y" "$file" 2>/dev/null || stat -f "%z-%m" "$file"
    fi
}

# Check if database exists, create if needed
ensure_database_exists() {
    log_info "Checking if database '$DB_NAME' exists..."
    
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1; then
        log_warn "Database '$DB_NAME' does not exist"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] Would create database '$DB_NAME'"
            return 0
        fi
        
        log_info "Creating database '$DB_NAME'..."
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -c "CREATE DATABASE $DB_NAME;"
        log_info "Database '$DB_NAME' created successfully"
    else
        log_info "Database '$DB_NAME' already exists"
    fi
}

# Get list of applied migrations
get_applied_migrations() {
    local migrations
    migrations=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -tAc \
        "SELECT version FROM schema_migrations ORDER BY version;" 2>/dev/null || echo "")
    echo "$migrations"
}

# Check if migration is already applied
is_migration_applied() {
    local version="$1"
    local applied_migrations="$2"
    echo "$applied_migrations" | grep -q "^$version$"
}

# Execute a migration file
execute_migration() {
    local migration_file="$1"
    local version="$2"
    local description="$3"
    local checksum="$4"
    
    log_info "Applying migration: $version - $description"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would execute: $migration_file"
        return 0
    fi
    
    # Execute the migration within a transaction
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -f "$migration_file"; then
        log_error "Migration failed: $version"
        log_error "Please check the migration file and database logs"
        exit 1
    fi
    
    # Record the migration as applied
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
        "INSERT INTO schema_migrations (version, description, checksum) 
         VALUES ('$version', '$description', '$checksum')
         ON CONFLICT (version) DO UPDATE SET 
         applied_at = NOW(), checksum = EXCLUDED.checksum, description = EXCLUDED.description;" &>/dev/null || true
    
    log_info "Migration applied successfully: $version"
}

# Run database initialization
run_init_migration() {
    local init_file="$MIGRATIONS_DIR/000_init_database.sql"
    
    if [[ ! -f "$init_file" ]]; then
        log_warn "Database initialization file not found: $init_file"
        return 0
    fi
    
    log_info "Running database initialization..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would run database initialization"
        return 0
    fi
    
    # For init migration, we might need superuser privileges
    # Run against postgres database first, then switch to target database
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U postgres -d postgres -v ON_ERROR_STOP=1 -f "$init_file" 2>/dev/null; then
        log_warn "Could not run init migration as superuser, trying with regular user..."
        if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -f "$init_file"; then
            log_error "Database initialization failed"
            exit 1
        fi
    fi
    
    log_info "Database initialization completed"
}

# Run all migrations
run_migrations() {
    log_info "Starting migration process..."
    
    # Ensure schema_migrations table exists
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            checksum VARCHAR(255),
            description TEXT
        );" &>/dev/null || true
    
    # Get list of already applied migrations
    local applied_migrations
    applied_migrations=$(get_applied_migrations)
    
    log_info "Applied migrations:"
    if [[ -n "$applied_migrations" ]]; then
        echo "$applied_migrations" | while read -r migration; do
            [[ -n "$migration" ]] && log_debug "  - $migration"
        done
    else
        log_debug "  - None"
    fi
    
    # Find and sort all migration files
    local migration_files
    migration_files=$(find "$MIGRATIONS_DIR" -name "*.sql" -not -name "000_init_database.sql" | sort)
    
    local migrations_applied=0
    
    # Process each migration file
    while IFS= read -r migration_file; do
        [[ -z "$migration_file" ]] && continue
        
        local filename
        filename=$(basename "$migration_file")
        local version="${filename%%.sql}"
        local checksum
        checksum=$(get_file_checksum "$migration_file")
        
        # Extract description from the first comment line
        local description
        description=$(head -n 10 "$migration_file" | grep -E '^-- ' | head -n 1 | sed 's/^-- //' || echo "Migration $version")
        
        if is_migration_applied "$version" "$applied_migrations"; then
            log_debug "Migration already applied: $version"
            continue
        fi
        
        execute_migration "$migration_file" "$version" "$description" "$checksum"
        ((migrations_applied++))
        
    done <<< "$migration_files"
    
    if [[ $migrations_applied -eq 0 ]]; then
        log_info "No new migrations to apply"
    else
        log_info "Applied $migrations_applied migration(s) successfully"
    fi
}

# Show migration status
show_status() {
    log_info "Migration status for database '$DB_NAME':"
    
    if ! psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
        "SELECT version, applied_at, description FROM schema_migrations ORDER BY version;" 2>/dev/null; then
        log_warn "Could not retrieve migration status (schema_migrations table might not exist)"
    fi
}

# Main execution
main() {
    log_info "Auth Service Database Migration Runner"
    log_info "====================================="
    
    parse_args "$@"
    check_prerequisites
    get_db_password
    test_connection
    ensure_database_exists
    
    # Run initialization if requested or if it's the first time
    if [[ "${INIT_ONLY:-false}" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        run_init_migration
        if [[ "${INIT_ONLY:-false}" == "true" ]]; then
            log_info "Database initialization completed"
            exit 0
        fi
    fi
    
    # Run migrations
    run_migrations
    
    # Show final status
    if [[ "$DRY_RUN" != "true" ]]; then
        echo
        show_status
    fi
    
    log_info "Migration process completed successfully!"
}

# Execute main function with all arguments
main "$@"