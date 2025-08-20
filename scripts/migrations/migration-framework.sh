#!/bin/bash
# Migration Framework for Rust Security Platform
# Provides comprehensive migration capabilities with rollback support

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIGRATIONS_DIR="$SCRIPT_DIR/migrations"
STATE_DIR="$SCRIPT_DIR/state"
LOG_DIR="$SCRIPT_DIR/logs"
BACKUP_DIR="$SCRIPT_DIR/backups"

# Create directories if they don't exist
mkdir -p "$MIGRATIONS_DIR" "$STATE_DIR" "$LOG_DIR" "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_DIR/migration.log"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Migration state management
get_current_version() {
    local component=$1
    local state_file="$STATE_DIR/${component}_version"
    if [[ -f "$state_file" ]]; then
        cat "$state_file"
    else
        echo "0"
    fi
}

set_current_version() {
    local component=$1
    local version=$2
    echo "$version" > "$STATE_DIR/${component}_version"
    log_migration_event "$component" "$version" "version_updated"
}

get_target_version() {
    local component=$1
    local latest_migration=$(find "$MIGRATIONS_DIR/$component" -name "*.sh" 2>/dev/null | \
        grep -o '[0-9]\+' | sort -n | tail -1)
    echo "${latest_migration:-0}"
}

# Migration event logging
log_migration_event() {
    local component=$1
    local version=$2
    local event=$3
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$timestamp,$component,$version,$event" >> "$STATE_DIR/migration_history.csv"
}

# Backup functions
create_backup() {
    local component=$1
    local version=$2
    local backup_name="${component}-v${version}-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    info "Creating backup for $component version $version"
    
    case $component in
        "redis")
            mkdir -p "$backup_path"
            kubectl exec redis-master-0 -n rust-security -- redis-cli BGSAVE
            kubectl cp rust-security/redis-master-0:/data/dump.rdb "$backup_path/dump.rdb"
            kubectl exec redis-master-0 -n rust-security -- redis-cli LASTSAVE > "$backup_path/lastsave.txt"
            ;;
        "config")
            mkdir -p "$backup_path"
            kubectl get configmaps -n rust-security -o yaml > "$backup_path/configmaps.yaml"
            kubectl get secrets -n rust-security -o yaml > "$backup_path/secrets.yaml"
            ;;
        "policies")
            mkdir -p "$backup_path"
            kubectl exec -i policy-service-$(kubectl get pods -n rust-security -l app=policy-service -o jsonpath='{.items[0].metadata.name}' | cut -d'-' -f3-) -n rust-security -- tar czf - /etc/policies > "$backup_path/policies.tar.gz"
            ;;
        "database")
            mkdir -p "$backup_path"
            # For future database implementations
            warn "Database backup not implemented yet"
            ;;
    esac
    
    echo "$backup_path" > "$STATE_DIR/${component}_last_backup"
    success "Backup created at $backup_path"
    return 0
}

restore_backup() {
    local component=$1
    local backup_path=$2
    
    if [[ ! -d "$backup_path" ]]; then
        error "Backup path does not exist: $backup_path"
        return 1
    fi
    
    info "Restoring backup for $component from $backup_path"
    
    case $component in
        "redis")
            kubectl cp "$backup_path/dump.rdb" rust-security/redis-master-0:/data/dump.rdb
            kubectl exec redis-master-0 -n rust-security -- redis-cli DEBUG RESTART
            ;;
        "config")
            kubectl apply -f "$backup_path/configmaps.yaml"
            kubectl apply -f "$backup_path/secrets.yaml"
            ;;
        "policies")
            kubectl cp "$backup_path/policies.tar.gz" rust-security/policy-service-$(kubectl get pods -n rust-security -l app=policy-service -o jsonpath='{.items[0].metadata.name}' | cut -d'-' -f3-):/tmp/policies.tar.gz
            kubectl exec -i policy-service-$(kubectl get pods -n rust-security -l app=policy-service -o jsonpath='{.items[0].metadata.name}' | cut -d'-' -f3-) -n rust-security -- tar xzf /tmp/policies.tar.gz -C /
            kubectl rollout restart deployment/policy-service -n rust-security
            ;;
        "database")
            warn "Database restore not implemented yet"
            ;;
    esac
    
    success "Backup restored for $component"
    return 0
}

# Pre-migration checks
run_pre_checks() {
    local component=$1
    local version=$2
    
    info "Running pre-migration checks for $component version $version"
    
    # Check if migration file exists
    local migration_file="$MIGRATIONS_DIR/$component/${version}.sh"
    if [[ ! -f "$migration_file" ]]; then
        error "Migration file not found: $migration_file"
        return 1
    fi
    
    # Check if migration is executable
    if [[ ! -x "$migration_file" ]]; then
        error "Migration file is not executable: $migration_file"
        return 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    # Check namespace exists
    if ! kubectl get namespace rust-security >/dev/null 2>&1; then
        error "Namespace 'rust-security' does not exist"
        return 1
    fi
    
    # Component-specific checks
    case $component in
        "redis")
            if ! kubectl get pod redis-master-0 -n rust-security >/dev/null 2>&1; then
                error "Redis master pod not found"
                return 1
            fi
            ;;
        "config")
            # No specific checks needed
            ;;
        "policies")
            if ! kubectl get deployment policy-service -n rust-security >/dev/null 2>&1; then
                error "Policy service deployment not found"
                return 1
            fi
            ;;
        "database")
            # For future database implementations
            warn "Database pre-checks not implemented yet"
            ;;
    esac
    
    success "Pre-migration checks passed for $component version $version"
    return 0
}

# Post-migration validation
run_post_checks() {
    local component=$1
    local version=$2
    
    info "Running post-migration validation for $component version $version"
    
    # Component-specific validation
    case $component in
        "redis")
            # Check Redis connectivity
            if kubectl exec redis-master-0 -n rust-security -- redis-cli ping | grep -q "PONG"; then
                success "Redis is responding"
            else
                error "Redis is not responding"
                return 1
            fi
            
            # Check Redis info
            local redis_info=$(kubectl exec redis-master-0 -n rust-security -- redis-cli info server | grep redis_version)
            info "Redis info: $redis_info"
            ;;
        "config")
            # Validate configurations are applied
            if kubectl get configmaps -n rust-security >/dev/null 2>&1; then
                success "ConfigMaps are accessible"
            else
                error "ConfigMaps are not accessible"
                return 1
            fi
            ;;
        "policies")
            # Check policy service health
            if kubectl get pods -n rust-security -l app=policy-service | grep -q "Running"; then
                success "Policy service is running"
            else
                error "Policy service is not running"
                return 1
            fi
            
            # Test policy evaluation (if health endpoint exists)
            local policy_pod=$(kubectl get pods -n rust-security -l app=policy-service -o jsonpath='{.items[0].metadata.name}')
            if kubectl exec "$policy_pod" -n rust-security -- curl -f http://localhost:8080/health >/dev/null 2>&1; then
                success "Policy service health check passed"
            else
                warn "Policy service health check failed or not implemented"
            fi
            ;;
        "database")
            warn "Database post-checks not implemented yet"
            ;;
    esac
    
    success "Post-migration validation passed for $component version $version"
    return 0
}

# Execute migration
execute_migration() {
    local component=$1
    local version=$2
    local migration_file="$MIGRATIONS_DIR/$component/${version}.sh"
    
    info "Executing migration: $component version $version"
    log_migration_event "$component" "$version" "migration_started"
    
    # Set environment variables for migration script
    export MIGRATION_COMPONENT="$component"
    export MIGRATION_VERSION="$version"
    export MIGRATION_BACKUP_DIR="$BACKUP_DIR"
    export MIGRATION_LOG_DIR="$LOG_DIR"
    
    # Execute migration with timeout
    local timeout_duration=300  # 5 minutes
    if timeout "$timeout_duration" bash "$migration_file"; then
        success "Migration executed successfully: $component version $version"
        log_migration_event "$component" "$version" "migration_completed"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            error "Migration timed out after $timeout_duration seconds: $component version $version"
        else
            error "Migration failed with exit code $exit_code: $component version $version"
        fi
        log_migration_event "$component" "$version" "migration_failed"
        return $exit_code
    fi
}

# Rollback migration
rollback_migration() {
    local component=$1
    local from_version=$2
    local to_version=$3
    
    info "Rolling back $component from version $from_version to $to_version"
    log_migration_event "$component" "$from_version" "rollback_started"
    
    # Check if rollback script exists
    local rollback_file="$MIGRATIONS_DIR/$component/rollback_${from_version}_to_${to_version}.sh"
    if [[ -f "$rollback_file" && -x "$rollback_file" ]]; then
        info "Using specific rollback script: $rollback_file"
        
        # Set environment variables
        export MIGRATION_COMPONENT="$component"
        export MIGRATION_FROM_VERSION="$from_version"
        export MIGRATION_TO_VERSION="$to_version"
        export MIGRATION_BACKUP_DIR="$BACKUP_DIR"
        export MIGRATION_LOG_DIR="$LOG_DIR"
        
        if timeout 300 bash "$rollback_file"; then
            success "Rollback completed successfully"
            set_current_version "$component" "$to_version"
            log_migration_event "$component" "$to_version" "rollback_completed"
            return 0
        else
            error "Rollback script failed"
            log_migration_event "$component" "$from_version" "rollback_failed"
            return 1
        fi
    else
        # Use backup restoration
        info "No specific rollback script found, using backup restoration"
        local backup_file="$STATE_DIR/${component}_last_backup"
        if [[ -f "$backup_file" ]]; then
            local backup_path=$(cat "$backup_file")
            if restore_backup "$component" "$backup_path"; then
                set_current_version "$component" "$to_version"
                log_migration_event "$component" "$to_version" "rollback_completed"
                return 0
            else
                error "Backup restoration failed"
                log_migration_event "$component" "$from_version" "rollback_failed"
                return 1
            fi
        else
            error "No backup available for rollback"
            return 1
        fi
    fi
}

# Main migration function
migrate() {
    local component=$1
    local target_version=${2:-"latest"}
    local force=${3:-false}
    
    info "Starting migration for component: $component"
    
    # Validate component
    if [[ ! -d "$MIGRATIONS_DIR/$component" ]]; then
        error "Component directory not found: $MIGRATIONS_DIR/$component"
        return 1
    fi
    
    local current_version=$(get_current_version "$component")
    
    if [[ "$target_version" == "latest" ]]; then
        target_version=$(get_target_version "$component")
    fi
    
    info "Current version: $current_version, Target version: $target_version"
    
    # Check if migration is needed
    if [[ "$current_version" -eq "$target_version" ]]; then
        if [[ "$force" == "true" ]]; then
            info "Forcing migration even though versions are the same"
        else
            info "Already at target version $target_version, no migration needed"
            return 0
        fi
    fi
    
    # Determine migration direction
    if [[ "$current_version" -lt "$target_version" ]]; then
        # Forward migration
        for ((version=current_version+1; version<=target_version; version++)); do
            info "Migrating $component from $((version-1)) to $version"
            
            # Pre-migration checks
            if ! run_pre_checks "$component" "$version"; then
                error "Pre-migration checks failed for $component version $version"
                return 1
            fi
            
            # Create backup
            if ! create_backup "$component" "$((version-1))"; then
                error "Backup creation failed for $component version $((version-1))"
                return 1
            fi
            
            # Execute migration
            if execute_migration "$component" "$version"; then
                # Post-migration validation
                if run_post_checks "$component" "$version"; then
                    set_current_version "$component" "$version"
                    success "Successfully migrated $component to version $version"
                else
                    error "Post-migration validation failed for $component version $version"
                    warn "Attempting rollback..."
                    rollback_migration "$component" "$version" "$((version-1))"
                    return 1
                fi
            else
                error "Migration execution failed for $component version $version"
                warn "Attempting rollback..."
                rollback_migration "$component" "$version" "$((version-1))"
                return 1
            fi
        done
    else
        # Backward migration (rollback)
        for ((version=current_version; version>target_version; version--)); do
            info "Rolling back $component from $version to $((version-1))"
            
            if ! rollback_migration "$component" "$version" "$((version-1))"; then
                error "Rollback failed for $component from version $version to $((version-1))"
                return 1
            fi
        done
    fi
    
    success "Migration completed successfully for $component"
    return 0
}

# Status reporting
show_status() {
    info "Migration Status Report"
    echo "======================"
    
    for component_dir in "$MIGRATIONS_DIR"/*; do
        if [[ -d "$component_dir" ]]; then
            local component=$(basename "$component_dir")
            local current_version=$(get_current_version "$component")
            local latest_version=$(get_target_version "$component")
            
            echo "Component: $component"
            echo "  Current Version: $current_version"
            echo "  Latest Version:  $latest_version"
            echo "  Status: $([ "$current_version" -eq "$latest_version" ] && echo "Up to date" || echo "Migration available")"
            echo
        fi
    done
    
    # Show recent migration history
    if [[ -f "$STATE_DIR/migration_history.csv" ]]; then
        echo "Recent Migration History:"
        echo "========================="
        tail -10 "$STATE_DIR/migration_history.csv" | while IFS=, read -r timestamp component version event; do
            echo "$timestamp | $component | v$version | $event"
        done
    fi
}

# Validation function
validate_migrations() {
    info "Validating all migration scripts"
    local validation_failed=false
    
    for component_dir in "$MIGRATIONS_DIR"/*; do
        if [[ -d "$component_dir" ]]; then
            local component=$(basename "$component_dir")
            info "Validating migrations for component: $component"
            
            for migration_file in "$component_dir"/*.sh; do
                if [[ -f "$migration_file" ]]; then
                    local filename=$(basename "$migration_file")
                    
                    # Check if filename follows naming convention
                    if [[ ! "$filename" =~ ^[0-9]+\.sh$ ]] && [[ ! "$filename" =~ ^rollback_[0-9]+_to_[0-9]+\.sh$ ]]; then
                        error "Invalid filename format: $filename (should be NUMBER.sh or rollback_FROM_to_TO.sh)"
                        validation_failed=true
                    fi
                    
                    # Check if file is executable
                    if [[ ! -x "$migration_file" ]]; then
                        error "Migration file is not executable: $migration_file"
                        validation_failed=true
                    fi
                    
                    # Basic syntax check
                    if ! bash -n "$migration_file"; then
                        error "Syntax error in migration file: $migration_file"
                        validation_failed=true
                    fi
                    
                    success "Validated: $migration_file"
                fi
            done
        fi
    done
    
    if [[ "$validation_failed" == "true" ]]; then
        error "Migration validation failed"
        return 1
    else
        success "All migrations validated successfully"
        return 0
    fi
}

# Usage function
usage() {
    cat << EOF
Migration Framework for Rust Security Platform

Usage: $0 <command> [arguments]

Commands:
    migrate <component> [version] [force]  - Migrate component to specified version (or latest)
    rollback <component> <version>         - Rollback component to specified version
    status                                - Show current migration status
    validate                              - Validate all migration scripts
    backup <component>                    - Create backup for component
    restore <component> <backup_path>     - Restore component from backup

Components:
    redis      - Redis data and configuration
    config     - Kubernetes configurations and secrets
    policies   - Authorization policies
    database   - Database schema and data (future)

Examples:
    $0 migrate redis                      # Migrate Redis to latest version
    $0 migrate config 5                   # Migrate config to version 5
    $0 rollback policies 3                # Rollback policies to version 3
    $0 status                             # Show migration status
    $0 validate                           # Validate all migrations
    $0 backup redis                       # Create Redis backup

EOF
}

# Main script execution
main() {
    local command=${1:-""}
    
    case $command in
        "migrate")
            if [[ $# -lt 2 ]]; then
                error "Component name required for migrate command"
                usage
                exit 1
            fi
            migrate "$2" "${3:-latest}" "${4:-false}"
            ;;
        "rollback")
            if [[ $# -lt 3 ]]; then
                error "Component name and version required for rollback command"
                usage
                exit 1
            fi
            local current_version=$(get_current_version "$2")
            rollback_migration "$2" "$current_version" "$3"
            ;;
        "status")
            show_status
            ;;
        "validate")
            validate_migrations
            ;;
        "backup")
            if [[ $# -lt 2 ]]; then
                error "Component name required for backup command"
                usage
                exit 1
            fi
            local current_version=$(get_current_version "$2")
            create_backup "$2" "$current_version"
            ;;
        "restore")
            if [[ $# -lt 3 ]]; then
                error "Component name and backup path required for restore command"
                usage
                exit 1
            fi
            restore_backup "$2" "$3"
            ;;
        "help"|"-h"|"--help"|"")
            usage
            ;;
        *)
            error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi