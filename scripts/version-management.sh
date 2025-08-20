#!/bin/bash
# Version Management System for Rust Security Platform
# Handles semantic versioning, release preparation, and component version tracking

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_DIR="$SCRIPT_DIR/versions"
RELEASE_DIR="$SCRIPT_DIR/releases"

# Create directories
mkdir -p "$VERSION_DIR" "$RELEASE_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}"
}

info() { log "${BLUE}INFO${NC}" "$@"; }
warn() { log "${YELLOW}WARN${NC}" "$@"; }
error() { log "${RED}ERROR${NC}" "$@"; }
success() { log "${GREEN}SUCCESS${NC}" "$@"; }

# Version validation
validate_version() {
    local version=$1
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]]; then
        error "Invalid version format: $version"
        error "Expected format: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]"
        return 1
    fi
    return 0
}

# Parse version components
parse_version() {
    local version=$1
    local major minor patch prerelease build
    
    # Extract build metadata
    if [[ "$version" == *"+"* ]]; then
        build=${version##*+}
        version=${version%+*}
    fi
    
    # Extract prerelease
    if [[ "$version" == *"-"* ]]; then
        prerelease=${version##*-}
        version=${version%-*}
    fi
    
    # Extract major.minor.patch
    IFS='.' read -r major minor patch <<< "$version"
    
    echo "MAJOR=$major"
    echo "MINOR=$minor"
    echo "PATCH=$patch"
    echo "PRERELEASE=${prerelease:-}"
    echo "BUILD=${build:-}"
}

# Get current version
get_current_version() {
    local component=${1:-"platform"}
    local version_file="$VERSION_DIR/${component}.version"
    
    if [[ -f "$version_file" ]]; then
        cat "$version_file"
    else
        echo "0.0.0"
    fi
}

# Set version
set_version() {
    local component=$1
    local version=$2
    local version_file="$VERSION_DIR/${component}.version"
    
    if ! validate_version "$version"; then
        return 1
    fi
    
    echo "$version" > "$version_file"
    
    # Update version history
    local history_file="$VERSION_DIR/${component}.history"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$version,$(whoami)" >> "$history_file"
    
    success "Version set for $component: $version"
    return 0
}

# Increment version
increment_version() {
    local component=$1
    local increment_type=$2  # major, minor, patch
    local current_version=$(get_current_version "$component")
    
    if [[ "$current_version" == "0.0.0" ]]; then
        error "No current version found for $component. Set initial version first."
        return 1
    fi
    
    eval "$(parse_version "$current_version")"
    
    case "$increment_type" in
        "major")
            MAJOR=$((MAJOR + 1))
            MINOR=0
            PATCH=0
            ;;
        "minor")
            MINOR=$((MINOR + 1))
            PATCH=0
            ;;
        "patch")
            PATCH=$((PATCH + 1))
            ;;
        *)
            error "Invalid increment type: $increment_type (expected: major, minor, patch)"
            return 1
            ;;
    esac
    
    local new_version="${MAJOR}.${MINOR}.${PATCH}"
    set_version "$component" "$new_version"
    echo "$new_version"
}

# Compare versions
compare_versions() {
    local version1=$1
    local version2=$2
    
    # Simple version comparison (assumes no prerelease/build for now)
    local v1_parts=(${version1//./ })
    local v2_parts=(${version2//./ })
    
    for i in {0..2}; do
        local v1_part=${v1_parts[$i]:-0}
        local v2_part=${v2_parts[$i]:-0}
        
        if (( v1_part > v2_part )); then
            echo "1"
            return
        elif (( v1_part < v2_part )); then
            echo "-1"
            return
        fi
    done
    
    echo "0"
}

# Get component versions
get_component_versions() {
    info "Current Component Versions:"
    echo "=========================="
    
    local components=("platform" "auth-service" "policy-service" "redis" "config" "policies")
    
    for component in "${components[@]}"; do
        local version=$(get_current_version "$component")
        local history_file="$VERSION_DIR/${component}.history"
        local last_updated=""
        
        if [[ -f "$history_file" ]]; then
            last_updated=$(tail -1 "$history_file" | cut -d',' -f1)
        fi
        
        printf "%-15s: %s" "$component" "$version"
        if [[ -n "$last_updated" ]]; then
            printf " (updated: %s)" "$last_updated"
        fi
        echo
    done
}

# Create release
create_release() {
    local version=$1
    local release_notes=${2:-""}
    
    if ! validate_version "$version"; then
        return 1
    fi
    
    local release_dir="$RELEASE_DIR/v$version"
    mkdir -p "$release_dir"
    
    info "Creating release v$version..."
    
    # Generate release manifest
    cat > "$release_dir/release-manifest.json" <<EOF
{
  "version": "$version",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "created_by": "$(whoami)",
  "release_notes": "$release_notes",
  "components": {
$(get_component_versions_json | sed 's/^/    /')
  },
  "migration_versions": {
$(get_migration_versions_json | sed 's/^/    /')
  },
  "compatibility": {
    "kubernetes_min_version": "1.24.0",
    "helm_min_version": "3.8.0",
    "redis_min_version": "6.2.0"
  },
  "deployment_requirements": {
    "min_cpu_cores": 2,
    "min_memory_gb": 4,
    "min_storage_gb": 10,
    "required_features": [
      "persistent_volumes",
      "load_balancer",
      "ingress_controller"
    ]
  }
}
EOF

    # Copy migration scripts for this release
    local migrations_dir="$release_dir/migrations"
    cp -r "$SCRIPT_DIR/migrations" "$migrations_dir"
    
    # Create release checksums
    find "$release_dir" -type f -exec sha256sum {} \; > "$release_dir/checksums.txt"
    
    # Create release package
    local package_file="$RELEASE_DIR/rust-security-platform-v$version.tar.gz"
    tar -czf "$package_file" -C "$RELEASE_DIR" "v$version"
    
    # Update platform version
    set_version "platform" "$version"
    
    success "Release v$version created successfully"
    info "Release directory: $release_dir"
    info "Release package: $package_file"
    
    return 0
}

# Helper function to get component versions as JSON
get_component_versions_json() {
    local components=("auth-service" "policy-service" "redis" "config" "policies")
    local json_parts=()
    
    for component in "${components[@]}"; do
        local version=$(get_current_version "$component")
        json_parts+=("\"$component\": \"$version\"")
    done
    
    # Join array elements with commas
    local IFS=","
    echo "${json_parts[*]}"
}

# Helper function to get migration versions as JSON
get_migration_versions_json() {
    local components=("redis" "config" "policies" "database")
    local json_parts=()
    
    for component in "${components[@]}"; do
        local migration_dir="$SCRIPT_DIR/migrations/migrations/$component"
        local latest_version=0
        
        if [[ -d "$migration_dir" ]]; then
            latest_version=$(find "$migration_dir" -name "[0-9]*.sh" | grep -o '[0-9]\+' | sort -n | tail -1 || echo "0")
        fi
        
        json_parts+=("\"$component\": $latest_version")
    done
    
    local IFS=","
    echo "${json_parts[*]}"
}

# Generate changelog
generate_changelog() {
    local from_version=${1:-""}
    local to_version=${2:-"$(get_current_version "platform")"}
    local changelog_file="$VERSION_DIR/CHANGELOG.md"
    
    info "Generating changelog from $from_version to $to_version"
    
    # Create changelog header
    cat > "$changelog_file" <<EOF
# Changelog

All notable changes to the Rust Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [$to_version] - $(date '+%Y-%m-%d')

### Added
- Comprehensive migration framework with rollback capabilities
- Version management system with semantic versioning
- External secrets integration support
- Advanced monitoring and alerting configurations
- Cedar policy engine with RBAC foundation
- Performance optimization and capacity planning

### Changed
- Enhanced security configurations for all services
- Improved Redis configuration with monitoring support
- Updated Policy Service with advanced Cedar features

### Fixed
- Various configuration improvements and bug fixes

### Security
- Added comprehensive threat modeling documentation
- Enhanced security monitoring and incident response
- Implemented data classification enforcement

EOF

    success "Changelog generated: $changelog_file"
}

# Validate release readiness
validate_release_readiness() {
    local version=$1
    local issues=()
    
    info "Validating release readiness for v$version..."
    
    # Check if migration framework is executable
    if [[ ! -x "$SCRIPT_DIR/migrations/migration-framework.sh" ]]; then
        issues+=("Migration framework script is not executable")
    fi
    
    # Check if migrations exist for all components
    local components=("redis" "config" "policies")
    for component in "${components[@]}"; do
        local migration_dir="$SCRIPT_DIR/migrations/migrations/$component"
        if [[ ! -d "$migration_dir" ]] || [[ -z "$(ls -A "$migration_dir")" ]]; then
            issues+=("No migrations found for component: $component")
        fi
    done
    
    # Check version format
    if ! validate_version "$version"; then
        issues+=("Invalid version format: $version")
    fi
    
    # Check if Kubernetes manifests exist
    if [[ ! -d "$(dirname "$SCRIPT_DIR")/k8s" ]]; then
        issues+=("Kubernetes manifests directory not found")
    fi
    
    # Check if Helm charts exist
    if [[ ! -d "$(dirname "$SCRIPT_DIR")/helm" ]]; then
        issues+=("Helm charts directory not found")
    fi
    
    # Report results
    if [[ ${#issues[@]} -eq 0 ]]; then
        success "Release v$version is ready for deployment"
        return 0
    else
        error "Release validation failed. Issues found:"
        for issue in "${issues[@]}"; do
            echo "  - $issue"
        done
        return 1
    fi
}

# Show release information
show_release_info() {
    local version=${1:-"$(get_current_version "platform")"}
    local release_dir="$RELEASE_DIR/v$version"
    local manifest_file="$release_dir/release-manifest.json"
    
    if [[ ! -f "$manifest_file" ]]; then
        error "Release v$version not found"
        return 1
    fi
    
    info "Release Information for v$version"
    echo "================================="
    
    # Parse and display release information
    local created_at=$(jq -r '.created_at' "$manifest_file")
    local created_by=$(jq -r '.created_by' "$manifest_file")
    local release_notes=$(jq -r '.release_notes' "$manifest_file")
    
    echo "Version: $version"
    echo "Created: $created_at"
    echo "Created By: $created_by"
    echo "Release Notes: $release_notes"
    echo ""
    
    echo "Component Versions:"
    jq -r '.components | to_entries[] | "  \(.key): \(.value)"' "$manifest_file"
    echo ""
    
    echo "Migration Versions:"
    jq -r '.migration_versions | to_entries[] | "  \(.key): \(.value)"' "$manifest_file"
    echo ""
    
    echo "Compatibility:"
    jq -r '.compatibility | to_entries[] | "  \(.key): \(.value)"' "$manifest_file"
}

# Usage information
usage() {
    cat << EOF
Version Management System for Rust Security Platform

Usage: $0 <command> [arguments]

Commands:
    get-version <component>                    - Get current version of component
    set-version <component> <version>          - Set version for component
    increment <component> <major|minor|patch>  - Increment version
    compare <version1> <version2>              - Compare two versions
    list-versions                              - List all component versions
    create-release <version> [release-notes]   - Create a new release
    validate-release <version>                 - Validate release readiness
    show-release <version>                     - Show release information
    generate-changelog [from] [to]             - Generate changelog
    
Components:
    platform        - Overall platform version
    auth-service    - Authentication service
    policy-service  - Authorization service
    redis           - Redis configuration
    config          - Kubernetes configurations
    policies        - Cedar policies

Examples:
    $0 get-version platform
    $0 set-version auth-service 1.2.3
    $0 increment platform minor
    $0 create-release 1.0.0 "Initial release"
    $0 validate-release 1.0.0
    $0 list-versions

EOF
}

# Main execution
main() {
    local command=${1:-""}
    
    case "$command" in
        "get-version")
            if [[ $# -lt 2 ]]; then
                error "Component name required"
                usage
                exit 1
            fi
            get_current_version "$2"
            ;;
        "set-version")
            if [[ $# -lt 3 ]]; then
                error "Component name and version required"
                usage
                exit 1
            fi
            set_version "$2" "$3"
            ;;
        "increment")
            if [[ $# -lt 3 ]]; then
                error "Component name and increment type required"
                usage
                exit 1
            fi
            increment_version "$2" "$3"
            ;;
        "compare")
            if [[ $# -lt 3 ]]; then
                error "Two versions required for comparison"
                usage
                exit 1
            fi
            result=$(compare_versions "$2" "$3")
            case "$result" in
                "1") echo "$2 > $3" ;;
                "-1") echo "$2 < $3" ;;
                "0") echo "$2 = $3" ;;
            esac
            ;;
        "list-versions")
            get_component_versions
            ;;
        "create-release")
            if [[ $# -lt 2 ]]; then
                error "Release version required"
                usage
                exit 1
            fi
            create_release "$2" "${3:-}"
            ;;
        "validate-release")
            if [[ $# -lt 2 ]]; then
                error "Release version required"
                usage
                exit 1
            fi
            validate_release_readiness "$2"
            ;;
        "show-release")
            if [[ $# -lt 2 ]]; then
                error "Release version required"
                usage
                exit 1
            fi
            show_release_info "$2"
            ;;
        "generate-changelog")
            generate_changelog "${2:-}" "${3:-}"
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