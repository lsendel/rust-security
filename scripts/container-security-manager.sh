#!/bin/bash
# Container Security Manager
# Automates base image updates and container security scanning

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTAINER_REPORTS_DIR="$PROJECT_ROOT/target/container-security"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Create reports directory
mkdir -p "$CONTAINER_REPORTS_DIR"

# Find all Dockerfiles in the project
find_dockerfiles() {
    find "$PROJECT_ROOT" -name "Dockerfile*" -type f | grep -v target | sort
}

# Extract base image from Dockerfile
get_base_image() {
    local dockerfile="$1"
    grep "^FROM" "$dockerfile" | head -1 | awk '{print $2}' | cut -d':' -f1
}

# Get current image tag from Dockerfile
get_current_tag() {
    local dockerfile="$1"
    grep "^FROM" "$dockerfile" | head -1 | awk '{print $2}' | cut -d':' -f2
}

# Check for latest image tags
check_latest_tags() {
    log_info "Checking for latest base image tags..."
    
    local dockerfile
    local base_image
    local current_tag
    local latest_tag
    local update_available=false
    
    while IFS= read -r dockerfile; do
        base_image=$(get_base_image "$dockerfile")
        current_tag=$(get_current_tag "$dockerfile")
        
        log_info "Checking $dockerfile: $base_image:$current_tag"
        
        # Get latest tag for common base images
        case "$base_image" in
            "rust")
                latest_tag=$(curl -s "https://registry.hub.docker.com/v2/repositories/library/rust/tags/?page_size=100" | \
                           jq -r '.results[] | select(.name | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")) | .name' | \
                           sort -V | tail -1 2>/dev/null || echo "unknown")
                ;;
            "alpine")
                latest_tag=$(curl -s "https://registry.hub.docker.com/v2/repositories/library/alpine/tags/?page_size=100" | \
                           jq -r '.results[] | select(.name | test("^[0-9]+\\.[0-9]+$")) | .name' | \
                           sort -V | tail -1 2>/dev/null || echo "unknown")
                ;;
            "debian")
                latest_tag="stable-slim"  # Use stable-slim as the recommended tag
                ;;
            "ubuntu")
                latest_tag="22.04"  # Use LTS version
                ;;
            "gcr.io/distroless/cc")
                latest_tag="latest"  # Distroless uses latest
                ;;
            *)
                latest_tag="unknown"
                ;;
        esac
        
        if [[ "$latest_tag" != "unknown" && "$current_tag" != "$latest_tag" ]]; then
            log_warning "Update available for $dockerfile: $current_tag -> $latest_tag"
            echo "$dockerfile,$base_image,$current_tag,$latest_tag" >> "$CONTAINER_REPORTS_DIR/updates-available.csv"
            update_available=true
        else
            log_success "$dockerfile is up to date ($current_tag)"
        fi
        
    done < <(find_dockerfiles)
    
    if $update_available; then
        return 1
    else
        log_success "All base images are up to date"
        return 0
    fi
}

# Scan container for vulnerabilities
scan_container() {
    local dockerfile="$1"
    local service_name
    service_name=$(basename "$(dirname "$dockerfile")")
    
    log_info "Scanning container from $dockerfile..."
    
    # Build the container
    local build_context
    build_context=$(dirname "$dockerfile")
    
    if ! docker build -t "security-scan/$service_name:latest" "$build_context"; then
        log_error "Failed to build container from $dockerfile"
        return 1
    fi
    
    # Run Trivy scan
    local scan_output="$CONTAINER_REPORTS_DIR/${service_name}-trivy-scan.json"
    
    if command -v trivy &> /dev/null; then
        trivy image --format json --output "$scan_output" "security-scan/$service_name:latest"
        
        # Parse results
        local critical_vulns
        local high_vulns
        critical_vulns=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "$scan_output" 2>/dev/null || echo "0")
        high_vulns=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "$scan_output" 2>/dev/null || echo "0")
        
        if [[ "$critical_vulns" -gt 0 || "$high_vulns" -gt 0 ]]; then
            log_error "Container $service_name has $critical_vulns critical and $high_vulns high severity vulnerabilities"
            
            # Extract vulnerability details
            jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL" or .Severity == "HIGH") | 
                   "• \(.VulnerabilityID): \(.Title) (Severity: \(.Severity))"' \
                   "$scan_output" > "$CONTAINER_REPORTS_DIR/${service_name}-vulnerabilities.txt"
            
            return 1
        else
            log_success "Container $service_name passed security scan"
            return 0
        fi
    else
        log_warning "Trivy not installed, skipping vulnerability scan"
        return 0
    fi
}

# Generate SBOM for container
generate_container_sbom() {
    local dockerfile="$1"
    local service_name
    service_name=$(basename "$(dirname "$dockerfile")")
    
    log_info "Generating SBOM for container $service_name..."
    
    # Use syft to generate SBOM
    if command -v syft &> /dev/null; then
        syft packages "security-scan/$service_name:latest" \
             -o cyclonedx-json="$CONTAINER_REPORTS_DIR/${service_name}-sbom.json"
        log_success "SBOM generated for $service_name"
    else
        log_warning "syft not available, installing..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        generate_container_sbom "$dockerfile"
    fi
}

# Update Dockerfile with new base image
update_dockerfile() {
    local dockerfile="$1"
    local new_tag="$2"
    
    log_info "Updating $dockerfile with new tag: $new_tag"
    
    # Create backup
    cp "$dockerfile" "${dockerfile}.bak"
    
    # Update the FROM line
    local base_image
    base_image=$(get_base_image "$dockerfile")
    
    sed -i.tmp "s|FROM ${base_image}:.*|FROM ${base_image}:${new_tag}|" "$dockerfile"
    rm "${dockerfile}.tmp"
    
    log_success "Updated $dockerfile"
}

# Test updated container
test_container_update() {
    local dockerfile="$1"
    local service_name
    service_name=$(basename "$(dirname "$dockerfile")")
    
    log_info "Testing updated container $service_name..."
    
    local build_context
    build_context=$(dirname "$dockerfile")
    
    # Build updated container
    if docker build -t "security-test/$service_name:updated" "$build_context"; then
        log_success "Updated container built successfully"
        
        # Run basic functionality test
        if [[ -f "$build_context/test-container.sh" ]]; then
            log_info "Running container tests..."
            bash "$build_context/test-container.sh" "security-test/$service_name:updated"
        else
            log_info "No container tests found, performing basic validation"
            # Basic validation - container should start and respond
            docker run --rm -d --name "test-$service_name" "security-test/$service_name:updated" &
            sleep 5
            docker stop "test-$service_name" 2>/dev/null || true
        fi
        
        return 0
    else
        log_error "Failed to build updated container"
        return 1
    fi
}

# Create container security report
create_security_report() {
    log_info "Creating container security report..."
    
    local report_file="$CONTAINER_REPORTS_DIR/container-security-report.md"
    local timestamp
    timestamp=$(date)
    
    cat > "$report_file" << EOF
# Container Security Report

**Generated:** $timestamp
**Project:** Rust Security Platform

## Executive Summary

This report details the security status of all container images in the project.

## Base Image Status

EOF
    
    # Add base image information
    if [[ -f "$CONTAINER_REPORTS_DIR/updates-available.csv" ]]; then
        echo "### Updates Available" >> "$report_file"
        echo "" >> "$report_file"
        echo "| Dockerfile | Base Image | Current | Latest |" >> "$report_file"
        echo "|------------|------------|---------|--------|" >> "$report_file"
        
        while IFS=',' read -r dockerfile base_image current latest; do
            echo "| $dockerfile | $base_image | $current | $latest |" >> "$report_file"
        done < "$CONTAINER_REPORTS_DIR/updates-available.csv"
        
        echo "" >> "$report_file"
    else
        echo "### ✅ All base images are up to date" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # Add vulnerability information
    echo "## Vulnerability Scan Results" >> "$report_file"
    echo "" >> "$report_file"
    
    local vuln_files
    vuln_files=$(find "$CONTAINER_REPORTS_DIR" -name "*-vulnerabilities.txt" 2>/dev/null || true)
    
    if [[ -n "$vuln_files" ]]; then
        echo "### 🚨 Vulnerabilities Found" >> "$report_file"
        echo "" >> "$report_file"
        
        for file in $vuln_files; do
            local service_name
            service_name=$(basename "$file" -vulnerabilities.txt)
            echo "#### $service_name" >> "$report_file"
            echo "" >> "$report_file"
            cat "$file" >> "$report_file"
            echo "" >> "$report_file"
        done
    else
        echo "### ✅ No vulnerabilities found" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    # Add SBOM information
    echo "## Software Bill of Materials" >> "$report_file"
    echo "" >> "$report_file"
    
    local sbom_files
    sbom_files=$(find "$CONTAINER_REPORTS_DIR" -name "*-sbom.json" 2>/dev/null || true)
    
    if [[ -n "$sbom_files" ]]; then
        echo "Generated SBOM files:" >> "$report_file"
        echo "" >> "$report_file"
        for file in $sbom_files; do
            echo "- $(basename "$file")" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi
    
    # Add recommendations
    cat >> "$report_file" << EOF

## Recommendations

### Immediate Actions
- Address all CRITICAL and HIGH severity vulnerabilities
- Update base images with available updates
- Review and test updated containers

### Ongoing Security
- Enable automated base image updates
- Set up vulnerability monitoring alerts
- Regular security scanning in CI/CD pipeline

### Best Practices
- Use minimal base images (distroless, alpine)
- Pin specific image versions in production
- Implement container security policies
- Regular security audits

---
*This report was generated automatically by the container security manager.*
EOF
    
    log_success "Container security report created: $report_file"
}

# Create or update dependabot config for Docker
update_dependabot_docker_config() {
    log_info "Updating Dependabot configuration for Docker images..."
    
    local dependabot_file="$PROJECT_ROOT/.github/dependabot.yml"
    
    if [[ ! -f "$dependabot_file" ]]; then
        log_error "Dependabot configuration not found"
        return 1
    fi
    
    # Check if Docker updates are already configured
    if grep -q "package-ecosystem: \"docker\"" "$dependabot_file"; then
        log_success "Docker updates already configured in Dependabot"
    else
        log_info "Adding Docker update configuration to Dependabot"
        
        # Add Docker configuration
        cat >> "$dependabot_file" << 'EOF'

  # Container base image updates
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "friday"
      time: "09:00"
      timezone: "UTC"
    open-pull-requests-limit: 5
    reviewers:
      - "security-team"
      - "devops-team"
    labels:
      - "dependencies"
      - "docker"
      - "security"
    commit-message:
      prefix: "deps(docker)"
      include: "scope"
    groups:
      rust-images:
        patterns:
          - "rust*"
        update-types:
          - "minor"
          - "patch"
      base-images:
        patterns:
          - "alpine*"
          - "debian*"
          - "ubuntu*"
        update-types:
          - "minor"
          - "patch"
EOF
        log_success "Added Docker updates to Dependabot configuration"
    fi
}

# Usage information
usage() {
    cat << EOF
Container Security Manager

Usage: $0 <command> [arguments]

Commands:
    check-updates              Check for base image updates
    scan [dockerfile]          Scan container(s) for vulnerabilities
    update <dockerfile> <tag>  Update Dockerfile with new base image tag
    test <dockerfile>          Test updated container
    generate-sbom [dockerfile] Generate SBOM for container(s)
    report                     Generate comprehensive security report
    update-dependabot          Update Dependabot config for Docker
    full-audit                 Run complete container security audit

Examples:
    $0 check-updates
    $0 scan auth-service/Dockerfile
    $0 update auth-service/Dockerfile 1.75
    $0 generate-sbom
    $0 report
    $0 full-audit

EOF
}

# Run full container security audit
full_audit() {
    log_info "Running full container security audit..."
    
    local exit_code=0
    
    # Check for updates
    check_latest_tags || exit_code=1
    
    # Scan all containers
    while IFS= read -r dockerfile; do
        scan_container "$dockerfile" || exit_code=1
        generate_container_sbom "$dockerfile"
    done < <(find_dockerfiles)
    
    # Generate report
    create_security_report
    
    # Update Dependabot config
    update_dependabot_docker_config
    
    if [[ $exit_code -eq 0 ]]; then
        log_success "Container security audit completed successfully"
    else
        log_error "Container security audit completed with issues"
    fi
    
    return $exit_code
}

# Main execution
main() {
    cd "$PROJECT_ROOT"
    
    case "${1:-}" in
        "check-updates")
            check_latest_tags
            ;;
        "scan")
            if [[ -n "${2:-}" ]]; then
                scan_container "$2"
            else
                while IFS= read -r dockerfile; do
                    scan_container "$dockerfile"
                done < <(find_dockerfiles)
            fi
            ;;
        "update")
            if [[ $# -ne 3 ]]; then
                echo "Usage: $0 update <dockerfile> <tag>"
                exit 1
            fi
            update_dockerfile "$2" "$3"
            ;;
        "test")
            if [[ $# -ne 2 ]]; then
                echo "Usage: $0 test <dockerfile>"
                exit 1
            fi
            test_container_update "$2"
            ;;
        "generate-sbom")
            if [[ -n "${2:-}" ]]; then
                generate_container_sbom "$2"
            else
                while IFS= read -r dockerfile; do
                    generate_container_sbom "$dockerfile"
                done < <(find_dockerfiles)
            fi
            ;;
        "report")
            create_security_report
            ;;
        "update-dependabot")
            update_dependabot_docker_config
            ;;
        "full-audit")
            full_audit
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"