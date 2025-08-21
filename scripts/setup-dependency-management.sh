#!/bin/bash
# Setup script for the automated dependency management system
# This script initializes all components and installs required tools

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

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

# Print banner
print_banner() {
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  🔒 Rust Security Platform - Dependency Management Setup     ║
║                                                               ║
║  This script will set up comprehensive dependency            ║
║  management and security auditing capabilities.              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

EOF
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    local missing_tools=()
    
    # Required tools
    local required_tools=("cargo" "git" "curl" "jq")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Please install the missing tools and run this script again."
        exit 1
    fi
    
    # Check Rust version
    local rust_version
    rust_version=$(rustc --version | cut -d' ' -f2)
    log_info "Rust version: $rust_version"
    
    # Check if we're in a Git repository
    if ! git rev-parse --git-dir &> /dev/null; then
        log_error "This script must be run from within a Git repository"
        exit 1
    fi
    
    log_success "System requirements check passed"
}

# Install security tools
install_security_tools() {
    log_info "Installing security tools..."
    
    local tools=(
        "cargo-audit"
        "cargo-deny"
        "cargo-cyclonedx"
        "cargo-license"
        "cargo-outdated"
    )
    
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_info "$tool is already installed"
        else
            log_info "Installing $tool..."
            if cargo install "$tool" --locked; then
                log_success "Installed $tool"
            else
                log_warning "Failed to install $tool, continuing..."
            fi
        fi
    done
    
    # Install syft for SBOM generation
    if command -v syft &> /dev/null; then
        log_info "syft is already installed"
    else
        log_info "Installing syft..."
        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin || {
            log_warning "Failed to install syft globally, trying local install..."
            curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin" || {
                log_warning "Failed to install syft, SBOM generation may not work"
            }
        }
    fi
    
    # Install trivy for container scanning
    if command -v trivy &> /dev/null; then
        log_info "trivy is already installed"
    else
        log_info "Installing trivy..."
        curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || {
            log_warning "Failed to install trivy globally, trying local install..."
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$HOME/.local/bin" || {
                log_warning "Failed to install trivy, container scanning may not work"
            }
        }
    fi
    
    log_success "Security tools installation completed"
}

# Make scripts executable
setup_scripts() {
    log_info "Setting up scripts..."
    
    local scripts=(
        "security-audit.sh"
        "dependency-risk-manager.sh"
        "container-security-manager.sh"
        "vulnerability-alerting.sh"
        "setup-dependency-management.sh"
    )
    
    for script in "${scripts[@]}"; do
        local script_path="$SCRIPT_DIR/$script"
        if [[ -f "$script_path" ]]; then
            chmod +x "$script_path"
            log_success "Made $script executable"
        else
            log_warning "Script not found: $script"
        fi
    done
}

# Initialize configurations
initialize_configs() {
    log_info "Initializing configurations..."
    
    # Initialize dependency risk manager
    if "$SCRIPT_DIR/dependency-risk-manager.sh" init; then
        log_success "Dependency risk manager initialized"
    else
        log_warning "Failed to initialize dependency risk manager"
    fi
    
    # Initialize vulnerability alerting
    if "$SCRIPT_DIR/vulnerability-alerting.sh" init; then
        log_success "Vulnerability alerting initialized"
    else
        log_warning "Failed to initialize vulnerability alerting"
    fi
    
    # Create reports directories
    mkdir -p "$PROJECT_ROOT/target/security-reports"
    mkdir -p "$PROJECT_ROOT/target/container-security"
    mkdir -p "$PROJECT_ROOT/target/vulnerability-alerts"
    mkdir -p "$PROJECT_ROOT/target/risk-assessments"
    
    log_success "Report directories created"
}

# Validate configurations
validate_configs() {
    log_info "Validating configurations..."
    
    local config_files=(
        "$PROJECT_ROOT/.github/dependabot.yml"
        "$PROJECT_ROOT/renovate.json"
        "$PROJECT_ROOT/deny.toml"
    )
    
    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            log_success "Found: $(basename "$config_file")"
            
            # Basic validation
            case "$config_file" in
                *.yml|*.yaml)
                    if command -v python3 &> /dev/null; then
                        python3 -c "import yaml; yaml.safe_load(open('$config_file'))" 2>/dev/null && \
                            log_success "Valid YAML: $(basename "$config_file")" || \
                            log_warning "Invalid YAML: $(basename "$config_file")"
                    fi
                    ;;
                *.json)
                    if jq empty "$config_file" 2>/dev/null; then
                        log_success "Valid JSON: $(basename "$config_file")"
                    else
                        log_warning "Invalid JSON: $(basename "$config_file")"
                    fi
                    ;;
                *.toml)
                    if command -v python3 &> /dev/null; then
                        python3 -c "import toml; toml.load('$config_file')" 2>/dev/null && \
                            log_success "Valid TOML: $(basename "$config_file")" || \
                            log_warning "Invalid TOML: $(basename "$config_file")"
                    fi
                    ;;
            esac
        else
            log_warning "Missing configuration: $(basename "$config_file")"
        fi
    done
}

# Run initial security scan
run_initial_scan() {
    log_info "Running initial security scan..."
    
    if "$SCRIPT_DIR/security-audit.sh"; then
        log_success "Initial security scan completed successfully"
    else
        log_warning "Initial security scan found issues - see reports for details"
    fi
}

# Setup GitHub workflows
setup_workflows() {
    log_info "Validating GitHub workflows..."
    
    local workflow_file="$PROJECT_ROOT/.github/workflows/dependency-security-workflow.yml"
    
    if [[ -f "$workflow_file" ]]; then
        log_success "Dependency security workflow is configured"
        
        # Check if workflow is valid YAML
        if command -v python3 &> /dev/null; then
            python3 -c "import yaml; yaml.safe_load(open('$workflow_file'))" 2>/dev/null && \
                log_success "Workflow YAML is valid" || \
                log_warning "Workflow YAML may have issues"
        fi
    else
        log_warning "Dependency security workflow not found"
    fi
    
    # Check for other important workflows
    local important_workflows=(
        "security-audit.yml"
        "ci.yml"
    )
    
    for workflow in "${important_workflows[@]}"; do
        if [[ -f "$PROJECT_ROOT/.github/workflows/$workflow" ]]; then
            log_success "Found workflow: $workflow"
        else
            log_info "Optional workflow not found: $workflow"
        fi
    done
}

# Create quick reference
create_quick_reference() {
    log_info "Creating quick reference guide..."
    
    cat > "$PROJECT_ROOT/DEPENDENCY_MANAGEMENT_QUICKSTART.md" << 'EOF'
# Dependency Management Quick Reference

## Daily Operations

```bash
# Run security audit
./scripts/security-audit.sh

# Check for vulnerabilities
./scripts/vulnerability-alerting.sh check

# Check container security
./scripts/container-security-manager.sh scan
```

## Exception Management

```bash
# Add vulnerability exception
./scripts/dependency-risk-manager.sh add-vuln \
    RUSTSEC-2023-0001 \
    crate-name \
    "Justification" \
    "Mitigation" \
    approver

# Check expired exceptions
./scripts/dependency-risk-manager.sh check-expired

# Generate risk assessment
./scripts/dependency-risk-manager.sh assess crate-name
```

## Container Management

```bash
# Check for base image updates
./scripts/container-security-manager.sh check-updates

# Update Dockerfile
./scripts/container-security-manager.sh update path/to/Dockerfile new-tag

# Generate container SBOM
./scripts/container-security-manager.sh generate-sbom
```

## Monitoring

```bash
# Start vulnerability monitoring
./scripts/vulnerability-alerting.sh monitor

# Generate reports
./scripts/security-audit.sh
./scripts/container-security-manager.sh report
```

## Configuration Files

- `.github/dependabot.yml` - Dependabot configuration
- `renovate.json` - Renovate configuration
- `deny.toml` - Cargo deny policies
- `.security/dependency-exceptions.toml` - Security exceptions
- `.security/alerting-config.toml` - Alert configuration

## GitHub Workflows

- Dependency Security Workflow: Comprehensive security pipeline
- Auto-merge criteria: Automated approval for low-risk updates
- Alerting integration: GitHub issues and notifications

## Environment Variables

```bash
export GITHUB_TOKEN="your_token"        # For GitHub API access
export SLACK_WEBHOOK_URL="webhook_url"  # For Slack notifications
```

## Support

- Documentation: `docs/DEPENDENCY_MANAGEMENT.md`
- Issues: GitHub repository issues
- Security: Contact security team for urgent matters
EOF
    
    log_success "Quick reference created: DEPENDENCY_MANAGEMENT_QUICKSTART.md"
}

# Print completion summary
print_completion_summary() {
    log_success "Setup completed successfully!"
    
    cat << EOF

╔═══════════════════════════════════════════════════════════════╗
║                    🎉 Setup Complete!                        ║
╚═══════════════════════════════════════════════════════════════╝

Your automated dependency management system is now ready!

📋 What was set up:
   ✅ Security tools installed
   ✅ Scripts made executable
   ✅ Configurations initialized
   ✅ Initial security scan completed
   ✅ Quick reference guide created

🚀 Next steps:
   1. Review the initial security scan results
   2. Configure GitHub tokens for alerts (optional)
   3. Customize alerting configuration
   4. Set up Slack webhooks (optional)
   5. Review and adjust dependency policies

📖 Documentation:
   - Quick Start: DEPENDENCY_MANAGEMENT_QUICKSTART.md
   - Full Guide: docs/DEPENDENCY_MANAGEMENT.md
   - Security Reports: target/security-reports/

🔧 Daily commands:
   - Security audit: ./scripts/security-audit.sh
   - Check vulnerabilities: ./scripts/vulnerability-alerting.sh check
   - Container scan: ./scripts/container-security-manager.sh scan

⚠️  Important:
   - Review any issues found in the initial scan
   - Set up environment variables for integrations
   - Test the alerting system before production use

Happy secure coding! 🔒
EOF
}

# Main execution
main() {
    cd "$PROJECT_ROOT"
    
    print_banner
    
    log_info "Starting dependency management system setup..."
    log_info "Project root: $PROJECT_ROOT"
    
    # Run setup steps
    check_requirements
    install_security_tools
    setup_scripts
    initialize_configs
    validate_configs
    setup_workflows
    run_initial_scan
    create_quick_reference
    
    print_completion_summary
}

# Handle script arguments
case "${1:-setup}" in
    "setup"|"")
        main
        ;;
    "tools")
        install_security_tools
        ;;
    "configs")
        initialize_configs
        validate_configs
        ;;
    "scan")
        run_initial_scan
        ;;
    "help"|"-h"|"--help")
        cat << EOF
Dependency Management Setup Script

Usage: $0 [command]

Commands:
    setup (default)  - Run complete setup process
    tools           - Install security tools only
    configs         - Initialize and validate configurations
    scan            - Run initial security scan
    help            - Show this help message

Examples:
    $0              # Run complete setup
    $0 tools        # Install tools only
    $0 configs      # Setup configurations
EOF
        ;;
    *)
        log_error "Unknown command: $1"
        log_info "Use '$0 help' for usage information"
        exit 1
        ;;
esac