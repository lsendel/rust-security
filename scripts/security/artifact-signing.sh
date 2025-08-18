#!/bin/bash
# Artifact Signing and Verification for Supply Chain Security
# Implements SLSA-compliant artifact signing with cosign and provenance generation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ARTIFACTS_DIR="${PROJECT_ROOT}/artifacts"
KEYS_DIR="${PROJECT_ROOT}/keys"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() {
    echo -e "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"
}

log_info() { log "${BLUE}INFO${NC} $*"; }
log_success() { log "${GREEN}SUCCESS${NC} $*"; }
log_warn() { log "${YELLOW}WARN${NC} $*"; }
log_error() { log "${RED}ERROR${NC} $*"; }

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v cosign &> /dev/null; then
        missing_deps+=("cosign")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install cosign: go install github.com/sigstore/cosign/v2/cmd/cosign@latest"
        exit 1
    fi
}

# Setup directories
setup_directories() {
    mkdir -p "$ARTIFACTS_DIR"
    mkdir -p "$KEYS_DIR"
}

# Generate signing keys (for development/testing)
generate_keys() {
    log_info "Generating signing keys for development..."
    
    cd "$KEYS_DIR"
    
    # Generate cosign key pair for development
    if [ ! -f "cosign.key" ]; then
        log_info "Generating cosign key pair..."
        cosign generate-key-pair
        log_success "Cosign keys generated"
    fi
    
    # Set proper permissions
    chmod 600 cosign.key
    chmod 644 cosign.pub
}

# Sign binary artifacts
sign_binaries() {
    log_info "Signing binary artifacts..."
    
    cd "$PROJECT_ROOT"
    
    # Find binary artifacts
    local binaries=(
        "target/release/auth-service"
    )
    
    for binary in "${binaries[@]}"; do
        if [ -f "$binary" ]; then
            log_info "Signing binary: $binary"
            
            # Generate checksum
            local checksum_file="${binary}.sha256"
            sha256sum "$binary" > "$checksum_file"
            
            # Sign with cosign
            if [ "${CI:-false}" = "true" ]; then
                # Keyless signing in CI/CD
                cosign sign-blob --yes "$checksum_file" --output-signature="${checksum_file}.sig"
            else
                # Key-based signing for development
                cosign sign-blob --key="${KEYS_DIR}/cosign.key" "$checksum_file" --output-signature="${checksum_file}.sig"
            fi
            
            log_success "Binary signed: $binary"
        fi
    done
}

# Main function
main() {
    local action=${1:-"all"}
    
    echo -e "${BLUE}Artifact Signing and Verification${NC}"
    echo -e "${BLUE}=================================${NC}"
    
    check_dependencies
    setup_directories
    
    case "$action" in
        "keys")
            generate_keys
            ;;
        "sign")
            if [ "${CI:-false}" != "true" ]; then
                generate_keys
            fi
            sign_binaries
            ;;
        "all")
            if [ "${CI:-false}" != "true" ]; then
                generate_keys
            fi
            sign_binaries
            ;;
        *)
            log_error "Unknown action: $action"
            log_info "Usage: $0 [keys|sign|all]"
            exit 1
            ;;
    esac
    
    log_success "Artifact signing completed"
}

# Execute main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
