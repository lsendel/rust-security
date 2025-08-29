#!/bin/bash

# Git Hooks Setup Script for Rust Security Platform
# This script installs pre-commit hooks to enforce code quality and security standards

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if we're in a git repository
check_git_repo() {
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not a git repository. Please run this script from the project root."
        exit 1
    fi
    log_success "Git repository detected"
}

# Create hooks directory if it doesn't exist
setup_hooks_directory() {
    local hooks_dir=".git/hooks"
    
    if [[ ! -d "$hooks_dir" ]]; then
        mkdir -p "$hooks_dir"
        log_info "Created hooks directory: $hooks_dir"
    fi
    
    log_success "Hooks directory ready"
}

# Create pre-commit hook
create_pre_commit_hook() {
    local hook_file=".git/hooks/pre-commit"
    
    log_info "Creating pre-commit hook..."
    
    cat > "$hook_file" << 'EOF'
#!/bin/bash

# Pre-commit hook for Rust Security Platform
# Enforces code quality, formatting, and security standards

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}🔍 Running pre-commit security and quality checks...${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
check_tools() {
    local missing_tools=()
    
    if ! command_exists cargo; then
        missing_tools+=("cargo (Rust toolchain)")
    fi
    
    if ! command_exists rustfmt; then
        missing_tools+=("rustfmt (cargo component)")
    fi
    
    if ! command_exists cargo-clippy; then
        missing_tools+=("clippy (cargo component)")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Missing required tools:${NC}"
        printf '%s\n' "${missing_tools[@]}"
        echo -e "${YELLOW}💡 Run 'make setup' to install required tools${NC}"
        exit 1
    fi
}

# Check code formatting
check_formatting() {
    echo -e "${GREEN}🎨 Checking code formatting...${NC}"
    
    if ! cargo fmt --all -- --check; then
        echo -e "${RED}❌ Code formatting issues found${NC}"
        echo -e "${YELLOW}💡 Run 'cargo fmt --all' to fix formatting${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Code formatting is correct${NC}"
}

# Run clippy lints
check_lints() {
    echo -e "${GREEN}📎 Running clippy lints...${NC}"
    
    if ! cargo clippy --workspace --all-targets --all-features -- -D warnings; then
        echo -e "${RED}❌ Clippy lints failed${NC}"
        echo -e "${YELLOW}💡 Fix clippy issues before committing${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Clippy lints passed${NC}"
}

# Security checks for staged files
check_security() {
    echo -e "${GREEN}🔒 Running security checks on staged files...${NC}"
    
    # Get list of staged Rust files
    local staged_files
    staged_files=$(git diff --cached --name-only --diff-filter=ACM | grep '\.rs$' || true)
    
    if [[ -z "$staged_files" ]]; then
        echo -e "${GREEN}ℹ️  No Rust files staged${NC}"
        return 0
    fi
    
    # Check for potential secrets in staged files
    local secret_patterns=(
        "password[[:space:]]*="
        "secret[[:space:]]*="
        "token[[:space:]]*="
        "api_key[[:space:]]*="
        "private_key"
        "jwt_secret"
        "-----BEGIN.*PRIVATE KEY"
        "sk-[a-zA-Z0-9]{40,}"
    )
    
    local violations=0
    
    for pattern in "${secret_patterns[@]}"; do
        # Check staged content, not just file names
        if git diff --cached --name-only | xargs grep -l -i "$pattern" 2>/dev/null | grep -v "test\|example\|demo"; then
            echo -e "${RED}❌ Potential secret found matching pattern: $pattern${NC}"
            violations=$((violations + 1))
        fi
    done
    
    # Check for hardcoded IPs and URLs
    if echo "$staged_files" | xargs grep -n "https\?://[^/]*\.(com\|org\|net)" 2>/dev/null | grep -v "example\|test\|localhost"; then
        echo -e "${YELLOW}⚠️  Hardcoded URLs found - ensure they're not sensitive${NC}"
    fi
    
    # Check for TODO/FIXME in security-critical files
    local security_files
    security_files=$(echo "$staged_files" | grep -E "(auth|security|crypto|jwt|oauth|session)" || true)
    
    if [[ -n "$security_files" ]]; then
        if echo "$security_files" | xargs grep -n "TODO\|FIXME\|XXX" 2>/dev/null; then
            echo -e "${YELLOW}⚠️  TODOs found in security-critical files - review before production${NC}"
        fi
    fi
    
    if [[ $violations -gt 0 ]]; then
        echo -e "${RED}❌ Security violations found in staged files${NC}"
        echo -e "${YELLOW}💡 Remove secrets and sensitive data before committing${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Security checks passed${NC}"
}

# Run unit tests on changed files
run_quick_tests() {
    echo -e "${GREEN}🧪 Running quick tests...${NC}"
    
    # Only run tests if there are Rust changes
    if git diff --cached --name-only | grep -q '\.rs$'; then
        if ! cargo test --workspace --lib; then
            echo -e "${RED}❌ Tests failed${NC}"
            echo -e "${YELLOW}💡 Fix failing tests before committing${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✅ Quick tests passed${NC}"
}

# Main execution
main() {
    echo -e "${GREEN}🚀 Starting pre-commit checks for Rust Security Platform${NC}"
    
    # Skip checks if NO_VERIFY is set
    if [[ "${NO_VERIFY:-}" == "1" ]]; then
        echo -e "${YELLOW}⚠️  Pre-commit checks skipped (NO_VERIFY=1)${NC}"
        exit 0
    fi
    
    check_tools
    check_formatting
    check_lints
    check_security
    run_quick_tests
    
    echo -e "${GREEN}🎉 All pre-commit checks passed!${NC}"
    echo -e "${GREEN}✅ Safe to commit${NC}"
}

# Run main function
main "$@"
EOF

    chmod +x "$hook_file"
    log_success "Pre-commit hook created and made executable"
}

# Create commit-msg hook
create_commit_msg_hook() {
    local hook_file=".git/hooks/commit-msg"
    
    log_info "Creating commit-msg hook..."
    
    cat > "$hook_file" << 'EOF'
#!/bin/bash

# Commit message hook for Rust Security Platform
# Enforces conventional commit format and security-aware messaging

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

commit_msg_file="$1"
commit_msg=$(cat "$commit_msg_file")

# Skip checks for merge commits and fixup commits
if [[ "$commit_msg" =~ ^Merge || "$commit_msg" =~ ^fixup! ]]; then
    exit 0
fi

echo -e "${GREEN}🔍 Validating commit message format...${NC}"

# Check conventional commit format
conventional_pattern="^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|security)(\(.+\))?: .{1,50}"

if ! [[ "$commit_msg" =~ $conventional_pattern ]]; then
    echo -e "${RED}❌ Commit message does not follow conventional commit format${NC}"
    echo -e "${YELLOW}Expected format: type(scope): description${NC}"
    echo ""
    echo "Valid types:"
    echo "  feat:     New features"
    echo "  fix:      Bug fixes"
    echo "  security: Security improvements"
    echo "  perf:     Performance improvements"
    echo "  refactor: Code refactoring"
    echo "  test:     Test additions/improvements"
    echo "  docs:     Documentation changes"
    echo "  ci:       CI/CD changes"
    echo ""
    echo "Example: security(auth): implement constant-time token comparison"
    exit 1
fi

# Check for security-sensitive keywords that might need special attention
security_keywords=("password" "secret" "token" "key" "auth" "security" "vulnerability" "exploit")
for keyword in "${security_keywords[@]}"; do
    if [[ "$commit_msg" =~ $keyword ]]; then
        echo -e "${YELLOW}⚠️  Security-sensitive keyword detected: '$keyword'${NC}"
        echo -e "${YELLOW}💡 Ensure this commit doesn't expose sensitive information${NC}"
        break
    fi
done

# Discourage certain words that might indicate incomplete work
discouraged_words=("hack" "quick fix" "temporary" "workaround" "broken")
for word in "${discouraged_words[@]}"; do
    if [[ "$commit_msg" =~ $word ]]; then
        echo -e "${YELLOW}⚠️  Consider if this change is production-ready ('$word' detected)${NC}"
        break
    fi
done

echo -e "${GREEN}✅ Commit message format is valid${NC}"
EOF

    chmod +x "$hook_file"
    log_success "Commit-msg hook created and made executable"
}

# Create pre-push hook
create_pre_push_hook() {
    local hook_file=".git/hooks/pre-push"
    
    log_info "Creating pre-push hook..."
    
    cat > "$hook_file" << 'EOF'
#!/bin/bash

# Pre-push hook for Rust Security Platform
# Ensures comprehensive validation before pushing to remote

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

protected_branches=("main" "master" "production")
current_branch=$(git branch --show-current)

echo -e "${GREEN}🔍 Running pre-push validation...${NC}"

# Check if pushing to protected branch
for branch in "${protected_branches[@]}"; do
    if [[ "$current_branch" == "$branch" ]]; then
        echo -e "${YELLOW}⚠️  Pushing to protected branch: $branch${NC}"
        echo -e "${YELLOW}💡 Ensure all tests and security checks pass${NC}"
        break
    fi
done

# Run comprehensive tests before push
echo -e "${GREEN}🧪 Running comprehensive test suite...${NC}"

if ! cargo test --workspace --all-features; then
    echo -e "${RED}❌ Tests failed - push aborted${NC}"
    exit 1
fi

# Run security audit
echo -e "${GREEN}🔒 Running security audit...${NC}"

if command -v cargo-audit >/dev/null 2>&1; then
    if ! cargo audit; then
        echo -e "${YELLOW}⚠️  Security advisories found - review before pushing to production${NC}"
        # Don't fail on advisories, just warn
    fi
fi

# Check for secrets one more time
echo -e "${GREEN}🕵️  Final secret scan...${NC}"

if git log --oneline -n 10 | grep -i "secret\|password\|key" | grep -v "test\|example"; then
    echo -e "${YELLOW}⚠️  Recent commits mention secrets - double-check no sensitive data is exposed${NC}"
fi

echo -e "${GREEN}✅ Pre-push validation complete${NC}"
EOF

    chmod +x "$hook_file"
    log_success "Pre-push hook created and made executable"
}

# Create a hook to bypass all checks if needed
create_bypass_info() {
    local info_file=".git/hooks/README.md"
    
    log_info "Creating hooks documentation..."
    
    cat > "$info_file" << 'EOF'
# Git Hooks for Rust Security Platform

This directory contains git hooks that enforce code quality and security standards.

## Installed Hooks

### pre-commit
- Code formatting validation (`cargo fmt`)
- Linting (`cargo clippy`)
- Security checks for secrets and sensitive data
- Quick unit tests

### commit-msg
- Conventional commit format validation
- Security-sensitive keyword detection
- Production-readiness checks

### pre-push
- Comprehensive test suite
- Security audit
- Final secret scan

## Bypassing Hooks

In emergency situations, you can bypass hooks:

```bash
# Skip pre-commit checks
NO_VERIFY=1 git commit -m "emergency fix"

# Skip pre-commit and pre-push checks
git commit --no-verify -m "emergency fix"
git push --no-verify
```

**⚠️ Warning**: Only bypass hooks in genuine emergencies. Always run manual validation afterward.

## Manual Validation

If you bypass hooks, run these commands manually:

```bash
# Code quality
make fmt-fix
make clippy

# Security
make security-audit

# Tests
make test
```

## Troubleshooting

If hooks fail to run:

1. Ensure tools are installed: `make setup`
2. Check file permissions: `chmod +x .git/hooks/*`
3. Verify git configuration: `git config core.hooksPath`

For persistent issues, run: `./setup-git-hooks.sh` to reinstall hooks.
EOF

    log_success "Hooks documentation created"
}

# Main setup function
main() {
    echo -e "${GREEN}🚀 Setting up Git hooks for Rust Security Platform${NC}"
    echo -e "${BLUE}This will install pre-commit, commit-msg, and pre-push hooks${NC}"
    echo ""
    
    check_git_repo
    setup_hooks_directory
    create_pre_commit_hook
    create_commit_msg_hook  
    create_pre_push_hook
    create_bypass_info
    
    echo ""
    echo -e "${GREEN}🎉 Git hooks setup complete!${NC}"
    echo ""
    echo -e "${BLUE}Hooks installed:${NC}"
    echo -e "  📋 pre-commit: Code quality and security checks"
    echo -e "  💬 commit-msg: Commit message format validation"
    echo -e "  🚀 pre-push: Comprehensive validation before push"
    echo ""
    echo -e "${YELLOW}💡 Tips:${NC}"
    echo -e "  • Run 'make pre-commit' to test pre-commit checks manually"
    echo -e "  • Use 'NO_VERIFY=1 git commit' to skip checks in emergencies"
    echo -e "  • See .git/hooks/README.md for detailed documentation"
    echo ""
    echo -e "${GREEN}✅ Your repository is now protected with security-focused git hooks!${NC}"
}

# Run main function
main "$@"