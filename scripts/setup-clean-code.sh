#!/bin/bash

# 🦀 Clean Code Setup Script
# Sets up all tools and hooks for enforcing clean code standards

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🦀 Setting up Rust Clean Code Environment${NC}"
echo "=============================================="

# Function to print status
print_status() {
    local status=$1
    local message=$2
    if [ "$status" = "OK" ]; then
        echo -e "${GREEN}✅ $message${NC}"
    elif [ "$status" = "WARN" ]; then
        echo -e "${YELLOW}⚠️  $message${NC}"
    else
        echo -e "${RED}❌ $message${NC}"
    fi
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Rust components
install_rust_components() {
    echo -e "\n${BLUE}🔧 Installing Rust components...${NC}"
    
    # Install rustfmt
    if rustup component add rustfmt 2>/dev/null; then
        print_status "OK" "rustfmt installed"
    else
        print_status "WARN" "rustfmt already installed"
    fi
    
    # Install clippy
    if rustup component add clippy 2>/dev/null; then
        print_status "OK" "clippy installed"
    else
        print_status "WARN" "clippy already installed"
    fi
}

# Install cargo tools
install_cargo_tools() {
    echo -e "\n${BLUE}📦 Installing cargo tools...${NC}"
    
    local tools=(
        "cargo-audit:Security vulnerability scanner"
        "cargo-tarpaulin:Code coverage tool"
        "cargo-deny:Dependency checker"
        "cargo-outdated:Dependency update checker"
        "cargo-udeps:Unused dependency finder"
        "tokei:Code statistics"
        "cargo-watch:File watcher for development"
    )
    
    for tool_info in "${tools[@]}"; do
        local tool="${tool_info%%:*}"
        local description="${tool_info##*:}"
        
        if command_exists "$tool"; then
            print_status "OK" "$tool already installed ($description)"
        else
            echo -e "${YELLOW}Installing $tool...${NC}"
            if cargo install "$tool" >/dev/null 2>&1; then
                print_status "OK" "$tool installed ($description)"
            else
                print_status "WARN" "Failed to install $tool"
            fi
        fi
    done
}

# Setup git hooks
setup_git_hooks() {
    echo -e "\n${BLUE}🪝 Setting up git hooks...${NC}"
    
    # Create hooks directory if it doesn't exist
    mkdir -p .git/hooks
    
    # Copy pre-commit hook
    if [ -f ".githooks/pre-commit-clean-code" ]; then
        cp .githooks/pre-commit-clean-code .git/hooks/pre-commit
        chmod +x .git/hooks/pre-commit
        print_status "OK" "Pre-commit hook installed"
    else
        print_status "WARN" "Pre-commit hook file not found"
    fi
    
    # Set git hooks path
    git config core.hooksPath .githooks
    print_status "OK" "Git hooks path configured"
}

# Create rustfmt configuration
setup_rustfmt_config() {
    echo -e "\n${BLUE}🎨 Setting up rustfmt configuration...${NC}"
    
    if [ ! -f ".rustfmt.toml" ]; then
        cat > .rustfmt.toml << 'EOF'
# Rust formatting configuration for clean code standards

# Basic settings
edition = "2021"
version = "Two"
max_width = 100
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"

# Function formatting
fn_args_layout = "Tall"
fn_single_line = false
fn_params_layout = "Tall"

# Control flow
brace_style = "SameLineWhere"
control_brace_style = "AlwaysSameLine"
match_block_trailing_comma = false

# Imports and modules
imports_indent = "Block"
imports_layout = "Mixed"
merge_imports = false
reorder_imports = true
reorder_modules = true

# Expressions and literals
binop_separator = "Front"
combine_control_expr = true
overflow_delimited_expr = false
struct_field_align_threshold = 0
enum_discrim_align_threshold = 0

# Comments and documentation
wrap_comments = false
format_code_in_doc_comments = false
comment_width = 80
normalize_comments = false
normalize_doc_attributes = false

# Miscellaneous
trailing_semicolon = true
trailing_comma = "Vertical"
use_small_heuristics = "Default"
blank_lines_upper_bound = 1
blank_lines_lower_bound = 0
empty_item_single_line = true
struct_lit_single_line = true
where_single_line = false
space_before_colon = false
space_after_colon = true
spaces_around_ranges = false
type_punctuation_density = "Wide"
remove_nested_parens = true
format_strings = false
format_macro_matchers = false
format_macro_bodies = true
hex_literal_case = "Preserve"
EOF
        print_status "OK" "rustfmt configuration created"
    else
        print_status "OK" "rustfmt configuration already exists"
    fi
}

# Create clippy configuration
setup_clippy_config() {
    echo -e "\n${BLUE}📎 Setting up clippy configuration...${NC}"
    
    if [ ! -f ".clippy.toml" ]; then
        cat > .clippy.toml << 'EOF'
# Clippy configuration for clean code standards

# Cognitive complexity threshold
cognitive-complexity-threshold = 10

# Documentation requirements
missing-docs-in-crate-items = true

# Avoid certain patterns
avoid-breaking-exported-api = true
msrv = "1.80"

# Allowed lints (use sparingly)
allowed = [
    "clippy::module_name_repetitions",  # Sometimes necessary for clarity
    "clippy::similar_names",            # Common in crypto/security code
]

# Denied lints (enforce strictly)
denied = [
    "clippy::unwrap_used",
    "clippy::expect_used", 
    "clippy::panic",
    "clippy::unimplemented",
    "clippy::todo",
    "clippy::unreachable",
    "clippy::indexing_slicing",
]
EOF
        print_status "OK" "clippy configuration created"
    else
        print_status "OK" "clippy configuration already exists"
    fi
}

# Create cargo configuration
setup_cargo_config() {
    echo -e "\n${BLUE}📦 Setting up cargo configuration...${NC}"
    
    mkdir -p .cargo
    
    if [ ! -f ".cargo/config.toml" ]; then
        cat > .cargo/config.toml << 'EOF'
# Cargo configuration for clean code standards

[alias]
# Quality checks
check-all = "check --workspace --all-features"
test-all = "test --workspace --all-features"
fmt-all = "fmt --all"
clippy-all = "clippy --workspace --all-features -- -D warnings"
doc-all = "doc --workspace --all-features --no-deps"

# Development helpers
watch-test = "watch -x 'test --workspace'"
watch-check = "watch -x 'check --workspace'"
clean-code = "run --bin enforce-clean-code"

# Security and maintenance
audit-all = "audit"
outdated-all = "outdated --workspace"
udeps-all = "udeps --workspace --all-features"

[build]
# Treat warnings as errors in CI
rustflags = ["-D", "warnings"]

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

[target.x86_64-apple-darwin]
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
EOF
        print_status "OK" "cargo configuration created"
    else
        print_status "OK" "cargo configuration already exists"
    fi
}

# Create VS Code settings for Rust development
setup_vscode_config() {
    echo -e "\n${BLUE}💻 Setting up VS Code configuration...${NC}"
    
    mkdir -p .vscode
    
    if [ ! -f ".vscode/settings.json" ]; then
        cat > .vscode/settings.json << 'EOF'
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.checkOnSave.allFeatures": true,
    "rust-analyzer.cargo.allFeatures": true,
    "rust-analyzer.procMacro.enable": true,
    "rust-analyzer.cargo.loadOutDirsFromCheck": true,
    "rust-analyzer.completion.addCallParenthesis": false,
    "rust-analyzer.completion.addCallArgumentSnippets": false,
    
    "[rust]": {
        "editor.formatOnSave": true,
        "editor.defaultFormatter": "rust-lang.rust-analyzer",
        "editor.rulers": [100],
        "editor.tabSize": 4,
        "editor.insertSpaces": true
    },
    
    "files.watcherExclude": {
        "**/target/**": true
    },
    
    "search.exclude": {
        "**/target": true,
        "**/Cargo.lock": true
    },
    
    "editor.codeActionsOnSave": {
        "source.fixAll": true,
        "source.organizeImports": true
    }
}
EOF
        print_status "OK" "VS Code settings created"
    else
        print_status "OK" "VS Code settings already exist"
    fi
    
    if [ ! -f ".vscode/extensions.json" ]; then
        cat > .vscode/extensions.json << 'EOF'
{
    "recommendations": [
        "rust-lang.rust-analyzer",
        "tamasfe.even-better-toml",
        "serayuzgur.crates",
        "vadimcn.vscode-lldb",
        "ms-vscode.test-adapter-converter"
    ]
}
EOF
        print_status "OK" "VS Code extensions recommendations created"
    else
        print_status "OK" "VS Code extensions recommendations already exist"
    fi
}

# Create GitHub Actions workflow for clean code
setup_github_actions() {
    echo -e "\n${BLUE}🚀 Setting up GitHub Actions workflow...${NC}"
    
    mkdir -p .github/workflows
    
    if [ ! -f ".github/workflows/clean-code.yml" ]; then
        cat > .github/workflows/clean-code.yml << 'EOF'
name: Clean Code Standards

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

env:
  CARGO_TERM_COLOR: always

jobs:
  clean-code:
    name: Clean Code Checks
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable
      with:
        components: rustfmt, clippy
        
    - name: Cache cargo registry
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
        
    - name: Check formatting
      run: cargo fmt --all -- --check
      
    - name: Run clippy
      run: cargo clippy --workspace --all-features -- -D warnings
      
    - name: Run tests
      run: cargo test --workspace --all-features
      
    - name: Check documentation
      run: cargo doc --workspace --all-features --no-deps
      
    - name: Security audit
      run: |
        cargo install cargo-audit
        cargo audit
        
    - name: Run clean code enforcement
      run: ./scripts/enforce-clean-code.sh
EOF
        print_status "OK" "GitHub Actions workflow created"
    else
        print_status "OK" "GitHub Actions workflow already exists"
    fi
}

# Create development scripts
create_dev_scripts() {
    echo -e "\n${BLUE}📜 Creating development scripts...${NC}"
    
    mkdir -p scripts
    
    # Quick development check script
    if [ ! -f "scripts/dev-check.sh" ]; then
        cat > scripts/dev-check.sh << 'EOF'
#!/bin/bash
# Quick development check script

set -euo pipefail

echo "🦀 Running quick development checks..."

echo "📎 Running clippy..."
cargo clippy --workspace --all-features

echo "🎨 Checking formatting..."
cargo fmt --all -- --check

echo "🧪 Running tests..."
cargo test --workspace --all-features

echo "✅ All checks passed!"
EOF
        chmod +x scripts/dev-check.sh
        print_status "OK" "Development check script created"
    fi
    
    # Code metrics script
    if [ ! -f "scripts/code-metrics.sh" ]; then
        cat > scripts/code-metrics.sh << 'EOF'
#!/bin/bash
# Generate code metrics report

set -euo pipefail

echo "📊 Generating code metrics..."

if command -v tokei >/dev/null 2>&1; then
    echo "Lines of code:"
    tokei --exclude target
else
    echo "Install tokei for detailed metrics: cargo install tokei"
fi

echo -e "\nWorkspace structure:"
find . -name "Cargo.toml" -not -path "./target/*" | head -10

echo -e "\nLarge files (>500 lines):"
find . -name "*.rs" -not -path "./target/*" -exec wc -l {} + | awk '$1 > 500 {print $2 ": " $1 " lines"}' | head -10

echo -e "\nTest coverage (if tarpaulin is installed):"
if command -v cargo-tarpaulin >/dev/null 2>&1; then
    cargo tarpaulin --workspace --all-features --skip-clean --out Stdout | tail -1
else
    echo "Install cargo-tarpaulin for coverage: cargo install cargo-tarpaulin"
fi
EOF
        chmod +x scripts/code-metrics.sh
        print_status "OK" "Code metrics script created"
    fi
}

# Main setup function
main() {
    echo -e "${BLUE}Starting clean code environment setup...${NC}\n"
    
    # Check if we're in a Rust project
    if [ ! -f "Cargo.toml" ]; then
        print_status "FAIL" "Not in a Rust project directory (no Cargo.toml found)"
        exit 1
    fi
    
    # Run setup steps
    install_rust_components
    install_cargo_tools
    setup_git_hooks
    setup_rustfmt_config
    setup_clippy_config
    setup_cargo_config
    setup_vscode_config
    setup_github_actions
    create_dev_scripts
    
    echo -e "\n${BLUE}📋 Setup Summary${NC}"
    echo "=================="
    
    print_status "OK" "Rust components installed"
    print_status "OK" "Cargo tools installed"
    print_status "OK" "Git hooks configured"
    print_status "OK" "Configuration files created"
    print_status "OK" "Development scripts created"
    
    echo -e "\n${GREEN}🎉 Clean code environment setup complete!${NC}"
    echo -e "\n${BLUE}💡 Next steps:${NC}"
    echo "  1. Run './scripts/enforce-clean-code.sh' to check current code quality"
    echo "  2. Run './scripts/dev-check.sh' for quick development checks"
    echo "  3. Use 'cargo fmt-all' and 'cargo clippy-all' for code maintenance"
    echo "  4. Check './scripts/code-metrics.sh' for project statistics"
    
    echo -e "\n${YELLOW}⚠️  Note: Pre-commit hooks are now active and will run on every commit${NC}"
}

# Run main function
main "$@"
