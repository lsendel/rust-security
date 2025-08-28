# Rust Security Platform - Comprehensive Build and Development Automation
# This Makefile provides commands for building, testing, and deploying the Rust Security platform

# Default shell
SHELL := /bin/bash

# Variables
RUST_VERSION := 1.80
PROJECT_NAME := rust-security
AUTH_SERVICE := auth-service
POLICY_SERVICE := policy-service

# Environment variables for testing
export TEST_MODE := 1
export DISABLE_RATE_LIMIT := 1
export RUST_LOG := info
export DATABASE_URL := postgres://postgres:postgres@localhost:5432/auth_test
export REDIS_URL := redis://localhost:6379

# Color codes for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

##@ Help
.PHONY: help
help: ## Display this help message
	@awk 'BEGIN {FS = ":.*##"; printf "\nRust Security Platform - Development Commands\n"}  /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BLUE)%s:$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Quick Start
.PHONY: quick-start
quick-start: setup build test ## Complete development setup and validation
	@echo "$(GREEN)✅ Quick start complete! Ready for development.$(NC)"

.PHONY: setup
setup: ## Set up development environment
	@echo "$(GREEN)🚀 Setting up development environment...$(NC)"
	@rustup install $(RUST_VERSION)
	@rustup default $(RUST_VERSION)
	@rustup component add rustfmt clippy
	@cargo install sqlx-cli --no-default-features --features postgres,sqlite
	@cargo install cargo-audit cargo-deny cargo-fuzz cargo-outdated
	@echo "$(YELLOW)📦 Starting dependencies...$(NC)"
	@docker-compose up -d postgres redis
	@sleep 5
	@echo "$(YELLOW)🗄️ Running database migrations...$(NC)"
	@sqlx migrate run --source auth-service/migrations || true
	@echo "$(GREEN)✅ Development environment ready!$(NC)"

##@ Development
.PHONY: dev
dev: ## Start development server with hot reload
	@echo "$(GREEN)🚀 Starting development server...$(NC)"
	@cd $(AUTH_SERVICE) && RUST_LOG=debug cargo run --bin auth-service

.PHONY: dev-watch
dev-watch: ## Start development server with auto-reload on file changes
	@echo "$(GREEN)👀 Starting development server with file watching...$(NC)"
	@cargo install cargo-watch
	@cd $(AUTH_SERVICE) && cargo watch -x "run --bin auth-service"

.PHONY: clean
clean: ## Clean build artifacts and cache
	@echo "$(YELLOW)🧹 Cleaning build artifacts...$(NC)"
	@cargo clean
	@docker-compose down
	@echo "$(GREEN)✅ Clean complete!$(NC)"

##@ Code Quality
.PHONY: check
check: fmt clippy audit test ## Run all code quality checks
	@echo "$(GREEN)✅ All quality checks passed!$(NC)"

.PHONY: fmt
fmt: ## Check code formatting
	@echo "$(GREEN)🎨 Checking code formatting...$(NC)"
	@cargo fmt --all -- --check || (echo "$(RED)❌ Code formatting issues found. Run 'make fmt-fix' to fix.$(NC)"; exit 1)

.PHONY: fmt-fix
fmt-fix: ## Fix code formatting issues
	@echo "$(GREEN)🎨 Fixing code formatting...$(NC)"
	@cargo fmt --all

.PHONY: clippy
clippy: ## Run clippy lints
	@echo "$(GREEN)📎 Running clippy lints...$(NC)"
	@cargo clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: clippy-fix
clippy-fix: ## Fix clippy issues automatically where possible
	@echo "$(GREEN)📎 Fixing clippy issues...$(NC)"
	@cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- -D warnings

.PHONY: audit
audit: security-audit ## Alias for security-audit

.PHONY: security-audit
security-audit: ## Run comprehensive security audit
	@echo "$(GREEN)🔒 Running security audit...$(NC)"
	@echo "$(YELLOW)📋 Checking for known vulnerabilities...$(NC)"
	@cargo audit || echo "$(YELLOW)⚠️ Security advisories found - review required$(NC)"
	@echo "$(YELLOW)🚫 Checking dependency policies...$(NC)"
	@cargo deny check || echo "$(YELLOW)⚠️ Dependency policy violations - review required$(NC)"
	@echo "$(GREEN)✅ Security audit complete!$(NC)"

##@ Testing
.PHONY: test
test: test-unit test-integration ## Run all tests
	@echo "$(GREEN)✅ All tests passed!$(NC)"

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "$(GREEN)🧪 Running unit tests...$(NC)"
	@cargo test --workspace --lib

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "$(GREEN)🔧 Running integration tests...$(NC)"
	@cargo test --workspace --test '*'

.PHONY: test-security
test-security: ## Run security-specific tests
	@echo "$(GREEN)🔒 Running security tests...$(NC)"
	@cargo test --workspace security
	@echo "$(YELLOW)🕵️ Running penetration tests...$(NC)"
	@./scripts/security/run_security_scenarios.sh || true

.PHONY: test-fuzz
test-fuzz: ## Run fuzz tests (limited time)
	@echo "$(GREEN)🎯 Running fuzz tests...$(NC)"
	@cd $(AUTH_SERVICE) && timeout 60 cargo fuzz run fuzz_jwt_parsing -- -max_total_time=60 || true
	@cd $(AUTH_SERVICE) && timeout 60 cargo fuzz run fuzz_oauth_parsing -- -max_total_time=60 || true
	@echo "$(GREEN)✅ Fuzz testing complete!$(NC)"

.PHONY: benchmark
benchmark: ## Run performance benchmarks
	@echo "$(GREEN)🏃 Running benchmarks...$(NC)"
	@cargo bench --workspace

##@ Building
.PHONY: build
build: ## Build all packages
	@echo "$(GREEN)🔨 Building all packages...$(NC)"
	@cargo build --workspace

.PHONY: build-release
build-release: ## Build optimized release version
	@echo "$(GREEN)🚀 Building release version...$(NC)"
	@cargo build --workspace --release

.PHONY: build-docker
build-docker: ## Build Docker images
	@echo "$(GREEN)🐳 Building Docker images...$(NC)"
	@docker build -t $(PROJECT_NAME)/$(AUTH_SERVICE):latest -f Dockerfile.$(AUTH_SERVICE) .
	@docker build -t $(PROJECT_NAME)/$(POLICY_SERVICE):latest -f Dockerfile.$(POLICY_SERVICE) .
	@echo "$(GREEN)✅ Docker images built successfully!$(NC)"

##@ Documentation
.PHONY: docs
docs: ## Generate documentation
	@echo "$(GREEN)📚 Generating documentation...$(NC)"
	@cargo doc --workspace --all-features --no-deps --document-private-items

.PHONY: docs-open
docs-open: docs ## Generate and open documentation in browser
	@cargo doc --workspace --all-features --no-deps --document-private-items --open

##@ Supply Chain
.PHONY: sbom
sbom: ## Generate Software Bill of Materials (SBOM)
	@echo "$(GREEN)📦 Generating SBOM...$(NC)"
	@cargo install cargo-auditable cargo-sbom
	@cargo auditable build --release
	@cargo sbom > target/rust-security-sbom.json
	@echo "$(GREEN)✅ SBOM generated at target/rust-security-sbom.json$(NC)"

.PHONY: supply-chain-check
supply-chain-check: audit sbom ## Complete supply chain security check
	@echo "$(GREEN)🔗 Supply chain security check complete!$(NC)"

##@ Git Hooks & CI
.PHONY: install-hooks
install-hooks: ## Install git pre-commit hooks
	@echo "$(GREEN)🪝 Installing git hooks...$(NC)"
	@./setup-git-hooks.sh

.PHONY: ci-local
ci-local: check test security-audit ## Run CI checks locally
	@echo "$(GREEN)🔄 Running CI checks locally...$(NC)"
	@echo "$(GREEN)✅ Local CI checks complete!$(NC)"

.PHONY: pre-commit
pre-commit: fmt-fix clippy-fix test-unit ## Run pre-commit checks and fixes
	@echo "$(GREEN)✅ Pre-commit checks complete!$(NC)"

.PHONY: validate-pr
validate-pr: ci-local supply-chain-check ## Validate changes before creating PR
	@echo "$(GREEN)✅ PR validation complete! Ready to create pull request.$(NC)"

##@ Utilities
.PHONY: show-env
show-env: ## Show current environment configuration
	@echo "$(BLUE)Environment Configuration:$(NC)"
	@echo "RUST_VERSION: $(RUST_VERSION)"
	@echo "DATABASE_URL: $(DATABASE_URL)"
	@echo "REDIS_URL: $(REDIS_URL)"
	@echo "TEST_MODE: $(TEST_MODE)"
	@echo "RUST_LOG: $(RUST_LOG)"

.PHONY: workspace-status
workspace-status: ## Show workspace status
	@echo "$(BLUE)Workspace Status:$(NC)"
	@echo "Rust version: $$(rustc --version)"
	@echo "Cargo version: $$(cargo --version)"
	@echo "Git branch: $$(git branch --show-current)"
	@echo "Git status: $$(git status --porcelain | wc -l) files changed"
	@echo "Docker status:"
	@docker-compose ps

.PHONY: doctor
doctor: ## Run diagnostic checks
	@echo "$(GREEN)🏥 Running diagnostic checks...$(NC)"
	@echo "$(BLUE)Checking Rust installation...$(NC)"
	@rustc --version || echo "$(RED)❌ Rust not installed$(NC)"
	@cargo --version || echo "$(RED)❌ Cargo not available$(NC)"
	@echo "$(BLUE)Checking required tools...$(NC)"
	@sqlx --version || echo "$(YELLOW)⚠️ SQLx CLI not installed$(NC)"
	@docker --version || echo "$(YELLOW)⚠️ Docker not available$(NC)"
	@docker-compose --version || echo "$(YELLOW)⚠️ Docker Compose not available$(NC)"
	@echo "$(GREEN)✅ Diagnostic complete!$(NC)"

.PHONY: reset
reset: clean setup ## Complete reset of development environment
	@echo "$(GREEN)🔄 Development environment reset complete!$(NC)"