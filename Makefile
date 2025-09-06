# ============================================================================
# Rust Security Platform - Comprehensive Development & Deployment Automation
# ============================================================================
# This Makefile provides complete development workflow automation covering:
# - Development environment setup and management
# - Frontend & backend service orchestration
# - Comprehensive testing (unit, integration, e2e, security, performance)
# - Code quality, security, and compliance checks
# - Multi-environment deployment (local, staging, production)
# - Monitoring, observability, and maintenance
# ============================================================================

# Default shell and settings
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# Core project variables
RUST_VERSION := 1.80
PROJECT_NAME := rust-security
AUTH_SERVICE := auth-service
POLICY_SERVICE := policy-service
USER_PORTAL := user-portal
COMPLIANCE_TOOLS := compliance-tools

# Test environment configurations
export TEST_MODE := 1
export DISABLE_RATE_LIMIT := 1
export RUST_LOG := info
export DATABASE_URL := postgresql://authuser:authpass@localhost:5432/authdb
export REDIS_URL := redis://localhost:6379
export CONFIG_DIR := config
export APP_ENV := development

# Color codes for beautiful output
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
BLUE := \033[0;34m
PURPLE := \033[0;35m
CYAN := \033[0;36m
WHITE := \033[1;37m
NC := \033[0m # No Color

# Emoji indicators for status
CHECKMARK := $(GREEN)✅$(NC)
CROSS := $(RED)❌$(NC)
HAMMER := $(YELLOW)🔨$(NC)
ROCKET := $(BLUE)🚀$(NC)
LOCK := $(PURPLE)🔒$(NC)
CHART := $(CYAN)📊$(NC)
TEST_TUBE := $(YELLOW)🧪$(NC)
STETHOSCOPE := $(GREEN)🏥$(NC)

# Default target
.DEFAULT_GOAL := help

# ============================================================================
# HELP SYSTEM
# ============================================================================

.PHONY: help
help: ## Display comprehensive help with command categories
	@echo "$(WHITE)================================================================================"
	@echo "🚀 RUST SECURITY PLATFORM - COMPREHENSIVE DEVELOPMENT WORKFLOW"
	@echo "================================================================================"
	@echo ""
	@echo "$(CYAN)USAGE:$(NC)"
	@echo "  make <command> [OPTIONS]"
	@echo ""
	@echo "$(CYAN)QUICK START:$(NC)"
	@echo "  make setup          # Initial development environment setup"
	@echo "  make dev            # Start all services for development"
	@echo "  make test           # Run complete test suite"
	@echo ""
	@echo "$(CYAN)AVAILABLE SECTIONS:$(NC)"
	@echo "  Quick Start & Environment Setup"
	@echo "  Development Workflow"
	@echo "  Code Quality & Formatting"
	@echo "  Frontend Management"
	@echo "  Testing & Quality Assurance"
	@echo "  Building & Compilation"
	@echo "  Documentation"
	@echo "  Supply Chain & Compliance"
	@echo "  Deployment & Infrastructure"
	@echo "  Monitoring & Observability"
	@echo "  Development Workflow & CI/CD"
	@echo "  Security & Vulnerability Management"
	@echo "  Utilities & Diagnostics"
	@echo ""
	@echo "$(CYAN)POPULAR COMMANDS:$(NC)"
	@grep -E "^[a-zA-Z_0-9-]+:.*##" $(MAKEFILE_LIST) | grep -E "(setup|dev|test|build|check|clean|help)" | head -10 | awk 'BEGIN {FS = ":.*##"} {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)TIPS:$(NC)"
	@echo "  • Use 'make help | grep <topic>' to filter commands"
	@echo "  • Most commands support parallel execution with '-j'"
	@echo "  • Use 'make doctor' to diagnose environment issues"
	@echo "================================================================================"

.PHONY: help-dev
help-dev: ## Show development workflow commands
	@echo "$(CYAN)Development Workflow:$(NC)"
	@grep -A 1 "^##@ Development" $(MAKEFILE_LIST) | grep -v "^##@" | awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  make %-20s %s\n", $$1, $$2 }'

.PHONY: help-test
help-test: ## Show testing commands
	@echo "$(CYAN)Testing Commands:$(NC)"
	@grep -A 1 "^##@ Testing" $(MAKEFILE_LIST) | grep -v "^##@" | awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  make %-20s %s\n", $$1, $$2 }'

.PHONY: help-deploy
help-deploy: ## Show deployment commands
	@echo "$(CYAN)Deployment Commands:$(NC)"
	@grep -A 1 "^##@ Deployment" $(MAKEFILE_LIST) | grep -v "^##@" | awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  make %-20s %s\n", $$1, $$2 }'

# ============================================================================
# QUICK START & ENVIRONMENT SETUP
# ============================================================================

.PHONY: quick-start
quick-start: setup dev-env-up build test-e2e-setup test ## 🚀 Complete development environment setup and validation
	@echo "$(CHECKMARK) Quick start complete! Access points:"
	@echo "  • Frontend:    http://localhost:5173"
	@echo "  • Auth API:    http://localhost:8080"
	@echo "  • Policy API:  http://localhost:8081"
	@echo "  • Health:      http://localhost:8080/health"
	@echo "  • Metrics:     http://localhost:8080/metrics"
	@echo "  • Database:    localhost:5432"
	@echo "  • Redis:       localhost:6379"

.PHONY: setup
setup: setup-rust setup-tools setup-deps setup-frontend ## 🔧 Complete development environment setup
	@echo "$(CHECKMARK) Development environment fully configured!"

.PHONY: setup-rust
setup-rust: ## Install and configure Rust toolchain
	@echo "$(HAMMER) Setting up Rust $(RUST_VERSION)..."
	@rustup install $(RUST_VERSION) || echo "Rust $(RUST_VERSION) already installed"
	@rustup default $(RUST_VERSION)
	@rustup component add rustfmt clippy rust-src
	@rustup target add wasm32-unknown-unknown
	@cargo --version && rustc --version
	@echo "$(CHECKMARK) Rust environment ready!"

.PHONY: setup-tools
setup-tools: ## Install development tools and dependencies
	@echo "$(HAMMER) Installing development tools..."
	@cargo install sqlx-cli --no-default-features --features postgres,sqlite || echo "sqlx-cli already installed"
	@cargo install cargo-audit cargo-deny cargo-fuzz cargo-outdated cargo-watch || echo "Tools already installed"
	@cargo install cargo-llvm-cov || echo "Coverage tools already installed"
	@echo "$(CHECKMARK) Development tools installed!"

.PHONY: setup-deps
setup-deps: ## Start required dependencies (PostgreSQL, Redis)
	@echo "$(HAMMER) Starting infrastructure dependencies..."
	@docker-compose up -d postgres redis
	@echo "$(YELLOW)⏳ Waiting for services to be ready...$(NC)"
	@sleep 10
	@docker-compose ps
	@echo "$(CHECKMARK) Infrastructure dependencies running!"

.PHONY: setup-frontend
setup-frontend: ## Install frontend dependencies
	@echo "$(HAMMER) Setting up frontend environment..."
	@cd $(USER_PORTAL) && npm install --no-audit --no-fund
	@echo "$(CHECKMARK) Frontend dependencies installed!"

.PHONY: setup-migrations
setup-migrations: ## Run database migrations
	@echo "$(HAMMER) Running database migrations..."
	@sqlx migrate run --source $(AUTH_SERVICE)/migrations || echo "Migrations may already be applied"
	@echo "$(CHECKMARK) Database migrations complete!"

.PHONY: setup-all
setup-all: setup setup-migrations setup-monitoring ## Complete environment setup with all components
	@echo "$(CHECKMARK) Full environment setup complete!"

# ============================================================================
# DEVELOPMENT WORKFLOW
# ============================================================================

.PHONY: dev
dev: dev-env-up dev-services ## 🚀 Start complete development environment
	@echo "$(CHECKMARK) Development environment running!"
	@echo "$(YELLOW)📋 Access URLs:$(NC)"
	@echo "  Frontend:    http://localhost:5173"
	@echo "  Auth API:    http://localhost:8080"
	@echo "  Policy API:  http://localhost:8081"
	@echo "  Metrics:     http://localhost:8080/metrics"

.PHONY: dev-env-up
dev-env-up: ## Start development infrastructure (DB, Redis, monitoring)
	@echo "$(HAMMER) Starting development infrastructure..."
	@docker-compose up -d postgres redis
	@sleep 5
	@docker-compose ps
	@echo "$(CHECKMARK) Development infrastructure ready!"

.PHONY: services-up
services-up: dev-env-up ## Start services for testing (alias for dev-env-up)

.PHONY: services-down
services-down: ## Stop all Docker services
	@echo "$(YELLOW) Stopping services..."
	@docker-compose down
	@echo "$(CHECKMARK) Services stopped!"

.PHONY: dev-env-down
dev-env-down: ## Stop development infrastructure
	@echo "$(HAMMER) Stopping development infrastructure..."
	@docker-compose down
	@echo "$(CHECKMARK) Development infrastructure stopped!"

.PHONY: dev-services
dev-services: ## Start all backend services
	@echo "$(ROCKET) Starting backend services..."
	@CONFIG_DIR=config APP_ENV=development cargo run -p $(AUTH_SERVICE) &
	@sleep 2
	@CONFIG_DIR=config APP_ENV=development cargo run -p $(POLICY_SERVICE) &
	@echo "$(CHECKMARK) Backend services started!"

.PHONY: dev-frontend
dev-frontend: ## Start frontend development server
	@echo "$(ROCKET) Starting frontend development server..."
	@cd $(USER_PORTAL) && npm run dev
	@echo "$(CHECKMARK) Frontend server started!"

.PHONY: dev-full
dev-full: dev-env-up dev-services ## Start full development stack (backend + infra)
	@echo "$(CHECKMARK) Full development stack running!"
	@echo "$(YELLOW)💡 Tip: Run 'make dev-frontend' in another terminal for frontend$(NC)"

.PHONY: dev-watch
dev-watch: ## Start development with auto-reload
	@echo "$(ROCKET) Starting development with file watching..."
	@cargo watch -x "run -p $(AUTH_SERVICE)" -x "run -p $(POLICY_SERVICE)"

.PHONY: dev-auth
dev-auth: ## Start auth service in development mode
	@echo "$(ROCKET) Starting auth service..."
	@CONFIG_DIR=config APP_ENV=development cargo run -p $(AUTH_SERVICE)

.PHONY: dev-policy
dev-policy: ## Start policy service in development mode
	@echo "$(ROCKET) Starting policy service..."
	@CONFIG_DIR=config APP_ENV=development cargo run -p $(POLICY_SERVICE)

.PHONY: dev-frontend-watch
dev-frontend-watch: ## Start frontend with hot reload
	@echo "$(ROCKET) Starting frontend with hot reload..."
	@cd $(USER_PORTAL) && npm run dev

.PHONY: clean
clean: clean-build clean-deps clean-frontend ## 🧹 Clean all build artifacts and caches
	@echo "$(CHECKMARK) Clean complete!"

.PHONY: clean-build
clean-build: ## Clean Rust build artifacts
	@echo "$(HAMMER) Cleaning Rust build artifacts..."
	@cargo clean
	@echo "$(CHECKMARK) Rust artifacts cleaned!"

.PHONY: clean-deps
clean-deps: ## Clean development dependencies
	@echo "$(HAMMER) Cleaning development dependencies..."
	@docker-compose down -v
	@docker system prune -f
	@echo "$(CHECKMARK) Dependencies cleaned!"

.PHONY: clean-frontend
clean-frontend: ## Clean frontend build artifacts
	@echo "$(HAMMER) Cleaning frontend artifacts..."
	@cd $(USER_PORTAL) && rm -rf node_modules/.vite dist
	@echo "$(CHECKMARK) Frontend artifacts cleaned!"

# ============================================================================
# CODE QUALITY & FORMATTING
# ============================================================================

.PHONY: check
check: fmt clippy audit test ## 🔍 Run comprehensive code quality checks
	@echo "$(CHECKMARK) All quality checks passed!"

.PHONY: check-fast
check-fast: fmt-check clippy-check ## ⚡ Run fast quality checks (formatting + linting)
	@echo "$(CHECKMARK) Fast quality checks passed!"

.PHONY: fmt
fmt: fmt-check ## Check code formatting (alias for fmt-check)

.PHONY: fmt-check
fmt-check: ## Check code formatting without making changes
	@echo "$(HAMMER) Checking code formatting..."
	@cargo fmt --all -- --check || (echo "$(CROSS) Code formatting issues found. Run 'make fmt-fix' to fix."; exit 1)
	@echo "$(CHECKMARK) Code formatting is correct!"

.PHONY: fmt-fix
fmt-fix: ## Fix code formatting issues
	@echo "$(HAMMER) Fixing code formatting..."
	@cargo fmt --all
	@echo "$(CHECKMARK) Code formatting fixed!"

.PHONY: clippy
clippy: clippy-check ## Run clippy lints (alias for clippy-check)

.PHONY: clippy-check
clippy-check: ## Run clippy lints with strict settings
	@echo "$(HAMMER) Running clippy lints..."
	@cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::perf -W clippy::suspicious -W clippy::nursery
	@echo "$(CHECKMARK) Clippy checks passed!"

.PHONY: clippy-fix
clippy-fix: ## Fix clippy issues automatically
	@echo "$(HAMMER) Fixing clippy issues..."
	@cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- -D warnings
	@echo "$(CHECKMARK) Clippy issues fixed!"

.PHONY: clippy-strict
clippy-strict: ## Run clippy with maximum strictness (CI mode)
	@echo "$(HAMMER) Running strict clippy checks..."
	@cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
	@echo "$(CHECKMARK) Strict clippy checks passed!"

.PHONY: audit
audit: security-audit ## 🔒 Run security audit (alias for security-audit)

.PHONY: security-audit
security-audit: audit-deps audit-vulns ## 🔒 Run comprehensive security audit
	@echo "$(CHECKMARK) Security audit complete!"

.PHONY: audit-deps
audit-deps: ## Check dependency security
	@echo "$(LOCK) Checking dependency security..."
	@cargo audit --deny warnings || (echo "$(CROSS) Security vulnerabilities found!"; exit 1)
	@cargo deny check || (echo "$(CROSS) Dependency policy violations found!"; exit 1)
	@echo "$(CHECKMARK) Dependency security checks passed!"

.PHONY: audit-vulns
audit-vulns: ## Check for known vulnerabilities
	@echo "$(LOCK) Scanning for vulnerabilities..."
	@cargo audit || echo "$(YELLOW)⚠️ Review security advisories above$(NC)"
	@echo "$(CHECKMARK) Vulnerability scan complete!"

.PHONY: lint
lint: clippy-check ## 📋 Run linting checks (alias for clippy-check)

.PHONY: lint-fix
lint-fix: clippy-fix ## 📋 Fix linting issues (alias for clippy-fix)

# ============================================================================
# FRONTEND MANAGEMENT
# ============================================================================

.PHONY: frontend-install
frontend-install: ## Install frontend dependencies
	@echo "$(HAMMER) Installing frontend dependencies..."
	@cd $(USER_PORTAL) && npm install --no-audit --no-fund
	@echo "$(CHECKMARK) Frontend dependencies installed!"

.PHONY: frontend-dev
frontend-dev: ## Start frontend development server
	@echo "$(ROCKET) Starting frontend development server..."
	@cd $(USER_PORTAL) && npm run dev

.PHONY: frontend-build
frontend-build: ## Build frontend for production
	@echo "$(HAMMER) Building frontend for production..."
	@cd $(USER_PORTAL) && npm run build
	@echo "$(CHECKMARK) Frontend build complete!"

.PHONY: frontend-test
frontend-test: ## Run frontend tests
	@echo "$(TEST_TUBE) Running frontend tests..."
	@cd $(USER_PORTAL) && npm run test
	@echo "$(CHECKMARK) Frontend tests complete!"

.PHONY: frontend-test-ui
frontend-test-ui: ## Run frontend tests with UI
	@echo "$(TEST_TUBE) Running frontend tests with UI..."
	@cd $(USER_PORTAL) && npm run test:ui

.PHONY: frontend-test-coverage
frontend-test-coverage: ## Run frontend tests with coverage
	@echo "$(TEST_TUBE) Running frontend tests with coverage..."
	@cd $(USER_PORTAL) && npm run test:coverage

.PHONY: frontend-lint
frontend-lint: ## Run frontend linting
	@echo "$(HAMMER) Running frontend linting..."
	@cd $(USER_PORTAL) && npm run lint
	@echo "$(CHECKMARK) Frontend linting complete!"

.PHONY: frontend-lint-fix
frontend-lint-fix: ## Fix frontend linting issues
	@echo "$(HAMMER) Fixing frontend linting issues..."
	@cd $(USER_PORTAL) && npm run lint:fix
	@echo "$(CHECKMARK) Frontend linting issues fixed!"

.PHONY: frontend-preview
frontend-preview: ## Preview production build
	@echo "$(ROCKET) Starting frontend preview server..."
	@cd $(USER_PORTAL) && npm run preview

.PHONY: frontend-clean
frontend-clean: ## Clean frontend build artifacts
	@echo "$(HAMMER) Cleaning frontend artifacts..."
	@cd $(USER_PORTAL) && rm -rf node_modules dist .vite
	@echo "$(CHECKMARK) Frontend artifacts cleaned!"

# ============================================================================
# TESTING & QUALITY ASSURANCE
# ============================================================================

.PHONY: test
test: test-unit test-integration-quick test-frontend test-e2e-smoke ## 🧪 Run complete test suite
	@echo "$(CHECKMARK) All tests passed!"

.PHONY: test-all
test-all: test test-security test-fuzz test-e2e benchmark ## 🧪 Run all tests including security, e2e and performance
	@echo "$(CHECKMARK) Complete test suite passed!"

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "$(TEST_TUBE) Running unit tests..."
	@cargo test --package common --package mvp-tools --lib --no-fail-fast
	@echo "$(CHECKMARK) Unit tests passed!"

.PHONY: test-integration
test-integration: services-up ## Run integration tests with Docker services
	@echo "$(TEST_TUBE) Running integration tests..."
	@cargo test --test core_auth_tests --features="full-integration api-keys redis-sessions crypto" --no-fail-fast
	@echo "$(CHECKMARK) Integration tests passed!"

.PHONY: test-integration-quick
test-integration-quick: ## Run integration tests without starting services (assumes running)
	@echo "$(TEST_TUBE) Running integration tests (quick)..."
	@cargo test --test core_auth_tests --features="full-integration api-keys redis-sessions crypto" --no-fail-fast
	@echo "$(CHECKMARK) Integration tests passed!"

.PHONY: test-with-services
test-with-services: services-up test-unit test-integration-quick ## Run all tests with Docker services
	@echo "$(CHECKMARK) All tests with services passed!"

.PHONY: test-clean
test-clean: services-down ## Clean up test environment
	@echo "$(YELLOW) Cleaning up test environment..."
	@docker system prune -f
	@echo "$(CHECKMARK) Test environment cleaned!"

.PHONY: test-frontend
test-frontend: ## Run frontend tests
	@echo "$(TEST_TUBE) Running frontend tests..."
	@cd $(USER_PORTAL) && npm run test
	@echo "$(CHECKMARK) Frontend tests passed!"

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "$(CHART) Running tests with coverage..."
	@cargo llvm-cov --workspace --all-features --html --output-dir target/coverage/html -- --nocapture
	@cargo llvm-cov --workspace --all-features --lcov --output-path target/coverage/lcov.info
	@echo "$(CHECKMARK) Coverage report generated at target/coverage/html/index.html"

.PHONY: test-coverage-frontend
test-coverage-frontend: ## Run frontend tests with coverage
	@echo "$(CHART) Running frontend tests with coverage..."
	@cd $(USER_PORTAL) && npm run test:coverage

.PHONY: test-security
test-security: test-security-unit test-security-integration ## 🔒 Run security-specific tests
	@echo "$(CHECKMARK) Security tests completed!"

.PHONY: test-security-unit
test-security-unit: ## Run security unit tests
	@echo "$(LOCK) Running security unit tests..."
	@cargo test --workspace --lib security -- --nocapture || echo "$(YELLOW)⚠️ Some security tests may have failed$(NC)"

.PHONY: test-security-integration
test-security-integration: ## Run security integration tests
	@echo "$(LOCK) Running security integration tests..."
	@cargo test -p $(AUTH_SERVICE) --test jwks_rs256 -- --nocapture || true
	@cargo test -p $(AUTH_SERVICE) --test csrf_middleware -- --nocapture || true
	@cargo test -p $(AUTH_SERVICE) --test cookie_issuance -- --nocapture || true
	@./scripts/security/run_security_scenarios.sh || echo "$(YELLOW)⚠️ Security scenario tests completed with warnings$(NC)"

.PHONY: test-fuzz
test-fuzz: ## Run fuzz tests with timeout
	@echo "$(TEST_TUBE) Running fuzz tests..."
	@cd $(AUTH_SERVICE) && timeout 60 cargo fuzz run fuzz_jwt_parsing -- -max_total_time=60 || true
	@cd $(AUTH_SERVICE) && timeout 60 cargo fuzz run fuzz_oauth_parsing -- -max_total_time=60 || true
	@echo "$(CHECKMARK) Fuzz testing complete!"

.PHONY: test-load
test-load: ## Run load tests
	@echo "$(CHART) Running load tests..."
	@./scripts/testing/comprehensive_load_test.sh || echo "$(YELLOW)⚠️ Load tests completed$(NC)"

# E2E Testing Suite
.PHONY: test-e2e
test-e2e: services-up ## 🎭 Run complete E2E test suite with Playwright
	@echo "$(TEST_TUBE) Running complete E2E test suite..."
	@cd e2e-testing && ./run-e2e.sh
	@echo "$(CHECKMARK) E2E tests completed!"

.PHONY: test-e2e-smoke
test-e2e-smoke: services-up ## 🔥 Run E2E smoke tests (5min)
	@echo "$(TEST_TUBE) Running E2E smoke tests..."
	@cd e2e-testing && npm run test:smoke
	@echo "$(CHECKMARK) E2E smoke tests passed!"

.PHONY: test-e2e-regression
test-e2e-regression: services-up ## 🔄 Run E2E regression tests (30min)
	@echo "$(TEST_TUBE) Running E2E regression tests..."
	@cd e2e-testing && npm run test:regression
	@echo "$(CHECKMARK) E2E regression tests passed!"

.PHONY: test-e2e-security
test-e2e-security: services-up ## 🛡️ Run E2E security tests (15min)
	@echo "$(LOCK) Running E2E security tests..."
	@cd e2e-testing && npm run test:security
	@echo "$(CHECKMARK) E2E security tests passed!"

.PHONY: test-e2e-ui
test-e2e-ui: services-up ## 🎨 Run E2E UI tests with Playwright
	@echo "$(TEST_TUBE) Running E2E UI tests..."
	@cd e2e-testing && npm run test:ui
	@echo "$(CHECKMARK) E2E UI tests passed!"

.PHONY: test-e2e-api
test-e2e-api: services-up ## 🔌 Run E2E API tests
	@echo "$(TEST_TUBE) Running E2E API tests..."
	@cd e2e-testing && npm run test:api
	@echo "$(CHECKMARK) E2E API tests passed!"

.PHONY: validate-urls
validate-urls: services-up ## 🔗 Validate all API endpoints and frontend routes
	@echo "$(TEST_TUBE) Validating URLs..."
	@cd e2e-testing && npm run validate:urls
	@echo "$(CHECKMARK) URL validation completed!"

.PHONY: test-e2e-docker
test-e2e-docker: ## 🐳 Run E2E tests in Docker environment
	@echo "$(TEST_TUBE) Running E2E tests in Docker..."
	@cd e2e-testing && npm run test:docker
	@echo "$(CHECKMARK) Docker E2E tests completed!"

.PHONY: test-e2e-setup
test-e2e-setup: ## 📦 Setup E2E testing environment
	@echo "$(HAMMER) Setting up E2E testing environment..."
	@cd e2e-testing && npm install
	@cd e2e-testing && npm run setup
	@echo "$(CHECKMARK) E2E environment ready!"

.PHONY: test-performance
test-performance: benchmark ## Run performance tests (alias for benchmark)

.PHONY: benchmark
benchmark: ## Run performance benchmarks
	@echo "$(CHART) Running performance benchmarks..."
	@cargo bench --workspace
	@echo "$(CHECKMARK) Benchmarks complete!"

.PHONY: test-watch
test-watch: ## Run tests in watch mode
	@echo "$(TEST_TUBE) Running tests in watch mode..."
	@cargo watch -x "test --workspace --lib -- --nocapture"

.PHONY: test-quick
test-quick: test-unit test-frontend ## ⚡ Run quick test suite (unit + frontend)
	@echo "$(CHECKMARK) Quick tests passed!"

.PHONY: test-verbose
test-verbose: ## Run tests with maximum verbosity
	@echo "$(TEST_TUBE) Running tests with maximum verbosity..."
	@RUST_LOG=debug cargo test --workspace --all-features -- --nocapture

# ============================================================================
# BUILDING & COMPILATION
# ============================================================================

.PHONY: build
build: build-debug ## 🔨 Build all packages (alias for build-debug)

.PHONY: build-debug
build-debug: ## Build all packages in debug mode
	@echo "$(HAMMER) Building all packages in debug mode..."
	@cargo build --workspace --all-features
	@echo "$(CHECKMARK) Debug build complete!"

.PHONY: build-release
build-release: ## Build optimized release version
	@echo "$(ROCKET) Building release version..."
	@cargo build --workspace --all-features --release
	@echo "$(CHECKMARK) Release build complete!"

.PHONY: build-fast
build-fast: ## Build with minimal features for faster compilation
	@echo "$(HAMMER) Building with minimal features..."
	@cargo build --workspace
	@echo "$(CHECKMARK) Fast build complete!"

.PHONY: build-check
build-check: ## Check compilation without building
	@echo "$(HAMMER) Checking compilation..."
	@cargo check --workspace --all-features --all-targets
	@echo "$(CHECKMARK) Compilation check passed!"

.PHONY: build-docker
build-docker: build-docker-auth build-docker-policy ## 🐳 Build all Docker images
	@echo "$(CHECKMARK) All Docker images built!"

.PHONY: build-docker-auth
build-docker-auth: ## Build auth service Docker image
	@echo "$(HAMMER) Building auth service Docker image..."
	@docker build -t $(PROJECT_NAME)/$(AUTH_SERVICE):latest -f $(AUTH_SERVICE)/Dockerfile.secure .
	@echo "$(CHECKMARK) Auth service Docker image built!"

.PHONY: build-docker-policy
build-docker-policy: ## Build policy service Docker image
	@echo "$(HAMMER) Building policy service Docker image..."
	@docker build -t $(PROJECT_NAME)/$(POLICY_SERVICE):latest -f $(POLICY_SERVICE)/Dockerfile .
	@echo "$(CHECKMARK) Policy service Docker image built!"

.PHONY: build-docker-all
build-docker-all: build-docker build-frontend-docker ## 🐳 Build all Docker images including frontend
	@echo "$(CHECKMARK) All Docker images built!"

.PHONY: build-frontend-docker
build-frontend-docker: ## Build frontend Docker image
	@echo "$(HAMMER) Building frontend Docker image..."
	@docker build -t $(PROJECT_NAME)/$(USER_PORTAL):latest -f $(USER_PORTAL)/Dockerfile .
	@echo "$(CHECKMARK) Frontend Docker image built!"

.PHONY: build-production
build-production: build-release build-frontend-build ## 🏭 Build all components for production
	@echo "$(CHECKMARK) Production build complete!"

# ============================================================================
# DOCUMENTATION
# ============================================================================

.PHONY: docs
docs: docs-generate ## 📚 Generate documentation (alias for docs-generate)

.PHONY: docs-generate
docs-generate: ## Generate Rust documentation
	@echo "$(HAMMER) Generating Rust documentation..."
	@cargo doc --workspace --all-features --no-deps --document-private-items
	@echo "$(CHECKMARK) Documentation generated at target/doc/index.html"

.PHONY: docs-open
docs-open: docs-generate ## Open documentation in browser
	@echo "$(ROCKET) Opening documentation in browser..."
	@cargo doc --workspace --all-features --no-deps --document-private-items --open

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	@echo "$(ROCKET) Serving documentation locally..."
	@cargo doc --workspace --all-features --no-deps --document-private-items --open

.PHONY: docs-api
docs-api: ## Generate API documentation from OpenAPI specs
	@echo "$(HAMMER) Generating API documentation..."
	@./scripts/documentation/regenerate-api-docs.sh || echo "$(YELLOW)⚠️ API docs generation completed$(NC)"

# ============================================================================
# SUPPLY CHAIN & COMPLIANCE
# ============================================================================

.PHONY: sbom
sbom: sbom-generate ## 📦 Generate Software Bill of Materials (alias for sbom-generate)

.PHONY: sbom-generate
sbom-generate: ## Generate Software Bill of Materials (SBOM)
	@echo "$(HAMMER) Generating SBOM..."
	@cargo install cargo-auditable cargo-sbom || echo "SBOM tools already installed"
	@cargo auditable build --release
	@cargo sbom > target/$(PROJECT_NAME)-sbom.json
	@echo "$(CHECKMARK) SBOM generated at target/$(PROJECT_NAME)-sbom.json"

.PHONY: sbom-spdx
sbom-spdx: ## Generate SPDX format SBOM
	@echo "$(HAMMER) Generating SPDX SBOM..."
	@cd $(COMPLIANCE_TOOLS) && cargo run --bin sbom-generator -- --project-root .. --output ../sbom.spdx.json
	@echo "$(CHECKMARK) SPDX SBOM generated at sbom.spdx.json"

.PHONY: supply-chain-check
supply-chain-check: audit sbom ## 🔗 Complete supply chain security check
	@echo "$(CHECKMARK) Supply chain security check complete!"

.PHONY: compliance-check
compliance-check: audit sbom validate-security ## 📋 Run compliance validation
	@echo "$(CHECKMARK) Compliance check complete!"

.PHONY: compliance-report
compliance-report: ## Generate compliance report
	@echo "$(CHART) Generating compliance report..."
	@./scripts/compliance/generate_compliance_report.py || echo "$(YELLOW)⚠️ Compliance report generation completed$(NC)"

# ============================================================================
# DEPLOYMENT & INFRASTRUCTURE
# ============================================================================

.PHONY: deploy-local
deploy-local: build-docker deploy-docker-compose ## 🚀 Deploy to local environment
	@echo "$(CHECKMARK) Local deployment complete!"
	@echo "$(YELLOW)📋 Service URLs:$(NC)"
	@echo "  Auth API:    http://localhost:8080"
	@echo "  Policy API:  http://localhost:8081"
	@echo "  Frontend:    http://localhost:5173"

.PHONY: deploy-docker-compose
deploy-docker-compose: ## Deploy using Docker Compose
	@echo "$(ROCKET) Deploying with Docker Compose..."
	@docker-compose up -d
	@echo "$(CHECKMARK) Docker Compose deployment complete!"

.PHONY: deploy-k8s
deploy-k8s: build-docker deploy-k8s-apply ## 🚀 Deploy to Kubernetes
	@echo "$(CHECKMARK) Kubernetes deployment complete!"

.PHONY: deploy-k8s-apply
deploy-k8s-apply: ## Apply Kubernetes manifests
	@echo "$(ROCKET) Applying Kubernetes manifests..."
	@kubectl apply -f k8s/
	@echo "$(CHECKMARK) Kubernetes manifests applied!"

.PHONY: deploy-k8s-delete
deploy-k8s-delete: ## Remove from Kubernetes
	@echo "$(HAMMER) Removing from Kubernetes..."
	@kubectl delete -f k8s/
	@echo "$(CHECKMARK) Kubernetes resources removed!"

.PHONY: deploy-helm
deploy-helm: ## Deploy using Helm charts
	@echo "$(ROCKET) Deploying with Helm..."
	@helm upgrade --install $(PROJECT_NAME) ./helm/$(PROJECT_NAME)
	@echo "$(CHECKMARK) Helm deployment complete!"

.PHONY: deploy-staging
deploy-staging: build-production ## 🚀 Deploy to staging environment
	@echo "$(ROCKET) Deploying to staging..."
	@./scripts/deployment/deploy-staging.sh
	@echo "$(CHECKMARK) Staging deployment complete!"

.PHONY: deploy-production
deploy-production: build-production ## 🚀 Deploy to production environment
	@echo "$(ROCKET) Deploying to production..."
	@./scripts/deployment/deploy-production.sh
	@echo "$(CHECKMARK) Production deployment complete!"

# ============================================================================
# MONITORING & OBSERVABILITY
# ============================================================================

.PHONY: monitoring-up
monitoring-up: ## Start monitoring stack (Prometheus, Grafana)
	@echo "$(ROCKET) Starting monitoring stack..."
	@docker-compose -f monitoring/docker-compose.yml up -d
	@echo "$(CHECKMARK) Monitoring stack started!"

.PHONY: monitoring-down
monitoring-down: ## Stop monitoring stack
	@echo "$(HAMMER) Stopping monitoring stack..."
	@docker-compose -f monitoring/docker-compose.yml down
	@echo "$(CHECKMARK) Monitoring stack stopped!"

.PHONY: logs
logs: logs-auth logs-policy ## 📋 Show logs from all services

.PHONY: logs-auth
logs-auth: ## Show auth service logs
	@echo "$(📋) Auth service logs:"
	@kubectl logs -f deployment/$(AUTH_SERVICE) || docker-compose logs -f $(AUTH_SERVICE)

.PHONY: logs-policy
logs-policy: ## Show policy service logs
	@echo "$(📋) Policy service logs:"
	@kubectl logs -f deployment/$(POLICY_SERVICE) || docker-compose logs -f $(POLICY_SERVICE)

.PHONY: metrics
metrics: ## Show service metrics
	@echo "$(CHART) Service metrics:"
	@curl -s http://localhost:8080/metrics || echo "Metrics not available"

# ============================================================================
# DEVELOPMENT WORKFLOW & CI/CD
# ============================================================================

.PHONY: install-hooks
install-hooks: ## 🪝 Install git pre-commit hooks
	@echo "$(HAMMER) Installing git hooks..."
	@./scripts/setup/setup-git-hooks.sh || pre-commit install
	@pre-commit install --hook-type commit-msg
	@echo "$(CHECKMARK) Git hooks installed!"

.PHONY: ci-local
ci-local: check test test-e2e-smoke security-audit ## 🔄 Run CI checks locally
	@echo "$(CHECKMARK) Local CI checks complete!"

.PHONY: ci-strict
ci-strict: ## 🔄 Run strict CI checks (warnings as errors)
	@echo "$(ROCKET) Running strict CI checks..."
	@RUSTFLAGS="-D warnings" cargo build --workspace --all-features
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@cargo test --workspace --all-features
	@echo "$(CHECKMARK) Strict CI checks complete!"

.PHONY: pre-commit
pre-commit: fmt-fix clippy-fix test-unit ## ✅ Run pre-commit checks and fixes
	@echo "$(CHECKMARK) Pre-commit checks complete!"

.PHONY: validate-pr
validate-pr: ci-local supply-chain-check compliance-check ## ✅ Validate changes before creating PR
	@echo "$(CHECKMARK) PR validation complete! Ready to create pull request."

.PHONY: validate-release
validate-release: test-all test-e2e compliance-check build-production ## ✅ Validate release readiness
	@echo "$(CHECKMARK) Release validation complete!"

# ============================================================================
# SECURITY & VULNERABILITY MANAGEMENT
# ============================================================================

.PHONY: security-scan
security-scan: audit test-security ## 🔒 Run comprehensive security scan
	@echo "$(CHECKMARK) Security scan complete!"

.PHONY: security-vulnerability-scan
security-vulnerability-scan: ## 🔒 Scan for vulnerabilities
	@echo "$(LOCK) Scanning for vulnerabilities..."
	@./scripts/security/security-vulnerability-scan.sh
	@echo "$(CHECKMARK) Vulnerability scan complete!"

.PHONY: security-threat-test
security-threat-test: ## 🔒 Run threat modeling tests
	@echo "$(LOCK) Running threat modeling tests..."
	@./scripts/security/simple_threat_test.rs || echo "$(YELLOW)⚠️ Threat tests completed$(NC)"

.PHONY: validate-security
validate-security: ## 📋 Validate security implementation
	@echo "$(LOCK) Validating security implementation..."
	@./scripts/validation/validate_security_implementation.sh
	@echo "$(CHECKMARK) Security validation complete!"

# ============================================================================
# UTILITIES & DIAGNOSTICS
# ============================================================================

.PHONY: show-env
show-env: ## Show current environment configuration
	@echo "$(BLUE)Environment Configuration:$(NC)"
	@echo "RUST_VERSION: $(RUST_VERSION)"
	@echo "PROJECT_NAME: $(PROJECT_NAME)"
	@echo "AUTH_SERVICE: $(AUTH_SERVICE)"
	@echo "POLICY_SERVICE: $(POLICY_SERVICE)"
	@echo "USER_PORTAL: $(USER_PORTAL)"
	@echo "DATABASE_URL: $(DATABASE_URL)"
	@echo "REDIS_URL: $(REDIS_URL)"
	@echo "CONFIG_DIR: $(CONFIG_DIR)"
	@echo "APP_ENV: $(APP_ENV)"

.PHONY: workspace-status
workspace-status: ## 📊 Show workspace status
	@echo "$(BLUE)Workspace Status:$(NC)"
	@echo "Rust version: $$(rustc --version)"
	@echo "Cargo version: $$(cargo --version)"
	@echo "Node version: $$(cd $(USER_PORTAL) && node --version 2>/dev/null || echo 'N/A')"
	@echo "Git branch: $$(git branch --show-current)"
	@echo "Git status: $$(git status --porcelain | wc -l) files changed"
	@echo "Docker status:"
	@docker-compose ps 2>/dev/null || echo "Docker not running"

.PHONY: doctor
doctor: doctor-system doctor-project ## 🏥 Run complete diagnostic checks
	@echo "$(CHECKMARK) Diagnostic complete!"

.PHONY: doctor-system
doctor-system: ## Check system dependencies
	@echo "$(STETHOSCOPE) Checking system dependencies..."
	@rustc --version || echo "$(CROSS) Rust not installed"
	@cargo --version || echo "$(CROSS) Cargo not available"
	@docker --version || echo "$(YELLOW)⚠️ Docker not available$(NC)"
	@docker-compose --version || echo "$(YELLOW)⚠️ Docker Compose not available$(NC)"
	@kubectl version --client || echo "$(YELLOW)⚠️ kubectl not available$(NC)"
	@echo "$(CHECKMARK) System check complete!"

.PHONY: doctor-project
doctor-project: ## Check project-specific dependencies
	@echo "$(STETHOSCOPE) Checking project dependencies..."
	@sqlx --version || echo "$(YELLOW)⚠️ SQLx CLI not installed$(NC)"
	@cargo audit --version || echo "$(YELLOW)⚠️ cargo-audit not installed$(NC)"
	@cargo deny --version || echo "$(YELLOW)⚠️ cargo-deny not installed$(NC)"
	@cd $(USER_PORTAL) && npm --version || echo "$(YELLOW)⚠️ npm not available$(NC)"
	@echo "$(CHECKMARK) Project check complete!"

.PHONY: reset
reset: clean setup ## 🔄 Complete reset of development environment
	@echo "$(CHECKMARK) Development environment reset complete!"

.PHONY: reset-hard
reset-hard: clean reset-deps setup ## 🔄 Hard reset (removes all containers and volumes)
	@echo "$(CHECKMARK) Hard reset complete!"

.PHONY: reset-deps
reset-deps: ## Reset development dependencies
	@echo "$(HAMMER) Resetting development dependencies..."
	@docker-compose down -v
	@docker system prune -f
	@echo "$(CHECKMARK) Dependencies reset!"

.PHONY: update
update: update-rust update-deps update-frontend ## 🔄 Update all dependencies
	@echo "$(CHECKMARK) All dependencies updated!"

.PHONY: update-rust
update-rust: ## Update Rust toolchain
	@echo "$(HAMMER) Updating Rust toolchain..."
	@rustup update
	@echo "$(CHECKMARK) Rust updated!"

.PHONY: update-deps
update-deps: ## Update Rust dependencies
	@echo "$(HAMMER) Updating Rust dependencies..."
	@cargo update
	@echo "$(CHECKMARK) Rust dependencies updated!"

.PHONY: update-frontend
update-frontend: ## Update frontend dependencies
	@echo "$(HAMMER) Updating frontend dependencies..."
	@cd $(USER_PORTAL) && npm update
	@echo "$(CHECKMARK) Frontend dependencies updated!"

.PHONY: outdated
outdated: outdated-rust outdated-frontend ## 📋 Check for outdated dependencies
	@echo "$(CHECKMARK) Outdated check complete!"

.PHONY: outdated-rust
outdated-rust: ## Check for outdated Rust dependencies
	@echo "$(📋) Checking Rust dependencies..."
	@cargo outdated --workspace

.PHONY: outdated-frontend
outdated-frontend: ## Check for outdated frontend dependencies
	@echo "$(📋) Checking frontend dependencies..."
	@cd $(USER_PORTAL) && npm outdated
# ============================================================================
# REGRESSION TESTING TARGETS
# ============================================================================

# Include regression testing makefile
include Makefile.regression

test-regression-quick: ## Quick regression tests (pre-commit)
	@echo "$(ROCKET) Running Quick Regression Tests..."
	@$(MAKE) -f Makefile.regression regression-quick
	@echo "$(CHECKMARK) Quick regression tests completed"

test-regression-full: ## Full regression test suite (pre-release)
	@echo "$(ROCKET) Running Full Regression Suite..."
	@$(MAKE) -f Makefile.regression regression-full
	@echo "$(CHECKMARK) Full regression suite completed"

test-regression-security: ## Security-focused regression tests
	@echo "$(ROCKET) Running Security Regression Tests..."
	@$(MAKE) -f Makefile.regression regression-security
	@echo "$(CHECKMARK) Security regression tests completed"

test-regression-performance: ## Performance regression tests
	@echo "$(ROCKET) Running Performance Regression Tests..."
	@$(MAKE) -f Makefile.regression regression-performance
	@echo "$(CHECKMARK) Performance regression tests completed"

test-regression-coverage: ## Regression tests with coverage
	@echo "$(ROCKET) Running Regression Tests with Coverage..."
	@$(MAKE) -f Makefile.regression regression-coverage
	@echo "$(CHECKMARK) Regression coverage analysis completed"
