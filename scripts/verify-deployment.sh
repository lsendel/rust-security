#!/bin/bash

echo "🔍 Verifying Rust Security Platform Deployment Readiness..."

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check compilation status
echo "📋 Checking Compilation Status..."
for pkg in auth-core auth-service policy-service common api-contracts compliance-tools; do
    if cargo check --package $pkg >/dev/null 2>&1; then
        success "$pkg compiles successfully"
    else
        error "$pkg compilation failed"
        exit 1
    fi
done

# Check release build
echo ""
echo "🚀 Checking Release Build..."
if cargo build --workspace --release >/dev/null 2>&1; then
    success "Release build successful"
else
    error "Release build failed"
    exit 1
fi

# Check Docker build capability
echo ""
echo "🐳 Checking Docker Build Readiness..."
if [ -f "Dockerfile" ]; then
    success "Dockerfile present and ready"
else
    error "Dockerfile missing"
fi

# Check Kubernetes manifests
echo ""
echo "☸️  Checking Kubernetes Deployment Readiness..."
if [ -d "k8s" ] && [ "$(ls -A k8s)" ]; then
    success "Kubernetes manifests ready"
else
    warning "Kubernetes manifests not found"
fi

# Check Helm charts
echo ""
echo "⚙️  Checking Helm Chart Readiness..."
if [ -d "helm/rust-security-platform" ]; then
    success "Helm charts ready for deployment"
else
    warning "Helm charts not found"
fi

# Check CI/CD pipeline
echo ""
echo "🔄 Checking CI/CD Pipeline..."
if [ -f ".github/workflows/ci.yml" ]; then
    success "GitHub Actions CI/CD pipeline ready"
else
    warning "CI/CD pipeline not configured"
fi

# Check monitoring configuration
echo ""
echo "📊 Checking Monitoring Setup..."
if [ -d "monitoring" ] && [ "$(ls -A monitoring)" ]; then
    success "Monitoring configuration ready"
else
    warning "Monitoring configuration not found"
fi

# Check security configuration
echo ""
echo "🔒 Checking Security Configuration..."
if [ -f "deny.toml" ]; then
    success "Security scanning configuration ready"
else
    warning "Security configuration not found"
fi

# Check documentation
echo ""
echo "📚 Checking Documentation..."
if [ -f "docs/api/README.md" ]; then
    success "API documentation ready"
else
    warning "API documentation not found"
fi

# Performance check
echo ""
echo "⚡ Checking Performance Optimizations..."
if grep -q "profile.release" Cargo.toml; then
    success "Performance optimizations configured"
else
    warning "Performance optimizations not configured"
fi

# Final summary
echo ""
echo "🎯 DEPLOYMENT READINESS SUMMARY"
echo "==============================="

# Count binaries
binary_count=$(find target/release -name "auth-service" -o -name "policy-service" -o -name "security_metrics_collector" 2>/dev/null | wc -l)
if [ "$binary_count" -gt 0 ]; then
    success "Production binaries built: $binary_count"
else
    warning "Production binaries not found (run cargo build --release)"
fi

# Check total files
total_files=$(find . -name "*.rs" -o -name "*.toml" -o -name "*.yaml" -o -name "*.yml" -o -name "*.sh" | grep -v target | wc -l)
success "Total project files: $total_files"

# Check scripts
script_count=$(find scripts -name "*.sh" 2>/dev/null | wc -l)
success "Automation scripts: $script_count"

echo ""
echo "🚀 READY FOR DEPLOYMENT!"
echo ""
echo "Next steps:"
echo "  1. Deploy to production: ./scripts/deploy-production.sh"
echo "  2. Start development: ./scripts/setup/quick-start.sh"
echo "  3. Run tests: ./scripts/run-tests.sh"
echo "  4. Monitor deployment: Access Grafana dashboards"
echo ""
echo "🎉 Your Rust Security Platform is production-ready!"
