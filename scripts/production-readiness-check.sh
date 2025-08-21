#!/bin/bash

# Production Readiness Checklist for Rust Security Platform
# This script validates all critical components for production deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_CHECKS++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNING_CHECKS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_CHECKS++))
}

check_item() {
    ((TOTAL_CHECKS++))
    local description="$1"
    local command="$2"
    local required="${3:-true}"
    
    echo -n "Checking: $description... "
    
    if eval "$command" >/dev/null 2>&1; then
        log_success "$description"
        return 0
    else
        if [[ "$required" == "true" ]]; then
            log_error "$description"
            return 1
        else
            log_warning "$description (optional)"
            return 0
        fi
    fi
}

# Header
echo "================================================================================"
echo "                    RUST SECURITY PLATFORM"
echo "                   Production Readiness Check"
echo "================================================================================"
echo

# 1. Core Dependencies
echo "🔧 Core Dependencies"
echo "--------------------------------------------------------------------------------"

check_item "Rust toolchain" "command -v rustc"
check_item "Cargo package manager" "command -v cargo"
check_item "Docker runtime" "command -v docker"
check_item "Kubernetes CLI" "command -v kubectl"
check_item "Helm package manager" "command -v helm"

# 2. Security Configuration
echo
echo "🔒 Security Configuration"
echo "--------------------------------------------------------------------------------"

check_item "ExternalSecrets configuration" "test -f k8s/external-secrets/external-secrets-deployment.yaml"
check_item "Security hardening scripts" "test -f scripts/security/run-security-hardening.sh"
check_item "TLS certificates configuration" "test -f security/configs/tls-config.yaml"
check_item "Network policies" "test -f k8s/network-policies/auth-service-network-policy.yaml"
check_item "Pod security standards" "test -f k8s/security/pod-security-standards.yaml"
check_item "RBAC configuration" "test -f k8s/rbac/auth-service-rbac.yaml"

# 3. Monitoring & Observability
echo
echo "📊 Monitoring & Observability"
echo "--------------------------------------------------------------------------------"

check_item "Prometheus configuration" "test -f k8s/monitoring/prometheus-config.yaml"
check_item "Grafana dashboards" "test -f k8s/observability/grafana-tracing-dashboards.yaml"
check_item "AlertManager rules" "test -f monitoring/alertmanager/security-alerts.yml"
check_item "OpenTelemetry setup" "test -f k8s/observability/opentelemetry-deployment.yaml"
check_item "Distributed tracing config" "test -f auth-service/src/observability.rs"

# 4. High Availability & Scaling
echo
echo "⚡ High Availability & Scaling"
echo "--------------------------------------------------------------------------------"

check_item "Horizontal Pod Autoscaler" "test -f k8s/auth-service/hpa.yaml"
check_item "Pod Disruption Budget" "test -f k8s/auth-service/pdb.yaml"
check_item "Multi-zone deployment" "grep -q 'topology.kubernetes.io/zone' k8s/auth-service/deployment.yaml"
check_item "Resource limits defined" "grep -q 'resources:' k8s/auth-service/deployment.yaml"
check_item "Readiness probes" "grep -q 'readinessProbe' k8s/auth-service/deployment.yaml"
check_item "Liveness probes" "grep -q 'livenessProbe' k8s/auth-service/deployment.yaml"

# 5. Data Persistence & Backup
echo
echo "💾 Data Persistence & Backup"
echo "--------------------------------------------------------------------------------"

check_item "Redis configuration" "test -f k8s/redis/redis-deployment.yaml"
check_item "Persistent volumes" "grep -q 'PersistentVolumeClaim' k8s/redis/redis-deployment.yaml"
check_item "Backup strategy" "test -f scripts/backup/backup-strategy.md" "false"
check_item "Disaster recovery plan" "test -f runbooks/disaster-recovery.md" "false"

# 6. CI/CD Pipeline
echo
echo "🚀 CI/CD Pipeline"
echo "--------------------------------------------------------------------------------"

check_item "GitHub Actions workflow" "test -f .github/workflows/ci-cd-pipeline.yml"
check_item "Security scanning" "grep -q 'trivy' .github/workflows/ci-cd-pipeline.yml"
check_item "Container signing" "grep -q 'cosign' .github/workflows/ci-cd-pipeline.yml"
check_item "SBOM generation" "grep -q 'cyclonedx' .github/workflows/ci-cd-pipeline.yml"
check_item "Automated testing" "grep -q 'cargo test' .github/workflows/ci-cd-pipeline.yml"

# 7. Performance & Load Testing
echo
echo "🔥 Performance & Load Testing"
echo "--------------------------------------------------------------------------------"

check_item "Load testing scripts" "test -f scripts/performance/load-tests/auth-service-k6.js"
check_item "Performance budgets" "test -f scripts/performance/performance-budget-monitor.sh"
check_item "Benchmark tests" "test -f auth-service/benches/auth_benchmarks.rs" "false"
check_item "Stress testing config" "test -f scripts/chaos-engineering/chaos-experiments.yaml"

# 8. Documentation
echo
echo "📚 Documentation"
echo "--------------------------------------------------------------------------------"

check_item "README documentation" "test -f README.md"
check_item "API documentation" "test -f api-contracts/README.md"
check_item "Operations guide" "test -f docs/operations/OPERATIONS_GUIDE.md"
check_item "Security documentation" "test -f docs/security/SECURITY_IMPLEMENTATION_GUIDE.md"
check_item "Deployment guide" "test -f docs/deployment/DEPLOYMENT_GUIDE.md" "false"
check_item "Troubleshooting guide" "test -f docs/troubleshooting/TROUBLESHOOTING_GUIDE.md" "false"

# 9. Configuration Management
echo
echo "⚙️ Configuration Management"
echo "--------------------------------------------------------------------------------"

check_item "Environment configurations" "test -d config/environments"
check_item "Helm values files" "test -f helm/auth-service/values.yaml"
check_item "Configuration validation" "test -f scripts/config/validate-config.sh" "false"
check_item "Secret management" "test -f .security/dependency-exceptions.toml"

# 10. Compliance & Auditing
echo
echo "✅ Compliance & Auditing"
echo "--------------------------------------------------------------------------------"

check_item "Audit logging configuration" "grep -q 'audit' auth-service/src/main.rs" "false"
check_item "Compliance scripts" "test -f scripts/compliance/nist-800-53-check.py" "false"
check_item "Security policies" "test -f docs/security/SECURITY_POLICIES.md" "false"
check_item "Threat modeling docs" "test -f docs/threat-modeling/COMPREHENSIVE_THREAT_MODEL.md"

# 11. Code Quality
echo
echo "🧹 Code Quality"
echo "--------------------------------------------------------------------------------"

echo -n "Checking: Rust code compilation... "
if cargo check --all-targets --all-features >/dev/null 2>&1; then
    log_success "Rust code compilation"
else
    log_error "Rust code compilation"
fi

echo -n "Checking: Clippy lints... "
if cargo clippy --all-targets --all-features -- -D warnings >/dev/null 2>&1; then
    log_success "Clippy lints"
else
    log_warning "Clippy lints (some warnings found)"
fi

echo -n "Checking: Code formatting... "
if cargo fmt --all -- --check >/dev/null 2>&1; then
    log_success "Code formatting"
else
    log_warning "Code formatting (needs formatting)"
fi

echo -n "Checking: Unit tests... "
if cargo test --all-targets --all-features >/dev/null 2>&1; then
    log_success "Unit tests"
else
    log_error "Unit tests"
fi

# 12. Container Security
echo
echo "🐳 Container Security"
echo "--------------------------------------------------------------------------------"

check_item "Distroless base images" "grep -q 'gcr.io/distroless' security/configs/Dockerfile.security"
check_item "Non-root user" "grep -q 'USER' security/configs/Dockerfile.security"
check_item "Security scanning config" "test -f .github/workflows/security-audit.yml"
check_item "Container signing setup" "grep -q 'cosign' .github/workflows/ci-cd-pipeline.yml"

# Final Summary
echo
echo "================================================================================"
echo "                             SUMMARY REPORT"
echo "================================================================================"
echo

echo "📊 Check Results:"
echo "   Total Checks:   $TOTAL_CHECKS"
echo "   ✅ Passed:       $PASSED_CHECKS"
echo "   ⚠️  Warnings:     $WARNING_CHECKS"
echo "   ❌ Failed:       $FAILED_CHECKS"
echo

# Calculate score
SCORE=$(echo "scale=1; ($PASSED_CHECKS + $WARNING_CHECKS * 0.5) * 100 / $TOTAL_CHECKS" | bc -l 2>/dev/null || echo "0")

echo "🎯 Production Readiness Score: ${SCORE}%"
echo

# Recommendations based on score
if (( $(echo "$SCORE >= 90" | bc -l) )); then
    echo "🎉 ${GREEN}EXCELLENT${NC}: Platform is production-ready!"
    echo "   Recommendation: Proceed with staged rollout to production."
elif (( $(echo "$SCORE >= 80" | bc -l) )); then
    echo "✅ ${GREEN}GOOD${NC}: Platform is mostly production-ready."
    echo "   Recommendation: Address critical failures before production deployment."
elif (( $(echo "$SCORE >= 70" | bc -l) )); then
    echo "⚠️  ${YELLOW}FAIR${NC}: Platform needs improvement before production."
    echo "   Recommendation: Address all failures and most warnings."
else
    echo "❌ ${RED}POOR${NC}: Platform is not ready for production."
    echo "   Recommendation: Significant work needed before production deployment."
fi

echo
echo "================================================================================"

# Exit with appropriate code
if (( FAILED_CHECKS > 0 )); then
    echo "❌ Production readiness check failed with $FAILED_CHECKS critical issues."
    exit 1
elif (( WARNING_CHECKS > 5 )); then
    echo "⚠️  Production readiness check passed with warnings. Review recommended."
    exit 2
else
    echo "✅ Production readiness check passed successfully!"
    exit 0
fi