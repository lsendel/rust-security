#!/bin/bash

set -euo pipefail

echo "🚀 Starting production deployment..."

# Configuration
NAMESPACE="rust-security"
HELM_RELEASE="rust-security-platform"
DOCKER_REGISTRY="ghcr.io/your-org"
IMAGE_TAG="${GITHUB_SHA:-latest}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Pre-deployment checks
log "Running pre-deployment checks..."

# Check if kubectl is available and configured
if ! command -v kubectl &> /dev/null; then
    error "kubectl is not installed or not in PATH"
fi

# Check if helm is available
if ! command -v helm &> /dev/null; then
    error "helm is not installed or not in PATH"
fi

# Check cluster connectivity
if ! kubectl cluster-info &> /dev/null; then
    error "Cannot connect to Kubernetes cluster"
fi

# Check if namespace exists
if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
    log "Creating namespace $NAMESPACE..."
    kubectl create namespace "$NAMESPACE"
fi

# Security checks
log "Running security checks..."

# Check for secrets
required_secrets=("database-credentials" "jwt-secret" "tls-certificates")
for secret in "${required_secrets[@]}"; do
    if ! kubectl get secret "$secret" -n "$NAMESPACE" &> /dev/null; then
        warn "Required secret '$secret' not found in namespace '$NAMESPACE'"
        echo "Please create the secret before deployment:"
        echo "kubectl create secret generic $secret -n $NAMESPACE --from-literal=..."
    fi
done

# Build and push Docker images
log "Building and pushing Docker images..."

# Build the application
log "Building Rust application..."
cargo build --release --workspace

# Build Docker image
log "Building Docker image..."
docker build -t "$DOCKER_REGISTRY/rust-security-platform:$IMAGE_TAG" .
docker build -t "$DOCKER_REGISTRY/rust-security-platform:latest" .

# Push to registry
log "Pushing Docker images..."
docker push "$DOCKER_REGISTRY/rust-security-platform:$IMAGE_TAG"
docker push "$DOCKER_REGISTRY/rust-security-platform:latest"

# Database migrations
log "Running database migrations..."
# Add your migration commands here
# kubectl run migration --image="$DOCKER_REGISTRY/rust-security-platform:$IMAGE_TAG" \
#   --restart=Never --rm -i --tty \
#   --command -- /usr/local/bin/migrate

# Deploy with Helm
log "Deploying with Helm..."

# Update Helm dependencies
helm dependency update ./helm/rust-security-platform/

# Deploy or upgrade
if helm list -n "$NAMESPACE" | grep -q "$HELM_RELEASE"; then
    log "Upgrading existing release..."
    helm upgrade "$HELM_RELEASE" ./helm/rust-security-platform/ \
        --namespace "$NAMESPACE" \
        --set image.tag="$IMAGE_TAG" \
        --set global.imageRegistry="$DOCKER_REGISTRY" \
        --timeout 10m \
        --wait
else
    log "Installing new release..."
    helm install "$HELM_RELEASE" ./helm/rust-security-platform/ \
        --namespace "$NAMESPACE" \
        --set image.tag="$IMAGE_TAG" \
        --set global.imageRegistry="$DOCKER_REGISTRY" \
        --timeout 10m \
        --wait
fi

# Post-deployment verification
log "Running post-deployment verification..."

# Wait for pods to be ready
log "Waiting for pods to be ready..."
kubectl wait --for=condition=ready pod -l app=auth-service -n "$NAMESPACE" --timeout=300s
kubectl wait --for=condition=ready pod -l app=policy-service -n "$NAMESPACE" --timeout=300s

# Health checks
log "Running health checks..."
AUTH_SERVICE_URL=$(kubectl get service auth-service -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
if [ -z "$AUTH_SERVICE_URL" ]; then
    AUTH_SERVICE_URL=$(kubectl get service auth-service -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}')
fi

# Test health endpoint
if curl -f "http://$AUTH_SERVICE_URL/health" &> /dev/null; then
    log "✅ Auth service health check passed"
else
    error "❌ Auth service health check failed"
fi

# Smoke tests
log "Running smoke tests..."
./scripts/run-smoke-tests.sh "$NAMESPACE"

# Update monitoring
log "Updating monitoring configuration..."
kubectl apply -f monitoring/prometheus-rules.yaml -n "$NAMESPACE"
kubectl apply -f monitoring/service-monitors.yaml -n "$NAMESPACE"

# Backup current state
log "Creating deployment backup..."
kubectl get all -n "$NAMESPACE" -o yaml > "backup-$(date +%Y%m%d-%H%M%S).yaml"

# Deployment summary
log "📊 Deployment Summary:"
echo "  • Namespace: $NAMESPACE"
echo "  • Release: $HELM_RELEASE"
echo "  • Image Tag: $IMAGE_TAG"
echo "  • Deployment Time: $(date)"

# Get service URLs
log "🌐 Service URLs:"
kubectl get ingress -n "$NAMESPACE" -o custom-columns=NAME:.metadata.name,HOSTS:.spec.rules[*].host,ADDRESS:.status.loadBalancer.ingress[*].ip

log "✅ Production deployment completed successfully!"

# Post-deployment notifications
if [ -n "${SLACK_WEBHOOK_URL:-}" ]; then
    curl -X POST -H 'Content-type: application/json' \
        --data "{\"text\":\"🚀 Rust Security Platform deployed successfully to production\nNamespace: $NAMESPACE\nImage: $IMAGE_TAG\"}" \
        "$SLACK_WEBHOOK_URL"
fi

log "🎉 Deployment complete! Monitor the application at your configured URLs."
