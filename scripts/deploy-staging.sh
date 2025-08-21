#!/bin/bash

# Staging Deployment Script for Rust Security Platform
# Deploys the platform to a staging environment for validation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="rust-security-staging"
REGISTRY="registry.company.com"
IMAGE_TAG="${IMAGE_TAG:-staging-$(date +%Y%m%d-%H%M%S)}"
HELM_RELEASE="rust-security-staging"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Header
echo "================================================================================"
echo "                    RUST SECURITY PLATFORM"
echo "                   Staging Environment Deployment"
echo "================================================================================"
echo

# 1. Pre-deployment checks
log_info "Running pre-deployment checks..."

# Check for required tools
command -v kubectl >/dev/null 2>&1 || { log_error "kubectl is not installed"; exit 1; }
command -v docker >/dev/null 2>&1 || { log_error "docker is not installed"; exit 1; }
command -v helm >/dev/null 2>&1 || { log_error "helm is not installed"; exit 1; }

# Check Kubernetes connectivity
if ! kubectl cluster-info >/dev/null 2>&1; then
    log_error "Cannot connect to Kubernetes cluster"
    exit 1
fi

log_success "Pre-deployment checks passed"

# 2. Build and push Docker images
log_info "Building Docker images..."

# Build auth-service
docker build -t ${REGISTRY}/rust-security/auth-service:${IMAGE_TAG} \
    -f Dockerfile.auth-service . || {
    log_error "Failed to build auth-service image"
    exit 1
}

# Build policy-service
docker build -t ${REGISTRY}/rust-security/policy-service:${IMAGE_TAG} \
    -f Dockerfile.policy-service . || {
    log_error "Failed to build policy-service image"
    exit 1
}

log_success "Docker images built successfully"

# Push images to registry
log_info "Pushing images to registry..."
docker push ${REGISTRY}/rust-security/auth-service:${IMAGE_TAG}
docker push ${REGISTRY}/rust-security/policy-service:${IMAGE_TAG}
log_success "Images pushed to registry"

# 3. Create namespace if it doesn't exist
log_info "Setting up namespace..."
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# Label namespace for pod security
kubectl label namespace ${NAMESPACE} \
    pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted \
    --overwrite

log_success "Namespace configured"

# 4. Deploy infrastructure dependencies
log_info "Deploying infrastructure dependencies..."

# Deploy PostgreSQL for staging
kubectl apply -n ${NAMESPACE} -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgres-config
data:
  POSTGRES_DB: auth_service_staging
  POSTGRES_USER: auth_service
---
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
type: Opaque
stringData:
  POSTGRES_PASSWORD: $(openssl rand -base64 32)
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgresql
spec:
  serviceName: postgresql
  replicas: 1
  selector:
    matchLabels:
      app: postgresql
  template:
    metadata:
      labels:
        app: postgresql
    spec:
      containers:
      - name: postgresql
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
        envFrom:
        - configMapRef:
            name: postgres-config
        - secretRef:
            name: postgres-secret
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: postgresql
spec:
  selector:
    app: postgresql
  ports:
  - port: 5432
    targetPort: 5432
EOF

# Deploy Redis for staging
kubectl apply -n ${NAMESPACE} -f - <<EOF
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
spec:
  serviceName: redis
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        command:
        - redis-server
        - --appendonly yes
        - --requirepass $(openssl rand -base64 32)
        volumeMounts:
        - name: redis-storage
          mountPath: /data
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "200m"
  volumeClaimTemplates:
  - metadata:
      name: redis-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 5Gi
---
apiVersion: v1
kind: Service
metadata:
  name: redis
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
EOF

log_success "Infrastructure dependencies deployed"

# 5. Deploy secrets and configurations
log_info "Creating secrets and configurations..."

# Generate secrets for staging
JWT_SECRET=$(openssl rand -base64 64)
ENCRYPTION_KEY=$(openssl rand -base64 32)
DATABASE_URL="postgresql://auth_service:$(kubectl get secret -n ${NAMESPACE} postgres-secret -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)@postgresql:5432/auth_service_staging"
REDIS_URL="redis://:$(openssl rand -base64 32)@redis:6379"

kubectl create secret generic auth-service-secrets \
    --namespace=${NAMESPACE} \
    --from-literal=jwt-secret="${JWT_SECRET}" \
    --from-literal=encryption-key="${ENCRYPTION_KEY}" \
    --from-literal=database-url="${DATABASE_URL}" \
    --from-literal=redis-url="${REDIS_URL}" \
    --dry-run=client -o yaml | kubectl apply -f -

log_success "Secrets configured"

# 6. Deploy the application
log_info "Deploying Rust Security Platform..."

# Update the deployment with staging image
cat k8s/auth-service/deployment.yaml | \
    sed "s|image: .*auth-service:.*|image: ${REGISTRY}/rust-security/auth-service:${IMAGE_TAG}|g" | \
    sed "s|namespace: rust-security|namespace: ${NAMESPACE}|g" | \
    kubectl apply -n ${NAMESPACE} -f -

# Apply other configurations
kubectl apply -n ${NAMESPACE} -f k8s/auth-service/hpa.yaml
kubectl apply -n ${NAMESPACE} -f k8s/auth-service/pdb.yaml
kubectl apply -n ${NAMESPACE} -f k8s/network-policies/
kubectl apply -n ${NAMESPACE} -f k8s/rbac/

log_success "Application deployed"

# 7. Deploy monitoring stack
log_info "Deploying monitoring..."

# Create monitoring namespace
kubectl create namespace monitoring-staging --dry-run=client -o yaml | kubectl apply -f -

# Deploy Prometheus
kubectl apply -n monitoring-staging -f k8s/monitoring/prometheus-config.yaml

# Deploy Grafana
kubectl apply -n monitoring-staging -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasources
data:
  prometheus.yaml: |
    apiVersion: 1
    datasources:
    - name: Prometheus
      type: prometheus
      access: proxy
      url: http://prometheus:9090
      isDefault: true
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
spec:
  replicas: 1
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
      - name: grafana
        image: grafana/grafana:10.0.0
        ports:
        - containerPort: 3000
        env:
        - name: GF_SECURITY_ADMIN_PASSWORD
          value: "admin"
        - name: GF_INSTALL_PLUGINS
          value: "redis-datasource,postgres-datasource"
        volumeMounts:
        - name: datasources
          mountPath: /etc/grafana/provisioning/datasources
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "200m"
      volumes:
      - name: datasources
        configMap:
          name: grafana-datasources
---
apiVersion: v1
kind: Service
metadata:
  name: grafana
spec:
  selector:
    app: grafana
  ports:
  - port: 3000
    targetPort: 3000
  type: LoadBalancer
EOF

log_success "Monitoring deployed"

# 8. Wait for deployment to be ready
log_info "Waiting for deployment to be ready..."

kubectl rollout status deployment/auth-service -n ${NAMESPACE} --timeout=300s || {
    log_error "Deployment failed to become ready"
    kubectl describe deployment auth-service -n ${NAMESPACE}
    exit 1
}

log_success "Deployment is ready"

# 9. Run smoke tests
log_info "Running smoke tests..."

# Get the service endpoint
SERVICE_IP=$(kubectl get svc auth-service -n ${NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")

if [ "$SERVICE_IP" == "pending" ]; then
    log_warning "LoadBalancer IP not yet assigned, using port-forward for testing"
    kubectl port-forward -n ${NAMESPACE} svc/auth-service 8080:8080 &
    PF_PID=$!
    sleep 5
    SERVICE_URL="http://localhost:8080"
else
    SERVICE_URL="http://${SERVICE_IP}:8080"
fi

# Test health endpoint
if curl -f ${SERVICE_URL}/health >/dev/null 2>&1; then
    log_success "Health check passed"
else
    log_error "Health check failed"
    [ ! -z "${PF_PID:-}" ] && kill $PF_PID
    exit 1
fi

# Test metrics endpoint
if curl -f ${SERVICE_URL}/metrics >/dev/null 2>&1; then
    log_success "Metrics endpoint accessible"
else
    log_warning "Metrics endpoint not accessible"
fi

[ ! -z "${PF_PID:-}" ] && kill $PF_PID

# 10. Output deployment information
echo
echo "================================================================================"
echo "                         DEPLOYMENT SUMMARY"
echo "================================================================================"
echo
echo "🎯 Deployment Details:"
echo "   Namespace:      ${NAMESPACE}"
echo "   Image Tag:      ${IMAGE_TAG}"
echo "   Auth Service:   ${REGISTRY}/rust-security/auth-service:${IMAGE_TAG}"
echo "   Policy Service: ${REGISTRY}/rust-security/policy-service:${IMAGE_TAG}"
echo
echo "📊 Access Points:"
if [ "$SERVICE_IP" != "pending" ]; then
    echo "   API Endpoint:   http://${SERVICE_IP}:8080"
else
    echo "   API Endpoint:   Use 'kubectl port-forward -n ${NAMESPACE} svc/auth-service 8080:8080'"
fi
echo "   Grafana:        kubectl port-forward -n monitoring-staging svc/grafana 3000:3000"
echo "   Prometheus:     kubectl port-forward -n monitoring-staging svc/prometheus 9090:9090"
echo
echo "🔍 Useful Commands:"
echo "   View logs:      kubectl logs -n ${NAMESPACE} -l app=auth-service -f"
echo "   Get pods:       kubectl get pods -n ${NAMESPACE}"
echo "   Describe:       kubectl describe deployment auth-service -n ${NAMESPACE}"
echo "   Exec into pod:  kubectl exec -it -n ${NAMESPACE} deploy/auth-service -- /bin/sh"
echo
echo "================================================================================"
echo "✅ Staging deployment completed successfully!"
echo "================================================================================"