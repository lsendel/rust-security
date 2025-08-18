# Deployment Guide

This guide covers deploying the Rust Security Workspace to various environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development](#local-development)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Production Considerations](#production-considerations)
- [Monitoring and Observability](#monitoring-and-observability)
- [Security Hardening](#security-hardening)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Tools

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **Docker**: For containerized deployments
- **Kubernetes**: For production deployments
- **kubectl**: Kubernetes command-line tool
- **Helm** (optional): For package management

### Required Services

- **Redis**: For token storage (production)
- **PostgreSQL** (optional): For user data in integration example
- **Prometheus**: For metrics collection
- **Jaeger** (optional): For distributed tracing

## Local Development

### 1. Environment Setup

```bash
# Clone the repository
git clone <repository-url>
cd rust-security

# Copy environment template
cp .env.example .env

# Edit environment variables
vim .env
```

### 2. Required Environment Variables

```bash
# Server Configuration
BIND_ADDR=127.0.0.1:8080
RUST_LOG=info,auth_service=debug

# Security Configuration
JWT_SECRET=your-super-secret-jwt-key-change-in-production
CLIENT_CREDENTIALS=test_client:test_secret;admin_client:admin_secret
ALLOWED_SCOPES=read,write,admin
REQUEST_SIGNING_SECRET=your-request-signing-secret

# Redis Configuration (optional for development)
REDIS_URL=redis://localhost:6379

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60

# External URLs
EXTERNAL_BASE_URL=http://localhost:8080
ALLOWED_ORIGINS=http://localhost:3000
```

### 3. Start Services

```bash
# Start Redis (if using)
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Start auth-service
cargo run -p auth-service

# Start policy-service (in another terminal)
cargo run -p policy-service
```

### 4. Verify Deployment

```bash
# Check health endpoints
curl http://localhost:8080/health
curl http://localhost:8081/health

# Test token issuance
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret"
```

## Docker Deployment

### 1. Build Images

```bash
# Build auth-service
docker build -t auth-service:latest auth-service/

# Build policy-service
docker build -t policy-service:latest policy-service/
```

### 2. Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 3. Production Docker Build

```bash
# Use production Dockerfile
docker build -f auth-service/Dockerfile.prod -t auth-service:prod auth-service/
```

## Kubernetes Deployment

### 1. Prerequisites

```bash
# Ensure kubectl is configured
kubectl cluster-info

# Create namespace
kubectl apply -f k8s/namespace.yaml
```

### 2. Secrets Management

```bash
# Copy secrets template
cp k8s/secrets.yaml.template k8s/secrets.yaml

# Generate secrets
JWT_SECRET=$(openssl rand -base64 32)
CLIENT_CREDS="client1:$(openssl rand -base64 16);client2:$(openssl rand -base64 16)"
SIGNING_SECRET=$(openssl rand -base64 32)

# Encode secrets
echo -n "$JWT_SECRET" | base64
echo -n "$CLIENT_CREDS" | base64
echo -n "$SIGNING_SECRET" | base64

# Edit secrets.yaml with encoded values
vim k8s/secrets.yaml

# Apply secrets
kubectl apply -f k8s/secrets.yaml
```

### 3. Deploy Infrastructure

```bash
# Deploy Redis
kubectl apply -f k8s/redis.yaml

# Wait for Redis to be ready
kubectl wait --for=condition=ready pod -l app=redis -n rust-security --timeout=300s
```

### 4. Deploy Applications

```bash
# Deploy auth-service
kubectl apply -f k8s/auth-service.yaml

# Deploy policy-service
kubectl apply -f k8s/policy-service.yaml

# Apply network policies
kubectl apply -f k8s/network-policies.yaml
```

### 5. Verify Deployment

```bash
# Check pod status
kubectl get pods -n rust-security

# Check services
kubectl get svc -n rust-security

# Check ingress
kubectl get ingress -n rust-security

# View logs
kubectl logs -f deployment/auth-service -n rust-security
```

### 6. Port Forwarding (for testing)

```bash
# Forward auth-service
kubectl port-forward svc/auth-service 8080:8080 -n rust-security

# Forward policy-service
kubectl port-forward svc/policy-service 8081:8080 -n rust-security
```

## Production Considerations

### 1. Security Hardening

#### Environment Variables
- Use strong, randomly generated secrets
- Set `ENVIRONMENT=production`
- Configure proper CORS origins
- Use HTTPS endpoints for `EXTERNAL_BASE_URL`

#### Network Security
- Enable network policies
- Use TLS for all communications
- Implement proper firewall rules
- Use private container registries

#### Container Security
- Run as non-root user (already configured)
- Use read-only root filesystem
- Drop all capabilities
- Scan images for vulnerabilities

### 2. High Availability

#### Redis Configuration
```yaml
# Use Redis Cluster or Sentinel for HA
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
data:
  redis.conf: |
    cluster-enabled yes
    cluster-config-file nodes.conf
    cluster-node-timeout 5000
    appendonly yes
```

#### Application Scaling
```yaml
# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### 3. Resource Management

#### Resource Requests and Limits
```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

#### Persistent Storage
```yaml
# Use appropriate storage class
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
spec:
  storageClassName: fast-ssd
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

## Monitoring and Observability

### 1. Metrics Collection

```bash
# Deploy Prometheus (using Helm)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace

# Apply ServiceMonitors
kubectl apply -f k8s/monitoring.yaml
```

### 2. Alerting

```bash
# Alerts are defined in k8s/monitoring.yaml
# Configure AlertManager for notifications
kubectl get prometheusrules -n rust-security
```

### 3. Distributed Tracing

```bash
# Deploy Jaeger
kubectl create namespace observability
kubectl apply -f https://github.com/jaegertracing/jaeger-operator/releases/download/v1.49.0/jaeger-operator.yaml -n observability

# Enable tracing feature
# Rebuild with: cargo build --features tracing
```

### 4. Log Aggregation

```bash
# Deploy ELK stack or use cloud logging
# Configure structured logging in production
export RUST_LOG=info,auth_service=debug
export LOG_FORMAT=json
```

## Security Hardening

### 1. TLS Configuration

```yaml
# Use cert-manager for automatic certificate management
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
```

### 2. Pod Security Standards

```yaml
# Apply Pod Security Standards
apiVersion: v1
kind: Namespace
metadata:
  name: rust-security
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 3. RBAC Configuration

```yaml
# Minimal RBAC permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: rust-security-role
  namespace: rust-security
rules:
- apiGroups: [""]
  resources: ["configmaps", "secrets"]
  verbs: ["get", "list"]
```

## Troubleshooting

### Common Issues

#### 1. Service Not Starting
```bash
# Check logs
kubectl logs -f deployment/auth-service -n rust-security

# Check configuration
kubectl describe configmap auth-service-config -n rust-security

# Check secrets
kubectl get secrets -n rust-security
```

#### 2. Redis Connection Issues
```bash
# Test Redis connectivity
kubectl exec -it deployment/auth-service -n rust-security -- sh
# Inside container:
redis-cli -h redis ping
```

#### 3. Certificate Issues
```bash
# Check certificate status
kubectl describe certificate auth-service-tls -n rust-security

# Check cert-manager logs
kubectl logs -f deployment/cert-manager -n cert-manager
```

#### 4. Network Policy Issues
```bash
# Temporarily disable network policies for testing
kubectl delete networkpolicy --all -n rust-security

# Test connectivity
kubectl exec -it deployment/auth-service -n rust-security -- curl http://redis:6379
```

### Performance Tuning

#### 1. JVM-like Tuning for Rust
```bash
# Set appropriate stack size
export RUST_MIN_STACK=8388608

# Enable optimizations
export RUSTFLAGS="-C target-cpu=native"
```

#### 2. Redis Tuning
```bash
# Redis configuration for production
maxmemory 2gb
maxmemory-policy allkeys-lru
tcp-keepalive 300
timeout 0
```

#### 3. Load Testing
```bash
# Run load tests
./scripts/load_test.sh http://auth.example.com 50 1000

# Monitor during load test
kubectl top pods -n rust-security
```

### Backup and Recovery

#### 1. Redis Backup
```bash
# Create Redis backup
kubectl exec deployment/redis -n rust-security -- redis-cli BGSAVE

# Copy backup
kubectl cp rust-security/redis-pod:/data/dump.rdb ./redis-backup.rdb
```

#### 2. Configuration Backup
```bash
# Backup all configurations
kubectl get all,configmaps,secrets,ingress,networkpolicies -n rust-security -o yaml > backup.yaml
```

## Maintenance

### 1. Updates and Rollouts

```bash
# Update image
kubectl set image deployment/auth-service auth-service=auth-service:v2.0.0 -n rust-security

# Monitor rollout
kubectl rollout status deployment/auth-service -n rust-security

# Rollback if needed
kubectl rollout undo deployment/auth-service -n rust-security
```

### 2. Health Checks

```bash
# Regular health checks
curl -f https://auth.example.com/health
curl -f https://policy.example.com/health

# Automated health monitoring
kubectl get pods -n rust-security -o wide
```

This deployment guide provides comprehensive instructions for deploying the Rust Security Workspace in various environments with proper security, monitoring, and operational considerations.
