# Production Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Rust Security Platform in production environments, covering Docker, Kubernetes, and cloud provider-specific deployments.

### Production Architecture Overview

```mermaid
graph TB
    subgraph "External Traffic"
        Users[Users]
        Apps[Applications]
        APIs[API Clients]
    end
    
    subgraph "Edge Layer"
        CDN[CloudFlare/CDN]
        WAF[Web Application Firewall]
        LB[Load Balancer<br/>ALB/ELB/GCP LB]
    end
    
    subgraph "Kubernetes Cluster"
        subgraph "Ingress"
            Ingress[NGINX/Istio Ingress]
        end
        
        subgraph "Auth Namespace"
            AuthPods[Auth Service Pods<br/>3+ replicas]
            AuthHPA[Horizontal Pod Autoscaler]
        end
        
        subgraph "Policy Namespace"
            PolicyPods[Policy Service Pods<br/>2+ replicas]
            PolicyHPA[HPA]
        end
        
        subgraph "Monitoring Namespace"
            Prometheus[Prometheus]
            Grafana[Grafana]
            AlertManager[AlertManager]
        end
    end
    
    subgraph "Data Layer"
        PostgresCluster[(PostgreSQL<br/>Primary + Replica)]
        RedisCluster[(Redis Cluster<br/>3 Masters + 3 Slaves)]
        S3[Object Storage<br/>S3/GCS/Azure Blob]
    end
    
    subgraph "Security & Secrets"
        Vault[HashiCorp Vault]
        KMS[Cloud KMS]
        CertManager[cert-manager]
    end
    
    Users --> CDN
    Apps --> CDN
    APIs --> WAF
    
    CDN --> WAF
    WAF --> LB
    LB --> Ingress
    
    Ingress --> AuthPods
    Ingress --> PolicyPods
    
    AuthHPA --> AuthPods
    PolicyHPA --> PolicyPods
    
    AuthPods --> RedisCluster
    AuthPods --> PostgresCluster
    PolicyPods --> RedisCluster
    
    AuthPods --> Prometheus
    PolicyPods --> Prometheus
    
    Prometheus --> AlertManager
    Prometheus --> Grafana
    
    AuthPods --> Vault
    PolicyPods --> Vault
    Vault --> KMS
    
    CertManager --> Ingress
    
    PostgresCluster --> S3
    
    style AuthPods fill:#e1f5fe
    style PolicyPods fill:#f3e5f5
    style Prometheus fill:#fff3e0
```

### Deployment Pipeline Overview

```mermaid
flowchart TD
    subgraph "CI/CD Pipeline"
        Code[Code Commit] --> Build[Build & Test]
        Build --> Security[Security Scan]
        Security --> Package[Build Container]
        Package --> Registry[Push to Registry]
    end
    
    subgraph "Deployment Stages"
        Registry --> Staging[Staging Deployment]
        Staging --> StagingTests[Integration Tests]
        StagingTests --> Approval[Manual Approval]
        Approval --> Production[Production Deployment]
    end
    
    subgraph "Deployment Strategies"
        Production --> BlueGreen[Blue-Green Deployment]
        Production --> Canary[Canary Deployment]
        Production --> Rolling[Rolling Update]
    end
    
    subgraph "Post-Deployment"
        BlueGreen --> HealthCheck[Health Checks]
        Canary --> HealthCheck
        Rolling --> HealthCheck
        HealthCheck --> Monitor[Monitor Metrics]
        Monitor --> Success{Success?}
        Success -->|No| Rollback[Automatic Rollback]
        Success -->|Yes| Complete[Deployment Complete]
        Rollback --> Monitor
    end
    
    style Build fill:#e8f5e8
    style Security fill:#fff3e0
    style Production fill:#e1f5fe
    style HealthCheck fill:#f3e5f5
```

## Pre-Deployment Checklist

### Infrastructure Requirements
- [ ] **CPU**: 4+ cores recommended per service
- [ ] **Memory**: 8GB+ RAM total (4GB auth-service, 2GB policy-service, 2GB database)
- [ ] **Storage**: 100GB+ SSD for database and logs
- [ ] **Network**: Load balancer with TLS termination
- [ ] **Database**: PostgreSQL 15+ cluster with backups
- [ ] **Cache**: Redis 7+ cluster or managed service

### Security Requirements
- [ ] **Secrets Management**: Vault, AWS Secrets Manager, or equivalent
- [ ] **TLS Certificates**: Valid certificates for all endpoints
- [ ] **Network Security**: Firewall rules and network segmentation
- [ ] **Access Control**: RBAC for deployment and monitoring
- [ ] **Audit Logging**: Centralized log collection and retention

### Monitoring Requirements  
- [ ] **Metrics**: Prometheus or equivalent metrics collection
- [ ] **Logging**: Centralized logging with retention policy
- [ ] **Alerting**: Alert manager with escalation procedures
- [ ] **Health Checks**: Application and infrastructure monitoring
- [ ] **Dashboards**: Grafana or equivalent visualization

## Docker Production Deployment

### 1. Quick Production Start
```bash
# Generate secrets (do this once)
./scripts/generate-production-secrets.sh

# Deploy all services
./deploy-docker-production.sh

# Verify deployment
./validate-services.sh
```

### 2. Manual Docker Deployment

#### Generate Secrets
```bash
# Create secrets directory
mkdir -p secrets/

# Generate JWT secret (256-bit)
openssl rand -base64 32 > secrets/jwt_secret.txt

# Generate database password
openssl rand -base64 32 > secrets/postgres_password.txt

# Generate Grafana admin password
openssl rand -base64 16 > secrets/grafana_password.txt

# Set proper permissions
chmod 600 secrets/*.txt
```

#### Environment Configuration
```bash
# Create production environment file
cat > .env.production << EOF
ENVIRONMENT=production
RUST_LOG=info
DATABASE_URL=postgres://auth_service:$(cat secrets/postgres_password.txt)@postgres:5432/auth_service
REDIS_URL=redis://redis:6379
JWT_SECRET_FILE=/run/secrets/jwt_secret
POSTGRES_PASSWORD_FILE=/run/secrets/postgres_password
GRAFANA_PASSWORD_FILE=/run/secrets/grafana_password
EOF
```

#### Start Services
```bash
# Start core services
docker-compose -f docker-compose.production.yml up -d postgres redis

# Wait for databases to be ready
./scripts/validate-migrations.sh

# Start application services
docker-compose -f docker-compose.production.yml up -d auth-service policy-service dashboard

# Start monitoring (optional)
docker-compose -f docker-compose.production.yml --profile monitoring up -d
```

#### Service Verification
```bash
# Check service health
curl -f http://localhost:8080/health
curl -f http://localhost:8081/health
curl -f http://localhost:3000

# Check metrics endpoints
curl http://localhost:8080/metrics
curl http://localhost:8081/metrics

# Verify authentication flow
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=admin_client&client_secret=admin_secret&scope=read"
```

## Kubernetes Deployment

### 1. Prerequisites
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Install Helm
curl https://get.helm.sh/helm-v3.12.0-linux-amd64.tar.gz | tar xz
sudo mv linux-amd64/helm /usr/local/bin/

# Verify cluster access
kubectl cluster-info
```

### 2. Namespace and Secrets
```bash
# Create namespace
kubectl create namespace rust-security

# Create secrets
kubectl create secret generic auth-secrets -n rust-security \
  --from-file=jwt-secret=secrets/jwt_secret.txt \
  --from-file=postgres-password=secrets/postgres_password.txt

# Create TLS secret (replace with your certificates)
kubectl create secret tls rust-security-tls -n rust-security \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key
```

### 3. Database Deployment
```yaml
# k8s/postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: rust-security
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: auth_service
        - name: POSTGRES_USER
          value: auth_service  
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: postgres-password
        ports:
        - containerPort: 5432
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        - name: migrations
          mountPath: /docker-entrypoint-initdb.d
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"  
            cpu: "1000m"
      volumes:
      - name: migrations
        configMap:
          name: postgres-migrations
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi

---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: rust-security
spec:
  selector:
    app: postgres
  ports:
  - port: 5432
    targetPort: 5432
```

### 4. Redis Deployment  
```yaml
# k8s/redis.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: rust-security
spec:
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
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        volumeMounts:
        - name: redis-storage
          mountPath: /data
      volumes:
      - name: redis-storage
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: rust-security
spec:
  selector:
    app: redis
  ports:
  - port: 6379
    targetPort: 6379
```

### 5. Auth Service Deployment
```yaml
# k8s/auth-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: rust-security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: rust-security/auth-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: RUST_LOG
          value: "info"
        - name: DATABASE_URL
          value: "postgres://auth_service:$(POSTGRES_PASSWORD)@postgres:5432/auth_service"
        - name: REDIS_URL  
          value: "redis://redis:6379"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: postgres-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"

---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: rust-security
spec:
  selector:
    app: auth-service
  ports:
  - port: 8080
    targetPort: 8080
```

### 6. Ingress Configuration
```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rust-security-ingress
  namespace: rust-security
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
    nginx.ingress.kubernetes.io/ssl-ciphers: "ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - auth.company.com
    - policy.company.com
    secretName: rust-security-tls
  rules:
  - host: auth.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 8080
  - host: policy.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: policy-service
            port:
              number: 8081
```

### 7. Deploy to Kubernetes
```bash
# Apply all manifests
kubectl apply -f k8s/

# Wait for deployment
kubectl rollout status deployment/auth-service -n rust-security
kubectl rollout status deployment/policy-service -n rust-security

# Verify services
kubectl get pods -n rust-security
kubectl get services -n rust-security
```

## Cloud Provider Deployments

### AWS EKS Deployment

#### 1. EKS Cluster Setup
```bash
# Install eksctl
curl --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin

# Create EKS cluster  
eksctl create cluster \
  --name rust-security \
  --version 1.28 \
  --region us-west-2 \
  --nodegroup-name worker-nodes \
  --node-type m5.large \
  --nodes 3 \
  --nodes-min 2 \
  --nodes-max 4 \
  --managed
```

#### 2. AWS-Specific Services
```yaml
# aws-services.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aws-secrets
  namespace: rust-security
stringData:
  aws-region: us-west-2
  rds-endpoint: rust-security.cluster-xyz.us-west-2.rds.amazonaws.com
  redis-endpoint: rust-security.abc123.cache.amazonaws.com

---
apiVersion: v1
kind: ConfigMap  
metadata:
  name: aws-config
  namespace: rust-security
data:
  DATABASE_URL: "postgres://auth_service:password@$(RDS_ENDPOINT):5432/auth_service"
  REDIS_URL: "redis://$(REDIS_ENDPOINT):6379"
  AWS_REGION: "us-west-2"
```

### Google GKE Deployment

#### 1. GKE Cluster Setup
```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# Create GKE cluster
gcloud container clusters create rust-security \
  --zone=us-central1-a \
  --machine-type=n1-standard-4 \
  --num-nodes=3 \
  --enable-autoscaling \
  --min-nodes=2 \
  --max-nodes=5
```

#### 2. GCP-Specific Configuration
```yaml
# gcp-services.yaml
apiVersion: v1
kind: Secret
metadata:
  name: gcp-secrets
  namespace: rust-security
stringData:
  database-connection-name: "project:region:instance"
  redis-host: "10.0.0.1"
  
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: gcp-config  
  namespace: rust-security
data:
  DATABASE_URL: "postgres://auth_service:password@127.0.0.1:5432/auth_service"
  REDIS_URL: "redis://$(REDIS_HOST):6379"
```

### Azure AKS Deployment

#### 1. AKS Cluster Setup
```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login

# Create resource group
az group create --name rust-security-rg --location eastus

# Create AKS cluster
az aks create \
  --resource-group rust-security-rg \
  --name rust-security \
  --node-count 3 \
  --node-vm-size Standard_D4s_v3 \
  --generate-ssh-keys
```

## Configuration Management

### Environment-Specific Configurations

#### Production Configuration
```bash
# config/production.toml
[database]
host = "postgres.internal"
port = 5432
database = "auth_service" 
username = "auth_service"
password_file = "/run/secrets/postgres_password"
max_connections = 20
timeout = "30s"

[redis]  
url = "redis://redis.internal:6379"
pool_size = 20
timeout = "10s"

[security]
jwt_secret_file = "/run/secrets/jwt_secret"
token_expiry = "1h"
refresh_token_expiry = "30d"
require_https = true

[monitoring]
metrics_enabled = true
tracing_enabled = true
health_check_interval = "30s"

[logging]
level = "info"
format = "json"
destination = "stdout"
```

#### Staging Configuration
```bash
# config/staging.toml  
[database]
host = "postgres-staging.internal"
port = 5432
database = "auth_service_staging"
username = "auth_service" 
password_file = "/run/secrets/postgres_password"
max_connections = 10
timeout = "30s"

[security]
jwt_secret_file = "/run/secrets/jwt_secret"
token_expiry = "4h"  # Longer for testing
refresh_token_expiry = "7d"
require_https = false  # Allow HTTP for testing

[logging]
level = "debug"
format = "pretty"  
destination = "stdout"
```

## Security Hardening

### Container Security
```dockerfile
# Dockerfile.auth-service.production
FROM rust:1.80-slim as builder

# Create non-root user
RUN useradd -m -u 1001 appuser

# Install security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build with security optimizations
RUN cargo build --release --features production

FROM debian:bookworm-slim

# Install security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 appuser

# Copy application
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
COPY --from=builder --chown=appuser:appuser /app/config /app/config

# Switch to non-root user
USER appuser

# Security settings
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["auth-service"]
```

### Network Security
```yaml
# k8s/network-policies.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: auth-service-policy
  namespace: rust-security
spec:
  podSelector:
    matchLabels:
      app: auth-service
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx-ingress
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    ports:
    - protocol: TCP
      port: 5432
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
```

## Monitoring and Alerting

### Prometheus Configuration
```yaml
# monitoring/prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

rule_files:
  - "security-alerts.yml"
  - "infrastructure-rules.yml"

scrape_configs:
  - job_name: 'auth-service'
    kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names:
        - rust-security
    relabel_configs:
    - source_labels: [__meta_kubernetes_service_name]
      action: keep
      regex: auth-service
    - source_labels: [__meta_kubernetes_endpoint_port_name]
      action: keep
      regex: metrics
```

### Alert Rules
```yaml
# monitoring/prometheus/security-alerts.yml
groups:
- name: security-alerts
  rules:
  - alert: HighFailedLoginRate
    expr: rate(auth_failed_logins_total[5m]) > 10
    for: 2m
    labels:
      severity: critical
      category: security
    annotations:
      summary: "High failed login rate detected"
      description: "Failed login rate is {{ $value }} per second"
      
  - alert: JWTValidationErrors
    expr: rate(auth_jwt_validation_errors_total[5m]) > 1
    for: 1m
    labels:
      severity: high
      category: security
    annotations:
      summary: "JWT validation errors detected"
      description: "JWT validation error rate is {{ $value }} per second"

  - alert: ServiceDown
    expr: up{job="auth-service"} == 0
    for: 30s
    labels:
      severity: critical
      category: infrastructure
    annotations:
      summary: "Auth service is down"
      description: "Auth service has been down for more than 30 seconds"
```

## Backup and Disaster Recovery

### Database Backups
```bash
#!/bin/bash
# scripts/backup-database.sh

set -euo pipefail

BACKUP_DIR="/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DATABASE_URL="${DATABASE_URL:-postgres://auth_service:password@postgres:5432/auth_service}"

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Perform database backup
pg_dump "${DATABASE_URL}" \
  --format=custom \
  --compress=9 \
  --verbose \
  --file="${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup"

# Compress and encrypt backup
gpg --cipher-algo AES256 \
    --compress-algo 2 \
    --symmetric \
    --output "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup.gpg" \
    "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup"

# Remove unencrypted backup  
rm "${BACKUP_DIR}/auth_service_${TIMESTAMP}.backup"

# Cleanup old backups (keep 30 days)
find "${BACKUP_DIR}" -name "*.backup.gpg" -mtime +30 -delete

echo "Backup completed: auth_service_${TIMESTAMP}.backup.gpg"
```

### Kubernetes Backup Strategy
```yaml
# k8s/backup-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: database-backup
  namespace: rust-security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:15-alpine
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: auth-secrets
                  key: postgres-password
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h postgres -U auth_service auth_service \
                --format=custom --compress=9 \
                > /backup/auth_service_$(date +%Y%m%d_%H%M%S).backup
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

## Performance Optimization

### Resource Allocation
```yaml
# Production resource requests/limits
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "2000m"

# HPA configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: rust-security
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
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Database Optimization
```sql
-- Database optimization settings
-- postgresql.conf settings for production

shared_buffers = 2GB                    # 25% of RAM
effective_cache_size = 6GB              # 75% of RAM  
work_mem = 256MB                        # For complex queries
maintenance_work_mem = 512MB            # For maintenance operations
checkpoint_segments = 64                # WAL segments
checkpoint_completion_target = 0.9      # Smooth checkpoints
wal_buffers = 64MB                      # WAL buffer size
random_page_cost = 1.1                  # SSD optimization
effective_io_concurrency = 200          # SSD optimization

# Connection pooling
max_connections = 200
shared_preload_libraries = 'pg_stat_statements'
```

## Deployment Automation

### CI/CD Pipeline
```yaml
# .github/workflows/deploy-production.yml  
name: Deploy to Production

on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
        
    - name: Run security audit
      run: cargo audit
      
    - name: Run tests
      run: cargo test --workspace
      
    - name: Build Docker images
      run: |
        docker build -f Dockerfile.auth-service.production -t auth-service:${{ github.sha }} .
        docker build -f Dockerfile.policy-service.production -t policy-service:${{ github.sha }} .
        
    - name: Push to registry
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker push auth-service:${{ github.sha }}
        docker push policy-service:${{ github.sha }}
        
    - name: Deploy to Kubernetes
      uses: azure/k8s-deploy@v1
      with:
        namespace: rust-security
        manifests: |
          k8s/auth-service.yaml
          k8s/policy-service.yaml
        images: |
          auth-service:${{ github.sha }}
          policy-service:${{ github.sha }}
```

### Zero-Downtime Deployment
```bash
#!/bin/bash
# scripts/zero-downtime-deploy.sh

set -euo pipefail

NEW_VERSION="$1"
NAMESPACE="rust-security"

echo "Starting zero-downtime deployment to version ${NEW_VERSION}"

# Update image versions
kubectl set image deployment/auth-service auth-service=auth-service:${NEW_VERSION} -n ${NAMESPACE}
kubectl set image deployment/policy-service policy-service=policy-service:${NEW_VERSION} -n ${NAMESPACE}

# Wait for rollout to complete
kubectl rollout status deployment/auth-service -n ${NAMESPACE} --timeout=300s
kubectl rollout status deployment/policy-service -n ${NAMESPACE} --timeout=300s

# Verify health
sleep 30
kubectl exec deployment/auth-service -n ${NAMESPACE} -- curl -f http://localhost:8080/health
kubectl exec deployment/policy-service -n ${NAMESPACE} -- curl -f http://localhost:8081/health

echo "Deployment completed successfully!"
```

## Troubleshooting

### Common Deployment Issues

#### Pod CrashLoopBackOff
```bash
# Check pod logs
kubectl logs -f deployment/auth-service -n rust-security

# Check pod events  
kubectl describe pod <pod-name> -n rust-security

# Check resource constraints
kubectl top pods -n rust-security
```

#### Service Discovery Issues
```bash
# Test DNS resolution
kubectl exec -it deployment/auth-service -n rust-security -- nslookup postgres

# Check service endpoints
kubectl get endpoints -n rust-security

# Test network connectivity
kubectl exec -it deployment/auth-service -n rust-security -- nc -zv postgres 5432
```

#### Database Connection Issues
```bash
# Check database logs
kubectl logs deployment/postgres -n rust-security

# Test database connection
kubectl exec -it deployment/postgres -n rust-security -- psql -U auth_service -d auth_service -c "SELECT version();"

# Check secret values
kubectl get secret auth-secrets -n rust-security -o yaml
```

### Recovery Procedures

#### Database Recovery
```bash
# Restore from backup
kubectl exec -it deployment/postgres -n rust-security -- pg_restore \
  -h localhost -U auth_service -d auth_service \
  --clean --if-exists /backup/auth_service_20240101_020000.backup
```

#### Service Recovery
```bash
# Restart failed deployment
kubectl rollout restart deployment/auth-service -n rust-security

# Scale up/down
kubectl scale deployment/auth-service --replicas=5 -n rust-security

# Emergency rollback
kubectl rollout undo deployment/auth-service -n rust-security
```

## Post-Deployment Validation

### Health Checks
```bash
# Comprehensive health check script
#!/bin/bash
# scripts/post-deployment-validation.sh

set -euo pipefail

BASE_URL="${BASE_URL:-https://auth.company.com}"

echo "Running post-deployment validation..."

# Health endpoints
curl -f "${BASE_URL}/health" || exit 1
curl -f "${BASE_URL}/.well-known/openid-configuration" || exit 1

# Authentication flow
TOKEN=$(curl -s -X POST "${BASE_URL}/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=read" \
  | jq -r '.access_token')

if [ "$TOKEN" = "null" ]; then
  echo "Failed to obtain access token"
  exit 1
fi

echo "✅ Authentication flow validated"

# Metrics endpoint
curl -f "${BASE_URL}/metrics" > /dev/null || exit 1
echo "✅ Metrics endpoint accessible"

echo "🎉 All validations passed!"
```

This comprehensive deployment guide covers all major production scenarios and provides the foundation for reliable, secure deployments of the Rust Security Platform. Follow the appropriate sections based on your infrastructure and requirements.