# 🚀 Enterprise Deployment Patterns

## Overview
This document provides enterprise-grade deployment patterns for the Rust Security Platform, covering multi-environment strategies, high availability, disaster recovery, and security hardening.

---

## 🏗️ Deployment Architecture Patterns

### **Pattern 1: Multi-Tier Production Deployment**

```yaml
┌─────────────────────────────────────────────────────────────────────┐
│                        ENTERPRISE DEPLOYMENT                       │
│                         (Recommended Pattern)                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │   PRODUCTION    │  │     STAGING     │  │   DEVELOPMENT   │     │
│  │                 │  │                 │  │                 │     │
│  │ • 3 AZ Deploy   │  │ • 2 AZ Deploy   │  │ • Single Node   │     │
│  │ • HA Database   │  │ • Prod Mirror   │  │ • Local Secrets │     │
│  │ • External KMS  │  │ • Test Data     │  │ • Debug Enable  │     │
│  │ • Full Monitor  │  │ • Monitoring    │  │ • Fast Builds   │     │
│  │ • Auto Scale    │  │ • Integration   │  │ • Hot Reload    │     │
│  │ • Backup/DR     │  │ • Performance   │  │ • Mock Services │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
│           │                     │                     │            │
│           └─────────────────────┼─────────────────────┘            │
│                                 │                                  │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    SHARED SERVICES                          │   │
│  │                                                             │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │   │
│  │  │   Vault     │ │ Monitoring  │ │   CI/CD     │          │   │
│  │  │  Cluster    │ │   Stack     │ │  Pipeline   │          │   │
│  │  │             │ │             │ │             │          │   │
│  │  │ • Multi-DC  │ │ • Prometheus│ │ • Security  │          │   │
│  │  │ • Auto-Seal │ │ • Grafana   │ │ • Testing   │          │   │
│  │  │ • HA Config │ │ • AlertMgr  │ │ • Deploy    │          │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘          │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### **Pattern 2: Microservices Service Mesh**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rust-security-prod
  labels:
    istio-injection: enabled
    security.company.com/tier: production
---
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: rust-security-prod
spec:
  mtls:
    mode: STRICT
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: auth-service-vs
spec:
  http:
  - match:
    - uri:
        prefix: "/api/v1/auth"
    route:
    - destination:
        host: auth-service.rust-security-prod.svc.cluster.local
        port:
          number: 8080
    timeout: 30s
    retries:
      attempts: 3
      perTryTimeout: 10s
```

---

## 🔒 Security-First Deployment Configuration

### **Production Security Manifest**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service-prod
  namespace: rust-security-prod
  labels:
    app: auth-service
    tier: production
    security-level: high
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
        tier: production
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "auth-service"
        vault.hashicorp.com/agent-inject-secret-config: "secret/auth-service/prod"
    spec:
      # Security Context - Container Level
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        fsGroupChangePolicy: "OnRootMismatch"
      
      # Service Account with minimal RBAC
      serviceAccountName: auth-service-prod
      automountServiceAccountToken: false
      
      # Node Selection & Scheduling
      nodeSelector:
        node.company.com/security-tier: high
        kubernetes.io/arch: amd64
      
      tolerations:
      - key: "security-tier"
        operator: "Equal"
        value: "high"
        effect: "NoSchedule"
      
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values: ["auth-service"]
            topologyKey: kubernetes.io/hostname
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: node.company.com/security-tier
                operator: In
                values: ["high"]
      
      containers:
      - name: auth-service
        image: registry.company.com/rust-security/auth-service:v1.0.0-secure
        imagePullPolicy: Always
        
        # Security Context - Pod Level
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 65532
          runAsGroup: 65532
          capabilities:
            drop:
            - ALL
            add: []  # No additional capabilities
          seccompProfile:
            type: RuntimeDefault
          seLinuxOptions:
            level: s0:c123,c456
        
        # Resource Management
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
            ephemeral-storage: "1Gi"
          limits:
            memory: "512Mi"
            cpu: "500m"
            ephemeral-storage: "2Gi"
        
        # Environment Configuration
        env:
        - name: RUST_LOG
          value: "warn,auth_service=info"
        - name: ENVIRONMENT
          value: "production"
        - name: ENABLE_DEBUG_ENDPOINTS
          value: "false"
        - name: SECURITY_MODE
          value: "strict"
        
        # Configuration from Vault
        envFrom:
        - secretRef:
            name: auth-service-secrets
        - configMapRef:
            name: auth-service-config
        
        # Ports Configuration
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        - containerPort: 8443
          name: https
          protocol: TCP
        - containerPort: 9090
          name: metrics
          protocol: TCP
        
        # Health Checks
        startupProbe:
          httpGet:
            path: /health/startup
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 30
          successThreshold: 1
        
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
          successThreshold: 1
        
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 5
          failureThreshold: 3
          successThreshold: 1
        
        # Volume Mounts
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
          readOnly: false
        - name: var-run-volume
          mountPath: /var/run
          readOnly: false
        - name: tls-certs
          mountPath: /etc/tls
          readOnly: true
        - name: config-volume
          mountPath: /etc/config
          readOnly: true
        
        # Lifecycle Hooks
        lifecycle:
          preStop:
            exec:
              command:
              - /bin/sh
              - -c
              - sleep 15
      
      # Volumes
      volumes:
      - name: tmp-volume
        emptyDir:
          sizeLimit: 1Gi
          medium: Memory
      - name: var-run-volume
        emptyDir:
          sizeLimit: 100Mi
          medium: Memory
      - name: tls-certs
        secret:
          secretName: auth-service-tls
          defaultMode: 0400
      - name: config-volume
        configMap:
          name: auth-service-config
          defaultMode: 0444
      
      # Image Pull Configuration
      imagePullSecrets:
      - name: registry-credentials
      
      # DNS Configuration
      dnsPolicy: ClusterFirst
      dnsConfig:
        options:
        - name: ndots
          value: "2"
        - name: edns0
      
      # Termination Configuration
      terminationGracePeriodSeconds: 30
      restartPolicy: Always
```

### **Network Security Policies**

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: auth-service-netpol
  namespace: rust-security-prod
spec:
  podSelector:
    matchLabels:
      app: auth-service
  policyTypes:
  - Ingress
  - Egress
  
  # Ingress Rules
  ingress:
  # Allow from API Gateway
  - from:
    - namespaceSelector:
        matchLabels:
          name: api-gateway
    - podSelector:
        matchLabels:
          app: api-gateway
    ports:
    - protocol: TCP
      port: 8080
  
  # Allow from monitoring
  - from:
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    - protocol: TCP
      port: 9090
  
  # Egress Rules
  egress:
  # Allow to policy service
  - to:
    - podSelector:
        matchLabels:
          app: policy-service
    ports:
    - protocol: TCP
      port: 8080
  
  # Allow to database
  - to:
    - namespaceSelector:
        matchLabels:
          name: database
    ports:
    - protocol: TCP
      port: 5432
  
  # Allow to Redis
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  
  # Allow to Vault
  - to:
    - namespaceSelector:
        matchLabels:
          name: vault-system
    ports:
    - protocol: TCP
      port: 8200
  
  # DNS Resolution
  - to: []
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

---

## 🗂️ Environment-Specific Configurations

### **Production Environment**

```bash
#!/bin/bash
# Production Deployment Script

set -euo pipefail

# Configuration
NAMESPACE="rust-security-prod"
IMAGE_TAG="v1.0.0-secure"
REPLICAS=3
ENVIRONMENT="production"

# Pre-deployment Security Checks
echo "🔒 Running Pre-deployment Security Validation..."

# 1. Verify image signatures
cosign verify --key cosign.pub registry.company.com/rust-security/auth-service:${IMAGE_TAG}

# 2. Scan for vulnerabilities
trivy image registry.company.com/rust-security/auth-service:${IMAGE_TAG}

# 3. Validate Kubernetes manifests
kustomize build overlays/production | kubectl apply --dry-run=client -f -

# 4. Check secrets availability
kubectl get secret auth-service-secrets -n ${NAMESPACE}
kubectl get secret auth-service-tls -n ${NAMESPACE}

# 5. Validate network policies
kubectl describe networkpolicy auth-service-netpol -n ${NAMESPACE}

echo "✅ Pre-deployment validation complete"

# Deployment with Rolling Update
echo "🚀 Deploying to production environment..."

kubectl set image deployment/auth-service-prod \
  auth-service=registry.company.com/rust-security/auth-service:${IMAGE_TAG} \
  -n ${NAMESPACE}

# Wait for rollout completion
kubectl rollout status deployment/auth-service-prod -n ${NAMESPACE} --timeout=300s

# Post-deployment verification
echo "🔍 Running Post-deployment Verification..."

# Health checks
kubectl get pods -n ${NAMESPACE} -l app=auth-service
kubectl logs -n ${NAMESPACE} -l app=auth-service --tail=20

# Service connectivity test
kubectl exec -n ${NAMESPACE} deployment/auth-service-prod -- \
  curl -f http://localhost:8080/health

echo "✅ Production deployment complete"
```

### **Staging Environment**

```yaml
# Staging-specific overrides
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: rust-security-staging

resources:
- ../../base

patchesStrategicMerge:
- staging-overrides.yaml

images:
- name: auth-service
  newTag: staging-latest

replicas:
- name: auth-service-deployment
  count: 2

configMapGenerator:
- name: auth-service-config
  literals:
  - RUST_LOG=debug,auth_service=debug
  - ENVIRONMENT=staging
  - ENABLE_DEBUG_ENDPOINTS=true
  - PERFORMANCE_TESTING=true
```

### **Development Environment**

```yaml
apiVersion: skaffold/v2beta29
kind: Config
metadata:
  name: rust-security-dev

build:
  artifacts:
  - image: auth-service-dev
    context: .
    docker:
      dockerfile: Dockerfile.dev
    sync:
      manual:
      - src: "src/**/*.rs"
        dest: /app/src

deploy:
  kubectl:
    manifests:
    - k8s/dev/*.yaml

portForward:
- resourceType: service
  resourceName: auth-service-dev
  port: 8080
  localPort: 8080

- resourceType: service
  resourceName: auth-service-dev
  port: 9090
  localPort: 9090
```

---

## 🔄 CI/CD Security Pipeline

### **Security-First Pipeline**

```yaml
name: Secure CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: registry.company.com
  IMAGE_NAME: rust-security/auth-service
  CARGO_TERM_COLOR: always

jobs:
  security-scan:
    name: Security & Compliance
    runs-on: ubuntu-latest
    steps:
    
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    # Security Scanning
    - name: Run Cargo Audit
      run: |
        cargo install cargo-audit
        cargo audit
    
    - name: Run Cargo Deny
      run: |
        cargo install cargo-deny
        cargo deny check
    
    - name: Secret Scanning
      uses: gitleaks/gitleaks-action@v2
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    - name: SAST with Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: auto
    
    - name: Dependency Review
      uses: actions/dependency-review-action@v3
      if: github.event_name == 'pull_request'

  build-and-test:
    name: Build & Test
    runs-on: ubuntu-latest
    needs: security-scan
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Rust toolchain
      uses: actions-rs/toolchain@v1
      with:
        toolchain: 1.86.0  # Minimum required version
        profile: minimal
        override: true
        components: rustfmt, clippy
    
    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/bin/
          ~/.cargo/registry/index/
          ~/.cargo/registry/cache/
          ~/.cargo/git/db/
          target/
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Format check
      run: cargo fmt --all -- --check
    
    - name: Lint with Clippy
      run: cargo clippy --workspace --all-features -- -D warnings
    
    - name: Run tests
      run: |
        cargo test --workspace --all-features
        cargo test --workspace --all-features --release
    
    - name: Security build
      run: cargo build --profile security --all-features

  container-security:
    name: Container Security
    runs-on: ubuntu-latest
    needs: build-and-test
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Build container image
      run: |
        docker build -t ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
          --target production .
    
    - name: Container vulnerability scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Sign container image
      uses: sigstore/cosign-installer@v3
    
    - name: Sign the published Docker image
      run: |
        cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}

  deploy-staging:
    name: Deploy to Staging
    runs-on: ubuntu-latest
    needs: [security-scan, build-and-test, container-security]
    environment: staging
    if: github.ref == 'refs/heads/develop'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG_STAGING }}
    
    - name: Deploy to staging
      run: |
        kubectl set image deployment/auth-service-staging \
          auth-service=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
          -n rust-security-staging
        
        kubectl rollout status deployment/auth-service-staging \
          -n rust-security-staging --timeout=300s
    
    - name: Run integration tests
      run: |
        ./scripts/integration-tests.sh staging
    
    - name: Security validation
      run: |
        ./scripts/security-validation.sh staging

  deploy-production:
    name: Deploy to Production
    runs-on: ubuntu-latest
    needs: deploy-staging
    environment: production
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Production deployment approval
      uses: trstringer/manual-approval@v1
      with:
        secret: ${{ secrets.GITHUB_TOKEN }}
        approvers: security-team,devops-team
        minimum-approvals: 2
        issue-title: "Production Deployment Approval"
        issue-body: |
          Security validation complete. Ready for production deployment.
          
          **Security Checks:**
          - ✅ Vulnerability scan passed
          - ✅ Container security validated
          - ✅ Staging tests passed
          - ✅ Security team approval required
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG_PRODUCTION }}
    
    - name: Blue-Green Deployment
      run: |
        ./scripts/blue-green-deploy.sh production ${{ github.sha }}
    
    - name: Production smoke tests
      run: |
        ./scripts/production-smoke-tests.sh
    
    - name: Security monitoring alert
      run: |
        curl -X POST "${{ secrets.SLACK_WEBHOOK }}" \
          -H 'Content-type: application/json' \
          --data '{"text":"🚀 Production deployment complete - Security monitoring active"}'
```

---

## 📊 Monitoring & Observability

### **Production Monitoring Stack**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    rule_files:
    - "/etc/prometheus/rules/*.yml"
    
    scrape_configs:
    # Auth Service Metrics
    - job_name: 'auth-service'
      static_configs:
      - targets: ['auth-service.rust-security-prod:9090']
      scrape_interval: 10s
      metrics_path: /metrics
      scheme: https
      tls_config:
        ca_file: /etc/prometheus/certs/ca.crt
        cert_file: /etc/prometheus/certs/client.crt
        key_file: /etc/prometheus/certs/client.key
      
    # Security-specific metrics
    - job_name: 'security-metrics'
      static_configs:
      - targets: ['auth-service.rust-security-prod:9091']
      scrape_interval: 5s
      metrics_path: /security-metrics
      
    alerting:
      alertmanagers:
      - static_configs:
        - targets: ['alertmanager:9093']
        scheme: https
        tls_config:
          ca_file: /etc/prometheus/certs/ca.crt

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: alerting-rules
  namespace: monitoring
data:
  security-alerts.yml: |
    groups:
    - name: security.rules
      rules:
      # Authentication Failures
      - alert: HighAuthFailureRate
        expr: rate(auth_failures_total[5m]) > 10
        for: 2m
        labels:
          severity: critical
          service: auth-service
        annotations:
          summary: "High authentication failure rate detected"
          description: "Auth failure rate is {{ $value }} failures/sec"
      
      # Rate Limiting Triggered
      - alert: RateLimitExceeded
        expr: rate(rate_limit_exceeded_total[1m]) > 100
        for: 30s
        labels:
          severity: warning
          service: auth-service
        annotations:
          summary: "Rate limiting frequently triggered"
          description: "Rate limit exceeded {{ $value }} times/min"
      
      # JWT Token Issues
      - alert: InvalidJWTTokens
        expr: rate(jwt_validation_failures_total[5m]) > 5
        for: 1m
        labels:
          severity: warning
          service: auth-service
        annotations:
          summary: "High rate of invalid JWT tokens"
          description: "JWT validation failing at {{ $value }} tokens/sec"
      
      # Service Health
      - alert: ServiceDown
        expr: up{job="auth-service"} == 0
        for: 1m
        labels:
          severity: critical
          service: auth-service
        annotations:
          summary: "Auth service is down"
          description: "Auth service has been down for more than 1 minute"
      
      # Memory Usage
      - alert: HighMemoryUsage
        expr: (process_resident_memory_bytes / 1024 / 1024) > 400
        for: 5m
        labels:
          severity: warning
          service: auth-service
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is {{ $value }}MB"
```

---

## 🔄 Disaster Recovery & Business Continuity

### **Multi-Region Disaster Recovery**

```yaml
# Primary Region (us-east-1)
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: rust-security-primary
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/company/rust-security
    targetRevision: main
    path: k8s/overlays/production-primary
  destination:
    server: https://primary-cluster.company.com
    namespace: rust-security-prod
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
    - PrunePropagationPolicy=foreground

---
# DR Region (us-west-2)  
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: rust-security-dr
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/company/rust-security
    targetRevision: main
    path: k8s/overlays/production-dr
  destination:
    server: https://dr-cluster.company.com
    namespace: rust-security-prod
  syncPolicy:
    manual: {}  # Manual sync for DR
```

### **Backup Strategy**

```bash
#!/bin/bash
# Automated Backup Script

set -euo pipefail

# Configuration
BACKUP_RETENTION_DAYS=30
ENCRYPTION_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
S3_BACKUP_BUCKET="company-rust-security-backups"

# Database Backup
echo "🗄️ Starting database backup..."
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME | \
  gzip | \
  aws s3 cp - s3://${S3_BACKUP_BUCKET}/database/$(date +%Y%m%d_%H%M%S)_database.sql.gz \
    --server-side-encryption aws:kms \
    --ssm-kms-key-id ${ENCRYPTION_KEY_ID}

# Secrets Backup (Vault)
echo "🔐 Starting secrets backup..."
vault operator raft snapshot save /tmp/vault-snapshot-$(date +%Y%m%d_%H%M%S).snap
aws s3 cp /tmp/vault-snapshot-*.snap s3://${S3_BACKUP_BUCKET}/vault/ \
  --server-side-encryption aws:kms \
  --ssm-kms-key-id ${ENCRYPTION_KEY_ID}
rm /tmp/vault-snapshot-*.snap

# Configuration Backup
echo "⚙️ Starting configuration backup..."
kubectl get all,secrets,configmaps,networkpolicies -n rust-security-prod -o yaml | \
  gzip | \
  aws s3 cp - s3://${S3_BACKUP_BUCKET}/k8s/$(date +%Y%m%d_%H%M%S)_k8s-config.yaml.gz \
    --server-side-encryption aws:kms \
    --ssm-kms-key-id ${ENCRYPTION_KEY_ID}

# Cleanup old backups
echo "🧹 Cleaning up old backups..."
aws s3 ls s3://${S3_BACKUP_BUCKET}/ --recursive | \
  awk '{print $4}' | \
  while read file; do
    file_date=$(echo $file | grep -oE '[0-9]{8}')
    if [[ $file_date < $(date -d "-${BACKUP_RETENTION_DAYS} days" +%Y%m%d) ]]; then
      aws s3 rm s3://${S3_BACKUP_BUCKET}/$file
    fi
  done

echo "✅ Backup complete"
```

---

## 🎯 Performance Optimization

### **Production Performance Tuning**

```yaml
# HPA Configuration
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: rust-security-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service-prod
  minReplicas: 3
  maxReplicas: 20
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
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "100"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60

---
# VPA Configuration
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: auth-service-vpa
  namespace: rust-security-prod
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service-prod
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: auth-service
      maxAllowed:
        cpu: 2
        memory: 4Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

---

**🏗️ These enterprise deployment patterns provide comprehensive, production-ready deployment strategies with security-first approach, high availability, and operational excellence for the Rust Security Platform.**