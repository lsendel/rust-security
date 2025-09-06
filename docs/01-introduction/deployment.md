# Deployment Guide

Comprehensive guide for deploying the Rust Security Platform to production environments.

## Deployment Architecture

### High Availability Setup

```
                    ┌────────────────────┐
                    │    Load Balancer   │
                    │  (nginx/haproxy)   │
                    └─────────┬──────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼────────┐   ┌────────▼────────┐   ┌───────▼────────┐
│  Auth Service  │   │  Auth Service   │   │  Auth Service  │
│    (Node 1)    │   │    (Node 2)     │   │    (Node 3)    │
└───────┬────────┘   └────────┬────────┘   └───────┬────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │     PostgreSQL     │
                    │  (Clustered/RDS)   │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │      Redis         │
                    │  (Clustered/ElastiCache) │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Policy Service    │
                    │    (Clustered)     │
                    └────────────────────┘
```

### Service Dependencies

1. **Database**: PostgreSQL 13+ (clustered for HA)
2. **Cache**: Redis 6+ (clustered for HA)
3. **Load Balancer**: nginx/haproxy
4. **Certificate Management**: Let's Encrypt/cert-manager
5. **Monitoring**: Prometheus + Grafana
6. **Logging**: ELK Stack or similar

## Deployment Methods

### 1. Docker Compose (Simple Deployment)

```bash
# Download deployment files
curl -O https://raw.githubusercontent.com/company/rust-security/main/deploy/production/docker-compose.yml
curl -O https://raw.githubusercontent.com/company/rust-security/main/deploy/production/.env

# Customize configuration
nano .env

# Deploy
docker-compose up -d

# Scale services
docker-compose up -d --scale auth-service=3 --scale policy-service=2
```

### 2. Kubernetes (Recommended for Production)

```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/configmaps.yaml
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/deployments.yaml
kubectl apply -f k8s/ingress.yaml

# Check deployment status
kubectl get pods -n rust-security
kubectl get services -n rust-security
```

### 3. Virtual Machines / Bare Metal

```bash
# Download and extract binaries
wget https://github.com/company/rust-security/releases/latest/download/rust-security-linux-amd64.tar.gz
tar -xzf rust-security-linux-amd64.tar.gz -C /opt/rust-security

# Create systemd services
sudo cp deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Start services
sudo systemctl enable auth-service policy-service
sudo systemctl start auth-service policy-service
```

## Kubernetes Deployment

### Namespace and RBAC

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rust-security
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rust-security-sa
  namespace: rust-security
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: rust-security-role
  namespace: rust-security
rules:
- apiGroups: [""]
  resources: ["pods", "services", "endpoints"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: rust-security-rolebinding
  namespace: rust-security
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: rust-security-role
subjects:
- kind: ServiceAccount
  name: rust-security-sa
  namespace: rust-security
```

### Secrets Management

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: rust-security-secrets
  namespace: rust-security
type: Opaque
data:
  jwt-secret: <base64-encoded-jwt-secret>
  database-password: <base64-encoded-db-password>
  redis-password: <base64-encoded-redis-password>
---
apiVersion: v1
kind: Secret
metadata:
  name: database-credentials
  namespace: rust-security
type: Opaque
data:
  username: <base64-encoded-username>
  password: <base64-encoded-password>
```

### ConfigMaps

```yaml
# k8s/configmaps.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-service-config
  namespace: rust-security
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
    database:
      url: "postgresql://$(DATABASE_USER):$(DATABASE_PASSWORD)@postgres:5432/auth_service"
      pool_size: 10
    redis:
      url: "redis://:$(REDIS_PASSWORD)@redis:6379"
    jwt:
      secret: "$(JWT_SECRET)"
      expiration: 3600
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: policy-service-config
  namespace: rust-security
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 8081
    database:
      url: "postgresql://$(DATABASE_USER):$(DATABASE_PASSWORD)@postgres:5432/policy_service"
      pool_size: 5
    redis:
      url: "redis://:$(REDIS_PASSWORD)@redis:6379"
    policies:
      directory: "/app/policies"
      cache_ttl: 300
```

### Deployments

```yaml
# k8s/deployments.yaml
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
      serviceAccountName: rust-security-sa
      containers:
      - name: auth-service
        image: company/rust-security-auth-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: rust-security-secrets
              key: jwt-secret
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: password
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: rust-security-secrets
              key: redis-password
        envFrom:
        - configMapRef:
            name: auth-service-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
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
        volumeMounts:
        - name: config-volume
          mountPath: /app/config
      volumes:
      - name: config-volume
        configMap:
          name: auth-service-config
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: policy-service
  namespace: rust-security
spec:
  replicas: 2
  selector:
    matchLabels:
      app: policy-service
  template:
    metadata:
      labels:
        app: policy-service
    spec:
      containers:
      - name: policy-service
        image: company/rust-security-policy-service:latest
        ports:
        - containerPort: 8081
        env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: password
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: rust-security-secrets
              key: redis-password
        envFrom:
        - configMapRef:
            name: policy-service-config
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "250m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Services

```yaml
# k8s/services.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: rust-security
spec:
  selector:
    app: auth-service
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: ClusterIP
---
apiVersion: v1
kind: Service
metadata:
  name: policy-service
  namespace: rust-security
spec:
  selector:
    app: policy-service
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8081
  type: ClusterIP
```

### Ingress

```yaml
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rust-security-ingress
  namespace: rust-security
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - auth.example.com
    - policy.example.com
    secretName: rust-security-tls
  rules:
  - host: auth.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 80
  - host: policy.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: policy-service
            port:
              number: 80
```

## Database Deployment

### PostgreSQL

#### High Availability Setup

```yaml
# k8s/postgres.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: rust-security
spec:
  serviceName: postgres
  replicas: 3
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
        image: postgres:13
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: password
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: database-credentials
              key: username
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

### Redis

#### Clustered Setup

```yaml
# k8s/redis.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis
  namespace: rust-security
spec:
  serviceName: redis
  replicas: 3
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
        image: redis:6-alpine
        ports:
        - containerPort: 6379
        command: ["redis-server"]
        args: ["--appendonly", "yes", "--requirepass", "$(REDIS_PASSWORD)"]
        env:
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: rust-security-secrets
              key: redis-password
        volumeMounts:
        - name: redis-storage
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: redis-storage
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 5Gi
```

## Monitoring and Observability

### Prometheus Configuration

```yaml
# monitoring/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service.rust-security.svc.cluster.local:8080']
    metrics_path: '/metrics'
    
  - job_name: 'policy-service'
    static_configs:
      - targets: ['policy-service.rust-security.svc.cluster.local:8081']
    metrics_path: '/metrics'
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres.rust-security.svc.cluster.local:9187']
    metrics_path: '/metrics'
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis.rust-security.svc.cluster.local:9121']
    metrics_path: '/metrics'
```

### Grafana Dashboards

```json
{
  "dashboard": {
    "id": null,
    "title": "Rust Security Platform",
    "tags": ["rust", "security", "auth"],
    "timezone": "browser",
    "schemaVersion": 16,
    "version": 0,
    "panels": [
      {
        "title": "Authentication Requests",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "rate(auth_requests_total[5m])",
            "legendFormat": "{{status}}"
          }
        ]
      }
    ]
  }
}
```

## Security Hardening

### Network Policies

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
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
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

### Pod Security Standards

```yaml
# k8s/pod-security.yaml
apiVersion: v1
kind: Pod
metadata:
  name: auth-service
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: auth-service
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

## Backup and Disaster Recovery

### Database Backup

```bash
# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
PGPASSWORD=$DATABASE_PASSWORD pg_dump -h $DATABASE_HOST -U $DATABASE_USER auth_service > $BACKUP_DIR/auth_service_$DATE.sql
PGPASSWORD=$DATABASE_PASSWORD pg_dump -h $DATABASE_HOST -U $DATABASE_USER policy_service > $BACKUP_DIR/policy_service_$DATE.sql

# Compress backups
gzip $BACKUP_DIR/*_$DATE.sql

# Remove old backups (keep last 30 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +30 -delete
```

### Configuration Backup

```bash
# Backup Kubernetes resources
kubectl get all -n rust-security -o yaml > rust-security-backup-$(date +%Y%m%d).yaml
kubectl get secrets -n rust-security -o yaml > rust-security-secrets-backup-$(date +%Y%m%d).yaml
kubectl get configmaps -n rust-security -o yaml > rust-security-configmaps-backup-$(date +%Y%m%d).yaml
```

## Scaling Considerations

### Horizontal Pod Autoscaler

```yaml
# k8s/hpa.yaml
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

### Resource Optimization

```yaml
# Optimized resource requests and limits
resources:
  requests:
    memory: "128Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "250m"
```

## Deployment Validation

### Health Checks

```bash
# Check service health
kubectl exec -it auth-service-<pod-id> -n rust-security -- curl -f http://localhost:8080/health
kubectl exec -it policy-service-<pod-id> -n rust-security -- curl -f http://localhost:8081/health

# Check database connectivity
kubectl exec -it auth-service-<pod-id> -n rust-security -- pg_isready -h postgres -U $DATABASE_USER

# Check Redis connectivity
kubectl exec -it auth-service-<pod-id> -n rust-security -- redis-cli -h redis ping
```

### Smoke Tests

```bash
# Test OAuth 2.0 flow
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test_client:test_secret" \
  -d "grant_type=client_credentials&scope=read"

# Test policy evaluation
curl -X POST https://policy.example.com/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {"id": "test-user"},
    "action": "read",
    "resource": {"type": "document", "id": "test-doc"}
  }'
```

## Rolling Updates

### Blue-Green Deployment

```yaml
# Blue deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service-blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
      version: blue
  template:
    metadata:
      labels:
        app: auth-service
        version: blue
    spec:
      containers:
      - name: auth-service
        image: company/rust-security-auth-service:v1.0.0
```

### Canary Deployment

```yaml
# Canary deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service-canary
spec:
  replicas: 1
  selector:
    matchLabels:
      app: auth-service
      version: canary
  template:
    metadata:
      labels:
        app: auth-service
        version: canary
    spec:
      containers:
      - name: auth-service
        image: company/rust-security-auth-service:v1.1.0-canary
```

## Troubleshooting

### Common Deployment Issues

#### Pod CrashLoopBackOff

```bash
# Check pod logs
kubectl logs auth-service-<pod-id> -n rust-security

# Describe pod for detailed status
kubectl describe pod auth-service-<pod-id> -n rust-security

# Check events
kubectl get events -n rust-security
```

#### Service Unavailable

```bash
# Check service endpoints
kubectl get endpoints auth-service -n rust-security

# Check network policies
kubectl get networkpolicies -n rust-security

# Test connectivity
kubectl exec -it test-pod -n rust-security -- curl -v http://auth-service:8080/health
```

#### Database Connection Issues

```bash
# Check database service
kubectl get service postgres -n rust-security

# Test database connectivity
kubectl exec -it auth-service-<pod-id> -n rust-security -- pg_isready -h postgres.rust-security.svc.cluster.local

# Check database credentials
kubectl get secret database-credentials -n rust-security -o yaml
```

## Next Steps

After successful deployment:

1. **Monitor Services**: Set up alerts and monitoring
2. **Configure Backup**: Implement backup and recovery procedures
3. **Test Failover**: Verify high availability setup
4. **Optimize Performance**: Tune resources and scaling
5. **Secure Access**: Implement access controls and security policies

For ongoing operations, see the [Operations Guide](../05-operations/README.md).