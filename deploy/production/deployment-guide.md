# 🚀 Production Deployment Guide

## Prerequisites

### Infrastructure Requirements
- **Minimum**: 4 CPU cores, 8GB RAM, 100GB SSD
- **Recommended Production**: 16 CPU cores, 32GB RAM, 500GB SSD
- **High Availability**: Multi-AZ deployment with load balancers
- **Network**: TLS 1.2+, proper firewall configuration

### Security Requirements
- SSL/TLS certificates (Let's Encrypt or commercial)
- Secure secrets management (Kubernetes Secrets, Vault, etc.)
- Network segmentation and firewall rules
- Backup and disaster recovery plan

## 🔐 Step 1: Secure Environment Setup

### Generate Production Secrets
```bash
# Generate secure secrets (run on secure machine)
openssl rand -base64 64 > jwt_secret.txt
openssl rand -base64 64 > admin_secret.txt
openssl rand -base64 64 > signing_secret.txt
openssl rand -base64 32 > db_password.txt
openssl rand -base64 32 > redis_password.txt

# Create Kubernetes secrets
kubectl create namespace rust-security

kubectl create secret generic auth-secrets \
  --from-literal=database-url="postgresql://auth_user:$(cat db_password.txt)@postgres:5432/auth_production" \
  --from-literal=redis-url="redis://:$(cat redis_password.txt)@redis:6379/0" \
  --from-literal=jwt-secret="$(cat jwt_secret.txt)" \
  --from-literal=admin-secret="$(cat admin_secret.txt)" \
  --from-literal=signing-secret="$(cat signing_secret.txt)" \
  --namespace rust-security

# Clean up secret files
shred -vfz *.txt
```

### SSL Certificate Setup
```bash
# For Let's Encrypt (automated)
certbot certonly --standalone -d your-domain.com

# Copy certificates to deployment directory
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ./ssl/
cp /etc/letsencrypt/live/your-domain.com/privkey.pem ./ssl/
```

## 🐳 Step 2: Docker Deployment (Simple)

### Quick Start
```bash
cd deploy/production

# Copy and configure environment
cp .env.example .env
# Edit .env with your secure values

# Deploy with Docker Compose
docker-compose -f docker-compose.prod.yml up -d

# Verify deployment
curl -k https://localhost/auth/health
```

### Database Setup
```bash
# Initialize database
docker-compose exec auth-service /app/scripts/init-db.sh

# Run migrations
docker-compose exec auth-service cargo run --bin migrate
```

## ☸️ Step 3: Kubernetes Deployment (Scalable)

### Deploy Infrastructure
```bash
# Deploy namespace and network policies
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/network-policies.yaml

# Deploy database and Redis
kubectl apply -f deploy/k8s/postgres-deployment.yaml
kubectl apply -f deploy/k8s/redis-deployment.yaml

# Wait for database to be ready
kubectl wait --for=condition=ready pod -l app=postgres --timeout=120s
```

### Deploy Services
```bash
# Deploy auth service with auto-scaling
kubectl apply -f deploy/k8s/auth-service-deployment.yaml

# Deploy policy service
kubectl apply -f deploy/k8s/policy-service-deployment.yaml

# Deploy security monitoring
kubectl apply -f deploy/k8s/security-monitoring.yaml

# Deploy scaling controls
kubectl apply -f deploy/k8s/scaling-security-controls.yaml
```

### Configure Ingress
```bash
# Deploy nginx ingress controller (if not present)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml

# Deploy application ingress
kubectl apply -f deploy/k8s/ingress.yaml
```

## 📊 Step 4: Monitoring Setup

### Prometheus & Grafana
```bash
# Deploy monitoring stack
kubectl apply -f deploy/k8s/security-monitoring.yaml

# Access Grafana (port-forward for initial setup)
kubectl port-forward svc/grafana 3000:3000 -n rust-security

# Import security dashboards
curl -X POST \
  http://admin:${GRAFANA_ADMIN_PASSWORD}@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @deploy/grafana/security-dashboard.json
```

### Configure Alerting
```bash
# Deploy AlertManager
kubectl apply -f deploy/k8s/alertmanager.yaml

# Configure notification channels (Slack, email, etc.)
kubectl create secret generic alertmanager-config \
  --from-file=deploy/alertmanager/alertmanager.yml \
  --namespace rust-security
```

## 🔍 Step 5: Security Validation

### Security Tests
```bash
# Run security test suite
cd security-testing
cargo test --features integration-tests

# Run penetration test suite
./scripts/pentest-suite.sh https://your-domain.com
```

### Load Testing
```bash
# Install load testing tools
cargo install drill

# Run load tests
drill --benchmark load-tests/auth-load-test.yml --stats
```

### Security Scanning
```bash
# Run security scan
docker run --rm -v $(pwd):/app \
  aquasec/trivy filesystem /app

# Check for vulnerabilities
cargo audit
```

## 🏥 Step 6: Health Checks & Monitoring

### Verify All Services
```bash
# Check service health
kubectl get pods -n rust-security
kubectl get services -n rust-security
kubectl get ingress -n rust-security

# Test endpoints
curl -k https://your-domain.com/auth/health
curl -k https://your-domain.com/policy/health
curl -k https://your-domain.com/metrics (from internal network)
```

### Monitor Key Metrics
```bash
# Check auto-scaling status
kubectl get hpa -n rust-security

# View recent scaling events
kubectl get events -n rust-security --sort-by='.lastTimestamp'

# Check security alerts
kubectl logs -n rust-security -l app=prometheus | grep ALERT
```

## 🔄 Step 7: Auto-Scaling Configuration

### Configure Scaling Thresholds
```yaml
# Edit scaling-security-controls.yaml
# Adjust these values based on your traffic patterns:
minReplicas: 3        # Minimum instances
maxReplicas: 20       # Maximum instances  
targetCPUUtilization: 70%
targetMemoryUtilization: 80%
```

### Test Auto-Scaling
```bash
# Generate load to trigger scaling
hey -z 5m -c 50 https://your-domain.com/auth/health

# Watch scaling in action
kubectl get pods -w -n rust-security
```

## 🛡️ Step 8: Security Hardening

### Network Security
```bash
# Verify network policies
kubectl describe netpol -n rust-security

# Check firewall rules (cloud-specific)
# AWS: Security Groups
# GCP: Firewall Rules
# Azure: Network Security Groups
```

### Access Controls
```bash
# Set up RBAC
kubectl apply -f deploy/k8s/rbac.yaml

# Verify minimal permissions
kubectl auth can-i list secrets --as=system:serviceaccount:rust-security:auth-service
```

## 📋 Production Checklist

### Pre-Launch
- [ ] All secrets generated and secured
- [ ] SSL certificates configured
- [ ] Database initialized and migrated
- [ ] All services deployed and healthy
- [ ] Monitoring and alerting configured
- [ ] Network policies applied
- [ ] Security tests passed
- [ ] Load tests completed
- [ ] Backup procedures tested

### Post-Launch
- [ ] Monitor error rates and performance
- [ ] Verify auto-scaling works correctly
- [ ] Test disaster recovery procedures
- [ ] Review security logs daily
- [ ] Update dependencies monthly
- [ ] Security audit quarterly

## 🚨 Emergency Procedures

### Scale Up Immediately
```bash
# Emergency scale up
kubectl patch hpa auth-service-hpa -n rust-security -p '{"spec":{"minReplicas":10}}'
```

### Enable DDoS Protection
```bash
# Tighten rate limits
kubectl patch configmap nginx-config -n rust-security --patch '
data:
  rate-limit: "10r/s"
  burst: "20"
'
```

### Security Incident Response
1. **Isolate**: Apply restrictive network policies
2. **Investigate**: Check logs and metrics
3. **Respond**: Scale resources, block IPs
4. **Recover**: Restore normal operations
5. **Review**: Post-incident analysis

## 📞 Support Contacts

### Monitoring Dashboards
- **Grafana**: https://your-domain.com:8443/grafana/
- **Prometheus**: https://your-domain.com:8443/prometheus/
- **Kubernetes Dashboard**: Apply k8s dashboard manifest

### Log Locations
- **Application Logs**: `kubectl logs -n rust-security -l app=auth-service`
- **Nginx Logs**: `kubectl logs -n rust-security -l app=nginx`
- **Security Events**: Check Prometheus alerts

---

**🎉 Congratulations! Your rust-security platform is now deployed in production with enterprise-grade security and auto-scaling capabilities.**