# Agent OS Installation Guide for Rust Security Platform

> **Version**: 1.0.0  
> **Last Updated**: 2025-08-28  
> **Compatibility**: Kubernetes 1.24+, Agent OS 2.0+

## 🎯 Overview

This guide provides step-by-step instructions for installing and integrating Agent OS with the Rust Security Platform. Agent OS will provide advanced orchestration, monitoring, and management capabilities for your security infrastructure.

## 📋 Prerequisites

### Required Components
- **Kubernetes Cluster**: 1.24+ with RBAC enabled
- **kubectl**: Configured and connected to your cluster
- **Docker**: For building custom images (optional)
- **Helm**: 3.8+ (recommended but optional)

### Recommended Components
- **Prometheus Operator**: For advanced monitoring
- **Istio/Linkerd**: For service mesh integration
- **Grafana**: For visualization dashboards
- **Consul**: For enhanced service discovery

### Resource Requirements
| Component | CPU Request | Memory Request | CPU Limit | Memory Limit |
|-----------|-------------|----------------|-----------|--------------|
| Agent OS Coordinator | 100m | 128Mi | 500m | 512Mi |
| Consul Agent | 100m | 128Mi | 200m | 256Mi |
| **Total** | **200m** | **256Mi** | **700m** | **768Mi** |

## 🚀 Quick Installation

### Option 1: Automated Installation (Recommended)

```bash
# Clone the repository (if not already done)
git clone <your-repository-url>
cd rust-security

# Run the automated installer
./install-agent-os.sh install
```

### Option 2: Manual Installation

```bash
# Create namespace
kubectl create namespace rust-security

# Apply configurations in order
kubectl apply -f agent-os-integration.yaml
kubectl apply -f agent-os-monitoring.yaml  
kubectl apply -f agent-os-service-discovery.yaml

# Verify installation
kubectl get pods -n rust-security -l app=agent-os
```

## 📖 Detailed Installation Steps

### Step 1: Environment Preparation

First, ensure your Kubernetes cluster meets the requirements:

```bash
# Check Kubernetes version
kubectl version

# Check cluster nodes
kubectl get nodes

# Verify RBAC is enabled
kubectl auth can-i create clusterroles --as=system:serviceaccount:kube-system:default
```

### Step 2: Configure Prerequisites

#### Install Prometheus Operator (Optional but Recommended)
```bash
# Add Prometheus community Helm repository
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Install Prometheus operator
helm install prometheus-operator prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
```

#### Install Istio Service Mesh (Optional)
```bash
# Download and install Istio
curl -L https://istio.io/downloadIstio | sh -
cd istio-*
export PATH=$PWD/bin:$PATH

# Install Istio
istioctl install --set values.defaultRevision=default
kubectl label namespace rust-security istio-injection=enabled
```

### Step 3: Deploy Rust Security Platform (If Not Already Deployed)

```bash
# Build and deploy core services
cargo build --release

# Deploy to Kubernetes
kubectl apply -f k8s/
```

### Step 4: Install Agent OS Integration

#### 4.1 Apply Core Configuration
```bash
kubectl apply -f agent-os-integration.yaml
```

This creates:
- `agent-os-config` ConfigMap with service configuration
- `agent-os-environment` ConfigMap with environment variables
- `agent-os-coordinator` Deployment
- `agent-os-coordinator` Service
- RBAC resources (ServiceAccount, ClusterRole, ClusterRoleBinding)
- NetworkPolicy for security

#### 4.2 Apply Monitoring Configuration
```bash
kubectl apply -f agent-os-monitoring.yaml
```

This creates:
- ServiceMonitor resources for Prometheus
- PrometheusRule for alerting
- Grafana dashboard ConfigMap
- Custom metrics definitions
- Logging configuration

#### 4.3 Apply Service Discovery Configuration
```bash
kubectl apply -f agent-os-service-discovery.yaml
```

This creates:
- Consul agent deployment
- Service discovery configuration
- Health check CronJob
- EndpointSlice for custom discovery

### Step 5: Verification

#### 5.1 Check Pod Status
```bash
kubectl get pods -n rust-security -l app=agent-os
```

Expected output:
```
NAME                                    READY   STATUS    RESTARTS   AGE
agent-os-coordinator-7d4b8c9f6d-abc123  1/1     Running   0          2m
consul-agent-5f6g7h8i9j-def456         1/1     Running   0          2m
```

#### 5.2 Test Health Endpoints
```bash
# Test Agent OS coordinator
kubectl port-forward -n rust-security svc/agent-os-coordinator 8090:8090 &
curl http://localhost:8090/health

# Expected response: {"status": "healthy", "timestamp": "..."}
```

#### 5.3 Verify Service Discovery
```bash
# Check discovered services
kubectl get endpoints -n rust-security

# Check Consul services
kubectl port-forward -n rust-security svc/consul 8500:8500 &
curl http://localhost:8500/v1/catalog/services
```

## 🔧 Configuration

### Environment Variables

You can customize the installation by modifying the `agent-os-environment` ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: agent-os-environment
  namespace: rust-security
data:
  # Service URLs
  AUTH_SERVICE_URL: "http://auth-service:8080"
  POLICY_SERVICE_URL: "http://policy-service:8081"
  
  # Performance tuning
  MAX_CONCURRENT_REQUESTS: "2000"
  CONNECTION_TIMEOUT: "15s"
  
  # Security settings
  TLS_ENABLED: "true"
  MTLS_ENABLED: "true"
  
  # Logging
  LOG_LEVEL: "debug"  # info, debug, warn, error
```

### Agent OS Configuration

Modify the `agent-os-config` ConfigMap to customize Agent OS behavior:

```yaml
# Key configuration sections:
integrations:
  monitoring:
    enabled: true
    prometheus_endpoint: "${PROMETHEUS_URL}/api/v1"
    
performance:
  circuit_breaker:
    failure_threshold: 3  # Reduce for faster failover
    recovery_timeout: "15s"
    
security:
  authentication:
    methods:
      - "oauth2"
      - "jwt"
      - "mtls"  # Enable mTLS
```

## 📊 Monitoring and Observability

### Grafana Dashboard

1. Import the dashboard from the ConfigMap:
```bash
kubectl get configmap -n rust-security agent-os-grafana-dashboard -o jsonpath='{.data.agent-os-dashboard\.json}' > agent-os-dashboard.json
```

2. Import to Grafana:
   - Open Grafana UI
   - Go to Dashboards → Import
   - Upload `agent-os-dashboard.json`

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `agent_os_services_discovered` | Number of discovered services | < 2 |
| `agent_os_integration_health` | Integration health status | < 1 |
| `agent_os_request_duration_seconds` | Request latency | P95 > 1s |
| `agent_os_requests_failed_total` | Failed requests | Rate > 5% |

### Alerts Configuration

The installation includes pre-configured alerts:

- **AgentOSServiceDown**: Triggers when Agent OS is unreachable
- **AgentOSHighLatency**: Triggers on P95 latency > 1s
- **AuthServiceIntegrationDown**: Triggers when auth service is unreachable

## 🔍 Troubleshooting

### Common Issues

#### 1. Pod Startup Issues
```bash
# Check pod events
kubectl describe pod -n rust-security -l app=agent-os

# Check logs
kubectl logs -n rust-security deployment/agent-os-coordinator
```

#### 2. Service Discovery Problems
```bash
# Check service endpoints
kubectl get endpoints -n rust-security

# Test DNS resolution
kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup auth-service.rust-security.svc.cluster.local
```

#### 3. Integration Health Issues
```bash
# Check network connectivity
kubectl exec -n rust-security deployment/agent-os-coordinator -- curl -v http://auth-service:8080/health

# Check network policies
kubectl get networkpolicy -n rust-security
```

#### 4. Monitoring Issues
```bash
# Check ServiceMonitor
kubectl get servicemonitor -n rust-security

# Verify Prometheus targets
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090
# Visit http://localhost:9090/targets
```

### Debug Commands

```bash
# Get all Agent OS resources
kubectl get all -n rust-security -l app=agent-os

# Check configuration
kubectl get configmap -n rust-security agent-os-config -o yaml

# View recent events
kubectl get events -n rust-security --sort-by='.lastTimestamp' | tail -20

# Test service connectivity
kubectl run -it --rm test-pod --image=curlimages/curl --restart=Never -- sh
```

## 🔒 Security Considerations

### Network Security
- NetworkPolicies restrict traffic to necessary services only
- mTLS encryption for service-to-service communication
- TLS 1.3 for external connections

### RBAC Configuration
- Minimal required permissions for Agent OS
- Separate ServiceAccount with limited cluster access
- ClusterRole restricted to read-only operations

### Secret Management
- Secrets stored in Kubernetes secrets (not ConfigMaps)
- Integration with external secret management (Vault, AWS Secrets Manager)
- Automatic secret rotation support

## 🚀 Advanced Configuration

### High Availability Setup

For production deployments, configure HA:

```yaml
# Increase replicas
spec:
  replicas: 3
  
# Add pod disruption budget
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: agent-os-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: agent-os
```

### Custom Resource Limits

Adjust based on your workload:

```yaml
resources:
  requests:
    cpu: "200m"      # Increase for high throughput
    memory: "256Mi"
  limits:
    cpu: "1000m"     # Adjust based on usage
    memory: "1Gi"
```

### Integration with External Systems

#### Vault Integration
```yaml
# Add to agent-os-config
integrations:
  vault:
    enabled: true
    address: "https://vault.company.com"
    auth_method: "kubernetes"
```

#### AWS Integration
```yaml
# Add service account annotation
annotations:
  eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT:role/AgentOSRole
```

## 📚 Additional Resources

### Documentation Links
- [Agent OS Official Documentation](https://docs.agent-os.com)
- [Rust Security Platform API](./api-contracts/README.md)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)

### Community Resources
- GitHub Issues: [Report bugs and request features]
- Community Discord: [Join discussions]
- Contributing Guide: [./CONTRIBUTING.md](./CONTRIBUTING.md)

## 🆘 Support

### Getting Help
1. **Check Troubleshooting Section**: Most common issues are covered above
2. **Review Logs**: Use kubectl logs to inspect component logs
3. **Check GitHub Issues**: Search for existing issues
4. **Create New Issue**: If problem persists, create a detailed issue

### Issue Template
When reporting issues, include:
- Kubernetes version
- Agent OS version  
- Complete error logs
- Configuration files (sanitized)
- Steps to reproduce

---

## ✅ Installation Complete

If you've followed this guide successfully, you should now have:

- ✅ Agent OS integrated with Rust Security Platform
- ✅ Service discovery configured and operational
- ✅ Monitoring and alerting enabled
- ✅ Health checks and verification passing

**Next Steps:**
1. Configure your applications to use the integrated authentication
2. Set up custom policies in the Policy Service
3. Configure monitoring dashboards
4. Review security settings and adjust as needed

For additional configuration and advanced features, refer to the [Operations Guide](./docs/operations/operations-guide.md).

---

<div align="center">
  <strong>🎉 Welcome to Agent OS integrated Rust Security Platform!</strong>
  <br>
  <sub>Enterprise-grade security with intelligent orchestration</sub>
</div>