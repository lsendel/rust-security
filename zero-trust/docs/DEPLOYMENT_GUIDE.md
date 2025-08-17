# Zero-Trust Architecture Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying a comprehensive zero-trust architecture for the Rust authentication service. The implementation includes service mesh security, identity-centric access controls, continuous verification, and runtime security monitoring.

## Architecture Components

### Core Infrastructure
- **Istio Service Mesh**: mTLS, traffic management, and observability
- **SPIRE**: SPIFFE-based workload identity and attestation
- **Open Policy Agent (OPA)**: Fine-grained authorization policies
- **Falco**: Runtime security monitoring and threat detection

### Security Services
- **Device Trust Service**: Device fingerprinting and trust assessment
- **Zero-Trust Gateway**: Secure ingress with WAF and rate limiting
- **Policy Engine**: Risk-based access control and continuous verification
- **Security Monitoring**: Comprehensive observability and alerting

## Prerequisites

### Required Tools
```bash
# Kubernetes cluster (1.25+)
kubectl version --client

# Istio service mesh
istioctl version

# Helm package manager
helm version

# Container runtime
docker version
```

### Cluster Requirements
- Kubernetes 1.25 or later
- At least 3 worker nodes
- 8 CPU cores and 16GB RAM minimum
- LoadBalancer service support
- Persistent volume support

### Network Requirements
- Pod-to-pod networking (CNI)
- Network policy support (Calico/Cilium recommended)
- External load balancer support
- DNS resolution

## Deployment Steps

### Step 1: Prepare Environment

```bash
# Clone the repository
git clone <repository-url>
cd rust-security/zero-trust

# Set environment variables
export ZT_DOMAIN="zero-trust.local"
export ZT_NAMESPACE="rust-security-zt"
export CLUSTER_NAME="zero-trust-cluster"

# Verify cluster access
kubectl cluster-info
kubectl get nodes
```

### Step 2: Deploy Foundation

```bash
# Execute the deployment script
./scripts/deploy-zero-trust.sh

# The script will:
# 1. Create namespaces
# 2. Install Istio service mesh
# 3. Deploy SPIRE identity infrastructure
# 4. Set up OPA policy engine
# 5. Deploy security monitoring
# 6. Configure applications
```

### Step 3: Verify Deployment

```bash
# Check all components are running
kubectl get pods -n zero-trust-system
kubectl get pods -n rust-security-zt
kubectl get pods -n spire-system
kubectl get pods -n policy-system
kubectl get pods -n istio-system

# Verify Istio configuration
istioctl proxy-status
istioctl analyze

# Check SPIFFE identities
kubectl exec -n spire-system deployment/spire-server -- \
  /opt/spire/bin/spire-server entry show
```

### Step 4: Enable Strict Mode

```bash
# Enable strict zero-trust enforcement
./scripts/deploy-zero-trust.sh --strict

# This will:
# - Enable strict mTLS
# - Activate policy enforcement
# - Configure continuous verification
```

### Step 5: Run Security Tests

```bash
# Execute security test suite
kubectl apply -f testing/security-tests.yaml

# Run penetration tests
kubectl exec -n zero-trust-system security-tests -- \
  /bin/bash /penetration-tests.sh
```

## Configuration Guide

### Service Mesh Configuration

#### mTLS Settings
```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system
spec:
  mtls:
    mode: STRICT  # Change to PERMISSIVE for gradual rollout
```

#### Authorization Policies
```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: auth-service-access
  namespace: rust-security-zt
spec:
  selector:
    matchLabels:
      app: auth-service
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - "cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"
    when:
    - key: source.certificate_fingerprint
      values: ["*"]
```

### Identity Configuration

#### SPIFFE Identity Templates
```yaml
apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterSPIFFEID
metadata:
  name: auth-service-spiffeid
spec:
  spiffeIDTemplate: "spiffe://zero-trust.local/auth-service/{{ .PodMeta.Name }}"
  podSelector:
    matchLabels:
      app: auth-service
  ttl: "1h"
```

### Policy Configuration

#### OPA Policies
```rego
package envoy.authz

default allow := false

allow if {
    input.attributes.request.http.method == "GET"
    input.attributes.request.http.path == "/health"
    is_internal_request
}

allow if {
    has_valid_spiffe_id
    has_valid_device_trust
    request_rate_limited
    not_from_blocked_ip
}
```

### Device Trust Configuration

#### Trust Scoring Rules
```yaml
trust_rules:
  - name: "corporate_device"
    conditions:
      - field: "device.domain"
        operator: "equals"
        value: "corp.zero-trust.local"
    score_modifier: 3
    
  - name: "updated_os"
    conditions:
      - field: "device.os_patch_level"
        operator: "less_than_days_old"
        value: 30
    score_modifier: 2
```

## Monitoring and Observability

### Security Metrics

#### Prometheus Queries
```promql
# mTLS connection success rate
rate(istio_request_total{security_policy="mutual_tls"}[5m])

# Policy enforcement success rate
rate(envoy_http_ext_authz_ok[5m])

# Device trust scores
histogram_quantile(0.95, device_trust_score_bucket)

# Threat detection alerts
rate(falco_events{priority="Critical"}[5m])
```

#### Grafana Dashboards
- Zero-Trust Security Overview
- Service Mesh Metrics
- Device Trust Analytics
- Threat Detection Dashboard

### Alerting Rules

#### Critical Alerts
```yaml
groups:
- name: zero-trust-critical
  rules:
  - alert: mTLSConnectionFailure
    expr: rate(istio_request_total{security_policy!="mutual_tls"}[5m]) > 0.01
    for: 1m
    annotations:
      summary: "mTLS connection failure detected"
      
  - alert: PolicyEnforcementFailure
    expr: rate(envoy_http_ext_authz_denied[5m]) / rate(envoy_http_ext_authz_total[5m]) > 0.1
    for: 2m
    annotations:
      summary: "High policy enforcement failure rate"
```

## Troubleshooting

### Common Issues

#### 1. Pods Not Starting
```bash
# Check pod status and events
kubectl describe pod <pod-name> -n <namespace>
kubectl get events -n <namespace> --sort-by='.lastTimestamp'

# Check resource constraints
kubectl top pods -n <namespace>
kubectl describe nodes
```

#### 2. mTLS Connection Issues
```bash
# Check certificate status
istioctl proxy-config secret <pod-name>.<namespace>

# Verify peer authentication
istioctl authn tls-check <service>.<namespace>.svc.cluster.local

# Check proxy configuration
istioctl proxy-config cluster <pod-name>.<namespace>
```

#### 3. SPIFFE Identity Issues
```bash
# Check SPIRE server logs
kubectl logs -n spire-system deployment/spire-server

# Verify agent registration
kubectl exec -n spire-system deployment/spire-server -- \
  /opt/spire/bin/spire-server agent list

# Check workload registration
kubectl exec -n spire-system deployment/spire-server -- \
  /opt/spire/bin/spire-server entry show
```

#### 4. Policy Enforcement Issues
```bash
# Check OPA status
kubectl logs -n policy-system deployment/opa

# Test policy evaluation
kubectl exec -n policy-system deployment/opa -- \
  curl -X POST localhost:8181/v1/data/envoy/authz/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"attributes": {...}}}'
```

### Debug Commands

```bash
# Get comprehensive status
./scripts/deploy-zero-trust.sh --validate

# Check Istio configuration
istioctl analyze --all-namespaces

# Verify network policies
kubectl get networkpolicies -A

# Check security contexts
kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext}{"\n"}{end}'
```

## Performance Tuning

### Resource Optimization

#### Istio Sidecar Configuration
```yaml
metadata:
  annotations:
    sidecar.istio.io/proxyCPU: "50m"
    sidecar.istio.io/proxyMemory: "128Mi"
    sidecar.istio.io/inject: "true"
```

#### OPA Performance Tuning
```yaml
env:
- name: OPA_CACHE_SIZE
  value: "1000"
- name: OPA_DECISION_LOG_CONSOLE
  value: "false"
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

### Network Optimization

#### Connection Pooling
```yaml
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: auth-service-dr
spec:
  host: auth-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 64
        maxRequestsPerConnection: 10
```

## Security Hardening

### Additional Hardening Steps

1. **Container Security**
   - Use minimal base images
   - Run as non-root users
   - Enable read-only root filesystem
   - Drop all capabilities

2. **Network Security**
   - Implement network policies
   - Use private container registries
   - Enable pod security standards

3. **Secrets Management**
   - Use external secret management
   - Rotate secrets regularly
   - Encrypt secrets at rest

4. **Compliance**
   - Enable audit logging
   - Implement resource quotas
   - Configure admission controllers

## Migration from Existing Setup

### Migration Strategy

1. **Parallel Deployment**
   - Deploy zero-trust infrastructure alongside existing
   - Gradually migrate traffic
   - Validate functionality at each step

2. **Blue-Green Migration**
   - Deploy complete zero-trust environment
   - Switch traffic after validation
   - Keep original as fallback

3. **Canary Migration**
   - Route small percentage of traffic
   - Gradually increase traffic
   - Monitor for issues

### Migration Script
```bash
# Start migration
./scripts/deploy-zero-trust.sh

# Validate parallel deployment
./scripts/deploy-zero-trust.sh --validate

# Switch to strict mode
./scripts/deploy-zero-trust.sh --strict

# Complete migration
kubectl label namespace rust-security istio-injection=enabled
kubectl rollout restart deployment -n rust-security
```

## Maintenance

### Regular Maintenance Tasks

1. **Certificate Rotation**
   - SPIFFE certificates auto-rotate
   - Monitor certificate expiration
   - Update root CA if needed

2. **Policy Updates**
   - Review and update OPA policies
   - Test policy changes in staging
   - Monitor policy effectiveness

3. **Security Updates**
   - Update container images regularly
   - Apply security patches
   - Review security configurations

4. **Performance Monitoring**
   - Monitor resource usage
   - Optimize configurations
   - Scale components as needed

### Backup and Recovery

```bash
# Backup SPIRE data
kubectl exec -n spire-system deployment/spire-server -- \
  tar -czf /tmp/spire-backup.tar.gz /run/spire/data

# Backup OPA policies
kubectl get configmap -n policy-system opa-policies -o yaml > opa-backup.yaml

# Backup Istio configuration
istioctl proxy-config dump -o yaml > istio-config-backup.yaml
```

## Support and Documentation

### Additional Resources
- [Istio Documentation](https://istio.io/docs/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire/)
- [OPA Documentation](https://www.openpolicyagent.org/docs/)
- [Falco Documentation](https://falco.org/docs/)

### Getting Help
- Check logs: `kubectl logs -f deployment/<service> -n <namespace>`
- Review events: `kubectl get events -n <namespace>`
- Use debug tools: `istioctl analyze`, `spire-server entry show`
- Consult troubleshooting section above

This completes the comprehensive zero-trust architecture deployment guide for the Rust authentication service.