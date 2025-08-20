# Resource Management Guide

This guide explains the comprehensive resource management implementation for the Rust Security Platform, including Horizontal Pod Autoscaling (HPA), Pod Disruption Budgets (PDB), and resource optimization for production deployments.

## Overview

The Auth Service implements enterprise-grade resource management to ensure:

- **High Availability**: Maintains service availability during node failures and maintenance
- **Auto-scaling**: Automatically scales based on resource utilization and custom metrics
- **Resource Efficiency**: Optimizes resource allocation to minimize costs
- **Performance**: Maintains consistent performance under varying loads
- **Fault Tolerance**: Gracefully handles infrastructure issues

## Resource Allocation

### Default Resource Configuration

```yaml
resources:
  limits:
    cpu: 1000m      # 1 CPU core maximum
    memory: 512Mi   # 512 MB maximum
  requests:
    cpu: 100m       # 0.1 CPU core guaranteed
    memory: 128Mi   # 128 MB guaranteed
```

### Resource Tuning Guidelines

#### CPU Configuration

**Request Sizing**:
- **Development**: 100m (0.1 core)
- **Staging**: 200m (0.2 core)  
- **Production**: 250m (0.25 core)

**Limit Sizing**:
- **Development**: 500m (0.5 core)
- **Staging**: 1000m (1 core)
- **Production**: 2000m (2 cores)

#### Memory Configuration

**Request Sizing**:
- **Development**: 128Mi
- **Staging**: 256Mi
- **Production**: 512Mi

**Limit Sizing**:
- **Development**: 256Mi
- **Staging**: 512Mi
- **Production**: 1Gi

### Load-Based Resource Profiles

#### Light Load Profile
```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

#### Medium Load Profile
```yaml
resources:
  requests:
    cpu: 250m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```

#### Heavy Load Profile
```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 1Gi
```

## Horizontal Pod Autoscaling (HPA)

### Basic HPA Configuration

```yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### Advanced HPA v2 Features

#### Scaling Behavior Configuration

```yaml
autoscaling:
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300  # Wait 5 minutes before scaling down
      percentPolicy: 50               # Max 50% scale down at once
      podsPolicy: 2                   # Max 2 pods removed at once
      periodSeconds: 60               # Evaluate every minute
      selectPolicy: "Min"             # Use conservative scaling
    scaleUp:
      stabilizationWindowSeconds: 60   # Wait 1 minute before scaling up
      percentPolicy: 100              # Max 100% scale up at once
      podsPolicy: 4                   # Max 4 pods added at once
      periodSeconds: 60               # Evaluate every minute
      selectPolicy: "Max"             # Use aggressive scaling
```

#### Custom Metrics Scaling

**Request Rate Based Scaling**:
```yaml
customMetrics:
  - type: "Pods"
    metric:
      name: "http_requests_per_second"
    target:
      type: "AverageValue"
      averageValue: "100"
```

**Queue Depth Based Scaling**:
```yaml
customMetrics:
  - type: "External"
    metric:
      name: "redis_queue_depth"
      selector:
        matchLabels:
          queue: "auth-tasks"
    target:
      type: "Value"
      value: "50"
```

**Response Time Based Scaling**:
```yaml
customMetrics:
  - type: "Pods"
    metric:
      name: "http_request_duration_p95"
    target:
      type: "AverageValue"
      averageValue: "500m"  # 500ms
```

### Scaling Strategies

#### Conservative Scaling
- Slower scale-up, slower scale-down
- Good for predictable workloads
- Minimizes resource waste

```yaml
behavior:
  scaleDown:
    stabilizationWindowSeconds: 600  # 10 minutes
    percentPolicy: 25               # Max 25% scale down
  scaleUp:
    stabilizationWindowSeconds: 120  # 2 minutes
    percentPolicy: 50               # Max 50% scale up
```

#### Aggressive Scaling
- Faster scale-up, moderate scale-down
- Good for spiky workloads
- Prioritizes performance over cost

```yaml
behavior:
  scaleDown:
    stabilizationWindowSeconds: 300  # 5 minutes
    percentPolicy: 50               # Max 50% scale down
  scaleUp:
    stabilizationWindowSeconds: 30   # 30 seconds
    percentPolicy: 200              # Max 200% scale up
```

#### Balanced Scaling
- Moderate scale-up and scale-down
- Good for most production workloads
- Balances performance and cost

```yaml
behavior:
  scaleDown:
    stabilizationWindowSeconds: 300  # 5 minutes
    percentPolicy: 33               # Max 33% scale down
  scaleUp:
    stabilizationWindowSeconds: 60   # 1 minute
    percentPolicy: 100              # Max 100% scale up
```

## Pod Disruption Budget (PDB)

### Basic PDB Configuration

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 2  # Always keep 2 pods running
```

### Alternative PDB Configurations

#### Percentage-Based PDB
```yaml
podDisruptionBudget:
  enabled: true
  maxUnavailable: "33%"  # Allow max 33% unavailable
```

#### Absolute Number PDB
```yaml
podDisruptionBudget:
  enabled: true
  maxUnavailable: 1      # Allow max 1 pod unavailable
```

### PDB Best Practices

1. **For High Availability**: Use `minAvailable` with at least 2 pods
2. **For Rolling Updates**: Use `maxUnavailable` as percentage
3. **For Small Deployments**: Use absolute numbers
4. **For Large Deployments**: Use percentages

#### PDB Sizing Guidelines

| Replica Count | minAvailable | maxUnavailable | Reasoning |
|---------------|--------------|----------------|-----------|
| 1-2           | 1            | 1              | Minimal disruption |
| 3-5           | 2            | 1              | Maintain majority |
| 6-10          | 50%          | 33%            | Percentage-based |
| 10+           | 66%          | 25%            | Conservative |

## Node Affinity and Pod Distribution

### Anti-Affinity Configuration

```yaml
affinity:
  podAntiAffinity:
    # Prefer to spread pods across nodes
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - auth-service
        topologyKey: kubernetes.io/hostname
    
    # Require spreading across zones (if available)
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app.kubernetes.io/name
          operator: In
          values:
          - auth-service
      topologyKey: topology.kubernetes.io/zone
```

### Node Selection

#### Node Selector for Dedicated Nodes
```yaml
nodeSelector:
  workload-type: "auth-service"
  instance-type: "compute-optimized"
```

#### Tolerations for Tainted Nodes
```yaml
tolerations:
- key: "dedicated"
  operator: "Equal"
  value: "auth-service"
  effect: "NoSchedule"
```

## Monitoring and Alerting

### Resource Metrics

Monitor these key metrics for resource management:

#### CPU Metrics
- `container_cpu_usage_seconds_total`
- `container_spec_cpu_quota`
- `container_spec_cpu_shares`

#### Memory Metrics  
- `container_memory_usage_bytes`
- `container_spec_memory_limit_bytes`
- `container_memory_working_set_bytes`

#### HPA Metrics
- `kube_hpa_status_current_replicas`
- `kube_hpa_status_desired_replicas`
- `kube_hpa_spec_max_replicas`
- `kube_hpa_spec_min_replicas`

### Alerting Rules

#### Resource Alerts
```yaml
# High CPU usage
- alert: AuthServiceHighCPU
  expr: rate(container_cpu_usage_seconds_total{pod=~"auth-service-.*"}[5m]) > 0.8
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Auth Service CPU usage is high"

# High memory usage
- alert: AuthServiceHighMemory
  expr: container_memory_usage_bytes{pod=~"auth-service-.*"} / container_spec_memory_limit_bytes > 0.9
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Auth Service memory usage is high"

# HPA at max replicas
- alert: AuthServiceHPAMaxReplicas
  expr: kube_hpa_status_current_replicas{hpa="auth-service"} >= kube_hpa_spec_max_replicas
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Auth Service HPA is at maximum replicas"
```

#### PDB Alerts
```yaml
# PDB violations
- alert: AuthServicePDBViolation
  expr: kube_poddisruptionbudget_status_pod_healthy{poddisruptionbudget="auth-service"} < kube_poddisruptionbudget_status_desired_healthy
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Auth Service PDB violation detected"
```

## Deployment Strategies

### Rolling Update Configuration

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxUnavailable: 1      # Only 1 pod unavailable during update
    maxSurge: 2           # Up to 2 extra pods during update
```

### Blue-Green Deployment

For zero-downtime deployments:

1. **Deploy green environment** alongside blue
2. **Test green environment** thoroughly
3. **Switch traffic** from blue to green
4. **Monitor and rollback** if needed

### Canary Deployment

For gradual traffic shifting:

1. **Deploy canary version** with 10% traffic
2. **Monitor metrics** for errors and performance
3. **Gradually increase** canary traffic
4. **Complete rollout** or rollback

## Performance Optimization

### Resource Right-Sizing

#### CPU Optimization
```bash
# Analyze CPU usage patterns
kubectl top pods -n rust-security --sort-by=cpu

# Get detailed CPU metrics
kubectl exec -it auth-service-xxx -- cat /proc/stat
```

#### Memory Optimization
```bash
# Analyze memory usage
kubectl top pods -n rust-security --sort-by=memory

# Get detailed memory metrics
kubectl exec -it auth-service-xxx -- cat /proc/meminfo
```

### Vertical Pod Autoscaling (VPA)

For automatic resource recommendations:

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: auth-service-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  updatePolicy:
    updateMode: "Off"  # Recommendation only
  resourcePolicy:
    containerPolicies:
    - containerName: auth-service
      maxAllowed:
        cpu: 2
        memory: 2Gi
      minAllowed:
        cpu: 100m
        memory: 128Mi
```

## Troubleshooting

### Common Issues

#### 1. Pods Not Scaling
```bash
# Check HPA status
kubectl get hpa auth-service -o yaml

# Check metrics server
kubectl top nodes
kubectl top pods

# Check resource metrics
kubectl describe hpa auth-service
```

#### 2. PDB Preventing Updates
```bash
# Check PDB status
kubectl get pdb auth-service -o yaml

# Check disruption events
kubectl get events --field-selector involvedObject.name=auth-service
```

#### 3. Resource Limits Hit
```bash
# Check resource usage
kubectl top pods auth-service-xxx

# Check events for OOMKilled
kubectl describe pod auth-service-xxx | grep -A 10 Events
```

#### 4. Node Resource Pressure
```bash
# Check node capacity
kubectl describe nodes

# Check resource allocation
kubectl describe node NODE_NAME | grep -A 10 "Allocated resources"
```

### Debugging Commands

```bash
# Get resource usage history
kubectl top pods --containers -n rust-security

# Check HPA scaling history
kubectl describe hpa auth-service

# Analyze pod resource requests vs limits
kubectl get pods -o custom-columns=NAME:.metadata.name,CPU_REQ:.spec.containers[*].resources.requests.cpu,CPU_LIM:.spec.containers[*].resources.limits.cpu,MEM_REQ:.spec.containers[*].resources.requests.memory,MEM_LIM:.spec.containers[*].resources.limits.memory

# Check node resource availability
kubectl get nodes -o custom-columns=NAME:.metadata.name,CPU_REQ:.status.allocatable.cpu,MEM_REQ:.status.allocatable.memory
```

## Production Deployment Examples

### Small Production Environment
```yaml
replicaCount: 3

resources:
  requests:
    cpu: 250m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 6
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Large Production Environment
```yaml
replicaCount: 5

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 5
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

podDisruptionBudget:
  enabled: true
  maxUnavailable: "25%"
```

### High-Availability Environment
```yaml
replicaCount: 6

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 6
  maxReplicas: 30
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 30
      percentPolicy: 200
    scaleDown:
      stabilizationWindowSeconds: 600
      percentPolicy: 25

podDisruptionBudget:
  enabled: true
  minAvailable: 4

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchLabels:
          app.kubernetes.io/name: auth-service
      topologyKey: kubernetes.io/hostname
```

This comprehensive resource management setup ensures optimal performance, availability, and cost-efficiency for the Rust Security Platform in production environments.