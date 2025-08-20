# Operations Runbook

## Overview

This runbook provides comprehensive operational procedures for the Rust Security Platform, covering incident response, troubleshooting, maintenance procedures, and operational best practices.

## Service Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Auth Service  │    │ Policy Service  │
│                 │────│                 │────│                 │
│ • Rate Limiting │    │ • Authentication│    │ • Authorization │
│ • TLS Term      │    │ • Token Mgmt    │    │ • Cedar Engine  │
│ • Health Checks │    │ • User Mgmt     │    │ • Policy Store  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                    ┌─────────────────────────┬─────────────────────────┐
                    │                         │                         │
          ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
          │  Redis Cluster  │    │   Monitoring    │    │ External APIs   │
          │                 │    │                 │    │                 │
          │ • Session Store │    │ • Prometheus    │    │ • OIDC Providers│
          │ • Rate Limits   │    │ • Grafana       │    │ • SCIM Targets  │
          │ • Cache Layer   │    │ • Alertmanager  │    │ • Audit Systems │
          └─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Incident Response

### Severity Levels

#### Severity 1 (Critical)
- **Definition**: Complete service outage or security breach
- **Response Time**: 15 minutes
- **Escalation**: Immediate
- **Examples**: 
  - All services down
  - Data breach detected
  - Authentication completely failing

#### Severity 2 (High)
- **Definition**: Major functionality impacted
- **Response Time**: 1 hour
- **Escalation**: Within 30 minutes if not resolved
- **Examples**:
  - Single service degraded
  - High error rates
  - Performance severely impacted

#### Severity 3 (Medium)
- **Definition**: Minor functionality impacted
- **Response Time**: 4 hours
- **Escalation**: Within 2 hours if not resolved
- **Examples**:
  - Non-critical features affected
  - Intermittent issues
  - Minor performance degradation

#### Severity 4 (Low)
- **Definition**: Cosmetic issues or minor inconveniences
- **Response Time**: Next business day
- **Escalation**: Within 1 business day
- **Examples**:
  - UI inconsistencies
  - Documentation errors
  - Minor configuration issues

### Incident Response Procedures

#### Initial Response (First 15 minutes)
1. **Acknowledge the incident** in monitoring system
2. **Assess severity** using criteria above
3. **Notify stakeholders** based on severity level
4. **Begin immediate triage** - check service status
5. **Establish communication channel** (Slack, Teams, etc.)

#### Investigation Phase (15-60 minutes)
1. **Gather initial information**:
   ```bash
   # Check service health
   kubectl get pods -n rust-security
   kubectl get svc -n rust-security
   kubectl get ingress -n rust-security
   
   # Check recent events
   kubectl get events --sort-by=.metadata.creationTimestamp -n rust-security
   
   # Check logs
   kubectl logs -l app=auth-service --tail=100 -n rust-security
   kubectl logs -l app=policy-service --tail=100 -n rust-security
   ```

2. **Check monitoring dashboards**:
   - Service availability metrics
   - Error rate trends
   - Latency percentiles
   - Resource utilization
   - External dependency status

3. **Identify root cause**:
   - Recent deployments
   - Configuration changes
   - Infrastructure changes
   - External service issues

#### Mitigation Phase (Immediate)
1. **Implement immediate fixes**:
   ```bash
   # Restart failing pods
   kubectl rollout restart deployment/auth-service -n rust-security
   
   # Scale up if resource constrained
   kubectl scale deployment auth-service --replicas=10 -n rust-security
   
   # Rollback recent deployment if needed
   kubectl rollout undo deployment/auth-service -n rust-security
   ```

2. **Traffic management**:
   ```bash
   # Enable maintenance mode
   kubectl annotate ingress auth-service-ingress \
     nginx.ingress.kubernetes.io/custom-http-errors="503" \
     -n rust-security
   
   # Implement rate limiting
   kubectl patch configmap nginx-configuration \
     --patch='{"data":{"rate-limit-requests-per-second":"10"}}' \
     -n ingress-nginx
   ```

#### Resolution Phase
1. **Implement permanent fix**
2. **Validate service recovery**
3. **Monitor for stability**
4. **Gradually restore traffic**
5. **Update monitoring and alerting**

#### Post-Incident Phase
1. **Write incident report** within 24 hours
2. **Conduct post-mortem** within 48 hours
3. **Implement preventive measures**
4. **Update runbooks and procedures**
5. **Share learnings with team**

## Common Issues and Troubleshooting

### Auth Service Issues

#### Issue: Login Failures
**Symptoms**: Users unable to authenticate, high 401 error rates

**Investigation**:
```bash
# Check authentication error rates
kubectl logs -l app=auth-service | grep "authentication_failed"

# Check JWT token validation
kubectl logs -l app=auth-service | grep "token_validation_error"

# Check external OIDC provider connectivity
kubectl exec -it auth-service-xxx -- curl -I https://accounts.google.com/.well-known/openid_configuration
```

**Common Causes**:
- JWT secret rotation without service restart
- OIDC provider configuration changes
- Clock skew between services
- Database connectivity issues

**Solutions**:
```bash
# Restart auth service to reload configuration
kubectl rollout restart deployment/auth-service -n rust-security

# Check and update OIDC configuration
kubectl get secret auth-service-config -o yaml | base64 -d

# Sync time on nodes
sudo chrony sources -v
```

#### Issue: High Latency
**Symptoms**: Slow response times, timeouts

**Investigation**:
```bash
# Check response time metrics
curl -s http://prometheus:9090/api/v1/query?query='histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{service="auth-service"}[5m]))'

# Check resource utilization
kubectl top pods -l app=auth-service

# Check database connection pool
kubectl logs -l app=auth-service | grep "connection_pool"
```

**Common Causes**:
- Resource constraints (CPU/Memory)
- Database performance issues
- Network latency to external services
- Inefficient queries or algorithms

**Solutions**:
```bash
# Scale horizontally
kubectl scale deployment auth-service --replicas=10

# Adjust resource limits
kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"limits":{"cpu":"2000m","memory":"1Gi"}}}]}}}}'

# Clear Redis cache if stale
kubectl exec -it redis-master-0 -- redis-cli FLUSHDB
```

#### Issue: Memory Leaks
**Symptoms**: Gradually increasing memory usage, OOMKilled pods

**Investigation**:
```bash
# Check memory usage trends
kubectl top pods -l app=auth-service --sort-by=memory

# Check for OOMKilled events
kubectl describe pods -l app=auth-service | grep -A 5 "OOMKilled"

# Get memory profile
kubectl exec -it auth-service-xxx -- curl http://localhost:8080/debug/pprof/heap > heap.prof
```

**Solutions**:
```bash
# Increase memory limits temporarily
kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"limits":{"memory":"2Gi"}}}]}}}}'

# Rolling restart to clear memory
kubectl rollout restart deployment/auth-service

# Check for known memory leaks in application logs
kubectl logs -l app=auth-service | grep -i "memory\|leak\|gc"
```

### Policy Service Issues

#### Issue: Authorization Failures
**Symptoms**: Unexpected access denials, policy evaluation errors

**Investigation**:
```bash
# Check policy evaluation errors
kubectl logs -l app=policy-service | grep "policy_evaluation_error"

# Check Cedar engine errors
kubectl logs -l app=policy-service | grep "cedar_error"

# Verify policy data integrity
kubectl exec -it policy-service-xxx -- curl http://localhost:8080/admin/policies | jq '.policies | length'
```

**Common Causes**:
- Policy syntax errors
- Missing entity data
- Policy conflicts
- Cedar engine bugs

**Solutions**:
```bash
# Validate policy syntax
kubectl exec -it policy-service-xxx -- /usr/local/bin/cedar validate --policies /etc/policies/

# Reload policies from source
kubectl delete configmap policy-service-policies
kubectl apply -f k8s/policy-service-policies.yaml

# Check entity resolution
kubectl logs -l app=policy-service | grep "entity_resolution"
```

#### Issue: Slow Policy Evaluation
**Symptoms**: High authorization latency, timeout errors

**Investigation**:
```bash
# Check evaluation time metrics
curl -s http://prometheus:9090/api/v1/query?query='histogram_quantile(0.95, rate(authorization_duration_seconds_bucket[5m]))'

# Check policy complexity
kubectl exec -it policy-service-xxx -- curl http://localhost:8080/admin/policy-stats

# Check cache hit rates
kubectl logs -l app=policy-service | grep "cache_hit_rate"
```

**Solutions**:
```bash
# Optimize policy structure
# - Reduce nesting depth
# - Use more specific conditions
# - Cache entity attributes

# Increase cache size
kubectl patch deployment policy-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"policy-service","env":[{"name":"CACHE_SIZE","value":"1000"}]}]}}}}'

# Add policy evaluation timeout
kubectl patch deployment policy-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"policy-service","env":[{"name":"EVAL_TIMEOUT_MS","value":"100"}]}]}}}}'
```

### Infrastructure Issues

#### Issue: High CPU Usage
**Symptoms**: CPU throttling, slow responses, autoscaling triggers

**Investigation**:
```bash
# Check cluster CPU utilization
kubectl top nodes

# Check pod CPU usage
kubectl top pods --all-namespaces --sort-by=cpu

# Check CPU throttling
kubectl describe nodes | grep -A 5 "cpu"
```

**Solutions**:
```bash
# Scale cluster nodes
kubectl scale nodepool default-pool --size=10

# Optimize resource requests
kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"requests":{"cpu":"500m"}}}]}}}}'

# Add CPU limits to prevent noisy neighbors
kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"limits":{"cpu":"2000m"}}}]}}}}'
```

#### Issue: Storage Issues
**Symptoms**: Disk space warnings, PVC expansion failures

**Investigation**:
```bash
# Check PVC usage
kubectl get pvc --all-namespaces

# Check node disk usage
kubectl describe nodes | grep -A 10 "Allocated resources"

# Check storage class configuration
kubectl get storageclass
```

**Solutions**:
```bash
# Expand PVC (if storage class supports it)
kubectl patch pvc redis-data-redis-master-0 -p='{"spec":{"resources":{"requests":{"storage":"50Gi"}}}}'

# Clean up old data
kubectl exec -it redis-master-0 -- redis-cli FLUSHDB

# Add storage monitoring
kubectl apply -f monitoring/storage-alerts.yaml
```

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
1. **Check service health**:
   ```bash
   # Automated health check script
   #!/bin/bash
   NAMESPACE="rust-security"
   
   echo "=== Daily Health Check $(date) ==="
   
   # Check pod status
   echo "Pod Status:"
   kubectl get pods -n $NAMESPACE
   
   # Check service endpoints
   echo "Service Health:"
   kubectl get endpoints -n $NAMESPACE
   
   # Check ingress status
   echo "Ingress Status:"
   kubectl get ingress -n $NAMESPACE
   
   # Check HPA status
   echo "HPA Status:"
   kubectl get hpa -n $NAMESPACE
   
   # Check recent events
   echo "Recent Events:"
   kubectl get events --sort-by=.metadata.creationTimestamp -n $NAMESPACE --since=24h
   ```

2. **Review monitoring dashboards**
3. **Check error rates and SLO compliance**
4. **Review resource utilization trends**
5. **Check backup status**

#### Weekly Tasks
1. **Security patch review**:
   ```bash
   # Check for security updates
   kubectl get vulnerabilityreports --all-namespaces
   
   # Update base images
   docker pull rust:latest
   docker pull nginx:latest
   docker pull redis:latest
   ```

2. **Performance analysis**:
   ```bash
   # Generate performance report
   curl -s http://prometheus:9090/api/v1/query_range?query='rate(http_requests_total[1w])&start=$(date -d "1 week ago" +%s)&end=$(date +%s)&step=3600'
   ```

3. **Capacity planning review**
4. **Backup verification**
5. **Documentation updates**

#### Monthly Tasks
1. **SSL certificate renewal**:
   ```bash
   # Check certificate expiry
   kubectl get certificates -n rust-security
   
   # Renew if needed
   kubectl annotate certificate auth-service-tls cert-manager.io/force-renew=true
   ```

2. **Security audit**:
   ```bash
   # Run security scan
   kubectl apply -f security/polaris-scan.yaml
   
   # Check RBAC permissions
   kubectl auth can-i --list --as=system:serviceaccount:rust-security:auth-service
   ```

3. **Disaster recovery testing**
4. **Cost optimization review**
5. **SLO review and adjustment**

### Deployment Procedures

#### Rolling Deployment
```bash
# Standard rolling deployment
kubectl set image deployment/auth-service auth-service=rust-security/auth-service:v1.2.0

# Monitor deployment progress
kubectl rollout status deployment/auth-service

# Verify deployment
kubectl get pods -l app=auth-service
kubectl logs -l app=auth-service --tail=20
```

#### Blue-Green Deployment
```bash
# Deploy green environment
kubectl apply -f k8s/auth-service-green.yaml

# Test green environment
curl -H "Host: auth-green.example.com" http://load-balancer/health

# Switch traffic
kubectl patch service auth-service -p='{"spec":{"selector":{"version":"green"}}}'

# Monitor and rollback if needed
kubectl patch service auth-service -p='{"spec":{"selector":{"version":"blue"}}}'

# Clean up old environment
kubectl delete -f k8s/auth-service-blue.yaml
```

#### Canary Deployment
```bash
# Deploy canary version (10% traffic)
kubectl apply -f k8s/auth-service-canary.yaml

# Configure traffic split
kubectl patch virtualservice auth-service -p='{"spec":{"http":[{"match":[{"headers":{"canary":{"exact":"true"}}}],"route":[{"destination":{"host":"auth-service-canary"}}]},{"route":[{"destination":{"host":"auth-service","weight":90}},{"destination":{"host":"auth-service-canary","weight":10}}]}]}}'

# Monitor metrics
# - Error rates
# - Latency percentiles
# - User feedback

# Gradually increase traffic or rollback
kubectl patch virtualservice auth-service -p='{"spec":{"http":[{"route":[{"destination":{"host":"auth-service","weight":50}},{"destination":{"host":"auth-service-canary","weight":50}}]}]}}'
```

### Backup and Recovery

#### Backup Procedures
```bash
# Redis backup
kubectl exec redis-master-0 -- redis-cli BGSAVE
kubectl cp redis-master-0:/data/dump.rdb ./backups/redis-$(date +%Y%m%d).rdb

# Configuration backup
kubectl get configmaps -n rust-security -o yaml > backups/configmaps-$(date +%Y%m%d).yaml
kubectl get secrets -n rust-security -o yaml > backups/secrets-$(date +%Y%m%d).yaml

# Policy backup
kubectl exec policy-service-xxx -- tar czf - /etc/policies > backups/policies-$(date +%Y%m%d).tar.gz
```

#### Recovery Procedures
```bash
# Restore Redis data
kubectl cp ./backups/redis-20240820.rdb redis-master-0:/data/dump.rdb
kubectl exec redis-master-0 -- redis-cli DEBUG RESTART

# Restore configuration
kubectl apply -f backups/configmaps-20240820.yaml
kubectl apply -f backups/secrets-20240820.yaml

# Restore policies
kubectl cp backups/policies-20240820.tar.gz policy-service-xxx:/tmp/
kubectl exec policy-service-xxx -- tar xzf /tmp/policies-20240820.tar.gz -C /
kubectl rollout restart deployment/policy-service
```

### Security Procedures

#### Security Incident Response
1. **Immediate containment**:
   ```bash
   # Isolate affected pods
   kubectl patch networkpolicy default-deny -p='{"spec":{"podSelector":{"matchLabels":{"incident":"isolate"}}}}'
   
   # Label affected pods
   kubectl label pod auth-service-xxx incident=isolate
   
   # Stop traffic to affected services
   kubectl patch service auth-service -p='{"spec":{"selector":{"incident":"none"}}}'
   ```

2. **Evidence collection**:
   ```bash
   # Collect logs
   kubectl logs auth-service-xxx > evidence/auth-service-logs.txt
   
   # Collect pod information
   kubectl describe pod auth-service-xxx > evidence/pod-description.txt
   
   # Collect network information
   kubectl get networkpolicies -o yaml > evidence/network-policies.yaml
   ```

3. **Containment and eradication**:
   ```bash
   # Remove compromised pods
   kubectl delete pod auth-service-xxx
   
   # Update images with patches
   kubectl set image deployment/auth-service auth-service=rust-security/auth-service:v1.2.1-security-patch
   
   # Update security policies
   kubectl apply -f security/updated-network-policies.yaml
   ```

#### Credential Rotation
```bash
# Rotate JWT signing keys
kubectl create secret generic auth-service-jwt-new --from-literal=secret=$(openssl rand -base64 32)

# Update deployment to use new secret
kubectl patch deployment auth-service -p='{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","env":[{"name":"JWT_SECRET","valueFrom":{"secretKeyRef":{"name":"auth-service-jwt-new","key":"secret"}}}]}]}}}}'

# Verify rotation
kubectl rollout status deployment/auth-service

# Clean up old secret
kubectl delete secret auth-service-jwt-old
```

## Monitoring and Alerting

### Key Metrics to Monitor

#### Service Health Metrics
- HTTP request rates and error rates
- Response time percentiles (P50, P95, P99)
- Service availability and uptime
- Dependency health and connectivity

#### Infrastructure Metrics
- CPU and memory utilization
- Network I/O and latency
- Disk usage and IOPS
- Pod restart rates and failures

#### Business Metrics
- User authentication success rates
- Authorization decision accuracy
- API usage patterns
- Security event frequencies

### Alert Escalation

#### Level 1: Warning (Team Notification)
- Slack notification to team channel
- Email to team mailing list
- Dashboard highlighting

#### Level 2: Error (On-Call Engineer)
- PagerDuty alert to on-call engineer
- SMS and phone call if not acknowledged
- Slack notification with escalation

#### Level 3: Critical (Manager Escalation)
- Immediate escalation to engineering manager
- Executive notification for business impact
- War room establishment

### Runbook Maintenance

#### Monthly Review
1. **Update procedures** based on recent incidents
2. **Test automation scripts** for accuracy
3. **Review and update contact information**
4. **Validate monitoring and alerting rules**

#### Quarterly Review
1. **Comprehensive procedure testing**
2. **Team training and knowledge transfer**
3. **Tool and system updates**
4. **Documentation optimization**

This operations runbook provides comprehensive guidance for managing the Rust Security Platform effectively, ensuring high availability, security, and performance while minimizing operational overhead and response times.