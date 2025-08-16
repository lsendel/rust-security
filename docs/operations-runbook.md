# Operations Runbook - Rust Authentication Service

## Service Overview

The Rust Authentication Service provides OAuth2/OIDC authentication and SCIM 2.0 user management. This runbook covers essential operational procedures.

## Emergency Contacts

### On-Call Rotation
- **Primary:** ops-primary@yourcompany.com
- **Secondary:** ops-secondary@yourcompany.com
- **Escalation:** ops-manager@yourcompany.com

### Emergency Numbers
- **Security Team:** +1-555-SEC-TEAM
- **Infrastructure Team:** +1-555-INFRA

## Quick Reference Commands

### Service Status
```bash
# Check service status
kubectl get pods -l app=auth-service

# View recent logs
kubectl logs -l app=auth-service --tail=100

# Restart service
kubectl rollout restart deployment/auth-service

# Emergency rollback
kubectl rollout undo deployment/auth-service
```

### Health Checks
```bash
# Application health
curl http://auth-service:3001/health

# Metrics endpoint
curl http://auth-service:3001/metrics

# Redis connectivity
redis-cli ping
```

## Critical Alerts

### 1. Service Down
**Trigger:** Service health check fails
**Severity:** Critical
**Response Time:** Immediate

**Response Steps:**
1. Check pod status: `kubectl get pods -l app=auth-service`
2. Check events: `kubectl describe pods -l app=auth-service`
3. Check logs: `kubectl logs -l app=auth-service --tail=100`
4. Restart if needed: `kubectl rollout restart deployment/auth-service`

### 2. High Error Rate
**Trigger:** Error rate > 10%
**Severity:** High
**Response Time:** 15 minutes

**Response Steps:**
1. Check error patterns: `kubectl logs -l app=auth-service | grep ERROR`
2. Check Redis: `redis-cli ping`
3. Check recent deployments: `kubectl rollout history deployment/auth-service`
4. Consider rollback if recent deployment

### 3. Authentication Failures
**Trigger:** High authentication failure rate
**Severity:** High
**Response Time:** 15 minutes

**Response Steps:**
1. Check for brute force: `kubectl logs -l app=auth-service | grep "authentication_failure"`
2. Identify source IPs
3. Check threat intelligence
4. Enable additional rate limiting if needed

## Common Issues

### Issue 1: Service Won't Start

**Symptoms:**
- Pods in CrashLoopBackOff
- Startup errors in logs

**Diagnosis:**
```bash
kubectl describe pod $POD_NAME
kubectl logs $POD_NAME
kubectl get configmap auth-service-config -o yaml
```

**Solutions:**
1. Check Redis connectivity
2. Verify environment variables
3. Check resource constraints

### Issue 2: High Response Times

**Symptoms:**
- API responses > 1 second
- Timeout errors

**Diagnosis:**
```bash
kubectl top pods -l app=auth-service
redis-cli --latency-history
```

**Solutions:**
1. Scale horizontally: `kubectl scale deployment auth-service --replicas=5`
2. Check Redis performance
3. Increase resource limits

### Issue 3: Authentication Issues

**Symptoms:**
- Users cannot log in
- Token validation errors

**Diagnosis:**
```bash
kubectl logs -l app=auth-service | grep "auth"
redis-cli keys "token:*"
curl https://auth.yourcompany.com/jwks.json
```

**Solutions:**
1. Clear corrupted tokens
2. Check JWT key rotation
3. Verify client configuration

## Maintenance Procedures

### Planned Maintenance
1. Schedule maintenance window
2. Notify stakeholders
3. Create backup
4. Perform updates
5. Test functionality
6. Monitor for issues

### Rolling Updates
```bash
# Update container image
kubectl set image deployment/auth-service auth-service=new-image:tag

# Monitor rollout
kubectl rollout status deployment/auth-service

# Rollback if necessary
kubectl rollout undo deployment/auth-service
```

## Monitoring

### Key Metrics
- Service uptime
- Response times (P50, P95, P99)
- Authentication success/failure rates
- Token operations
- Error rates

### Dashboards
- Service Overview Dashboard
- Security Metrics Dashboard
- Performance Dashboard

### Log Analysis
```bash
# Security events
kubectl logs -l app=auth-service | grep "security"

# Authentication failures
kubectl logs -l app=auth-service | grep "auth.*fail"

# Performance issues
kubectl logs -l app=auth-service | grep "timeout\|slow"
```

## Backup and Recovery

### Daily Backups
- Redis data backup
- Configuration backup
- Kubernetes manifests

### Recovery Procedures
1. Stop auth service
2. Restore Redis data
3. Restore configurations
4. Start services
5. Verify functionality

## Escalation Procedures

### When to Escalate
- Complete service outage > 5 minutes
- Security incident
- Data corruption
- Multiple critical alerts

### Information to Provide
1. Problem description and impact
2. Timeline of events
3. Steps taken so far
4. Current status
5. Relevant logs and metrics

## Documentation Links
- [API Documentation](api-documentation.md)
- [Security Guide](security-guide.md)
- [Deployment Guide](deployment-guide.md)
- [Troubleshooting Guide](troubleshooting-guide.md)

---

**Last Updated:** December 2023
**Version:** 1.0
**Next Review:** March 2024
