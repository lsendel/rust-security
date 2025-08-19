# Troubleshooting Guide - Rust Authentication Service

## Quick Reference

### Emergency Commands
```bash
# Check service status
kubectl get pods -l app=auth-service

# View logs
kubectl logs -l app=auth-service --tail=100

# Restart service
kubectl rollout restart deployment/auth-service

# Check Redis
redis-cli ping

# Test health endpoint
curl http://localhost:3001/health
```

## Common Issues

### Service Startup Problems

**Problem:** Service won't start

**Symptoms:**
- CrashLoopBackOff status
- Connection refused errors
- Port binding failures

**Diagnosis:**
```bash
kubectl describe pod $POD_NAME
kubectl logs $POD_NAME
kubectl top node
```

**Solutions:**
1. **Port conflicts:**
   ```bash
   kubectl get svc | grep 3001
   kubectl delete pod $CONFLICTING_POD
   ```

2. **Missing configuration:**
   ```bash
   kubectl get configmap auth-service-config -o yaml
   kubectl create configmap auth-service-config --from-literal=AUTH_SERVICE_PORT=3001
   ```

3. **Resource constraints:**
   ```bash
   kubectl patch deployment auth-service -p '{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"limits":{"memory":"1Gi"}}}]}}}}'
   ```

### Redis Connection Issues

**Problem:** Cannot connect to Redis

**Symptoms:**
- Redis connection timeout
- Authentication failed errors

**Diagnosis:**
```bash
redis-cli -h $REDIS_HOST ping
kubectl logs -l app=redis
kubectl get networkpolicy
```

**Solutions:**
1. **Network connectivity:**
   ```bash
   kubectl exec -it $AUTH_POD -- telnet $REDIS_HOST $REDIS_PORT
   kubectl exec -it $AUTH_POD -- nslookup $REDIS_HOST
   ```

2. **Authentication:**
   ```bash
   kubectl get secret redis-secret -o jsonpath='{.data.password}' | base64 -d
   kubectl patch secret auth-service-secrets --type merge -p '{"data":{"REDIS_PASSWORD":"[NEW_PASSWORD_BASE64]"}}'
   ```

### Authentication Problems

**Problem:** Users cannot authenticate

**Symptoms:**
- HTTP 401 Unauthorized
- Invalid client credentials
- Token validation failed

**Diagnosis:**
```bash
kubectl logs -l app=auth-service | grep -E "(auth|login)"
kubectl get secret oauth-clients -o yaml
redis-cli keys "token:*"
```

**Solutions:**
1. **Invalid credentials:**
   ```bash
   redis-cli hget "client:$CLIENT_ID" secret
   redis-cli hset "client:$CLIENT_ID" secret "$NEW_SECRET"
   ```

2. **Token issues:**
   ```bash
   curl https://auth.yourcompany.com/jwks.json
   kubectl exec -it $AUTH_POD -- /app/rotate-keys.sh
   ```

3. **Clear corrupted tokens:**
   ```bash
   redis-cli del $(redis-cli keys "token:*")
   kubectl rollout restart deployment/auth-service
   ```

### Performance Issues

**Problem:** Slow response times

**Symptoms:**
- API responses > 1 second
- Timeout errors
- High latency

**Diagnosis:**
```bash
curl -s http://localhost:3001/metrics | grep duration
kubectl top pods -l app=auth-service
redis-cli --latency-history
```

**Solutions:**
1. **Scale service:**
   ```bash
   kubectl scale deployment auth-service --replicas=5
   ```

2. **Increase resources:**
   ```bash
   kubectl patch deployment auth-service -p '{"spec":{"template":{"spec":{"containers":[{"name":"auth-service","resources":{"limits":{"cpu":"1000m","memory":"1Gi"}}}]}}}}'
   ```

3. **Optimize Redis:**
   ```bash
   redis-cli config set maxmemory-policy allkeys-lru
   kubectl patch configmap auth-service-config --type merge -p '{"data":{"REDIS_POOL_SIZE":"50"}}'
   ```

### Security Issues

**Problem:** Suspicious activity detected

**Indicators:**
- High failed authentication rate
- Requests from malicious IPs
- Unusual traffic patterns

**Investigation:**
```bash
kubectl logs -l app=auth-service | grep "authentication_failure" | grep -o '"client_ip":"[^"]*"' | sort | uniq -c | sort -nr
kubectl logs -l app=auth-service | grep "threat_intel"
kubectl logs -l app=auth-service | grep "security_event"
```

**Response:**
1. **Block malicious IPs:**
   ```bash
   kubectl patch configmap threat-intel-config --type merge -p '{"data":{"blocked_ips":"[MALICIOUS_IPS]"}}'
   kubectl rollout restart deployment/auth-service
   ```

2. **Emergency rate limiting:**
   ```bash
   kubectl patch configmap auth-service-config --type merge -p '{"data":{"RATE_LIMIT_PER_MINUTE":"10"}}'
   ```

3. **Revoke tokens:**
   ```bash
   redis-cli del $(redis-cli keys "token:*")
   ```

### Certificate Problems

**Problem:** TLS certificate issues

**Symptoms:**
- Certificate expired errors
- TLS handshake failures

**Diagnosis:**
```bash
openssl x509 -in /etc/ssl/certs/auth-service.crt -noout -dates
openssl s_client -connect auth.yourcompany.com:443
```

**Solutions:**
1. **Renew certificates:**
   ```bash
   kubectl delete secret auth-service-tls
   kubectl annotate certificate auth-service-cert cert-manager.io/force-renew=true
   ```

2. **Manual update:**
   ```bash
   kubectl create secret tls auth-service-tls --cert=/path/to/cert.pem --key=/path/to/key.pem
   ```

## Monitoring Issues

### Missing Metrics

**Problem:** Dashboards showing no data

**Diagnosis:**
```bash
curl http://localhost:3001/metrics
kubectl logs -l app=prometheus | grep auth-service
```

**Solutions:**
1. **Enable metrics:**
   ```bash
   kubectl patch configmap auth-service-config --type merge -p '{"data":{"PROMETHEUS_METRICS_ENABLED":"true"}}'
   kubectl rollout restart deployment/auth-service
   ```

### Log Problems

**Problem:** Missing logs in aggregation

**Diagnosis:**
```bash
kubectl logs -l app=auth-service | head -5
kubectl logs -l app=fluentd | grep auth-service
```

**Solutions:**
1. **Fix log format:**
   ```bash
   kubectl patch configmap auth-service-config --type merge -p '{"data":{"LOG_FORMAT":"json"}}'
   ```

## Escalation

### When to Escalate
- Complete service outage > 5 minutes
- Security incident (active attack)
- Data corruption
- Multiple critical alerts

### Escalation Contacts
- **Level 1:** oncall-l1@yourcompany.com (+1-555-ONCALL1)
- **Level 2:** oncall-l2@yourcompany.com (+1-555-ONCALL2)
- **Level 3:** engineering-manager@yourcompany.com (+1-555-ESCALATE)

### Information to Include
1. Problem description and impact
2. Timeline of events
3. Steps already taken
4. Current status
5. Relevant logs and metrics

## Useful Commands

### Kubernetes
```bash
kubectl get pods -l app=auth-service
kubectl describe pod $POD_NAME
kubectl logs -f $POD_NAME
kubectl exec -it $POD_NAME -- /bin/bash
kubectl rollout restart deployment/auth-service
kubectl scale deployment auth-service --replicas=5
```

### Redis
```bash
redis-cli ping
redis-cli info
redis-cli keys "*"
redis-cli hgetall "token:example"
redis-cli --latency-history
```

### Monitoring
```bash
curl http://localhost:3001/metrics
curl http://localhost:3001/health
kubectl logs -l app=auth-service | grep ERROR
```

---

**Document Version:** 1.0
**Last Updated:** December 2023
**Next Review:** March 2024

For additional support, contact ops@yourcompany.com
