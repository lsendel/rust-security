# Security Incident Response Procedures

## Critical Security Alert Response (P0)

### Authentication Failure Spike
**Alert**: `PotentialBruteForceAttack`
**Severity**: Critical
**Response Time**: Immediate (< 5 minutes)

#### Immediate Actions:
1. **Block attacking IPs**:
   ```bash
   # Add IP to Redis blocklist
   redis-cli SADD blocked_ips "192.168.1.100"
   
   # Verify rate limiting is active
   curl -s "http://localhost:9090/api/v1/query?query=rate_limit_hits_total"
   ```

2. **Check attack pattern**:
   ```bash
   # Query Elasticsearch for attack details
   curl -X POST "localhost:9200/security-logs-*/_search" -H "Content-Type: application/json" -d '{
     "query": {
       "bool": {
         "must": [
           {"term": {"security.event_type": "authentication_failure"}},
           {"range": {"@timestamp": {"gte": "now-15m"}}}
         ]
       }
     },
     "aggs": {
       "by_ip": {"terms": {"field": "source.ip", "size": 10}},
       "by_client": {"terms": {"field": "security.client_id", "size": 10}}
     }
   }'
   ```

3. **Scale rate limiting**:
   ```bash
   # Temporarily reduce rate limits
   kubectl patch configmap auth-config --patch '{"data":{"RATE_LIMIT_REQUESTS_PER_MINUTE":"10"}}'
   ```

#### Investigation:
1. Identify compromised accounts
2. Check for successful authentications from attacking IPs
3. Review access logs for lateral movement
4. Contact affected clients

#### Recovery:
1. Reset credentials for compromised accounts
2. Implement temporary IP restrictions
3. Update threat intelligence feeds
4. Document incident in security log

---

### Token Binding Violation
**Alert**: `TokenBindingViolationDetected`
**Severity**: Critical
**Response Time**: Immediate (< 2 minutes)

#### Immediate Actions:
1. **Revoke suspicious tokens**:
   ```bash
   # Get token details from logs
   curl -X POST "localhost:9200/security-logs-*/_search" -H "Content-Type: application/json" -d '{
     "query": {
       "term": {"security.event_type": "token_binding_violation"}
     },
     "sort": [{"@timestamp": {"order": "desc"}}],
     "size": 10
   }'
   
   # Revoke tokens via API
   curl -X POST "http://localhost:8080/revoke" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "token=SUSPICIOUS_TOKEN"
   ```

2. **Block source IP immediately**:
   ```bash
   # Emergency IP block
   redis-cli SADD emergency_blocked_ips "SOURCE_IP"
   ```

3. **Alert security team**:
   ```bash
   # Send immediate Slack notification
   curl -X POST "SLACK_WEBHOOK_URL" -H "Content-Type: application/json" -d '{
     "text": "🚨 CRITICAL: Token binding violation detected - immediate investigation required",
     "attachments": [{
       "color": "danger",
       "fields": [
         {"title": "Source IP", "value": "IP_ADDRESS", "short": true},
         {"title": "Time", "value": "'$(date)'", "short": true}
       ]
     }]
   }'
   ```

#### Investigation:
1. Trace token origin and usage
2. Check for account takeover
3. Review related authentication events
4. Identify potential data exposure

---

## High Priority Security Alerts (P1)

### Suspicious Activity Pattern
**Alert**: `SuspiciousActivityDetected`
**Severity**: High
**Response Time**: 15 minutes

#### Response Checklist:
- [ ] Query activity logs for pattern analysis
- [ ] Check user behavior analytics
- [ ] Review geolocation data
- [ ] Escalate if confirmed malicious
- [ ] Implement temporary restrictions
- [ ] Document findings

#### Investigation Queries:
```bash
# Check user activity patterns
curl -X POST "localhost:9200/security-logs-*/_search" -H "Content-Type: application/json" -d '{
  "query": {
    "bool": {
      "must": [
        {"term": {"security.event_type": "suspicious_activity"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "activity_timeline": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "5m"
      }
    }
  }
}'
```

---

### Rate Limit Threshold Exceeded
**Alert**: `HighRateLimitingActivity`
**Severity**: High
**Response Time**: 10 minutes

#### Response Actions:
1. **Analyze traffic patterns**:
   ```bash
   # Check rate limiting metrics
   curl -s "http://localhost:9090/api/v1/query?query=rate(rate_limit_hits_total[5m])"
   ```

2. **Identify top offenders**:
   ```bash
   # Query top rate-limited clients
   curl -s "http://localhost:9090/api/v1/query?query=topk(10, sum by (client_id) (rate_limit_hits_total))"
   ```

3. **Adjust rate limits if needed**:
   ```bash
   # Temporary rate limit adjustment
   curl -X POST "http://localhost:8080/admin/rate-limits" \
     -H "Authorization: Bearer ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"client_id": "CLIENT_ID", "rate_limit": 60}'
   ```

---

## Medium Priority Alerts (P2)

### Input Validation Failures
**Alert**: `InputValidationFailureSpike`
**Severity**: Medium
**Response Time**: 30 minutes

#### Response Actions:
1. Review failed validation patterns
2. Check for potential injection attempts
3. Update validation rules if necessary
4. Monitor for escalation

---

## Infrastructure Alerts

### Service Availability
**Alert**: `ServiceDown`
**Severity**: Critical
**Response Time**: Immediate

#### Response Actions:
1. **Check service status**:
   ```bash
   docker-compose ps
   kubectl get pods -n auth-system
   ```

2. **Review service logs**:
   ```bash
   docker logs auth-service --tail 100
   kubectl logs -f deployment/auth-service
   ```

3. **Attempt restart**:
   ```bash
   docker-compose restart auth-service
   kubectl rollout restart deployment/auth-service
   ```

4. **Check dependencies**:
   ```bash
   # Test Redis connectivity
   redis-cli ping
   
   # Check database connections
   curl -s "http://localhost:8080/health"
   ```

---

## Escalation Procedures

### Security Team Escalation
- **Trigger**: Critical security alerts not resolved in 15 minutes
- **Contact**: security-team@company.com
- **Slack**: #security-incidents
- **PagerDuty**: Security On-Call rotation

### Management Escalation
- **Trigger**: 
  - Multiple critical alerts
  - Service downtime > 15 minutes
  - Confirmed data breach
- **Contact**: incident-commander@company.com
- **Process**: Follow incident management runbook

---

## Post-Incident Activities

### Immediate (< 24 hours)
1. Incident summary report
2. Timeline documentation
3. Impact assessment
4. Stakeholder communication

### Short-term (< 1 week)
1. Root cause analysis
2. Preventive measures implementation
3. Process improvements
4. Team training updates

### Long-term (< 1 month)
1. Security posture review
2. Monitoring improvements
3. Policy updates
4. Lessons learned documentation

---

## Tools and Resources

### Monitoring URLs
- **Grafana**: http://localhost:3000
- **Prometheus**: http://localhost:9090
- **Alertmanager**: http://localhost:9093
- **Kibana**: http://localhost:5601
- **Jaeger**: http://localhost:16686

### Emergency Contacts
- **Security Team**: +1-555-SEC-TEAM
- **Infrastructure Team**: +1-555-OPS-TEAM
- **Management**: +1-555-MGT-TEAM

### Documentation
- **Security Policies**: https://docs.company.com/security
- **Runbooks**: https://docs.company.com/runbooks
- **Incident Templates**: https://docs.company.com/incident-templates
