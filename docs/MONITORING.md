# Production Monitoring Guide

This document describes the comprehensive monitoring setup for the Rust Security Platform production deployment.

## Overview

The monitoring stack consists of:

- **Prometheus** - Metrics collection and alerting
- **Grafana** - Visualization and dashboards  
- **Alertmanager** - Alert management and routing
- **Node Exporter** - System metrics collection
- **Redis Exporter** - Redis metrics collection

## Quick Start

### Start Monitoring Stack

```bash
# Start all monitoring services
./scripts/start-monitoring.sh

# Or as part of full production deployment
./deploy-docker-production.sh
```

### Access Monitoring Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3001 | admin / (see secrets/grafana_password.txt) |
| Prometheus | http://localhost:9090 | No auth |
| Alertmanager | http://localhost:9093 | No auth |

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Auth Service  │    │ Policy Service  │    │    Dashboard    │
│     :8080       │    │     :8081       │    │     :3000       │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          │ /metrics             │ /metrics             │
          │                      │                      │
          v                      v                      v
┌─────────────────────────────────────────────────────────────────┐
│                     Prometheus (:9090)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Node Export │  │Redis Export │  │   Application Metrics   │ │
│  │    :9100    │  │    :9121    │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────┬───────────────────────────────┬───────────────────┘
              │                               │
              │ Alert Rules                   │ Query API
              v                               v
┌─────────────────────────────┐    ┌─────────────────────────────┐
│   Alertmanager (:9093)      │    │      Grafana (:3001)       │
│  ┌─────────────────────────┐│    │ ┌─────────────────────────┐ │
│  │  Email Notifications   ││    │ │    Security Dashboard   │ │
│  │  Slack Notifications   ││    │ │  Infrastructure Metrics │ │
│  │  PagerDuty Integration ││    │ │   Application Metrics   │ │
│  └─────────────────────────┘│    │ └─────────────────────────┘ │
└─────────────────────────────┘    └─────────────────────────────┘
```

## Metrics Collection

### Application Metrics

Each service exposes metrics at `/metrics` endpoint:

**Auth Service Metrics:**
- `auth_requests_total` - Total authentication requests
- `auth_request_duration_seconds` - Request duration histogram
- `auth_active_sessions` - Current active sessions
- `auth_failed_logins_total` - Failed login attempts
- `auth_jwt_tokens_issued_total` - JWT tokens issued
- `auth_database_connections` - Database connection pool status

**Policy Service Metrics:**
- `policy_evaluations_total` - Total policy evaluations
- `policy_evaluation_duration_seconds` - Evaluation duration
- `policy_cache_hits_total` - Policy cache performance
- `policy_errors_total` - Policy evaluation errors

**System Metrics (Node Exporter):**
- CPU usage, memory, disk space, network I/O
- System load averages
- File descriptor usage
- Process statistics

**Redis Metrics (Redis Exporter):**
- Connected clients, memory usage
- Command statistics
- Keyspace information
- Replication status

## Alerting

### Alert Rules

Alerts are configured in `monitoring/prometheus/` directory:

- `security-alerts.yml` - Security-specific alerts
- `infrastructure-rules.yml` - Infrastructure monitoring
- `sla-rules.yml` - SLA breach monitoring

### Alert Categories

#### Critical Security Alerts
- Failed login threshold exceeded
- Suspicious authentication patterns
- JWT token validation failures
- Database connection anomalies

#### Infrastructure Alerts
- High CPU/Memory usage
- Disk space exhaustion
- Network connectivity issues
- Service unavailability

#### Performance Alerts
- High response times
- Request rate anomalies
- Database query slowdowns
- Cache miss rates

### Alert Routing

Alerts are routed based on severity and category:

| Severity | Category | Notification Method | Response Time |
|----------|----------|-------------------|---------------|
| Critical | Security | Email + Slack + PagerDuty | Immediate |
| Critical | Infrastructure | Email + Slack | <5 minutes |
| High | Security | Email + Slack | <30 minutes |
| High | Performance | Slack | <1 hour |
| Medium | Any | Email (business hours) | <4 hours |

## Dashboards

### Security Overview Dashboard
- Authentication success/failure rates
- Active user sessions
- Security event timeline
- Geographic login distribution
- Threat intelligence metrics

### Infrastructure Dashboard
- System resource utilization
- Service health status
- Database performance metrics
- Redis cache performance
- Network traffic patterns

### Application Performance Dashboard
- Request rates and response times
- Error rates by endpoint
- Database query performance
- Cache hit ratios
- Service dependencies

## Configuration

### Prometheus Configuration

Located at `monitoring/prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:8080']
    scrape_interval: 10s
```

### Alertmanager Configuration

Located at `monitoring/alertmanager/alertmanager.yml`:

```yaml
global:
  smtp_smarthost: 'mail.example.com:587'
  smtp_from: 'alerts@example.com'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  receiver: 'default'
```

### Grafana Provisioning

Automatic provisioning of:
- Data sources (`monitoring/grafana/datasources/`)
- Dashboards (`monitoring/grafana/dashboards/`)

## Maintenance

### Daily Tasks
- Review alert notifications
- Check dashboard metrics for anomalies
- Verify monitoring service health

### Weekly Tasks
- Review alert rule effectiveness
- Update dashboard queries if needed
- Check metric retention and storage

### Monthly Tasks
- Review and tune alert thresholds
- Update monitoring documentation
- Evaluate new monitoring requirements

## Troubleshooting

### Common Issues

#### Prometheus Not Scraping Metrics
```bash
# Check target status
curl http://localhost:9090/api/v1/targets

# Check service connectivity
docker-compose -f docker-compose.production.yml logs prometheus
```

#### Grafana Dashboard Not Loading
```bash
# Check Grafana logs
docker-compose -f docker-compose.production.yml logs grafana

# Verify datasource configuration
curl http://admin:password@localhost:3001/api/datasources
```

#### Alerts Not Firing
```bash
# Check alert rule syntax
curl http://localhost:9090/api/v1/rules

# Verify Alertmanager connectivity
curl http://localhost:9093/api/v1/status
```

### Log Locations

Monitor service logs:
```bash
# View all monitoring service logs
./scripts/start-monitoring.sh logs

# View specific service logs
./scripts/start-monitoring.sh logs prometheus
./scripts/start-monitoring.sh logs alertmanager
./scripts/start-monitoring.sh logs grafana
```

## Security Considerations

### Access Control
- Grafana admin credentials stored in secrets
- Prometheus and Alertmanager access via internal network only
- Consider implementing authentication proxy for production

### Data Protection
- Metrics data contains sensitive information
- Configure appropriate retention policies
- Ensure encrypted communication in production

### Alert Sensitivity
- Balance between alert fatigue and missing critical issues
- Regular review and tuning of alert thresholds
- Implement alert escalation procedures

## Performance Optimization

### Metric Retention
- Default: 15 days retention
- Adjust based on storage capacity and requirements
- Consider long-term storage solutions for compliance

### Query Performance
- Use recording rules for complex queries
- Optimize dashboard queries
- Monitor Prometheus resource usage

### Scaling Considerations
- Single Prometheus instance suitable for moderate scale
- Consider federation for multi-cluster deployments
- Plan for metric cardinality growth

## Integration

### External Systems

#### SIEM Integration
```bash
# Webhook example for security alerts
curl -X POST "https://siem.company.com/api/security-alerts" \
  -H "Authorization: Bearer $SIEM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"alert": "SecurityAlert", "severity": "critical"}'
```

#### Ticketing Systems
- Configure webhook receivers for automatic ticket creation
- Include runbook URLs and alert context
- Implement automatic ticket updates on resolution

#### Chat Platforms
- Slack integration for real-time notifications
- Microsoft Teams support available
- Custom webhook integrations

## Best Practices

1. **Alert Design**
   - Write actionable alerts with clear descriptions
   - Include runbook links for investigation steps
   - Test alert rules before production deployment

2. **Dashboard Design**
   - Focus on business-relevant metrics
   - Use appropriate visualization types
   - Organize dashboards by audience (ops, security, business)

3. **Maintenance**
   - Regular review of alert effectiveness
   - Keep documentation updated
   - Plan for monitoring stack upgrades

4. **Security**
   - Secure access to monitoring systems
   - Protect sensitive metric data
   - Implement proper backup procedures

## Commands Reference

```bash
# Start monitoring stack
./scripts/start-monitoring.sh

# Check monitoring service health
./scripts/start-monitoring.sh health

# View service status
./scripts/start-monitoring.sh status

# Stop monitoring services
./scripts/start-monitoring.sh stop

# Restart monitoring services
./scripts/start-monitoring.sh restart

# View service endpoints
./scripts/start-monitoring.sh endpoints
```

## Support

For monitoring-related issues:

1. Check service logs first
2. Verify configuration syntax
3. Test connectivity between services
4. Review alert rule documentation
5. Consult Prometheus/Grafana official documentation

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Alertmanager Documentation](https://prometheus.io/docs/alerting/alertmanager/)
- [Node Exporter Metrics](https://github.com/prometheus/node_exporter#enabled-by-default)