# Comprehensive Threat Hunting Toolkit

A production-ready threat hunting system designed specifically for the Rust Authentication Service. This toolkit provides advanced behavioral analysis, machine learning-based user profiling, real-time threat intelligence correlation, sophisticated attack pattern detection, and automated response capabilities.

## Features

### 🔍 Advanced Behavioral Analysis
- Real-time anomaly detection using isolation forests and clustering
- User behavior profiling with baseline deviation analysis
- Credential stuffing detection with configurable thresholds
- Account takeover pattern recognition
- Brute force attack identification
- Session hijacking detection

### 🤖 Machine Learning User Profiling
- LSTM-based behavioral sequence analysis
- Random forest risk classification
- User baseline establishment and monitoring
- Behavioral anomaly scoring
- Risk assessment with confidence intervals
- Automated model retraining

### 🌐 Real-time Threat Intelligence
- Integration with MISP, VirusTotal, Abuse.ch, and AlienVault OTX
- IOC matching and correlation
- Threat campaign tracking
- False positive reduction
- Custom indicator management
- Whitelist/blacklist support

### 🎯 Advanced Attack Pattern Detection
- Multi-stage attack sequence detection
- Graph-based network analysis
- Clustering-based pattern recognition
- APT campaign identification
- Lateral movement detection
- Statistical time-series analysis

### ⚡ Automated Response & Orchestration
- Rule-based response automation
- IP blocking and user account locking
- Token revocation and session management
- Notification and escalation workflows
- Approval-based response actions
- Integration with external security tools

### 🔗 Seamless Rust Integration
- Native log parsing for Rust security events
- Real-time event streaming
- Bidirectional API communication
- Prometheus metrics integration
- Health monitoring and alerting

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Rust Auth      │    │  Log Parser     │    │  Event Queue    │
│  Service        │───▶│  & Integration  │───▶│  (Redis)        │
│                 │    │  Bridge         │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                       ┌─────────────────────────────────┴─────────────────────────────────┐
                       │                                                                   │
                       ▼                                                                   ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Behavioral     │    │  ML User        │    │  Threat Intel   │    │  Attack Pattern │
│  Analyzer       │    │  Profiler       │    │  Correlator     │    │  Detector       │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │                       │
         └───────────────────────┼───────────────────────┼───────────────────────┘
                                 │                       │
                                 ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Response       │    │  Notification   │
                       │  Orchestrator   │    │  & Alerting     │
                       └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites
- Python 3.9+
- Redis 6.0+
- PostgreSQL 13+
- Rust Authentication Service

### Setup

1. **Clone and install dependencies:**
```bash
cd threat-hunting
pip install -r requirements.txt
```

2. **Database Setup:**
```sql
-- Create database schema
CREATE TABLE security_events (
    event_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source VARCHAR(100) NOT NULL,
    client_id VARCHAR(255),
    user_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    session_id VARCHAR(255),
    description TEXT NOT NULL,
    details JSONB,
    outcome VARCHAR(50) NOT NULL,
    resource VARCHAR(255),
    action VARCHAR(100),
    risk_score INTEGER,
    location VARCHAR(255),
    device_fingerprint VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE threat_indicators (
    indicator VARCHAR(255) PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    source VARCHAR(100) NOT NULL,
    description TEXT,
    tags JSONB,
    ttl INTEGER NOT NULL,
    false_positive_probability FLOAT DEFAULT 0.1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE attack_sequences (
    sequence_id VARCHAR(255) PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence FLOAT NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    affected_entities JSONB,
    source_ips JSONB,
    pattern_signature TEXT,
    complexity_score INTEGER,
    mitigation_priority VARCHAR(50),
    recommended_actions JSONB,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE response_plans (
    plan_id VARCHAR(255) PRIMARY KEY,
    threat_id VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL,
    escalation_level VARCHAR(20) NOT NULL,
    executed_actions INTEGER DEFAULT 0,
    failed_actions INTEGER DEFAULT 0,
    plan_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_ip_address ON security_events(ip_address);
CREATE INDEX idx_security_events_event_type ON security_events(event_type);
CREATE INDEX idx_threat_indicators_type ON threat_indicators(indicator_type);
CREATE INDEX idx_attack_sequences_type ON attack_sequences(attack_type);
CREATE INDEX idx_response_plans_status ON response_plans(status);
```

3. **Configuration:**
```python
config = {
    'rust_service': {
        'url': 'http://localhost:8080',
        'api_key': 'your_api_key_here'
    },
    'redis_url': 'redis://localhost:6379',
    'postgres_url': 'postgresql://username:password@localhost/security_db',
    'processing_workers': 4,
    'response_config': {
        'firewall': {
            'api_url': 'https://your-firewall.com/api',
            'api_key': 'firewall_api_key'
        },
        'notifications': {
            'slack_webhook_url': 'https://hooks.slack.com/your/webhook',
            'email_config': {
                'smtp_server': 'smtp.company.com',
                'username': 'security@company.com',
                'password': 'email_password'
            }
        }
    }
}
```

## Usage Examples

### Basic Integration

```python
from integration_bridge import ThreatHuntingOrchestrator
from behavioral_analyzer import SecurityEvent
import asyncio

async def main():
    config = {
        'rust_service': {'url': 'http://localhost:8080', 'api_key': 'key'},
        'redis_url': 'redis://localhost:6379',
        'postgres_url': 'postgresql://localhost/security_db'
    }
    
    orchestrator = ThreatHuntingOrchestrator(config)
    await orchestrator.initialize()
    
    # Process log file
    await orchestrator.process_log_file('/var/log/auth-service.log')
    
    # Or process events directly
    event = SecurityEvent(
        event_id='evt_001',
        timestamp=datetime.now(),
        event_type='authentication_failure',
        severity='medium',
        source='auth-service',
        client_id='client123',
        user_id='user456',
        ip_address='192.168.1.100',
        description='Failed login attempt',
        outcome='failure',
        risk_score=60
    )
    
    result = await orchestrator.process_event_directly(event)
    print(f"Threats detected: {len(result.threats_detected)}")
    
    await orchestrator.close()

asyncio.run(main())
```

### Custom Threat Callbacks

```python
async def custom_threat_handler(event: SecurityEvent, result: ProcessingResult):
    """Custom handler for detected threats"""
    if result.threats_detected:
        for threat in result.threats_detected:
            if threat['severity'] == 'critical':
                # Send immediate alert
                await send_critical_alert(threat)
            
            # Log to SIEM
            await log_to_siem(event, threat)
    
    if result.response_plan_id:
        # Track response plan execution
        await track_response_plan(result.response_plan_id)

orchestrator.register_threat_callback(custom_threat_handler)
```

### Individual Component Usage

#### Behavioral Analysis
```python
from behavioral_analyzer import AdvancedThreatDetector

detector = AdvancedThreatDetector()
await detector.initialize()

threats = await detector.analyze_event(security_event)
for threat in threats:
    print(f"Threat: {threat.threat_type}, Confidence: {threat.confidence}")
```

#### User Profiling
```python
from ml_user_profiler import AdvancedUserProfiler

profiler = AdvancedUserProfiler()
await profiler.initialize()

assessment = await profiler.analyze_user_behavior('user123')
print(f"Risk Score: {assessment.risk_score}, Level: {assessment.risk_level}")
```

#### Threat Intelligence
```python
from threat_intelligence import ThreatIntelligenceCorrelator

correlator = ThreatIntelligenceCorrelator()
await correlator.initialize()

matches = await correlator.check_indicators(event_data)
for match in matches:
    print(f"IOC Match: {match.indicator.indicator}, Risk: {match.risk_score}")
```

#### Attack Pattern Detection
```python
from attack_pattern_detector import AttackPatternDetector

detector = AttackPatternDetector()
await detector.initialize()

sequences = await detector.process_event(event_data)
for sequence in sequences:
    print(f"Attack: {sequence.attack_type}, Complexity: {sequence.complexity_score}")
```

#### Automated Response
```python
from automated_response import AutomatedResponseOrchestrator, ThreatContext

orchestrator = AutomatedResponseOrchestrator(config=response_config)
await orchestrator.initialize()

threat_context = ThreatContext(
    threat_id='threat_001',
    threat_type='credential_stuffing',
    severity='high',
    confidence=0.85,
    affected_entities={'user1', 'user2'},
    source_ips={'192.168.1.100'},
    indicators=['high_failure_rate'],
    first_seen=datetime.now(),
    last_seen=datetime.now(),
    risk_score=85,
    related_events=['event1']
)

plan = await orchestrator.create_response_plan(threat_context)
await orchestrator.execute_response_plan(plan.plan_id)
```

## Configuration Options

### Behavioral Analysis Thresholds
```python
thresholds = {
    'credential_stuffing': {
        'failed_logins_per_minute': 10,
        'unique_usernames_per_ip': 20,
        'time_window_minutes': 5
    },
    'account_takeover': {
        'location_anomaly_threshold': 1000,  # km
        'device_change_threshold': 3,
        'behavior_deviation_threshold': 2.5
    }
}
```

### Machine Learning Models
```python
model_config = {
    'isolation_forest': {
        'contamination': 0.1,
        'n_estimators': 100
    },
    'lstm_behavioral': {
        'sequence_length': 30,
        'features': 20,
        'epochs': 50
    }
}
```

### Threat Intelligence Feeds
```python
threat_feeds = {
    'misp': {
        'url': 'https://your-misp.com/events/restSearch',
        'api_key': 'misp_api_key',
        'refresh_interval': 3600
    },
    'virustotal': {
        'api_key': 'vt_api_key',
        'refresh_interval': 7200
    }
}
```

### Response Actions
```python
response_rules = {
    'credential_stuffing': {
        'actions': [
            {'type': 'ip_block', 'priority': 1, 'auto_approve': True},
            {'type': 'notification', 'priority': 2, 'auto_approve': True}
        ]
    },
    'account_takeover': {
        'actions': [
            {'type': 'account_lock', 'priority': 1, 'auto_approve': False},
            {'type': 'token_revoke', 'priority': 2, 'auto_approve': True}
        ]
    }
}
```

## Monitoring and Metrics

The toolkit exposes comprehensive Prometheus metrics:

- `threat_hunting_events_processed_total`: Events processed by source and type
- `threat_patterns_detected_total`: Patterns detected by type and severity
- `threat_intel_queries_total`: Threat intelligence queries by source
- `response_actions_executed_total`: Response actions by type and outcome
- `behavioral_anomalies_detected_total`: Behavioral anomalies by type
- `ml_predictions_total`: ML model predictions by type
- `active_threats_count`: Currently active threats
- `threat_hunting_integration_health`: Component health status

### Grafana Dashboard

Import the provided Grafana dashboard for comprehensive visualization:

```json
{
  "dashboard": {
    "title": "Threat Hunting Overview",
    "panels": [
      {
        "title": "Threats Detected",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(threat_patterns_detected_total[5m])",
            "legendFormat": "{{threat_type}}"
          }
        ]
      }
    ]
  }
}
```

## Performance Considerations

### Resource Requirements
- **Memory**: 2-4 GB for normal operation, 8+ GB for large deployments
- **CPU**: 4+ cores recommended for real-time processing
- **Storage**: PostgreSQL with sufficient space for historical data
- **Network**: Low latency connection to Redis and external threat feeds

### Scaling Guidelines
- Use multiple processing workers for high event volumes
- Implement Redis clustering for large-scale deployments
- Consider read replicas for PostgreSQL under heavy load
- Use Redis streams for distributed event processing

### Optimization Tips
- Tune ML model parameters based on your environment
- Adjust time windows and thresholds for your threat landscape
- Implement custom caching for frequently accessed data
- Use database partitioning for large historical datasets

## Security Considerations

### API Security
- Use strong API keys with limited scope
- Implement rate limiting for external API calls
- Validate all input data and sanitize logs
- Use TLS for all communications

### Data Protection
- Encrypt sensitive data at rest and in transit
- Implement proper access controls
- Regular security audits of threat hunting configurations
- Secure storage of ML models and threat intelligence

### Network Security
- Isolate threat hunting infrastructure
- Monitor for data exfiltration attempts
- Implement network segmentation
- Regular vulnerability assessments

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Reduce event buffer sizes
   - Implement more aggressive cleanup policies
   - Tune ML model parameters

2. **Slow Processing**
   - Increase processing workers
   - Optimize database queries
   - Check Redis performance

3. **False Positives**
   - Tune detection thresholds
   - Expand whitelists
   - Improve user baselines

4. **Component Health Issues**
   - Check database connections
   - Verify Redis connectivity
   - Monitor external API limits

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable detailed logging for specific components
logger = logging.getLogger('behavioral_analyzer')
logger.setLevel(logging.DEBUG)
```

### Health Checks
```python
status = await orchestrator.get_system_status()
print(f"Component Health: {status['component_health']}")
print(f"Queue Size: {status['event_queue_size']}")
print(f"Active Threats: {status['active_threats']}")
```

## Contributing

1. Follow Python PEP 8 style guidelines
2. Add comprehensive tests for new features
3. Update documentation for any API changes
4. Ensure backward compatibility
5. Add appropriate logging and metrics

## License

This threat hunting toolkit is designed specifically for integration with the Rust Authentication Service and follows the same licensing terms.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review logs with DEBUG level enabled
3. Verify configuration parameters
4. Test individual components separately

The toolkit is production-ready and actively maintained for the Rust Authentication Service ecosystem.