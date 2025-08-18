# SOAR API Reference

## Overview

The SOAR (Security Orchestration, Automation, and Response) API provides programmatic access to security automation capabilities including workflow execution, alert processing, case management, and system monitoring.

## Base URL

```
https://api.company.com/soar/v1
```

## Authentication

All API requests require authentication using Bearer tokens:

```bash
curl -H "Authorization: Bearer <token>" \
     https://api.company.com/soar/v1/workflows
```

## Rate Limiting

- 1000 requests per minute per API key
- Rate limit headers included in responses:
  - `X-RateLimit-Limit`: Maximum requests per window
  - `X-RateLimit-Remaining`: Remaining requests in current window
  - `X-RateLimit-Reset`: Time when rate limit resets

## Common Response Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `429` - Rate Limited
- `500` - Internal Server Error

## Workflows

### Execute Workflow

Trigger execution of a security playbook.

```http
POST /workflows/execute
```

**Request Body:**
```json
{
  "playbook_id": "credential_stuffing_response",
  "inputs": {
    "source_ip": "192.168.1.100",
    "severity": "high"
  },
  "context": {
    "alert_id": "alert-123",
    "triggered_by": "user@company.com"
  },
  "priority": 1
}
```

**Response:**
```json
{
  "workflow_id": "wf-uuid-123",
  "status": "pending",
  "created_at": "2024-01-01T00:00:00Z",
  "estimated_duration_minutes": 30
}
```

### Get Workflow Status

Retrieve current status of a workflow execution.

```http
GET /workflows/{workflow_id}
```

**Response:**
```json
{
  "id": "wf-uuid-123",
  "playbook_id": "credential_stuffing_response",
  "status": "running",
  "started_at": "2024-01-01T00:00:00Z",
  "current_step": 2,
  "total_steps": 5,
  "progress_percentage": 40,
  "outputs": {
    "blocked_ips": ["192.168.1.100"],
    "actions_taken": ["ip_block", "notification_sent"]
  },
  "error": null
}
```

### Cancel Workflow

Cancel a running workflow.

```http
DELETE /workflows/{workflow_id}
```

**Request Body:**
```json
{
  "reason": "Manual cancellation by administrator"
}
```

**Response:**
```json
{
  "status": "cancelled",
  "cancelled_at": "2024-01-01T00:15:00Z"
}
```

### List Workflows

Retrieve list of workflow executions.

```http
GET /workflows?status=running&limit=50&offset=0
```

**Query Parameters:**
- `status` - Filter by status (pending, running, completed, failed, cancelled)
- `playbook_id` - Filter by playbook ID
- `limit` - Maximum results (default: 50, max: 100)
- `offset` - Pagination offset
- `start_date` - Start date filter (ISO 8601)
- `end_date` - End date filter (ISO 8601)

**Response:**
```json
{
  "workflows": [
    {
      "id": "wf-uuid-123",
      "playbook_id": "credential_stuffing_response",
      "status": "running",
      "started_at": "2024-01-01T00:00:00Z",
      "progress_percentage": 40
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### Schedule Workflow

Schedule a workflow for future execution.

```http
POST /workflows/schedule
```

**Request Body:**
```json
{
  "playbook_id": "maintenance_check",
  "execution_time": "2024-01-02T02:00:00Z",
  "inputs": {
    "check_type": "full"
  },
  "recurrence": {
    "type": "cron",
    "expression": "0 2 * * *"
  }
}
```

**Response:**
```json
{
  "schedule_id": "sched-uuid-456",
  "next_execution": "2024-01-02T02:00:00Z",
  "status": "scheduled"
}
```

## Alerts

### Process Alert

Submit a security alert for SOAR processing.

```http
POST /alerts/process
```

**Request Body:**
```json
{
  "alert_type": "authentication_failure",
  "severity": "high",
  "title": "Multiple failed login attempts",
  "description": "User account experiencing multiple failed login attempts",
  "source_ip": "192.168.1.100",
  "user_id": "user123",
  "client_id": "mobile_app",
  "metadata": {
    "failure_count": 15,
    "time_window": "5 minutes",
    "user_agent": "MobileApp/1.0"
  }
}
```

**Response:**
```json
{
  "alert_id": "alert-uuid-789",
  "status": "processed",
  "correlations_found": 2,
  "workflows_triggered": ["wf-uuid-124"],
  "case_created": "case-uuid-456",
  "processing_time_ms": 245
}
```

### Get Alert Correlations

Retrieve correlations found for an alert.

```http
GET /alerts/{alert_id}/correlations
```

**Response:**
```json
{
  "correlations": [
    {
      "id": "corr-uuid-001",
      "rule_id": "auth_failure_correlation",
      "score": 0.95,
      "related_alerts": ["alert-uuid-788", "alert-uuid-787"],
      "pattern": "credential_stuffing",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

## Cases

### Create Case

Create a new security case.

```http
POST /cases
```

**Request Body:**
```json
{
  "title": "Suspicious Activity Investigation",
  "description": "Investigating unusual login patterns for user123",
  "severity": "high",
  "assignee": "security_analyst",
  "related_alerts": ["alert-uuid-789"],
  "tags": ["investigation", "user_account"],
  "custom_fields": {
    "affected_user": "user123",
    "business_impact": "low"
  }
}
```

**Response:**
```json
{
  "case_id": "case-uuid-456",
  "status": "new",
  "created_at": "2024-01-01T00:00:00Z",
  "sla_info": {
    "response_deadline": "2024-01-01T00:30:00Z",
    "resolution_deadline": "2024-01-01T08:00:00Z"
  }
}
```

### Update Case Status

Update the status of a security case.

```http
PATCH /cases/{case_id}/status
```

**Request Body:**
```json
{
  "status": "in_progress",
  "notes": "Beginning detailed investigation of login patterns"
}
```

**Response:**
```json
{
  "status": "in_progress",
  "updated_at": "2024-01-01T00:05:00Z",
  "updated_by": "security_analyst"
}
```

### Add Evidence

Add evidence to a security case.

```http
POST /cases/{case_id}/evidence
```

**Request Body (multipart/form-data):**
- `name`: Evidence name
- `type`: Evidence type (file, screenshot, log, network_capture, etc.)
- `description`: Evidence description
- `file`: Evidence file (binary data)

**Response:**
```json
{
  "evidence_id": "evidence-uuid-123",
  "name": "suspicious_login_logs.json",
  "type": "log",
  "size_bytes": 15420,
  "hash": "sha256:abc123...",
  "collected_at": "2024-01-01T00:10:00Z",
  "collected_by": "security_analyst"
}
```

### Get Case Details

Retrieve detailed information about a case.

```http
GET /cases/{case_id}
```

**Response:**
```json
{
  "id": "case-uuid-456",
  "title": "Suspicious Activity Investigation",
  "description": "Investigating unusual login patterns for user123",
  "severity": "high",
  "status": "in_progress",
  "assignee": "security_analyst",
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T00:05:00Z",
  "due_date": "2024-01-01T08:00:00Z",
  "related_alerts": ["alert-uuid-789"],
  "related_workflows": ["wf-uuid-124"],
  "evidence": [
    {
      "id": "evidence-uuid-123",
      "name": "suspicious_login_logs.json",
      "type": "log",
      "collected_at": "2024-01-01T00:10:00Z"
    }
  ],
  "timeline": [
    {
      "id": "timeline-uuid-001",
      "timestamp": "2024-01-01T00:00:00Z",
      "type": "case_created",
      "actor": "system",
      "description": "Case created automatically"
    },
    {
      "id": "timeline-uuid-002",
      "timestamp": "2024-01-01T00:05:00Z",
      "type": "status_changed",
      "actor": "security_analyst",
      "description": "Status changed to in_progress"
    }
  ],
  "sla_info": {
    "response_time_minutes": 30,
    "resolution_time_hours": 8,
    "response_deadline": "2024-01-01T00:30:00Z",
    "resolution_deadline": "2024-01-01T08:00:00Z",
    "response_sla_breached": false,
    "resolution_sla_breached": false
  }
}
```

### List Cases

Retrieve list of security cases.

```http
GET /cases?status=open&severity=high&limit=25&offset=0
```

**Query Parameters:**
- `status` - Filter by status
- `severity` - Filter by severity
- `assignee` - Filter by assignee
- `created_after` - Filter by creation date
- `created_before` - Filter by creation date
- `limit` - Maximum results (default: 25, max: 100)
- `offset` - Pagination offset

**Response:**
```json
{
  "cases": [
    {
      "id": "case-uuid-456",
      "title": "Suspicious Activity Investigation",
      "severity": "high",
      "status": "in_progress",
      "assignee": "security_analyst",
      "created_at": "2024-01-01T00:00:00Z",
      "sla_status": "on_track"
    }
  ],
  "total": 1,
  "limit": 25,
  "offset": 0
}
```

## Playbooks

### List Playbooks

Retrieve available security playbooks.

```http
GET /playbooks
```

**Response:**
```json
{
  "playbooks": [
    {
      "id": "credential_stuffing_response",
      "name": "Credential Stuffing Response",
      "description": "Automated response to credential stuffing attacks",
      "version": "1.0.0",
      "category": "Authentication Security",
      "auto_executable": true,
      "steps": 3,
      "estimated_duration_minutes": 15
    }
  ],
  "total": 1
}
```

### Get Playbook Details

Retrieve detailed information about a playbook.

```http
GET /playbooks/{playbook_id}
```

**Response:**
```json
{
  "id": "credential_stuffing_response",
  "name": "Credential Stuffing Response",
  "description": "Automated response to credential stuffing attacks",
  "version": "1.0.0",
  "category": "Authentication Security",
  "auto_executable": true,
  "triggers": [
    {
      "type": "alert_received",
      "conditions": [
        {
          "field": "alert_type",
          "operator": "equals",
          "value": "authentication_failure"
        }
      ]
    }
  ],
  "steps": [
    {
      "id": "analyze_source_ips",
      "name": "Analyze Source IPs",
      "type": "siem_query",
      "timeout_minutes": 5
    },
    {
      "id": "block_malicious_ips",
      "name": "Block Malicious IPs",
      "type": "block_ip",
      "dependencies": ["analyze_source_ips"],
      "timeout_minutes": 2
    }
  ],
  "inputs": [
    {
      "name": "alert",
      "type": "object",
      "required": true,
      "description": "Security alert data"
    }
  ],
  "outputs": [
    {
      "name": "blocked_ips",
      "type": "array",
      "description": "List of blocked IP addresses"
    }
  ]
}
```

## System

### Health Check

Check system health and status.

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "components": {
    "database": {
      "status": "healthy",
      "response_time_ms": 15
    },
    "redis": {
      "status": "healthy",
      "response_time_ms": 2
    },
    "integrations": {
      "siem": {
        "status": "healthy",
        "last_check": "2024-01-01T00:00:00Z"
      },
      "firewall": {
        "status": "degraded",
        "last_check": "2024-01-01T00:00:00Z",
        "error": "Connection timeout"
      }
    }
  }
}
```

### System Metrics

Retrieve system performance metrics.

```http
GET /metrics
```

**Response:**
```json
{
  "workflows": {
    "total_executed": 1250,
    "currently_running": 5,
    "success_rate": 0.987,
    "avg_execution_time_minutes": 12.5
  },
  "alerts": {
    "total_processed": 8934,
    "correlations_found": 234,
    "avg_processing_time_ms": 156
  },
  "cases": {
    "total_cases": 456,
    "open_cases": 23,
    "sla_compliance_rate": 0.943,
    "avg_resolution_time_hours": 18.2
  },
  "system": {
    "uptime_seconds": 2592000,
    "memory_usage_mb": 512,
    "cpu_usage_percent": 15.5,
    "active_connections": 45
  }
}
```

### Configuration

Get system configuration (non-sensitive values only).

```http
GET /config
```

**Response:**
```json
{
  "soar": {
    "enabled": true,
    "max_concurrent_workflows": 50,
    "default_workflow_timeout_minutes": 60
  },
  "auto_response": {
    "enabled": false,
    "severity_threshold": "Medium",
    "confidence_threshold": 80
  },
  "case_management": {
    "auto_create_cases": true,
    "case_creation_threshold": "Medium"
  },
  "integrations": {
    "siem": {
      "type": "elasticsearch",
      "enabled": true
    },
    "firewall": {
      "type": "palo_alto",
      "enabled": true
    }
  }
}
```

## Webhooks

### Register Webhook

Register a webhook to receive SOAR events.

```http
POST /webhooks
```

**Request Body:**
```json
{
  "url": "https://your-system.com/soar-webhook",
  "events": [
    "workflow.completed",
    "workflow.failed",
    "case.created",
    "alert.correlated"
  ],
  "secret": "webhook-secret-key",
  "active": true
}
```

**Response:**
```json
{
  "webhook_id": "webhook-uuid-123",
  "url": "https://your-system.com/soar-webhook",
  "events": ["workflow.completed", "workflow.failed", "case.created", "alert.correlated"],
  "created_at": "2024-01-01T00:00:00Z",
  "active": true
}
```

### Webhook Events

SOAR sends webhook events in the following format:

```json
{
  "event_type": "workflow.completed",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    "workflow_id": "wf-uuid-123",
    "playbook_id": "credential_stuffing_response",
    "status": "completed",
    "duration_minutes": 8,
    "outputs": {
      "blocked_ips": ["192.168.1.100"],
      "notifications_sent": 3
    }
  },
  "webhook_id": "webhook-uuid-123"
}
```

## Error Handling

All API errors return a consistent error format:

```json
{
  "error": {
    "code": "WORKFLOW_NOT_FOUND",
    "message": "The specified workflow was not found",
    "details": {
      "workflow_id": "invalid-uuid"
    },
    "request_id": "req-uuid-456"
  }
}
```

Common error codes:
- `INVALID_REQUEST` - Request validation failed
- `WORKFLOW_NOT_FOUND` - Workflow does not exist
- `PLAYBOOK_NOT_FOUND` - Playbook does not exist
- `CASE_NOT_FOUND` - Case does not exist
- `UNAUTHORIZED` - Authentication required
- `FORBIDDEN` - Insufficient permissions
- `RATE_LIMITED` - Rate limit exceeded
- `INTEGRATION_ERROR` - External integration failed
- `INTERNAL_ERROR` - Internal system error

## SDK Examples

### Python

```python
import requests

class SOARClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
    
    def execute_workflow(self, playbook_id, inputs, context=None):
        payload = {
            'playbook_id': playbook_id,
            'inputs': inputs,
            'context': context or {}
        }
        response = requests.post(
            f'{self.base_url}/workflows/execute',
            json=payload,
            headers=self.headers
        )
        return response.json()
    
    def get_workflow_status(self, workflow_id):
        response = requests.get(
            f'{self.base_url}/workflows/{workflow_id}',
            headers=self.headers
        )
        return response.json()

# Usage
client = SOARClient('https://api.company.com/soar/v1', 'your-token')
result = client.execute_workflow(
    'credential_stuffing_response',
    {'source_ip': '192.168.1.100', 'severity': 'high'}
)
print(f"Workflow started: {result['workflow_id']}")
```

### JavaScript

```javascript
class SOARClient {
    constructor(baseUrl, token) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        };
    }
    
    async executeWorkflow(playbookId, inputs, context = {}) {
        const response = await fetch(`${this.baseUrl}/workflows/execute`, {
            method: 'POST',
            headers: this.headers,
            body: JSON.stringify({
                playbook_id: playbookId,
                inputs: inputs,
                context: context
            })
        });
        return response.json();
    }
    
    async getWorkflowStatus(workflowId) {
        const response = await fetch(`${this.baseUrl}/workflows/${workflowId}`, {
            headers: this.headers
        });
        return response.json();
    }
}

// Usage
const client = new SOARClient('https://api.company.com/soar/v1', 'your-token');
const result = await client.executeWorkflow(
    'credential_stuffing_response',
    { source_ip: '192.168.1.100', severity: 'high' }
);
console.log(`Workflow started: ${result.workflow_id}`);
```

### cURL Examples

```bash
# Execute workflow
curl -X POST https://api.company.com/soar/v1/workflows/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_id": "credential_stuffing_response",
    "inputs": {
      "source_ip": "192.168.1.100",
      "severity": "high"
    }
  }'

# Check workflow status
curl -X GET https://api.company.com/soar/v1/workflows/wf-uuid-123 \
  -H "Authorization: Bearer YOUR_TOKEN"

# Create case
curl -X POST https://api.company.com/soar/v1/cases \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Security Investigation",
    "description": "Investigating suspicious activity",
    "severity": "high"
  }'

# Process alert
curl -X POST https://api.company.com/soar/v1/alerts/process \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_type": "authentication_failure",
    "severity": "high",
    "title": "Multiple failed login attempts",
    "source_ip": "192.168.1.100"
  }'
```

## API Versioning

The API uses semantic versioning:
- Major version changes: Breaking changes to API
- Minor version changes: New features, backward compatible
- Patch version changes: Bug fixes, backward compatible

Version is specified in the URL path: `/soar/v1/`

## Support

For API support and questions:
- API Documentation: https://docs.company.com/soar-api
- Support Email: soar-support@company.com
- Developer Portal: https://developer.company.com/soar
