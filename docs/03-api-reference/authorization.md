# Authorization API

## Overview

The Authorization API provides endpoints for policy evaluation, access control decisions, and authorization management. It implements fine-grained authorization using the Cedar policy language and supports both role-based access control (RBAC) and attribute-based access control (ABAC).

## Base URL

```
http://localhost:8081
```

## Policy Evaluation Endpoints

### Single Authorization Decision

**POST /v1/authorize**

Evaluate a single authorization request and return an access control decision.

**Request:**
```http
POST /v1/authorize HTTP/1.1
Content-Type: application/json
Authorization: Bearer access_token

{
  "principal": {
    "type": "User",
    "id": "alice",
    "attributes": {
      "department": "engineering",
      "roles": ["developer", "user"],
      "clearance_level": 3
    }
  },
  "action": {
    "type": "Action",
    "id": "read"
  },
  "resource": {
    "type": "Document",
    "id": "confidential_report.pdf",
    "attributes": {
      "owner": "bob",
      "classification": "confidential",
      "department": "engineering"
    }
  },
  "context": {
    "time": "2024-01-15T14:30:00Z",
    "ip_address": "192.168.1.100",
    "user_agent": "MyApp/1.0"
  }
}
```

**Response (200 OK) - Allow:**
```json
{
  "decision": "Allow",
  "policy_id": "engineering_read_policy",
  "obligations": [
    {
      "action": "log_access",
      "parameters": {
        "level": "info",
        "message": "Document access granted"
      }
    }
  ]
}
```

**Response (200 OK) - Deny:**
```json
{
  "decision": "Deny",
  "policy_id": "engineering_read_policy",
  "reason": "insufficient_clearance",
  "advice": [
    {
      "action": "request_approval",
      "parameters": {
        "approver_role": "manager",
        "justification_required": true
      }
    }
  ]
}
```

### Bulk Authorization Decisions

**POST /v1/authorize/bulk**

Evaluate multiple authorization requests in a single call.

**Request:**
```http
POST /v1/authorize/bulk HTTP/1.1
Content-Type: application/json
Authorization: Bearer access_token

{
  "requests": [
    {
      "principal": {
        "type": "User",
        "id": "alice"
      },
      "action": {
        "type": "Action",
        "id": "read"
      },
      "resource": {
        "type": "File",
        "id": "public/doc1.pdf"
      }
    },
    {
      "principal": {
        "type": "User",
        "id": "alice"
      },
      "action": {
        "type": "Action",
        "id": "write"
      },
      "resource": {
        "type": "File",
        "id": "private/doc2.pdf"
      }
    }
  ]
}
```

**Response (200 OK):**
```json
{
  "decisions": [
    {
      "decision": "Allow",
      "policy_id": "public_read_policy"
    },
    {
      "decision": "Deny",
      "policy_id": "private_write_policy",
      "reason": "insufficient_permissions"
    }
  ]
}
```

## Policy Management Endpoints

### List Policies

**GET /v1/policies**

List all policies with filtering options.

**Request:**
```http
GET /v1/policies?scope=engineering&type=rbac HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "policies": [
    {
      "id": "engineering_read_policy",
      "name": "Engineering Read Access",
      "type": "cedar",
      "scope": "engineering",
      "version": "1.0",
      "created_at": "2024-01-15T10:00:00Z",
      "updated_at": "2024-01-15T10:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 10
}
```

### Get Policy

**GET /v1/policies/{policy_id}**

Retrieve a specific policy by ID.

**Request:**
```http
GET /v1/policies/engineering_read_policy HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "id": "engineering_read_policy",
  "name": "Engineering Read Access",
  "description": "Allows engineering team members to read documents in their department",
  "type": "cedar",
  "scope": "engineering",
  "content": "permit (
  principal in Group::\"Engineering\",
  action == Action::\"Read\",
  resource in Folder::\"Engineering\"
) when {
  resource.owner == principal ||
  resource.public == true
};",
  "version": "1.0",
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-01-15T10:00:00Z"
}
```

### Create Policy

**POST /v1/policies**

Create a new authorization policy.

**Request:**
```http
POST /v1/policies HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "name": "Marketing Write Access",
  "description": "Allows marketing team to write to their shared folder",
  "type": "cedar",
  "scope": "marketing",
  "content": "permit (
  principal in Group::\"Marketing\",
  action == Action::\"Write\",
  resource in Folder::\"Marketing\"
);"
}
```

**Response (201 Created):**
```json
{
  "id": "marketing_write_policy",
  "name": "Marketing Write Access",
  "description": "Allows marketing team to write to their shared folder",
  "type": "cedar",
  "scope": "marketing",
  "content": "permit (
  principal in Group::\"Marketing\",
  action == Action::\"Write\",
  resource in Folder::\"Marketing\"
);",
  "version": "1.0",
  "created_at": "2024-01-15T11:00:00Z",
  "updated_at": "2024-01-15T11:00:00Z"
}
```

### Update Policy

**PUT /v1/policies/{policy_id}**

Update an existing policy.

**Request:**
```http
PUT /v1/policies/marketing_write_policy HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "name": "Marketing Write Access",
  "description": "Allows marketing team to write to their shared folder",
  "content": "permit (
  principal in Group::\"Marketing\",
  action in [Action::\"Write\", Action::\"Read\"],
  resource in Folder::\"Marketing\"
);"
}
```

**Response (200 OK):**
```json
{
  "id": "marketing_write_policy",
  "name": "Marketing Write Access",
  "description": "Allows marketing team to write to their shared folder",
  "type": "cedar",
  "scope": "marketing",
  "content": "permit (
  principal in Group::\"Marketing\",
  action in [Action::\"Write\", Action::\"Read\"],
  resource in Folder::\"Marketing\"
);",
  "version": "1.1",
  "created_at": "2024-01-15T11:00:00Z",
  "updated_at": "2024-01-15T11:30:00Z"
}
```

### Delete Policy

**DELETE /v1/policies/{policy_id}**

Delete a policy.

**Request:**
```http
DELETE /v1/policies/marketing_write_policy HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (204 No Content)**

## Entity Management Endpoints

### List Entities

**GET /v1/entities**

List all authorization entities.

**Request:**
```http
GET /v1/entities?type=User&limit=50 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "entities": [
    {
      "uid": {
        "type": "User",
        "id": "alice"
      },
      "attrs": {
        "department": "engineering",
        "roles": ["developer", "user"]
      },
      "parents": [
        {
          "type": "Group",
          "id": "Engineering"
        },
        {
          "type": "Group",
          "id": "Developers"
        }
      ]
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 50
}
```

### Get Entity

**GET /v1/entities/{entity_type}/{entity_id}**

Get a specific entity by type and ID.

**Request:**
```http
GET /v1/entities/User/alice HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "uid": {
    "type": "User",
    "id": "alice"
  },
  "attrs": {
    "department": "engineering",
    "roles": ["developer", "user"]
  },
  "parents": [
    {
      "type": "Group",
      "id": "Engineering"
    },
    {
      "type": "Group",
      "id": "Developers"
    }
  ]
}
```

### Create Entity

**POST /v1/entities**

Create a new authorization entity.

**Request:**
```http
POST /v1/entities HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "uid": {
    "type": "User",
    "id": "bob"
  },
  "attrs": {
    "department": "marketing",
    "roles": ["user"]
  },
  "parents": [
    {
      "type": "Group",
      "id": "Marketing"
    }
  ]
}
```

**Response (201 Created):**
```json
{
  "uid": {
    "type": "User",
    "id": "bob"
  },
  "attrs": {
    "department": "marketing",
    "roles": ["user"]
  },
  "parents": [
    {
      "type": "Group",
      "id": "Marketing"
    }
  ]
}
```

## Policy Templates

### List Templates

**GET /v1/templates**

List available policy templates.

**Request:**
```http
GET /v1/templates?type=rbac HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "templates": [
    {
      "id": "rbac_basic",
      "name": "Basic RBAC Template",
      "description": "Template for basic role-based access control",
      "type": "cedar",
      "content": "permit (
  principal in Role::\"{{role}}\",
  action == Action::\"{{action}}\",
  resource in Resource::\"{{resource}}\"
);"
    }
  ]
}
```

### Instantiate Template

**POST /v1/templates/{template_id}/instantiate**

Create a policy from a template.

**Request:**
```http
POST /v1/templates/rbac_basic/instantiate HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "name": "Admin Read Access",
  "parameters": {
    "role": "Admin",
    "action": "Read",
    "resource": "System"
  }
}
```

**Response (201 Created):**
```json
{
  "id": "admin_read_policy",
  "name": "Admin Read Access",
  "description": "Template instance: Basic RBAC Template",
  "type": "cedar",
  "scope": "system",
  "content": "permit (
  principal in Role::\"Admin\",
  action == Action::\"Read\",
  resource in Resource::\"System\"
);",
  "version": "1.0",
  "created_at": "2024-01-15T12:00:00Z",
  "updated_at": "2024-01-15T12:00:00Z"
}
```

## Audit and Monitoring

### Authorization Audit Log

**GET /v1/audit/authorization**

Get authorization decision audit logs.

**Request:**
```http
GET /v1/audit/authorization?principal=alice&decision=Deny&limit=100 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "logs": [
    {
      "id": "audit-123",
      "timestamp": "2024-01-15T14:30:00Z",
      "principal": {
        "type": "User",
        "id": "alice"
      },
      "action": {
        "type": "Action",
        "id": "delete"
      },
      "resource": {
        "type": "Document",
        "id": "confidential_report.pdf"
      },
      "decision": "Deny",
      "policy_id": "document_delete_policy",
      "reason": "insufficient_permissions",
      "context": {
        "ip_address": "192.168.1.100",
        "user_agent": "MyApp/1.0"
      }
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 100
}
```

## Error Responses

### Standard Errors

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_request` | 400 | Malformed request or missing required parameters |
| `unauthorized` | 401 | Missing or invalid authentication token |
| `forbidden` | 403 | Insufficient permissions for the requested operation |
| `not_found` | 404 | Requested resource not found |
| `conflict` | 409 | Resource already exists |
| `unprocessable_entity` | 422 | Request content is syntactically correct but semantically invalid |
| `too_many_requests` | 429 | Rate limit exceeded |
| `internal_server_error` | 500 | Internal server error |
| `service_unavailable` | 503 | Service temporarily unavailable |

### Error Response Format

```json
{
  "error": "forbidden",
  "error_description": "Insufficient permissions to perform this operation",
  "details": {
    "required_permission": "policy:write",
    "current_permissions": ["policy:read"]
  }
}
```