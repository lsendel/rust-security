# Policy Service Regression Tests - Policy Management
# This file tests complete policy CRUD operations and evaluation

# Test 1: Create a new RBAC policy
POST http://localhost:8002/v1/policies
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "name": "Admin Access Policy {{$randomInt}}",
    "description": "Policy granting admin access to system resources",
    "type": "RBAC",
    "rules": [
        {
            "name": "Admin Full Access",
            "description": "Allow all actions for admin role",
            "effect": "allow",
            "priority": 100,
            "conditions": [
                {
                    "type": "attribute",
                    "operator": "eq",
                    "field": "role",
                    "value": "admin"
                }
            ],
            "resources": ["*"],
            "actions": ["*"]
        }
    ],
    "tags": ["admin", "rbac", "production"]
}

HTTP 201
[Captures]
policy_id: jsonpath "$.data.id"
policy_name: jsonpath "$.data.name"

[Asserts]
jsonpath "$.data.id" matches "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
jsonpath "$.data.name" exists
jsonpath "$.data.type" == "RBAC"
jsonpath "$.data.status" == "draft"
jsonpath "$.data.version" == 1
jsonpath "$.data.rules" isArray
jsonpath "$.data.rules[0].effect" == "allow"
jsonpath "$.data.created_at" exists
jsonpath "$.meta.request_id" exists

# Test 2: List policies with pagination
GET http://localhost:8002/v1/policies?page=1&limit=10&type=RBAC
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" isArray
jsonpath "$.meta.page" == 1
jsonpath "$.meta.per_page" == 10
jsonpath "$.meta.total" >= 1
jsonpath "$.meta.total_pages" >= 1

# Test 3: Get specific policy by ID
GET http://localhost:8002/v1/policies/{{policy_id}}
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data.id" == "{{policy_id}}"
jsonpath "$.data.name" == "{{policy_name}}"
jsonpath "$.data.type" == "RBAC"
jsonpath "$.data.rules" isArray
jsonpath "$.data.rules[0]" exists

# Test 4: Update policy
PUT http://localhost:8002/v1/policies/{{policy_id}}
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "name": "Updated Admin Policy",
    "description": "Updated description for admin policy",
    "rules": [
        {
            "name": "Admin Full Access",
            "description": "Allow all actions for admin role",
            "effect": "allow",
            "priority": 100,
            "conditions": [
                {
                    "type": "attribute",
                    "operator": "eq",
                    "field": "role",
                    "value": "admin"
                }
            ],
            "resources": ["*"],
            "actions": ["*"]
        },
        {
            "name": "Restricted Sensitive Actions",
            "description": "Deny sensitive operations during maintenance",
            "effect": "deny",
            "priority": 200,
            "conditions": [
                {
                    "type": "context",
                    "operator": "eq",
                    "field": "maintenance_mode",
                    "value": true
                }
            ],
            "resources": ["sensitive/*"],
            "actions": ["delete", "update"]
        }
    ],
    "tags": ["admin", "rbac", "production", "updated"]
}

HTTP 200
[Asserts]
jsonpath "$.data.name" == "Updated Admin Policy"
jsonpath "$.data.description" contains "Updated description"
jsonpath "$.data.rules" count == 2
jsonpath "$.data.rules[1].effect" == "deny"
jsonpath "$.data.tags" contains "updated"

# Test 5: Activate policy
POST http://localhost:8002/v1/policies/{{policy_id}}/activate
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data.status" == "active"

# Test 6: Evaluate access - Admin user should be allowed
POST http://localhost:8002/v1/evaluate
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "subject": {
        "id": "admin-user-123",
        "type": "user",
        "attributes": {
            "role": "admin",
            "department": "engineering"
        }
    },
    "resource": "/api/users",
    "action": "read",
    "context": {
        "ip_address": "192.168.1.1",
        "user_agent": "TestClient/1.0",
        "maintenance_mode": false
    }
}

HTTP 200
[Asserts]
jsonpath "$.allowed" == true
jsonpath "$.decision" == "permit"
jsonpath "$.applied_policies" isArray
jsonpath "$.applied_policies[0].id" == "{{policy_id}}"
jsonpath "$.evaluation_time_ms" > 0

# Test 7: Evaluate access - Admin during maintenance (should be denied for sensitive actions)
POST http://localhost:8002/v1/evaluate
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "subject": {
        "id": "admin-user-123",
        "type": "user",
        "attributes": {
            "role": "admin"
        }
    },
    "resource": "sensitive/config",
    "action": "delete",
    "context": {
        "maintenance_mode": true
    }
}

HTTP 200
[Asserts]
jsonpath "$.allowed" == false
jsonpath "$.decision" == "deny"
jsonpath "$.reasons" isArray

# Test 8: Batch evaluation
POST http://localhost:8002/v1/evaluate/batch
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "requests": [
        {
            "subject": {
                "id": "user-1",
                "type": "user",
                "attributes": {"role": "user"}
            },
            "resource": "/api/profile",
            "action": "read"
        },
        {
            "subject": {
                "id": "admin-1",
                "type": "user", 
                "attributes": {"role": "admin"}
            },
            "resource": "/api/admin",
            "action": "write"
        },
        {
            "subject": {
                "id": "guest-1",
                "type": "user",
                "attributes": {"role": "guest"}
            },
            "resource": "/api/admin",
            "action": "read"
        }
    ]
}

HTTP 200
[Asserts]
jsonpath "$.results" isArray
jsonpath "$.results" count == 3
jsonpath "$.results[1].allowed" == true
jsonpath "$.results[2].allowed" == false
jsonpath "$.total_time_ms" > 0

# Test 9: Simulate policy evaluation
POST http://localhost:8002/v1/evaluate/simulate
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "policy": {
        "name": "Test Simulation Policy",
        "type": "RBAC",
        "rules": [
            {
                "name": "User Read Access",
                "effect": "allow",
                "priority": 50,
                "conditions": [
                    {
                        "type": "attribute",
                        "operator": "eq",
                        "field": "role",
                        "value": "user"
                    }
                ],
                "resources": ["/api/profile"],
                "actions": ["read"]
            }
        ]
    },
    "evaluation_request": {
        "subject": {
            "id": "test-user",
            "type": "user",
            "attributes": {"role": "user"}
        },
        "resource": "/api/profile",
        "action": "read"
    }
}

HTTP 200
[Asserts]
jsonpath "$.result.allowed" == true
jsonpath "$.result.decision" == "permit"
jsonpath "$.trace" isArray
jsonpath "$.trace[0].rule_name" == "User Read Access"
jsonpath "$.trace[0].matched" == true

# Test 10: List policy templates
GET http://localhost:8002/v1/templates?category=security
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" isArray
jsonpath "$.meta" exists

# Test 11: Get policy rules
GET http://localhost:8002/v1/policies/{{policy_id}}/rules
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" isArray
jsonpath "$.data" count == 2
jsonpath "$.data[0].name" exists
jsonpath "$.data[0].effect" exists

# Test 12: Get audit logs
GET http://localhost:8002/v1/audit/logs?policyId={{policy_id}}&action=created
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" isArray
jsonpath "$.meta.page" exists
jsonpath "$.meta.per_page" exists

# Test 13: Deactivate policy
POST http://localhost:8002/v1/policies/{{policy_id}}/deactivate
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data.status" == "inactive"

# Test 14: Delete policy
DELETE http://localhost:8002/v1/policies/{{policy_id}}
Authorization: Bearer valid-test-token

HTTP 204

# Test 15: Verify policy is deleted
GET http://localhost:8002/v1/policies/{{policy_id}}
Authorization: Bearer valid-test-token

HTTP 404
[Asserts]
jsonpath "$.error.code" exists
jsonpath "$.error.message" exists

# Test 16: Create ABAC policy
POST http://localhost:8002/v1/policies
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "name": "ABAC Time-based Access Policy",
    "description": "Policy based on attributes and time constraints",
    "type": "ABAC",
    "rules": [
        {
            "name": "Business Hours Access",
            "description": "Allow access only during business hours",
            "effect": "allow",
            "priority": 100,
            "conditions": [
                {
                    "type": "time",
                    "operator": "gte",
                    "field": "hour",
                    "value": 9
                },
                {
                    "type": "time",
                    "operator": "lte", 
                    "field": "hour",
                    "value": 17
                },
                {
                    "type": "attribute",
                    "operator": "eq",
                    "field": "department",
                    "value": "engineering"
                }
            ],
            "resources": ["/api/development/*"],
            "actions": ["read", "write"]
        }
    ]
}

HTTP 201
[Captures]
abac_policy_id: jsonpath "$.data.id"

[Asserts]
jsonpath "$.data.type" == "ABAC"
jsonpath "$.data.rules[0].conditions" count == 3

# Test 17: Test unauthorized access
GET http://localhost:8002/v1/policies
Authorization: Bearer invalid-token

HTTP 401
[Asserts]
jsonpath "$.error.code" exists

# Test 18: Test forbidden access (insufficient permissions)
DELETE http://localhost:8002/v1/policies/{{abac_policy_id}}
Authorization: Bearer user-token

HTTP 403
[Asserts]
jsonpath "$.error.code" exists
jsonpath "$.error.message" exists

# Cleanup: Delete the ABAC policy
DELETE http://localhost:8002/v1/policies/{{abac_policy_id}}
Authorization: Bearer valid-test-token

HTTP 204