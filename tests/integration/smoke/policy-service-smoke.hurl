# Policy Service Smoke Tests
# Quick health checks to ensure basic functionality

# Test 1: Health Check
GET http://localhost:8002/health

HTTP 200
[Asserts]
jsonpath "$.status" == "healthy"
jsonpath "$.service" == "policy-service"
jsonpath "$.timestamp" exists

# Test 2: API Version Check
GET http://localhost:8002/version

HTTP 200
[Asserts]
jsonpath "$.version" matches "^[0-9]+\\.[0-9]+\\.[0-9]+"
jsonpath "$.service" == "policy-service"

# Test 3: List Policies (Smoke)
GET http://localhost:8002/v1/policies?limit=5
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.meta.page" exists

# Test 4: Basic Policy Creation (Smoke)
POST http://localhost:8002/v1/policies
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "name": "Smoke Test Policy 123",
    "description": "Basic smoke test policy",
    "type": "RBAC",
    "rules": [
        {
            "name": "Basic Rule",
            "effect": "allow",
            "priority": 50,
            "conditions": [
                {
                    "type": "attribute",
                    "operator": "eq",
                    "field": "role",
                    "value": "test"
                }
            ],
            "resources": ["/test/*"],
            "actions": ["read"]
        }
    ]
}

HTTP 201
[Captures]
smoke_policy_id: jsonpath "$.data.id"

[Asserts]
jsonpath "$.data.name" contains "Smoke Test Policy"
jsonpath "$.data.type" == "RBAC"

# Test 5: Basic Access Evaluation (Smoke)
POST http://localhost:8002/v1/evaluate
Authorization: Bearer valid-test-token
Content-Type: application/json
{
    "subject": {
        "id": "smoke-user",
        "type": "user",
        "attributes": {"role": "test"}
    },
    "resource": "/test/resource",
    "action": "read"
}

HTTP 200
[Asserts]
jsonpath "$.decision" exists
jsonpath "$.evaluation_time_ms" > 0

# Test 6: List Templates (Smoke)
GET http://localhost:8002/v1/templates
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" exists

# Test 7: Get Audit Logs (Smoke)
GET http://localhost:8002/v1/audit/logs?limit=5
Authorization: Bearer valid-test-token

HTTP 200
[Asserts]
jsonpath "$.data" exists
jsonpath "$.meta" exists

# Cleanup: Delete smoke test policy
DELETE http://localhost:8002/v1/policies/{{smoke_policy_id}}
Authorization: Bearer valid-test-token

HTTP 204