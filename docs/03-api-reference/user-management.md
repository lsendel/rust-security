# User Management API

## Overview

The User Management API provides endpoints for creating, reading, updating, and deleting user accounts, as well as managing user sessions, groups, and related security features.

## Base URL

```
http://localhost:8080
```

## User Endpoints

### Create User

**POST /users**

Create a new user account.

**Request:**
```http
POST /users HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "username": "johndoe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1-555-123-4567",
  "department": "engineering",
  "require_mfa": true,
  "send_welcome_email": true
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | Yes | Unique username for the user |
| `email` | string | Yes | User's email address |
| `password` | string | Yes | User's password (min 8 characters) |
| `first_name` | string | Yes | User's first name |
| `last_name` | string | Yes | User's last name |
| `phone_number` | string | No | User's phone number for MFA |
| `department` | string | No | User's department |
| `require_mfa` | boolean | No | Whether MFA is required for this user |
| `send_welcome_email` | boolean | No | Whether to send a welcome email |

**Response (201 Created):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1-555-123-4567",
  "department": "engineering",
  "require_mfa": true,
  "email_verified": false,
  "status": "active",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### List Users

**GET /users**

List users with optional filtering and pagination.

**Request:**
```http
GET /users?department=engineering&status=active&limit=50&page=1 HTTP/1.1
Authorization: Bearer access_token
```

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | No | Filter by username |
| `email` | string | No | Filter by email |
| `department` | string | No | Filter by department |
| `status` | string | No | Filter by status (active, inactive, suspended) |
| `role` | string | No | Filter by role |
| `limit` | integer | No | Number of results per page (default: 20, max: 100) |
| `page` | integer | No | Page number (default: 1) |

**Response (200 OK):**
```json
{
  "users": [
    {
      "id": "user-123",
      "username": "johndoe",
      "email": "john.doe@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "department": "engineering",
      "require_mfa": true,
      "email_verified": true,
      "status": "active",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 20,
  "total_pages": 1
}
```

### Get User

**GET /users/{user_id}**

Get detailed information about a specific user.

**Request:**
```http
GET /users/user-123 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "phone_number": "+1-555-123-4567",
  "department": "engineering",
  "require_mfa": true,
  "email_verified": true,
  "status": "active",
  "roles": ["user", "developer"],
  "last_login": "2024-01-15T10:00:00Z",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

### Update User

**PUT /users/{user_id}**

Update user information.

**Request:**
```http
PUT /users/user-123 HTTP/1.1
Content-Type: application/json
Authorization: Bearer access_token

{
  "first_name": "Johnny",
  "last_name": "Smith",
  "phone_number": "+1-555-987-6543",
  "department": "platform",
  "require_mfa": true
}
```

**Response (200 OK):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "first_name": "Johnny",
  "last_name": "Smith",
  "phone_number": "+1-555-987-6543",
  "department": "platform",
  "require_mfa": true,
  "email_verified": true,
  "status": "active",
  "roles": ["user", "developer"],
  "last_login": "2024-01-15T10:00:00Z",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T11:00:00Z"
}
```

### Delete User

**DELETE /users/{user_id}**

Delete a user account.

**Request:**
```http
DELETE /users/user-123 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (204 No Content)**

### Deactivate User

**POST /users/{user_id}/deactivate**

Deactivate a user account without deleting it.

**Request:**
```http
POST /users/user-123/deactivate HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "status": "inactive",
  "updated_at": "2024-01-15T11:30:00Z"
}
```

### Activate User

**POST /users/{user_id}/activate**

Activate a deactivated user account.

**Request:**
```http
POST /users/user-123/activate HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "id": "user-123",
  "username": "johndoe",
  "email": "john.doe@example.com",
  "status": "active",
  "updated_at": "2024-01-15T11:45:00Z"
}
```

## Group Management

### Create Group

**POST /groups**

Create a new user group.

**Request:**
```http
POST /groups HTTP/1.1
Content-Type: application/json
Authorization: Bearer admin_access_token

{
  "name": "developers",
  "description": "Software developers group",
  "permissions": ["read", "write"]
}
```

**Response (201 Created):**
```json
{
  "id": "group-456",
  "name": "developers",
  "description": "Software developers group",
  "permissions": ["read", "write"],
  "member_count": 0,
  "created_at": "2024-01-15T12:00:00Z",
  "updated_at": "2024-01-15T12:00:00Z"
}
```

### List Groups

**GET /groups**

List all user groups.

**Request:**
```http
GET /groups?limit=50 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "groups": [
    {
      "id": "group-456",
      "name": "developers",
      "description": "Software developers group",
      "permissions": ["read", "write"],
      "member_count": 5,
      "created_at": "2024-01-15T12:00:00Z",
      "updated_at": "2024-01-15T12:00:00Z"
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 20
}
```

### Add User to Group

**POST /groups/{group_id}/members/{user_id}**

Add a user to a group.

**Request:**
```http
POST /groups/group-456/members/user-123 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User added to group successfully"
}
```

### Remove User from Group

**DELETE /groups/{group_id}/members/{user_id}**

Remove a user from a group.

**Request:**
```http
DELETE /groups/group-456/members/user-123 HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "User removed from group successfully"
}
```

## Password Management

### Change Password

**POST /users/{user_id}/password**

Change a user's password.

**Request:**
```http
POST /users/user-123/password HTTP/1.1
Content-Type: application/json
Authorization: Bearer access_token

{
  "current_password": "OldSecurePass123!",
  "new_password": "NewSecurePass456@"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

### Reset Password

**POST /users/{user_id}/password/reset**

Initiate a password reset for a user (admin only).

**Request:**
```http
POST /users/user-123/password/reset HTTP/1.1
Authorization: Bearer admin_access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password reset email sent to user"
}
```

## Multi-Factor Authentication (MFA)

### Enable MFA

**POST /users/{user_id}/mfa/enable**

Enable MFA for a user.

**Request:**
```http
POST /users/user-123/mfa/enable HTTP/1.1
Authorization: Bearer access_token

{
  "method": "totp",
  "phone_number": "+1-555-123-4567"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "MFA enabled successfully",
  "qr_code_url": "otpauth://totp/Example:john.doe@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
}
```

### Disable MFA

**POST /users/{user_id}/mfa/disable**

Disable MFA for a user.

**Request:**
```http
POST /users/user-123/mfa/disable HTTP/1.1
Authorization: Bearer access_token

{
  "password": "SecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "MFA disabled successfully"
}
```

### Verify MFA

**POST /users/{user_id}/mfa/verify**

Verify an MFA code during setup.

**Request:**
```http
POST /users/user-123/mfa/verify HTTP/1.1
Content-Type: application/json
Authorization: Bearer access_token

{
  "code": "123456"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "MFA verified successfully"
}
```

## Session Management

### List User Sessions

**GET /users/{user_id}/sessions**

List all active sessions for a user.

**Request:**
```http
GET /users/user-123/sessions HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "sessions": [
    {
      "id": "session-789",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "created_at": "2024-01-15T10:00:00Z",
      "last_activity": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-16T10:00:00Z"
    }
  ]
}
```

### Revoke Session

**DELETE /users/{user_id}/sessions/{session_id}**

Revoke a specific user session.

**Request:**
```http
DELETE /users/user-123/sessions/session-789 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Session revoked successfully"
}
```

### Revoke All Sessions

**DELETE /users/{user_id}/sessions**

Revoke all sessions for a user (except current).

**Request:**
```http
DELETE /users/user-123/sessions HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "All sessions revoked successfully",
  "count": 3
}
```

## User Audit

### Get User Activity Log

**GET /users/{user_id}/audit**

Get audit log for user activities.

**Request:**
```http
GET /users/user-123/audit?limit=50 HTTP/1.1
Authorization: Bearer access_token
```

**Response (200 OK):**
```json
{
  "activities": [
    {
      "id": "audit-123",
      "timestamp": "2024-01-15T10:30:00Z",
      "action": "login",
      "ip_address": "192.168.1.100",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "success": true
    }
  ],
  "total": 1,
  "page": 1,
  "limit": 50
}
```

## Error Responses

### Standard Errors

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `invalid_request` | 400 | Malformed request or missing required parameters |
| `unauthorized` | 401 | Missing or invalid authentication token |
| `forbidden` | 403 | Insufficient permissions for the requested operation |
| `not_found` | 404 | Requested user or resource not found |
| `conflict` | 409 | User with this username or email already exists |
| `unprocessable_entity` | 422 | Request content is syntactically correct but semantically invalid |
| `too_many_requests` | 429 | Rate limit exceeded |
| `internal_server_error` | 500 | Internal server error |
| `service_unavailable` | 503 | Service temporarily unavailable |

### Error Response Format

```json
{
  "error": "conflict",
  "error_description": "A user with this email already exists",
  "details": {
    "field": "email",
    "value": "john.doe@example.com"
  }
}
```