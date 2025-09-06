# API Reference - Enhanced

## Authentication Service

### POST /auth/login
Authenticate user with credentials.

**Performance:** <50ms P95 latency
**Rate Limit:** 10 requests/minute per IP

### GET /auth/profile  
Get authenticated user profile.

**Security:** Requires valid Bearer token
