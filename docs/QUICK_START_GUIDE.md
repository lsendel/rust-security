# Rust Security Platform - Quick Start Guide

## 30-Second Demo Setup

Get the Rust Security Platform running in under 30 seconds with our pre-configured demo environment.

### Platform Architecture Overview

```mermaid
graph LR
    subgraph "Your Application"
        Web[Web Frontend]
        API[Backend API]
        Mobile[Mobile App]
    end
    
    subgraph "Rust Security Platform"
        Auth[Auth Service :8080]
        Policy[Policy Service :8081]
        Dashboard[Security Dashboard :8082]
    end
    
    subgraph "Data Layer"
        Redis[(Redis Cache)]
        DB[(PostgreSQL)]
    end
    
    Web --> Auth
    API --> Auth
    Mobile --> Auth
    
    Auth --> Policy
    Auth --> Redis
    Auth --> DB
    Policy --> Redis
    
    Auth --> Dashboard
    Policy --> Dashboard
    
    style Auth fill:#e1f5fe
    style Policy fill:#f3e5f5
    style Dashboard fill:#fff3e0
```

### Quick Setup Flow

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Setup as Setup Script
    participant Auth as Auth Service
    participant Policy as Policy Service
    participant Redis as Redis Cache
    
    Dev->>Setup: ./start-services.sh --demo
    Setup->>Redis: Start Redis server
    Setup->>Auth: Build & start auth-service
    Setup->>Policy: Build & start policy-service
    
    Auth->>Redis: Initialize demo data
    Auth->>Auth: Create demo OAuth client
    Policy->>Policy: Load default policies
    
    Setup-->>Dev: ✅ Platform ready!
    
    Note over Dev,Redis: Total time: ~30 seconds
```

### Prerequisites Check
```bash
# Verify requirements (takes 10 seconds)
cargo --version    # Should be 1.80+
docker --version   # Should be 20.0+
redis-cli ping     # Should return PONG (or start Redis)
```

### Lightning-Fast Startup
```bash
# Clone and start (20 seconds total)
git clone https://github.com/company/rust-security.git
cd rust-security

# One-command startup (fast development mode)
./start-services-dev.sh --demo

# Alternative: Production build (slower but optimized)
./start-services.sh --demo
```

> 💡 **Tip**: Use `start-services-dev.sh` for faster startup with debug builds, or `start-services.sh` for optimized release builds.

**🎉 Done!** Your platform is running at:
- **Auth Service**: http://localhost:8080
- **Policy Service**: http://localhost:8081  
- **Auth API Documentation**: http://localhost:8080/swagger-ui (if available)
- **Policy API Documentation**: http://localhost:8081/swagger-ui

## Instant API Testing

### Get Your First Token (10 seconds)
```bash
# Register demo user and get access token
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@example.com",
    "password": "demo123",
    "name": "Demo User"
  }'

# Login and get access token (use pre-configured demo credentials)  
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@example.com", 
    "password": "demo123"
  }' | jq '.access_token'
```

### Test OAuth 2.0 Flow (30 seconds)

```mermaid
sequenceDiagram
    participant User as Demo User
    participant Browser as Browser
    participant Auth as Auth Service
    participant Client as Demo Client
    
    Note over User,Client: Quick OAuth 2.0 Test Flow
    
    User->>Browser: Click authorization link
    Browser->>Auth: GET /oauth/authorize
    Auth->>Browser: Show login form
    Browser->>User: Display login
    
    User->>Browser: Enter demo credentials
    Browser->>Auth: POST login
    Auth->>Auth: Validate demo@company.com
    Auth->>Browser: Redirect with code
    Browser->>Client: Authorization code
    
    Client->>Auth: POST /oauth/token
    Auth->>Auth: Validate code + client
    Auth->>Client: Access + Refresh tokens
    
    Note over User,Client: ✅ OAuth flow complete in 30s
```

```bash
# Start OAuth authorization
open "http://localhost:8080/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http://localhost:3000/callback&scope=read+write&state=abc123"

# After login, exchange code for token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=YOUR_AUTH_CODE&client_id=demo-client&client_secret=demo-secret&redirect_uri=http://localhost:3000/callback"
```

### Validate Tokens & Permissions
```bash
# Check user profile
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Test Policy Authorization (15 seconds)
```bash
# Test policy service authorization
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "test-123",
    "principal": {"type": "User", "id": "demo-user"},
    "action": "Document::read",
    "resource": {"type": "Document", "id": "doc-1"},
    "context": {}
  }'

# Check policy service health
curl http://localhost:8081/health

# Check policy service metrics
curl http://localhost:8081/metrics
```

---

## Complete Integration Tutorial

### Step 1: Environment Setup (5 minutes)

#### Development Environment
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default 1.80

# Install development dependencies
cargo install cargo-watch cargo-llvm-cov
brew install redis postgresql  # macOS
sudo apt install redis-server postgresql  # Ubuntu

# Start required services
redis-server &
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS
```

#### Docker Environment (Recommended)
```bash
# Start complete stack with Docker
docker-compose up -d

# Verify all services are healthy
docker-compose ps
curl http://localhost:8080/health
curl http://localhost:8081/health
```

### Step 2: Service Configuration (3 minutes)

#### Auth Service Configuration
```yaml
# auth-service/config.yaml
server:
  host: "0.0.0.0"
  port: 8080
  
database:
  url: "postgres://user:pass@localhost:5432/auth_db"
  pool_size: 10
  
redis:
  url: "redis://localhost:6379"
  pool_size: 10
  
jwt:
  secret: "your-super-secure-jwt-secret-key-32-chars-min"
  expiration: 3600  # 1 hour
  
oauth:
  authorization_code_ttl: 600  # 10 minutes
  refresh_token_ttl: 2592000  # 30 days
  
security:
  rate_limit:
    requests_per_minute: 100
    burst_size: 10
  mfa:
    totp_issuer: "Rust Security Platform"
    backup_codes_count: 10
```

#### Policy Service Configuration
```yaml
# policy-service/config.yaml
server:
  host: "0.0.0.0"
  port: 8081
  
policies:
  directory: "./policies"
  watch_for_changes: true
  cache_ttl: 300  # 5 minutes
  
entities:
  directory: "./entities" 
  auto_reload: true
```

### Step 3: OAuth Client Registration (2 minutes)

#### Register OAuth Client
```rust
use serde_json::json;

// Register a new OAuth client
let client_registration = json!({
    "client_name": "My Web App",
    "redirect_uris": [
        "http://localhost:3000/callback",
        "http://localhost:3000/silent-callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid profile email read write",
    "token_endpoint_auth_method": "client_secret_basic"
});

let response = reqwest::Client::new()
    .post("http://localhost:8080/oauth/register")
    .json(&client_registration)
    .send()
    .await?;
    
let client_info: ClientInfo = response.json().await?;
println!("Client ID: {}", client_info.client_id);
println!("Client Secret: {}", client_info.client_secret);
```

#### Demo Client (Pre-configured)
```json
{
  "client_id": "demo-client",
  "client_secret": "demo-secret",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
  "response_types": ["code"],
  "scope": "openid profile email read write admin"
}
```

### Step 4: Integration Examples

#### Web Application Integration (JavaScript)
```html
<!DOCTYPE html>
<html>
<head>
    <title>OAuth Demo</title>
</head>
<body>
    <div id="app">
        <button onclick="startLogin()">Login with OAuth</button>
        <div id="user-info" style="display:none;">
            <h3>User Information:</h3>
            <pre id="user-data"></pre>
            <button onclick="logout()">Logout</button>
        </div>
    </div>

    <script>
        const CLIENT_ID = 'demo-client';
        const REDIRECT_URI = 'http://localhost:3000/callback';
        const AUTH_URL = 'http://localhost:8080';
        
        // Generate PKCE challenge
        function generateCodeVerifier() {
            const array = new Uint8Array(32);
            crypto.getRandomValues(array);
            return btoa(String.fromCharCode.apply(null, array))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        }
        
        async function generateCodeChallenge(verifier) {
            const data = new TextEncoder().encode(verifier);
            const digest = await crypto.subtle.digest('SHA-256', data);
            return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        }
        
        async function startLogin() {
            const codeVerifier = generateCodeVerifier();
            const codeChallenge = await generateCodeChallenge(codeVerifier);
            const state = generateCodeVerifier(); // Use same function for simplicity
            
            // Store for later use
            localStorage.setItem('code_verifier', codeVerifier);
            localStorage.setItem('oauth_state', state);
            
            // Build authorization URL
            const authUrl = new URL(`${AUTH_URL}/oauth/authorize`);
            authUrl.searchParams.set('response_type', 'code');
            authUrl.searchParams.set('client_id', CLIENT_ID);
            authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
            authUrl.searchParams.set('scope', 'openid profile email');
            authUrl.searchParams.set('state', state);
            authUrl.searchParams.set('code_challenge', codeChallenge);
            authUrl.searchParams.set('code_challenge_method', 'S256');
            
            // Redirect to authorization server
            window.location.href = authUrl.toString();
        }
        
        async function handleCallback() {
            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const storedState = localStorage.getItem('oauth_state');
            
            if (!code || !state || state !== storedState) {
                alert('Authorization failed or state mismatch');
                return;
            }
            
            // Exchange code for tokens
            const codeVerifier = localStorage.getItem('code_verifier');
            const tokenResponse = await fetch(`${AUTH_URL}/oauth/token`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code: code,
                    client_id: CLIENT_ID,
                    redirect_uri: REDIRECT_URI,
                    code_verifier: codeVerifier,
                }),
            });
            
            const tokens = await tokenResponse.json();
            
            if (tokens.access_token) {
                localStorage.setItem('access_token', tokens.access_token);
                localStorage.setItem('refresh_token', tokens.refresh_token);
                await fetchUserInfo();
            }
        }
        
        async function fetchUserInfo() {
            const accessToken = localStorage.getItem('access_token');
            if (!accessToken) return;
            
            try {
                const response = await fetch(`${AUTH_URL}/api/v1/auth/me`, {
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                    },
                });
                
                if (response.ok) {
                    const userInfo = await response.json();
                    document.getElementById('user-data').textContent = JSON.stringify(userInfo, null, 2);
                    document.getElementById('user-info').style.display = 'block';
                } else {
                    alert('Failed to fetch user info');
                }
            } catch (error) {
                console.error('Error fetching user info:', error);
            }
        }
        
        function logout() {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            localStorage.removeItem('code_verifier');
            localStorage.removeItem('oauth_state');
            document.getElementById('user-info').style.display = 'none';
        }
        
        // Handle callback on page load
        if (window.location.search.includes('code=')) {
            handleCallback();
        } else if (localStorage.getItem('access_token')) {
            fetchUserInfo();
        }
    </script>
</body>
</html>
```

#### Node.js Backend Integration
```javascript
// server.js
const express = require('express');
const passport = require('passport');
const OAuth2Strategy = require('passport-oauth2');

const app = express();

// Configure OAuth2 strategy
passport.use('rust-security', new OAuth2Strategy({
    authorizationURL: 'http://localhost:8080/oauth/authorize',
    tokenURL: 'http://localhost:8080/oauth/token',
    clientID: 'your-client-id',
    clientSecret: 'your-client-secret',
    callbackURL: 'http://localhost:3000/auth/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Fetch user info using access token
        const response = await fetch('http://localhost:8080/api/v1/auth/me', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        
        const userInfo = await response.json();
        return done(null, { ...userInfo, accessToken, refreshToken });
    } catch (error) {
        return done(error);
    }
}));

// Routes
app.get('/auth/login', passport.authenticate('rust-security'));

app.get('/auth/callback', 
    passport.authenticate('rust-security', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/dashboard');
    }
);

// Protected route middleware
const requireAuth = async (req, res, next) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // Introspect token
        const response = await fetch('http://localhost:8080/oauth/introspect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Bearer ${token}`
            },
            body: `token=${token}`
        });
        
        const introspection = await response.json();
        
        if (introspection.active) {
            req.user = introspection;
            next();
        } else {
            res.status(401).json({ error: 'Invalid token' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Token validation failed' });
    }
};

app.get('/api/protected', requireAuth, (req, res) => {
    res.json({ 
        message: 'Protected resource accessed successfully',
        user: req.user 
    });
});

app.listen(3000, () => {
    console.log('Demo app running on http://localhost:3000');
});
```

### Step 5: Policy Configuration (5 minutes)

#### Create Authorization Policies
```cedar
// policies/user-access-policy.cedar
permit (
    principal in Group::"Users",
    action == Action::"Read",
    resource
) when {
    resource.owner == principal ||
    resource.public == true
};

permit (
    principal in Group::"Admins", 
    action,
    resource
) when {
    principal.department == "IT" &&
    principal.clearance >= resource.required_clearance
};

// Time-based access policy
permit (
    principal,
    action == Action::"AccessSystem",
    resource
) when {
    context.time >= time("09:00:00") &&
    context.time <= time("17:00:00") &&
    context.day_of_week in ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
};
```

#### Define Entities
```json
// entities/entities.json
[
  {
    "uid": {"type": "User", "id": "alice"},
    "attrs": {
      "department": "Engineering", 
      "clearance": 3,
      "groups": ["Users", "Engineers"]
    },
    "parents": [
      {"type": "Group", "id": "Users"},
      {"type": "Group", "id": "Engineers"}
    ]
  },
  {
    "uid": {"type": "User", "id": "bob"},
    "attrs": {
      "department": "IT",
      "clearance": 5,
      "groups": ["Users", "Admins"]
    },
    "parents": [
      {"type": "Group", "id": "Users"},
      {"type": "Group", "id": "Admins"}
    ]
  },
  {
    "uid": {"type": "Resource", "id": "document1"},
    "attrs": {
      "owner": "alice",
      "public": false,
      "required_clearance": 2,
      "classification": "Internal"
    }
  }
]
```

#### Test Policy Evaluation
```bash
# Test authorization decision
curl -X POST http://localhost:8081/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": {"type": "User", "id": "alice"},
    "action": {"type": "Action", "id": "Read"}, 
    "resource": {"type": "Resource", "id": "document1"},
    "context": {
      "time": "14:30:00",
      "day_of_week": "Wednesday"
    }
  }'
```

### Step 6: Security Features Demo (10 minutes)

#### Enable Multi-Factor Authentication
```bash
# Setup TOTP for a user
curl -X POST http://localhost:8080/mfa/totp/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_name": "demo@company.com"
  }'

# This returns a QR code URL and secret for authenticator app setup
```

#### Monitor Security Events
```bash
# View real-time security dashboard
open http://localhost:8082/security-dashboard

# Query audit logs
curl -X GET "http://localhost:8080/admin/audit-logs?start_date=2025-01-28&event_type=authentication" \
  -H "Authorization: Bearer ADMIN_TOKEN"
```

#### Run Security Tests
```bash
# Execute red team security tests
cargo run --bin red-team-exercises -- \
  --target http://localhost:8080 \
  --intensity low \
  --scenarios token,oauth,session
  
# Generate security report
cargo run --bin red-team-exercises -- \
  --target http://localhost:8080 \
  --output-format html \
  --report-file security-assessment.html
```

## Performance Benchmarking

### Load Testing (2 minutes)
```bash
# Install hey load testing tool
go install github.com/rakyll/hey@latest

# Test token endpoint performance
hey -n 1000 -c 10 -m POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=demo-client&client_secret=demo-secret" \
  http://localhost:8080/oauth/token

# Test token validation performance  
hey -n 1000 -c 10 -m POST \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN_TO_VALIDATE" \
  http://localhost:8080/oauth/introspect
```

### Expected Performance Metrics
```
Token Generation:     ~5ms P95 latency, 2000+ req/sec
Token Validation:     ~2ms P95 latency, 5000+ req/sec  
Policy Evaluation:    ~1ms P95 latency, 10000+ req/sec
OAuth Authorization:  ~50ms P95 latency, 500+ req/sec
```

## Production Deployment

### Docker Production Setup
```bash
# Build production images
docker build -f Dockerfile.auth-service.production -t auth-service:prod .
docker build -f Dockerfile.policy-service.production -t policy-service:prod .

# Deploy with production configuration
docker-compose -f docker-compose.production.yml up -d

# Verify deployment
./validate-services.sh
```

### Kubernetes Deployment
```yaml
# k8s/auth-service-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: auth-service:prod
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: auth-secrets
              key: jwt-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi" 
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Monitoring & Observability

### Prometheus Metrics Setup
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    
  - job_name: 'policy-service'  
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/metrics'
```

### Grafana Dashboard Import
```bash
# Import pre-built dashboards
curl -X POST http://admin:admin@localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d @monitoring/grafana/auth-service-dashboard.json
```

## Troubleshooting

### Common Issues & Solutions

#### Service Won't Start
```bash
# Check port availability
netstat -tlnp | grep :8080

# Verify configuration
cargo run --bin auth-service -- --validate-config

# Check dependencies
redis-cli ping
pg_isready -h localhost -p 5432
```

#### Authentication Failures
```bash
# Check JWT configuration
curl http://localhost:8080/.well-known/jwks.json

# Validate token
curl -X POST http://localhost:8080/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_TOKEN"
```

#### Performance Issues
```bash
# Check metrics
curl http://localhost:8080/metrics | grep -E "(request_duration|error_rate)"

# Monitor resource usage
docker stats
```

### Get Help

- **Documentation**: https://docs.rust-security-platform.com
- **GitHub Issues**: https://github.com/company/rust-security/issues  
- **Community Slack**: https://rust-security.slack.com
- **Security Contact**: security@company.com

---

🎉 **Congratulations!** You now have a fully functional Rust Security Platform with OAuth 2.0, policy-based authorization, and enterprise security features. 

Start building secure applications with confidence!