# Integration Guide

## Overview

This guide provides comprehensive instructions for integrating applications with the Rust Security Platform. Whether you're migrating from existing solutions like Auth0, Okta, or AWS Cognito, or building new applications, this guide covers all integration patterns and enterprise scenarios.

## Quick Start Integration

### 1. Basic Authentication Flow

#### Client Credentials Flow (Service-to-Service)
```javascript
// JavaScript/Node.js example
const axios = require('axios');

class AuthClient {
    constructor(baseUrl, clientId, clientSecret) {
        this.baseUrl = baseUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.accessToken = null;
        this.tokenExpiry = null;
    }
    
    async getAccessToken() {
        // Check if token is still valid
        if (this.accessToken && this.tokenExpiry > Date.now()) {
            return this.accessToken;
        }
        
        try {
            const response = await axios.post(`${this.baseUrl}/oauth2/token`, 
                new URLSearchParams({
                    grant_type: 'client_credentials',
                    client_id: this.clientId,
                    client_secret: this.clientSecret,
                    scope: 'read write'
                }), {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );
            
            this.accessToken = response.data.access_token;
            this.tokenExpiry = Date.now() + (response.data.expires_in * 1000) - 60000; // 1min buffer
            
            return this.accessToken;
        } catch (error) {
            throw new Error(`Token acquisition failed: ${error.response?.data?.error || error.message}`);
        }
    }
    
    async makeAuthenticatedRequest(url, options = {}) {
        const token = await this.getAccessToken();
        
        return axios({
            ...options,
            url: url,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${token}`
            }
        });
    }
}

// Usage example
const authClient = new AuthClient(
    'https://auth.company.com',
    'your_client_id',
    'your_client_secret'
);

// Make authenticated API call
authClient.makeAuthenticatedRequest('https://api.company.com/users')
    .then(response => console.log(response.data))
    .catch(error => console.error('API call failed:', error));
```

#### Authorization Code Flow (Web Applications)
```javascript
// Express.js middleware example
const express = require('express');
const session = require('express-session');
const { generators } = require('openid-client');

const app = express();

app.use(session({
    secret: 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// OpenID Connect configuration
const OIDC_CONFIG = {
    issuer: 'https://auth.company.com',
    client_id: 'your_web_app_client_id',
    client_secret: 'your_web_app_client_secret',
    redirect_uri: 'https://your-app.com/auth/callback',
    scope: 'openid profile email'
};

// Login route
app.get('/login', (req, res) => {
    const state = generators.state();
    const nonce = generators.nonce();
    
    req.session.state = state;
    req.session.nonce = nonce;
    
    const authUrl = new URL(`${OIDC_CONFIG.issuer}/oauth2/authorize`);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', OIDC_CONFIG.client_id);
    authUrl.searchParams.set('redirect_uri', OIDC_CONFIG.redirect_uri);
    authUrl.searchParams.set('scope', OIDC_CONFIG.scope);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);
    
    res.redirect(authUrl.toString());
});

// Callback route
app.get('/auth/callback', async (req, res) => {
    const { code, state } = req.query;
    
    // Validate state parameter
    if (state !== req.session.state) {
        return res.status(400).send('Invalid state parameter');
    }
    
    try {
        // Exchange code for tokens
        const tokenResponse = await axios.post(`${OIDC_CONFIG.issuer}/oauth2/token`, 
            new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: OIDC_CONFIG.redirect_uri,
                client_id: OIDC_CONFIG.client_id,
                client_secret: OIDC_CONFIG.client_secret
            }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );
        
        const { access_token, id_token, refresh_token } = tokenResponse.data;
        
        // Validate ID token
        const userInfo = await validateIdToken(id_token, req.session.nonce);
        
        // Store tokens in session
        req.session.user = userInfo;
        req.session.accessToken = access_token;
        req.session.refreshToken = refresh_token;
        
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Authentication failed:', error);
        res.status(500).send('Authentication failed');
    }
});

// Authentication middleware
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

// Protected route
app.get('/dashboard', requireAuth, (req, res) => {
    res.json({ user: req.session.user });
});
```

### 2. Python/Django Integration
```python
# Django integration example
import requests
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

class AuthService:
    def __init__(self):
        self.base_url = settings.AUTH_SERVICE_URL
        self.client_id = settings.AUTH_CLIENT_ID
        self.client_secret = settings.AUTH_CLIENT_SECRET
        self.access_token = None
        self.token_expiry = None
    
    def get_access_token(self):
        if self.access_token and self.token_expiry > datetime.now():
            return self.access_token
        
        response = requests.post(f'{self.base_url}/oauth2/token', data={
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'read write'
        })
        
        if response.status_code == 200:
            token_data = response.json()
            self.access_token = token_data['access_token']
            self.token_expiry = datetime.now() + timedelta(seconds=token_data['expires_in'] - 60)
            return self.access_token
        else:
            raise Exception(f'Token acquisition failed: {response.text}')
    
    def validate_token(self, token):
        """Validate JWT token with Auth Service"""
        try:
            # Get JWKS from auth service
            jwks_response = requests.get(f'{self.base_url}/.well-known/jwks.json')
            jwks = jwks_response.json()
            
            # Decode and validate token
            headers = jwt.get_unverified_header(token)
            rsa_key = {}
            
            for key in jwks['keys']:
                if key['kid'] == headers['kid']:
                    rsa_key = {
                        'kty': key['kty'],
                        'kid': key['kid'],
                        'use': key['use'],
                        'n': key['n'],
                        'e': key['e']
                    }
                    break
            
            if rsa_key:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=['RS256'],
                    audience=self.client_id,
                    issuer=self.base_url
                )
                return payload
            else:
                raise jwt.InvalidTokenError('Unable to find appropriate key')
        except jwt.ExpiredSignatureError:
            raise Exception('Token has expired')
        except jwt.InvalidTokenError as e:
            raise Exception(f'Token validation failed: {str(e)}')

# Django middleware for authentication
class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.auth_service = AuthService()
    
    def __call__(self, request):
        # Skip auth for public endpoints
        if request.path in ['/health', '/login', '/register']:
            return self.get_response(request)
        
        # Extract token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        token = auth_header.split(' ')[1]
        
        try:
            payload = self.auth_service.validate_token(token)
            request.user_id = payload.get('sub')
            request.user_scopes = payload.get('scope', '').split()
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=401)
        
        return self.get_response(request)

# Settings configuration
# settings.py
AUTH_SERVICE_URL = 'https://auth.company.com'
AUTH_CLIENT_ID = 'your_client_id'
AUTH_CLIENT_SECRET = 'your_client_secret'

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'your_app.middleware.AuthMiddleware',  # Add this
    # ... other middleware
]
```

### 3. React Frontend Integration
```jsx
// React hooks for authentication
import React, { createContext, useContext, useEffect, useState } from 'react';
import axios from 'axios';

const AuthContext = createContext();

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [accessToken, setAccessToken] = useState(
        localStorage.getItem('access_token')
    );

    const authConfig = {
        issuer: process.env.REACT_APP_AUTH_ISSUER,
        clientId: process.env.REACT_APP_CLIENT_ID,
        redirectUri: window.location.origin + '/auth/callback',
        scope: 'openid profile email'
    };

    useEffect(() => {
        if (accessToken) {
            validateToken();
        } else {
            setLoading(false);
        }
    }, [accessToken]);

    const validateToken = async () => {
        try {
            const response = await axios.get(`${authConfig.issuer}/userinfo`, {
                headers: {
                    Authorization: `Bearer ${accessToken}`
                }
            });
            setUser(response.data);
        } catch (error) {
            console.error('Token validation failed:', error);
            logout();
        } finally {
            setLoading(false);
        }
    };

    const login = () => {
        const state = generateRandomString();
        const nonce = generateRandomString();
        
        sessionStorage.setItem('auth_state', state);
        sessionStorage.setItem('auth_nonce', nonce);
        
        const params = new URLSearchParams({
            response_type: 'code',
            client_id: authConfig.clientId,
            redirect_uri: authConfig.redirectUri,
            scope: authConfig.scope,
            state: state,
            nonce: nonce
        });
        
        window.location.href = `${authConfig.issuer}/oauth2/authorize?${params}`;
    };

    const handleCallback = async (code, state) => {
        const savedState = sessionStorage.getItem('auth_state');
        if (state !== savedState) {
            throw new Error('Invalid state parameter');
        }

        try {
            const response = await axios.post(`${authConfig.issuer}/oauth2/token`, {
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: authConfig.redirectUri,
                client_id: authConfig.clientId
            });

            const { access_token, id_token } = response.data;
            
            localStorage.setItem('access_token', access_token);
            localStorage.setItem('id_token', id_token);
            setAccessToken(access_token);
            
            // Clean up
            sessionStorage.removeItem('auth_state');
            sessionStorage.removeItem('auth_nonce');
            
            window.history.replaceState({}, document.title, '/');
        } catch (error) {
            console.error('Token exchange failed:', error);
            throw error;
        }
    };

    const logout = () => {
        localStorage.removeItem('access_token');
        localStorage.removeItem('id_token');
        setAccessToken(null);
        setUser(null);
        
        // Optional: redirect to auth service logout
        const logoutUrl = `${authConfig.issuer}/oauth2/logout?client_id=${authConfig.clientId}&logout_uri=${window.location.origin}`;
        window.location.href = logoutUrl;
    };

    const value = {
        user,
        loading,
        accessToken,
        login,
        logout,
        handleCallback,
        isAuthenticated: !!user
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Protected Route component
export const ProtectedRoute = ({ children }) => {
    const { isAuthenticated, loading } = useAuth();

    if (loading) {
        return <div>Loading...</div>;
    }

    if (!isAuthenticated) {
        return <LoginRequired />;
    }

    return children;
};

// Axios interceptor for automatic token handling
const setupAxiosInterceptors = (accessToken, logout) => {
    axios.interceptors.request.use(
        (config) => {
            if (accessToken) {
                config.headers.Authorization = `Bearer ${accessToken}`;
            }
            return config;
        },
        (error) => Promise.reject(error)
    );

    axios.interceptors.response.use(
        (response) => response,
        (error) => {
            if (error.response?.status === 401) {
                logout();
            }
            return Promise.reject(error);
        }
    );
};

// Usage in App.js
function App() {
    return (
        <AuthProvider>
            <Router>
                <Routes>
                    <Route path="/auth/callback" element={<AuthCallback />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/dashboard" element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    } />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

const AuthCallback = () => {
    const { handleCallback } = useAuth();
    
    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');
        
        if (code && state) {
            handleCallback(code, state).catch(error => {
                console.error('Authentication failed:', error);
                // Handle error - redirect to login
            });
        }
    }, [handleCallback]);
    
    return <div>Processing authentication...</div>;
};

function generateRandomString() {
    const array = new Uint32Array(28);
    window.crypto.getRandomValues(array);
    return Array.from(array, dec => ('0' + dec.toString(16)).substr(-2)).join('');
}
```

## Migration Guides

### Migrating from Auth0

#### 1. Mapping Auth0 Concepts
| Auth0 Concept | Rust Security Platform |
|---------------|------------------------|
| Application | Client Registration |
| Connection | Identity Provider |
| Rule | Policy Engine |
| Hook | Webhook/Event Handler |
| Management API | Admin API |
| User Profile | User Claims |

#### 2. Auth0 to Rust Security Migration Script
```javascript
// Migration script from Auth0
const auth0 = require('auth0');
const axios = require('axios');

class Auth0Migration {
    constructor(auth0Config, rustAuthConfig) {
        this.auth0 = new auth0.ManagementClient(auth0Config);
        this.rustAuth = rustAuthConfig;
    }

    async migrateUsers(batchSize = 100) {
        let page = 0;
        let totalMigrated = 0;

        while (true) {
            try {
                // Get users from Auth0
                const users = await this.auth0.getUsers({
                    per_page: batchSize,
                    page: page,
                    include_totals: true
                });

                if (users.users.length === 0) break;

                // Transform and migrate users
                for (const auth0User of users.users) {
                    const rustUser = this.transformUser(auth0User);
                    await this.createUserInRustAuth(rustUser);
                    totalMigrated++;
                }

                console.log(`Migrated ${totalMigrated} users...`);
                page++;
            } catch (error) {
                console.error('Migration error:', error);
                break;
            }
        }

        console.log(`Migration complete: ${totalMigrated} users migrated`);
    }

    transformUser(auth0User) {
        return {
            id: auth0User.user_id,
            email: auth0User.email,
            email_verified: auth0User.email_verified,
            name: auth0User.name,
            picture: auth0User.picture,
            created_at: auth0User.created_at,
            updated_at: auth0User.updated_at,
            metadata: {
                ...auth0User.user_metadata,
                ...auth0User.app_metadata,
                auth0_migrated: true,
                original_provider: auth0User.identities?.[0]?.provider
            }
        };
    }

    async createUserInRustAuth(user) {
        try {
            const token = await this.getRustAuthToken();
            
            await axios.post(`${this.rustAuth.baseUrl}/admin/users`, user, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
        } catch (error) {
            console.error(`Failed to create user ${user.email}:`, error.response?.data || error.message);
            throw error;
        }
    }

    async migrateApplications() {
        const clients = await this.auth0.getClients();
        
        for (const client of clients) {
            const rustClient = {
                name: client.name,
                description: client.description,
                client_type: this.mapClientType(client.app_type),
                redirect_uris: client.callbacks || [],
                allowed_origins: client.allowed_origins || [],
                grant_types: client.grant_types || ['authorization_code'],
                scopes: ['openid', 'profile', 'email']
            };

            await this.createClientInRustAuth(rustClient);
        }
    }

    mapClientType(auth0AppType) {
        const mapping = {
            'spa': 'public',
            'native': 'public',
            'regular_web': 'confidential',
            'non_interactive': 'client_credentials'
        };
        return mapping[auth0AppType] || 'confidential';
    }

    async createClientInRustAuth(client) {
        const token = await this.getRustAuthToken();
        
        const response = await axios.post(`${this.rustAuth.baseUrl}/admin/clients`, client, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        console.log(`Created client: ${client.name} (ID: ${response.data.client_id})`);
        return response.data;
    }

    async getRustAuthToken() {
        if (this.cachedToken && this.tokenExpiry > Date.now()) {
            return this.cachedToken;
        }

        const response = await axios.post(`${this.rustAuth.baseUrl}/oauth2/token`, {
            grant_type: 'client_credentials',
            client_id: this.rustAuth.clientId,
            client_secret: this.rustAuth.clientSecret,
            scope: 'admin'
        });

        this.cachedToken = response.data.access_token;
        this.tokenExpiry = Date.now() + (response.data.expires_in * 1000) - 60000;

        return this.cachedToken;
    }
}

// Usage
const migration = new Auth0Migration(
    {
        domain: 'your-auth0-domain.auth0.com',
        clientId: 'your-auth0-client-id',
        clientSecret: 'your-auth0-client-secret',
        scope: 'read:users read:clients'
    },
    {
        baseUrl: 'https://auth.company.com',
        clientId: 'migration-client-id',
        clientSecret: 'migration-client-secret'
    }
);

// Run migration
migration.migrateUsers()
    .then(() => migration.migrateApplications())
    .then(() => console.log('Migration completed'))
    .catch(error => console.error('Migration failed:', error));
```

### Migrating from AWS Cognito

#### 1. Cognito User Pool Migration
```python
import boto3
import requests
import json
from datetime import datetime

class CognitoMigration:
    def __init__(self, cognito_config, rust_auth_config):
        self.cognito = boto3.client('cognito-idp', region_name=cognito_config['region'])
        self.user_pool_id = cognito_config['user_pool_id']
        self.rust_auth = rust_auth_config
        self.access_token = None
        self.token_expiry = None

    def migrate_users(self):
        paginator = self.cognito.get_paginator('list_users')
        total_users = 0
        
        for page in paginator.paginate(UserPoolId=self.user_pool_id):
            for user in page['Users']:
                try:
                    rust_user = self.transform_cognito_user(user)
                    self.create_user_in_rust_auth(rust_user)
                    total_users += 1
                    print(f"Migrated user: {rust_user['email']}")
                except Exception as e:
                    print(f"Failed to migrate user {user.get('Username', 'unknown')}: {e}")
        
        print(f"Migration complete: {total_users} users migrated")

    def transform_cognito_user(self, cognito_user):
        # Extract attributes
        attributes = {attr['Name']: attr['Value'] for attr in cognito_user.get('Attributes', [])}
        
        return {
            'id': cognito_user['Username'],
            'email': attributes.get('email'),
            'email_verified': attributes.get('email_verified') == 'true',
            'phone_number': attributes.get('phone_number'),
            'phone_verified': attributes.get('phone_number_verified') == 'true',
            'given_name': attributes.get('given_name'),
            'family_name': attributes.get('family_name'),
            'created_at': cognito_user['UserCreateDate'].isoformat(),
            'updated_at': cognito_user['UserLastModifiedDate'].isoformat(),
            'enabled': cognito_user['Enabled'],
            'status': cognito_user['UserStatus'],
            'metadata': {
                'cognito_migrated': True,
                'original_username': cognito_user['Username'],
                'mfa_enabled': len(cognito_user.get('MFAOptions', [])) > 0
            }
        }

    def create_user_in_rust_auth(self, user):
        token = self.get_rust_auth_token()
        
        response = requests.post(
            f"{self.rust_auth['base_url']}/admin/users",
            json=user,
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
        )
        
        if response.status_code not in [200, 201]:
            raise Exception(f"Failed to create user: {response.text}")
        
        return response.json()

    def migrate_user_pool_clients(self):
        response = self.cognito.list_user_pool_clients(UserPoolId=self.user_pool_id)
        
        for client in response['UserPoolClients']:
            client_details = self.cognito.describe_user_pool_client(
                UserPoolId=self.user_pool_id,
                ClientId=client['ClientId']
            )['UserPoolClient']
            
            rust_client = self.transform_cognito_client(client_details)
            self.create_client_in_rust_auth(rust_client)

    def transform_cognito_client(self, cognito_client):
        return {
            'name': cognito_client['ClientName'],
            'client_type': 'confidential' if cognito_client.get('GenerateSecret', False) else 'public',
            'redirect_uris': cognito_client.get('CallbackURLs', []),
            'logout_uris': cognito_client.get('LogoutURLs', []),
            'allowed_oauth_flows': cognito_client.get('AllowedOAuthFlows', []),
            'allowed_oauth_scopes': cognito_client.get('AllowedOAuthScopes', []),
            'metadata': {
                'cognito_migrated': True,
                'original_client_id': cognito_client['ClientId']
            }
        }

    def get_rust_auth_token(self):
        if self.access_token and self.token_expiry > datetime.now().timestamp():
            return self.access_token
        
        response = requests.post(
            f"{self.rust_auth['base_url']}/oauth2/token",
            data={
                'grant_type': 'client_credentials',
                'client_id': self.rust_auth['client_id'],
                'client_secret': self.rust_auth['client_secret'],
                'scope': 'admin'
            }
        )
        
        token_data = response.json()
        self.access_token = token_data['access_token']
        self.token_expiry = datetime.now().timestamp() + token_data['expires_in'] - 60
        
        return self.access_token

# Usage example
migration = CognitoMigration(
    cognito_config={
        'region': 'us-east-1',
        'user_pool_id': 'us-east-1_example123'
    },
    rust_auth_config={
        'base_url': 'https://auth.company.com',
        'client_id': 'migration-client-id',
        'client_secret': 'migration-client-secret'
    }
)

# Run migration
migration.migrate_users()
migration.migrate_user_pool_clients()
```

### Migrating from Okta

#### 1. Okta to Rust Security Migration
```bash
#!/bin/bash
# Okta migration script using Okta API

set -euo pipefail

OKTA_DOMAIN="$1"
OKTA_API_TOKEN="$2"
RUST_AUTH_URL="$3"
RUST_CLIENT_ID="$4"
RUST_CLIENT_SECRET="$5"

echo "Starting Okta to Rust Security Platform migration..."

# Get Rust Auth token
get_rust_token() {
    curl -s -X POST "$RUST_AUTH_URL/oauth2/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$RUST_CLIENT_ID&client_secret=$RUST_CLIENT_SECRET&scope=admin" \
        | jq -r '.access_token'
}

RUST_TOKEN=$(get_rust_token)

# Migrate Okta users
migrate_users() {
    echo "Migrating users..."
    local limit=200
    local after=""
    local total_migrated=0
    
    while true; do
        local url="https://$OKTA_DOMAIN/api/v1/users?limit=$limit"
        if [ -n "$after" ]; then
            url="$url&after=$after"
        fi
        
        local response=$(curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" "$url")
        local users=$(echo "$response" | jq -c '.[]')
        
        if [ -z "$users" ]; then
            break
        fi
        
        while IFS= read -r user; do
            local email=$(echo "$user" | jq -r '.profile.email')
            local first_name=$(echo "$user" | jq -r '.profile.firstName')
            local last_name=$(echo "$user" | jq -r '.profile.lastName')
            local created=$(echo "$user" | jq -r '.created')
            local status=$(echo "$user" | jq -r '.status')
            
            # Transform to Rust Auth format
            local rust_user=$(jq -n \
                --arg email "$email" \
                --arg first_name "$first_name" \
                --arg last_name "$last_name" \
                --arg created "$created" \
                --arg status "$status" \
                '{
                    email: $email,
                    first_name: $first_name,
                    last_name: $last_name,
                    created_at: $created,
                    enabled: ($status == "ACTIVE"),
                    metadata: {
                        okta_migrated: true,
                        original_status: $status
                    }
                }')
            
            # Create user in Rust Auth
            local create_result=$(curl -s -X POST "$RUST_AUTH_URL/admin/users" \
                -H "Authorization: Bearer $RUST_TOKEN" \
                -H "Content-Type: application/json" \
                -d "$rust_user")
            
            if echo "$create_result" | jq -e '.id' > /dev/null; then
                echo "✓ Migrated user: $email"
                ((total_migrated++))
            else
                echo "✗ Failed to migrate user: $email"
                echo "  Error: $(echo "$create_result" | jq -r '.error // .message // .')"
            fi
        done <<< "$users"
        
        # Get next page
        after=$(curl -s -I -H "Authorization: SSWS $OKTA_API_TOKEN" "$url" | grep -i 'link:' | grep -o 'after=[^>]*' | cut -d'=' -f2 | tr -d '"' | head -1)
        if [ -z "$after" ]; then
            break
        fi
    done
    
    echo "Users migration complete: $total_migrated users migrated"
}

# Migrate Okta applications
migrate_applications() {
    echo "Migrating applications..."
    
    local apps=$(curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
        "https://$OKTA_DOMAIN/api/v1/apps?filter=status eq \"ACTIVE\"" | jq -c '.[]')
    
    local total_migrated=0
    
    while IFS= read -r app; do
        local app_name=$(echo "$app" | jq -r '.name')
        local app_label=$(echo "$app" | jq -r '.label')
        local client_id=$(echo "$app" | jq -r '.credentials.oauthClient.client_id // empty')
        
        if [ -z "$client_id" ]; then
            echo "Skipping non-OAuth app: $app_label"
            continue
        fi
        
        # Transform to Rust Auth format
        local rust_client=$(jq -n \
            --arg name "$app_label" \
            --arg description "Migrated from Okta: $app_name" \
            '{
                name: $name,
                description: $description,
                client_type: "confidential",
                grant_types: ["authorization_code", "refresh_token"],
                scopes: ["openid", "profile", "email"],
                metadata: {
                    okta_migrated: true,
                    original_app_name: $app_name
                }
            }')
        
        local create_result=$(curl -s -X POST "$RUST_AUTH_URL/admin/clients" \
            -H "Authorization: Bearer $RUST_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$rust_client")
        
        if echo "$create_result" | jq -e '.client_id' > /dev/null; then
            echo "✓ Migrated application: $app_label"
            ((total_migrated++))
        else
            echo "✗ Failed to migrate application: $app_label"
        fi
    done <<< "$apps"
    
    echo "Applications migration complete: $total_migrated applications migrated"
}

# Run migration
migrate_users
migrate_applications

echo "Okta migration completed successfully!"
```

## Enterprise Integration Patterns

### 1. SAML Federation Setup
```rust
// SAML configuration for enterprise SSO
use saml2::{IdpMetadata, ServiceProvider, AuthnRequest};
use std::collections::HashMap;

pub struct SamlConfig {
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: String,
    pub certificate: String,
    pub private_key: String,
    pub idp_metadata: IdpMetadata,
}

pub struct SamlIntegration {
    config: SamlConfig,
    service_provider: ServiceProvider,
}

impl SamlIntegration {
    pub fn new(config: SamlConfig) -> Result<Self> {
        let sp = ServiceProvider::builder()
            .entity_id(&config.entity_id)
            .acs_url(&config.acs_url)
            .certificate(&config.certificate)
            .private_key(&config.private_key)
            .build()?;
            
        Ok(Self {
            config,
            service_provider: sp,
        })
    }
    
    pub fn generate_sso_url(&self, relay_state: Option<&str>) -> Result<String> {
        let authn_request = AuthnRequest::builder()
            .issuer(&self.config.entity_id)
            .acs_url(&self.config.acs_url)
            .relay_state(relay_state)
            .build()?;
            
        let sso_url = self.service_provider
            .generate_sso_url(&self.config.idp_metadata, &authn_request)?;
            
        Ok(sso_url)
    }
    
    pub async fn handle_saml_response(&self, saml_response: &str) -> Result<SamlUser> {
        let response = self.service_provider
            .validate_response(saml_response, &self.config.idp_metadata)?;
            
        let assertions = response.get_assertions()?;
        let attributes = self.extract_attributes(&assertions)?;
        
        Ok(SamlUser {
            name_id: response.get_name_id()?,
            attributes,
            session_index: response.get_session_index(),
        })
    }
    
    fn extract_attributes(&self, assertions: &[Assertion]) -> Result<HashMap<String, String>> {
        let mut attributes = HashMap::new();
        
        for assertion in assertions {
            for attr_stmt in assertion.get_attribute_statements() {
                for attr in attr_stmt.get_attributes() {
                    if let Some(value) = attr.get_attribute_value() {
                        attributes.insert(attr.get_name().to_string(), value);
                    }
                }
            }
        }
        
        Ok(attributes)
    }
}

// Axum handler for SAML SSO
#[axum::debug_handler]
pub async fn saml_sso_handler(
    Query(params): Query<HashMap<String, String>>,
    State(saml): State<SamlIntegration>,
) -> Result<Redirect, AppError> {
    let relay_state = params.get("RelayState").map(|s| s.as_str());
    let sso_url = saml.generate_sso_url(relay_state)?;
    
    Ok(Redirect::to(&sso_url))
}

#[axum::debug_handler]
pub async fn saml_acs_handler(
    Form(form): Form<HashMap<String, String>>,
    State(saml): State<SamlIntegration>,
    State(auth_service): State<AuthService>,
) -> Result<Redirect, AppError> {
    let saml_response = form.get("SAMLResponse")
        .ok_or(AppError::MissingParameter("SAMLResponse"))?;
    
    let saml_user = saml.handle_saml_response(saml_response).await?;
    
    // Create or update user in local system
    let user = auth_service.create_or_update_federated_user(&saml_user).await?;
    
    // Generate JWT token
    let token = auth_service.generate_token(&user).await?;
    
    // Redirect with token (in production, use secure cookie)
    let redirect_url = form.get("RelayState")
        .unwrap_or(&"/dashboard".to_string());
    
    Ok(Redirect::to(&format!("{}?token={}", redirect_url, token)))
}
```

### 2. Multi-Tenant Architecture
```rust
// Multi-tenant support
use uuid::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    pub name: String,
    pub domain: String,
    pub settings: TenantSettings,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantSettings {
    pub allow_self_registration: bool,
    pub require_email_verification: bool,
    pub password_policy: PasswordPolicy,
    pub session_timeout: Duration,
    pub mfa_required: bool,
    pub allowed_identity_providers: Vec<String>,
    pub custom_claims: HashMap<String, serde_json::Value>,
}

pub struct MultiTenantService {
    pool: PgPool,
    cache: Arc<DashMap<String, Tenant>>,
}

impl MultiTenantService {
    pub async fn get_tenant_by_domain(&self, domain: &str) -> Result<Option<Tenant>> {
        // Check cache first
        if let Some(tenant) = self.cache.get(domain) {
            return Ok(Some(tenant.clone()));
        }
        
        // Query database
        let tenant = sqlx::query_as!(
            Tenant,
            "SELECT * FROM tenants WHERE domain = $1 AND enabled = true",
            domain
        )
        .fetch_optional(&self.pool)
        .await?;
        
        // Cache the result
        if let Some(ref t) = tenant {
            self.cache.insert(domain.to_string(), t.clone());
        }
        
        Ok(tenant)
    }
    
    pub async fn create_tenant(&self, tenant: &CreateTenantRequest) -> Result<Tenant> {
        let tenant_id = Uuid::new_v4();
        
        let new_tenant = sqlx::query_as!(
            Tenant,
            "INSERT INTO tenants (id, name, domain, settings, created_at, enabled)
             VALUES ($1, $2, $3, $4, NOW(), true)
             RETURNING *",
            tenant_id,
            tenant.name,
            tenant.domain,
            serde_json::to_value(&tenant.settings)?
        )
        .fetch_one(&self.pool)
        .await?;
        
        // Create tenant-specific database schema
        self.create_tenant_schema(&tenant_id).await?;
        
        // Cache the new tenant
        self.cache.insert(tenant.domain.clone(), new_tenant.clone());
        
        Ok(new_tenant)
    }
    
    async fn create_tenant_schema(&self, tenant_id: &Uuid) -> Result<()> {
        let schema_name = format!("tenant_{}", tenant_id.simple());
        
        sqlx::query(&format!("CREATE SCHEMA {}", schema_name))
            .execute(&self.pool)
            .await?;
            
        // Create tenant-specific tables
        sqlx::query(&format!(
            "CREATE TABLE {}.users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                email VARCHAR NOT NULL UNIQUE,
                password_hash VARCHAR NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                tenant_id UUID NOT NULL DEFAULT '{}',
                CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
            )", schema_name, tenant_id
        ))
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}

// Middleware for tenant resolution
pub async fn tenant_middleware<B>(
    request: Request<B>,
    next: Next<B>,
) -> Result<Response, AppError> {
    let host = request.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::MissingHost)?;
    
    // Extract domain (remove port if present)
    let domain = host.split(':').next().unwrap_or(host);
    
    // Resolve tenant
    let tenant_service = request.extensions()
        .get::<MultiTenantService>()
        .ok_or(AppError::ServiceUnavailable)?;
    
    let tenant = tenant_service.get_tenant_by_domain(domain).await?
        .ok_or(AppError::TenantNotFound)?;
    
    // Add tenant to request extensions
    let mut request = request;
    request.extensions_mut().insert(tenant);
    
    Ok(next.run(request).await?)
}

// Tenant-aware authentication
impl AuthService {
    pub async fn authenticate_with_tenant(
        &self,
        email: &str,
        password: &str,
        tenant: &Tenant,
    ) -> Result<AuthResult> {
        // Query tenant-specific user table
        let schema_name = format!("tenant_{}", tenant.id.simple());
        
        let user = sqlx::query_as!(
            User,
            &format!("SELECT * FROM {}.users WHERE email = $1", schema_name),
            email
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AuthError::UserNotFound)?;
        
        // Verify password
        if !self.password_service.verify_password(password, &user.password_hash).await? {
            return Err(AuthError::InvalidCredentials);
        }
        
        // Apply tenant-specific settings
        let claims = self.generate_tenant_claims(&user, tenant).await?;
        
        Ok(AuthResult {
            user,
            access_token: self.generate_token(&claims).await?,
            refresh_token: self.generate_refresh_token(&user.id).await?,
            expires_in: tenant.settings.session_timeout.as_secs() as u32,
        })
    }
    
    async fn generate_tenant_claims(&self, user: &User, tenant: &Tenant) -> Result<Claims> {
        let mut claims = Claims {
            sub: user.id.to_string(),
            iss: self.config.issuer.clone(),
            aud: vec![tenant.domain.clone()],
            exp: (Utc::now() + tenant.settings.session_timeout).timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
            tenant_id: Some(tenant.id.to_string()),
            tenant_domain: Some(tenant.domain.clone()),
            custom_claims: HashMap::new(),
        };
        
        // Add tenant-specific custom claims
        for (key, value) in &tenant.settings.custom_claims {
            claims.custom_claims.insert(key.clone(), value.clone());
        }
        
        Ok(claims)
    }
}
```

### 3. API Gateway Integration
```yaml
# Kong Gateway configuration for Rust Security Platform
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: oidc-auth
plugin: oidc
config:
  issuer: https://auth.company.com
  client_id: api-gateway
  client_secret: gateway-secret
  discovery: https://auth.company.com/.well-known/openid-configuration
  introspection_endpoint: https://auth.company.com/oauth2/introspect
  bearer_only: "yes"
  realm: api-gateway
  logout_path: /logout

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: api-gateway
  annotations:
    konghq.com/plugins: oidc-auth
spec:
  rules:
  - host: api.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: backend-service
            port:
              number: 8080
```

This comprehensive integration guide provides everything needed to successfully integrate applications with the Rust Security Platform, whether migrating from existing solutions or building new integrations.