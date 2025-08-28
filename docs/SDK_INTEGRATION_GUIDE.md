# Rust Security Platform - SDK Integration Guide

## Table of Contents

1. [TypeScript/Node.js SDK](#typescriptnodejs-sdk)
2. [Python SDK](#python-sdk)
3. [Go SDK](#go-sdk)
4. [Framework Integrations](#framework-integrations)
5. [Advanced Patterns](#advanced-patterns)
6. [Testing Strategies](#testing-strategies)

---

# TypeScript/Node.js SDK

## Installation & Setup

```bash
npm install @rust-security/sdk @rust-security/types
# For React applications
npm install @rust-security/react-sdk
# For Express middleware
npm install @rust-security/express-middleware
```

### Basic Configuration

```typescript
// sdk-config.ts
import { RustSecuritySDK, SDKConfig } from '@rust-security/sdk';

const config: SDKConfig = {
  baseUrl: process.env.RUST_SECURITY_API_URL || 'https://api.rust-security.com',
  apiKey: process.env.RUST_SECURITY_API_KEY,
  
  // Timeout configuration
  timeout: 30000,
  retries: 3,
  retryDelay: 1000,
  retryDelayMultiplier: 2,
  
  // Circuit breaker configuration
  circuitBreaker: {
    enabled: true,
    failureThreshold: 5,
    recoveryTimeout: 60000,
    monitoringPeriod: 10000
  },
  
  // Caching configuration
  cache: {
    enabled: true,
    ttl: 300000, // 5 minutes
    maxSize: 1000
  },
  
  // Logging configuration
  logging: {
    level: process.env.NODE_ENV === 'development' ? 'debug' : 'info',
    includeRequestBodies: process.env.NODE_ENV === 'development',
    includeResponseBodies: false // Don't log sensitive data in production
  }
};

export const sdk = new RustSecuritySDK(config);
export const auth = sdk.auth;
export const policy = sdk.policy;
export const soar = sdk.soar;
```

## Express.js Integration

### Authentication Middleware

```typescript
// middleware/auth.ts
import { Request, Response, NextFunction } from 'express';
import { auth } from '../sdk-config';
import { AuthenticationError, RateLimitError } from '@rust-security/sdk';

interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    email: string;
    roles: string[];
    permissions: string[];
    mfaVerified: boolean;
    sessionId: string;
  };
}

export function requireAuth() {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.header('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'AUTH_TOKEN_MISSING',
          message: 'Authorization header with Bearer token is required'
        });
      }

      const token = authHeader.substring(7);
      
      // Verify token with Auth Service
      const verification = await auth.verifyToken(token);
      
      if (!verification.valid) {
        return res.status(401).json({
          error: 'AUTH_TOKEN_INVALID',
          message: 'Invalid or expired token'
        });
      }

      // Get user details
      const user = await auth.getCurrentUser(token);
      
      // Attach user to request
      req.user = {
        userId: user.userId,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        mfaVerified: user.mfaVerified,
        sessionId: verification.sessionId
      };

      next();
    } catch (error) {
      if (error instanceof AuthenticationError) {
        return res.status(401).json({
          error: error.code,
          message: error.message
        });
      } else if (error instanceof RateLimitError) {
        return res.status(429).json({
          error: 'RATE_LIMITED',
          message: 'Too many authentication requests',
          retryAfter: error.retryAfter
        });
      } else {
        console.error('Authentication middleware error:', error);
        return res.status(500).json({
          error: 'INTERNAL_ERROR',
          message: 'Authentication service unavailable'
        });
      }
    }
  };
}

// Role-based access control
export function requireRole(roles: string | string[]) {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];
  
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Authentication required'
      });
    }

    const hasRequiredRole = requiredRoles.some(role => 
      req.user!.roles.includes(role)
    );

    if (!hasRequiredRole) {
      return res.status(403).json({
        error: 'INSUFFICIENT_ROLE',
        message: `Required roles: ${requiredRoles.join(', ')}`,
        userRoles: req.user.roles
      });
    }

    next();
  };
}

// Permission-based access control
export function requirePermission(permissions: string | string[]) {
  const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
  
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Authentication required'
      });
    }

    const hasRequiredPermissions = requiredPermissions.every(permission =>
      req.user!.permissions.includes(permission)
    );

    if (!hasRequiredPermissions) {
      return res.status(403).json({
        error: 'INSUFFICIENT_PERMISSIONS',
        message: `Required permissions: ${requiredPermissions.join(', ')}`,
        userPermissions: req.user.permissions
      });
    }

    next();
  };
}
```

### Policy Enforcement Middleware

```typescript
// middleware/policy.ts
import { policy } from '../sdk-config';
import { AuthorizationRequest } from '@rust-security/sdk';

export function enforcePolicy(action: string, resourceExtractor?: (req: Request) => string) {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'AUTH_REQUIRED',
          message: 'Authentication required for policy evaluation'
        });
      }

      const resource = resourceExtractor 
        ? resourceExtractor(req)
        : `${req.method}:${req.path}`;

      const authRequest: AuthorizationRequest = {
        requestId: `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        principal: {
          type: 'User',
          id: req.user.userId
        },
        action: {
          type: 'Action',
          id: action
        },
        resource: {
          type: 'Resource',
          id: resource
        },
        context: {
          ipAddress: req.ip,
          userAgent: req.header('User-Agent'),
          timestamp: new Date().toISOString(),
          mfaVerified: req.user.mfaVerified,
          sessionId: req.user.sessionId,
          requestMethod: req.method,
          requestPath: req.path,
          userRoles: req.user.roles,
          userPermissions: req.user.permissions
        }
      };

      const result = await policy.authorize(authRequest);

      if (result.decision !== 'Allow') {
        return res.status(403).json({
          error: 'ACCESS_DENIED',
          message: 'Policy evaluation denied access',
          reasons: result.reasons,
          requestId: result.requestId
        });
      }

      // Add policy result to request for potential logging/auditing
      (req as any).policyResult = result;
      next();

    } catch (error) {
      console.error('Policy enforcement error:', error);
      return res.status(500).json({
        error: 'POLICY_EVALUATION_FAILED',
        message: 'Unable to evaluate access policy'
      });
    }
  };
}

// Usage examples
export const documentPolicyMiddleware = enforcePolicy(
  'Document::Read',
  (req) => `document:${req.params.documentId}`
);

export const apiPolicyMiddleware = enforcePolicy(
  'API::Access',
  (req) => `api:${req.method.toLowerCase()}:${req.path}`
);
```

### Complete Express Application Example

```typescript
// app.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { requireAuth, requireRole, requirePermission } from './middleware/auth';
import { enforcePolicy, documentPolicyMiddleware } from './middleware/policy';
import { auth, soar } from './sdk-config';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'RATE_LIMITED',
    message: 'Too many requests from this IP'
  }
});
app.use(limiter);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Public endpoints
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, mfaCode, rememberDevice } = req.body;
    
    const loginResult = await auth.login({
      email,
      password,
      mfaCode,
      rememberDevice,
      clientInfo: {
        ipAddress: req.ip,
        userAgent: req.header('User-Agent'),
        deviceFingerprint: req.header('X-Device-Fingerprint')
      }
    });

    if (loginResult.requiresMfa) {
      return res.status(202).json({
        success: false,
        requiresMfa: true,
        challengeToken: loginResult.challengeToken,
        availableMethods: loginResult.mfaMethods,
        message: 'MFA verification required'
      });
    }

    // Set secure HTTP-only cookie for refresh token
    res.cookie('refreshToken', loginResult.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });

    res.json({
      success: true,
      accessToken: loginResult.accessToken,
      expiresIn: loginResult.expiresIn,
      user: loginResult.user
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({
      success: false,
      error: error.code || 'LOGIN_FAILED',
      message: error.message || 'Authentication failed'
    });
  }
});

app.post('/api/auth/mfa/verify', async (req, res) => {
  try {
    const { challengeToken, mfaCode, method } = req.body;
    
    const result = await auth.completeMfaChallenge({
      challengeToken,
      mfaCode,
      method
    });

    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      accessToken: result.accessToken,
      expiresIn: result.expiresIn,
      user: result.user
    });

  } catch (error) {
    res.status(401).json({
      success: false,
      error: error.code || 'MFA_VERIFICATION_FAILED',
      message: error.message || 'MFA verification failed'
    });
  }
});

// Protected endpoints
app.get('/api/user/profile', 
  requireAuth(), 
  async (req, res) => {
    res.json({
      user: req.user
    });
  }
);

app.get('/api/documents/:documentId',
  requireAuth(),
  documentPolicyMiddleware,
  async (req, res) => {
    try {
      // Your document retrieval logic here
      const document = await getDocument(req.params.documentId);
      res.json({ document });
    } catch (error) {
      res.status(404).json({
        error: 'DOCUMENT_NOT_FOUND',
        message: 'Document not found'
      });
    }
  }
);

// Admin endpoints
app.get('/api/admin/incidents',
  requireAuth(),
  requireRole(['admin', 'security_analyst']),
  enforcePolicy('Incident::List'),
  async (req, res) => {
    try {
      const { page = 1, limit = 20, severity, status } = req.query;
      
      const incidents = await soar.incidents.list({
        page: Number(page),
        limit: Number(limit),
        severity: severity as string,
        status: status as string
      });

      res.json(incidents);
    } catch (error) {
      res.status(500).json({
        error: 'INCIDENTS_FETCH_FAILED',
        message: 'Unable to retrieve incidents'
      });
    }
  }
);

// Security incident creation endpoint
app.post('/api/security/incidents',
  requireAuth(),
  requirePermission(['incident:create']),
  async (req, res) => {
    try {
      const incident = await soar.incidents.create({
        ...req.body,
        createdBy: req.user?.userId,
        context: {
          ...req.body.context,
          reporterIp: req.ip,
          reporterUserAgent: req.header('User-Agent')
        }
      });

      res.status(201).json({
        success: true,
        incident
      });
    } catch (error) {
      res.status(500).json({
        error: 'INCIDENT_CREATION_FAILED',
        message: error.message
      });
    }
  }
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

## React Integration

### Context Provider Setup

```typescript
// contexts/AuthContext.tsx
import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { auth } from '../sdk-config';

interface User {
  userId: string;
  email: string;
  fullName: string;
  roles: string[];
  permissions: string[];
  mfaEnabled: boolean;
}

interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  loading: boolean;
  error: string | null;
  accessToken: string | null;
}

type AuthAction = 
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_SUCCESS'; payload: { user: User; accessToken: string } }
  | { type: 'LOGIN_FAILURE'; payload: string }
  | { type: 'LOGOUT' }
  | { type: 'MFA_REQUIRED'; payload: { challengeToken: string; methods: string[] } }
  | { type: 'CLEAR_ERROR' };

const initialState: AuthState = {
  isAuthenticated: false,
  user: null,
  loading: true,
  error: null,
  accessToken: null
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOGIN_START':
      return { ...state, loading: true, error: null };
    
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        accessToken: action.payload.accessToken,
        loading: false,
        error: null
      };
    
    case 'LOGIN_FAILURE':
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        accessToken: null,
        loading: false,
        error: action.payload
      };
    
    case 'LOGOUT':
      return {
        ...initialState,
        loading: false
      };
    
    case 'CLEAR_ERROR':
      return { ...state, error: null };
    
    default:
      return state;
  }
}

interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  completeMfa: (code: string, method: string) => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  const login = async (email: string, password: string) => {
    dispatch({ type: 'LOGIN_START' });
    
    try {
      const result = await auth.login({ email, password });
      
      if (result.requiresMfa) {
        dispatch({
          type: 'MFA_REQUIRED',
          payload: {
            challengeToken: result.challengeToken,
            methods: result.mfaMethods
          }
        });
        return;
      }

      // Store token securely
      localStorage.setItem('accessToken', result.accessToken);
      
      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user: result.user,
          accessToken: result.accessToken
        }
      });
      
    } catch (error) {
      dispatch({
        type: 'LOGIN_FAILURE',
        payload: error.message || 'Login failed'
      });
    }
  };

  const logout = async () => {
    try {
      if (state.accessToken) {
        await auth.logout(state.accessToken);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('accessToken');
      dispatch({ type: 'LOGOUT' });
    }
  };

  const completeMfa = async (code: string, method: string) => {
    try {
      const challengeToken = localStorage.getItem('mfaChallengeToken');
      if (!challengeToken) {
        throw new Error('No MFA challenge token found');
      }

      const result = await auth.completeMfaChallenge({
        challengeToken,
        mfaCode: code,
        method
      });

      localStorage.setItem('accessToken', result.accessToken);
      localStorage.removeItem('mfaChallengeToken');

      dispatch({
        type: 'LOGIN_SUCCESS',
        payload: {
          user: result.user,
          accessToken: result.accessToken
        }
      });
    } catch (error) {
      dispatch({
        type: 'LOGIN_FAILURE',
        payload: error.message || 'MFA verification failed'
      });
    }
  };

  const clearError = () => {
    dispatch({ type: 'CLEAR_ERROR' });
  };

  // Initialize auth state on mount
  useEffect(() => {
    const initializeAuth = async () => {
      const token = localStorage.getItem('accessToken');
      if (token) {
        try {
          const user = await auth.getCurrentUser(token);
          dispatch({
            type: 'LOGIN_SUCCESS',
            payload: { user, accessToken: token }
          });
        } catch (error) {
          localStorage.removeItem('accessToken');
          dispatch({ type: 'LOGOUT' });
        }
      } else {
        dispatch({ type: 'LOGOUT' });
      }
    };

    initializeAuth();
  }, []);

  return (
    <AuthContext.Provider value={{
      ...state,
      login,
      logout,
      completeMfa,
      clearError
    }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### Protected Route Component

```typescript
// components/ProtectedRoute.tsx
import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  roles?: string[];
  permissions?: string[];
  fallback?: React.ReactNode;
}

export function ProtectedRoute({ 
  children, 
  roles, 
  permissions, 
  fallback 
}: ProtectedRouteProps) {
  const { isAuthenticated, user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Check role requirements
  if (roles && user) {
    const hasRequiredRole = roles.some(role => user.roles.includes(role));
    if (!hasRequiredRole) {
      return fallback || <div>Access denied: insufficient role</div>;
    }
  }

  // Check permission requirements
  if (permissions && user) {
    const hasRequiredPermissions = permissions.every(permission =>
      user.permissions.includes(permission)
    );
    if (!hasRequiredPermissions) {
      return fallback || <div>Access denied: insufficient permissions</div>;
    }
  }

  return <>{children}</>;
}

// Usage example
export function AdminDashboard() {
  return (
    <ProtectedRoute 
      roles={['admin', 'security_analyst']} 
      permissions={['dashboard:view']}
      fallback={<div>You need admin access to view this page</div>}
    >
      <div>Admin Dashboard Content</div>
    </ProtectedRoute>
  );
}
```

---

# Python SDK

## Installation & Setup

```bash
pip install rust-security-sdk[async]
# For Django integration
pip install rust-security-django
# For FastAPI integration  
pip install rust-security-fastapi
```

### Basic Configuration

```python
# config.py
import os
from rust_security_sdk import RustSecuritySDK, SDKConfig
from rust_security_sdk.exceptions import RustSecurityError

# SDK Configuration
config = SDKConfig(
    base_url=os.getenv('RUST_SECURITY_API_URL', 'https://api.rust-security.com'),
    api_key=os.getenv('RUST_SECURITY_API_KEY'),
    
    # Timeout configuration
    timeout=30.0,
    max_retries=3,
    retry_delay=1.0,
    retry_backoff=2.0,
    
    # Circuit breaker
    circuit_breaker_enabled=True,
    circuit_breaker_failure_threshold=5,
    circuit_breaker_recovery_timeout=60.0,
    
    # Logging
    log_level='DEBUG' if os.getenv('DEBUG') else 'INFO',
    log_requests=os.getenv('DEBUG', '').lower() == 'true',
    
    # Connection pooling
    connection_pool_size=20,
    connection_pool_maxsize=100
)

# Initialize SDK
sdk = RustSecuritySDK(config)
auth_client = sdk.auth
policy_client = sdk.policy
soar_client = sdk.soar
```

## Django Integration

### Authentication Backend

```python
# backends/rust_security_auth.py
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User, Group
from django.contrib.auth import get_user_model
from rust_security_sdk.exceptions import AuthenticationError
from .config import auth_client
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class RustSecurityAuthBackend(BaseBackend):
    """
    Authentication backend that validates credentials against Rust Security Platform
    """
    
    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password:
            return None
            
        try:
            # Authenticate with Rust Security Platform
            auth_result = auth_client.login(
                email=username,
                password=password,
                client_info={
                    'ip_address': self._get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'device_fingerprint': request.META.get('HTTP_X_DEVICE_FINGERPRINT')
                }
            )
            
            if auth_result.requires_mfa:
                # Store MFA challenge token in session
                request.session['mfa_challenge_token'] = auth_result.challenge_token
                request.session['mfa_methods'] = auth_result.mfa_methods
                return None  # MFA required - handle in view
            
            # Create or update Django user
            user = self._get_or_create_user(auth_result.user)
            
            # Store tokens in session
            request.session['access_token'] = auth_result.access_token
            request.session['refresh_token'] = auth_result.refresh_token
            request.session['user_data'] = auth_result.user.__dict__
            
            return user
            
        except AuthenticationError as e:
            logger.warning(f"Authentication failed for {username}: {e}")
            return None
        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
    
    def _get_or_create_user(self, rust_user):
        """Create or update Django user from Rust Security user data"""
        user, created = User.objects.get_or_create(
            email=rust_user.email,
            defaults={
                'username': rust_user.email,
                'first_name': rust_user.full_name.split(' ')[0] if rust_user.full_name else '',
                'last_name': ' '.join(rust_user.full_name.split(' ')[1:]) if rust_user.full_name else '',
                'is_active': True,
                'is_staff': 'admin' in rust_user.roles,
                'is_superuser': 'superuser' in rust_user.roles
            }
        )
        
        if not created:
            # Update existing user
            user.first_name = rust_user.full_name.split(' ')[0] if rust_user.full_name else ''
            user.last_name = ' '.join(rust_user.full_name.split(' ')[1:]) if rust_user.full_name else ''
            user.is_staff = 'admin' in rust_user.roles
            user.is_superuser = 'superuser' in rust_user.roles
            user.save()
        
        # Sync user groups with roles
        self._sync_user_groups(user, rust_user.roles)
        
        return user
    
    def _sync_user_groups(self, user, roles):
        """Sync Django groups with Rust Security roles"""
        user.groups.clear()
        
        for role in roles:
            group, created = Group.objects.get_or_create(name=role)
            user.groups.add(group)
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
```

### Middleware for Policy Enforcement

```python
# middleware/policy_enforcement.py
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.urls import resolve
from rust_security_sdk.exceptions import AuthorizationError
from .config import policy_client
import logging
import json

logger = logging.getLogger(__name__)

class PolicyEnforcementMiddleware(MiddlewareMixin):
    """
    Middleware to enforce Rust Security Platform policies on Django views
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip policy enforcement for certain paths
        if self._should_skip_policy_check(request):
            return None
        
        # Only enforce for authenticated users
        if not request.user.is_authenticated:
            return None
        
        try:
            # Extract resource and action from request
            action = self._extract_action(request, view_func)
            resource = self._extract_resource(request, view_kwargs)
            
            # Build authorization request
            auth_request = {
                'request_id': f"django_{id(request)}_{request.method}",
                'principal': {
                    'type': 'User',
                    'id': str(request.user.id)
                },
                'action': {
                    'type': 'Action', 
                    'id': action
                },
                'resource': {
                    'type': 'Resource',
                    'id': resource
                },
                'context': {
                    'ip_address': self._get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'method': request.method,
                    'path': request.path,
                    'timestamp': datetime.utcnow().isoformat(),
                    'session_id': request.session.session_key,
                    'user_roles': list(request.user.groups.values_list('name', flat=True)),
                    'is_staff': request.user.is_staff,
                    'is_superuser': request.user.is_superuser
                }
            }
            
            # Evaluate policy
            result = policy_client.authorize(auth_request)
            
            if result.decision != 'Allow':
                logger.warning(
                    f"Policy denied access: user={request.user.id}, "
                    f"action={action}, resource={resource}, "
                    f"reasons={result.reasons}"
                )
                
                return JsonResponse({
                    'error': 'ACCESS_DENIED',
                    'message': 'Access denied by security policy',
                    'reasons': result.reasons,
                    'request_id': result.request_id
                }, status=403)
            
            # Store policy result for logging/auditing
            request.policy_result = result
            
        except AuthorizationError as e:
            logger.error(f"Policy evaluation error: {e}")
            return JsonResponse({
                'error': 'POLICY_EVALUATION_FAILED',
                'message': 'Unable to evaluate access policy'
            }, status=500)
        except Exception as e:
            logger.error(f"Unexpected policy middleware error: {e}")
            return JsonResponse({
                'error': 'INTERNAL_ERROR',
                'message': 'Internal server error'
            }, status=500)
        
        return None
    
    def _should_skip_policy_check(self, request):
        """Determine if policy check should be skipped for this request"""
        skip_paths = [
            '/admin/',
            '/api/auth/',
            '/health/',
            '/static/',
            '/media/'
        ]
        
        return any(request.path.startswith(path) for path in skip_paths)
    
    def _extract_action(self, request, view_func):
        """Extract action from request method and view function"""
        method_mapping = {
            'GET': 'read',
            'POST': 'create', 
            'PUT': 'update',
            'PATCH': 'update',
            'DELETE': 'delete'
        }
        
        action_base = method_mapping.get(request.method, 'access')
        view_name = getattr(view_func, '__name__', 'unknown')
        
        return f"{view_name}::{action_base}"
    
    def _extract_resource(self, request, view_kwargs):
        """Extract resource identifier from request"""
        url_name = resolve(request.path_info).url_name or 'unknown'
        
        # Include primary key if available
        if 'pk' in view_kwargs:
            return f"{url_name}:{view_kwargs['pk']}"
        elif 'id' in view_kwargs:
            return f"{url_name}:{view_kwargs['id']}"
        else:
            return f"{url_name}:collection"
    
    def _get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
```

### Custom Decorators

```python
# decorators.py
from functools import wraps
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from rust_security_sdk.exceptions import AuthorizationError
from .config import policy_client, soar_client

def require_policy_permission(action, resource_extractor=None):
    """
    Decorator to enforce specific policy permissions
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapper(request, *args, **kwargs):
            try:
                resource = resource_extractor(request, *args, **kwargs) if resource_extractor else f"{request.method}:{request.path}"
                
                auth_request = {
                    'request_id': f"decorator_{id(request)}",
                    'principal': {'type': 'User', 'id': str(request.user.id)},
                    'action': {'type': 'Action', 'id': action},
                    'resource': {'type': 'Resource', 'id': resource},
                    'context': {
                        'ip_address': request.META.get('REMOTE_ADDR'),
                        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                        'method': request.method,
                        'timestamp': datetime.utcnow().isoformat()
                    }
                }
                
                result = policy_client.authorize(auth_request)
                
                if result.decision != 'Allow':
                    return JsonResponse({
                        'error': 'ACCESS_DENIED',
                        'message': f'Permission denied for action: {action}',
                        'reasons': result.reasons
                    }, status=403)
                
                return view_func(request, *args, **kwargs)
                
            except AuthorizationError as e:
                return JsonResponse({
                    'error': 'AUTHORIZATION_FAILED',
                    'message': str(e)
                }, status=500)
        
        return wrapper
    return decorator

def create_security_incident_on_error(incident_type, severity='medium'):
    """
    Decorator to automatically create security incidents for errors
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            try:
                return view_func(request, *args, **kwargs)
            except Exception as e:
                # Create security incident
                try:
                    incident = soar_client.incidents.create({
                        'title': f'Application Error in {view_func.__name__}',
                        'description': f'Unhandled exception: {str(e)}',
                        'severity': severity,
                        'category': incident_type,
                        'source': 'django_application',
                        'affected_assets': [
                            {
                                'type': 'application_endpoint',
                                'identifier': request.path,
                                'criticality': severity
                            }
                        ],
                        'evidence': [
                            {
                                'type': 'application_log',
                                'timestamp': datetime.utcnow().isoformat(),
                                'source': 'django',
                                'data': {
                                    'exception': str(e),
                                    'view': view_func.__name__,
                                    'method': request.method,
                                    'path': request.path,
                                    'user_id': str(request.user.id) if request.user.is_authenticated else None,
                                    'ip_address': request.META.get('REMOTE_ADDR')
                                }
                            }
                        ]
                    })
                    
                    logger.error(f"Created security incident {incident.incident_id} for error in {view_func.__name__}: {e}")
                    
                except Exception as incident_error:
                    logger.error(f"Failed to create security incident: {incident_error}")
                
                # Re-raise original exception
                raise e
        
        return wrapper
    return decorator

# Usage examples
@require_policy_permission('Document::Read', lambda req, doc_id: f'document:{doc_id}')
def get_document(request, doc_id):
    # View implementation
    pass

@create_security_incident_on_error('application_error', 'high')
def sensitive_operation(request):
    # Sensitive operation that should create incident on error
    pass
```

## FastAPI Integration

### Dependency Injection

```python
# dependencies.py
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from rust_security_sdk.exceptions import AuthenticationError, AuthorizationError
from .config import auth_client, policy_client
import logging

logger = logging.getLogger(__name__)
security = HTTPBearer()

class CurrentUser:
    def __init__(self, user_id: str, email: str, roles: list, permissions: list, 
                 mfa_verified: bool, session_id: str):
        self.user_id = user_id
        self.email = email
        self.roles = roles
        self.permissions = permissions
        self.mfa_verified = mfa_verified
        self.session_id = session_id

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> CurrentUser:
    """
    Dependency to get current authenticated user
    """
    try:
        # Verify token with Rust Security Platform
        verification = await auth_client.verify_token(credentials.credentials)
        
        if not verification.valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        
        # Get user details
        user = await auth_client.get_current_user(credentials.credentials)
        
        return CurrentUser(
            user_id=user.user_id,
            email=user.email,
            roles=user.roles,
            permissions=user.permissions,
            mfa_verified=user.mfa_verified,
            session_id=verification.session_id
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {e}"
        )
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service unavailable"
        )

def require_role(required_roles: list[str]):
    """
    Dependency factory for role-based access control
    """
    def role_checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not any(role in current_user.roles for role in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required roles: {required_roles}, user roles: {current_user.roles}"
            )
        return current_user
    
    return role_checker

def require_permission(required_permissions: list[str]):
    """
    Dependency factory for permission-based access control
    """
    def permission_checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not all(perm in current_user.permissions for perm in required_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required permissions: {required_permissions}, user permissions: {current_user.permissions}"
            )
        return current_user
    
    return permission_checker

def enforce_policy(action: str, resource_extractor=None):
    """
    Dependency factory for policy enforcement
    """
    def policy_enforcer(request: Request, current_user: CurrentUser = Depends(get_current_user)):
        try:
            resource = resource_extractor(request) if resource_extractor else f"{request.method}:{request.url.path}"
            
            auth_request = {
                'request_id': f"fastapi_{id(request)}",
                'principal': {'type': 'User', 'id': current_user.user_id},
                'action': {'type': 'Action', 'id': action},
                'resource': {'type': 'Resource', 'id': resource},
                'context': {
                    'ip_address': request.client.host,
                    'user_agent': request.headers.get('user-agent', ''),
                    'method': request.method,
                    'path': str(request.url.path),
                    'timestamp': datetime.utcnow().isoformat(),
                    'mfa_verified': current_user.mfa_verified,
                    'user_roles': current_user.roles,
                    'user_permissions': current_user.permissions
                }
            }
            
            result = policy_client.authorize(auth_request)
            
            if result.decision != 'Allow':
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        'error': 'ACCESS_DENIED',
                        'message': 'Access denied by security policy',
                        'reasons': result.reasons,
                        'request_id': result.request_id
                    }
                )
            
            return current_user
            
        except AuthorizationError as e:
            logger.error(f"Policy evaluation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Policy evaluation failed"
            )
    
    return policy_enforcer
```

### FastAPI Application Example

```python
# main.py
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from pydantic import BaseModel, EmailStr
from datetime import datetime
from .dependencies import get_current_user, require_role, require_permission, enforce_policy
from .config import auth_client, soar_client
import logging

app = FastAPI(
    title="Secure FastAPI Application",
    description="FastAPI application with Rust Security Platform integration",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Configure as needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str = None
    remember_device: bool = False

class LoginResponse(BaseModel):
    success: bool
    access_token: str = None
    expires_in: int = None
    requires_mfa: bool = False
    challenge_token: str = None
    mfa_methods: list[str] = []
    user: dict = None

class MfaVerificationRequest(BaseModel):
    challenge_token: str
    mfa_code: str
    method: str

class IncidentRequest(BaseModel):
    title: str
    description: str
    severity: str
    category: str
    affected_assets: list[dict]
    evidence: list[dict] = []

# Authentication endpoints
@app.post("/auth/login", response_model=LoginResponse)
async def login(request: Request, login_data: LoginRequest):
    try:
        result = await auth_client.login(
            email=login_data.email,
            password=login_data.password,
            mfa_code=login_data.mfa_code,
            remember_device=login_data.remember_device,
            client_info={
                'ip_address': request.client.host,
                'user_agent': request.headers.get('user-agent', ''),
                'device_fingerprint': request.headers.get('x-device-fingerprint')
            }
        )
        
        if result.requires_mfa:
            return LoginResponse(
                success=False,
                requires_mfa=True,
                challenge_token=result.challenge_token,
                mfa_methods=result.mfa_methods
            )
        
        return LoginResponse(
            success=True,
            access_token=result.access_token,
            expires_in=result.expires_in,
            user=result.user.__dict__
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

@app.post("/auth/mfa/verify", response_model=LoginResponse)
async def verify_mfa(mfa_data: MfaVerificationRequest):
    try:
        result = await auth_client.complete_mfa_challenge(
            challenge_token=mfa_data.challenge_token,
            mfa_code=mfa_data.mfa_code,
            method=mfa_data.method
        )
        
        return LoginResponse(
            success=True,
            access_token=result.access_token,
            expires_in=result.expires_in,
            user=result.user.__dict__
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"MFA verification failed: {str(e)}"
        )

# Protected endpoints
@app.get("/user/profile")
async def get_user_profile(current_user = Depends(get_current_user)):
    return {
        "user": {
            "user_id": current_user.user_id,
            "email": current_user.email,
            "roles": current_user.roles,
            "permissions": current_user.permissions,
            "mfa_verified": current_user.mfa_verified
        }
    }

@app.get("/admin/users")
async def list_users(
    current_user = Depends(require_role(['admin', 'user_manager']))
):
    # Implementation to list users
    return {"users": []}

@app.get("/documents/{document_id}")
async def get_document(
    document_id: str,
    current_user = Depends(enforce_policy(
        'Document::Read',
        lambda req: f"document:{req.path_params['document_id']}"
    ))
):
    # Implementation to get document
    return {"document_id": document_id, "content": "Document content"}

@app.post("/security/incidents")
async def create_incident(
    incident_data: IncidentRequest,
    current_user = Depends(require_permission(['incident:create']))
):
    try:
        incident = await soar_client.incidents.create({
            **incident_data.dict(),
            'created_by': current_user.user_id,
            'context': {
                'reporter_ip': request.client.host,
                'reporter_user_agent': request.headers.get('user-agent', '')
            }
        })
        
        return {
            "success": True,
            "incident_id": incident.incident_id
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create incident: {str(e)}"
        )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

# Go SDK

## Installation & Setup

```bash
go get github.com/rust-security/go-sdk/v2
```

### Basic Configuration

```go
// config/sdk.go
package config

import (
    "context"
    "os"
    "time"
    
    rustsecurity "github.com/rust-security/go-sdk/v2"
)

var (
    SDK    *rustsecurity.Client
    Auth   *rustsecurity.AuthService
    Policy *rustsecurity.PolicyService
    SOAR   *rustsecurity.SOARService
)

func InitializeSDK() error {
    config := &rustsecurity.Config{
        BaseURL: getEnv("RUST_SECURITY_API_URL", "https://api.rust-security.com"),
        APIKey:  os.Getenv("RUST_SECURITY_API_KEY"),
        
        // HTTP client configuration
        Timeout:     30 * time.Second,
        MaxRetries:  3,
        RetryDelay:  1 * time.Second,
        RetryBackoff: 2.0,
        
        // Circuit breaker
        CircuitBreaker: &rustsecurity.CircuitBreakerConfig{
            Enabled:           true,
            FailureThreshold:  5,
            RecoveryTimeout:   60 * time.Second,
            MonitoringPeriod:  10 * time.Second,
        },
        
        // Logging
        Logger: rustsecurity.DefaultLogger{
            Level: rustsecurity.LogLevelInfo,
        },
        
        // Connection pooling
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 50,
        IdleConnTimeout:     90 * time.Second,
    }
    
    client, err := rustsecurity.NewClient(config)
    if err != nil {
        return err
    }
    
    SDK = client
    Auth = client.Auth()
    Policy = client.Policy()
    SOAR = client.SOAR()
    
    return nil
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

## Gin Framework Integration

### Middleware Implementation

```go
// middleware/auth.go
package middleware

import (
    "context"
    "net/http"
    "strings"
    "time"
    
    "github.com/gin-gonic/gin"
    rustsecurity "github.com/rust-security/go-sdk/v2"
    "your-app/config"
)

type AuthenticatedUser struct {
    UserID       string   `json:"user_id"`
    Email        string   `json:"email"`
    FullName     string   `json:"full_name"`
    Roles        []string `json:"roles"`
    Permissions  []string `json:"permissions"`
    MFAVerified  bool     `json:"mfa_verified"`
    SessionID    string   `json:"session_id"`
}

// AuthMiddleware validates JWT tokens and populates user context
func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "AUTH_TOKEN_MISSING",
                "message": "Authorization header with Bearer token is required",
            })
            c.Abort()
            return
        }
        
        token := strings.TrimPrefix(authHeader, "Bearer ")
        
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        
        // Verify token
        verification, err := config.Auth.VerifyToken(ctx, token)
        if err != nil {
            handleAuthError(c, err)
            c.Abort()
            return
        }
        
        if !verification.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "AUTH_TOKEN_INVALID", 
                "message": "Invalid or expired token",
            })
            c.Abort()
            return
        }
        
        // Get user details
        user, err := config.Auth.GetCurrentUser(ctx, token)
        if err != nil {
            handleAuthError(c, err)
            c.Abort()
            return
        }
        
        // Set user in context
        authUser := &AuthenticatedUser{
            UserID:      user.UserID,
            Email:       user.Email,
            FullName:    user.FullName,
            Roles:       user.Roles,
            Permissions: user.Permissions,
            MFAVerified: user.MFAVerified,
            SessionID:   verification.SessionID,
        }
        
        c.Set("user", authUser)
        c.Set("access_token", token)
        c.Next()
    }
}

// RequireRole middleware for role-based access control
func RequireRole(roles ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "AUTH_REQUIRED",
                "message": "Authentication required",
            })
            c.Abort()
            return
        }
        
        authUser := user.(*AuthenticatedUser)
        
        hasRole := false
        for _, requiredRole := range roles {
            for _, userRole := range authUser.Roles {
                if userRole == requiredRole {
                    hasRole = true
                    break
                }
            }
            if hasRole {
                break
            }
        }
        
        if !hasRole {
            c.JSON(http.StatusForbidden, gin.H{
                "error":     "INSUFFICIENT_ROLE",
                "message":   "Required roles not found",
                "required":  roles,
                "user_roles": authUser.Roles,
            })
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// RequirePermission middleware for permission-based access control
func RequirePermission(permissions ...string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "AUTH_REQUIRED",
                "message": "Authentication required",
            })
            c.Abort()
            return
        }
        
        authUser := user.(*AuthenticatedUser)
        
        for _, requiredPerm := range permissions {
            hasPerm := false
            for _, userPerm := range authUser.Permissions {
                if userPerm == requiredPerm {
                    hasPerm = true
                    break
                }
            }
            if !hasPerm {
                c.JSON(http.StatusForbidden, gin.H{
                    "error":            "INSUFFICIENT_PERMISSIONS",
                    "message":          "Required permissions not found",
                    "required":         permissions,
                    "user_permissions": authUser.Permissions,
                })
                c.Abort()
                return
            }
        }
        
        c.Next()
    }
}

func handleAuthError(c *gin.Context, err error) {
    switch e := err.(type) {
    case *rustsecurity.AuthenticationError:
        c.JSON(http.StatusUnauthorized, gin.H{
            "error":   e.Code,
            "message": e.Message,
        })
    case *rustsecurity.RateLimitError:
        c.Header("Retry-After", string(rune(e.RetryAfter)))
        c.JSON(http.StatusTooManyRequests, gin.H{
            "error":       "RATE_LIMITED",
            "message":     "Too many requests",
            "retry_after": e.RetryAfter,
        })
    default:
        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "INTERNAL_ERROR",
            "message": "Authentication service error",
        })
    }
}
```

### Policy Enforcement Middleware

```go
// middleware/policy.go
package middleware

import (
    "context"
    "fmt"
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
    rustsecurity "github.com/rust-security/go-sdk/v2"
    "your-app/config"
)

// PolicyEnforcement middleware enforces authorization policies
func PolicyEnforcement(action string, resourceExtractor func(*gin.Context) string) gin.HandlerFunc {
    return func(c *gin.Context) {
        user, exists := c.Get("user")
        if !exists {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error":   "AUTH_REQUIRED",
                "message": "Authentication required for policy evaluation",
            })
            c.Abort()
            return
        }
        
        authUser := user.(*AuthenticatedUser)
        
        // Extract resource
        var resource string
        if resourceExtractor != nil {
            resource = resourceExtractor(c)
        } else {
            resource = fmt.Sprintf("%s:%s", c.Request.Method, c.Request.URL.Path)
        }
        
        // Build authorization request
        authRequest := &rustsecurity.AuthorizationRequest{
            RequestID: fmt.Sprintf("gin_%d_%s", time.Now().UnixNano(), generateRandomID()),
            Principal: rustsecurity.Principal{
                Type: "User",
                ID:   authUser.UserID,
            },
            Action: rustsecurity.Action{
                Type: "Action",
                ID:   action,
            },
            Resource: rustsecurity.Resource{
                Type: "Resource",
                ID:   resource,
            },
            Context: map[string]interface{}{
                "ip_address":       c.ClientIP(),
                "user_agent":       c.Request.UserAgent(),
                "method":           c.Request.Method,
                "path":             c.Request.URL.Path,
                "timestamp":        time.Now().UTC().Format(time.RFC3339),
                "mfa_verified":     authUser.MFAVerified,
                "session_id":       authUser.SessionID,
                "user_roles":       authUser.Roles,
                "user_permissions": authUser.Permissions,
            },
        }
        
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        
        // Evaluate policy
        result, err := config.Policy.Authorize(ctx, authRequest)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{
                "error":   "POLICY_EVALUATION_FAILED",
                "message": "Unable to evaluate access policy",
            })
            c.Abort()
            return
        }
        
        if result.Decision != "Allow" {
            c.JSON(http.StatusForbidden, gin.H{
                "error":      "ACCESS_DENIED",
                "message":    "Access denied by security policy",
                "reasons":    result.Reasons,
                "request_id": result.RequestID,
            })
            c.Abort()
            return
        }
        
        // Store policy result for logging/auditing
        c.Set("policy_result", result)
        c.Next()
    }
}

// Convenience functions for common policy patterns
func RequireDocumentRead() gin.HandlerFunc {
    return PolicyEnforcement("Document::Read", func(c *gin.Context) string {
        if docID := c.Param("document_id"); docID != "" {
            return fmt.Sprintf("document:%s", docID)
        }
        return "document:collection"
    })
}

func RequireAPIAccess() gin.HandlerFunc {
    return PolicyEnforcement("API::Access", func(c *gin.Context) string {
        return fmt.Sprintf("api:%s:%s", strings.ToLower(c.Request.Method), c.Request.URL.Path)
    })
}

func generateRandomID() string {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    result := make([]byte, 8)
    for i := range result {
        result[i] = chars[rand.Intn(len(chars))]
    }
    return string(result)
}
```

### Complete Gin Application Example

```go
// main.go
package main

import (
    "context"
    "log"
    "net/http"
    "time"
    
    "github.com/gin-gonic/gin"
    rustsecurity "github.com/rust-security/go-sdk/v2"
    "your-app/config"
    "your-app/middleware"
)

func main() {
    // Initialize SDK
    if err := config.InitializeSDK(); err != nil {
        log.Fatal("Failed to initialize SDK:", err)
    }
    
    // Create Gin router
    router := gin.Default()
    
    // Global middleware
    router.Use(gin.Recovery())
    router.Use(corsMiddleware())
    router.Use(rateLimitMiddleware())
    
    // Public routes
    public := router.Group("/api")
    {
        public.POST("/auth/login", loginHandler)
        public.POST("/auth/mfa/verify", mfaVerifyHandler)
        public.GET("/health", healthHandler)
    }
    
    // Protected routes
    protected := router.Group("/api")
    protected.Use(middleware.AuthMiddleware())
    {
        protected.GET("/user/profile", getUserProfile)
        
        // Document routes with policy enforcement
        documents := protected.Group("/documents")
        documents.Use(middleware.RequireDocumentRead())
        {
            documents.GET("/:document_id", getDocument)
        }
        
        // Admin routes
        admin := protected.Group("/admin")
        admin.Use(middleware.RequireRole("admin", "security_analyst"))
        {
            admin.GET("/incidents", getIncidents)
            admin.POST("/incidents", middleware.RequirePermission("incident:create"), createIncident)
        }
    }
    
    // Start server
    log.Println("Starting server on :8080")
    if err := router.Run(":8080"); err != nil {
        log.Fatal("Failed to start server:", err)
    }
}

func loginHandler(c *gin.Context) {
    var req struct {
        Email        string `json:"email" binding:"required"`
        Password     string `json:"password" binding:"required"`
        MFACode      string `json:"mfa_code,omitempty"`
        RememberDevice bool `json:"remember_device"`
    }
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
        return
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    result, err := config.Auth.Login(ctx, &rustsecurity.LoginRequest{
        Email:          req.Email,
        Password:       req.Password,
        MFACode:        req.MFACode,
        RememberDevice: req.RememberDevice,
        ClientInfo: &rustsecurity.ClientInfo{
            IPAddress:         c.ClientIP(),
            UserAgent:         c.Request.UserAgent(),
            DeviceFingerprint: c.GetHeader("X-Device-Fingerprint"),
        },
    })
    
    if err != nil {
        handleAuthError(c, err)
        return
    }
    
    if result.RequiresMFA {
        c.JSON(http.StatusAccepted, gin.H{
            "success":         false,
            "requires_mfa":    true,
            "challenge_token": result.ChallengeToken,
            "mfa_methods":     result.MFAMethods,
        })
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success":      true,
        "access_token": result.AccessToken,
        "expires_in":   result.ExpiresIn,
        "user":         result.User,
    })
}

func mfaVerifyHandler(c *gin.Context) {
    var req struct {
        ChallengeToken string `json:"challenge_token" binding:"required"`
        MFACode        string `json:"mfa_code" binding:"required"`
        Method         string `json:"method" binding:"required"`
    }
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
        return
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    result, err := config.Auth.CompleteMFAChallenge(ctx, &rustsecurity.MFAChallengeRequest{
        ChallengeToken: req.ChallengeToken,
        MFACode:        req.MFACode,
        Method:         req.Method,
    })
    
    if err != nil {
        handleAuthError(c, err)
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success":      true,
        "access_token": result.AccessToken,
        "expires_in":   result.ExpiresIn,
        "user":         result.User,
    })
}

func getUserProfile(c *gin.Context) {
    user, _ := c.Get("user")
    c.JSON(http.StatusOK, gin.H{
        "user": user,
    })
}

func getDocument(c *gin.Context) {
    documentID := c.Param("document_id")
    
    // Your document retrieval logic here
    document := map[string]interface{}{
        "id":      documentID,
        "title":   "Sample Document",
        "content": "Document content here",
    }
    
    c.JSON(http.StatusOK, gin.H{
        "document": document,
    })
}

func getIncidents(c *gin.Context) {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    incidents, err := config.SOAR.Incidents.List(ctx, &rustsecurity.IncidentListRequest{
        Page:     1,
        Limit:    20,
        Severity: c.Query("severity"),
        Status:   c.Query("status"),
    })
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "INCIDENTS_FETCH_FAILED",
            "message": "Unable to retrieve incidents",
        })
        return
    }
    
    c.JSON(http.StatusOK, incidents)
}

func createIncident(c *gin.Context) {
    var req rustsecurity.CreateIncidentRequest
    
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
        return
    }
    
    user, _ := c.Get("user")
    authUser := user.(*middleware.AuthenticatedUser)
    
    // Add context information
    req.CreatedBy = authUser.UserID
    if req.Context == nil {
        req.Context = make(map[string]interface{})
    }
    req.Context["reporter_ip"] = c.ClientIP()
    req.Context["reporter_user_agent"] = c.Request.UserAgent()
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    incident, err := config.SOAR.Incidents.Create(ctx, &req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "INCIDENT_CREATION_FAILED",
            "message": err.Error(),
        })
        return
    }
    
    c.JSON(http.StatusCreated, gin.H{
        "success":  true,
        "incident": incident,
    })
}

func healthHandler(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "status":    "healthy",
        "timestamp": time.Now().UTC().Format(time.RFC3339),
    })
}

func corsMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    }
}

func rateLimitMiddleware() gin.HandlerFunc {
    // Simple in-memory rate limiter - use Redis in production
    clients := make(map[string][]time.Time)
    
    return func(c *gin.Context) {
        clientIP := c.ClientIP()
        now := time.Now()
        windowStart := now.Add(-time.Minute)
        
        // Clean old entries
        if times, exists := clients[clientIP]; exists {
            filtered := make([]time.Time, 0)
            for _, t := range times {
                if t.After(windowStart) {
                    filtered = append(filtered, t)
                }
            }
            clients[clientIP] = filtered
        }
        
        // Check rate limit (100 requests per minute)
        if len(clients[clientIP]) >= 100 {
            c.JSON(http.StatusTooManyRequests, gin.H{
                "error":   "RATE_LIMITED",
                "message": "Too many requests from this IP",
            })
            c.Abort()
            return
        }
        
        // Add current request
        clients[clientIP] = append(clients[clientIP], now)
        c.Next()
    }
}

func handleAuthError(c *gin.Context, err error) {
    switch e := err.(type) {
    case *rustsecurity.AuthenticationError:
        c.JSON(http.StatusUnauthorized, gin.H{
            "error":   e.Code,
            "message": e.Message,
        })
    case *rustsecurity.RateLimitError:
        c.Header("Retry-After", fmt.Sprintf("%d", e.RetryAfter))
        c.JSON(http.StatusTooManyRequests, gin.H{
            "error":       "RATE_LIMITED",
            "message":     "Too many requests",
            "retry_after": e.RetryAfter,
        })
    default:
        c.JSON(http.StatusInternalServerError, gin.H{
            "error":   "INTERNAL_ERROR",
            "message": "Authentication service error",
        })
    }
}
```

This comprehensive SDK integration guide provides production-ready examples for TypeScript/Node.js, Python, and Go applications. Each section includes:

1. **Complete setup and configuration** with proper error handling and timeouts
2. **Framework-specific integrations** (Express, Django, FastAPI, Gin) with middleware
3. **Authentication and authorization patterns** including role-based and policy-based access control
4. **Real-world examples** with proper security considerations
5. **Error handling strategies** with circuit breakers and retry logic
6. **Performance optimizations** including connection pooling and caching

The examples demonstrate best practices for integrating the Rust Security Platform into existing applications while maintaining security, performance, and maintainability.