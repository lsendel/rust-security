#!/usr/bin/env python3
"""
Mock Services for Integration Testing
Provides lightweight HTTP endpoints that mimic the auth and policy services
"""

import json
import time
import uuid
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from werkzeug.serving import make_server
import threading
import signal
import sys

# Mock data stores
USERS = {}
SESSIONS = {}
POLICIES = {}
TOKENS = {}

# Configuration
AUTH_PORT = 8001
POLICY_PORT = 8002

def create_auth_service():
    """Create mock auth service"""
    app = Flask('auth-service')
    
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            "status": "healthy",
            "service": "auth-service",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    @app.route('/version', methods=['GET'])
    def version():
        return jsonify({
            "version": "1.0.0",
            "service": "auth-service"
        })
    
    @app.route('/v1/auth/register', methods=['POST'])
    def register():
        data = request.get_json()
        
        if not data or 'username' not in data or 'email' not in data or 'password' not in data:
            return jsonify({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Missing required fields"
                }
            }), 422
        
        # Check if user already exists
        for user in USERS.values():
            if user['username'] == data['username'] or user['email'] == data['email']:
                return jsonify({
                    "error": {
                        "code": "USER_EXISTS",
                        "message": "User already exists"
                    }
                }), 409
        
        user_id = str(uuid.uuid4())
        user = {
            "id": user_id,
            "username": data['username'],
            "email": data['email'],
            "full_name": data.get('full_name', ''),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "email_verified": False,
            "two_factor_enabled": False
        }
        
        USERS[user_id] = {**user, 'password': data['password']}
        
        return jsonify({
            "data": user,
            "meta": {
                "request_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "api_version": "1.0"
            }
        }), 201
    
    @app.route('/v1/auth/login', methods=['POST'])
    def login():
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Missing username or password"
                },
                "meta": {
                    "request_id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }), 422
        
        # Find user
        user = None
        for u in USERS.values():
            if u['username'] == data['username'] and u['password'] == data['password']:
                user = u
                break
        
        if not user:
            return jsonify({
                "error": {
                    "code": "INVALID_CREDENTIALS",
                    "message": "Invalid username or password"
                },
                "meta": {
                    "request_id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }), 401
        
        # Generate tokens
        access_token = f"mock_access_token_{int(time.time())}_{user['id'][:8]}"
        refresh_token = f"mock_refresh_token_{int(time.time())}_{user['id'][:8]}"
        
        # Store tokens
        TOKENS[access_token] = {
            "user_id": user['id'],
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "type": "access"
        }
        TOKENS[refresh_token] = {
            "user_id": user['id'],
            "expires_at": datetime.utcnow() + timedelta(days=7),
            "type": "refresh"
        }
        
        # Create session
        session_id = str(uuid.uuid4())
        SESSIONS[session_id] = {
            "id": session_id,
            "user_id": user['id'],
            "user_agent": request.headers.get('User-Agent', ''),
            "ip_address": request.remote_addr,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "last_accessed": datetime.utcnow().isoformat() + "Z",
            "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z"
        }
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "user": {k: v for k, v in user.items() if k != 'password'}
        })
    
    @app.route('/v1/auth/verify', methods=['POST'])
    def verify():
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                "error": {
                    "code": "INVALID_TOKEN",
                    "message": "Missing or invalid authorization header"
                }
            }), 401
        
        token = auth_header.split(' ')[1]
        
        if token not in TOKENS:
            return jsonify({
                "error": {
                    "code": "INVALID_TOKEN", 
                    "message": "Token not found"
                }
            }), 401
        
        token_data = TOKENS[token]
        if datetime.utcnow() > token_data['expires_at']:
            return jsonify({
                "error": {
                    "code": "TOKEN_EXPIRED",
                    "message": "Token has expired"
                }
            }), 401
        
        return jsonify({
            "valid": True,
            "claims": {
                "sub": token_data['user_id'],
                "exp": int(token_data['expires_at'].timestamp()),
                "iat": int(time.time()),
                "jti": str(uuid.uuid4()),
                "roles": ["user"]
            }
        })
    
    @app.route('/v1/auth/sessions', methods=['GET'])
    def list_sessions():
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        token = auth_header.split(' ')[1]
        if token not in TOKENS:
            return jsonify({"error": {"code": "INVALID_TOKEN"}}), 401
        
        user_id = TOKENS[token]['user_id']
        user_sessions = [s for s in SESSIONS.values() if s['user_id'] == user_id]
        
        return jsonify({
            "data": user_sessions,
            "meta": {
                "page": 1,
                "per_page": 20,
                "total": len(user_sessions),
                "total_pages": 1
            }
        })
    
    @app.route('/v1/auth/logout', methods=['POST'])
    def logout():
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        token = auth_header.split(' ')[1]
        if token in TOKENS:
            del TOKENS[token]
        
        return '', 204
    
    @app.route('/v1/auth/refresh', methods=['POST'])
    def refresh():
        data = request.get_json()
        if not data or 'refresh_token' not in data:
            return jsonify({"error": {"code": "VALIDATION_ERROR"}}), 422
        
        refresh_token = data['refresh_token']
        if refresh_token not in TOKENS or TOKENS[refresh_token]['type'] != 'refresh':
            return jsonify({"error": {"code": "INVALID_TOKEN"}}), 401
        
        # Generate new access token
        user_id = TOKENS[refresh_token]['user_id']
        new_access_token = f"mock_access_token_{int(time.time())}_{user_id[:8]}"
        
        TOKENS[new_access_token] = {
            "user_id": user_id,
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "type": "access"
        }
        
        return jsonify({
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 3600
        })
    
    @app.route('/v1/auth/password/reset', methods=['POST'])
    def password_reset():
        return '', 202  # Always return accepted for security
    
    return app

def create_policy_service():
    """Create mock policy service"""
    app = Flask('policy-service')
    
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            "status": "healthy", 
            "service": "policy-service",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    
    @app.route('/version', methods=['GET'])
    def version():
        return jsonify({
            "version": "1.0.0",
            "service": "policy-service"
        })
    
    @app.route('/v1/policies', methods=['GET'])
    def list_policies():
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        policies_list = list(POLICIES.values())
        return jsonify({
            "data": policies_list,
            "meta": {
                "page": 1,
                "per_page": 20,
                "total": len(policies_list),
                "total_pages": 1
            }
        })
    
    @app.route('/v1/policies', methods=['POST'])
    def create_policy():
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        data = request.get_json()
        if not data or 'name' not in data or 'type' not in data:
            return jsonify({"error": {"code": "VALIDATION_ERROR"}}), 422
        
        policy_id = str(uuid.uuid4())
        policy = {
            "id": policy_id,
            "name": data['name'],
            "description": data.get('description', ''),
            "type": data['type'],
            "status": "draft",
            "version": 1,
            "rules": data.get('rules', []),
            "created_at": datetime.utcnow().isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "created_by": "test-user",
            "tags": data.get('tags', [])
        }
        
        POLICIES[policy_id] = policy
        
        return jsonify({
            "data": policy,
            "meta": {
                "request_id": str(uuid.uuid4()),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "api_version": "1.0"
            }
        }), 201
    
    @app.route('/v1/policies/<policy_id>', methods=['GET'])
    def get_policy(policy_id):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        if policy_id not in POLICIES:
            return jsonify({"error": {"code": "NOT_FOUND"}}), 404
        
        return jsonify({
            "data": POLICIES[policy_id],
            "meta": {"request_id": str(uuid.uuid4())}
        })
    
    @app.route('/v1/policies/<policy_id>', methods=['DELETE'])
    def delete_policy(policy_id):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        if policy_id not in POLICIES:
            return jsonify({"error": {"code": "NOT_FOUND"}}), 404
        
        del POLICIES[policy_id]
        return '', 204
    
    @app.route('/v1/policies/<policy_id>/activate', methods=['POST'])
    def activate_policy(policy_id):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        if policy_id not in POLICIES:
            return jsonify({"error": {"code": "NOT_FOUND"}}), 404
        
        POLICIES[policy_id]['status'] = 'active'
        return jsonify({"data": POLICIES[policy_id]})
    
    @app.route('/v1/evaluate', methods=['POST'])
    def evaluate():
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"error": {"code": "UNAUTHORIZED"}}), 401
        
        data = request.get_json()
        if not data or 'subject' not in data or 'resource' not in data or 'action' not in data:
            return jsonify({"error": {"code": "VALIDATION_ERROR"}}), 422
        
        # Mock evaluation logic
        subject = data['subject']
        allowed = subject.get('attributes', {}).get('role') in ['admin', 'user']
        
        return jsonify({
            "allowed": allowed,
            "decision": "permit" if allowed else "deny",
            "reasons": ["Role-based access granted" if allowed else "Access denied"],
            "applied_policies": [],
            "evaluation_time_ms": 5.2
        })
    
    @app.route('/v1/templates', methods=['GET'])
    def list_templates():
        return jsonify({
            "data": [
                {
                    "id": str(uuid.uuid4()),
                    "name": "Basic RBAC Template",
                    "category": "security",
                    "variables": []
                }
            ],
            "meta": {"request_id": str(uuid.uuid4())}
        })
    
    @app.route('/v1/audit/logs', methods=['GET'])
    def audit_logs():
        return jsonify({
            "data": [],
            "meta": {
                "page": 1,
                "per_page": 20,
                "total": 0,
                "total_pages": 0
            }
        })
    
    return app

def run_server(app, port, name):
    """Run server in a thread"""
    server = make_server('127.0.0.1', port, app, threaded=True)
    print(f"🚀 {name} mock server starting on http://localhost:{port}")
    
    def signal_handler(sig, frame):
        print(f"\n💀 Shutting down {name} mock server...")
        server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n💀 {name} mock server stopped")

if __name__ == '__main__':
    print("🔧 Starting Mock Services for Integration Testing")
    print("=" * 50)
    
    # Create apps
    auth_app = create_auth_service()
    policy_app = create_policy_service()
    
    # Start servers in threads
    auth_thread = threading.Thread(target=run_server, args=(auth_app, AUTH_PORT, "Auth Service"))
    policy_thread = threading.Thread(target=run_server, args=(policy_app, POLICY_PORT, "Policy Service"))
    
    auth_thread.daemon = True
    policy_thread.daemon = True
    
    auth_thread.start()
    policy_thread.start()
    
    print(f"✅ Auth Service Mock: http://localhost:{AUTH_PORT}")
    print(f"✅ Policy Service Mock: http://localhost:{POLICY_PORT}")
    print("\n📋 Available endpoints:")
    print("  Auth Service:")
    print("    - GET  /health, /version")
    print("    - POST /v1/auth/register, /v1/auth/login, /v1/auth/verify")
    print("    - GET  /v1/auth/sessions")
    print("    - POST /v1/auth/logout, /v1/auth/refresh")
    print("  Policy Service:")
    print("    - GET  /health, /version")
    print("    - GET  /v1/policies, /v1/templates, /v1/audit/logs")
    print("    - POST /v1/policies, /v1/evaluate")
    print("\n🔄 Press Ctrl+C to stop all services")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n💀 Stopping all mock services...")
        sys.exit(0)