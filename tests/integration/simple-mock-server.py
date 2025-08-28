#!/usr/bin/env python3
"""
Simple Mock Server for Integration Testing
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import time
from urllib.parse import urlparse
import uuid
from datetime import datetime

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "status": "healthy",
                "service": "auth-service" if self.server.server_port == 8001 else "policy-service",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/version':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "version": "1.0.0",
                "service": "auth-service" if self.server.server_port == 8001 else "policy-service"
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path.startswith('/v1/auth/sessions'):
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "data": [
                    {
                        "id": str(uuid.uuid4()),
                        "user_agent": self.headers.get('User-Agent', ''),
                        "ip_address": "127.0.0.1",
                        "created_at": datetime.utcnow().isoformat() + "Z",
                        "last_accessed": datetime.utcnow().isoformat() + "Z",
                        "expires_at": datetime.utcnow().isoformat() + "Z"
                    }
                ],
                "meta": {"page": 1, "per_page": 20, "total": 1, "total_pages": 1}
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path.startswith('/v1/policies'):
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "data": [],
                "meta": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0}
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path.startswith('/v1/templates'):
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {"data": [], "meta": {"request_id": str(uuid.uuid4())}}
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path.startswith('/v1/audit/logs'):
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "data": [],
                "meta": {"page": 1, "per_page": 20, "total": 0, "total_pages": 0}
            }
            self.wfile.write(json.dumps(response).encode())
        
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            data = json.loads(post_data.decode('utf-8')) if post_data != b'{}' else {}
        except:
            data = {}
        
        if self.path == '/v1/auth/register':
            if not data.get('username') or not data.get('email') or not data.get('password'):
                self.send_error(422, "Validation Error")
                return
            
            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "data": {
                    "id": str(uuid.uuid4()),
                    "username": data['username'],
                    "email": data['email'],
                    "full_name": data.get('full_name', ''),
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "updated_at": datetime.utcnow().isoformat() + "Z",
                    "email_verified": False,
                    "two_factor_enabled": False
                },
                "meta": {
                    "request_id": str(uuid.uuid4()),
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/v1/auth/login':
            if not data.get('username') or not data.get('password'):
                self.send_error(422, "Validation Error")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            user_id = str(uuid.uuid4())
            response = {
                "access_token": f"mock_access_token_{int(time.time())}",
                "refresh_token": f"mock_refresh_token_{int(time.time())}",
                "token_type": "Bearer",
                "expires_in": 3600,
                "user": {
                    "id": user_id,
                    "username": data['username'],
                    "email": "user@test.com"
                }
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/v1/auth/verify':
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "valid": True,
                "claims": {
                    "sub": str(uuid.uuid4()),
                    "exp": int(time.time() + 3600),
                    "iat": int(time.time()),
                    "jti": str(uuid.uuid4())
                }
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/v1/auth/logout':
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(204)
            self.end_headers()
        
        elif self.path == '/v1/auth/refresh':
            if not data.get('refresh_token'):
                self.send_error(422, "Validation Error")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "access_token": f"mock_new_access_token_{int(time.time())}",
                "token_type": "Bearer",
                "expires_in": 3600
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/v1/auth/password/reset':
            self.send_response(202)
            self.end_headers()
        
        elif self.path == '/v1/policies':
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            policy_id = str(uuid.uuid4())
            response = {
                "data": {
                    "id": policy_id,
                    "name": data.get('name', 'Test Policy'),
                    "type": data.get('type', 'RBAC'),
                    "status": "draft",
                    "version": 1,
                    "rules": data.get('rules', []),
                    "created_at": datetime.utcnow().isoformat() + "Z"
                },
                "meta": {"request_id": str(uuid.uuid4())}
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == '/v1/evaluate':
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self.send_error(401, "Unauthorized")
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "allowed": True,
                "decision": "permit",
                "reasons": ["Mock evaluation"],
                "applied_policies": [],
                "evaluation_time_ms": 5.0
            }
            self.wfile.write(json.dumps(response).encode())
        
        else:
            self.send_error(404, "Not Found")
    
    def do_DELETE(self):
        if self.path.startswith('/v1/policies/'):
            auth_header = self.headers.get('Authorization')
            if not auth_header:
                self.send_error(401, "Unauthorized")
                return
            
            # Extract policy ID from path
            policy_id = self.path.split('/')[-1]
            
            self.send_response(204)
            self.end_headers()
        else:
            self.send_error(404, "Not Found")
    
    def log_message(self, format, *args):
        # Suppress default logging
        pass

def start_server(port):
    server = HTTPServer(('localhost', port), MockHandler)
    print(f"✅ Mock server started on http://localhost:{port}")
    server.serve_forever()

if __name__ == '__main__':
    print("🔧 Starting Simple Mock Services")
    
    # Start auth service (8001) and policy service (8002) in threads
    auth_thread = threading.Thread(target=start_server, args=(8001,))
    policy_thread = threading.Thread(target=start_server, args=(8002,))
    
    auth_thread.daemon = True
    policy_thread.daemon = True
    
    auth_thread.start()
    policy_thread.start()
    
    print("🚀 Auth Service Mock: http://localhost:8001")
    print("🚀 Policy Service Mock: http://localhost:8002")
    print("🔄 Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n💀 Stopping mock services...")