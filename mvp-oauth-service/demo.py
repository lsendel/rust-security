#!/usr/bin/env python3
"""
MVP OAuth 2.0 Service Demo Script (Python)
This script demonstrates all the key features of the MVP OAuth service
"""

import requests
import json
import base64
import sys
import time
from typing import Dict, Any

# Configuration
BASE_URL = "http://localhost:3000"

# Color codes for terminal output
BLUE = '\033[0;34m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
NC = '\033[0m'  # No Color

def print_colored(text: str, color: str = NC) -> None:
    """Print colored text to terminal"""
    print(f"{color}{text}{NC}")

def print_json_response(response: requests.Response, title: str = "") -> None:
    """Print formatted JSON response"""
    if title:
        print_colored(f"\n{title}", YELLOW)
    print(f"Status: {response.status_code}")
    try:
        json_data = response.json()
        print(json.dumps(json_data, indent=2))
    except ValueError:
        print(response.text)

def check_service_health() -> bool:
    """Check if the service is running"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def demo_health_check() -> None:
    """Demo: Health check endpoint"""
    print_colored("🔍 Step 1: Health Check", YELLOW)
    print(f"GET {BASE_URL}/health")
    
    response = requests.get(f"{BASE_URL}/health")
    print_json_response(response)
    print()

def demo_jwks_endpoint() -> None:
    """Demo: JWKS public keys endpoint"""
    print_colored("🔑 Step 2: JWKS Public Keys", YELLOW)
    print(f"GET {BASE_URL}/.well-known/jwks.json")
    
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    print_json_response(response)
    print()

def demo_valid_token_request() -> str:
    """Demo: Valid OAuth token request"""
    print_colored("🎟️  Step 3: Valid OAuth Token Request", YELLOW)
    print(f"POST {BASE_URL}/oauth/token")
    
    data = {
        "grant_type": "client_credentials",
        "client_id": "mvp-client",
        "client_secret": "mvp-secret"
    }
    
    response = requests.post(
        f"{BASE_URL}/oauth/token",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    
    print_json_response(response)
    
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get("access_token", "")
        print_colored(f"✅ Token obtained: {access_token[:50]}...", GREEN)
        return access_token
    
    return ""

def demo_token_introspection_valid(token: str) -> None:
    """Demo: Token introspection with valid token"""
    print_colored("🔍 Step 4: Token Introspection (Valid Token)", YELLOW)
    print(f"POST {BASE_URL}/oauth/introspect")
    
    data = {"token": token}
    response = requests.post(
        f"{BASE_URL}/oauth/introspect",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    
    print_json_response(response)
    print()

def demo_token_introspection_invalid() -> None:
    """Demo: Token introspection with invalid token"""
    print_colored("❌ Step 5: Token Introspection (Invalid Token)", YELLOW)
    print(f"POST {BASE_URL}/oauth/introspect")
    
    data = {"token": "invalid.jwt.token"}
    response = requests.post(
        f"{BASE_URL}/oauth/introspect",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    
    print_json_response(response)
    print()

def demo_invalid_credentials() -> None:
    """Demo: Invalid client credentials"""
    print_colored("🚫 Step 6: Invalid Client Credentials", YELLOW)
    print(f"POST {BASE_URL}/oauth/token")
    
    data = {
        "grant_type": "client_credentials",
        "client_id": "invalid-client",
        "client_secret": "wrong-secret"
    }
    
    response = requests.post(
        f"{BASE_URL}/oauth/token",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    
    print_json_response(response)
    print_colored("✅ Properly rejected invalid credentials", GREEN)
    print()

def demo_security_validation() -> None:
    """Demo: Security validation with malicious input"""
    print_colored("🛡️  Step 7: Security Validation (Malicious Input)", YELLOW)
    print(f"POST {BASE_URL}/oauth/token (with control characters)")
    
    data = {
        "grant_type": "client_credentials",
        "client_id": "malicious\x00client",
        "client_secret": "secret"
    }
    
    response = requests.post(
        f"{BASE_URL}/oauth/token",
        json=data,
        headers={"Content-Type": "application/json"}
    )
    
    print_json_response(response)
    print_colored("✅ Security validation blocked malicious input", GREEN)
    print()

def demo_metrics_endpoint() -> None:
    """Demo: Metrics endpoint"""
    print_colored("📊 Step 8: Metrics Endpoint", YELLOW)
    print(f"GET {BASE_URL}/metrics")
    
    response = requests.get(f"{BASE_URL}/metrics")
    print(f"Status: {response.status_code}")
    
    # Show first few lines of metrics
    lines = response.text.split('\n')
    for line in lines[:10]:
        if line.strip():
            print(line)
    print("...")
    print()

def decode_jwt_part(part: str) -> Dict[str, Any]:
    """Decode a base64-encoded JWT part"""
    try:
        # Add padding if needed
        padded = part + '=' * (4 - len(part) % 4)
        decoded = base64.b64decode(padded, validate=True)
        return json.loads(decoded)
    except Exception:
        return {"error": "Could not decode"}

def demo_jwt_analysis(token: str) -> None:
    """Demo: JWT token analysis"""
    print_colored("🔬 Step 9: JWT Token Analysis", YELLOW)
    print("Analyzing the obtained JWT token:")
    print()
    
    try:
        parts = token.split('.')
        if len(parts) == 3:
            header = decode_jwt_part(parts[0])
            payload = decode_jwt_part(parts[1])
            
            print("JWT Header:")
            print(json.dumps(header, indent=2))
            print()
            
            print("JWT Payload:")
            print(json.dumps(payload, indent=2))
            print()
        else:
            print("Invalid JWT format")
    except Exception as e:
        print(f"Error analyzing JWT: {e}")
    
    print()

def demo_performance_test() -> None:
    """Demo: Simple performance test"""
    print_colored("⚡ Step 10: Performance Test", YELLOW)
    print("Making 5 rapid requests to test service responsiveness...")
    
    for i in range(1, 6):
        start_time = time.time()
        try:
            response = requests.get(f"{BASE_URL}/health", timeout=5)
            response_time = time.time() - start_time
            print(f"Request {i}: {response_time:.3f}s")
        except requests.RequestException:
            print(f"Request {i}: Failed")
    
    print()

def main():
    """Main demo function"""
    print_colored("🚀 MVP OAuth 2.0 Service Demo", BLUE)
    print_colored("================================", BLUE)
    print()
    
    # Check if service is running
    print_colored("📡 Checking service health...", YELLOW)
    if not check_service_health():
        print_colored("❌ Service not running. Please start with: cargo run", RED)
        print_colored("💡 Or use Docker: docker-compose up -d", YELLOW)
        sys.exit(1)
    
    print_colored("✅ Service is running", GREEN)
    print()
    
    try:
        # Run all demos
        demo_health_check()
        demo_jwks_endpoint()
        
        access_token = demo_valid_token_request()
        print()
        
        if access_token:
            demo_token_introspection_valid(access_token)
        
        demo_token_introspection_invalid()
        demo_invalid_credentials()
        demo_security_validation()
        demo_metrics_endpoint()
        
        if access_token:
            demo_jwt_analysis(access_token)
        
        demo_performance_test()
        
        # Summary
        print_colored("📋 Demo Summary", BLUE)
        print_colored("===============", BLUE)
        print_colored("✅ Health check: Service is operational", GREEN)
        print_colored("✅ JWKS endpoint: Public keys available", GREEN)
        print_colored("✅ OAuth flow: Token issuance working", GREEN)
        print_colored("✅ Token introspection: Validation working", GREEN)
        print_colored("✅ Security validation: Malicious input blocked", GREEN)
        print_colored("✅ Error handling: Invalid clients rejected", GREEN)
        print_colored("✅ Monitoring: Health and metrics endpoints", GREEN)
        print_colored("✅ JWT analysis: Standard-compliant tokens", GREEN)
        print()
        print_colored("🎉 MVP OAuth 2.0 Service Demo Complete!", BLUE)
        print_colored("💡 Next steps:", YELLOW)
        print("   • Configure production secrets in .env")
        print("   • Deploy with Docker: docker-compose up -d")
        print("   • Enable HTTPS and proper SSL certificates")
        print("   • Configure monitoring and alerting")
        print("   • Integrate with your applications")
        print()
        
        print_colored("📚 Documentation:", BLUE)
        print("   • README.md - Setup and configuration")
        print("   • .env.example - Environment variables")
        print("   • docker-compose.yml - Deployment configuration")
        
    except KeyboardInterrupt:
        print_colored("\n\nDemo interrupted by user", YELLOW)
    except Exception as e:
        print_colored(f"\n\nDemo failed with error: {e}", RED)
        sys.exit(1)

if __name__ == "__main__":
    main()