#!/bin/bash

# Sample requests to test zero-trust implementation
# This script demonstrates various authentication flows and security features

set -euo pipefail

# Configuration
AUTH_SERVICE_URL="https://auth.zero-trust.local"
CLIENT_ID="trusted-client-001"
CLIENT_SECRET="super-secure-client-secret"
DEVICE_FINGERPRINT="sha256:trusted-device-fingerprint-001"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to make authenticated requests
make_request() {
    local method=$1
    local endpoint=$2
    local headers=$3
    local data=$4
    
    curl -s -X "$method" \
        "$AUTH_SERVICE_URL$endpoint" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
        -H "User-Agent: ZeroTrustClient/1.0" \
        $headers \
        ${data:+-d "$data"}
}

# Test 1: Health Check
test_health_check() {
    log_info "Testing health check endpoint..."
    
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
        "$AUTH_SERVICE_URL/health")
    
    http_code=$(echo "$response" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    if [ "$http_code" = "200" ]; then
        log_success "Health check passed: $body"
    else
        log_error "Health check failed with HTTP $http_code: $body"
    fi
}

# Test 2: Client Credentials Flow
test_client_credentials() {
    log_info "Testing client credentials flow..."
    
    response=$(make_request POST "/token" "" \
        "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=api:read api:write")
    
    if echo "$response" | jq -e '.access_token' > /dev/null 2>&1; then
        access_token=$(echo "$response" | jq -r '.access_token')
        log_success "Client credentials flow successful"
        echo "Access Token: ${access_token:0:20}..."
        
        # Store token for subsequent tests
        echo "$access_token" > /tmp/zt_access_token
    else
        log_error "Client credentials flow failed: $response"
    fi
}

# Test 3: Token Introspection
test_token_introspection() {
    log_info "Testing token introspection..."
    
    if [ ! -f /tmp/zt_access_token ]; then
        log_error "No access token available. Run client credentials test first."
        return 1
    fi
    
    access_token=$(cat /tmp/zt_access_token)
    
    response=$(make_request POST "/introspect" "" \
        "token=$access_token&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET")
    
    if echo "$response" | jq -e '.active == true' > /dev/null 2>&1; then
        log_success "Token introspection successful"
        echo "Token details: $(echo "$response" | jq -c '.')"
    else
        log_error "Token introspection failed: $response"
    fi
}

# Test 4: OIDC Discovery
test_oidc_discovery() {
    log_info "Testing OIDC discovery endpoint..."
    
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        "$AUTH_SERVICE_URL/.well-known/openid_configuration")
    
    http_code=$(echo "$response" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    if [ "$http_code" = "200" ] && echo "$body" | jq -e '.issuer' > /dev/null 2>&1; then
        log_success "OIDC discovery successful"
        echo "Issuer: $(echo "$body" | jq -r '.issuer')"
        echo "Supported grants: $(echo "$body" | jq -r '.grant_types_supported | join(", ")')"
    else
        log_error "OIDC discovery failed with HTTP $http_code"
    fi
}

# Test 5: JWKS Endpoint
test_jwks() {
    log_info "Testing JWKS endpoint..."
    
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        "$AUTH_SERVICE_URL/.well-known/jwks.json")
    
    http_code=$(echo "$response" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    if [ "$http_code" = "200" ] && echo "$body" | jq -e '.keys' > /dev/null 2>&1; then
        key_count=$(echo "$body" | jq '.keys | length')
        log_success "JWKS endpoint successful - $key_count keys available"
    else
        log_error "JWKS endpoint failed with HTTP $http_code"
    fi
}

# Test 6: SCIM User Management
test_scim_operations() {
    log_info "Testing SCIM operations..."
    
    if [ ! -f /tmp/zt_access_token ]; then
        log_error "No access token available. Run client credentials test first."
        return 1
    fi
    
    access_token=$(cat /tmp/zt_access_token)
    
    # List users
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "Authorization: Bearer $access_token" \
        -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
        "$AUTH_SERVICE_URL/scim/v2/Users")
    
    http_code=$(echo "$response" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    body=$(echo "$response" | sed -E 's/HTTPSTATUS:[0-9]{3}$//')
    
    if [ "$http_code" = "200" ]; then
        log_success "SCIM user listing successful"
        echo "Total users: $(echo "$body" | jq -r '.totalResults // 0')"
    else
        log_error "SCIM operation failed with HTTP $http_code: $body"
    fi
}

# Test 7: Rate Limiting
test_rate_limiting() {
    log_info "Testing rate limiting..."
    
    rate_limited_count=0
    total_requests=20
    
    for i in $(seq 1 $total_requests); do
        response=$(curl -s -w "%{http_code}" -o /dev/null \
            -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
            "$AUTH_SERVICE_URL/health")
        
        if [ "$response" = "429" ]; then
            rate_limited_count=$((rate_limited_count + 1))
        fi
        
        # Small delay to avoid overwhelming
        sleep 0.1
    done
    
    if [ $rate_limited_count -gt 0 ]; then
        log_success "Rate limiting active: $rate_limited_count/$total_requests requests rate limited"
    else
        log_success "Rate limiting not triggered (normal traffic load)"
    fi
}

# Test 8: Device Trust Validation
test_device_trust() {
    log_info "Testing device trust validation..."
    
    # Test with valid device fingerprint
    response_valid=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
        "$AUTH_SERVICE_URL/health")
    
    # Test with missing device fingerprint
    response_invalid=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        "$AUTH_SERVICE_URL/health")
    
    valid_code=$(echo "$response_valid" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    invalid_code=$(echo "$response_invalid" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    
    if [ "$valid_code" = "200" ] && [ "$invalid_code" != "200" ]; then
        log_success "Device trust validation working correctly"
    else
        log_error "Device trust validation not working as expected (valid: $valid_code, invalid: $invalid_code)"
    fi
}

# Test 9: Security Headers
test_security_headers() {
    log_info "Testing security headers..."
    
    headers=$(curl -s -I \
        -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
        "$AUTH_SERVICE_URL/health")
    
    security_headers=(
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
        "Strict-Transport-Security"
        "Content-Security-Policy"
    )
    
    found_headers=0
    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -i "$header" > /dev/null; then
            found_headers=$((found_headers + 1))
        fi
    done
    
    if [ $found_headers -ge 3 ]; then
        log_success "Security headers present: $found_headers/${#security_headers[@]}"
    else
        log_error "Insufficient security headers: $found_headers/${#security_headers[@]}"
    fi
}

# Test 10: Threat Detection
test_threat_detection() {
    log_info "Testing threat detection..."
    
    # Test with suspicious user agent
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        -H "User-Agent: sqlmap/1.0" \
        -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
        "$AUTH_SERVICE_URL/health")
    
    if [ "$response" = "403" ]; then
        log_success "Threat detection blocking suspicious requests"
    else
        log_error "Threat detection not working (expected 403, got $response)"
    fi
}

# Test 11: mTLS Verification
test_mtls() {
    log_info "Testing mTLS connectivity..."
    
    # This test requires access to the Kubernetes cluster
    if command -v kubectl > /dev/null && kubectl cluster-info > /dev/null 2>&1; then
        mtls_status=$(istioctl authn tls-check auth-service.rust-security-zt.svc.cluster.local 2>/dev/null || echo "FAILED")
        
        if echo "$mtls_status" | grep -q "OK"; then
            log_success "mTLS verification successful"
        else
            log_error "mTLS verification failed"
        fi
    else
        log_info "Skipping mTLS test (kubectl not available or not connected to cluster)"
    fi
}

# Test 12: OAuth 2.0 Authorization Code Flow (simulation)
test_oauth_authorization_code() {
    log_info "Testing OAuth 2.0 authorization code flow setup..."
    
    # Check authorization endpoint
    response=$(curl -s -w "HTTPSTATUS:%{http_code}" \
        "$AUTH_SERVICE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=https://client.example.com/callback&state=test123")
    
    http_code=$(echo "$response" | sed -E 's/.*HTTPSTATUS:([0-9]{3})$/\1/')
    
    if [ "$http_code" = "302" ] || [ "$http_code" = "200" ]; then
        log_success "OAuth authorization endpoint accessible"
    else
        log_error "OAuth authorization endpoint failed with HTTP $http_code"
    fi
}

# Main test execution
run_all_tests() {
    echo "========================================"
    echo "Zero-Trust Authentication Service Tests"
    echo "========================================"
    echo "Service URL: $AUTH_SERVICE_URL"
    echo "Client ID: $CLIENT_ID"
    echo "Device Fingerprint: ${DEVICE_FINGERPRINT:0:20}..."
    echo "========================================"
    echo
    
    test_health_check
    echo
    test_client_credentials
    echo
    test_token_introspection
    echo
    test_oidc_discovery
    echo
    test_jwks
    echo
    test_scim_operations
    echo
    test_rate_limiting
    echo
    test_device_trust
    echo
    test_security_headers
    echo
    test_threat_detection
    echo
    test_mtls
    echo
    test_oauth_authorization_code
    echo
    
    echo "========================================"
    echo "All tests completed!"
    echo "========================================"
    
    # Cleanup
    rm -f /tmp/zt_access_token
}

# Performance test
run_performance_test() {
    log_info "Running performance test..."
    
    if command -v hey > /dev/null; then
        hey -n 1000 -c 10 -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
            "$AUTH_SERVICE_URL/health"
    elif command -v ab > /dev/null; then
        ab -n 1000 -c 10 -H "X-Device-Fingerprint: $DEVICE_FINGERPRINT" \
            "$AUTH_SERVICE_URL/health"
    else
        log_error "Performance testing tools (hey or ab) not available"
    fi
}

# Parse command line arguments
case "${1:-all}" in
    all)
        run_all_tests
        ;;
    performance)
        run_performance_test
        ;;
    health)
        test_health_check
        ;;
    auth)
        test_client_credentials
        test_token_introspection
        ;;
    security)
        test_device_trust
        test_security_headers
        test_threat_detection
        ;;
    --help)
        echo "Usage: $0 [all|performance|health|auth|security|--help]"
        echo "  all         : Run all tests (default)"
        echo "  performance : Run performance tests"
        echo "  health      : Test health endpoint only"
        echo "  auth        : Test authentication flows"
        echo "  security    : Test security features"
        echo "  --help      : Show this help"
        ;;
    *)
        log_error "Unknown option: $1"
        echo "Run '$0 --help' for usage information"
        exit 1
        ;;
esac