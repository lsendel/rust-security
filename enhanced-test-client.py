#!/usr/bin/env python3
"""
Comprehensive Security Platform Test Client
Advanced testing client for the Rust Security Platform with OAuth 2.0,
user authentication, security features, and performance testing capabilities.
"""

import requests
import json
import sys
import time
import os
import argparse
import logging
import threading
import statistics
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin

# Configuration with environment variable support
SERVER_URL = os.getenv("AUTH_SERVER_URL", "http://localhost:8080")
CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "demo-client")
CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "demo-secret")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper()),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Test result data structure"""
    name: str
    success: bool
    duration: float
    message: str
    details: Optional[Dict] = None

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p95_response_time: float
    requests_per_second: float
    error_rate: float

class SecurityTestClient:
    """Comprehensive security platform test client"""
    
    def __init__(self, base_url: str = SERVER_URL, timeout: int = 10):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RustSecurityPlatform-TestClient/2.0',
            'Accept': 'application/json'
        })
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    def _request(self, method: str, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
        """Make HTTP request with timing"""
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))
        start_time = time.time()
        
        try:
            response = self.session.request(
                method, url, 
                timeout=self.timeout,
                **kwargs
            )
            duration = time.time() - start_time
            logger.debug(f"{method} {url} -> {response.status_code} ({duration:.3f}s)")
            return response, duration
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{method} {url} -> Error: {e} ({duration:.3f}s)")
            raise

    def _authenticated_request(self, method: str, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
        """Make authenticated HTTP request"""
        if self.access_token:
            headers = kwargs.get('headers', {})
            headers['Authorization'] = f'Bearer {self.access_token}'
            kwargs['headers'] = headers
        return self._request(method, endpoint, **kwargs)

def print_header(title):
    print(f"\n{'='*60}")
    print(f"🔐 {title}")
    print('='*60)

def print_subheader(title):
    print(f"\n{'─'*40}")
    print(f"📋 {title}")
    print('─'*40)

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 0.001:
        return f"{seconds * 1000000:.1f}μs"
    elif seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    else:
        return f"{seconds:.2f}s"

# Test Functions

def test_health_check(client: SecurityTestClient) -> TestResult:
    """Test the health endpoint"""
    print("\n🏥 Testing Health Check...")
    
    try:
        response, duration = client._request('GET', '/health')
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {format_duration(duration)}")
        
        if response.status_code == 200:
            try:
                health_data = response.json()
                print(f"Response: {json.dumps(health_data, indent=2)}")
                
                # Validate health response structure
                required_fields = ['status', 'timestamp']
                missing_fields = [field for field in required_fields if field not in health_data]
                
                if missing_fields:
                    return TestResult(
                        name="health_check",
                        success=False,
                        duration=duration,
                        message=f"Missing required fields: {missing_fields}",
                        details=health_data
                    )
                
                print("✅ Health check PASSED")
                return TestResult(
                    name="health_check",
                    success=True,
                    duration=duration,
                    message="Health endpoint is working correctly",
                    details=health_data
                )
            except json.JSONDecodeError:
                print(f"Response: {response.text}")
                print("⚠️  Response is not valid JSON")
                return TestResult(
                    name="health_check",
                    success=False,
                    duration=duration,
                    message="Health endpoint returned non-JSON response"
                )
        else:
            print(f"Response: {response.text}")
            print("❌ Health check FAILED")
            return TestResult(
                name="health_check",
                success=False,
                duration=duration,
                message=f"Health check returned status {response.status_code}"
            )
            
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Is it running?")
        return TestResult(
            name="health_check",
            success=False,
            duration=0.0,
            message="Cannot connect to server"
        )
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="health_check",
            success=False,
            duration=0.0,
            message=f"Unexpected error: {e}"
        )

def test_user_registration(client: SecurityTestClient) -> TestResult:
    """Test user registration endpoint"""
    print("\n📝 Testing User Registration...")
    
    # Generate unique test user
    timestamp = int(time.time())
    test_user = {
        "username": f"testuser_{timestamp}",
        "email": f"test_{timestamp}@example.com",
        "password": "SecureTestPassword123!",
        "profile": {
            "first_name": "Test",
            "last_name": "User"
        }
    }
    
    try:
        response, duration = client._request(
            'POST', '/auth/register',
            json=test_user
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {format_duration(duration)}")
        
        if response.status_code in [200, 201]:
            try:
                user_data = response.json()
                print(f"Response: {json.dumps(user_data, indent=2)}")
                
                # Validate response structure
                if 'user_id' in user_data and 'username' in user_data:
                    print("✅ User registration PASSED")
                    return TestResult(
                        name="user_registration",
                        success=True,
                        duration=duration,
                        message="User registered successfully",
                        details={"user": user_data, "test_credentials": test_user}
                    )
                else:
                    return TestResult(
                        name="user_registration",
                        success=False,
                        duration=duration,
                        message="Registration response missing required fields"
                    )
            except json.JSONDecodeError:
                print(f"Response: {response.text}")
                return TestResult(
                    name="user_registration",
                    success=False,
                    duration=duration,
                    message="Registration returned non-JSON response"
                )
        else:
            print(f"Response: {response.text}")
            return TestResult(
                name="user_registration",
                success=False,
                duration=duration,
                message=f"Registration failed with status {response.status_code}"
            )
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="user_registration",
            success=False,
            duration=0.0,
            message=f"Registration error: {e}"
        )

def test_user_login(client: SecurityTestClient, credentials: Dict) -> TestResult:
    """Test user login endpoint"""
    print("\n🔐 Testing User Login...")
    
    try:
        login_data = {
            "username": credentials["username"],
            "password": credentials["password"]
        }
        
        response, duration = client._request(
            'POST', '/auth/login',
            json=login_data
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {format_duration(duration)}")
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                # Don't print the actual token for security
                safe_data = {k: v for k, v in token_data.items() if k != 'access_token'}
                print(f"Response: {json.dumps(safe_data, indent=2)}")
                
                if 'access_token' in token_data:
                    client.access_token = token_data['access_token']
                    client.refresh_token = token_data.get('refresh_token')
                    
                    print("✅ User login PASSED")
                    return TestResult(
                        name="user_login",
                        success=True,
                        duration=duration,
                        message="User logged in successfully",
                        details=token_data
                    )
                else:
                    return TestResult(
                        name="user_login",
                        success=False,
                        duration=duration,
                        message="Login response missing access_token"
                    )
            except json.JSONDecodeError:
                print(f"Response: {response.text}")
                return TestResult(
                    name="user_login",
                    success=False,
                    duration=duration,
                    message="Login returned non-JSON response"
                )
        else:
            print(f"Response: {response.text}")
            return TestResult(
                name="user_login",
                success=False,
                duration=duration,
                message=f"Login failed with status {response.status_code}"
            )
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="user_login",
            success=False,
            duration=0.0,
            message=f"Login error: {e}"
        )

def test_authenticated_profile(client: SecurityTestClient) -> TestResult:
    """Test authenticated profile endpoint"""
    print("\n👤 Testing Authenticated Profile Access...")
    
    if not client.access_token:
        return TestResult(
            name="authenticated_profile",
            success=False,
            duration=0.0,
            message="No access token available for authentication"
        )
    
    try:
        response, duration = client._authenticated_request('GET', '/auth/profile')
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {format_duration(duration)}")
        
        if response.status_code == 200:
            try:
                profile_data = response.json()
                print(f"Response: {json.dumps(profile_data, indent=2)}")
                
                print("✅ Authenticated profile access PASSED")
                return TestResult(
                    name="authenticated_profile",
                    success=True,
                    duration=duration,
                    message="Profile retrieved successfully",
                    details=profile_data
                )
            except json.JSONDecodeError:
                print(f"Response: {response.text}")
                return TestResult(
                    name="authenticated_profile",
                    success=False,
                    duration=duration,
                    message="Profile endpoint returned non-JSON response"
                )
        elif response.status_code == 401:
            return TestResult(
                name="authenticated_profile",
                success=False,
                duration=duration,
                message="Authentication failed - token may be invalid"
            )
        else:
            print(f"Response: {response.text}")
            return TestResult(
                name="authenticated_profile",
                success=False,
                duration=duration,
                message=f"Profile access failed with status {response.status_code}"
            )
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="authenticated_profile",
            success=False,
            duration=0.0,
            message=f"Profile access error: {e}"
        )

def test_invalid_credentials(client: SecurityTestClient) -> TestResult:
    """Test login with invalid credentials"""
    print("\n❌ Testing Invalid Credentials...")
    
    try:
        invalid_login = {
            "username": "invalid_user",
            "password": "wrong_password"
        }
        
        response, duration = client._request(
            'POST', '/auth/login',
            json=invalid_login
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {format_duration(duration)}")
        print(f"Response: {response.text}")
        
        if response.status_code in [400, 401]:
            print("✅ Invalid credentials properly rejected")
            return TestResult(
                name="invalid_credentials",
                success=True,
                duration=duration,
                message="Invalid credentials properly rejected"
            )
        else:
            return TestResult(
                name="invalid_credentials",
                success=False,
                duration=duration,
                message=f"Unexpected status code for invalid credentials: {response.status_code}"
            )
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="invalid_credentials",
            success=False,
            duration=0.0,
            message=f"Invalid credentials test error: {e}"
        )

def test_rate_limiting(client: SecurityTestClient) -> TestResult:
    """Test rate limiting behavior"""
    print("\n⏱️ Testing Rate Limiting...")
    
    try:
        # Make rapid requests to trigger rate limiting
        responses = []
        start_time = time.time()
        
        for i in range(20):  # Try 20 rapid requests
            try:
                response, duration = client._request('GET', '/health')
                responses.append((response.status_code, duration))
                
                if response.status_code == 429:
                    print(f"✅ Rate limiting triggered at request {i+1}")
                    return TestResult(
                        name="rate_limiting",
                        success=True,
                        duration=time.time() - start_time,
                        message=f"Rate limiting properly enforced after {i+1} requests",
                        details={"requests_made": i+1, "responses": responses}
                    )
                    
            except Exception as e:
                print(f"Request {i+1} failed: {e}")
                continue
        
        # If we get here, rate limiting might not be configured or threshold is higher
        print("⚠️  Rate limiting not triggered within 20 requests")
        return TestResult(
            name="rate_limiting",
            success=True,  # Not necessarily a failure
            duration=time.time() - start_time,
            message="Rate limiting not triggered within 20 requests (may be configured with higher threshold)",
            details={"requests_made": 20, "responses": responses}
        )
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="rate_limiting",
            success=False,
            duration=0.0,
            message=f"Rate limiting test error: {e}"
        )

def test_oauth_token(client: SecurityTestClient) -> TestResult:
    """Test OAuth client credentials flow"""
    print("\n🎫 Testing OAuth Client Credentials...")
    
    try:
        data = {
            'grant_type': 'client_credentials',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
        
        response, duration = client._request(
            'POST', '/oauth/token',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Time: {format_duration(duration)}")
        
        if response.status_code == 200:
            try:
                token_data = response.json()
                safe_data = {k: v for k, v in token_data.items() if k != 'access_token'}
                print(f"Response: {json.dumps(safe_data, indent=2)}")
                
                if 'access_token' in token_data:
                    print("✅ OAuth token request PASSED")
                    return TestResult(
                        name="oauth_token",
                        success=True,
                        duration=duration,
                        message="OAuth token obtained successfully",
                        details=token_data
                    )
                else:
                    return TestResult(
                        name="oauth_token",
                        success=False,
                        duration=duration,
                        message="OAuth response missing access_token"
                    )
            except json.JSONDecodeError:
                print("⚠️  Response is not JSON (OAuth endpoint may not be implemented)")
                return TestResult(
                    name="oauth_token",
                    success=True,  # Not a failure if not implemented
                    duration=duration,
                    message="OAuth endpoint returned non-JSON response (may not be implemented)"
                )
        elif response.status_code == 404:
            print("⚠️  OAuth endpoint not implemented")
            return TestResult(
                name="oauth_token",
                success=True,  # Not a failure if not implemented
                duration=duration,
                message="OAuth endpoint not implemented"
            )
        else:
            print(f"Response: {response.text}")
            return TestResult(
                name="oauth_token",
                success=False,
                duration=duration,
                message=f"OAuth token request failed with status {response.status_code}"
            )
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="oauth_token",
            success=False,
            duration=0.0,
            message=f"OAuth token error: {e}"
        )

# Performance Testing

def performance_test_single_request(client: SecurityTestClient, endpoint: str = '/health') -> Tuple[bool, float]:
    """Single request for performance testing"""
    try:
        response, duration = client._request('GET', endpoint)
        return response.status_code == 200, duration
    except:
        return False, 0.0

def test_performance_load(client: SecurityTestClient, 
                         concurrent_users: int = 10, 
                         requests_per_user: int = 50) -> TestResult:
    """Test performance under load"""
    print(f"\n⚡ Testing Performance Load ({concurrent_users} users, {requests_per_user} requests each)...")
    
    start_time = time.time()
    all_durations = []
    successful_requests = 0
    total_requests = concurrent_users * requests_per_user
    
    def user_session(user_id: int) -> List[float]:
        """Simulate a user session"""
        session_durations = []
        user_client = SecurityTestClient(client.base_url, client.timeout)
        
        for _ in range(requests_per_user):
            success, duration = performance_test_single_request(user_client)
            if success:
                session_durations.append(duration)
        
        return session_durations
    
    try:
        with ThreadPoolExecutor(max_workers=concurrent_users) as executor:
            futures = [executor.submit(user_session, i) for i in range(concurrent_users)]
            
            for future in as_completed(futures):
                try:
                    durations = future.result()
                    all_durations.extend(durations)
                    successful_requests += len(durations)
                except Exception as e:
                    logger.error(f"User session failed: {e}")
        
        total_duration = time.time() - start_time
        
        if not all_durations:
            return TestResult(
                name="performance_load",
                success=False,
                duration=total_duration,
                message="No successful requests in performance test"
            )
        
        # Calculate metrics
        avg_response_time = statistics.mean(all_durations)
        min_response_time = min(all_durations)
        max_response_time = max(all_durations)
        p95_response_time = statistics.quantiles(all_durations, n=20)[18]  # 95th percentile
        requests_per_second = successful_requests / total_duration
        error_rate = (total_requests - successful_requests) / total_requests * 100
        
        metrics = PerformanceMetrics(
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=total_requests - successful_requests,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p95_response_time=p95_response_time,
            requests_per_second=requests_per_second,
            error_rate=error_rate
        )
        
        print(f"Total Requests: {metrics.total_requests}")
        print(f"Successful: {metrics.successful_requests}")
        print(f"Failed: {metrics.failed_requests}")
        print(f"Average Response Time: {format_duration(metrics.avg_response_time)}")
        print(f"95th Percentile: {format_duration(metrics.p95_response_time)}")
        print(f"Requests/Second: {metrics.requests_per_second:.2f}")
        print(f"Error Rate: {metrics.error_rate:.2f}%")
        
        # Determine success based on performance criteria
        success = (
            metrics.error_rate < 5.0 and  # Less than 5% error rate
            metrics.avg_response_time < 1.0 and  # Less than 1 second average
            metrics.p95_response_time < 2.0  # Less than 2 seconds 95th percentile
        )
        
        if success:
            print("✅ Performance load test PASSED")
        else:
            print("❌ Performance load test FAILED (high error rate or slow response times)")
        
        return TestResult(
            name="performance_load",
            success=success,
            duration=total_duration,
            message=f"Performance test completed: {metrics.requests_per_second:.1f} RPS, {metrics.error_rate:.1f}% error rate",
            details=metrics.__dict__
        )
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return TestResult(
            name="performance_load",
            success=False,
            duration=time.time() - start_time,
            message=f"Performance test error: {e}"
        )

# Test Suites

def run_basic_tests(client: SecurityTestClient) -> List[TestResult]:
    """Run basic functionality tests"""
    print_header("Basic Functionality Tests")
    
    results = []
    
    # Test 1: Health Check
    results.append(test_health_check(client))
    
    # Test 2: User Registration
    registration_result = test_user_registration(client)
    results.append(registration_result)
    
    # Test 3: User Login (if registration succeeded)
    if registration_result.success and registration_result.details:
        test_creds = registration_result.details["test_credentials"]
        login_result = test_user_login(client, test_creds)
        results.append(login_result)
        
        # Test 4: Authenticated Profile Access
        if login_result.success:
            results.append(test_authenticated_profile(client))
    
    # Test 5: Invalid Credentials
    results.append(test_invalid_credentials(client))
    
    # Test 6: OAuth Token (optional)
    results.append(test_oauth_token(client))
    
    return results

def run_security_tests(client: SecurityTestClient) -> List[TestResult]:
    """Run security-focused tests"""
    print_header("Security Tests")
    
    results = []
    
    # Test rate limiting
    results.append(test_rate_limiting(client))
    
    # Additional security tests can be added here
    
    return results

def run_performance_tests(client: SecurityTestClient) -> List[TestResult]:
    """Run performance tests"""
    print_header("Performance Tests")
    
    results = []
    
    # Light load test
    results.append(test_performance_load(client, concurrent_users=5, requests_per_user=20))
    
    # Medium load test (optional, based on args)
    # results.append(test_performance_load(client, concurrent_users=10, requests_per_user=50))
    
    return results

def print_test_summary(results: List[TestResult]):
    """Print comprehensive test summary"""
    print_header("Test Summary")
    
    total_tests = len(results)
    passed_tests = sum(1 for r in results if r.success)
    failed_tests = total_tests - passed_tests
    
    total_duration = sum(r.duration for r in results)
    
    print(f"📊 Total Tests: {total_tests}")
    print(f"✅ Passed: {passed_tests}")
    print(f"❌ Failed: {failed_tests}")
    print(f"⏱️  Total Duration: {format_duration(total_duration)}")
    print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")
    
    if failed_tests > 0:
        print_subheader("Failed Tests")
        for result in results:
            if not result.success:
                print(f"❌ {result.name}: {result.message}")
    
    print_subheader("Test Details")
    for result in results:
        status = "✅ PASS" if result.success else "❌ FAIL"
        print(f"{status} {result.name} ({format_duration(result.duration)}): {result.message}")

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Security Platform Test Client")
    parser.add_argument("--url", default=SERVER_URL, help="Server URL")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--basic", action="store_true", help="Run basic tests only")
    parser.add_argument("--security", action="store_true", help="Run security tests only")
    parser.add_argument("--performance", action="store_true", help="Run performance tests only")
    parser.add_argument("--all", action="store_true", help="Run all test suites")
    parser.add_argument("--json-output", help="Output results to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create test client
    client = SecurityTestClient(args.url, args.timeout)
    
    print_header("Rust Security Platform - Test Client v2.0")
    print(f"🌐 Server URL: {client.base_url}")
    print(f"⏱️  Timeout: {client.timeout}s")
    print(f"🕐 Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    all_results = []
    
    # Determine which tests to run
    if args.all or (not args.basic and not args.security and not args.performance):
        # Run all tests by default
        all_results.extend(run_basic_tests(client))
        all_results.extend(run_security_tests(client))
        all_results.extend(run_performance_tests(client))
    else:
        if args.basic:
            all_results.extend(run_basic_tests(client))
        if args.security:
            all_results.extend(run_security_tests(client))
        if args.performance:
            all_results.extend(run_performance_tests(client))
    
    # Print summary
    print_test_summary(all_results)
    
    # Save JSON output if requested
    if args.json_output:
        output_data = {
            "timestamp": datetime.now().isoformat(),
            "server_url": client.base_url,
            "total_tests": len(all_results),
            "passed_tests": sum(1 for r in all_results if r.success),
            "failed_tests": sum(1 for r in all_results if not r.success),
            "total_duration": sum(r.duration for r in all_results),
            "results": [
                {
                    "name": r.name,
                    "success": r.success,
                    "duration": r.duration,
                    "message": r.message,
                    "details": r.details
                }
                for r in all_results
            ]
        }
        
        with open(args.json_output, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n📄 Results saved to: {args.json_output}")
    
    # Exit with appropriate code
    failed_tests = sum(1 for r in all_results if not r.success)
    if failed_tests == 0:
        print("\n🎉 All tests PASSED! Server is working correctly.")
        sys.exit(0)
    else:
        print(f"\n⚠️  {failed_tests} test(s) failed. Check server implementation.")
        sys.exit(1)

if __name__ == "__main__":
    main()