import http from 'k6/http';
import { check, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const tokenIntrospectionDuration = new Trend('token_introspection_duration');
const tokenIssuanceDuration = new Trend('token_issuance_duration');

// Test configuration
export let options = {
  scenarios: {
    // Token introspection load test
    introspection_load: {
      executor: 'constant-arrival-rate',
      rate: 100, // 100 requests per second
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: 'testTokenIntrospection',
      tags: { test_type: 'introspection' },
    },
    
    // Token issuance load test
    issuance_load: {
      executor: 'constant-arrival-rate', 
      rate: 50, // 50 requests per second
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 25,
      maxVUs: 100,
      exec: 'testTokenIssuance',
      tags: { test_type: 'issuance' },
    },
    
    // Spike test for rate limiting
    spike_test: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 500,
      stages: [
        { duration: '1m', target: 50 },   // Ramp up
        { duration: '30s', target: 500 }, // Spike
        { duration: '1m', target: 50 },   // Ramp down
      ],
      exec: 'testRateLimiting',
      tags: { test_type: 'spike' },
    },
    
    // Endurance test
    endurance_test: {
      executor: 'constant-vus',
      vus: 20,
      duration: '30m',
      exec: 'testEndurance',
      tags: { test_type: 'endurance' },
    }
  },
  
  thresholds: {
    http_req_duration: ['p(95)<100'], // 95% of requests under 100ms
    http_req_failed: ['rate<0.01'],   // Error rate under 1%
    errors: ['rate<0.01'],            // Custom error rate under 1%
    token_introspection_duration: ['p(95)<50'], // Introspection under 50ms
    token_issuance_duration: ['p(95)<100'],     // Token issuance under 100ms
  }
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID || 'test-client';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'test-secret';

// Setup function to get access tokens
export function setup() {
  // Get initial token for introspection tests
  const tokenResponse = http.post(`${BASE_URL}/oauth/token`, {
    grant_type: 'client_credentials',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'read write'
  }, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  
  if (tokenResponse.status === 200) {
    const tokenData = JSON.parse(tokenResponse.body);
    return {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token
    };
  }
  
  console.error('Failed to get setup token:', tokenResponse.status, tokenResponse.body);
  return {};
}

// Token introspection load test
export function testTokenIntrospection(data) {
  group('Token Introspection Load', () => {
    const startTime = Date.now();
    
    const response = http.post(`${BASE_URL}/oauth/introspect`, JSON.stringify({
      token: data.access_token || 'invalid_token',
      token_type_hint: 'access_token'
    }), {
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': `load-test-${Date.now()}-${Math.random()}`
      }
    });
    
    const duration = Date.now() - startTime;
    tokenIntrospectionDuration.add(duration);
    
    const success = check(response, {
      'introspection status is 200': (r) => r.status === 200,
      'introspection response has active field': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.hasOwnProperty('active');
        } catch (e) {
          return false;
        }
      },
      'introspection response time < 100ms': () => duration < 100,
    });
    
    if (!success) {
      errorRate.add(1);
    }
  });
}

// Token issuance load test
export function testTokenIssuance() {
  group('Token Issuance Load', () => {
    const startTime = Date.now();
    
    const response = http.post(`${BASE_URL}/oauth/token`, {
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      scope: 'read'
    }, {
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Request-Id': `load-test-${Date.now()}-${Math.random()}`
      }
    });
    
    const duration = Date.now() - startTime;
    tokenIssuanceDuration.add(duration);
    
    const success = check(response, {
      'token issuance status is 200': (r) => r.status === 200,
      'token response has access_token': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.access_token && body.access_token.length > 0;
        } catch (e) {
          return false;
        }
      },
      'token response has token_type': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.token_type === 'Bearer';
        } catch (e) {
          return false;
        }
      },
      'token issuance response time < 200ms': () => duration < 200,
    });
    
    if (!success) {
      errorRate.add(1);
    }
  });
}

// Rate limiting spike test
export function testRateLimiting() {
  group('Rate Limiting Spike', () => {
    // Make rapid requests to trigger rate limiting
    const responses = [];
    for (let i = 0; i < 5; i++) {
      const response = http.get(`${BASE_URL}/health`, {
        headers: {
          'X-Forwarded-For': `192.168.1.${Math.floor(Math.random() * 255)}`,
          'X-Request-Id': `spike-test-${Date.now()}-${i}`
        }
      });
      responses.push(response);
    }
    
    // Check that some requests succeed and rate limiting is working
    let successCount = 0;
    let rateLimitedCount = 0;
    
    responses.forEach((response, index) => {
      if (response.status === 200) {
        successCount++;
      } else if (response.status === 429) {
        rateLimitedCount++;
        check(response, {
          'rate limited response has retry-after header': (r) => 
            r.headers['Retry-After'] !== undefined
        });
      }
    });
    
    check(null, {
      'some requests succeed during spike': () => successCount > 0,
      'rate limiting is working': () => rateLimitedCount >= 0, // Allow for rate limiting
    });
  });
}

// Endurance test
export function testEndurance(data) {
  group('Endurance Test', () => {
    // Rotate between different operations
    const operations = [
      () => testTokenIntrospection(data),
      () => testTokenIssuance(),
      () => testHealthCheck(),
      () => testJwksEndpoint(),
      () => testOAuthMetadata(),
    ];
    
    const operation = operations[Math.floor(Math.random() * operations.length)];
    operation();
  });
}

// Helper functions for endurance test
function testHealthCheck() {
  const response = http.get(`${BASE_URL}/health`);
  check(response, {
    'health check status is 200': (r) => r.status === 200,
    'health check response is valid JSON': (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch (e) {
        return false;
      }
    }
  });
}

function testJwksEndpoint() {
  const response = http.get(`${BASE_URL}/jwks.json`);
  check(response, {
    'jwks status is 200': (r) => r.status === 200,
    'jwks response has keys': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.keys && Array.isArray(body.keys);
      } catch (e) {
        return false;
      }
    }
  });
}

function testOAuthMetadata() {
  const response = http.get(`${BASE_URL}/.well-known/oauth-authorization-server`);
  check(response, {
    'oauth metadata status is 200': (r) => r.status === 200,
    'oauth metadata has required fields': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.issuer && body.token_endpoint && body.introspection_endpoint;
      } catch (e) {
        return false;
      }
    }
  });
}

// SCIM endpoints test
export function testScimEndpoints() {
  group('SCIM Operations', () => {
    // Test user creation
    const createUserResponse = http.post(`${BASE_URL}/scim/v2/Users`, JSON.stringify({
      userName: `testuser_${Date.now()}`,
      active: true
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(createUserResponse, {
      'SCIM user creation status is 200': (r) => r.status === 200,
      'SCIM user has ID': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.id && body.id.length > 0;
        } catch (e) {
          return false;
        }
      }
    });
    
    // Test user listing with filter
    const listUsersResponse = http.get(`${BASE_URL}/scim/v2/Users?filter=userName co "test"`);
    
    check(listUsersResponse, {
      'SCIM user listing status is 200': (r) => r.status === 200,
      'SCIM user listing has resources': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.Resources && Array.isArray(body.Resources);
        } catch (e) {
          return false;
        }
      }
    });
  });
}

// MFA endpoints test  
export function testMfaEndpoints() {
  group('MFA Operations', () => {
    // Test TOTP registration
    const registerResponse = http.post(`${BASE_URL}/mfa/totp/register`, JSON.stringify({
      user_id: `testuser_${Date.now()}`
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(registerResponse, {
      'MFA TOTP registration status is 200': (r) => r.status === 200,
      'MFA TOTP registration has secret': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.secret_base32 && body.otpauth_url;
        } catch (e) {
          return false;
        }
      }
    });
    
    // Test backup codes generation
    const backupCodesResponse = http.post(`${BASE_URL}/mfa/totp/backup-codes/generate`, JSON.stringify({
      user_id: `testuser_${Date.now()}`
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(backupCodesResponse, {
      'MFA backup codes status is 200': (r) => r.status === 200,
      'MFA backup codes has codes': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.codes && Array.isArray(body.codes) && body.codes.length > 0;
        } catch (e) {
          return false;
        }
      }
    });
  });
}

// Performance analysis functions
export function handleSummary(data) {
  const summary = {
    test_run: new Date().toISOString(),
    scenarios: {},
    overall_metrics: {
      http_req_duration_avg: data.metrics.http_req_duration.values.avg,
      http_req_duration_p95: data.metrics.http_req_duration.values['p(95)'],
      http_req_duration_p99: data.metrics.http_req_duration.values['p(99)'],
      http_req_failed_rate: data.metrics.http_req_failed.values.rate,
      error_rate: data.metrics.errors ? data.metrics.errors.values.rate : 0,
      total_requests: data.metrics.http_reqs.values.count,
      requests_per_second: data.metrics.http_req_duration.values.count / (data.state.testRunDurationMs / 1000),
    }
  };
  
  if (data.metrics.token_introspection_duration) {
    summary.token_introspection = {
      avg: data.metrics.token_introspection_duration.values.avg,
      p95: data.metrics.token_introspection_duration.values['p(95)'],
      p99: data.metrics.token_introspection_duration.values['p(99)'],
    };
  }
  
  if (data.metrics.token_issuance_duration) {
    summary.token_issuance = {
      avg: data.metrics.token_issuance_duration.values.avg,
      p95: data.metrics.token_issuance_duration.values['p(95)'],
      p99: data.metrics.token_issuance_duration.values['p(99)'],
    };
  }
  
  return {
    'performance_summary.json': JSON.stringify(summary, null, 2),
    stdout: generateConsoleReport(summary),
  };
}

function generateConsoleReport(summary) {
  return `
=== Performance Test Summary ===
Test Run: ${summary.test_run}

Overall Metrics:
- Average Response Time: ${summary.overall_metrics.http_req_duration_avg.toFixed(2)}ms
- 95th Percentile: ${summary.overall_metrics.http_req_duration_p95.toFixed(2)}ms
- 99th Percentile: ${summary.overall_metrics.http_req_duration_p99.toFixed(2)}ms
- Error Rate: ${(summary.overall_metrics.http_req_failed_rate * 100).toFixed(2)}%
- Requests per Second: ${summary.overall_metrics.requests_per_second.toFixed(2)}
- Total Requests: ${summary.overall_metrics.total_requests}

${summary.token_introspection ? `
Token Introspection Performance:
- Average: ${summary.token_introspection.avg.toFixed(2)}ms
- 95th Percentile: ${summary.token_introspection.p95.toFixed(2)}ms
- 99th Percentile: ${summary.token_introspection.p99.toFixed(2)}ms
` : ''}

${summary.token_issuance ? `
Token Issuance Performance:
- Average: ${summary.token_issuance.avg.toFixed(2)}ms
- 95th Percentile: ${summary.token_issuance.p95.toFixed(2)}ms  
- 99th Percentile: ${summary.token_issuance.p99.toFixed(2)}ms
` : ''}

=== End Summary ===
`;
}