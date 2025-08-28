import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics
const authSuccessRate = new Rate('auth_success_rate');
const tokenValidationRate = new Rate('token_validation_rate');
const authLatency = new Trend('auth_latency_ms');
const tokenLatency = new Trend('token_validation_latency_ms');
const introspectLatency = new Trend('introspect_latency_ms');
const refreshLatency = new Trend('refresh_token_latency_ms');
const totalRequests = new Counter('total_requests');
const activeTokens = new Gauge('active_tokens');

// Test scenarios
export const options = {
  scenarios: {
    // Scenario 1: Authentication load test
    authentication: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m', target: 50 },   // Ramp up to 50 users
        { duration: '5m', target: 100 },  // Ramp up to 100 users
        { duration: '10m', target: 100 }, // Stay at 100 users
        { duration: '5m', target: 200 },  // Spike to 200 users
        { duration: '3m', target: 0 },    // Ramp down to 0
      ],
      gracefulRampDown: '30s',
      exec: 'authenticationScenario',
    },
    // Scenario 2: Token validation stress test
    tokenValidation: {
      executor: 'constant-vus',
      vus: 50,
      duration: '25m',
      exec: 'tokenValidationScenario',
      startTime: '2m', // Start after auth scenario ramps up
    },
    // Scenario 3: API usage simulation
    apiUsage: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      preAllocatedVUs: 50,
      maxVUs: 100,
      stages: [
        { duration: '5m', target: 50 },   // Ramp up to 50 RPS
        { duration: '10m', target: 100 }, // Ramp up to 100 RPS
        { duration: '5m', target: 150 },  // Peak at 150 RPS
        { duration: '5m', target: 50 },   // Ramp down
      ],
      exec: 'apiUsageScenario',
    },
  },
  thresholds: {
    // Response time thresholds
    'http_req_duration{scenario:authentication}': ['p(95)<500', 'p(99)<1000'],
    'http_req_duration{scenario:tokenValidation}': ['p(95)<100', 'p(99)<200'],
    'http_req_duration{scenario:apiUsage}': ['p(95)<200', 'p(99)<500'],

    // Success rate thresholds
    'auth_success_rate': ['rate>0.95'],
    'token_validation_rate': ['rate>0.99'],

    // Error rate threshold
    'http_req_failed': ['rate<0.01'],

    // Custom latency thresholds
    'auth_latency_ms': ['p(95)<500', 'p(99)<1000'],
    'token_validation_latency_ms': ['p(95)<100', 'p(99)<200'],
    'introspect_latency_ms': ['p(95)<150', 'p(99)<300'],
    'refresh_token_latency_ms': ['p(95)<200', 'p(99)<400'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const CLIENT_ID = __ENV.CLIENT_ID;
const CLIENT_SECRET = __ENV.CLIENT_SECRET;

// Validate required environment variables
if (!CLIENT_ID || !CLIENT_SECRET) {
  throw new Error('CLIENT_ID and CLIENT_SECRET environment variables are required');
}

// Shared token storage
const tokens = [];

// Helper functions
function generateUser() {
  return {
    username: `user_${randomString(8)}_${Date.now()}`,
    password: randomString(16),
    email: `user_${randomString(8)}@example.com`,
  };
}

function authenticateUser(username, password) {
  const payload = {
    grant_type: 'password',
    username: username,
    password: password,
    client_id: CLIENT_ID,
    scope: 'read write',
  };

  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`),
    },
    tags: { name: 'OAuth Token Request' },
  };

  const start = Date.now();
  const response = http.post(`${BASE_URL}/oauth/token`, payload, params);
  authLatency.add(Date.now() - start);

  const success = check(response, {
    'auth status is 200': (r) => r.status === 200,
    'has access_token': (r) => r.json('access_token') !== undefined,
    'has refresh_token': (r) => r.json('refresh_token') !== undefined,
  });

  authSuccessRate.add(success);
  totalRequests.add(1);

  if (success && response.json('access_token')) {
    const tokenData = {
      access_token: response.json('access_token'),
      refresh_token: response.json('refresh_token'),
      expires_in: response.json('expires_in'),
      created_at: Date.now(),
    };
    tokens.push(tokenData);
    activeTokens.add(tokens.length);
    return tokenData;
  }

  return null;
}

function validateToken(token) {
  const params = {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
    tags: { name: 'Token Validation' },
  };

  const start = Date.now();
  const response = http.get(`${BASE_URL}/oauth/userinfo`, params);
  tokenLatency.add(Date.now() - start);

  const success = check(response, {
    'validation status is 200': (r) => r.status === 200,
    'has user info': (r) => r.json('sub') !== undefined,
  });

  tokenValidationRate.add(success);
  totalRequests.add(1);

  return success;
}

function introspectToken(token) {
  const payload = {
    token: token,
    token_type_hint: 'access_token',
  };

  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`),
    },
    tags: { name: 'Token Introspection' },
  };

  const start = Date.now();
  const response = http.post(`${BASE_URL}/oauth/introspect`, payload, params);
  introspectLatency.add(Date.now() - start);

  check(response, {
    'introspect status is 200': (r) => r.status === 200,
    'token is active': (r) => r.json('active') === true,
  });

  totalRequests.add(1);
}

function refreshAccessToken(refreshToken) {
  const payload = {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
  };

  const params = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`),
    },
    tags: { name: 'Refresh Token' },
  };

  const start = Date.now();
  const response = http.post(`${BASE_URL}/oauth/token`, payload, params);
  refreshLatency.add(Date.now() - start);

  const success = check(response, {
    'refresh status is 200': (r) => r.status === 200,
    'has new access_token': (r) => r.json('access_token') !== undefined,
  });

  totalRequests.add(1);

  if (success && response.json('access_token')) {
    return {
      access_token: response.json('access_token'),
      refresh_token: response.json('refresh_token'),
      expires_in: response.json('expires_in'),
      created_at: Date.now(),
    };
  }

  return null;
}

// Scenario 1: Authentication load test
export function authenticationScenario() {
  const user = generateUser();

  group('User Registration and Authentication', () => {
    // Register user (if SCIM is enabled)
    const scimPayload = JSON.stringify({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: user.username,
      password: user.password,
      emails: [{ value: user.email, primary: true }],
      active: true,
    });

    const scimResponse = http.post(`${BASE_URL}/scim/v2/Users`, scimPayload, {
      headers: {
        'Content-Type': 'application/scim+json',
        'Authorization': `Bearer ${__ENV.ADMIN_TOKEN}`, // Use environment variable for admin token
      },
      tags: { name: 'SCIM User Creation' },
    });

    check(scimResponse, {
      'user created': (r) => r.status === 201 || r.status === 409, // 409 if user exists
    });

    // Authenticate
    const tokenData = authenticateUser(user.username, user.password);

    if (tokenData) {
      // Validate token
      validateToken(tokenData.access_token);

      // Introspect token
      introspectToken(tokenData.access_token);

      // Wait and refresh if needed
      sleep(randomIntBetween(1, 5));

      if (randomIntBetween(1, 10) > 7) { // 30% chance to refresh
        const newTokenData = refreshAccessToken(tokenData.refresh_token);
        if (newTokenData) {
          validateToken(newTokenData.access_token);
        }
      }
    }
  });

  sleep(randomIntBetween(1, 3));
}

// Scenario 2: Token validation stress test
export function tokenValidationScenario() {
  // Use existing tokens or create new ones
  let token = null;

  if (tokens.length > 0 && randomIntBetween(1, 10) > 3) {
    // Use existing token (70% chance)
    token = tokens[randomIntBetween(0, tokens.length - 1)];
  } else {
    // Create new token
    const user = generateUser();
    const tokenData = authenticateUser(user.username, user.password);
    if (tokenData) {
      token = tokenData;
    }
  }

  if (token) {
    // Rapid token validation
    for (let i = 0; i < 10; i++) {
      validateToken(token.access_token);
      sleep(0.1);
    }

    // Introspect periodically
    if (randomIntBetween(1, 10) > 8) {
      introspectToken(token.access_token);
    }
  }

  sleep(randomIntBetween(0.5, 2));
}

// Scenario 3: API usage simulation
export function apiUsageScenario() {
  const operations = [
    'authenticate',
    'validate',
    'introspect',
    'refresh',
    'revoke',
  ];

  const operation = operations[randomIntBetween(0, operations.length - 1)];

  switch (operation) {
    case 'authenticate':
      const user = generateUser();
      authenticateUser(user.username, user.password);
      break;

    case 'validate':
      if (tokens.length > 0) {
        const token = tokens[randomIntBetween(0, tokens.length - 1)];
        validateToken(token.access_token);
      }
      break;

    case 'introspect':
      if (tokens.length > 0) {
        const token = tokens[randomIntBetween(0, tokens.length - 1)];
        introspectToken(token.access_token);
      }
      break;

    case 'refresh':
      if (tokens.length > 0) {
        const token = tokens[randomIntBetween(0, tokens.length - 1)];
        if (token.refresh_token) {
          refreshAccessToken(token.refresh_token);
        }
      }
      break;

    case 'revoke':
      if (tokens.length > 0) {
        const tokenIndex = randomIntBetween(0, tokens.length - 1);
        const token = tokens[tokenIndex];

        const revokeResponse = http.post(`${BASE_URL}/oauth/revoke`, {
          token: token.access_token,
          token_type_hint: 'access_token',
        }, {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + encoding.b64encode(`${CLIENT_ID}:${CLIENT_SECRET}`),
          },
          tags: { name: 'Token Revocation' },
        });

        if (revokeResponse.status === 200) {
          tokens.splice(tokenIndex, 1);
          activeTokens.add(tokens.length);
        }
      }
      break;
  }

  sleep(randomIntBetween(0.1, 1));
}

// Summary handler
export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    duration: data.state.testRunDurationMs,
    scenarios: {},
    metrics: {},
    thresholds: {},
  };

  // Process scenarios
  for (const [name, scenario] of Object.entries(data.metrics)) {
    if (scenario.type === 'counter' || scenario.type === 'gauge' || scenario.type === 'rate' || scenario.type === 'trend') {
      summary.metrics[name] = {
        type: scenario.type,
        values: scenario.values,
      };
    }
  }

  // Process thresholds
  for (const [name, threshold] of Object.entries(data.thresholds || {})) {
    summary.thresholds[name] = {
      passed: threshold.ok,
      thresholds: threshold.thresholds,
    };
  }

  return {
    'performance-summary.json': JSON.stringify(summary, null, 2),
    stdout: generateTextSummary(data),
  };
}

function generateTextSummary(data) {
  let summary = '\n' + '='.repeat(80) + '\n';
  summary += '                    PERFORMANCE TEST SUMMARY\n';
  summary += '='.repeat(80) + '\n\n';

  // Key metrics
  if (data.metrics.http_req_duration) {
    summary += '📊 Response Times:\n';
    summary += `   P50: ${data.metrics.http_req_duration.p(50).toFixed(2)}ms\n`;
    summary += `   P95: ${data.metrics.http_req_duration.p(95).toFixed(2)}ms\n`;
    summary += `   P99: ${data.metrics.http_req_duration.p(99).toFixed(2)}ms\n\n`;
  }

  if (data.metrics.http_reqs) {
    summary += '🚀 Throughput:\n';
    summary += `   Total Requests: ${data.metrics.http_reqs.count}\n`;
    summary += `   Requests/sec: ${data.metrics.http_reqs.rate.toFixed(2)}\n\n`;
  }

  if (data.metrics.http_req_failed) {
    summary += '❌ Error Rate:\n';
    summary += `   Failed Requests: ${(data.metrics.http_req_failed.rate * 100).toFixed(2)}%\n\n`;
  }

  // Custom metrics
  summary += '🔐 Authentication Metrics:\n';
  if (data.metrics.auth_success_rate) {
    summary += `   Success Rate: ${(data.metrics.auth_success_rate.rate * 100).toFixed(2)}%\n`;
  }
  if (data.metrics.auth_latency_ms) {
    summary += `   P95 Latency: ${data.metrics.auth_latency_ms.p(95).toFixed(2)}ms\n`;
  }
  summary += '\n';

  // Threshold results
  summary += '✅ Threshold Results:\n';
  let allPassed = true;
  for (const [name, result] of Object.entries(data.thresholds || {})) {
    const status = result.ok ? '✅' : '❌';
    summary += `   ${status} ${name}\n`;
    if (!result.ok) allPassed = false;
  }

  summary += '\n' + '='.repeat(80) + '\n';
  summary += allPassed ?
    '✅ All performance thresholds PASSED!\n' :
    '❌ Some performance thresholds FAILED - review results above\n';
  summary += '='.repeat(80) + '\n';

  return summary;
}
