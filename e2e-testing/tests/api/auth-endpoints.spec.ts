import { test, expect } from '@playwright/test';
import { ApiTestHelper } from '../../utils/api-helper';
import { TestDataGenerator } from '../../utils/test-data-generator';
import { CoverageTracker } from '../../utils/coverage-tracker';

/**
 * Authentication API Endpoint Tests
 * Comprehensive testing of all auth-related endpoints with coverage tracking
 */
test.describe('Authentication API Endpoints', () => {
  let apiHelper: ApiTestHelper;
  let coverage: CoverageTracker;

  test.beforeAll(async () => {
    apiHelper = new ApiTestHelper();
    coverage = new CoverageTracker('auth-endpoints');
    await apiHelper.initialize();
  });

  test.afterAll(async () => {
    await coverage.generateReport();
  });

  test.describe('Health & Status Endpoints', () => {
    test('GET /health - Health check endpoint', async ({ request }) => {
      coverage.trackEndpoint('GET', '/health');
      
      const response = await request.get('/health');
      
      expect(response.status()).toBe(200);
      
      const body = await response.json();
      expect(body).toHaveProperty('status', 'healthy');
      expect(body).toHaveProperty('timestamp');
      expect(body).toHaveProperty('version');
      
      await coverage.recordResponse('/health', response.status(), body);
    });

    test('GET /metrics - Metrics endpoint', async ({ request }) => {
      coverage.trackEndpoint('GET', '/metrics');
      
      const response = await request.get('/metrics');
      
      expect(response.status()).toBe(200);
      const metricsText = await response.text();
      expect(metricsText).toContain('# HELP');
      
      await coverage.recordResponse('/metrics', response.status(), { metrics: 'present' });
    });

    test('GET /version - Version information', async ({ request }) => {
      coverage.trackEndpoint('GET', '/version');
      
      const response = await request.get('/version');
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('version');
      expect(body).toHaveProperty('build_time');
      
      await coverage.recordResponse('/version', response.status(), body);
    });
  });

  test.describe('Authentication Endpoints', () => {
    test('POST /auth/register - User registration', async ({ request }) => {
      coverage.trackEndpoint('POST', '/auth/register');
      
      const userData = TestDataGenerator.generateValidUser();
      
      const response = await request.post('/auth/register', {
        data: userData
      });
      
      expect(response.status()).toBe(201);
      const body = await response.json();
      expect(body).toHaveProperty('user_id');
      expect(body).toHaveProperty('email', userData.email);
      
      await coverage.recordResponse('/auth/register', response.status(), body);
    });

    test('POST /auth/register - Invalid email validation', async ({ request }) => {
      coverage.trackEndpoint('POST', '/auth/register', 'invalid-email');
      
      const invalidUserData = {
        email: 'invalid-email',
        password: 'ValidPassword123!',
        first_name: 'Test',
        last_name: 'User'
      };
      
      const response = await request.post('/auth/register', {
        data: invalidUserData
      });
      
      expect(response.status()).toBe(400);
      const body = await response.json();
      expect(body).toHaveProperty('error');
      expect(body.error).toContain('email');
      
      await coverage.recordResponse('/auth/register', response.status(), body, 'invalid-email');
    });

    test('POST /auth/login - Valid credentials', async ({ request }) => {
      coverage.trackEndpoint('POST', '/auth/login');
      
      // First register a user
      const userData = TestDataGenerator.generateValidUser();
      await request.post('/auth/register', { data: userData });
      
      // Then attempt login
      const response = await request.post('/auth/login', {
        data: {
          email: userData.email,
          password: userData.password
        }
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('access_token');
      expect(body).toHaveProperty('refresh_token');
      expect(body).toHaveProperty('expires_in');
      
      await coverage.recordResponse('/auth/login', response.status(), body);
    });

    test('POST /auth/login - Invalid credentials', async ({ request }) => {
      coverage.trackEndpoint('POST', '/auth/login', 'invalid-credentials');
      
      const response = await request.post('/auth/login', {
        data: {
          email: 'nonexistent@example.com',
          password: 'WrongPassword123!'
        }
      });
      
      expect(response.status()).toBe(401);
      const body = await response.json();
      expect(body).toHaveProperty('error');
      
      await coverage.recordResponse('/auth/login', response.status(), body, 'invalid-credentials');
    });

    test('POST /auth/refresh - Token refresh', async ({ request }) => {
      coverage.trackEndpoint('POST', '/auth/refresh');
      
      // First login to get tokens
      const userData = TestDataGenerator.generateValidUser();
      await request.post('/auth/register', { data: userData });
      
      const loginResponse = await request.post('/auth/login', {
        data: { email: userData.email, password: userData.password }
      });
      
      const tokens = await loginResponse.json();
      
      // Refresh token
      const response = await request.post('/auth/refresh', {
        data: {
          refresh_token: tokens.refresh_token
        }
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('access_token');
      expect(body).toHaveProperty('expires_in');
      
      await coverage.recordResponse('/auth/refresh', response.status(), body);
    });

    test('POST /auth/logout - User logout', async ({ request }) => {
      coverage.trackEndpoint('POST', '/auth/logout');
      
      // First login to get tokens
      const { accessToken } = await apiHelper.createAuthenticatedUser();
      
      const response = await request.post('/auth/logout', {
        headers: {
          'Authorization': `Bearer ${accessToken}`
        }
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('message');
      
      await coverage.recordResponse('/auth/logout', response.status(), body);
    });
  });

  test.describe('Protected Endpoints', () => {
    let authHeaders: Record<string, string>;

    test.beforeEach(async ({ request }) => {
      const { accessToken } = await apiHelper.createAuthenticatedUser();
      authHeaders = { 'Authorization': `Bearer ${accessToken}` };
    });

    test('GET /user/profile - Get user profile', async ({ request }) => {
      coverage.trackEndpoint('GET', '/user/profile');
      
      const response = await request.get('/user/profile', {
        headers: authHeaders
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('user_id');
      expect(body).toHaveProperty('email');
      expect(body).toHaveProperty('first_name');
      expect(body).toHaveProperty('last_name');
      
      await coverage.recordResponse('/user/profile', response.status(), body);
    });

    test('PUT /user/profile - Update user profile', async ({ request }) => {
      coverage.trackEndpoint('PUT', '/user/profile');
      
      const updateData = {
        first_name: 'Updated',
        last_name: 'Name'
      };
      
      const response = await request.put('/user/profile', {
        headers: authHeaders,
        data: updateData
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body.first_name).toBe(updateData.first_name);
      expect(body.last_name).toBe(updateData.last_name);
      
      await coverage.recordResponse('/user/profile', response.status(), body);
    });

    test('POST /user/change-password - Change password', async ({ request }) => {
      coverage.trackEndpoint('POST', '/user/change-password');
      
      const passwordData = {
        current_password: 'TempPassword123!',
        new_password: 'NewPassword123!',
        confirm_password: 'NewPassword123!'
      };
      
      const response = await request.post('/user/change-password', {
        headers: authHeaders,
        data: passwordData
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('message');
      
      await coverage.recordResponse('/user/change-password', response.status(), body);
    });
  });

  test.describe('API Key Endpoints', () => {
    let authHeaders: Record<string, string>;

    test.beforeEach(async ({ request }) => {
      const { accessToken } = await apiHelper.createAuthenticatedUser();
      authHeaders = { 'Authorization': `Bearer ${accessToken}` };
    });

    test('POST /api-keys - Create API key', async ({ request }) => {
      coverage.trackEndpoint('POST', '/api-keys');
      
      const keyData = {
        name: 'Test API Key',
        scopes: ['read:profile', 'write:profile'],
        expires_in: 86400 // 1 day
      };
      
      const response = await request.post('/api-keys', {
        headers: authHeaders,
        data: keyData
      });
      
      expect(response.status()).toBe(201);
      const body = await response.json();
      expect(body).toHaveProperty('api_key');
      expect(body).toHaveProperty('key_id');
      expect(body).toHaveProperty('expires_at');
      
      await coverage.recordResponse('/api-keys', response.status(), body);
    });

    test('GET /api-keys - List API keys', async ({ request }) => {
      coverage.trackEndpoint('GET', '/api-keys');
      
      // Create a key first
      await request.post('/api-keys', {
        headers: authHeaders,
        data: { name: 'List Test Key', scopes: ['read:profile'] }
      });
      
      const response = await request.get('/api-keys', {
        headers: authHeaders
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(Array.isArray(body.keys)).toBeTruthy();
      expect(body.keys.length).toBeGreaterThan(0);
      
      await coverage.recordResponse('/api-keys', response.status(), body);
    });

    test('DELETE /api-keys/:key_id - Revoke API key', async ({ request }) => {
      coverage.trackEndpoint('DELETE', '/api-keys/:key_id');
      
      // Create a key first
      const createResponse = await request.post('/api-keys', {
        headers: authHeaders,
        data: { name: 'Delete Test Key', scopes: ['read:profile'] }
      });
      
      const { key_id } = await createResponse.json();
      
      const response = await request.delete(`/api-keys/${key_id}`, {
        headers: authHeaders
      });
      
      expect(response.status()).toBe(200);
      const body = await response.json();
      expect(body).toHaveProperty('message');
      
      await coverage.recordResponse(`/api-keys/${key_id}`, response.status(), body);
    });
  });

  test.describe('OAuth2 Endpoints', () => {
    test('GET /oauth/authorize - OAuth authorization', async ({ request }) => {
      coverage.trackEndpoint('GET', '/oauth/authorize');
      
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: 'test_client',
        redirect_uri: 'http://localhost:3000/callback',
        scope: 'read:profile',
        state: 'random_state_value'
      });
      
      const response = await request.get(`/oauth/authorize?${params}`);
      
      // Should redirect to login or return authorization page
      expect([200, 302]).toContain(response.status());
      
      await coverage.recordResponse('/oauth/authorize', response.status(), 
        { redirect: response.status() === 302 });
    });

    test('POST /oauth/token - OAuth token exchange', async ({ request }) => {
      coverage.trackEndpoint('POST', '/oauth/token');
      
      const tokenData = {
        grant_type: 'authorization_code',
        code: 'test_auth_code',
        redirect_uri: 'http://localhost:3000/callback',
        client_id: 'test_client',
        client_secret: 'test_secret'
      };
      
      const response = await request.post('/oauth/token', {
        data: tokenData
      });
      
      // Might be 400 for invalid code, but endpoint should exist
      expect([200, 400]).toContain(response.status());
      
      await coverage.recordResponse('/oauth/token', response.status(), await response.json());
    });
  });

  test.describe('Admin Endpoints', () => {
    test('GET /admin/users - List all users (admin only)', async ({ request }) => {
      coverage.trackEndpoint('GET', '/admin/users');
      
      // Try with regular user (should fail)
      const { accessToken } = await apiHelper.createAuthenticatedUser();
      
      const response = await request.get('/admin/users', {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      // Should be forbidden for non-admin users
      expect(response.status()).toBe(403);
      
      await coverage.recordResponse('/admin/users', response.status(), await response.json());
    });
  });
});