import { APIRequestContext } from '@playwright/test';
import { TestDataGenerator } from './test-data-generator';

/**
 * API Test Helper
 * Provides common API testing utilities and authentication helpers
 */
export class ApiTestHelper {
  private testData: TestDataGenerator;
  private baseURL: string;

  constructor() {
    this.testData = new TestDataGenerator();
    this.baseURL = process.env.API_BASE_URL || 'http://localhost:8080';
  }

  async initialize(): Promise<void> {
    // Any initialization logic
    console.log(`API Helper initialized for ${this.baseURL}`);
  }

  /**
   * Create a new user and return authentication tokens
   */
  async createAuthenticatedUser(userData?: any): Promise<{
    userId: string;
    email: string;
    accessToken: string;
    refreshToken: string;
  }> {
    const user = userData || TestDataGenerator.generateValidUser();
    
    // Register user
    const registerResponse = await fetch(`${this.baseURL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(user)
    });

    if (!registerResponse.ok) {
      throw new Error(`Registration failed: ${await registerResponse.text()}`);
    }

    const registerData = await registerResponse.json();

    // Login user
    const loginResponse = await fetch(`${this.baseURL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: user.email,
        password: user.password
      })
    });

    if (!loginResponse.ok) {
      throw new Error(`Login failed: ${await loginResponse.text()}`);
    }

    const loginData = await loginResponse.json();

    return {
      userId: registerData.user_id,
      email: user.email,
      accessToken: loginData.access_token,
      refreshToken: loginData.refresh_token
    };
  }

  /**
   * Create admin user (if supported by the system)
   */
  async createAdminUser(): Promise<{
    userId: string;
    email: string;
    accessToken: string;
    refreshToken: string;
  }> {
    const adminData = this.testData.generateAdminUser();
    return this.createAuthenticatedUser(adminData);
  }

  /**
   * Create API key for authenticated user
   */
  async createApiKey(accessToken: string, keyData: any): Promise<{
    apiKey: string;
    keyId: string;
    expiresAt: string;
  }> {
    const response = await fetch(`${this.baseURL}/api-keys`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify(keyData)
    });

    if (!response.ok) {
      throw new Error(`API key creation failed: ${await response.text()}`);
    }

    const data = await response.json();
    return {
      apiKey: data.api_key,
      keyId: data.key_id,
      expiresAt: data.expires_at
    };
  }

  /**
   * Test API endpoint accessibility
   */
  async testEndpointAccessibility(endpoint: string, method: string = 'GET'): Promise<{
    accessible: boolean;
    statusCode: number;
    responseTime: number;
  }> {
    const startTime = Date.now();
    
    try {
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        method,
        headers: { 'Content-Type': 'application/json' }
      });

      const responseTime = Date.now() - startTime;

      return {
        accessible: response.status < 500, // Not a server error
        statusCode: response.status,
        responseTime
      };
    } catch (error) {
      return {
        accessible: false,
        statusCode: 0,
        responseTime: Date.now() - startTime
      };
    }
  }

  /**
   * Validate JWT token format
   */
  validateJwtFormat(token: string): boolean {
    const jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;
    return jwtRegex.test(token);
  }

  /**
   * Parse JWT payload (without verification)
   */
  parseJwtPayload(token: string): any {
    try {
      const payload = token.split('.')[1];
      const decoded = Buffer.from(payload, 'base64').toString();
      return JSON.parse(decoded);
    } catch (error) {
      throw new Error(`Invalid JWT format: ${error}`);
    }
  }

  /**
   * Clean up test data
   */
  async cleanup(): Promise<void> {
    // Implement cleanup logic if needed
    console.log('API Helper cleanup completed');
  }
}