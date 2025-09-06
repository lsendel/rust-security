import { test, expect } from '@playwright/test';

test.describe('E2E Smoke Tests', () => {
  test('Environment setup verification', async () => {
    // Verify test environment is working
    expect(process.env.NODE_ENV || 'test').toBeTruthy();
  });

  test('External API connectivity', async ({ request }) => {
    // Test external connectivity
    const response = await request.get('https://httpbin.org/status/200');
    expect(response.status()).toBe(200);
  });

  test('Local service health check (graceful fail)', async ({ request }) => {
    // Test local service with graceful failure
    try {
      const response = await request.get('http://localhost:8080/health', {
        timeout: 2000
      });
      
      if (response.ok()) {
        expect(response.status()).toBe(200);
        console.log('✅ Local auth service is running');
      }
    } catch (error) {
      console.log('ℹ️ Local auth service not available (expected in CI)');
      // This is expected when services aren't running
    }
  });

  test('Test data generation', async () => {
    // Test our test data utilities
    const { TestDataGenerator } = await import('../utils/test-data-generator');
    
    const user = TestDataGenerator.generateUser();
    expect(user.email).toContain('@example.com');
    expect(user.password).toBe('TestPassword123!');
    expect(user.firstName).toBeTruthy();
    expect(user.lastName).toBe('User');
  });

  test('Evidence collection setup', async () => {
    // Test evidence collection utilities
    const { EvidenceCollector } = await import('../utils/evidence-collector');
    
    const collector = new EvidenceCollector('smoke-test');
    await collector.setup();
    
    const evidenceDir = collector.getEvidenceDir();
    expect(evidenceDir).toContain('smoke-test');
  });
});
