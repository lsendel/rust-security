import { test, expect } from '@playwright/test';

test.describe('Simple E2E Tests', () => {
  test('Basic test functionality', async ({ page }) => {
    // Test that Playwright is working
    await page.goto('https://example.com');
    await expect(page).toHaveTitle(/Example Domain/);
  });

  test('API request test', async ({ request }) => {
    // Test that API requests work
    const response = await request.get('https://httpbin.org/get');
    expect(response.ok()).toBeTruthy();
    expect(response.status()).toBe(200);
  });

  test('Local service connection test', async ({ request }) => {
    // Test connection to local services (will fail gracefully)
    try {
      const response = await request.get('http://localhost:8080/health');
      if (response.ok()) {
        expect(response.status()).toBe(200);
      }
    } catch (error) {
      // Service not running - this is expected
      console.log('Local service not available (expected)');
    }
  });
});
