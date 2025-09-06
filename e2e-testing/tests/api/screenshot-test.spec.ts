import { test, expect } from '@playwright/test';
import { EvidenceCollector } from '../../utils/evidence-collector';

test.describe('Screenshot Validation Tests', () => {
  let evidence: EvidenceCollector;

  test.beforeEach(async () => {
    evidence = new EvidenceCollector('screenshot-validation');
    await evidence.setup();
  });

  test('Generate and validate screenshots', async ({ page }) => {
    console.log('📸 Testing screenshot generation...');
    
    // Navigate to a simple page
    await page.goto('https://example.com');
    await page.waitForLoadState('networkidle');
    
    // Take screenshot
    const screenshotPath = await evidence.captureScreenshot(page, 'example-com-test');
    console.log(`Screenshot saved to: ${screenshotPath}`);
    
    // Verify screenshot exists
    const fs = require('fs');
    expect(fs.existsSync(screenshotPath)).toBe(true);
    
    // Check file size (should be > 1KB for a real screenshot)
    const stats = fs.statSync(screenshotPath);
    expect(stats.size).toBeGreaterThan(1000);
    
    console.log(`✅ Screenshot generated: ${stats.size} bytes`);
  });

  test('Generate multiple screenshots', async ({ page }) => {
    console.log('📸 Testing multiple screenshot generation...');
    
    // Test different pages
    const pages = [
      { url: 'https://httpbin.org/html', name: 'httpbin-html' },
      { url: 'https://httpbin.org/json', name: 'httpbin-json' }
    ];
    
    for (const pageInfo of pages) {
      await page.goto(pageInfo.url);
      await page.waitForLoadState('networkidle');
      
      const screenshotPath = await evidence.captureScreenshot(page, pageInfo.name);
      console.log(`Screenshot saved: ${screenshotPath}`);
      
      const fs = require('fs');
      const stats = fs.statSync(screenshotPath);
      expect(stats.size).toBeGreaterThan(500);
      
      console.log(`✅ ${pageInfo.name}: ${stats.size} bytes`);
    }
  });

  test('Test local page screenshot', async ({ page }) => {
    console.log('📸 Testing local page screenshot...');
    
    // Create a simple HTML page
    await page.setContent(`
      <html>
        <head><title>Test Page</title></head>
        <body style="background: linear-gradient(45deg, #ff6b6b, #4ecdc4); padding: 50px;">
          <h1 style="color: white; text-align: center;">Screenshot Test Page</h1>
          <p style="color: white; text-align: center; font-size: 18px;">
            This is a test page for validating screenshot generation.
          </p>
          <div style="background: white; padding: 20px; margin: 20px; border-radius: 10px;">
            <h2>Test Content</h2>
            <p>Current time: ${new Date().toISOString()}</p>
            <ul>
              <li>Screenshot validation ✅</li>
              <li>Evidence collection ✅</li>
              <li>File generation ✅</li>
            </ul>
          </div>
        </body>
      </html>
    `);
    
    // Take screenshot
    const screenshotPath = await evidence.captureScreenshot(page, 'local-test-page');
    console.log(`Local page screenshot: ${screenshotPath}`);
    
    // Verify
    const fs = require('fs');
    const stats = fs.statSync(screenshotPath);
    expect(stats.size).toBeGreaterThan(2000);
    
    console.log(`✅ Local page screenshot: ${stats.size} bytes`);
  });
});
