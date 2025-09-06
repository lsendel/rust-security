import { defineConfig, devices } from '@playwright/test';
import * as path from 'path';

/**
 * Comprehensive Playwright Configuration for Rust Security Platform
 * Supports API, UI, and Frontend testing with evidence collection
 */
export default defineConfig({
  testDir: './tests',
  outputDir: './evidence/test-results',
  
  /* Run tests in files in parallel */
  fullyParallel: true,
  
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  
  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,
  
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,
  
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [
    ['html', { outputFolder: 'reports/html-report', open: 'never' }],
    ['json', { outputFile: 'reports/test-results.json' }],
    ['junit', { outputFile: 'reports/junit-results.xml' }],
    ['allure-playwright', { outputFolder: 'reports/allure-results' }],
    ['list'],
    ['./utils/coverage-reporter.js']
  ],
  
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: process.env.BASE_URL || 'http://localhost:8080',
    
    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',
    
    /* Screenshot on failure */
    screenshot: 'only-on-failure',
    
    /* Video on failure */
    video: 'retain-on-failure',
    
    /* Collect network activity */
    launchOptions: {
      slowMo: process.env.SLOW_MO ? parseInt(process.env.SLOW_MO) : 0,
    }
  },

  /* Configure projects for major browsers and testing types */
  projects: [
    // API Testing Project
    {
      name: 'api',
      testDir: './tests/api',
      use: {
        baseURL: process.env.API_BASE_URL || 'http://localhost:8080',
        extraHTTPHeaders: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
      },
      outputDir: './evidence/api-results',
    },

    // Frontend Testing Projects
    {
      name: 'frontend-chromium',
      testDir: './tests/frontend',
      use: { 
        ...devices['Desktop Chrome'],
        baseURL: process.env.FRONTEND_URL || 'http://localhost:5173',
      },
      outputDir: './evidence/frontend-chromium',
    },

    {
      name: 'frontend-firefox',
      testDir: './tests/frontend',
      use: { 
        ...devices['Desktop Firefox'],
        baseURL: process.env.FRONTEND_URL || 'http://localhost:5173',
      },
      outputDir: './evidence/frontend-firefox',
    },

    {
      name: 'frontend-safari',
      testDir: './tests/frontend',
      use: { 
        ...devices['Desktop Safari'],
        baseURL: process.env.FRONTEND_URL || 'http://localhost:5173',
      },
      outputDir: './evidence/frontend-safari',
    },

    // UI Testing Projects
    {
      name: 'ui-chromium',
      testDir: './tests/ui',
      use: { 
        ...devices['Desktop Chrome'],
        baseURL: process.env.BASE_URL || 'http://localhost:8080',
      },
      outputDir: './evidence/ui-chromium',
    },

    {
      name: 'ui-mobile',
      testDir: './tests/ui',
      use: { 
        ...devices['Pixel 5'],
        baseURL: process.env.BASE_URL || 'http://localhost:8080',
      },
      outputDir: './evidence/ui-mobile',
    },

    // Security Testing Project
    {
      name: 'security',
      testDir: './tests/security',
      use: {
        baseURL: process.env.API_BASE_URL || 'http://localhost:8080',
      },
      outputDir: './evidence/security-results',
    }
  ],

  /* Global setup and teardown */
  globalSetup: require.resolve('./config/global-setup.ts'),
  globalTeardown: require.resolve('./config/global-teardown.ts'),

  /* Run your local dev server before starting the tests */
  webServer: process.env.CI ? undefined : [
    {
      command: 'make services-up',
      cwd: '../',
      port: 5432, // PostgreSQL port to check if services are ready
      reuseExistingServer: !process.env.CI,
      timeout: 60 * 1000, // 60 seconds
    }
  ],

  /* Test timeout */
  timeout: 60 * 1000, // 60 seconds
  expect: {
    timeout: 10 * 1000, // 10 seconds
  },
});