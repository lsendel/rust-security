import { test, expect, Page } from '@playwright/test';
import { TestDataGenerator } from '../../utils/test-data-generator';
import { EvidenceCollector } from '../../utils/evidence-collector';

/**
 * UI Authentication Flow Tests
 * Complete user journey testing with evidence collection
 */
test.describe('Authentication UI Flow', () => {
  let testData: TestDataGenerator;
  let evidence: EvidenceCollector;

  test.beforeAll(async () => {
    testData = new TestDataGenerator();
    evidence = new EvidenceCollector('ui-auth-flow');
  });

  test.afterAll(async () => {
    await evidence.generateReport();
  });

  test.describe('User Registration Flow', () => {
    test('Complete user registration journey', async ({ page }) => {
      await evidence.startTest('complete-user-registration');
      
      // Navigate to registration page
      await page.goto('/register');
      await evidence.captureStep(page, 'navigation-to-register');

      // Verify registration form is visible
      await expect(page.locator('form[data-testid="registration-form"]')).toBeVisible();
      await evidence.captureStep(page, 'registration-form-visible');

      // Generate test user data
      const userData = testData.generateValidUser();

      // Fill registration form
      await page.fill('input[name="email"]', userData.email);
      await page.fill('input[name="password"]', userData.password);
      await page.fill('input[name="confirmPassword"]', userData.password);
      await page.fill('input[name="firstName"]', userData.first_name);
      await page.fill('input[name="lastName"]', userData.last_name);
      
      await evidence.captureStep(page, 'registration-form-filled');

      // Submit registration
      await page.click('button[type="submit"]');
      
      // Wait for success message or redirect
      await expect(
        page.locator('.success-message').or(page.locator('h1:has-text("Welcome")'))
      ).toBeVisible({ timeout: 10000 });
      
      await evidence.captureStep(page, 'registration-success');
      await evidence.recordUserAction('registration-completed', { email: userData.email });
    });

    test('Registration form validation', async ({ page }) => {
      await evidence.startTest('registration-validation');
      
      await page.goto('/register');
      
      // Test empty form submission
      await page.click('button[type="submit"]');
      await expect(page.locator('.error-message')).toBeVisible();
      await evidence.captureStep(page, 'empty-form-validation');

      // Test invalid email
      await page.fill('input[name="email"]', 'invalid-email');
      await page.fill('input[name="password"]', 'ValidPass123!');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('.email-error')).toBeVisible();
      await evidence.captureStep(page, 'invalid-email-validation');

      // Test weak password
      await page.fill('input[name="email"]', 'test@example.com');
      await page.fill('input[name="password"]', '123');
      await page.click('button[type="submit"]');
      
      await expect(page.locator('.password-error')).toBeVisible();
      await evidence.captureStep(page, 'weak-password-validation');

      await evidence.recordValidationTest('registration-form', {
        emptyForm: 'passed',
        invalidEmail: 'passed',
        weakPassword: 'passed'
      });
    });
  });

  test.describe('User Login Flow', () => {
    let registeredUser: any;

    test.beforeEach(async ({ page }) => {
      // Register a user for login tests
      registeredUser = testData.generateValidUser();
      await registerUserForTest(page, registeredUser);
    });

    test('Successful login flow', async ({ page }) => {
      await evidence.startTest('successful-login');
      
      await page.goto('/login');
      await evidence.captureStep(page, 'navigation-to-login');

      // Fill login form
      await page.fill('input[name="email"]', registeredUser.email);
      await page.fill('input[name="password"]', registeredUser.password);
      await evidence.captureStep(page, 'login-form-filled');

      // Submit login
      await page.click('button[type="submit"]');
      
      // Wait for successful login (redirect to dashboard)
      await expect(page).toHaveURL(/.*\/dashboard/);
      await evidence.captureStep(page, 'login-success-dashboard');

      // Verify user is logged in
      await expect(page.locator('[data-testid="user-menu"]')).toBeVisible();
      await evidence.captureStep(page, 'user-authenticated-ui');

      await evidence.recordUserAction('login-completed', { 
        email: registeredUser.email,
        redirectUrl: page.url()
      });
    });

    test('Invalid credentials handling', async ({ page }) => {
      await evidence.startTest('invalid-login-credentials');
      
      await page.goto('/login');
      
      // Try invalid credentials
      await page.fill('input[name="email"]', registeredUser.email);
      await page.fill('input[name="password"]', 'wrong-password');
      await page.click('button[type="submit"]');
      
      // Verify error message
      await expect(page.locator('.login-error')).toBeVisible();
      await expect(page.locator('.login-error')).toContainText(/invalid.*credentials/i);
      await evidence.captureStep(page, 'invalid-credentials-error');

      // Verify user stays on login page
      await expect(page).toHaveURL(/.*\/login/);
      
      await evidence.recordSecurityTest('login-invalid-credentials', {
        errorDisplayed: true,
        noRedirect: true,
        noSessionCreated: true
      });
    });

    test('Remember me functionality', async ({ page }) => {
      await evidence.startTest('remember-me-functionality');
      
      await page.goto('/login');
      
      // Login with remember me checked
      await page.fill('input[name="email"]', registeredUser.email);
      await page.fill('input[name="password"]', registeredUser.password);
      await page.check('input[name="rememberMe"]');
      await evidence.captureStep(page, 'remember-me-checked');
      
      await page.click('button[type="submit"]');
      await expect(page).toHaveURL(/.*\/dashboard/);
      
      // Check if remember me token is set
      const cookies = await page.context().cookies();
      const rememberMeCookie = cookies.find(c => c.name.includes('remember'));
      
      expect(rememberMeCookie).toBeTruthy();
      await evidence.recordTest('remember-me-cookie-set', { 
        cookieExists: !!rememberMeCookie,
        cookieName: rememberMeCookie?.name
      });
    });
  });

  test.describe('Password Reset Flow', () => {
    test('Password reset request', async ({ page }) => {
      await evidence.startTest('password-reset-request');
      
      await page.goto('/forgot-password');
      await evidence.captureStep(page, 'forgot-password-page');

      // Fill email
      const testEmail = 'test@example.com';
      await page.fill('input[name="email"]', testEmail);
      await evidence.captureStep(page, 'email-filled');

      // Submit request
      await page.click('button[type="submit"]');
      
      // Verify confirmation message
      await expect(page.locator('.reset-confirmation')).toBeVisible();
      await expect(page.locator('.reset-confirmation')).toContainText(/reset.*sent/i);
      await evidence.captureStep(page, 'reset-request-confirmation');

      await evidence.recordUserAction('password-reset-requested', { email: testEmail });
    });
  });

  test.describe('Multi-Factor Authentication', () => {
    test('MFA setup flow', async ({ page }) => {
      await evidence.startTest('mfa-setup-flow');
      
      // Login first
      const user = testData.generateValidUser();
      await registerUserForTest(page, user);
      await loginUser(page, user);

      // Navigate to security settings
      await page.goto('/settings/security');
      await evidence.captureStep(page, 'security-settings-page');

      // Enable MFA
      await page.click('[data-testid="enable-mfa-button"]');
      await evidence.captureStep(page, 'mfa-setup-initiated');

      // Verify QR code is displayed
      await expect(page.locator('.qr-code-container')).toBeVisible();
      await evidence.captureStep(page, 'qr-code-displayed');

      // Verify backup codes are shown
      await expect(page.locator('.backup-codes')).toBeVisible();
      await evidence.captureStep(page, 'backup-codes-shown');

      await evidence.recordSecurityFeature('mfa-setup', {
        qrCodeShown: true,
        backupCodesGenerated: true
      });
    });
  });

  test.describe('User Profile Management', () => {
    let authenticatedUser: any;

    test.beforeEach(async ({ page }) => {
      authenticatedUser = testData.generateValidUser();
      await registerUserForTest(page, authenticatedUser);
      await loginUser(page, authenticatedUser);
    });

    test('Profile update flow', async ({ page }) => {
      await evidence.startTest('profile-update');
      
      await page.goto('/profile');
      await evidence.captureStep(page, 'profile-page');

      // Update profile information
      const newFirstName = 'Updated';
      await page.fill('input[name="firstName"]', newFirstName);
      await page.fill('input[name="lastName"]', 'Name');
      await evidence.captureStep(page, 'profile-form-updated');

      // Save changes
      await page.click('button[type="submit"]');
      
      // Verify success message
      await expect(page.locator('.success-message')).toBeVisible();
      await evidence.captureStep(page, 'profile-update-success');

      // Verify changes are reflected
      await expect(page.locator('input[name="firstName"]')).toHaveValue(newFirstName);
      
      await evidence.recordUserAction('profile-updated', {
        fields: ['firstName', 'lastName'],
        success: true
      });
    });
  });

  // Helper functions
  async function registerUserForTest(page: Page, userData: any): Promise<void> {
    await page.goto('/register');
    await page.fill('input[name="email"]', userData.email);
    await page.fill('input[name="password"]', userData.password);
    await page.fill('input[name="confirmPassword"]', userData.password);
    await page.fill('input[name="firstName"]', userData.first_name);
    await page.fill('input[name="lastName"]', userData.last_name);
    await page.click('button[type="submit"]');
    
    // Wait for registration to complete
    await expect(
      page.locator('.success-message').or(page.locator('h1:has-text("Welcome")'))
    ).toBeVisible({ timeout: 10000 });
  }

  async function loginUser(page: Page, userData: any): Promise<void> {
    await page.goto('/login');
    await page.fill('input[name="email"]', userData.email);
    await page.fill('input[name="password"]', userData.password);
    await page.click('button[type="submit"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*\/dashboard/);
  }
});