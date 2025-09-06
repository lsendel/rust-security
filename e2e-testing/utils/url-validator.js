const fs = require('fs-extra');
const axios = require('axios');
const path = require('path');

/**
 * URL Path Validator
 * Validates all API endpoints and UI routes for accessibility and correct responses
 */
class URLValidator {
  constructor() {
    this.baseURL = process.env.API_BASE_URL || 'http://localhost:8080';
    this.frontendURL = process.env.FRONTEND_URL || 'http://localhost:5173';
    this.results = {
      api: [],
      frontend: [],
      summary: {},
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Load endpoint definitions from configuration
   */
  async loadEndpointDefinitions() {
    const configPath = path.join(__dirname, '..', 'config', 'endpoints.json');
    
    if (await fs.pathExists(configPath)) {
      return await fs.readJson(configPath);
    }

    // Default endpoint definitions if config doesn't exist
    return {
      api: {
        public: [
          { method: 'GET', path: '/health', expectedStatus: 200 },
          { method: 'GET', path: '/version', expectedStatus: 200 },
          { method: 'GET', path: '/metrics', expectedStatus: 200 },
          { method: 'POST', path: '/auth/register', expectedStatus: [400, 422] },
          { method: 'POST', path: '/auth/login', expectedStatus: [400, 401] },
          { method: 'POST', path: '/auth/refresh', expectedStatus: [400, 401] },
          { method: 'GET', path: '/oauth/authorize', expectedStatus: [200, 302] },
          { method: 'POST', path: '/oauth/token', expectedStatus: [400, 401] }
        ],
        protected: [
          { method: 'GET', path: '/user/profile', expectedStatus: 401 },
          { method: 'PUT', path: '/user/profile', expectedStatus: 401 },
          { method: 'POST', path: '/user/change-password', expectedStatus: 401 },
          { method: 'POST', path: '/api-keys', expectedStatus: 401 },
          { method: 'GET', path: '/api-keys', expectedStatus: 401 },
          { method: 'DELETE', path: '/api-keys/test-key-id', expectedStatus: 401 },
          { method: 'POST', path: '/auth/logout', expectedStatus: 401 }
        ],
        admin: [
          { method: 'GET', path: '/admin/users', expectedStatus: [401, 403] },
          { method: 'POST', path: '/admin/users', expectedStatus: [401, 403] },
          { method: 'DELETE', path: '/admin/users/test-id', expectedStatus: [401, 403] }
        ]
      },
      frontend: {
        public: [
          { path: '/', expectedStatus: 200 },
          { path: '/login', expectedStatus: 200 },
          { path: '/register', expectedStatus: 200 },
          { path: '/forgot-password', expectedStatus: 200 }
        ],
        protected: [
          { path: '/dashboard', expectedStatus: [200, 302] },
          { path: '/profile', expectedStatus: [200, 302] },
          { path: '/settings', expectedStatus: [200, 302] },
          { path: '/api-keys', expectedStatus: [200, 302] }
        ]
      }
    };
  }

  /**
   * Validate API endpoints
   */
  async validateApiEndpoints(endpoints) {
    console.log('🔍 Validating API endpoints...');
    
    const categories = ['public', 'protected', 'admin'];
    
    for (const category of categories) {
      if (!endpoints.api[category]) continue;
      
      console.log(`  Testing ${category} endpoints...`);
      
      for (const endpoint of endpoints.api[category]) {
        const result = await this.testApiEndpoint(endpoint, category);
        this.results.api.push(result);
        
        const status = result.success ? '✅' : '❌';
        console.log(`    ${status} ${endpoint.method} ${endpoint.path} - ${result.actualStatus}`);
      }
    }
  }

  /**
   * Validate frontend routes
   */
  async validateFrontendRoutes(endpoints) {
    console.log('🔍 Validating frontend routes...');
    
    const categories = ['public', 'protected'];
    
    for (const category of categories) {
      if (!endpoints.frontend[category]) continue;
      
      console.log(`  Testing ${category} routes...`);
      
      for (const route of endpoints.frontend[category]) {
        const result = await this.testFrontendRoute(route, category);
        this.results.frontend.push(result);
        
        const status = result.success ? '✅' : '❌';
        console.log(`    ${status} ${route.path} - ${result.actualStatus}`);
      }
    }
  }

  /**
   * Test individual API endpoint
   */
  async testApiEndpoint(endpoint, category) {
    const startTime = Date.now();
    const url = `${this.baseURL}${endpoint.path}`;
    
    try {
      const config = {
        method: endpoint.method.toLowerCase(),
        url,
        timeout: 10000,
        validateStatus: () => true, // Don't throw on any status
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      };

      // Add test data for POST/PUT requests
      if (['POST', 'PUT'].includes(endpoint.method)) {
        config.data = this.getTestDataForEndpoint(endpoint.path);
      }

      const response = await axios(config);
      const responseTime = Date.now() - startTime;
      
      const expectedStatuses = Array.isArray(endpoint.expectedStatus) 
        ? endpoint.expectedStatus 
        : [endpoint.expectedStatus];
      
      const success = expectedStatuses.includes(response.status);
      
      return {
        category,
        method: endpoint.method,
        path: endpoint.path,
        url,
        expectedStatus: endpoint.expectedStatus,
        actualStatus: response.status,
        responseTime,
        success,
        error: null,
        headers: response.headers,
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      return {
        category,
        method: endpoint.method,
        path: endpoint.path,
        url,
        expectedStatus: endpoint.expectedStatus,
        actualStatus: 0,
        responseTime: Date.now() - startTime,
        success: false,
        error: error.message,
        headers: {},
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Test individual frontend route
   */
  async testFrontendRoute(route, category) {
    const startTime = Date.now();
    const url = `${this.frontendURL}${route.path}`;
    
    try {
      const response = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      });
      
      const responseTime = Date.now() - startTime;
      
      const expectedStatuses = Array.isArray(route.expectedStatus) 
        ? route.expectedStatus 
        : [route.expectedStatus];
      
      const success = expectedStatuses.includes(response.status);
      
      return {
        category,
        path: route.path,
        url,
        expectedStatus: route.expectedStatus,
        actualStatus: response.status,
        responseTime,
        success,
        error: null,
        contentType: response.headers['content-type'],
        contentLength: response.headers['content-length'],
        timestamp: new Date().toISOString()
      };
      
    } catch (error) {
      return {
        category,
        path: route.path,
        url,
        expectedStatus: route.expectedStatus,
        actualStatus: 0,
        responseTime: Date.now() - startTime,
        success: false,
        error: error.message,
        contentType: null,
        contentLength: null,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Get test data for specific endpoints
   */
  getTestDataForEndpoint(path) {
    const testData = {
      '/auth/register': {
        email: 'test@example.com',
        password: 'TestPassword123!',
        first_name: 'Test',
        last_name: 'User'
      },
      '/auth/login': {
        email: 'test@example.com',
        password: 'TestPassword123!'
      },
      '/auth/refresh': {
        refresh_token: 'invalid-token'
      },
      '/oauth/token': {
        grant_type: 'authorization_code',
        code: 'invalid-code',
        client_id: 'test-client'
      },
      '/user/profile': {
        first_name: 'Updated',
        last_name: 'Name'
      },
      '/user/change-password': {
        current_password: 'old-password',
        new_password: 'NewPassword123!'
      },
      '/api-keys': {
        name: 'Test Key',
        scopes: ['read:profile']
      }
    };

    return testData[path] || {};
  }

  /**
   * Generate summary statistics
   */
  generateSummary() {
    const apiResults = this.results.api;
    const frontendResults = this.results.frontend;
    
    this.results.summary = {
      api: {
        total: apiResults.length,
        successful: apiResults.filter(r => r.success).length,
        failed: apiResults.filter(r => !r.success).length,
        averageResponseTime: this.calculateAverageResponseTime(apiResults)
      },
      frontend: {
        total: frontendResults.length,
        successful: frontendResults.filter(r => r.success).length,
        failed: frontendResults.filter(r => !r.success).length,
        averageResponseTime: this.calculateAverageResponseTime(frontendResults)
      }
    };

    // Calculate overall success rate
    const totalTests = apiResults.length + frontendResults.length;
    const totalSuccessful = this.results.summary.api.successful + this.results.summary.frontend.successful;
    
    this.results.summary.overall = {
      total: totalTests,
      successful: totalSuccessful,
      failed: totalTests - totalSuccessful,
      successRate: totalTests > 0 ? (totalSuccessful / totalTests) * 100 : 0
    };
  }

  /**
   * Calculate average response time
   */
  calculateAverageResponseTime(results) {
    if (results.length === 0) return 0;
    const totalTime = results.reduce((sum, r) => sum + r.responseTime, 0);
    return Math.round(totalTime / results.length);
  }

  /**
   * Generate validation report
   */
  async generateReport() {
    await fs.ensureDir('reports/validation');
    
    const jsonPath = 'reports/validation/url-validation-report.json';
    await fs.writeJson(jsonPath, this.results, { spaces: 2 });
    
    const htmlPath = 'reports/validation/url-validation-report.html';
    await fs.writeFile(htmlPath, this.generateHtmlReport());
    
    console.log('📊 URL validation reports generated:');
    console.log(`   JSON: ${jsonPath}`);
    console.log(`   HTML: ${htmlPath}`);
    
    return this.results;
  }

  /**
   * Generate HTML report
   */
  generateHtmlReport() {
    const { summary, api, frontend } = this.results;
    
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Validation Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2563eb; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { padding: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8fafc; padding: 15px; border-radius: 6px; border-left: 4px solid #2563eb; }
        .metric-value { font-size: 2em; font-weight: bold; color: #1e40af; }
        .metric-label { color: #64748b; font-size: 0.9em; margin-top: 5px; }
        .section { margin-bottom: 30px; }
        .test-result { border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 10px; overflow: hidden; }
        .test-header { padding: 12px 15px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; display: flex; justify-content: space-between; align-items: center; }
        .test-details { padding: 15px; display: none; }
        .success { border-left: 4px solid #10b981; }
        .failure { border-left: 4px solid #ef4444; }
        .method { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white; }
        .GET { background: #10b981; }
        .POST { background: #3b82f6; }
        .PUT { background: #f59e0b; }
        .DELETE { background: #ef4444; }
        .status-success { color: #10b981; font-weight: bold; }
        .status-failure { color: #ef4444; font-weight: bold; }
        .toggle { cursor: pointer; color: #2563eb; font-size: 0.9em; }
    </style>
    <script>
        function toggleDetails(id) {
            const details = document.getElementById(id);
            const toggle = details.previousElementSibling.querySelector('.toggle');
            if (details.style.display === 'none' || details.style.display === '') {
                details.style.display = 'block';
                toggle.textContent = '▼ Hide Details';
            } else {
                details.style.display = 'none';
                toggle.textContent = '▶ Show Details';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>URL Validation Report</h1>
            <p>Generated: ${new Date(this.results.timestamp).toLocaleString()}</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="metric">
                    <div class="metric-value">${summary.overall.total}</div>
                    <div class="metric-label">Total Tests</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${summary.overall.successful}</div>
                    <div class="metric-label">Successful</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${summary.overall.failed}</div>
                    <div class="metric-label">Failed</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${summary.overall.successRate.toFixed(1)}%</div>
                    <div class="metric-label">Success Rate</div>
                </div>
            </div>
            
            <div class="section">
                <h2>API Endpoints (${summary.api.successful}/${summary.api.total} passed)</h2>
                ${api.map((result, index) => `
                    <div class="test-result ${result.success ? 'success' : 'failure'}">
                        <div class="test-header" onclick="toggleDetails('api-${index}')">
                            <div>
                                <span class="method ${result.method}">${result.method}</span>
                                <strong>${result.path}</strong>
                            </div>
                            <div>
                                <span class="${result.success ? 'status-success' : 'status-failure'}">
                                    ${result.actualStatus} ${result.success ? '✅' : '❌'}
                                </span>
                                <span class="toggle">▶ Show Details</span>
                            </div>
                        </div>
                        <div id="api-${index}" class="test-details">
                            <p><strong>URL:</strong> ${result.url}</p>
                            <p><strong>Expected Status:</strong> ${JSON.stringify(result.expectedStatus)}</p>
                            <p><strong>Actual Status:</strong> ${result.actualStatus}</p>
                            <p><strong>Response Time:</strong> ${result.responseTime}ms</p>
                            <p><strong>Category:</strong> ${result.category}</p>
                            ${result.error ? `<p><strong>Error:</strong> ${result.error}</p>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
            
            <div class="section">
                <h2>Frontend Routes (${summary.frontend.successful}/${summary.frontend.total} passed)</h2>
                ${frontend.map((result, index) => `
                    <div class="test-result ${result.success ? 'success' : 'failure'}">
                        <div class="test-header" onclick="toggleDetails('frontend-${index}')">
                            <div>
                                <strong>${result.path}</strong>
                            </div>
                            <div>
                                <span class="${result.success ? 'status-success' : 'status-failure'}">
                                    ${result.actualStatus} ${result.success ? '✅' : '❌'}
                                </span>
                                <span class="toggle">▶ Show Details</span>
                            </div>
                        </div>
                        <div id="frontend-${index}" class="test-details">
                            <p><strong>URL:</strong> ${result.url}</p>
                            <p><strong>Expected Status:</strong> ${JSON.stringify(result.expectedStatus)}</p>
                            <p><strong>Actual Status:</strong> ${result.actualStatus}</p>
                            <p><strong>Response Time:</strong> ${result.responseTime}ms</p>
                            <p><strong>Category:</strong> ${result.category}</p>
                            <p><strong>Content Type:</strong> ${result.contentType || 'N/A'}</p>
                            ${result.error ? `<p><strong>Error:</strong> ${result.error}</p>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    </div>
</body>
</html>`;
  }

  /**
   * Run complete validation
   */
  async run() {
    console.log('🚀 Starting URL validation...');
    
    try {
      const endpoints = await this.loadEndpointDefinitions();
      
      await this.validateApiEndpoints(endpoints);
      await this.validateFrontendRoutes(endpoints);
      
      this.generateSummary();
      await this.generateReport();
      
      console.log(`\n📊 Validation Summary:`);
      console.log(`   Overall Success Rate: ${this.results.summary.overall.successRate.toFixed(1)}%`);
      console.log(`   API Endpoints: ${this.results.summary.api.successful}/${this.results.summary.api.total} passed`);
      console.log(`   Frontend Routes: ${this.results.summary.frontend.successful}/${this.results.summary.frontend.total} passed`);
      
      return this.results;
      
    } catch (error) {
      console.error('❌ Validation failed:', error.message);
      throw error;
    }
  }
}

// Run validation if called directly
if (require.main === module) {
  const validator = new URLValidator();
  validator.run()
    .then(results => {
      process.exit(results.summary.overall.failed > 0 ? 1 : 0);
    })
    .catch(error => {
      console.error('Validation error:', error);
      process.exit(1);
    });
}

module.exports = URLValidator;