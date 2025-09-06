import * as fs from 'fs-extra';
import * as path from 'path';

/**
 * Coverage Tracker
 * Tracks API endpoint coverage and generates comprehensive reports
 */
export class CoverageTracker {
  private testSuite: string;
  private endpoints: Map<string, EndpointCoverage> = new Map();
  private startTime: number;

  constructor(testSuite: string) {
    this.testSuite = testSuite;
    this.startTime = Date.now();
  }

  /**
   * Track an endpoint being tested
   */
  trackEndpoint(method: string, path: string, scenario: string = 'default'): void {
    const key = `${method} ${path}`;
    
    if (!this.endpoints.has(key)) {
      this.endpoints.set(key, {
        method,
        path,
        scenarios: new Map(),
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        responseTimeMs: [],
        statusCodes: new Map()
      });
    }

    const endpoint = this.endpoints.get(key)!;
    
    if (!endpoint.scenarios.has(scenario)) {
      endpoint.scenarios.set(scenario, {
        name: scenario,
        tested: true,
        requests: 0,
        responses: []
      });
    }
  }

  /**
   * Record response for an endpoint
   */
  async recordResponse(
    path: string, 
    statusCode: number, 
    responseBody: any,
    scenario: string = 'default',
    responseTimeMs?: number
  ): Promise<void> {
    // Find endpoint by path
    const endpoint = Array.from(this.endpoints.values())
      .find(ep => ep.path === path);

    if (!endpoint) {
      console.warn(`Endpoint not found for path: ${path}`);
      return;
    }

    // Update endpoint statistics
    endpoint.totalRequests++;
    
    if (statusCode >= 200 && statusCode < 400) {
      endpoint.successfulRequests++;
    } else {
      endpoint.failedRequests++;
    }

    // Track status codes
    const statusCount = endpoint.statusCodes.get(statusCode) || 0;
    endpoint.statusCodes.set(statusCode, statusCount + 1);

    // Track response time if provided
    if (responseTimeMs) {
      endpoint.responseTimeMs.push(responseTimeMs);
    }

    // Update scenario
    const scenarioData = endpoint.scenarios.get(scenario);
    if (scenarioData) {
      scenarioData.requests++;
      scenarioData.responses.push({
        statusCode,
        body: this.sanitizeResponseBody(responseBody),
        timestamp: new Date().toISOString()
      });
    }
  }

  /**
   * Generate comprehensive coverage report
   */
  async generateReport(): Promise<void> {
    const reportData = this.generateReportData();
    
    // Ensure reports directory exists
    await fs.ensureDir('reports/coverage');
    
    // Generate JSON report
    const jsonPath = `reports/coverage/${this.testSuite}-coverage.json`;
    await fs.writeJson(jsonPath, reportData, { spaces: 2 });

    // Generate HTML report
    const htmlPath = `reports/coverage/${this.testSuite}-coverage.html`;
    await fs.writeFile(htmlPath, this.generateHtmlReport(reportData));

    // Generate summary report
    const summaryPath = `reports/coverage/${this.testSuite}-summary.json`;
    await fs.writeJson(summaryPath, this.generateSummary(reportData), { spaces: 2 });

    console.log(`📊 Coverage reports generated:`);
    console.log(`   JSON: ${jsonPath}`);
    console.log(`   HTML: ${htmlPath}`);
    console.log(`   Summary: ${summaryPath}`);
  }

  /**
   * Generate report data
   */
  private generateReportData(): CoverageReport {
    const endpointsArray = Array.from(this.endpoints.values());
    
    return {
      testSuite: this.testSuite,
      timestamp: new Date().toISOString(),
      duration: Date.now() - this.startTime,
      summary: {
        totalEndpoints: endpointsArray.length,
        totalRequests: endpointsArray.reduce((sum, ep) => sum + ep.totalRequests, 0),
        successfulRequests: endpointsArray.reduce((sum, ep) => sum + ep.successfulRequests, 0),
        failedRequests: endpointsArray.reduce((sum, ep) => sum + ep.failedRequests, 0),
        averageResponseTime: this.calculateAverageResponseTime(endpointsArray)
      },
      endpoints: endpointsArray.map(ep => ({
        ...ep,
        scenarios: Array.from(ep.scenarios.values()),
        statusCodes: Object.fromEntries(ep.statusCodes),
        averageResponseTime: ep.responseTimeMs.length > 0 
          ? ep.responseTimeMs.reduce((a, b) => a + b, 0) / ep.responseTimeMs.length 
          : 0
      }))
    };
  }

  /**
   * Generate HTML report
   */
  private generateHtmlReport(reportData: CoverageReport): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Coverage Report - ${reportData.testSuite}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2563eb; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { padding: 20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric { background: #f8fafc; padding: 15px; border-radius: 6px; border-left: 4px solid #2563eb; }
        .metric-value { font-size: 2em; font-weight: bold; color: #1e40af; }
        .metric-label { color: #64748b; font-size: 0.9em; margin-top: 5px; }
        .endpoint { border: 1px solid #e2e8f0; border-radius: 6px; margin-bottom: 15px; overflow: hidden; }
        .endpoint-header { background: #f8fafc; padding: 15px; border-bottom: 1px solid #e2e8f0; }
        .endpoint-method { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .GET { background: #10b981; color: white; }
        .POST { background: #3b82f6; color: white; }
        .PUT { background: #f59e0b; color: white; }
        .DELETE { background: #ef4444; color: white; }
        .endpoint-details { padding: 15px; }
        .status-codes { display: flex; gap: 10px; flex-wrap: wrap; }
        .status-code { padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }
        .status-2xx { background: #10b981; color: white; }
        .status-4xx { background: #f59e0b; color: white; }
        .status-5xx { background: #ef4444; color: white; }
        .scenarios { margin-top: 10px; }
        .scenario { background: #f1f5f9; padding: 10px; margin: 5px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>API Coverage Report</h1>
            <p>${reportData.testSuite} - ${new Date(reportData.timestamp).toLocaleString()}</p>
            <p>Test Duration: ${Math.round(reportData.duration / 1000)}s</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="metric">
                    <div class="metric-value">${reportData.summary.totalEndpoints}</div>
                    <div class="metric-label">Total Endpoints</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${reportData.summary.totalRequests}</div>
                    <div class="metric-label">Total Requests</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${reportData.summary.successfulRequests}</div>
                    <div class="metric-label">Successful Requests</div>
                </div>
                <div class="metric">
                    <div class="metric-value">${reportData.summary.averageResponseTime.toFixed(0)}ms</div>
                    <div class="metric-label">Avg Response Time</div>
                </div>
            </div>
            
            <h2>Endpoint Coverage</h2>
            ${reportData.endpoints.map(endpoint => `
                <div class="endpoint">
                    <div class="endpoint-header">
                        <span class="endpoint-method ${endpoint.method}">${endpoint.method}</span>
                        <strong>${endpoint.path}</strong>
                    </div>
                    <div class="endpoint-details">
                        <p><strong>Requests:</strong> ${endpoint.totalRequests} (${endpoint.successfulRequests} successful, ${endpoint.failedRequests} failed)</p>
                        <p><strong>Average Response Time:</strong> ${endpoint.averageResponseTime.toFixed(0)}ms</p>
                        
                        <div class="status-codes">
                            ${Object.entries(endpoint.statusCodes).map(([code, count]) => 
                                `<span class="status-code status-${code.charAt(0)}xx">${code}: ${count}</span>`
                            ).join('')}
                        </div>
                        
                        <div class="scenarios">
                            <strong>Test Scenarios:</strong>
                            ${endpoint.scenarios.map(scenario => 
                                `<div class="scenario">
                                    <strong>${scenario.name}:</strong> ${scenario.requests} requests
                                </div>`
                            ).join('')}
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    </div>
</body>
</html>`;
  }

  /**
   * Generate summary statistics
   */
  private generateSummary(reportData: CoverageReport): CoverageSummary {
    const endpointsByMethod = reportData.endpoints.reduce((acc, ep) => {
      acc[ep.method] = (acc[ep.method] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const statusCodeDistribution = reportData.endpoints.reduce((acc, ep) => {
      Object.entries(ep.statusCodes).forEach(([code, count]) => {
        acc[code] = (acc[code] || 0) + (count as number);
      });
      return acc;
    }, {} as Record<string, number>);

    return {
      testSuite: reportData.testSuite,
      timestamp: reportData.timestamp,
      summary: reportData.summary,
      endpointsByMethod,
      statusCodeDistribution,
      coverage: {
        totalEndpoints: reportData.endpoints.length,
        testedEndpoints: reportData.endpoints.filter(ep => ep.totalRequests > 0).length,
        coveragePercentage: reportData.endpoints.length > 0 
          ? (reportData.endpoints.filter(ep => ep.totalRequests > 0).length / reportData.endpoints.length) * 100 
          : 0
      }
    };
  }

  private calculateAverageResponseTime(endpoints: EndpointCoverage[]): number {
    const allResponseTimes = endpoints.flatMap(ep => ep.responseTimeMs);
    return allResponseTimes.length > 0 
      ? allResponseTimes.reduce((a, b) => a + b, 0) / allResponseTimes.length 
      : 0;
  }

  private sanitizeResponseBody(body: any): any {
    if (typeof body === 'string' && body.length > 1000) {
      return body.substring(0, 1000) + '... (truncated)';
    }
    return body;
  }
}

// Type definitions
interface EndpointCoverage {
  method: string;
  path: string;
  scenarios: Map<string, Scenario>;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  responseTimeMs: number[];
  statusCodes: Map<number, number>;
}

interface Scenario {
  name: string;
  tested: boolean;
  requests: number;
  responses: Response[];
}

interface Response {
  statusCode: number;
  body: any;
  timestamp: string;
}

interface CoverageReport {
  testSuite: string;
  timestamp: string;
  duration: number;
  summary: {
    totalEndpoints: number;
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
  };
  endpoints: any[];
}

interface CoverageSummary {
  testSuite: string;
  timestamp: string;
  summary: CoverageReport['summary'];
  endpointsByMethod: Record<string, number>;
  statusCodeDistribution: Record<string, number>;
  coverage: {
    totalEndpoints: number;
    testedEndpoints: number;
    coveragePercentage: number;
  };
}