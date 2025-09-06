import { test, expect, Page } from '@playwright/test';
import fs from 'fs';
import path from 'path';

export interface TestResult {
  name: string;
  status: 'passed' | 'failed' | 'skipped';
  duration: number;
  error?: string;
  screenshot?: string;
}

export interface TestSuite {
  name: string;
  tests: TestResult[];
  coverage: number;
  startTime: Date;
  endTime?: Date;
}

export class TestPlanExecutor {
  private suites: TestSuite[] = [];
  private currentSuite?: TestSuite;
  
  startSuite(name: string): void {
    this.currentSuite = {
      name,
      tests: [],
      coverage: 0,
      startTime: new Date()
    };
  }

  async executeTest(
    name: string, 
    testFn: () => Promise<void>,
    page?: Page
  ): Promise<TestResult> {
    const startTime = Date.now();
    let result: TestResult;

    try {
      await testFn();
      result = {
        name,
        status: 'passed',
        duration: Date.now() - startTime
      };
    } catch (error) {
      const screenshot = page ? await this.captureEvidence(page, name) : undefined;
      result = {
        name,
        status: 'failed',
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        screenshot
      };
    }

    this.currentSuite?.tests.push(result);
    return result;
  }

  finishSuite(): TestSuite | undefined {
    if (!this.currentSuite) return undefined;
    
    this.currentSuite.endTime = new Date();
    this.currentSuite.coverage = this.calculateCoverage(this.currentSuite);
    this.suites.push(this.currentSuite);
    
    const suite = this.currentSuite;
    this.currentSuite = undefined;
    return suite;
  }

  private calculateCoverage(suite: TestSuite): number {
    const passed = suite.tests.filter(t => t.status === 'passed').length;
    return suite.tests.length > 0 ? (passed / suite.tests.length) * 100 : 0;
  }

  private async captureEvidence(page: Page, testName: string): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${testName}-${timestamp}.png`;
    const filepath = path.join('evidence', filename);
    
    await page.screenshot({ path: filepath, fullPage: true });
    return filepath;
  }

  generateReport(): TestReport {
    return new TestReport(this.suites);
  }
}

export class TestReport {
  constructor(private suites: TestSuite[]) {}

  generateHTML(): string {
    const totalTests = this.suites.reduce((sum, s) => sum + s.tests.length, 0);
    const passedTests = this.suites.reduce((sum, s) => 
      sum + s.tests.filter(t => t.status === 'passed').length, 0);
    const overallCoverage = totalTests > 0 ? (passedTests / totalTests) * 100 : 0;

    return `
<!DOCTYPE html>
<html>
<head>
    <title>E2E Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 5px; }
        .suite { margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }
        .suite-header { background: #e9e9e9; padding: 10px; font-weight: bold; }
        .test { padding: 8px; border-bottom: 1px solid #eee; }
        .passed { color: green; }
        .failed { color: red; }
        .coverage { font-weight: bold; }
    </style>
</head>
<body>
    <h1>E2E Test Execution Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Tests: ${totalTests}</p>
        <p>Passed: ${passedTests}</p>
        <p>Failed: ${totalTests - passedTests}</p>
        <p class="coverage">Overall Coverage: ${overallCoverage.toFixed(1)}%</p>
        <p>Generated: ${new Date().toISOString()}</p>
    </div>

    ${this.suites.map(suite => `
    <div class="suite">
        <div class="suite-header">
            ${suite.name} - Coverage: ${suite.coverage.toFixed(1)}%
        </div>
        ${suite.tests.map(test => `
        <div class="test ${test.status}">
            <strong>${test.name}</strong> - ${test.status} (${test.duration}ms)
            ${test.error ? `<br><small>Error: ${test.error}</small>` : ''}
            ${test.screenshot ? `<br><small>Screenshot: ${test.screenshot}</small>` : ''}
        </div>
        `).join('')}
    </div>
    `).join('')}
</body>
</html>`;
  }

  saveReport(): void {
    const html = this.generateHTML();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `test-report-${timestamp}.html`;
    
    fs.writeFileSync(path.join('reports', filename), html);
    console.log(`Test report saved: ${filename}`);
  }

  getQualityGates(): QualityGateResult[] {
    const results: QualityGateResult[] = [];
    
    // Coverage gate
    const overallCoverage = this.calculateOverallCoverage();
    results.push({
      name: 'Coverage',
      passed: overallCoverage >= 85,
      value: overallCoverage,
      threshold: 85
    });

    // Security tests gate
    const securitySuite = this.suites.find(s => s.name.includes('Security'));
    if (securitySuite) {
      results.push({
        name: 'Security',
        passed: securitySuite.coverage === 100,
        value: securitySuite.coverage,
        threshold: 100
      });
    }

    return results;
  }

  private calculateOverallCoverage(): number {
    const totalTests = this.suites.reduce((sum, s) => sum + s.tests.length, 0);
    const passedTests = this.suites.reduce((sum, s) => 
      sum + s.tests.filter(t => t.status === 'passed').length, 0);
    return totalTests > 0 ? (passedTests / totalTests) * 100 : 0;
  }
}

export interface QualityGateResult {
  name: string;
  passed: boolean;
  value: number;
  threshold: number;
}
