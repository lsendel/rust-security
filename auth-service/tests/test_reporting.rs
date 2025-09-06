//! Structured Test Result Reporting and Analytics
//!
//! Provides comprehensive test result analysis, reporting, and trend analysis
//! to help identify test quality issues, performance regressions, and coverage gaps.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Comprehensive test report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestReport {
    pub report_id: String,
    pub timestamp: u64,
    pub test_suite: String,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub timed_out: usize,
    pub total_duration: Duration,
    pub test_results: Vec<TestResult>,
    pub environment_info: EnvironmentInfo,
    pub coverage_summary: Option<CoverageSummary>,
    pub performance_metrics: Option<PerformanceMetrics>,
}

/// Individual test result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestResult {
    pub test_name: String,
    pub module: String,
    pub category: String,
    pub status: TestStatus,
    pub duration: Duration,
    pub error_message: Option<String>,
    pub output: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

/// Test execution status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum TestStatus {
    Passed,
    Failed,
    Skipped,
    TimedOut,
    Panicked,
}

/// Environment information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnvironmentInfo {
    pub rust_version: String,
    pub cargo_version: String,
    pub os: String,
    pub cpu_count: usize,
    pub memory_gb: Option<u64>,
    pub git_commit: Option<String>,
    pub branch: Option<String>,
}

/// Coverage summary (integrated with coverage_reporting)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageSummary {
    pub line_coverage: f64,
    pub function_coverage: f64,
    pub branch_coverage: f64,
    pub total_files: usize,
    pub uncovered_lines: Vec<String>,
}

/// Performance metrics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PerformanceMetrics {
    pub average_test_duration: Duration,
    pub slowest_tests: Vec<(String, Duration)>,
    pub fastest_tests: Vec<(String, Duration)>,
    pub memory_usage_peak: Option<u64>,
    pub flaky_tests: Vec<String>,
}

/// Test analytics and insights
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestAnalytics {
    pub report: TestReport,
    pub insights: Vec<TestInsight>,
    pub recommendations: Vec<String>,
    pub trends: Option<TestTrends>,
    pub quality_score: f64,
}

/// Individual test insight
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestInsight {
    pub insight_type: InsightType,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_tests: Vec<String>,
    pub suggested_fix: Option<String>,
}

/// Type of insight
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum InsightType {
    Performance,
    Reliability,
    Coverage,
    Quality,
    Maintenance,
}

/// Severity level
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Test trend analysis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestTrends {
    pub baseline_report: Option<TestReport>,
    pub pass_rate_change: f64,
    pub duration_change: f64,
    pub new_failures: Vec<String>,
    pub fixed_failures: Vec<String>,
    pub new_tests: Vec<String>,
}

/// Test report generator
pub struct TestReportGenerator {
    reports: Vec<TestReport>,
    output_dir: PathBuf,
    baseline_reports: HashMap<String, TestReport>,
}

impl TestReportGenerator {
    #[must_use]
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            reports: Vec::new(),
            output_dir,
            baseline_reports: HashMap::new(),
        }
    }

    /// Generate a new test report
    pub fn generate_report(
        &mut self,
        test_suite: &str,
        test_results: Vec<TestResult>,
        environment_info: EnvironmentInfo,
    ) -> Result<TestReport, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let total_tests = test_results.len();
        let passed = test_results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Passed))
            .count();
        let failed = test_results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Failed))
            .count();
        let skipped = test_results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Skipped))
            .count();
        let timed_out = test_results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::TimedOut))
            .count();

        let total_duration = test_results.iter().map(|r| r.duration).sum();

        let report = TestReport {
            report_id: format!("{}_{}", test_suite, timestamp),
            timestamp,
            test_suite: test_suite.to_string(),
            total_tests,
            passed,
            failed,
            skipped,
            timed_out,
            total_duration,
            test_results,
            environment_info,
            coverage_summary: None,
            performance_metrics: None,
        };

        self.reports.push(report.clone());
        Ok(report)
    }

    /// Add coverage information to a report
    pub fn add_coverage(
        &mut self,
        report_id: &str,
        coverage: CoverageSummary,
    ) -> Result<(), String> {
        if let Some(report) = self.reports.iter_mut().find(|r| r.report_id == report_id) {
            report.coverage_summary = Some(coverage);
            Ok(())
        } else {
            Err(format!("Report with ID {} not found", report_id))
        }
    }

    /// Add performance metrics to a report
    pub fn add_performance_metrics(
        &mut self,
        report_id: &str,
        metrics: PerformanceMetrics,
    ) -> Result<(), String> {
        if let Some(report) = self.reports.iter_mut().find(|r| r.report_id == report_id) {
            report.performance_metrics = Some(metrics);
            Ok(())
        } else {
            Err(format!("Report with ID {} not found", report_id))
        }
    }

    /// Generate comprehensive analytics
    pub fn generate_analytics(&self, report: &TestReport) -> TestAnalytics {
        let insights = self.analyze_test_results(report);
        let recommendations = self.generate_recommendations(report, &insights);
        let trends = self.calculate_trends(report);
        let quality_score = self.calculate_quality_score(report);

        TestAnalytics {
            report: report.clone(),
            insights,
            recommendations,
            trends,
            quality_score,
        }
    }

    /// Export report in various formats
    pub fn export_report(
        &self,
        analytics: &TestAnalytics,
        format: ExportFormat,
    ) -> Result<(), String> {
        fs::create_dir_all(&self.output_dir)
            .map_err(|e| format!("Failed to create output directory: {e}"))?;

        match format {
            ExportFormat::JSON => self.export_json(analytics)?,
            ExportFormat::HTML => self.export_html(analytics)?,
            ExportFormat::JUnit => self.export_junit(analytics)?,
            ExportFormat::Markdown => self.export_markdown(analytics)?,
        }

        Ok(())
    }

    fn analyze_test_results(&self, report: &TestReport) -> Vec<TestInsight> {
        let mut insights = Vec::new();

        // Analyze test failures
        let failed_tests: Vec<_> = report
            .test_results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Failed))
            .collect();

        if !failed_tests.is_empty() {
            insights.push(TestInsight {
                insight_type: InsightType::Reliability,
                severity: Severity::Critical,
                title: "Test Failures Detected".to_string(),
                description: format!(
                    "{} tests failed out of {}",
                    failed_tests.len(),
                    report.total_tests
                ),
                affected_tests: failed_tests.iter().map(|t| t.test_name.clone()).collect(),
                suggested_fix: Some("Review test failures and fix underlying issues".to_string()),
            });
        }

        // Analyze slow tests
        let avg_duration = if report.total_tests > 0 {
            report.total_duration / report.total_tests as u32
        } else {
            Duration::from_secs(0)
        };

        let slow_tests: Vec<_> = report
            .test_results
            .iter()
            .filter(|r| r.duration > avg_duration * 3)
            .collect();

        if !slow_tests.is_empty() {
            insights.push(TestInsight {
                insight_type: InsightType::Performance,
                severity: Severity::Medium,
                title: "Slow Tests Detected".to_string(),
                description: format!(
                    "{} tests are significantly slower than average",
                    slow_tests.len()
                ),
                affected_tests: slow_tests.iter().map(|t| t.test_name.clone()).collect(),
                suggested_fix: Some(
                    "Optimize slow tests or consider moving to integration test suite".to_string(),
                ),
            });
        }

        // Analyze flaky tests (based on metadata)
        let flaky_tests: Vec<_> = report
            .test_results
            .iter()
            .filter(|r| r.metadata.contains_key("flaky"))
            .collect();

        if !flaky_tests.is_empty() {
            insights.push(TestInsight {
                insight_type: InsightType::Reliability,
                severity: Severity::High,
                title: "Flaky Tests Detected".to_string(),
                description: format!("{} tests have been marked as flaky", flaky_tests.len()),
                affected_tests: flaky_tests.iter().map(|t| t.test_name.clone()).collect(),
                suggested_fix: Some(
                    "Investigate and fix flaky tests to ensure reliable CI/CD".to_string(),
                ),
            });
        }

        insights
    }

    fn generate_recommendations(
        &self,
        report: &TestReport,
        insights: &[TestInsight],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        let pass_rate = if report.total_tests > 0 {
            (report.passed as f64 / report.total_tests as f64) * 100.0
        } else {
            0.0
        };

        if pass_rate < 95.0 {
            recommendations.push(format!(
                "Improve test reliability - current pass rate is {:.1}%",
                pass_rate
            ));
        }

        if report.timed_out > 0 {
            recommendations.push("Review test timeouts and optimize slow tests".to_string());
        }

        if insights
            .iter()
            .any(|i| matches!(i.insight_type, InsightType::Performance))
        {
            recommendations
                .push("Consider parallel test execution for better performance".to_string());
        }

        if let Some(coverage) = &report.coverage_summary {
            if coverage.line_coverage < 80.0 {
                recommendations
                    .push("Increase test coverage to at least 80% line coverage".to_string());
            }
        }

        recommendations
    }

    fn calculate_trends(&self, report: &TestReport) -> Option<TestTrends> {
        let baseline = self.baseline_reports.get(&report.test_suite)?;

        let current_pass_rate = if report.total_tests > 0 {
            (report.passed as f64 / report.total_tests as f64) * 100.0
        } else {
            0.0
        };

        let baseline_pass_rate = if baseline.total_tests > 0 {
            (baseline.passed as f64 / baseline.total_tests as f64) * 100.0
        } else {
            0.0
        };

        let current_test_names: HashSet<_> = report
            .test_results
            .iter()
            .map(|r| r.test_name.as_str())
            .collect();

        let baseline_test_names: HashSet<_> = baseline
            .test_results
            .iter()
            .map(|r| r.test_name.as_str())
            .collect();

        let new_tests: Vec<String> = current_test_names
            .difference(&baseline_test_names)
            .map(std::string::ToString::to_string)
            .collect();

        let _removed_tests: Vec<String> = baseline_test_names
            .difference(&current_test_names)
            .map(std::string::ToString::to_string)
            .collect();

        Some(TestTrends {
            baseline_report: Some(baseline.clone()),
            pass_rate_change: current_pass_rate - baseline_pass_rate,
            duration_change: report.total_duration.as_secs_f64()
                - baseline.total_duration.as_secs_f64(),
            new_failures: Vec::new(),   // Would need more complex analysis
            fixed_failures: Vec::new(), // Would need more complex analysis
            new_tests,
        })
    }

    fn calculate_quality_score(&self, report: &TestReport) -> f64 {
        let mut score = 0.0;

        // Base score from pass rate
        let pass_rate = if report.total_tests > 0 {
            (report.passed as f64 / report.total_tests as f64) * 100.0
        } else {
            0.0
        };
        score += pass_rate * 0.4; // 40% weight

        // Coverage score
        if let Some(coverage) = &report.coverage_summary {
            score += coverage.line_coverage * 0.3; // 30% weight
            score += coverage.function_coverage * 0.2; // 20% weight
            score += coverage.branch_coverage * 0.1; // 10% weight
        } else {
            score += 70.0 * 0.6; // Default coverage assumption
        }

        // Penalty for failures and timeouts
        let penalty = (report.failed + report.timed_out) as f64 * 5.0;
        score - penalty.min(50.0) // Max penalty of 50 points
    }

    fn export_json(&self, analytics: &TestAnalytics) -> Result<(), String> {
        let json_path = self.output_dir.join("test_report.json");
        let json_content = serde_json::to_string_pretty(analytics)
            .map_err(|e| format!("Failed to serialize analytics: {e}"))?;
        fs::write(json_path, json_content).map_err(|e| format!("Failed to write JSON report: {e}"))
    }

    fn export_html(&self, analytics: &TestAnalytics) -> Result<(), String> {
        let html_path = self.output_dir.join("test_report.html");
        let html_content = self.generate_html_report(analytics);
        fs::write(html_path, html_content).map_err(|e| format!("Failed to write HTML report: {e}"))
    }

    fn export_junit(&self, analytics: &TestAnalytics) -> Result<(), String> {
        let junit_path = self.output_dir.join("junit_report.xml");
        let junit_content = self.generate_junit_report(analytics);
        fs::write(junit_path, junit_content)
            .map_err(|e| format!("Failed to write JUnit report: {e}"))
    }

    fn export_markdown(&self, analytics: &TestAnalytics) -> Result<(), String> {
        let md_path = self.output_dir.join("test_report.md");
        let md_content = self.generate_markdown_report(analytics);
        fs::write(md_path, md_content).map_err(|e| format!("Failed to write Markdown report: {e}"))
    }

    fn generate_html_report(&self, analytics: &TestAnalytics) -> String {
        let report = &analytics.report;
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Test Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .passed {{ color: #28a745; }}
        .failed {{ color: #dc3545; }}
        .skipped {{ color: #ffc107; }}
        .insight {{ margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
        .critical {{ border-color: #dc3545; background: #f8d7da; }}
        .high {{ border-color: #fd7e14; background: #fff3cd; }}
        .medium {{ border-color: #ffc107; background: #fff3cd; }}
    </style>
</head>
<body>
    <h1>Test Report - {}</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Tests: {}</p>
        <p class="passed">Passed: {} ({:.1}%)</p>
        <p class="failed">Failed: {}</p>
        <p class="skipped">Skipped: {}</p>
        <p>Timed Out: {}</p>
        <p>Total Duration: {:.2}s</p>
        <p>Quality Score: {:.1}/100</p>
    </div>

    <h2>Insights</h2>
    {}
</body>
</html>"#,
            report.test_suite,
            report.test_suite,
            report.total_tests,
            report.passed,
            if report.total_tests > 0 {
                (report.passed as f64 / report.total_tests as f64) * 100.0
            } else {
                0.0
            },
            report.failed,
            report.skipped,
            report.timed_out,
            report.total_duration.as_secs_f64(),
            analytics.quality_score,
            analytics
                .insights
                .iter()
                .map(|insight| {
                    let severity_class = match insight.severity {
                        Severity::Critical => "critical",
                        Severity::High => "high",
                        Severity::Medium => "medium",
                        _ => "",
                    };
                    format!(
                        r#"<div class="insight {}">
                    <h3>{}</h3>
                    <p>{}</p>
                    <p><strong>Affected Tests:</strong> {}</p>
                    {}
                </div>"#,
                        severity_class,
                        insight.title,
                        insight.description,
                        insight.affected_tests.join(", "),
                        insight
                            .suggested_fix
                            .as_ref()
                            .map_or(String::new(), |fix| format!(
                                "<p><strong>Suggested Fix:</strong> {}</p>",
                                fix
                            ))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    fn generate_junit_report(&self, analytics: &TestAnalytics) -> String {
        let report = &analytics.report;
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
    <testsuite name="{}" tests="{}" failures="{}" skipped="{}" time="{:.3}">
        {}
    </testsuite>
</testsuites>"#,
            report.test_suite,
            report.total_tests,
            report.failed,
            report.skipped,
            report.total_duration.as_secs_f64(),
            report
                .test_results
                .iter()
                .map(|result| {
                    let status = match result.status {
                        TestStatus::Passed => "passed",
                        TestStatus::Failed => "failed",
                        TestStatus::Skipped => "skipped",
                        TestStatus::TimedOut => "error",
                        TestStatus::Panicked => "error",
                    };
                    format!(
                        r#"<testcase name="{}" classname="{}" time="{:.3}" status="{}">
                        {}
                    </testcase>"#,
                        result.test_name,
                        result.module,
                        result.duration.as_secs_f64(),
                        status,
                        result
                            .error_message
                            .as_ref()
                            .map_or(String::new(), |msg| format!(
                                "<failure message=\"{}\">{}</failure>",
                                msg, msg
                            ))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    fn generate_markdown_report(&self, analytics: &TestAnalytics) -> String {
        let report = &analytics.report;
        format!(
            r#"# Test Report - {}

Generated: {}

## Summary

- **Total Tests**: {}
- **Passed**: {} ({:.1}%)
- **Failed**: {}
- **Skipped**: {}
- **Timed Out**: {}
- **Total Duration**: {:.2}s
- **Quality Score**: {:.1}/100

## Insights

{}
"#,
            report.test_suite,
            chrono::DateTime::from_timestamp(report.timestamp as i64, 0)
                .unwrap_or_default()
                .format("%Y-%m-%d %H:%M:%S UTC"),
            report.total_tests,
            report.passed,
            if report.total_tests > 0 {
                (report.passed as f64 / report.total_tests as f64) * 100.0
            } else {
                0.0
            },
            report.failed,
            report.skipped,
            report.timed_out,
            report.total_duration.as_secs_f64(),
            analytics.quality_score,
            analytics
                .insights
                .iter()
                .map(|insight| {
                    format!(
                        "### {}\n\n**Severity**: {:?}\n\n{}\n\n**Affected Tests**: {}\n\n{}",
                        insight.title,
                        insight.severity,
                        insight.description,
                        insight.affected_tests.join(", "),
                        insight
                            .suggested_fix
                            .as_ref()
                            .map_or(String::new(), |fix| format!("**Suggested Fix**: {}", fix))
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n---\n\n")
        )
    }
}

/// Export format options
#[derive(Debug, Clone)]
pub enum ExportFormat {
    JSON,
    HTML,
    JUnit,
    Markdown,
}

/// Test result collector for integrating with test frameworks
#[derive(Default)]
pub struct TestResultCollector {
    results: Vec<TestResult>,
    start_times: HashMap<String, std::time::Instant>,
}

impl TestResultCollector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            start_times: HashMap::new(),
        }
    }

    /// Start timing a test
    pub fn start_test(&mut self, test_name: &str, _module: &str, _category: &str) {
        self.start_times
            .insert(test_name.to_string(), std::time::Instant::now());
    }

    /// Record a test result
    pub fn record_result(
        &mut self,
        test_name: &str,
        _module: &str,
        _category: &str,
        status: TestStatus,
        error_message: Option<String>,
        output: Option<String>,
    ) {
        let duration = self
            .start_times
            .get(test_name)
            .map(|start| start.elapsed())
            .unwrap_or(Duration::from_secs(0));

        let result = TestResult {
            test_name: test_name.to_string(),
            module: _module.to_string(),
            category: _category.to_string(),
            status,
            duration,
            error_message,
            output,
            tags: Vec::new(),
            metadata: HashMap::new(),
        };

        self.results.push(result);
        self.start_times.remove(test_name);
    }

    /// Get collected results
    #[must_use]
    pub fn get_results(&self) -> &[TestResult] {
        &self.results
    }

    /// Clear all results
    pub fn clear(&mut self) {
        self.results.clear();
        self.start_times.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test_report_generation() {
        let mut generator = TestReportGenerator::new(std::env::temp_dir().join("test_reports"));

        let test_results = vec![
            TestResult {
                test_name: "test_passed".to_string(),
                module: "auth".to_string(),
                category: "unit".to_string(),
                status: TestStatus::Passed,
                duration: Duration::from_millis(100),
                error_message: None,
                output: None,
                tags: vec!["fast".to_string()],
                metadata: HashMap::new(),
            },
            TestResult {
                test_name: "test_failed".to_string(),
                module: "auth".to_string(),
                category: "unit".to_string(),
                status: TestStatus::Failed,
                duration: Duration::from_millis(50),
                error_message: Some("Assertion failed".to_string()),
                output: None,
                tags: Vec::new(),
                metadata: HashMap::new(),
            },
        ];

        let env_info = EnvironmentInfo {
            rust_version: "1.70.0".to_string(),
            cargo_version: "1.70.0".to_string(),
            os: "linux".to_string(),
            cpu_count: 4,
            memory_gb: Some(8),
            git_commit: None,
            branch: None,
        };

        let report = generator
            .generate_report("unit_tests", test_results, env_info)
            .unwrap();

        assert_eq!(report.test_suite, "unit_tests");
        assert_eq!(report.total_tests, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
    }

    #[test]
    fn test_quality_score_calculation() {
        let generator = TestReportGenerator::new(std::env::temp_dir().join("test_reports"));

        let report = TestReport {
            report_id: "test".to_string(),
            timestamp: 1000,
            test_suite: "test_suite".to_string(),
            total_tests: 10,
            passed: 8,
            failed: 2,
            skipped: 0,
            timed_out: 0,
            total_duration: Duration::from_secs(1),
            test_results: Vec::new(),
            environment_info: EnvironmentInfo {
                rust_version: "1.70.0".to_string(),
                cargo_version: "1.70.0".to_string(),
                os: "linux".to_string(),
                cpu_count: 4,
                memory_gb: Some(8),
                git_commit: None,
                branch: None,
            },
            coverage_summary: Some(CoverageSummary {
                line_coverage: 85.0,
                function_coverage: 90.0,
                branch_coverage: 80.0,
                total_files: 10,
                uncovered_lines: Vec::new(),
            }),
            performance_metrics: None,
        };

        let quality_score = generator.calculate_quality_score(&report);
        assert!(quality_score > 70.0); // Should be a decent score
    }

    #[test]
    fn test_test_result_collector() {
        let mut collector = TestResultCollector::default();

        collector.start_test("test1", "test", "unit");
        collector.record_result(
            "test1",
            "auth",
            "unit",
            TestStatus::Passed,
            None,
            Some("Test output".to_string()),
        );

        let results = collector.get_results();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].test_name, "test1");
        assert!(matches!(results[0].status, TestStatus::Passed));
    }
}
