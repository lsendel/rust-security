//! Test Coverage Reporting and Analysis
//!
//! Provides comprehensive test coverage measurement, reporting, and analysis
//! including line coverage, branch coverage, and coverage trends over time.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Coverage data structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageData {
    pub timestamp: u64,
    pub test_run_id: String,
    pub files: HashMap<String, FileCoverage>,
    pub summary: CoverageSummary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileCoverage {
    pub file_path: String,
    pub total_lines: usize,
    pub covered_lines: usize,
    pub executable_lines: usize,
    pub functions: Vec<FunctionCoverage>,
    pub branches: Vec<BranchCoverage>,
    pub line_coverage: HashMap<usize, bool>, // Line number -> covered
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionCoverage {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub covered: bool,
    pub execution_count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BranchCoverage {
    pub line: usize,
    pub branch_type: String,
    pub covered: bool,
    pub true_count: u64,
    pub false_count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageSummary {
    pub total_files: usize,
    pub total_lines: usize,
    pub covered_lines: usize,
    pub total_functions: usize,
    pub covered_functions: usize,
    pub total_branches: usize,
    pub covered_branches: usize,
    pub line_coverage_percentage: f64,
    pub function_coverage_percentage: f64,
    pub branch_coverage_percentage: f64,
}

/// Coverage analyzer and reporter
pub struct CoverageAnalyzer {
    coverage_data: Option<CoverageData>,
    baseline_data: Option<CoverageData>,
    output_dir: PathBuf,
}

impl CoverageAnalyzer {
    #[must_use]
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            coverage_data: None,
            baseline_data: None,
            output_dir,
        }
    }

    /// Load coverage data from various formats
    pub fn load_coverage_data(&mut self, format: CoverageFormat, data: &str) -> Result<(), String> {
        let coverage_data = match format {
            CoverageFormat::LCOV => self.parse_lcov(data)?,
            CoverageFormat::Cobertura => self.parse_cobertura(data)?,
            CoverageFormat::JSON => self.parse_json(data)?,
        };

        self.coverage_data = Some(coverage_data);
        Ok(())
    }

    /// Load baseline coverage data for comparison
    pub fn load_baseline(&mut self, baseline_path: &Path) -> Result<(), String> {
        if baseline_path.exists() {
            let data = fs::read_to_string(baseline_path)
                .map_err(|e| format!("Failed to read baseline file: {e}"))?;
            let baseline: CoverageData = serde_json::from_str(&data)
                .map_err(|e| format!("Failed to parse baseline data: {e}"))?;
            self.baseline_data = Some(baseline);
        }
        Ok(())
    }

    /// Generate comprehensive coverage report
    pub fn generate_report(&self) -> Result<CoverageReport, String> {
        let coverage_data = self
            .coverage_data
            .as_ref()
            .ok_or("No coverage data loaded")?;

        let mut report = CoverageReport {
            timestamp: coverage_data.timestamp,
            summary: coverage_data.summary.clone(),
            file_reports: Vec::new(),
            trends: Vec::new(),
            recommendations: Vec::new(),
        };

        // Generate file-specific reports
        for (file_path, file_coverage) in &coverage_data.files {
            let file_report = self.generate_file_report(file_path, file_coverage);
            report.file_reports.push(file_report);
        }

        // Calculate trends if baseline exists
        if let Some(baseline) = &self.baseline_data {
            report.trends = self.calculate_trends(coverage_data, baseline);
        }

        // Generate recommendations
        report.recommendations = self.generate_recommendations(coverage_data);

        Ok(report)
    }

    /// Export coverage report to various formats
    pub fn export_report(
        &self,
        report: &CoverageReport,
        format: ExportFormat,
    ) -> Result<(), String> {
        fs::create_dir_all(&self.output_dir)
            .map_err(|e| format!("Failed to create output directory: {e}"))?;

        match format {
            ExportFormat::HTML => self.export_html(report)?,
            ExportFormat::JSON => self.export_json(report)?,
            ExportFormat::Markdown => self.export_markdown(report)?,
            ExportFormat::Cobertura => self.export_cobertura(report)?,
        }

        Ok(())
    }

    fn parse_lcov(&self, data: &str) -> Result<CoverageData, String> {
        // Basic LCOV parser - in a real implementation, this would be more comprehensive
        let files = HashMap::new();
        let mut _current_file: Option<String> = None;

        for line in data.lines() {
            if let Some(_file) = line.strip_prefix("SF:") {
                _current_file = Some(_file.to_string());
            } else if line.starts_with("LF:") {
                // Total lines
            } else if line.starts_with("LH:") {
                // Hit lines
            } else if line == "end_of_record" {
                _current_file = None;
            }
        }

        // Create basic coverage data structure
        let summary = CoverageSummary {
            total_files: files.len(),
            total_lines: 0,
            covered_lines: 0,
            total_functions: 0,
            covered_functions: 0,
            total_branches: 0,
            covered_branches: 0,
            line_coverage_percentage: 0.0,
            function_coverage_percentage: 0.0,
            branch_coverage_percentage: 0.0,
        };

        Ok(CoverageData {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            test_run_id: format!("lcov_{}", chrono::Utc::now().timestamp()),
            files,
            summary,
        })
    }

    fn parse_cobertura(&self, _data: &str) -> Result<CoverageData, String> {
        // Placeholder for Cobertura XML parsing
        Err("Cobertura parsing not implemented".to_string())
    }

    fn parse_json(&self, data: &str) -> Result<CoverageData, String> {
        serde_json::from_str(data).map_err(|e| format!("Failed to parse JSON coverage data: {e}"))
    }

    fn generate_file_report(&self, file_path: &str, file_coverage: &FileCoverage) -> FileReport {
        let uncovered_lines: Vec<usize> = file_coverage
            .line_coverage
            .iter()
            .filter_map(|(line, &covered)| if !covered { Some(*line) } else { None })
            .collect();

        let low_coverage_functions: Vec<&FunctionCoverage> = file_coverage
            .functions
            .iter()
            .filter(|f| !f.covered)
            .collect();

        FileReport {
            file_path: file_path.to_string(),
            line_coverage: file_coverage.covered_lines as f64
                / file_coverage.executable_lines.max(1) as f64
                * 100.0,
            function_coverage: file_coverage.functions.iter().filter(|f| f.covered).count() as f64
                / file_coverage.functions.len().max(1) as f64
                * 100.0,
            branch_coverage: file_coverage.branches.iter().filter(|b| b.covered).count() as f64
                / file_coverage.branches.len().max(1) as f64
                * 100.0,
            uncovered_lines,
            low_coverage_functions: low_coverage_functions.into_iter().cloned().collect(),
            total_lines: file_coverage.total_lines,
            executable_lines: file_coverage.executable_lines,
        }
    }

    fn calculate_trends(
        &self,
        current: &CoverageData,
        baseline: &CoverageData,
    ) -> Vec<CoverageTrend> {
        vec![
            CoverageTrend {
                metric: "Line Coverage".to_string(),
                current_value: current.summary.line_coverage_percentage,
                baseline_value: baseline.summary.line_coverage_percentage,
                change: current.summary.line_coverage_percentage
                    - baseline.summary.line_coverage_percentage,
            },
            CoverageTrend {
                metric: "Function Coverage".to_string(),
                current_value: current.summary.function_coverage_percentage,
                baseline_value: baseline.summary.function_coverage_percentage,
                change: current.summary.function_coverage_percentage
                    - baseline.summary.function_coverage_percentage,
            },
            CoverageTrend {
                metric: "Branch Coverage".to_string(),
                current_value: current.summary.branch_coverage_percentage,
                baseline_value: baseline.summary.branch_coverage_percentage,
                change: current.summary.branch_coverage_percentage
                    - baseline.summary.branch_coverage_percentage,
            },
        ]
    }

    fn generate_recommendations(&self, coverage_data: &CoverageData) -> Vec<String> {
        let mut recommendations = Vec::new();

        if coverage_data.summary.line_coverage_percentage < 80.0 {
            recommendations
                .push("Consider adding more unit tests to achieve 80%+ line coverage".to_string());
        }

        if coverage_data.summary.branch_coverage_percentage < 75.0 {
            recommendations
                .push("Add tests for conditional branches to improve branch coverage".to_string());
        }

        let low_coverage_files: Vec<_> = coverage_data
            .files
            .values()
            .filter(|f| {
                let coverage = f.covered_lines as f64 / f.executable_lines.max(1) as f64 * 100.0;
                coverage < 70.0
            })
            .collect();

        if !low_coverage_files.is_empty() {
            recommendations.push(format!(
                "Focus on improving coverage for {} files with <70% coverage",
                low_coverage_files.len()
            ));
        }

        recommendations
    }

    fn export_html(&self, report: &CoverageReport) -> Result<(), String> {
        let html_path = self.output_dir.join("coverage_report.html");
        let html_content = self.generate_html_report(report);
        fs::write(html_path, html_content).map_err(|e| format!("Failed to write HTML report: {e}"))
    }

    fn export_json(&self, report: &CoverageReport) -> Result<(), String> {
        let json_path = self.output_dir.join("coverage_report.json");
        let json_content = serde_json::to_string_pretty(report)
            .map_err(|e| format!("Failed to serialize report: {e}"))?;
        fs::write(json_path, json_content).map_err(|e| format!("Failed to write JSON report: {e}"))
    }

    fn export_markdown(&self, report: &CoverageReport) -> Result<(), String> {
        let md_path = self.output_dir.join("coverage_report.md");
        let md_content = self.generate_markdown_report(report);
        fs::write(md_path, md_content).map_err(|e| format!("Failed to write Markdown report: {e}"))
    }

    fn export_cobertura(&self, _report: &CoverageReport) -> Result<(), String> {
        // Placeholder for Cobertura XML export
        Err("Cobertura export not implemented".to_string())
    }

    fn generate_html_report(&self, report: &CoverageReport) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Test Coverage Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .file {{ margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; }}
        .good {{ background: #d4edda; }}
        .warning {{ background: #fff3cd; }}
        .danger {{ background: #f8d7da; }}
    </style>
</head>
<body>
    <h1>Test Coverage Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Line Coverage: {:.1}%</p>
        <p>Function Coverage: {:.1}%</p>
        <p>Branch Coverage: {:.1}%</p>
        <p>Total Files: {}</p>
    </div>
    <h2>File Details</h2>
    <!-- File details would be populated here -->
</body>
</html>"#,
            report.summary.line_coverage_percentage,
            report.summary.function_coverage_percentage,
            report.summary.branch_coverage_percentage,
            report.summary.total_files
        )
    }

    fn generate_markdown_report(&self, report: &CoverageReport) -> String {
        format!(
            r#"# Test Coverage Report

Generated: {}

## Summary

- **Line Coverage**: {:.1}%
- **Function Coverage**: {:.1}%
- **Branch Coverage**: {:.1}%
- **Total Files**: {}
- **Total Lines**: {}
- **Covered Lines**: {}

## File Details

| File | Line Coverage | Function Coverage | Branch Coverage |
|------|---------------|-------------------|-----------------|
{}
"#,
            chrono::DateTime::from_timestamp(report.timestamp as i64, 0)
                .unwrap_or_default()
                .format("%Y-%m-%d %H:%M:%S UTC"),
            report.summary.line_coverage_percentage,
            report.summary.function_coverage_percentage,
            report.summary.branch_coverage_percentage,
            report.summary.total_files,
            report.summary.total_lines,
            report.summary.covered_lines,
            report
                .file_reports
                .iter()
                .map(|f| format!(
                    "| {} | {:.1}% | {:.1}% | {:.1}% |",
                    f.file_path, f.line_coverage, f.function_coverage, f.branch_coverage
                ))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

/// Supported coverage data formats
#[derive(Debug, Clone)]
pub enum CoverageFormat {
    LCOV,
    Cobertura,
    JSON,
}

/// Supported export formats
#[derive(Debug, Clone)]
pub enum ExportFormat {
    HTML,
    JSON,
    Markdown,
    Cobertura,
}

/// Comprehensive coverage report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageReport {
    pub timestamp: u64,
    pub summary: CoverageSummary,
    pub file_reports: Vec<FileReport>,
    pub trends: Vec<CoverageTrend>,
    pub recommendations: Vec<String>,
}

/// Individual file coverage report
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileReport {
    pub file_path: String,
    pub line_coverage: f64,
    pub function_coverage: f64,
    pub branch_coverage: f64,
    pub uncovered_lines: Vec<usize>,
    pub low_coverage_functions: Vec<FunctionCoverage>,
    pub total_lines: usize,
    pub executable_lines: usize,
}

/// Coverage trend analysis
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageTrend {
    pub metric: String,
    pub current_value: f64,
    pub baseline_value: f64,
    pub change: f64,
}

/// Coverage quality gates
pub mod quality_gates {
    use super::*;

    /// Check if coverage meets minimum quality standards
    #[must_use]
    pub fn check_quality_gates(summary: &CoverageSummary) -> Vec<QualityGateResult> {
        vec![
            check_line_coverage_gate(summary.line_coverage_percentage),
            check_function_coverage_gate(summary.function_coverage_percentage),
            check_branch_coverage_gate(summary.branch_coverage_percentage),
        ]
    }

    fn check_line_coverage_gate(percentage: f64) -> QualityGateResult {
        QualityGateResult {
            name: "Line Coverage".to_string(),
            value: percentage,
            threshold: 80.0,
            passed: percentage >= 80.0,
            severity: if percentage < 60.0 {
                "critical"
            } else if percentage < 75.0 {
                "warning"
            } else {
                "info"
            }
            .to_string(),
        }
    }

    fn check_function_coverage_gate(percentage: f64) -> QualityGateResult {
        QualityGateResult {
            name: "Function Coverage".to_string(),
            value: percentage,
            threshold: 85.0,
            passed: percentage >= 85.0,
            severity: if percentage < 70.0 {
                "critical"
            } else if percentage < 80.0 {
                "warning"
            } else {
                "info"
            }
            .to_string(),
        }
    }

    fn check_branch_coverage_gate(percentage: f64) -> QualityGateResult {
        QualityGateResult {
            name: "Branch Coverage".to_string(),
            value: percentage,
            threshold: 75.0,
            passed: percentage >= 75.0,
            severity: if percentage < 50.0 {
                "critical"
            } else if percentage < 65.0 {
                "warning"
            } else {
                "info"
            }
            .to_string(),
        }
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct QualityGateResult {
        pub name: String,
        pub value: f64,
        pub threshold: f64,
        pub passed: bool,
        pub severity: String,
    }
}

/// Coverage badge generation
pub mod badges {
    use super::*;

    /// Generate coverage badge for CI/CD
    #[must_use]
    pub fn generate_coverage_badge(summary: &CoverageSummary) -> String {
        let coverage = summary.line_coverage_percentage;
        let color = if coverage >= 90.0 {
            "brightgreen"
        } else if coverage >= 80.0 {
            "green"
        } else if coverage >= 70.0 {
            "yellow"
        } else if coverage >= 60.0 {
            "orange"
        } else {
            "red"
        };

        format!(
            "https://img.shields.io/badge/coverage-{:.1}%25-{color}",
            coverage
        )
    }

    /// Generate Shields.io badge URL
    #[must_use]
    pub fn generate_shields_badge(coverage: f64, label: &str) -> String {
        let color = if coverage >= 90.0 {
            "brightgreen"
        } else if coverage >= 80.0 {
            "green"
        } else if coverage >= 70.0 {
            "yellow"
        } else if coverage >= 60.0 {
            "orange"
        } else {
            "red"
        };

        format!(
            "https://img.shields.io/badge/{}-{:.1}%25-{}",
            label.replace(' ', "%20"),
            coverage,
            color
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_analyzer_creation() {
        let temp_dir = std::env::temp_dir().join("coverage_test");
        let analyzer = CoverageAnalyzer::new(temp_dir);
        assert!(analyzer.coverage_data.is_none());
    }

    #[test]
    fn test_quality_gates() {
        let summary = CoverageSummary {
            total_files: 10,
            total_lines: 1000,
            covered_lines: 850,
            total_functions: 100,
            covered_functions: 90,
            total_branches: 50,
            covered_branches: 40,
            line_coverage_percentage: 85.0,
            function_coverage_percentage: 90.0,
            branch_coverage_percentage: 80.0,
        };

        let gates = quality_gates::check_quality_gates(&summary);
        assert_eq!(gates.len(), 3);
        assert!(gates[0].passed); // Line coverage >= 80
        assert!(gates[1].passed); // Function coverage >= 85
        assert!(gates[2].passed); // Branch coverage >= 75
    }

    #[test]
    fn test_coverage_badge_generation() {
        let summary = CoverageSummary {
            total_files: 1,
            total_lines: 100,
            covered_lines: 85,
            total_functions: 10,
            covered_functions: 9,
            total_branches: 5,
            covered_branches: 4,
            line_coverage_percentage: 85.0,
            function_coverage_percentage: 90.0,
            branch_coverage_percentage: 80.0,
        };

        let badge = badges::generate_coverage_badge(&summary);
        assert!(badge.contains("85.0"));
        assert!(badge.contains("green"));
    }

    #[test]
    fn test_coverage_trend_calculation() {
        let baseline = CoverageData {
            timestamp: 1000,
            test_run_id: "baseline".to_string(),
            files: HashMap::new(),
            summary: CoverageSummary {
                total_files: 1,
                total_lines: 100,
                covered_lines: 80,
                total_functions: 10,
                covered_functions: 8,
                total_branches: 5,
                covered_branches: 4,
                line_coverage_percentage: 80.0,
                function_coverage_percentage: 85.0,
                branch_coverage_percentage: 80.0,
            },
        };

        let current = CoverageData {
            timestamp: 2000,
            test_run_id: "current".to_string(),
            files: HashMap::new(),
            summary: CoverageSummary {
                total_files: 1,
                total_lines: 100,
                covered_lines: 85,
                total_functions: 10,
                covered_functions: 9,
                total_branches: 5,
                covered_branches: 4,
                line_coverage_percentage: 85.0,
                function_coverage_percentage: 90.0,
                branch_coverage_percentage: 80.0,
            },
        };

        let mut analyzer = CoverageAnalyzer::new(std::env::temp_dir().join("test"));
        analyzer.baseline_data = Some(baseline);

        let trends = analyzer.calculate_trends(&current, analyzer.baseline_data.as_ref().unwrap());
        assert_eq!(trends.len(), 3);
        assert_eq!(trends[0].change, 5.0); // Line coverage increased by 5%
    }
}
