//! Code Review Standards and Automated Review System
//!
//! This module provides comprehensive code review standards including:
//! - Automated code review processes
//! - Code quality standards and rules
//! - Linting and formatting validation
//! - Pre-commit hooks and CI/CD integration
//! - Review checklists and guidelines
//! - Code quality metrics and reporting
//! - Security code review integration

pub mod automated_review;
pub mod checklists;
pub mod formatting;
pub mod hooks;
pub mod linting;
pub mod metrics;
pub mod reporting;
pub mod security_review;
pub mod standards;

// Re-export main code review types
pub use automated_review::{AutomatedReviewer, IssueSeverity, ReviewResult};
pub use checklists::{ChecklistItem, ChecklistResult, ReviewChecklist};
pub use formatting::{FormatConfig, FormatResult, Formatter};
pub use hooks::{HookResult, PostCommitHook, PreCommitHook};
pub use linting::{LintResult, LintRule, Linter};
pub use metrics::{CodeMetrics, QualityMetrics, ReviewMetrics};
pub use reporting::{MetricsReport, QualityReport, ReviewReport};
pub use security_review::{SecurityIssue, SecurityResult, SecurityReviewer};
pub use standards::{CodeStandard, QualityThreshold, ReviewRule};

/// Code review configuration
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CodeReviewConfig {
    /// Enable automated code review
    pub automated_review_enabled: bool,
    /// Enable security code review
    pub security_review_enabled: bool,
    /// Enable pre-commit hooks
    pub pre_commit_hooks_enabled: bool,
    /// Enable CI/CD integration
    pub ci_cd_integration_enabled: bool,
    /// Quality thresholds
    pub quality_thresholds: QualityThreshold,
    /// Review rules
    pub review_rules: Vec<ReviewRule>,
    /// Lint configuration
    pub lint_config: LintConfig,
    /// Format configuration
    pub format_config: FormatConfig,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct LintConfig {
    pub max_line_length: usize,
    pub max_function_length: usize,
    pub max_complexity: usize,
    pub require_documentation: bool,
    pub allow_todo_comments: bool,
    pub strict_naming: bool,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct QualityThreshold {
    pub min_test_coverage: f64,
    pub max_cyclomatic_complexity: usize,
    pub max_maintainability_index: f64,
    pub max_technical_debt_ratio: f64,
    pub min_code_quality_score: f64,
}

impl Default for CodeReviewConfig {
    fn default() -> Self {
        Self {
            automated_review_enabled: true,
            security_review_enabled: true,
            pre_commit_hooks_enabled: true,
            ci_cd_integration_enabled: true,
            quality_thresholds: QualityThreshold {
                min_test_coverage: 80.0,
                max_cyclomatic_complexity: 10,
                max_maintainability_index: 50.0,
                max_technical_debt_ratio: 10.0,
                min_code_quality_score: 7.0,
            },
            review_rules: vec![
                ReviewRule::RequireDocumentation,
                ReviewRule::RequireTests,
                ReviewRule::CheckSecurity,
                ReviewRule::ValidatePerformance,
                ReviewRule::CheckErrorHandling,
            ],
            lint_config: LintConfig {
                max_line_length: 100,
                max_function_length: 50,
                max_complexity: 10,
                require_documentation: true,
                allow_todo_comments: false,
                strict_naming: true,
            },
            format_config: FormatConfig::default(),
        }
    }
}

/// Main code review orchestrator
pub struct CodeReviewOrchestrator {
    config: CodeReviewConfig,
    automated_reviewer: AutomatedReviewer,
    security_reviewer: SecurityReviewer,
    linter: Linter,
    formatter: Formatter,
    metrics_collector: CodeMetricsCollector,
}

impl CodeReviewOrchestrator {
    /// Create new code review orchestrator
    pub fn new(config: CodeReviewConfig) -> Self {
        Self {
            automated_reviewer: AutomatedReviewer::new(),
            security_reviewer: SecurityReviewer::new(),
            linter: Linter::new(config.lint_config.clone()),
            formatter: Formatter::new(config.format_config.clone()),
            metrics_collector: CodeMetricsCollector::new(),
            config,
        }
    }

    /// Perform comprehensive code review
    pub async fn review_code(
        &self,
        code: &str,
        file_path: &str,
    ) -> Result<ReviewResult, ReviewError> {
        let mut issues = Vec::new();
        let mut metrics = CodeMetrics::default();

        // 1. Automated code review
        if self.config.automated_review_enabled {
            let review_result = self.automated_reviewer.review_code(code, file_path).await?;
            issues.extend(review_result.issues);
        }

        // 2. Security review
        if self.config.security_review_enabled {
            let security_result = self.security_reviewer.review_code(code, file_path).await?;
            issues.extend(security_result.issues.into_iter().map(|issue| ReviewIssue {
                rule: "security".to_string(),
                message: issue.description,
                severity: match issue.severity {
                    super::security_review::SecuritySeverity::Critical => IssueSeverity::Critical,
                    super::security_review::SecuritySeverity::High => IssueSeverity::High,
                    super::security_review::SecuritySeverity::Medium => IssueSeverity::Medium,
                    super::security_review::SecuritySeverity::Low => IssueSeverity::Low,
                    super::security_review::SecuritySeverity::Info => IssueSeverity::Info,
                },
                file: file_path.to_string(),
                line: issue.line_number,
                column: 0,
                suggestion: issue.recommendation,
            }));
        }

        // 3. Linting
        let lint_result = self.linter.lint_code(code, file_path)?;
        issues.extend(lint_result.issues.into_iter().map(|issue| ReviewIssue {
            rule: issue.rule,
            message: issue.message,
            severity: issue.severity,
            file: file_path.to_string(),
            line: issue.line,
            column: issue.column,
            suggestion: issue.suggestion,
        }));

        // 4. Formatting check
        let format_result = self.formatter.check_format(code, file_path)?;
        if !format_result.is_formatted {
            issues.push(ReviewIssue {
                rule: "formatting".to_string(),
                message: "Code is not properly formatted".to_string(),
                severity: IssueSeverity::Medium,
                file: file_path.to_string(),
                line: 0,
                column: 0,
                suggestion: "Run code formatter".to_string(),
            });
        }

        // 5. Collect metrics
        metrics = self.metrics_collector.collect_metrics(code, file_path)?;

        // Determine overall status
        let status = self.determine_review_status(&issues, &metrics);

        Ok(ReviewResult {
            status,
            issues,
            metrics,
            suggestions: self.generate_suggestions(&issues, &metrics),
        })
    }

    /// Generate review report
    pub async fn generate_report(
        &self,
        results: &[ReviewResult],
    ) -> Result<ReviewReport, ReviewError> {
        let total_files = results.len();
        let total_issues = results.iter().map(|r| r.issues.len()).sum();
        let critical_issues = results
            .iter()
            .flat_map(|r| &r.issues)
            .filter(|i| matches!(i.severity, IssueSeverity::Critical))
            .count();
        let high_issues = results
            .iter()
            .flat_map(|r| &r.issues)
            .filter(|i| matches!(i.severity, IssueSeverity::High))
            .count();

        let average_quality_score =
            results.iter().map(|r| r.metrics.quality_score).sum::<f64>() / total_files as f64;

        let passed_reviews = results
            .iter()
            .filter(|r| matches!(r.status, ReviewStatus::Passed))
            .count();

        Ok(ReviewReport {
            generated_at: chrono::Utc::now(),
            total_files,
            total_issues,
            critical_issues,
            high_issues,
            average_quality_score,
            passed_reviews,
            failed_reviews: total_files - passed_reviews,
            top_issues: self.identify_top_issues(results),
            recommendations: self.generate_overall_recommendations(results),
        })
    }

    fn determine_review_status(
        &self,
        issues: &[ReviewIssue],
        metrics: &CodeMetrics,
    ) -> ReviewStatus {
        // Check critical issues
        if issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::Critical))
        {
            return ReviewStatus::Failed;
        }

        // Check quality thresholds
        if metrics.quality_score < self.config.quality_thresholds.min_code_quality_score {
            return ReviewStatus::Failed;
        }

        if metrics.cyclomatic_complexity > self.config.quality_thresholds.max_cyclomatic_complexity
        {
            return ReviewStatus::Failed;
        }

        // Check high-severity issues
        let high_issues = issues
            .iter()
            .filter(|i| matches!(i.severity, IssueSeverity::High))
            .count();

        if high_issues > 5 {
            return ReviewStatus::Failed;
        }

        ReviewStatus::Passed
    }

    fn generate_suggestions(&self, issues: &[ReviewIssue], metrics: &CodeMetrics) -> Vec<String> {
        let mut suggestions = Vec::new();

        if metrics.cyclomatic_complexity > self.config.quality_thresholds.max_cyclomatic_complexity
        {
            suggestions
                .push("Consider breaking down complex functions into smaller ones".to_string());
        }

        if metrics.quality_score < self.config.quality_thresholds.min_code_quality_score {
            suggestions.push(
                "Improve code quality by following established patterns and practices".to_string(),
            );
        }

        let security_issues = issues.iter().filter(|i| i.rule == "security").count();

        if security_issues > 0 {
            suggestions.push("Address security issues identified in the review".to_string());
        }

        let formatting_issues = issues.iter().filter(|i| i.rule == "formatting").count();

        if formatting_issues > 0 {
            suggestions.push("Run code formatter to fix formatting issues".to_string());
        }

        suggestions
    }

    fn identify_top_issues(&self, results: &[ReviewResult]) -> Vec<(String, usize)> {
        let mut issue_counts = std::collections::HashMap::new();

        for result in results {
            for issue in &result.issues {
                *issue_counts.entry(issue.rule.clone()).or_insert(0) += 1;
            }
        }

        let mut top_issues: Vec<_> = issue_counts.into_iter().collect();
        top_issues.sort_by(|a, b| b.1.cmp(&a.1));
        top_issues.truncate(5);

        top_issues
    }

    fn generate_overall_recommendations(&self, results: &[ReviewResult]) -> Vec<String> {
        let mut recommendations = Vec::new();

        let total_files = results.len();
        let failed_reviews = results
            .iter()
            .filter(|r| matches!(r.status, ReviewStatus::Failed))
            .count();

        if failed_reviews as f64 / total_files as f64 > 0.5 {
            recommendations
                .push("Major code quality improvements needed across the codebase".to_string());
        }

        let average_complexity = results
            .iter()
            .map(|r| r.metrics.cyclomatic_complexity)
            .sum::<usize>() as f64
            / total_files as f64;

        if average_complexity > 8.0 {
            recommendations
                .push("Consider reducing code complexity through refactoring".to_string());
        }

        recommendations
    }
}

/// Review result
#[derive(Debug, Clone)]
pub struct ReviewResult {
    pub status: ReviewStatus,
    pub issues: Vec<ReviewIssue>,
    pub metrics: CodeMetrics,
    pub suggestions: Vec<String>,
}

/// Review status
#[derive(Debug, Clone, PartialEq)]
pub enum ReviewStatus {
    Passed,
    Failed,
    Warning,
}

/// Review issue
#[derive(Debug, Clone)]
pub struct ReviewIssue {
    pub rule: String,
    pub message: String,
    pub severity: IssueSeverity,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub suggestion: String,
}

/// Issue severity
#[derive(Debug, Clone, PartialEq)]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Review error
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("Code review failed: {message}")]
    ReviewFailed { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("IO error: {source}")]
    IoError {
        #[from]
        source: std::io::Error,
    },

    #[error("Parse error: {message}")]
    ParseError { message: String },
}

/// Code metrics collector
pub struct CodeMetricsCollector;

impl CodeMetricsCollector {
    pub fn new() -> Self {
        Self
    }

    pub fn collect_metrics(&self, code: &str, file_path: &str) -> Result<CodeMetrics, ReviewError> {
        // This is a simplified implementation
        // In a real system, you would use tools like rust-code-analysis
        // or similar to calculate actual metrics

        let lines_of_code = code.lines().count();
        let functions = code.matches("fn ").count();
        let structs = code.matches("struct ").count();
        let enums = code.matches("enum ").count();
        let comments = code
            .lines()
            .filter(|line| line.trim().starts_with("//") || line.trim().starts_with("///"))
            .count();

        // Estimate cyclomatic complexity (very basic)
        let cyclomatic_complexity = code.matches("if ").count()
            + code.matches("match ").count()
            + code.matches("for ").count()
            + code.matches("while ").count()
            + functions; // +1 for each function

        // Calculate comment ratio with safe casting
        let comment_ratio = if lines_of_code > 0 {
            let comments_f64 = f64::from(u32::try_from(comments).unwrap_or(u32::MAX));
            let lines_f64 = f64::from(u32::try_from(lines_of_code).unwrap_or(u32::MAX));
            comments_f64 / lines_f64 * 100.0
        } else {
            0.0
        };

        // Calculate quality score (simplified formula)
        let quality_score = if lines_of_code > 0 {
            let base_score = 10.0;
            let complexity_penalty = (cyclomatic_complexity as f64 / 10.0).min(3.0);
            let comment_bonus = (comment_ratio / 20.0).min(2.0);

            (base_score - complexity_penalty + comment_bonus)
                .max(0.0)
                .min(10.0)
        } else {
            0.0
        };

        Ok(CodeMetrics {
            file_path: file_path.to_string(),
            lines_of_code,
            functions,
            structs,
            enums,
            comments,
            comment_ratio,
            cyclomatic_complexity,
            quality_score,
        })
    }
}

/// Code metrics
#[derive(Debug, Clone, Default)]
pub struct CodeMetrics {
    pub file_path: String,
    pub lines_of_code: usize,
    pub functions: usize,
    pub structs: usize,
    pub enums: usize,
    pub comments: usize,
    pub comment_ratio: f64,
    pub cyclomatic_complexity: usize,
    pub quality_score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_review_config_defaults() {
        let config = CodeReviewConfig::default();
        assert!(config.automated_review_enabled);
        assert!(config.security_review_enabled);
        assert!(config.pre_commit_hooks_enabled);
        assert!(config.ci_cd_integration_enabled);
        assert_eq!(config.quality_thresholds.min_test_coverage, 80.0);
    }

    #[test]
    fn test_code_metrics_collection() {
        let collector = CodeMetricsCollector::new();

        let code = r#"
// This is a test function
fn test_function() {
    if true {
        tracing::debug!("Hello");
    }
    for i in 0..5 {
        match i {
            0 => tracing::debug!("Zero"),
            _ => tracing::debug!("Other"),
        }
    }
}
"#;

        let metrics = collector.collect_metrics(code, "test.rs").unwrap();
        assert_eq!(metrics.lines_of_code, 14);
        assert_eq!(metrics.functions, 1);
        assert!(metrics.cyclomatic_complexity >= 4); // if + for + match + function
        assert!(metrics.quality_score > 0.0);
    }

    #[test]
    fn test_review_status_determination() {
        let config = CodeReviewConfig::default();
        let orchestrator = CodeReviewOrchestrator::new(config);

        // Test with no issues - should pass
        let issues = vec![];
        let metrics = CodeMetrics {
            quality_score: 8.0,
            cyclomatic_complexity: 5,
            ..Default::default()
        };

        let status = orchestrator.determine_review_status(&issues, &metrics);
        assert!(matches!(status, ReviewStatus::Passed));

        // Test with critical issue - should fail
        let critical_issue = ReviewIssue {
            rule: "test".to_string(),
            message: "Critical issue".to_string(),
            severity: IssueSeverity::Critical,
            file: "test.rs".to_string(),
            line: 1,
            column: 0,
            suggestion: "Fix it".to_string(),
        };

        let status = orchestrator.determine_review_status(&[critical_issue], &metrics);
        assert!(matches!(status, ReviewStatus::Failed));

        // Test with low quality score - should fail
        let low_quality_metrics = CodeMetrics {
            quality_score: 3.0,
            cyclomatic_complexity: 5,
            ..Default::default()
        };

        let status = orchestrator.determine_review_status(&issues, &low_quality_metrics);
        assert!(matches!(status, ReviewStatus::Failed));
    }
}
