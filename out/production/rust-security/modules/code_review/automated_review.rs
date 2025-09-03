//! Automated Code Review Module
//!
//! This module provides automated code review capabilities including:
//! - Static analysis and code quality checks
//! - Automated rule validation
//! - Issue detection and reporting
//! - Code quality scoring
//! - Review workflow automation
//! - Integration with CI/CD pipelines

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Automated reviewer trait
#[async_trait]
pub trait AutomatedReviewer: Send + Sync {
    /// Review code automatically
    async fn review_code(&self, code: &str, file_path: &str) -> Result<ReviewResult, ReviewError>;

    /// Get review statistics
    async fn get_statistics(&self) -> Result<ReviewStatistics, ReviewError>;

    /// Configure review rules
    async fn configure_rules(&mut self, rules: Vec<ReviewRule>) -> Result<(), ReviewError>;
}

/// Review result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewResult {
    pub status: ReviewStatus,
    pub issues: Vec<ReviewIssue>,
    pub quality_score: f64,
    pub review_time_ms: u64,
    pub rules_applied: Vec<String>,
}

/// Review status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReviewStatus {
    Passed,
    Warning,
    Failed,
    Error,
}

/// Review issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewIssue {
    pub rule_id: String,
    pub severity: IssueSeverity,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub code_snippet: String,
    pub suggestion: String,
    pub category: IssueCategory,
}

/// Issue severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IssueSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Issue category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IssueCategory {
    Security,
    Performance,
    Maintainability,
    Documentation,
    Style,
    BestPractice,
}

/// Review rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: IssueCategory,
    pub severity: IssueSeverity,
    pub pattern: String,
    pub message: String,
    pub suggestion: String,
    pub enabled: bool,
}

/// Review statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewStatistics {
    pub total_reviews: u64,
    pub total_issues: u64,
    pub issues_by_severity: HashMap<String, u64>,
    pub issues_by_category: HashMap<String, u64>,
    pub average_quality_score: f64,
    pub average_review_time_ms: u64,
    pub reviews_passed: u64,
    pub reviews_failed: u64,
}

/// Review error
#[derive(Debug, thiserror::Error)]
pub enum ReviewError {
    #[error("Review failed: {message}")]
    ReviewFailed { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Pattern compilation error: {message}")]
    PatternError { message: String },

    #[error("File read error: {source}")]
    FileError {
        #[from]
        source: std::io::Error,
    },
}

/// Comprehensive automated reviewer implementation
pub struct ComprehensiveAutomatedReviewer {
    rules: Vec<ReviewRule>,
    statistics: ReviewStatistics,
    start_time: DateTime<Utc>,
}

impl ComprehensiveAutomatedReviewer {
    /// Create new automated reviewer
    pub fn new() -> Self {
        let mut reviewer = Self {
            rules: Vec::new(),
            statistics: ReviewStatistics {
                total_reviews: 0,
                total_issues: 0,
                issues_by_severity: HashMap::new(),
                issues_by_category: HashMap::new(),
                average_quality_score: 0.0,
                average_review_time_ms: 0,
                reviews_passed: 0,
                reviews_failed: 0,
            },
            start_time: Utc::now(),
        };

        reviewer.load_default_rules();
        reviewer
    }

    /// Load default review rules
    fn load_default_rules(&mut self) {
        self.rules = vec![
            // Security Rules
            ReviewRule {
                id: "SEC-001".to_string(),
                name: "Hardcoded Secrets".to_string(),
                description: "Detects hardcoded passwords, tokens, and secrets".to_string(),
                category: IssueCategory::Security,
                severity: IssueSeverity::Critical,
                pattern: r#"(?i)(password|secret|token|key)\s*[:=]\s*["'][^"']{8,}["']"#.to_string(),
                message: "Hardcoded secret detected".to_string(),
                suggestion: "Use environment variables or secure vaults for secrets".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "SEC-002".to_string(),
                name: "SQL Injection".to_string(),
                description: "Detects potential SQL injection vulnerabilities".to_string(),
                category: IssueCategory::Security,
                severity: IssueSeverity::High,
                pattern: r#"(?i)(format!|concat!)\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)[^)]*\)"#.to_string(),
                message: "Potential SQL injection vulnerability".to_string(),
                suggestion: "Use prepared statements or parameterized queries".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "SEC-003".to_string(),
                name: "Unsafe Code".to_string(),
                description: "Detects usage of unsafe code blocks".to_string(),
                category: IssueCategory::Security,
                severity: IssueSeverity::Medium,
                pattern: r"unsafe\s*\{".to_string(),
                message: "Unsafe code block detected".to_string(),
                suggestion: "Review unsafe code for security implications".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "SEC-004".to_string(),
                name: "Weak Cryptography".to_string(),
                description: "Detects usage of weak cryptographic algorithms".to_string(),
                category: IssueCategory::Security,
                severity: IssueSeverity::High,
                pattern: r"(?i)(md5|sha1|rc4|des)\s*\(".to_string(),
                message: "Weak cryptographic algorithm detected".to_string(),
                suggestion: "Use strong cryptographic algorithms like SHA-256 or AES-256".to_string(),
                enabled: true,
            },

            // Performance Rules
            ReviewRule {
                id: "PERF-001".to_string(),
                name: "Excessive Allocations".to_string(),
                description: "Detects excessive heap allocations in loops".to_string(),
                category: IssueCategory::Performance,
                severity: IssueSeverity::Medium,
                pattern: r"(?m)for.*\{\s*let\s+\w+\s*=\s*(String::|Vec::|HashMap::)[\w:]*\(".to_string(),
                message: "Potential excessive allocations in loop".to_string(),
                suggestion: "Consider reusing allocations or using stack-allocated alternatives".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "PERF-002".to_string(),
                name: "Blocking Operations in Async".to_string(),
                description: "Detects blocking operations in async functions".to_string(),
                category: IssueCategory::Performance,
                severity: IssueSeverity::High,
                pattern: r"(?m)async\s+fn.*\{[^}]*std::fs::[^}]*\}".to_string(),
                message: "Blocking file operation in async function".to_string(),
                suggestion: "Use tokio::fs::* for async file operations".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "PERF-003".to_string(),
                name: "Large Data Structures".to_string(),
                description: "Detects large data structures that may impact performance".to_string(),
                category: IssueCategory::Performance,
                severity: IssueSeverity::Low,
                pattern: r"Vec<[^>]*>\s*=\s*vec!\[.*;.*1000.*\]".to_string(),
                message: "Large data structure allocation detected".to_string(),
                suggestion: "Consider lazy initialization or streaming for large datasets".to_string(),
                enabled: true,
            },

            // Maintainability Rules
            ReviewRule {
                id: "MAINT-001".to_string(),
                name: "Long Function".to_string(),
                description: "Detects functions that are too long".to_string(),
                category: IssueCategory::Maintainability,
                severity: IssueSeverity::Medium,
                pattern: r"(?s)fn\s+\w+.*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{(?:[^{}]|\{[^{}]*\})*\{".to_string(),
                message: "Function is too long (more than 50 lines)".to_string(),
                suggestion: "Break down into smaller functions".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "MAINT-002".to_string(),
                name: "High Complexity".to_string(),
                description: "Detects functions with high cyclomatic complexity".to_string(),
                category: IssueCategory::Maintainability,
                severity: IssueSeverity::Medium,
                pattern: r"(?s)fn\s+\w+.*\{(?:[^{}]|\{[^{}]*\})*\b(if|match|for|while)\b.*(?:[^{}]|\{[^{}]*\})*\b(if|match|for|while)\b.*(?:[^{}]|\{[^{}]*\})*\b(if|match|for|while)\b.*(?:[^{}]|\{[^{}]*\})*\b(if|match|for|while)\b.*(?:[^{}]|\{[^{}]*\})*\b(if|match|for|while)\b".to_string(),
                message: "High cyclomatic complexity detected".to_string(),
                suggestion: "Simplify function logic or break into smaller functions".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "MAINT-003".to_string(),
                name: "Missing Documentation".to_string(),
                description: "Detects public functions without documentation".to_string(),
                category: IssueCategory::Documentation,
                severity: IssueSeverity::Medium,
                pattern: r"(?m)^pub\s+fn\s+\w+.*\{".to_string(),
                message: "Public function missing documentation".to_string(),
                suggestion: "Add documentation comment starting with ///".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "MAINT-004".to_string(),
                name: "Inconsistent Naming".to_string(),
                description: "Detects inconsistent naming conventions".to_string(),
                category: IssueCategory::Style,
                severity: IssueSeverity::Low,
                pattern: r"(?i)\b[a-z]+[A-Z][a-zA-Z]*\b".to_string(), // camelCase in Rust context
                message: "Potential inconsistent naming convention".to_string(),
                suggestion: "Use snake_case for variables and functions, PascalCase for types".to_string(),
                enabled: true,
            },

            // Best Practice Rules
            ReviewRule {
                id: "BEST-001".to_string(),
                name: "Unnecessary Clone".to_string(),
                description: "Detects unnecessary clone() calls".to_string(),
                category: IssueCategory::BestPractice,
                severity: IssueSeverity::Low,
                pattern: r"\.clone\(\)\s*;?\s*$".to_string(),
                message: "Unnecessary clone detected".to_string(),
                suggestion: "Consider using references or moving ownership instead of cloning".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "BEST-002".to_string(),
                name: "Unused Variable".to_string(),
                description: "Detects variables that are assigned but never used".to_string(),
                category: IssueCategory::BestPractice,
                severity: IssueSeverity::Info,
                pattern: r"let\s+(\w+)\s*=.*;(?!\s*\w+\s*=.*\1|.*\1\s*[;)}]|.*\1\s*\.)".to_string(),
                message: "Unused variable detected".to_string(),
                suggestion: "Remove unused variable or prefix with underscore if intentionally unused".to_string(),
                enabled: true,
            },
            ReviewRule {
                id: "BEST-003".to_string(),
                name: "Missing Error Handling".to_string(),
                description: "Detects unwrap() and expect() calls that may panic".to_string(),
                category: IssueCategory::BestPractice,
                severity: IssueSeverity::Medium,
                pattern: r"\.(unwrap|expect)\(\)".to_string(),
                message: "Potential panic from unwrap/expect".to_string(),
                suggestion: "Use proper error handling with Result/Option patterns".to_string(),
                enabled: true,
            },
        ];
    }

    /// Apply review rules to code
    fn apply_rules(&self, code: &str, file_path: &str) -> Result<Vec<ReviewIssue>, ReviewError> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match regex::Regex::new(&rule.pattern) {
                Ok(regex) => {
                    for (line_idx, line) in lines.iter().enumerate() {
                        for mat in regex.find_iter(line) {
                            let issue = ReviewIssue {
                                rule_id: rule.id.clone(),
                                severity: rule.severity.clone(),
                                message: rule.message.clone(),
                                file: file_path.to_string(),
                                line: line_idx + 1,
                                column: mat.start(),
                                code_snippet: line.trim().to_string(),
                                suggestion: rule.suggestion.clone(),
                                category: rule.category.clone(),
                            };
                            issues.push(issue);
                        }
                    }
                }
                Err(e) => {
                    return Err(ReviewError::PatternError {
                        message: format!("Invalid regex pattern in rule {}: {}", rule.id, e),
                    });
                }
            }
        }

        Ok(issues)
    }

    /// Calculate code quality score
    fn calculate_quality_score(&self, code: &str, issues: &[ReviewIssue]) -> f64 {
        let lines_of_code = code.lines().count() as f64;

        if lines_of_code == 0.0 {
            return 10.0; // Perfect score for empty files
        }

        // Base score
        let mut score = 10.0;

        // Deduct points for issues based on severity
        for issue in issues {
            let deduction = match issue.severity {
                IssueSeverity::Info => 0.1,
                IssueSeverity::Low => 0.2,
                IssueSeverity::Medium => 0.5,
                IssueSeverity::High => 1.0,
                IssueSeverity::Critical => 2.0,
            };
            score -= deduction;
        }

        // Bonus for documentation
        let doc_lines = code
            .lines()
            .filter(|line| line.trim().starts_with("///") || line.trim().starts_with("//!"))
            .count() as f64;

        let doc_ratio = doc_lines / lines_of_code;
        score += doc_ratio * 2.0; // Up to 2 points for good documentation

        // Ensure score is between 0 and 10
        score.max(0.0).min(10.0)
    }

    /// Determine review status
    fn determine_status(&self, issues: &[ReviewIssue], quality_score: f64) -> ReviewStatus {
        // Check for critical or high severity issues
        let has_critical = issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::Critical));
        let has_high = issues
            .iter()
            .any(|i| matches!(i.severity, IssueSeverity::High));

        if has_critical || quality_score < 3.0 {
            ReviewStatus::Failed
        } else if has_high || quality_score < 7.0 {
            ReviewStatus::Warning
        } else {
            ReviewStatus::Passed
        }
    }

    /// Update review statistics
    fn update_statistics(&mut self, result: &ReviewResult) {
        self.statistics.total_reviews += 1;
        self.statistics.total_issues += result.issues.len() as u64;

        // Update issue counts by severity
        for issue in &result.issues {
            let severity_key = format!("{:?}", issue.severity);
            *self
                .statistics
                .issues_by_severity
                .entry(severity_key)
                .or_insert(0) += 1;

            let category_key = format!("{:?}", issue.category);
            *self
                .statistics
                .issues_by_category
                .entry(category_key)
                .or_insert(0) += 1;
        }

        // Update quality score average
        let total_score =
            self.statistics.average_quality_score * (self.statistics.total_reviews - 1) as f64;
        self.statistics.average_quality_score =
            (total_score + result.quality_score) / self.statistics.total_reviews as f64;

        // Update review time average
        let total_time =
            self.statistics.average_review_time_ms * (self.statistics.total_reviews - 1) as u64;
        self.statistics.average_review_time_ms =
            (total_time + result.review_time_ms) / self.statistics.total_reviews;

        // Update pass/fail counts
        match result.status {
            ReviewStatus::Passed => self.statistics.reviews_passed += 1,
            ReviewStatus::Failed => self.statistics.reviews_failed += 1,
            _ => {} // Warnings don't count as pass or fail
        }
    }
}

#[async_trait]
impl AutomatedReviewer for ComprehensiveAutomatedReviewer {
    async fn review_code(&self, code: &str, file_path: &str) -> Result<ReviewResult, ReviewError> {
        let start_time = std::time::Instant::now();

        // Apply all enabled rules
        let issues = self.apply_rules(code, file_path)?;

        // Calculate quality score
        let quality_score = self.calculate_quality_score(code, &issues);

        // Determine review status
        let status = self.determine_status(&issues, quality_score);

        let review_time_ms = start_time.elapsed().as_millis() as u64;

        // Get applied rule IDs
        let rules_applied = self
            .rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.id.clone())
            .collect();

        let result = ReviewResult {
            status,
            issues,
            quality_score,
            review_time_ms,
            rules_applied,
        };

        Ok(result)
    }

    async fn get_statistics(&self) -> Result<ReviewStatistics, ReviewError> {
        Ok(self.statistics.clone())
    }

    async fn configure_rules(&mut self, rules: Vec<ReviewRule>) -> Result<(), ReviewError> {
        // Validate rules
        for rule in &rules {
            if let Err(e) = regex::Regex::new(&rule.pattern) {
                return Err(ReviewError::PatternError {
                    message: format!("Invalid regex pattern in rule {}: {}", rule.id, e),
                });
            }
        }

        self.rules = rules;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_automated_reviewer_creation() {
        let reviewer = ComprehensiveAutomatedReviewer::new();
        assert!(!reviewer.rules.is_empty());
    }

    #[tokio::test]
    async fn test_code_review_with_issues() {
        let reviewer = ComprehensiveAutomatedReviewer::new();

        let code_with_issues = r#"
            const PASSWORD: &str = "secret123";
            let data = String::new();

            pub fn undocumented_function() {
                if true {
                    if false {
                        for _ in 0..10 {
                            let cloned = data.clone();
                        }
                    }
                }
            }
        "#;

        let result = reviewer
            .review_code(code_with_issues, "test.rs")
            .await
            .unwrap();

        // Should find issues
        assert!(!result.issues.is_empty());
        assert!(result.quality_score < 10.0);
        assert!(result.review_time_ms > 0);
    }

    #[tokio::test]
    async fn test_clean_code_review() {
        let reviewer = ComprehensiveAutomatedReviewer::new();

        let clean_code = r#"
            /// This is a well-documented function
            /// # Arguments
            /// * `data` - Input data
            /// # Returns
            /// Processed data
            pub fn process_data(data: &str) -> String {
                data.to_uppercase()
            }
        "#;

        let result = reviewer.review_code(clean_code, "test.rs").await.unwrap();

        // Should have high quality score
        assert!(result.quality_score > 8.0);
        assert!(result.review_time_ms > 0);
    }

    #[test]
    fn test_rule_configuration() {
        let mut reviewer = ComprehensiveAutomatedReviewer::new();

        let custom_rules = vec![ReviewRule {
            id: "CUSTOM-001".to_string(),
            name: "Custom Rule".to_string(),
            description: "A custom review rule".to_string(),
            category: IssueCategory::Security,
            severity: IssueSeverity::Medium,
            pattern: r"todo!".to_string(),
            message: "TODO found".to_string(),
            suggestion: "Replace TODO with actual implementation".to_string(),
            enabled: true,
        }];

        // This should work in an async context
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            reviewer.configure_rules(custom_rules).await.unwrap();
            assert_eq!(reviewer.rules.len(), 1);
            assert_eq!(reviewer.rules[0].id, "CUSTOM-001");
        });
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let mut reviewer = ComprehensiveAutomatedReviewer::new();

        // Perform a few reviews
        let code = "fn test() {}";
        let result1 = reviewer.review_code(code, "test1.rs").await.unwrap();
        let result2 = reviewer.review_code(code, "test2.rs").await.unwrap();

        // Update statistics manually (since it's private)
        reviewer.update_statistics(&result1);
        reviewer.update_statistics(&result2);

        let stats = reviewer.get_statistics().await.unwrap();

        assert_eq!(stats.total_reviews, 2);
        assert!(stats.average_quality_score > 0.0);
        assert!(stats.average_review_time_ms > 0);
    }

    #[test]
    fn test_quality_score_calculation() {
        let reviewer = ComprehensiveAutomatedReviewer::new();

        let clean_code = "/// Documentation\npub fn test() {}";
        let issues = vec![]; // No issues
        let score = reviewer.calculate_quality_score(clean_code, &issues);
        assert!(score > 8.0); // High score for documented code

        let undocumented_code = "pub fn test() {}";
        let score2 = reviewer.calculate_quality_score(undocumented_code, &issues);
        assert!(score2 < score); // Lower score for undocumented code
    }

    #[test]
    fn test_status_determination() {
        let reviewer = ComprehensiveAutomatedReviewer::new();

        // Test with no issues and high score
        let issues = vec![];
        let status = reviewer.determine_status(&issues, 9.0);
        assert!(matches!(status, ReviewStatus::Passed));

        // Test with critical issue
        let critical_issue = ReviewIssue {
            rule_id: "test".to_string(),
            severity: IssueSeverity::Critical,
            message: "Critical issue".to_string(),
            file: "test.rs".to_string(),
            line: 1,
            column: 0,
            code_snippet: "test".to_string(),
            suggestion: "fix".to_string(),
            category: IssueCategory::Security,
        };

        let status = reviewer.determine_status(&[critical_issue], 9.0);
        assert!(matches!(status, ReviewStatus::Failed));

        // Test with low quality score
        let status = reviewer.determine_status(&issues, 2.0);
        assert!(matches!(status, ReviewStatus::Failed));
    }
}
