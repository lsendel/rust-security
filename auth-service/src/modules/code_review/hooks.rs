//! Git Hooks Integration for Automated Code Review
//!
//! This module provides Git hooks integration for automated code review including:
//! - Pre-commit hooks for code quality validation
//! - Post-commit hooks for reporting and notifications
//! - Hook installation and management
//! - CI/CD pipeline integration
//! - Automated code review triggers

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// Hook trait
#[async_trait]
pub trait Hook: Send + Sync {
    /// Execute the hook
    async fn execute(&self, context: &HookContext) -> Result<HookResult, HookError>;

    /// Get hook configuration
    fn get_config(&self) -> &HookConfig;

    /// Update hook configuration
    fn update_config(&mut self, config: HookConfig) -> Result<(), HookError>;
}

/// Pre-commit hook trait
#[async_trait]
pub trait PreCommitHook: Hook {
    /// Validate code before commit
    async fn validate_code(
        &self,
        files: &[String],
        context: &HookContext,
    ) -> Result<ValidationResult, HookError>;
}

/// Post-commit hook trait
#[async_trait]
pub trait PostCommitHook: Hook {
    /// Process after commit
    async fn process_commit(
        &self,
        commit_hash: &str,
        context: &HookContext,
    ) -> Result<ProcessResult, HookError>;
}

/// Hook result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    pub success: bool,
    pub message: String,
    pub issues: Vec<HookIssue>,
    pub suggestions: Vec<String>,
    pub execution_time_ms: u64,
}

/// Hook issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookIssue {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub severity: HookSeverity,
    pub message: String,
    pub rule_id: String,
}

/// Hook severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HookSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Hook context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookContext {
    pub repository_path: String,
    pub branch_name: String,
    pub commit_hash: Option<String>,
    pub author: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub environment: HookEnvironment,
}

/// Hook environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookEnvironment {
    Local,
    CI,
    CD,
}

/// Hook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    pub enabled: bool,
    pub fail_on_warnings: bool,
    pub fail_on_errors: bool,
    pub timeout_seconds: u64,
    pub max_issues_per_file: usize,
    pub excluded_files: Vec<String>,
    pub excluded_extensions: Vec<String>,
    pub required_checks: Vec<String>,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub passed: bool,
    pub issues: Vec<HookIssue>,
    pub files_processed: usize,
    pub validation_time_ms: u64,
}

/// Process result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessResult {
    pub success: bool,
    pub message: String,
    pub processed_files: Vec<String>,
    pub processing_time_ms: u64,
}

/// Hook error
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("Hook execution failed: {message}")]
    ExecutionFailed { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Git command failed: {message}")]
    GitError { message: String },

    #[error("File system error: {source}")]
    FileSystemError {
        #[from]
        source: std::io::Error,
    },

    #[error("Timeout error")]
    TimeoutError,

    #[error("Validation error: {message}")]
    ValidationError { message: String },
}

/// Pre-commit hook implementation
pub struct CodeReviewPreCommitHook {
    config: HookConfig,
    reviewer: crate::modules::code_review::automated_review::ComprehensiveAutomatedReviewer,
    linter: crate::modules::code_review::linting::ComprehensiveLinter,
    formatter: crate::modules::code_review::formatting::RustFormatter,
}

impl CodeReviewPreCommitHook {
    /// Create new pre-commit hook
    pub fn new(
        config: HookConfig,
        reviewer: crate::modules::code_review::automated_review::ComprehensiveAutomatedReviewer,
        linter: crate::modules::code_review::linting::ComprehensiveLinter,
        formatter: crate::modules::code_review::formatting::RustFormatter,
    ) -> Self {
        Self {
            config,
            reviewer,
            linter,
            formatter,
        }
    }

    /// Get staged files for validation
    fn get_staged_files(&self) -> Result<Vec<String>, HookError> {
        let output = Command::new("git")
            .args(["diff", "--cached", "--name-only"])
            .output()
            .map_err(|e| HookError::GitError {
                message: format!("Failed to get staged files: {}", e),
            })?;

        if !output.status.success() {
            return Err(HookError::GitError {
                message: "Git command failed".to_string(),
            });
        }

        let files = String::from_utf8(output.stdout).map_err(|e| HookError::GitError {
            message: format!("Invalid UTF-8 in git output: {}", e),
        })?;

        Ok(files
            .lines()
            .map(|s| s.to_string())
            .filter(|f| self.should_process_file(f))
            .collect())
    }

    /// Check if file should be processed
    fn should_process_file(&self, file_path: &str) -> bool {
        // Check excluded files
        if self.config.excluded_files.contains(&file_path.to_string()) {
            return false;
        }

        // Check excluded extensions
        if let Some(ext) = Path::new(file_path).extension() {
            if self
                .config
                .excluded_extensions
                .contains(&ext.to_string_lossy().to_string())
            {
                return false;
            }
        }

        // Only process Rust files for now
        file_path.ends_with(".rs")
    }

    /// Read file content
    fn read_file_content(&self, file_path: &str) -> Result<String, HookError> {
        std::fs::read_to_string(file_path).map_err(|e| HookError::FileSystemError { source: e })
    }

    /// Run validation checks
    async fn run_validation_checks(&self, files: &[String]) -> Result<Vec<HookIssue>, HookError> {
        let mut all_issues = Vec::new();

        for file_path in files {
            let content = self.read_file_content(file_path)?;

            // Automated review
            if self.config.required_checks.contains(&"review".to_string()) {
                let review_result = self
                    .reviewer
                    .review_code(&content, file_path)
                    .await
                    .map_err(|e| HookError::ExecutionFailed {
                        message: format!("Review failed for {}: {}", file_path, e),
                    })?;

                let review_issues: Vec<HookIssue> = review_result.issues.into_iter()
                    .map(|issue| HookIssue {
                        file: file_path.clone(),
                        line: issue.line,
                        column: issue.column,
                        severity: match issue.severity {
                            crate::modules::code_review::automated_review::IssueSeverity::Critical => HookSeverity::Critical,
                            crate::modules::code_review::automated_review::IssueSeverity::High => HookSeverity::Error,
                            crate::modules::code_review::automated_review::IssueSeverity::Medium => HookSeverity::Warning,
                            crate::modules::code_review::automated_review::IssueSeverity::Low => HookSeverity::Warning,
                            crate::modules::code_review::automated_review::IssueSeverity::Info => HookSeverity::Info,
                        },
                        message: issue.message,
                        rule_id: issue.rule_id,
                    })
                    .collect();

                all_issues.extend(review_issues);
            }

            // Linting
            if self.config.required_checks.contains(&"lint".to_string()) {
                let lint_result = self.linter.lint_code(&content, file_path).map_err(|e| {
                    HookError::ExecutionFailed {
                        message: format!("Linting failed for {}: {}", file_path, e),
                    }
                })?;

                let lint_issues: Vec<HookIssue> = lint_result
                    .issues
                    .into_iter()
                    .map(|issue| HookIssue {
                        file: file_path.clone(),
                        line: issue.line,
                        column: issue.column,
                        severity: match issue.severity {
                            crate::modules::code_review::linting::IssueSeverity::Error => {
                                HookSeverity::Error
                            }
                            crate::modules::code_review::linting::IssueSeverity::Warning => {
                                HookSeverity::Warning
                            }
                            crate::modules::code_review::linting::IssueSeverity::Info => {
                                HookSeverity::Info
                            }
                        },
                        message: issue.message,
                        rule_id: issue.rule.id,
                    })
                    .collect();

                all_issues.extend(lint_issues);
            }

            // Formatting check
            if self.config.required_checks.contains(&"format".to_string()) {
                let format_result =
                    self.formatter
                        .check_format(&content, file_path)
                        .map_err(|e| HookError::ExecutionFailed {
                            message: format!("Format check failed for {}: {}", file_path, e),
                        })?;

                let format_issues: Vec<HookIssue> = format_result
                    .issues
                    .into_iter()
                    .map(|issue| HookIssue {
                        file: file_path.clone(),
                        line: issue.line,
                        column: issue.column,
                        severity: match issue.severity {
                            crate::modules::code_review::formatting::FormatSeverity::Error => {
                                HookSeverity::Error
                            }
                            crate::modules::code_review::formatting::FormatSeverity::Warning => {
                                HookSeverity::Warning
                            }
                            crate::modules::code_review::formatting::FormatSeverity::Info => {
                                HookSeverity::Info
                            }
                        },
                        message: issue.message,
                        rule_id: "formatting".to_string(),
                    })
                    .collect();

                all_issues.extend(format_issues);
            }

            // Check maximum issues per file
            let file_issues: Vec<_> = all_issues
                .iter()
                .filter(|issue| issue.file == *file_path)
                .collect();

            if file_issues.len() > self.config.max_issues_per_file {
                // Truncate issues for this file
                all_issues.retain(|issue| issue.file != *file_path);
                all_issues.push(HookIssue {
                    file: file_path.clone(),
                    line: 0,
                    column: 0,
                    severity: HookSeverity::Warning,
                    message: format!(
                        "Too many issues ({}), showing first {}",
                        file_issues.len(),
                        self.config.max_issues_per_file
                    ),
                    rule_id: "max-issues".to_string(),
                });
            }
        }

        Ok(all_issues)
    }

    /// Generate validation result
    fn generate_validation_result(
        &self,
        issues: Vec<HookIssue>,
        files_processed: usize,
        validation_time_ms: u64,
    ) -> ValidationResult {
        let has_errors = issues
            .iter()
            .any(|i| matches!(i.severity, HookSeverity::Error | HookSeverity::Critical));
        let has_warnings = issues
            .iter()
            .any(|i| matches!(i.severity, HookSeverity::Warning));

        let passed = if self.config.fail_on_errors && has_errors {
            false
        } else if self.config.fail_on_warnings && has_warnings {
            false
        } else {
            !has_errors
        };

        ValidationResult {
            passed,
            issues,
            files_processed,
            validation_time_ms,
        }
    }
}

#[async_trait]
impl PreCommitHook for CodeReviewPreCommitHook {
    async fn validate_code(
        &self,
        files: &[String],
        context: &HookContext,
    ) -> Result<ValidationResult, HookError> {
        if !self.config.enabled {
            return Ok(ValidationResult {
                passed: true,
                issues: vec![],
                files_processed: 0,
                validation_time_ms: 0,
            });
        }

        let start_time = std::time::Instant::now();

        // Filter files to process
        let files_to_process: Vec<String> = files
            .iter()
            .filter(|f| self.should_process_file(f))
            .cloned()
            .collect();

        if files_to_process.is_empty() {
            return Ok(ValidationResult {
                passed: true,
                issues: vec![],
                files_processed: 0,
                validation_time_ms: start_time.elapsed().as_millis() as u64,
            });
        }

        // Run validation checks with timeout
        let issues = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_seconds),
            self.run_validation_checks(&files_to_process),
        )
        .await
        .map_err(|_| HookError::TimeoutError)?
        .map_err(|e| HookError::ExecutionFailed {
            message: format!("Validation failed: {}", e),
        })?;

        let validation_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(self.generate_validation_result(issues, files_to_process.len(), validation_time_ms))
    }
}

#[async_trait]
impl Hook for CodeReviewPreCommitHook {
    async fn execute(&self, context: &HookContext) -> Result<HookResult, HookError> {
        let files = self.get_staged_files()?;
        let validation_result = self.validate_code(&files, context).await?;

        let success = validation_result.passed;
        let message = if success {
            format!(
                "✅ Code review passed for {} files",
                validation_result.files_processed
            )
        } else {
            format!(
                "❌ Code review failed: {} issues found",
                validation_result.issues.len()
            )
        };

        let suggestions = if !success {
            vec![
                "Fix the reported issues before committing".to_string(),
                "Run 'cargo fmt' to format your code".to_string(),
                "Run 'cargo clippy' to check for additional issues".to_string(),
            ]
        } else {
            vec![]
        };

        Ok(HookResult {
            success,
            message,
            issues: validation_result.issues,
            suggestions,
            execution_time_ms: validation_result.validation_time_ms,
        })
    }

    fn get_config(&self) -> &HookConfig {
        &self.config
    }

    fn update_config(&mut self, config: HookConfig) -> Result<(), HookError> {
        self.config = config;
        Ok(())
    }
}

/// Post-commit hook implementation
pub struct CodeReviewPostCommitHook {
    config: HookConfig,
    // In a real implementation, this would have notification services
}

impl CodeReviewPostCommitHook {
    pub fn new(config: HookConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PostCommitHook for CodeReviewPostCommitHook {
    async fn process_commit(
        &self,
        commit_hash: &str,
        context: &HookContext,
    ) -> Result<ProcessResult, HookError> {
        if !self.config.enabled {
            return Ok(ProcessResult {
                success: true,
                message: "Post-commit hook disabled".to_string(),
                processed_files: vec![],
                processing_time_ms: 0,
            });
        }

        let start_time = std::time::Instant::now();

        // Get files changed in commit
        let output = Command::new("git")
            .args(["show", "--name-only", "--pretty=format:", commit_hash])
            .output()
            .map_err(|e| HookError::GitError {
                message: format!("Failed to get commit files: {}", e),
            })?;

        let files = String::from_utf8(output.stdout).map_err(|e| HookError::GitError {
            message: format!("Invalid UTF-8 in git output: {}", e),
        })?;

        let processed_files: Vec<String> = files
            .lines()
            .filter(|line| !line.is_empty())
            .map(|s| s.to_string())
            .collect();

        let processing_time_ms = start_time.elapsed().as_millis() as u64;

        // In a real implementation, this would:
        // - Send notifications
        // - Update dashboards
        // - Trigger CI/CD pipelines
        // - Generate reports

        Ok(ProcessResult {
            success: true,
            message: format!(
                "Post-commit processing completed for commit {}",
                commit_hash
            ),
            processed_files,
            processing_time_ms,
        })
    }
}

#[async_trait]
impl Hook for CodeReviewPostCommitHook {
    async fn execute(&self, context: &HookContext) -> Result<HookResult, HookError> {
        if let Some(commit_hash) = &context.commit_hash {
            let process_result = self.process_commit(commit_hash, context).await?;

            Ok(HookResult {
                success: process_result.success,
                message: process_result.message,
                issues: vec![],
                suggestions: vec![],
                execution_time_ms: process_result.processing_time_ms,
            })
        } else {
            Ok(HookResult {
                success: false,
                message: "No commit hash provided".to_string(),
                issues: vec![],
                suggestions: vec![],
                execution_time_ms: 0,
            })
        }
    }

    fn get_config(&self) -> &HookConfig {
        &self.config
    }

    fn update_config(&mut self, config: HookConfig) -> Result<(), HookError> {
        self.config = config;
        Ok(())
    }
}

/// Hook manager for managing multiple hooks
pub struct HookManager {
    pre_commit_hooks: Vec<Box<dyn PreCommitHook>>,
    post_commit_hooks: Vec<Box<dyn PostCommitHook>>,
    config: HookManagerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookManagerConfig {
    pub enable_pre_commit: bool,
    pub enable_post_commit: bool,
    pub fail_fast: bool,
    pub parallel_execution: bool,
}

impl Default for HookManagerConfig {
    fn default() -> Self {
        Self {
            enable_pre_commit: true,
            enable_post_commit: true,
            fail_fast: true,
            parallel_execution: false,
        }
    }
}

impl HookManager {
    /// Create new hook manager
    pub fn new(config: HookManagerConfig) -> Self {
        Self {
            pre_commit_hooks: vec![],
            post_commit_hooks: vec![],
            config,
        }
    }

    /// Add pre-commit hook
    pub fn add_pre_commit_hook(&mut self, hook: Box<dyn PreCommitHook>) {
        self.pre_commit_hooks.push(hook);
    }

    /// Add post-commit hook
    pub fn add_post_commit_hook(&mut self, hook: Box<dyn PostCommitHook>) {
        self.post_commit_hooks.push(hook);
    }

    /// Execute all pre-commit hooks
    pub async fn execute_pre_commit(
        &self,
        context: &HookContext,
    ) -> Result<Vec<HookResult>, HookError> {
        if !self.config.enable_pre_commit {
            return Ok(vec![]);
        }

        let files = Self::get_staged_files_static()?;

        let mut results = Vec::new();

        for hook in &self.pre_commit_hooks {
            let result = hook.execute(context).await?;

            results.push(result.clone());

            // Fail fast if configured and hook failed
            if self.config.fail_fast && !result.success {
                return Ok(results);
            }
        }

        Ok(results)
    }

    /// Execute all post-commit hooks
    pub async fn execute_post_commit(
        &self,
        context: &HookContext,
    ) -> Result<Vec<HookResult>, HookError> {
        if !self.config.enable_post_commit {
            return Ok(vec![]);
        }

        let mut results = Vec::new();

        for hook in &self.post_commit_hooks {
            let result = hook.execute(context).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Get staged files (static method for reuse)
    fn get_staged_files_static() -> Result<Vec<String>, HookError> {
        let output = Command::new("git")
            .args(["diff", "--cached", "--name-only"])
            .output()
            .map_err(|e| HookError::GitError {
                message: format!("Failed to get staged files: {}", e),
            })?;

        if !output.status.success() {
            return Err(HookError::GitError {
                message: "Git command failed".to_string(),
            });
        }

        let files = String::from_utf8(output.stdout).map_err(|e| HookError::GitError {
            message: format!("Invalid UTF-8 in git output: {}", e),
        })?;

        Ok(files.lines().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::code_review::formatting::FormatConfig;
    use crate::modules::code_review::linting::LintConfig;

    #[test]
    fn test_hook_config_defaults() {
        let config = HookConfig {
            enabled: true,
            fail_on_warnings: false,
            fail_on_errors: true,
            timeout_seconds: 30,
            max_issues_per_file: 50,
            excluded_files: vec![],
            excluded_extensions: vec!["md".to_string(), "txt".to_string()],
            required_checks: vec!["review".to_string(), "lint".to_string()],
        };

        assert!(config.enabled);
        assert!(!config.fail_on_warnings);
        assert!(config.fail_on_errors);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_hook_context_creation() {
        let context = HookContext {
            repository_path: "/path/to/repo".to_string(),
            branch_name: "main".to_string(),
            commit_hash: Some("abc123".to_string()),
            author: "test@example.com".to_string(),
            timestamp: chrono::Utc::now(),
            environment: HookEnvironment::CI,
        };

        assert_eq!(context.repository_path, "/path/to/repo");
        assert_eq!(context.branch_name, "main");
        assert_eq!(context.commit_hash, Some("abc123".to_string()));
    }

    #[test]
    fn test_file_filtering() {
        let config = HookConfig {
            enabled: true,
            fail_on_warnings: false,
            fail_on_errors: true,
            timeout_seconds: 30,
            max_issues_per_file: 50,
            excluded_files: vec!["target/debug/build.rs".to_string()],
            excluded_extensions: vec!["md".to_string(), "txt".to_string()],
            required_checks: vec![],
        };

        let hook = CodeReviewPreCommitHook::new(
            config,
            crate::modules::code_review::automated_review::ComprehensiveAutomatedReviewer::new(),
            crate::modules::code_review::linting::ComprehensiveLinter::new(LintConfig::default()),
            crate::modules::code_review::formatting::RustFormatter::new(FormatConfig::default()),
        );

        // Test file filtering
        assert!(hook.should_process_file("src/main.rs"));
        assert!(hook.should_process_file("src/lib.rs"));
        assert!(!hook.should_process_file("README.md"));
        assert!(!hook.should_process_file("docs/guide.txt"));
        assert!(!hook.should_process_file("target/debug/build.rs"));
    }

    #[test]
    fn test_hook_result_structure() {
        let result = HookResult {
            success: false,
            message: "Validation failed".to_string(),
            issues: vec![HookIssue {
                file: "test.rs".to_string(),
                line: 10,
                column: 5,
                severity: HookSeverity::Error,
                message: "Missing semicolon".to_string(),
                rule_id: "syntax".to_string(),
            }],
            suggestions: vec!["Add semicolon".to_string()],
            execution_time_ms: 150,
        };

        assert!(!result.success);
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.suggestions.len(), 1);
        assert_eq!(result.execution_time_ms, 150);
    }

    #[test]
    fn test_hook_manager_config() {
        let config = HookManagerConfig::default();

        assert!(config.enable_pre_commit);
        assert!(config.enable_post_commit);
        assert!(config.fail_fast);
        assert!(!config.parallel_execution);
    }

    #[test]
    fn test_validation_result_creation() {
        let issues = vec![HookIssue {
            file: "test.rs".to_string(),
            line: 1,
            column: 1,
            severity: HookSeverity::Warning,
            message: "Test issue".to_string(),
            rule_id: "test".to_string(),
        }];

        let hook = CodeReviewPreCommitHook::new(
            HookConfig {
                enabled: true,
                fail_on_warnings: false,
                fail_on_errors: true,
                timeout_seconds: 30,
                max_issues_per_file: 50,
                excluded_files: vec![],
                excluded_extensions: vec![],
                required_checks: vec![],
            },
            crate::modules::code_review::automated_review::ComprehensiveAutomatedReviewer::new(),
            crate::modules::code_review::linting::ComprehensiveLinter::new(LintConfig::default()),
            crate::modules::code_review::formatting::RustFormatter::new(FormatConfig::default()),
        );

        let result = hook.generate_validation_result(issues, 1, 100);

        assert!(result.passed); // No errors, only warnings
        assert_eq!(result.files_processed, 1);
        assert_eq!(result.validation_time_ms, 100);
    }
}
