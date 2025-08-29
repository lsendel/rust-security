//! Linting Module for Code Quality and Style Checking
//!
//! This module provides comprehensive linting capabilities including:
//! - Code style and formatting validation
//! - Complexity and maintainability checks
//! - Best practice enforcement
//! - Custom rule definition and application
//! - Integration with existing linters (clippy, rustfmt)
//! - Detailed error reporting and suggestions

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Linter trait
pub trait Linter: Send + Sync {
    /// Lint code and return issues
    fn lint_code(&self, code: &str, file_path: &str) -> Result<LintResult, LintError>;

    /// Get supported rules
    fn get_rules(&self) -> Vec<LintRule>;

    /// Configure linter rules
    fn configure_rules(&mut self, config: LintConfig) -> Result<(), LintError>;
}

/// Lint result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintResult {
    pub file_path: String,
    pub issues: Vec<LintIssue>,
    pub statistics: LintStatistics,
    pub passed: bool,
}

/// Lint issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintIssue {
    pub rule: LintRule,
    pub message: String,
    pub severity: IssueSeverity,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub code_snippet: String,
    pub suggestion: String,
}

/// Lint rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: RuleCategory,
    pub severity: IssueSeverity,
    pub pattern: Option<String>,
    pub check_function: Option<String>, // For custom checks
    pub enabled: bool,
    pub fixable: bool,
}

/// Rule category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleCategory {
    Style,
    Maintainability,
    Performance,
    Security,
    Documentation,
    BestPractice,
}

/// Issue severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
}

/// Lint statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintStatistics {
    pub total_lines: usize,
    pub total_issues: usize,
    pub issues_by_severity: HashMap<String, usize>,
    pub issues_by_category: HashMap<String, usize>,
    pub code_complexity: f64,
    pub maintainability_index: f64,
}

/// Lint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintConfig {
    pub max_line_length: usize,
    pub max_function_length: usize,
    pub max_file_length: usize,
    pub max_complexity: usize,
    pub require_documentation: bool,
    pub strict_naming: bool,
    pub allow_todo_comments: bool,
    pub custom_rules: Vec<LintRule>,
    pub excluded_rules: Vec<String>,
}

/// Lint error
#[derive(Debug, thiserror::Error)]
pub enum LintError {
    #[error("Linting failed: {message}")]
    LintFailed { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Pattern compilation error: {message}")]
    PatternError { message: String },

    #[error("File parsing error: {message}")]
    ParseError { message: String },
}

/// Comprehensive linter implementation
pub struct ComprehensiveLinter {
    config: LintConfig,
    rules: Vec<LintRule>,
}

impl ComprehensiveLinter {
    /// Create new comprehensive linter
    pub fn new(config: LintConfig) -> Self {
        let mut linter = Self {
            config,
            rules: Vec::new(),
        };

        linter.load_default_rules();
        linter.apply_configuration();

        linter
    }

    /// Load default linting rules
    fn load_default_rules(&mut self) {
        self.rules = vec![
            // Style Rules
            LintRule {
                id: "style-line-length".to_string(),
                name: "Line Length".to_string(),
                description: "Lines should not exceed maximum length".to_string(),
                category: RuleCategory::Style,
                severity: IssueSeverity::Warning,
                pattern: None,
                check_function: Some("check_line_length".to_string()),
                enabled: true,
                fixable: true,
            },
            LintRule {
                id: "style-naming-convention".to_string(),
                name: "Naming Convention".to_string(),
                description: "Follow Rust naming conventions".to_string(),
                category: RuleCategory::Style,
                severity: IssueSeverity::Warning,
                pattern: Some(r"(?i)\b[a-z]+[A-Z][a-zA-Z]*\b".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },
            LintRule {
                id: "style-trailing-whitespace".to_string(),
                name: "Trailing Whitespace".to_string(),
                description: "Remove trailing whitespace".to_string(),
                category: RuleCategory::Style,
                severity: IssueSeverity::Info,
                pattern: Some(r"\s+$".to_string()),
                check_function: None,
                enabled: true,
                fixable: true,
            },

            // Maintainability Rules
            LintRule {
                id: "maintainability-function-length".to_string(),
                name: "Function Length".to_string(),
                description: "Functions should not be too long".to_string(),
                category: RuleCategory::Maintainability,
                severity: IssueSeverity::Warning,
                pattern: None,
                check_function: Some("check_function_length".to_string()),
                enabled: true,
                fixable: false,
            },
            LintRule {
                id: "maintainability-complexity".to_string(),
                name: "Cyclomatic Complexity".to_string(),
                description: "Functions should not be too complex".to_string(),
                category: RuleCategory::Maintainability,
                severity: IssueSeverity::Warning,
                pattern: None,
                check_function: Some("check_complexity".to_string()),
                enabled: true,
                fixable: false,
            },
            LintRule {
                id: "maintainability-nested-control".to_string(),
                name: "Nested Control Structures".to_string(),
                description: "Avoid deeply nested control structures".to_string(),
                category: RuleCategory::Maintainability,
                severity: IssueSeverity::Warning,
                pattern: Some(r"(?m)^\s*(if|for|while|match)\s+.*\{\s*$(\s*(if|for|while|match)\s+.*\{\s*$){3,}".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },

            // Documentation Rules
            LintRule {
                id: "documentation-missing-pub".to_string(),
                name: "Missing Public Documentation".to_string(),
                description: "Public items should have documentation".to_string(),
                category: RuleCategory::Documentation,
                severity: IssueSeverity::Warning,
                pattern: Some(r"(?m)^pub\s+(fn|struct|enum|trait|mod)\s+\w+".to_string()),
                check_function: Some("check_public_docs".to_string()),
                enabled: true,
                fixable: false,
            },
            LintRule {
                id: "documentation-todo-comments".to_string(),
                name: "TODO Comments".to_string(),
                description: "TODO comments should be addressed".to_string(),
                category: RuleCategory::Documentation,
                severity: IssueSeverity::Info,
                pattern: Some(r"(?i)todo".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },

            // Security Rules
            LintRule {
                id: "security-unsafe-code".to_string(),
                name: "Unsafe Code".to_string(),
                description: "Review usage of unsafe code blocks".to_string(),
                category: RuleCategory::Security,
                severity: IssueSeverity::Warning,
                pattern: Some(r"unsafe\s*\{".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },
            LintRule {
                id: "security-panic-usage".to_string(),
                name: "Panic Usage".to_string(),
                description: "Avoid using panic! in production code".to_string(),
                category: RuleCategory::Security,
                severity: IssueSeverity::Warning,
                pattern: Some(r"panic!\s*\(".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },

            // Performance Rules
            LintRule {
                id: "performance-unnecessary-clone".to_string(),
                name: "Unnecessary Clone".to_string(),
                description: "Avoid unnecessary clone() calls".to_string(),
                category: RuleCategory::Performance,
                severity: IssueSeverity::Info,
                pattern: Some(r"\.clone\(\)\s*;?\s*$".to_string()),
                check_function: None,
                enabled: true,
                fixable: true,
            },
            LintRule {
                id: "performance-large-allocation".to_string(),
                name: "Large Allocation".to_string(),
                description: "Review large data structure allocations".to_string(),
                category: RuleCategory::Performance,
                severity: IssueSeverity::Info,
                pattern: Some(r"Vec<[^>]*>\s*=\s*vec!\[.*;.*1000.*\]".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },

            // Best Practice Rules
            LintRule {
                id: "best-practice-unused-variable".to_string(),
                name: "Unused Variable".to_string(),
                description: "Variables should be used or prefixed with underscore".to_string(),
                category: RuleCategory::BestPractice,
                severity: IssueSeverity::Warning,
                pattern: Some(r"let\s+(\w+)\s*=.*;(?!\s*\w+\s*=.*\1|.*\1\s*[;)}]|.*\1\s*\.)".to_string()),
                check_function: Some("check_unused_variables".to_string()),
                enabled: true,
                fixable: true,
            },
            LintRule {
                id: "best-practice-unnecessary-unwrap".to_string(),
                name: "Unnecessary Unwrap".to_string(),
                description: "Avoid unwrap() and expect() in production code".to_string(),
                category: RuleCategory::BestPractice,
                severity: IssueSeverity::Warning,
                pattern: Some(r"\.(unwrap|expect)\(\)".to_string()),
                check_function: None,
                enabled: true,
                fixable: false,
            },
            LintRule {
                id: "best-practice-missing-error-handling".to_string(),
                name: "Missing Error Handling".to_string(),
                description: "All Result types should be handled properly".to_string(),
                category: RuleCategory::BestPractice,
                severity: IssueSeverity::Warning,
                pattern: Some(r"Result<[^>]*>".*\{").to_string()),
                check_function: Some("check_error_handling".to_string()),
                enabled: true,
                fixable: false,
            },
        ];
    }

    /// Apply configuration to rules
    fn apply_configuration(&mut self) {
        // Enable/disable rules based on configuration
        for rule in &mut self.rules {
            // Disable rules that are in the excluded list
            if self.config.excluded_rules.contains(&rule.id) {
                rule.enabled = false;
            }

            // Override severity for documentation rules
            if matches!(rule.category, RuleCategory::Documentation) && !self.config.require_documentation {
                rule.severity = IssueSeverity::Info;
            }

            // Override naming rules
            if rule.id.contains("naming") && !self.config.strict_naming {
                rule.severity = IssueSeverity::Info;
            }

            // Handle TODO comments
            if rule.id.contains("todo") && self.config.allow_todo_comments {
                rule.enabled = false;
            }
        }

        // Add custom rules from configuration
        self.rules.extend(self.config.custom_rules.clone());
    }

    /// Apply all linting rules to code
    fn apply_rules(&self, code: &str, file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = code.lines().collect();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let rule_issues = if let Some(pattern) = &rule.pattern {
                self.apply_pattern_rule(rule, pattern, code, file_path, &lines)?
            } else if let Some(check_function) = &rule.check_function {
                self.apply_function_rule(rule, check_function, code, file_path, &lines)?
            } else {
                Vec::new()
            };

            issues.extend(rule_issues);
        }

        Ok(issues)
    }

    /// Apply pattern-based rule
    fn apply_pattern_rule(
        &self,
        rule: &LintRule,
        pattern: &str,
        code: &str,
        file_path: &str,
        lines: &[&str],
    ) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        let regex = regex::Regex::new(pattern)
            .map_err(|e| LintError::PatternError {
                message: format!("Invalid regex pattern in rule {}: {}", rule.id, e),
            })?;

        for (line_idx, line) in lines.iter().enumerate() {
            for mat in regex.find_iter(line) {
                let issue = LintIssue {
                    rule: rule.clone(),
                    message: rule.description.clone(),
                    severity: rule.severity.clone(),
                    file: file_path.to_string(),
                    line: line_idx + 1,
                    column: mat.start(),
                    code_snippet: line.trim().to_string(),
                    suggestion: self.generate_suggestion(rule, line),
                };
                issues.push(issue);
            }
        }

        Ok(issues)
    }

    /// Apply function-based rule
    fn apply_function_rule(
        &self,
        rule: &LintRule,
        check_function: &str,
        code: &str,
        file_path: &str,
        lines: &[&str],
    ) -> Result<Vec<LintIssue>, LintError> {
        match check_function {
            "check_line_length" => self.check_line_length(rule, lines, file_path),
            "check_function_length" => self.check_function_length(rule, code, file_path),
            "check_complexity" => self.check_complexity(rule, code, file_path),
            "check_public_docs" => self.check_public_docs(rule, code, file_path),
            "check_unused_variables" => self.check_unused_variables(rule, code, file_path),
            "check_error_handling" => self.check_error_handling(rule, code, file_path),
            _ => Ok(Vec::new()),
        }
    }

    /// Check line length violations
    fn check_line_length(&self, rule: &LintRule, lines: &[&str], file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            if line.len() > self.config.max_line_length {
                let issue = LintIssue {
                    rule: rule.clone(),
                    message: format!("Line exceeds {} characters", self.config.max_line_length),
                    severity: rule.severity.clone(),
                    file: file_path.to_string(),
                    line: line_idx + 1,
                    column: 0,
                    code_snippet: line.to_string(),
                    suggestion: "Break line into multiple lines or shorten variable names".to_string(),
                };
                issues.push(issue);
            }
        }

        Ok(issues)
    }

    /// Check function length violations
    fn check_function_length(&self, rule: &LintRule, code: &str, file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        // Simple function detection and length checking
        let function_pattern = regex::Regex::new(r"fn\s+\w+.*\{([^}]*)\}")
            .map_err(|e| LintError::PatternError {
                message: format!("Function pattern error: {}", e),
            })?;

        for cap in function_pattern.captures_iter(code) {
            if let Some(body) = cap.get(1) {
                let line_count = body.as_str().lines().count();
                if line_count > self.config.max_function_length {
                    let issue = LintIssue {
                        rule: rule.clone(),
                        message: format!("Function exceeds {} lines", self.config.max_function_length),
                        severity: rule.severity.clone(),
                        file: file_path.to_string(),
                        line: 0, // Would need more sophisticated parsing to get exact line
                        column: 0,
                        code_snippet: body.as_str().to_string(),
                        suggestion: "Break function into smaller functions".to_string(),
                    };
                    issues.push(issue);
                }
            }
        }

        Ok(issues)
    }

    /// Check code complexity
    fn check_complexity(&self, rule: &LintRule, code: &str, file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        // Calculate cyclomatic complexity
        let if_count = code.matches("if ").count();
        let match_count = code.matches("match ").count();
        let for_count = code.matches("for ").count();
        let while_count = code.matches("while ").count();
        let function_count = code.matches("fn ").count();

        let complexity = 1 + if_count + match_count + for_count + while_count + function_count;

        if complexity > self.config.max_complexity {
            let issue = LintIssue {
                rule: rule.clone(),
                message: format!("Code complexity ({}) exceeds maximum ({})", complexity, self.config.max_complexity),
                severity: rule.severity.clone(),
                file: file_path.to_string(),
                line: 1,
                column: 0,
                code_snippet: format!("// Complexity: {}", complexity),
                suggestion: "Refactor to reduce complexity".to_string(),
            };
            issues.push(issue);
        }

        Ok(issues)
    }

    /// Check public documentation
    fn check_public_docs(&self, rule: &LintRule, code: &str, file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        let public_pattern = regex::Regex::new(r"(?m)^pub\s+(fn|struct|enum|trait|mod)\s+\w+")
            .map_err(|e| LintError::PatternError {
                message: format!("Public pattern error: {}", e),
            })?;

        for (line_idx, line) in code.lines().enumerate() {
            if public_pattern.is_match(line) {
                // Check if there's documentation before this line
                let has_docs = if line_idx > 0 {
                    let prev_line = code.lines().nth(line_idx - 1).unwrap_or("");
                    prev_line.trim().starts_with("///") || prev_line.trim().starts_with("//!")
                } else {
                    false
                };

                if !has_docs {
                    let issue = LintIssue {
                        rule: rule.clone(),
                        message: "Public item missing documentation".to_string(),
                        severity: rule.severity.clone(),
                        file: file_path.to_string(),
                        line: line_idx + 1,
                        column: 0,
                        code_snippet: line.to_string(),
                        suggestion: "Add documentation comment starting with ///".to_string(),
                    };
                    issues.push(issue);
                }
            }
        }

        Ok(issues)
    }

    /// Check unused variables
    fn check_unused_variables(&self, rule: &LintRule, code: &str, file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        let var_pattern = regex::Regex::new(r"let\s+(\w+)\s*=")
            .map_err(|e| LintError::PatternError {
                message: format!("Variable pattern error: {}", e),
            })?;

        for (line_idx, line) in code.lines().enumerate() {
            for cap in var_pattern.captures_iter(line) {
                if let Some(var_name) = cap.get(1) {
                    let var_name = var_name.as_str();

                    // Check if variable is used later in the function
                    let remaining_code = &code[code.lines().skip(line_idx + 1).map(|l| l.to_string() + "\n").collect::<String>()];
                    if !remaining_code.contains(var_name) {
                        let issue = LintIssue {
                            rule: rule.clone(),
                            message: format!("Unused variable: {}", var_name),
                            severity: rule.severity.clone(),
                            file: file_path.to_string(),
                            line: line_idx + 1,
                            column: cap.get(1).unwrap().start(),
                            code_snippet: line.to_string(),
                            suggestion: format!("Remove unused variable or prefix with underscore: _{}", var_name),
                        };
                        issues.push(issue);
                    }
                }
            }
        }

        Ok(issues)
    }

    /// Check error handling
    fn check_error_handling(&self, rule: &LintRule, code: &str, file_path: &str) -> Result<Vec<LintIssue>, LintError> {
        let mut issues = Vec::new();

        // Look for Result types that might not be handled properly
        let result_pattern = regex::Regex::new(r"Result<[^>]*>")
            .map_err(|e| LintError::PatternError {
                message: format!("Result pattern error: {}", e),
            })?;

        for (line_idx, line) in code.lines().enumerate() {
            if result_pattern.is_match(line) && !line.contains('?') && !line.contains("unwrap") && !line.contains("expect") {
                // This is a simplified check - in reality, you'd need more sophisticated analysis
                let issue = LintIssue {
                    rule: rule.clone(),
                    message: "Result type may not be handled properly".to_string(),
                    severity: rule.severity.clone(),
                    file: file_path.to_string(),
                    line: line_idx + 1,
                    column: 0,
                    code_snippet: line.to_string(),
                    suggestion: "Use ? operator, match statement, or proper error handling".to_string(),
                };
                issues.push(issue);
            }
        }

        Ok(issues)
    }

    /// Generate suggestion for a rule violation
    fn generate_suggestion(&self, rule: &LintRule, line: &str) -> String {
        match rule.id.as_str() {
            "style-line-length" => "Break line into multiple lines or shorten expressions".to_string(),
            "style-naming-convention" => "Use snake_case for variables/functions, PascalCase for types".to_string(),
            "style-trailing-whitespace" => "Remove trailing whitespace".to_string(),
            "maintainability-function-length" => "Extract function into smaller, focused functions".to_string(),
            "maintainability-complexity" => "Simplify logic or break into smaller functions".to_string(),
            "documentation-missing-pub" => "Add documentation comment with ///".to_string(),
            "security-unsafe-code" => "Review unsafe block necessity and safety".to_string(),
            "performance-unnecessary-clone" => "Use references or move semantics instead".to_string(),
            "best-practice-unused-variable" => "Remove variable or prefix with underscore if intentionally unused".to_string(),
            _ => format!("Address {} violation", rule.name),
        }
    }

    /// Calculate linting statistics
    fn calculate_statistics(&self, issues: &[LintIssue], code: &str) -> LintStatistics {
        let mut issues_by_severity = HashMap::new();
        let mut issues_by_category = HashMap::new();

        for issue in issues {
            let severity_key = format!("{:?}", issue.severity);
            *issues_by_severity.entry(severity_key).or_insert(0) += 1;

            let category_key = format!("{:?}", issue.rule.category);
            *issues_by_category.entry(category_key).or_insert(0) += 1;
        }

        // Calculate basic complexity metrics
        let total_lines = code.lines().count();
        let code_complexity = self.calculate_code_complexity(code);
        let maintainability_index = self.calculate_maintainability_index(code);

        LintStatistics {
            total_lines,
            total_issues: issues.len(),
            issues_by_severity,
            issues_by_category,
            code_complexity,
            maintainability_index,
        }
    }

    /// Calculate code complexity metric
    fn calculate_code_complexity(&self, code: &str) -> f64 {
        let if_count = code.matches("if ").count() as f64;
        let match_count = code.matches("match ").count() as f64;
        let loop_count = code.matches("for ").count() as f64 + code.matches("while ").count() as f64;
        let function_count = code.matches("fn ").count() as f64;

        // Simplified complexity formula
        1.0 + (if_count * 1.0) + (match_count * 0.5) + (loop_count * 1.5) + function_count
    }

    /// Calculate maintainability index
    fn calculate_maintainability_index(&self, code: &str) -> f64 {
        let lines_of_code = code.lines().count() as f64;
        let comment_lines = code.lines()
            .filter(|line| line.trim().starts_with("//") || line.trim().starts_with("///"))
            .count() as f64;

        if lines_of_code == 0.0 {
            return 100.0;
        }

        let comment_ratio = comment_lines / lines_of_code;
        let complexity = self.calculate_code_complexity(code);

        // Simplified maintainability index (0-100 scale)
        let base_score = 100.0;
        let complexity_penalty = (complexity / 10.0).min(40.0);
        let comment_bonus = (comment_ratio * 20.0).min(20.0);

        (base_score - complexity_penalty + comment_bonus).max(0.0).min(100.0)
    }

    /// Determine if linting passed
    fn determine_passed(&self, issues: &[LintIssue]) -> bool {
        !issues.iter().any(|issue| matches!(issue.severity, IssueSeverity::Error))
    }
}

impl Linter for ComprehensiveLinter {
    fn lint_code(&self, code: &str, file_path: &str) -> Result<LintResult, LintError> {
        let issues = self.apply_rules(code, file_path)?;
        let statistics = self.calculate_statistics(&issues, code);
        let passed = self.determine_passed(&issues);

        Ok(LintResult {
            file_path: file_path.to_string(),
            issues,
            statistics,
            passed,
        })
    }

    fn get_rules(&self) -> Vec<LintRule> {
        self.rules.clone()
    }

    fn configure_rules(&mut self, config: LintConfig) -> Result<(), LintError> {
        self.config = config;
        self.apply_configuration();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linter_creation() {
        let config = LintConfig {
            max_line_length: 100,
            max_function_length: 50,
            max_file_length: 1000,
            max_complexity: 10,
            require_documentation: true,
            strict_naming: true,
            allow_todo_comments: false,
            custom_rules: vec![],
            excluded_rules: vec![],
        };

        let linter = ComprehensiveLinter::new(config);
        assert!(!linter.get_rules().is_empty());
    }

    #[test]
    fn test_line_length_checking() {
        let config = LintConfig {
            max_line_length: 50,
            max_function_length: 50,
            max_file_length: 1000,
            max_complexity: 10,
            require_documentation: true,
            strict_naming: true,
            allow_todo_comments: false,
            custom_rules: vec![],
            excluded_rules: vec![],
        };

        let linter = ComprehensiveLinter::new(config);

        let long_line = "This is a very long line that exceeds the maximum allowed line length and should trigger a linting warning";
        let result = linter.lint_code(long_line, "test.rs").unwrap();

        assert!(!result.issues.is_empty());
        assert!(result.issues.iter().any(|i| i.rule.id == "style-line-length"));
    }

    #[test]
    fn test_complexity_calculation() {
        let config = LintConfig::default();
        let linter = ComprehensiveLinter::new(config);

        let complex_code = r#"
            fn complex_function() {
                if condition1 {
                    if condition2 {
                        for item in items {
                            match item {
                                Case1 => {},
                                Case2 => {},
                                _ => {}
                            }
                        }
                    }
                }
                while running {
                    // loop
                }
            }
        "#;

        let complexity = linter.calculate_code_complexity(complex_code);
        assert!(complexity >= 7.0); // 1 + 2(if) + 1(match) + 1(for) + 1(while) + 1(fn)
    }

    #[test]
    fn test_maintainability_index() {
        let config = LintConfig::default();
        let linter = ComprehensiveLinter::new(config);

        let well_documented_code = r#"
            /// This is a well-documented function
            /// It performs important operations
            pub fn documented_function() {
                // Simple implementation
            }
        "#;

        let index = linter.calculate_maintainability_index(well_documented_code);
        assert!(index > 80.0); // High maintainability due to documentation
    }

    #[test]
    fn test_public_docs_checking() {
        let config = LintConfig {
            max_line_length: 100,
            max_function_length: 50,
            max_file_length: 1000,
            max_complexity: 10,
            require_documentation: true,
            strict_naming: true,
            allow_todo_comments: false,
            custom_rules: vec![],
            excluded_rules: vec![],
        };

        let linter = ComprehensiveLinter::new(config);

        let undocumented_code = r#"
            pub fn public_function() {}
            pub struct PublicStruct {}
        "#;

        let result = linter.lint_code(undocumented_code, "test.rs").unwrap();

        // Should find missing documentation issues
        assert!(result.issues.iter().any(|i| i.rule.id == "documentation-missing-pub"));
    }

    #[test]
    fn test_rule_configuration() {
        let mut config = LintConfig::default();
        config.excluded_rules = vec!["style-line-length".to_string()];
        config.max_line_length = 50;

        let mut linter = ComprehensiveLinter::new(config);

        // The line length rule should be disabled
        let disabled_rules: Vec<_> = linter.get_rules().into_iter()
            .filter(|r| r.id == "style-line-length" && !r.enabled)
            .collect();

        assert!(!disabled_rules.is_empty());
    }

    #[test]
    fn test_statistics_calculation() {
        let config = LintConfig::default();
        let linter = ComprehensiveLinter::new(config);

        let code = r#"
            /// Documented function
            pub fn test() {
                if true {
                    println!("test");
                }
            }
        "#;

        let result = linter.lint_code(code, "test.rs").unwrap();

        assert_eq!(result.statistics.total_lines, 7);
        assert!(result.statistics.code_complexity >= 2.0); // 1 + 1(if) + 1(fn)
        assert!(result.statistics.maintainability_index > 70.0); // Good due to documentation
    }
}
