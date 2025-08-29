//! Code Review Standards and Quality Rules
//!
//! This module defines comprehensive code review standards including:
//! - Code quality rules and guidelines
//! - Naming conventions and patterns
//! - Documentation requirements
//! - Security standards
//! - Performance guidelines
//! - Testing standards
//! - Maintainability criteria

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Code standard definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeStandard {
    pub name: String,
    pub version: String,
    pub description: String,
    pub rules: Vec<ReviewRule>,
    pub categories: Vec<StandardCategory>,
    pub severity_levels: HashMap<String, RuleSeverity>,
}

/// Standard categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StandardCategory {
    Security,
    Performance,
    Maintainability,
    Documentation,
    Testing,
    Architecture,
    CodeStyle,
    BestPractices,
}

/// Review rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRule {
    pub id: String,
    pub category: StandardCategory,
    pub severity: RuleSeverity,
    pub title: String,
    pub description: String,
    pub rationale: String,
    pub examples: Vec<RuleExample>,
    pub exceptions: Vec<String>,
    pub references: Vec<String>,
    pub automated: bool,
    pub enabled: bool,
}

/// Rule severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Rule example
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExample {
    pub description: String,
    pub good_example: Option<String>,
    pub bad_example: Option<String>,
}

/// Quality guideline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityGuideline {
    pub id: String,
    pub category: StandardCategory,
    pub title: String,
    pub description: String,
    pub checklist: Vec<String>,
    pub resources: Vec<String>,
}

/// Standards registry
pub struct StandardsRegistry {
    standards: HashMap<String, CodeStandard>,
    guidelines: Vec<QualityGuideline>,
}

impl StandardsRegistry {
    /// Create new standards registry with default Rust/Security standards
    pub fn new() -> Self {
        let mut registry = Self {
            standards: HashMap::new(),
            guidelines: Vec::new(),
        };

        registry.load_default_standards();
        registry.load_quality_guidelines();

        registry
    }

    /// Load default code review standards
    fn load_default_standards(&mut self) {
        // Security Standards
        let security_standard = CodeStandard {
            name: "Security Code Review Standard".to_string(),
            version: "1.0".to_string(),
            description: "Security-focused code review standards for enterprise applications".to_string(),
            rules: vec![
                ReviewRule {
                    id: "SEC-001".to_string(),
                    category: StandardCategory::Security,
                    severity: RuleSeverity::Critical,
                    title: "No hardcoded secrets or credentials".to_string(),
                    description: "Never hardcode passwords, API keys, or other sensitive credentials in source code".to_string(),
                    rationale: "Hardcoded credentials can be easily discovered and exploited by attackers".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Avoid hardcoded passwords".to_string(),
                            bad_example: Some("const PASSWORD: &str = \"mysecretpassword\";".to_string()),
                            good_example: Some("Use environment variables or secure vaults".to_string()),
                        }
                    ],
                    exceptions: vec!["Test code with dummy values".to_string()],
                    references: vec!["OWASP A02:2021 - Cryptographic Failures".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "SEC-002".to_string(),
                    category: StandardCategory::Security,
                    severity: RuleSeverity::Critical,
                    title: "Input validation and sanitization".to_string(),
                    description: "All user inputs must be validated and sanitized before processing".to_string(),
                    rationale: "Unvalidated input can lead to injection attacks and data corruption".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Validate and sanitize SQL inputs".to_string(),
                            bad_example: Some("format!(\"SELECT * FROM users WHERE id = {}\", user_id)".to_string()),
                            good_example: Some("Use prepared statements with parameter binding".to_string()),
                        }
                    ],
                    exceptions: vec![],
                    references: vec!["OWASP A03:2021 - Injection".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "SEC-003".to_string(),
                    category: StandardCategory::Security,
                    severity: RuleSeverity::High,
                    title: "Proper error handling without information disclosure".to_string(),
                    description: "Error messages must not leak sensitive information".to_string(),
                    rationale: "Detailed error messages can reveal system internals to attackers".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Avoid exposing stack traces or internal errors".to_string(),
                            bad_example: Some("return Err(format!(\"Database error: {}\", e))".to_string()),
                            good_example: Some("return Err(\"Internal server error\".to_string())".to_string()),
                        }
                    ],
                    exceptions: vec!["Development environments with debug logging".to_string()],
                    references: vec!["OWASP A04:2021 - Insecure Design".to_string()],
                    automated: false,
                    enabled: true,
                },
                ReviewRule {
                    id: "SEC-004".to_string(),
                    category: StandardCategory::Security,
                    severity: RuleSeverity::High,
                    title: "Secure authentication and session management".to_string(),
                    description: "Implement proper authentication and secure session handling".to_string(),
                    rationale: "Weak authentication enables unauthorized access".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Use secure session tokens".to_string(),
                            bad_example: Some("Store session data in URL parameters".to_string()),
                            good_example: Some("Use HttpOnly, Secure cookies with proper expiration".to_string()),
                        }
                    ],
                    exceptions: vec![],
                    references: vec!["OWASP A07:2021 - Identification and Authentication Failures".to_string()],
                    automated: false,
                    enabled: true,
                },
                ReviewRule {
                    id: "SEC-005".to_string(),
                    category: StandardCategory::Security,
                    severity: RuleSeverity::Medium,
                    title: "Secure logging practices".to_string(),
                    description: "Log security events without exposing sensitive data".to_string(),
                    rationale: "Insecure logging can lead to data leakage and compliance violations".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Avoid logging sensitive information".to_string(),
                            bad_example: Some("log::info!(\"User login: {} with password: {}\", username, password)".to_string()),
                            good_example: Some("log::info!(\"User login attempt: {}\", username)".to_string()),
                        }
                    ],
                    exceptions: vec![],
                    references: vec!["OWASP A09:2021 - Security Logging and Monitoring Failures".to_string()],
                    automated: true,
                    enabled: true,
                },
            ],
            categories: vec![StandardCategory::Security],
            severity_levels: HashMap::from([
                ("info".to_string(), RuleSeverity::Info),
                ("warning".to_string(), RuleSeverity::Warning),
                ("error".to_string(), RuleSeverity::Error),
                ("critical".to_string(), RuleSeverity::Critical),
            ]),
        };

        // Performance Standards
        let performance_standard = CodeStandard {
            name: "Performance Code Review Standard".to_string(),
            version: "1.0".to_string(),
            description: "Performance-focused code review standards".to_string(),
            rules: vec![
                ReviewRule {
                    id: "PERF-001".to_string(),
                    category: StandardCategory::Performance,
                    severity: RuleSeverity::High,
                    title: "Avoid unnecessary allocations".to_string(),
                    description: "Minimize heap allocations in performance-critical code paths"
                        .to_string(),
                    rationale: "Excessive allocations can impact performance and memory usage"
                        .to_string(),
                    examples: vec![RuleExample {
                        description: "Use stack allocation when possible".to_string(),
                        bad_example: Some("let s = String::from(\"hello\");".to_string()),
                        good_example: Some("let s = \"hello\";".to_string()),
                    }],
                    exceptions: vec!["When heap allocation is necessary for ownership".to_string()],
                    references: vec!["Rust Performance Book".to_string()],
                    automated: false,
                    enabled: true,
                },
                ReviewRule {
                    id: "PERF-002".to_string(),
                    category: StandardCategory::Performance,
                    severity: RuleSeverity::Medium,
                    title: "Use efficient data structures".to_string(),
                    description: "Choose appropriate data structures for the use case".to_string(),
                    rationale: "Wrong data structure choice can significantly impact performance"
                        .to_string(),
                    examples: vec![RuleExample {
                        description: "Use HashMap for frequent lookups".to_string(),
                        bad_example: Some("Searching Vec for each lookup".to_string()),
                        good_example: Some("Use HashMap for O(1) lookups".to_string()),
                    }],
                    exceptions: vec![],
                    references: vec!["Algorithm Design Manual".to_string()],
                    automated: false,
                    enabled: true,
                },
                ReviewRule {
                    id: "PERF-003".to_string(),
                    category: StandardCategory::Performance,
                    severity: RuleSeverity::Medium,
                    title: "Avoid blocking operations in async code".to_string(),
                    description: "Don't use blocking operations in async contexts".to_string(),
                    rationale: "Blocking operations can cause thread starvation".to_string(),
                    examples: vec![RuleExample {
                        description: "Use async file operations".to_string(),
                        bad_example: Some("std::fs::read_to_string(path)?".to_string()),
                        good_example: Some("tokio::fs::read_to_string(path).await?".to_string()),
                    }],
                    exceptions: vec!["Short blocking operations in dedicated threads".to_string()],
                    references: vec!["Async Book".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "PERF-004".to_string(),
                    category: StandardCategory::Performance,
                    severity: RuleSeverity::Warning,
                    title: "Limit collection sizes in memory".to_string(),
                    description: "Prevent unbounded memory growth in collections".to_string(),
                    rationale: "Unbounded collections can cause memory exhaustion".to_string(),
                    examples: vec![RuleExample {
                        description: "Limit vector growth".to_string(),
                        bad_example: Some("vec.push(item); // Unlimited growth".to_string()),
                        good_example: Some(
                            "if vec.len() < MAX_SIZE { vec.push(item); }".to_string(),
                        ),
                    }],
                    exceptions: vec!["When memory limits are enforced elsewhere".to_string()],
                    references: vec!["System Resource Limits".to_string()],
                    automated: false,
                    enabled: true,
                },
            ],
            categories: vec![StandardCategory::Performance],
            severity_levels: HashMap::from([
                ("info".to_string(), RuleSeverity::Info),
                ("warning".to_string(), RuleSeverity::Warning),
                ("error".to_string(), RuleSeverity::Error),
                ("critical".to_string(), RuleSeverity::Critical),
            ]),
        };

        // Maintainability Standards
        let maintainability_standard = CodeStandard {
            name: "Code Maintainability Standard".to_string(),
            version: "1.0".to_string(),
            description: "Standards for maintainable and readable code".to_string(),
            rules: vec![
                ReviewRule {
                    id: "MAINT-001".to_string(),
                    category: StandardCategory::Maintainability,
                    severity: RuleSeverity::Error,
                    title: "Function complexity limit".to_string(),
                    description: "Functions should not exceed cyclomatic complexity of 10"
                        .to_string(),
                    rationale: "High complexity makes code hard to understand and maintain"
                        .to_string(),
                    examples: vec![RuleExample {
                        description: "Break down complex functions".to_string(),
                        bad_example: Some(
                            "fn complex_function() { /* 20+ conditional branches */ }".to_string(),
                        ),
                        good_example: Some(
                            "fn simple_function() { /* < 10 branches */ }".to_string(),
                        ),
                    }],
                    exceptions: vec!["Generated code".to_string()],
                    references: vec!["Clean Code by Robert Martin".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "MAINT-002".to_string(),
                    category: StandardCategory::Maintainability,
                    severity: RuleSeverity::Warning,
                    title: "Function length limit".to_string(),
                    description: "Functions should not exceed 50 lines".to_string(),
                    rationale: "Long functions are hard to understand and test".to_string(),
                    examples: vec![RuleExample {
                        description: "Extract smaller functions".to_string(),
                        bad_example: Some("fn long_function() { /* 100+ lines */ }".to_string()),
                        good_example: Some("fn short_function() { /* < 50 lines */ }".to_string()),
                    }],
                    exceptions: vec!["Simple data structure definitions".to_string()],
                    references: vec!["Clean Code by Robert Martin".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "MAINT-003".to_string(),
                    category: StandardCategory::Maintainability,
                    severity: RuleSeverity::Error,
                    title: "Require documentation for public APIs".to_string(),
                    description:
                        "All public functions, structs, and modules must have documentation"
                            .to_string(),
                    rationale: "Documentation is essential for API usability and maintenance"
                        .to_string(),
                    examples: vec![RuleExample {
                        description: "Document public functions".to_string(),
                        bad_example: Some("pub fn my_function() {}".to_string()),
                        good_example: Some(
                            "/// This function does something important\npub fn my_function() {}"
                                .to_string(),
                        ),
                    }],
                    exceptions: vec!["Test functions".to_string()],
                    references: vec!["Rust API Guidelines".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "MAINT-004".to_string(),
                    category: StandardCategory::Maintainability,
                    severity: RuleSeverity::Warning,
                    title: "Consistent naming conventions".to_string(),
                    description:
                        "Follow Rust naming conventions for variables, functions, and types"
                            .to_string(),
                    rationale: "Consistent naming improves code readability".to_string(),
                    examples: vec![RuleExample {
                        description: "Use snake_case for functions and variables".to_string(),
                        bad_example: Some("fn MyFunction() {}".to_string()),
                        good_example: Some("fn my_function() {}".to_string()),
                    }],
                    exceptions: vec![],
                    references: vec!["Rust Naming Conventions".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "MAINT-005".to_string(),
                    category: StandardCategory::Maintainability,
                    severity: RuleSeverity::Info,
                    title: "Avoid TODO comments".to_string(),
                    description: "Replace TODO comments with proper issue tracking".to_string(),
                    rationale: "TODO comments can be forgotten and don't track progress"
                        .to_string(),
                    examples: vec![RuleExample {
                        description: "Use issue tracking instead of TODO".to_string(),
                        bad_example: Some("// TODO: Implement this feature".to_string()),
                        good_example: Some(
                            "// See issue #123 for implementation details".to_string(),
                        ),
                    }],
                    exceptions: vec!["Temporary TODOs with specific deadlines".to_string()],
                    references: vec!["Code Review Best Practices".to_string()],
                    automated: true,
                    enabled: true,
                },
            ],
            categories: vec![StandardCategory::Maintainability],
            severity_levels: HashMap::from([
                ("info".to_string(), RuleSeverity::Info),
                ("warning".to_string(), RuleSeverity::Warning),
                ("error".to_string(), RuleSeverity::Error),
                ("critical".to_string(), RuleSeverity::Critical),
            ]),
        };

        // Documentation Standards
        let documentation_standard = CodeStandard {
            name: "Documentation Standard".to_string(),
            version: "1.0".to_string(),
            description: "Standards for code documentation and comments".to_string(),
            rules: vec![
                ReviewRule {
                    id: "DOC-001".to_string(),
                    category: StandardCategory::Documentation,
                    severity: RuleSeverity::Error,
                    title: "Comprehensive module documentation".to_string(),
                    description: "Every module must have a module-level doc comment explaining its purpose".to_string(),
                    rationale: "Module documentation helps developers understand the codebase structure".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Document module purpose".to_string(),
                            bad_example: Some("mod my_module;".to_string()),
                            good_example: Some("/// This module handles user authentication\nmod my_module;".to_string()),
                        }
                    ],
                    exceptions: vec!["Test modules".to_string()],
                    references: vec!["Rust Documentation Guidelines".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "DOC-002".to_string(),
                    category: StandardCategory::Documentation,
                    severity: RuleSeverity::Warning,
                    title: "Function parameter documentation".to_string(),
                    description: "Document all function parameters and return values".to_string(),
                    rationale: "Parameter documentation clarifies function usage".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Document parameters".to_string(),
                            bad_example: Some("/// Processes user data\nfn process_user(data: UserData) {}".to_string()),
                            good_example: Some("/// Processes user data\n///\n/// # Arguments\n/// * `data` - The user data to process\nfn process_user(data: UserData) {}".to_string()),
                        }
                    ],
                    exceptions: vec!["Simple getter/setter functions".to_string()],
                    references: vec!["Rust Doc Comments".to_string()],
                    automated: true,
                    enabled: true,
                },
                ReviewRule {
                    id: "DOC-003".to_string(),
                    category: StandardCategory::Documentation,
                    severity: RuleSeverity::Info,
                    title: "Example code in documentation".to_string(),
                    description: "Include usage examples in documentation where appropriate".to_string(),
                    rationale: "Examples help developers understand how to use the code".to_string(),
                    examples: vec![
                        RuleExample {
                            description: "Add usage examples".to_string(),
                            bad_example: Some("/// Creates a new user\nfn create_user(name: &str) -> User".to_string()),
                            good_example: Some("/// Creates a new user\n///\n/// # Example\n/// ```\n/// let user = create_user(\"Alice\");\n/// ```\nfn create_user(name: &str) -> User".to_string()),
                        }
                    ],
                    exceptions: vec!["Internal implementation functions".to_string()],
                    references: vec!["Rust Documentation Best Practices".to_string()],
                    automated: false,
                    enabled: true,
                },
            ],
            categories: vec![StandardCategory::Documentation],
            severity_levels: HashMap::from([
                ("info".to_string(), RuleSeverity::Info),
                ("warning".to_string(), RuleSeverity::Warning),
                ("error".to_string(), RuleSeverity::Error),
                ("critical".to_string(), RuleSeverity::Critical),
            ]),
        };

        self.standards
            .insert("security".to_string(), security_standard);
        self.standards
            .insert("performance".to_string(), performance_standard);
        self.standards
            .insert("maintainability".to_string(), maintainability_standard);
        self.standards
            .insert("documentation".to_string(), documentation_standard);
    }

    /// Load quality guidelines
    fn load_quality_guidelines(&mut self) {
        self.guidelines = vec![
            QualityGuideline {
                id: "QG-001".to_string(),
                category: StandardCategory::Security,
                title: "Security Code Review Checklist".to_string(),
                description: "Comprehensive checklist for security code reviews".to_string(),
                checklist: vec![
                    "✅ Verify input validation and sanitization".to_string(),
                    "✅ Check for hardcoded secrets or credentials".to_string(),
                    "✅ Ensure proper error handling without information disclosure".to_string(),
                    "✅ Validate authentication and authorization mechanisms".to_string(),
                    "✅ Review logging practices for sensitive data exposure".to_string(),
                    "✅ Check for proper session management".to_string(),
                    "✅ Verify encryption and data protection measures".to_string(),
                    "✅ Ensure secure configuration management".to_string(),
                ],
                resources: vec![
                    "OWASP Top 10".to_string(),
                    "NIST Cybersecurity Framework".to_string(),
                ],
            },
            QualityGuideline {
                id: "QG-002".to_string(),
                category: StandardCategory::Performance,
                title: "Performance Review Checklist".to_string(),
                description: "Checklist for performance-focused code reviews".to_string(),
                checklist: vec![
                    "✅ Identify performance bottlenecks".to_string(),
                    "✅ Check for unnecessary allocations".to_string(),
                    "✅ Verify efficient data structure usage".to_string(),
                    "✅ Ensure proper async/await patterns".to_string(),
                    "✅ Check for memory leaks".to_string(),
                    "✅ Validate caching strategies".to_string(),
                    "✅ Review database query efficiency".to_string(),
                    "✅ Monitor resource utilization".to_string(),
                ],
                resources: vec![
                    "Rust Performance Book".to_string(),
                    "Systems Performance".to_string(),
                ],
            },
            QualityGuideline {
                id: "QG-003".to_string(),
                category: StandardCategory::Maintainability,
                title: "Code Maintainability Checklist".to_string(),
                description: "Checklist for assessing code maintainability".to_string(),
                checklist: vec![
                    "✅ Verify code complexity is within acceptable limits".to_string(),
                    "✅ Check function and module sizes".to_string(),
                    "✅ Ensure consistent naming conventions".to_string(),
                    "✅ Validate documentation coverage".to_string(),
                    "✅ Check for code duplication".to_string(),
                    "✅ Review error handling patterns".to_string(),
                    "✅ Validate test coverage".to_string(),
                    "✅ Assess technical debt".to_string(),
                ],
                resources: vec![
                    "Clean Code by Robert Martin".to_string(),
                    "Code Complete".to_string(),
                ],
            },
            QualityGuideline {
                id: "QG-004".to_string(),
                category: StandardCategory::Testing,
                title: "Testing Standards Checklist".to_string(),
                description: "Checklist for comprehensive testing practices".to_string(),
                checklist: vec![
                    "✅ Verify unit test coverage > 80%".to_string(),
                    "✅ Check for integration tests".to_string(),
                    "✅ Validate error case testing".to_string(),
                    "✅ Ensure edge case coverage".to_string(),
                    "✅ Check performance testing".to_string(),
                    "✅ Validate security testing".to_string(),
                    "✅ Review test documentation".to_string(),
                    "✅ Assess test maintainability".to_string(),
                ],
                resources: vec![
                    "Effective Unit Testing".to_string(),
                    "Growing Object-Oriented Software".to_string(),
                ],
            },
        ];
    }

    /// Get standard by name
    pub fn get_standard(&self, name: &str) -> Option<&CodeStandard> {
        self.standards.get(name)
    }

    /// Get all standards
    pub fn get_all_standards(&self) -> &HashMap<String, CodeStandard> {
        &self.standards
    }

    /// Get quality guidelines
    pub fn get_guidelines(&self) -> &[QualityGuideline] {
        &self.guidelines
    }

    /// Get guidelines by category
    pub fn get_guidelines_by_category(
        &self,
        category: &StandardCategory,
    ) -> Vec<&QualityGuideline> {
        self.guidelines
            .iter()
            .filter(|g| &g.category == category)
            .collect()
    }

    /// Validate code against standards
    pub fn validate_code(
        &self,
        code: &str,
        file_path: &str,
        standards: &[&str],
    ) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        for standard_name in standards {
            if let Some(standard) = self.get_standard(standard_name) {
                for rule in &standard.rules {
                    if rule.enabled && rule.automated {
                        let rule_results = self.validate_rule(code, file_path, rule);
                        results.extend(rule_results);
                    }
                }
            }
        }

        results
    }

    /// Validate single rule
    fn validate_rule(
        &self,
        code: &str,
        file_path: &str,
        rule: &ReviewRule,
    ) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        match rule.id.as_str() {
            "SEC-001" => {
                // Check for hardcoded secrets
                if self.contains_hardcoded_secrets(code) {
                    results.push(ValidationResult {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        message: rule.title.clone(),
                        file: file_path.to_string(),
                        line: 0,
                        suggestion: "Use environment variables or secure vaults for secrets"
                            .to_string(),
                    });
                }
            }
            "SEC-002" => {
                // Check for input validation
                if !self.has_input_validation(code) {
                    results.push(ValidationResult {
                        rule_id: rule.id.clone(),
                        severity: RuleSeverity::Warning,
                        message: "Consider adding input validation".to_string(),
                        file: file_path.to_string(),
                        line: 0,
                        suggestion: "Add input validation before processing user data".to_string(),
                    });
                }
            }
            "MAINT-001" => {
                // Check cyclomatic complexity
                let complexity = self.calculate_cyclomatic_complexity(code);
                if complexity > 10 {
                    results.push(ValidationResult {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        message: format!("High cyclomatic complexity: {}", complexity),
                        file: file_path.to_string(),
                        line: 0,
                        suggestion: "Break down complex functions into smaller ones".to_string(),
                    });
                }
            }
            "MAINT-003" => {
                // Check documentation
                if !self.has_public_docs(code) {
                    results.push(ValidationResult {
                        rule_id: rule.id.clone(),
                        severity: rule.severity.clone(),
                        message: "Missing documentation for public APIs".to_string(),
                        file: file_path.to_string(),
                        line: 0,
                        suggestion: "Add documentation comments for public functions and structs"
                            .to_string(),
                    });
                }
            }
            _ => {
                // Placeholder for other rules
            }
        }

        results
    }

    fn contains_hardcoded_secrets(&self, code: &str) -> bool {
        let secret_patterns = [
            r#"password\s*=\s*["'][^"']*["']"#,
            r#"secret\s*=\s*["'][^"']*["']"#,
            r#"token\s*=\s*["'][^"']*["']"#,
            r#"key\s*=\s*["'][^"']*["']"#,
        ];

        for pattern in &secret_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if regex.is_match(code) {
                    return true;
                }
            }
        }

        false
    }

    fn has_input_validation(&self, code: &str) -> bool {
        // Simple check for validation patterns
        code.contains("validate") || code.contains("sanitize") || code.contains("check")
    }

    fn has_public_docs(&self, code: &str) -> bool {
        // Check for documentation comments on public items
        let public_items = code
            .lines()
            .filter(|line| line.trim().starts_with("pub "))
            .count();

        let documented_items = code
            .lines()
            .filter(|line| line.trim().starts_with("///") || line.trim().starts_with("//!"))
            .count();

        documented_items >= public_items
    }

    fn calculate_cyclomatic_complexity(&self, code: &str) -> usize {
        let if_count = code.matches("if ").count();
        let match_count = code.matches("match ").count();
        let for_count = code.matches("for ").count();
        let while_count = code.matches("while ").count();
        let function_count = code.matches("fn ").count();

        // Base complexity + decision points
        1 + if_count + match_count + for_count + while_count + function_count
    }
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub rule_id: String,
    pub severity: RuleSeverity,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub suggestion: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standards_registry_creation() {
        let registry = StandardsRegistry::new();
        assert!(!registry.standards.is_empty());
        assert!(!registry.guidelines.is_empty());
    }

    #[test]
    fn test_get_standard() {
        let registry = StandardsRegistry::new();
        let security_standard = registry.get_standard("security");
        assert!(security_standard.is_some());
        assert_eq!(
            security_standard.unwrap().name,
            "Security Code Review Standard"
        );
    }

    #[test]
    fn test_guidelines_by_category() {
        let registry = StandardsRegistry::new();
        let security_guidelines = registry.get_guidelines_by_category(&StandardCategory::Security);
        assert!(!security_guidelines.is_empty());
        assert_eq!(
            security_guidelines[0].title,
            "Security Code Review Checklist"
        );
    }

    #[test]
    fn test_hardcoded_secrets_detection() {
        let registry = StandardsRegistry::new();
        let code_with_secrets = r#"
            const PASSWORD: &str = "mysecretpassword";
            let token = "secret_token_123";
        "#;

        let code_without_secrets = r#"
            fn authenticate() {
                // Secrets loaded from environment
            }
        "#;

        assert!(registry.contains_hardcoded_secrets(code_with_secrets));
        assert!(!registry.contains_hardcoded_secrets(code_without_secrets));
    }

    #[test]
    fn test_cyclomatic_complexity_calculation() {
        let registry = StandardsRegistry::new();
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

        let complexity = registry.calculate_cyclomatic_complexity(complex_code);
        assert!(complexity >= 7); // 1 (base) + 2 (if) + 1 (for) + 1 (match) + 1 (while) + 1 (fn)
    }

    #[test]
    fn test_documentation_check() {
        let registry = StandardsRegistry::new();

        let undocumented_code = r#"
            pub fn public_function() {}
            pub struct PublicStruct {}
        "#;

        let documented_code = r#"
            /// This is a public function
            pub fn public_function() {}

            /// This is a public struct
            pub struct PublicStruct {}
        "#;

        assert!(!registry.has_public_docs(undocumented_code));
        assert!(registry.has_public_docs(documented_code));
    }

    #[test]
    fn test_code_validation() {
        let registry = StandardsRegistry::new();
        let code_with_issues = r#"
            const PASSWORD: &str = "secret123";
            fn complex_function() {
                if true {
                    if false {
                        for _ in 0..10 {
                            match 1 {
                                1 => {},
                                2 => {},
                                _ => {}
                            }
                        }
                    }
                }
            }
            pub fn undocumented() {}
        "#;

        let results = registry.validate_code(
            code_with_issues,
            "test.rs",
            &["security", "maintainability"],
        );
        assert!(!results.is_empty());

        // Should find hardcoded password and high complexity
        let has_security_issue = results.iter().any(|r| r.rule_id.starts_with("SEC"));
        let has_maintainability_issue = results.iter().any(|r| r.rule_id.starts_with("MAINT"));

        assert!(has_security_issue || has_maintainability_issue);
    }
}
