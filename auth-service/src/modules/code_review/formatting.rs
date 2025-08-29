//! Code Formatting Module for Style Consistency
//!
//! This module provides comprehensive code formatting capabilities including:
//! - Code formatting validation against standards
//! - Integration with rustfmt
//! - Custom formatting rules
//! - Formatting consistency checking
//! - Automatic formatting suggestions

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Formatter trait
pub trait Formatter: Send + Sync {
    /// Format code string
    fn format_code(&self, code: &str) -> Result<String, FormatError>;

    /// Check if code is properly formatted
    fn check_format(&self, code: &str, file_path: &str) -> Result<FormatResult, FormatError>;

    /// Get formatting configuration
    fn get_config(&self) -> &FormatConfig;

    /// Update formatting configuration
    fn update_config(&mut self, config: FormatConfig) -> Result<(), FormatError>;
}

/// Format result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatResult {
    pub is_formatted: bool,
    pub formatted_code: Option<String>,
    pub issues: Vec<FormatIssue>,
    pub file_path: String,
}

/// Format issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatIssue {
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub severity: FormatSeverity,
    pub suggestion: String,
}

/// Format severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FormatSeverity {
    Info,
    Warning,
    Error,
}

/// Format configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatConfig {
    pub max_line_length: usize,
    pub indent_size: usize,
    pub use_tabs: bool,
    pub brace_style: BraceStyle,
    pub newline_style: NewlineStyle,
    pub trailing_comma: TrailingCommaStyle,
    pub spaces_around_operators: bool,
    pub align_items: bool,
    pub group_imports: bool,
    pub sort_imports: bool,
    pub remove_unused_imports: bool,
}

/// Brace style options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BraceStyle {
    SameLine,
    NextLine,
    Preserve,
}

/// Newline style options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NewlineStyle {
    Unix,    // \n
    Windows, // \r\n
    Auto,
}

/// Trailing comma style
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrailingCommaStyle {
    Never,
    Always,
    Vertical,
}

/// Format error
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("Formatting failed: {message}")]
    FormatFailed { message: String },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Command execution error: {message}")]
    CommandError { message: String },

    #[error("Parse error: {message}")]
    ParseError { message: String },
}

/// Rust code formatter implementation
pub struct RustFormatter {
    config: FormatConfig,
}

impl RustFormatter {
    /// Create new Rust formatter
    pub fn new(config: FormatConfig) -> Self {
        Self { config }
    }

    /// Format code using rustfmt
    fn format_with_rustfmt(&self, code: &str) -> Result<String, FormatError> {
        use std::io::Write;

        // Create a temporary file
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("temp_format.rs");

        // Write code to temporary file
        std::fs::write(&temp_file, code)
            .map_err(|e| FormatError::CommandError {
                message: format!("Failed to write temp file: {}", e),
            })?;

        // Run rustfmt on the file
        let output = Command::new("rustfmt")
            .arg("--emit")
            .arg("stdout")
            .arg(&temp_file)
            .output()
            .map_err(|e| FormatError::CommandError {
                message: format!("Failed to run rustfmt: {}", e),
            })?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_file);

        if output.status.success() {
            String::from_utf8(output.stdout)
                .map_err(|e| FormatError::ParseError {
                    message: format!("Invalid UTF-8 in formatted output: {}", e),
                })
        } else {
            Err(FormatError::FormatFailed {
                message: String::from_utf8_lossy(&output.stderr).to_string(),
            })
        }
    }

    /// Check formatting without applying changes
    fn check_with_rustfmt(&self, code: &str, file_path: &str) -> Result<FormatResult, FormatError> {
        let formatted = self.format_with_rustfmt(code)?;
        let is_formatted = formatted == code;

        let issues = if !is_formatted {
            vec![FormatIssue {
                line: 0,
                column: 0,
                message: "Code is not properly formatted".to_string(),
                severity: FormatSeverity::Warning,
                suggestion: "Run `cargo fmt` or use the formatter".to_string(),
            }]
        } else {
            vec![]
        };

        Ok(FormatResult {
            is_formatted,
            formatted_code: if !is_formatted { Some(formatted) } else { None },
            issues,
            file_path: file_path.to_string(),
        })
    }

    /// Apply custom formatting rules
    fn apply_custom_rules(&self, code: &str) -> String {
        let mut result = code.to_string();

        // Apply line length rule
        result = self.apply_line_length_rule(&result);

        // Apply brace style
        result = self.apply_brace_style(&result);

        // Apply trailing comma rules
        result = self.apply_trailing_comma_rule(&result);

        // Apply import sorting/grouping
        result = self.apply_import_rules(&result);

        result
    }

    /// Apply line length formatting
    fn apply_line_length_rule(&self, code: &str) -> String {
        let mut result = String::new();

        for line in code.lines() {
            if line.len() > self.config.max_line_length {
                // Simple line breaking - in a real implementation,
                // this would be much more sophisticated
                let words: Vec<&str> = line.split_whitespace().collect();
                let mut current_line = String::new();

                for word in words {
                    if current_line.len() + word.len() + 1 > self.config.max_line_length && !current_line.is_empty() {
                        result.push_str(&current_line);
                        result.push('\n');
                        current_line = word.to_string();
                    } else {
                        if !current_line.is_empty() {
                            current_line.push(' ');
                        }
                        current_line.push_str(word);
                    }
                }

                if !current_line.is_empty() {
                    result.push_str(&current_line);
                    result.push('\n');
                }
            } else {
                result.push_str(line);
                result.push('\n');
            }
        }

        result
    }

    /// Apply brace style formatting
    fn apply_brace_style(&self, code: &str) -> String {
        // This is a simplified implementation
        // A real implementation would use proper AST parsing
        match self.config.brace_style {
            BraceStyle::SameLine => {
                code.replace("{\n", "{ ")
                    .replace("\n}", " }")
            },
            BraceStyle::NextLine => {
                code.replace("{ ", "{\n")
                    .replace(" }", "\n}")
            },
            BraceStyle::Preserve => code.to_string(),
        }
    }

    /// Apply trailing comma rules
    fn apply_trailing_comma_rule(&self, code: &str) -> String {
        // Simplified implementation - real version would parse AST
        match self.config.trailing_comma {
            TrailingCommaStyle::Always => {
                // Add trailing commas where missing
                code.replace(",\n", ",\n").replace("\n}", ",\n}")
            },
            TrailingCommaStyle::Never => {
                // Remove trailing commas
                code.replace(",\n}", "\n}").replace(",\n", "\n")
            },
            TrailingCommaStyle::Vertical => {
                // Add commas for vertical lists
                code.to_string() // Placeholder
            }
        }
    }

    /// Apply import sorting and grouping
    fn apply_import_rules(&self, code: &str) -> String {
        if !self.config.sort_imports && !self.config.group_imports {
            return code.to_string();
        }

        // This is a highly simplified implementation
        // A real implementation would properly parse and sort imports
        let mut lines: Vec<String> = code.lines().map(|s| s.to_string()).collect();

        if self.config.sort_imports {
            // Simple alphabetical sort of import lines
            lines.sort_by(|a, b| {
                if a.starts_with("use ") && b.starts_with("use ") {
                    a.cmp(b)
                } else {
                    std::cmp::Ordering::Equal
                }
            });
        }

        lines.join("\n")
    }

    /// Find formatting issues beyond rustfmt
    fn find_custom_issues(&self, code: &str, file_path: &str) -> Vec<FormatIssue> {
        let mut issues = Vec::new();

        for (line_idx, line) in code.lines().enumerate() {
            // Check for inconsistent indentation
            let indent = line.chars().take_while(|c| c.is_whitespace()).collect::<String>();
            if self.config.use_tabs && indent.contains(' ') {
                issues.push(FormatIssue {
                    line: line_idx + 1,
                    column: 0,
                    message: "Inconsistent indentation: mixing spaces and tabs".to_string(),
                    severity: FormatSeverity::Warning,
                    suggestion: "Use tabs consistently for indentation".to_string(),
                });
            } else if !self.config.use_tabs && indent.contains('\t') {
                issues.push(FormatIssue {
                    line: line_idx + 1,
                    column: 0,
                    message: "Inconsistent indentation: mixing tabs and spaces".to_string(),
                    severity: FormatSeverity::Warning,
                    suggestion: "Use spaces consistently for indentation".to_string(),
                });
            }

            // Check for multiple consecutive blank lines
            // This would need more context to implement properly
        }

        issues
    }
}

impl Default for FormatConfig {
    fn default() -> Self {
        Self {
            max_line_length: 100,
            indent_size: 4,
            use_tabs: false,
            brace_style: BraceStyle::SameLine,
            newline_style: NewlineStyle::Unix,
            trailing_comma: TrailingCommaStyle::Vertical,
            spaces_around_operators: true,
            align_items: false,
            group_imports: true,
            sort_imports: true,
            remove_unused_imports: true,
        }
    }
}

impl Formatter for RustFormatter {
    fn format_code(&self, code: &str) -> Result<String, FormatError> {
        // First apply rustfmt
        let rustfmt_result = self.format_with_rustfmt(code)?;

        // Then apply custom rules
        let custom_result = self.apply_custom_rules(&rustfmt_result);

        Ok(custom_result)
    }

    fn check_format(&self, code: &str, file_path: &str) -> Result<FormatResult, FormatError> {
        // Check with rustfmt first
        let rustfmt_result = self.check_with_rustfmt(code, file_path)?;

        // Find additional custom issues
        let custom_issues = self.find_custom_issues(code, file_path);

        let all_issues = rustfmt_result.issues.into_iter()
            .chain(custom_issues)
            .collect::<Vec<_>>();

        Ok(FormatResult {
            is_formatted: rustfmt_result.is_formatted && custom_issues.is_empty(),
            formatted_code: rustfmt_result.formatted_code,
            issues: all_issues,
            file_path: file_path.to_string(),
        })
    }

    fn get_config(&self) -> &FormatConfig {
        &self.config
    }

    fn update_config(&mut self, config: FormatConfig) -> Result<(), FormatError> {
        self.config = config;
        Ok(())
    }
}

/// Generic code formatter for other languages
pub struct GenericFormatter {
    config: FormatConfig,
}

impl GenericFormatter {
    pub fn new(config: FormatConfig) -> Self {
        Self { config }
    }
}

impl Formatter for GenericFormatter {
    fn format_code(&self, code: &str) -> Result<String, FormatError> {
        // Apply basic formatting rules
        let mut result = code.to_string();

        // Apply line length
        result = self.apply_line_length(&result);

        // Apply indentation
        result = self.apply_indentation(&result);

        // Apply brace style
        result = self.apply_braces(&result);

        Ok(result)
    }

    fn check_format(&self, code: &str, file_path: &str) -> Result<FormatResult, FormatError> {
        let formatted = self.format_code(code)?;
        let is_formatted = formatted == code;

        let issues = if !is_formatted {
            vec![FormatIssue {
                line: 0,
                column: 0,
                message: "Code formatting does not match standards".to_string(),
                severity: FormatSeverity::Warning,
                suggestion: "Run formatter to fix formatting issues".to_string(),
            }]
        } else {
            vec![]
        };

        Ok(FormatResult {
            is_formatted,
            formatted_code: if !is_formatted { Some(formatted) } else { None },
            issues,
            file_path: file_path.to_string(),
        })
    }

    fn get_config(&self) -> &FormatConfig {
        &self.config
    }

    fn update_config(&mut self, config: FormatConfig) -> Result<(), FormatError> {
        self.config = config;
        Ok(())
    }
}

impl GenericFormatter {
    fn apply_line_length(&self, code: &str) -> String {
        // Simplified line length handling
        let mut result = String::new();

        for line in code.lines() {
            if line.len() > self.config.max_line_length {
                // Simple line breaking
                let mut current_line = String::new();
                let words: Vec<&str> = line.split_whitespace().collect();

                for word in words {
                    if current_line.len() + word.len() + 1 > self.config.max_line_length {
                        if !current_line.is_empty() {
                            result.push_str(&current_line);
                            result.push('\n');
                        }
                        current_line = word.to_string();
                    } else {
                        if !current_line.is_empty() {
                            current_line.push(' ');
                        }
                        current_line.push_str(word);
                    }
                }

                if !current_line.is_empty() {
                    result.push_str(&current_line);
                    result.push('\n');
                }
            } else {
                result.push_str(line);
                result.push('\n');
            }
        }

        result
    }

    fn apply_indentation(&self, code: &str) -> String {
        // Simplified indentation handling
        let indent_char = if self.config.use_tabs { '\t' } else { ' ' };
        let indent_size = if self.config.use_tabs { 1 } else { self.config.indent_size };

        code.lines()
            .map(|line| {
                let indent_level = line.chars().take_while(|c| c.is_whitespace()).count() / indent_size;
                let new_indent = indent_char.to_string().repeat(indent_level * indent_size);
                let content = line.trim_start();
                format!("{}{}", new_indent, content)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn apply_braces(&self, code: &str) -> String {
        match self.config.brace_style {
            BraceStyle::SameLine => {
                code.replace("{\n", "{ ")
                    .replace("\n}", " }")
            },
            BraceStyle::NextLine => {
                code.replace("{ ", "{\n")
                    .replace(" }", "\n}")
            },
            BraceStyle::Preserve => code.to_string(),
        }
    }
}

/// Factory for creating formatters
pub struct FormatterFactory;

impl FormatterFactory {
    /// Create formatter for a specific language
    pub fn create_formatter(language: &str, config: FormatConfig) -> Box<dyn Formatter> {
        match language.to_lowercase().as_str() {
            "rust" | "rs" => Box::new(RustFormatter::new(config)),
            _ => Box::new(GenericFormatter::new(config)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_formatter_creation() {
        let config = FormatConfig::default();
        let formatter = RustFormatter::new(config);

        assert_eq!(formatter.get_config().max_line_length, 100);
        assert!(!formatter.get_config().use_tabs);
    }

    #[test]
    fn test_generic_formatter_creation() {
        let config = FormatConfig::default();
        let formatter = GenericFormatter::new(config);

        assert_eq!(formatter.get_config().max_line_length, 100);
    }

    #[test]
    fn test_line_length_formatting() {
        let config = FormatConfig {
            max_line_length: 20,
            ..Default::default()
        };

        let formatter = GenericFormatter::new(config);
        let long_line = "This is a very long line that should be broken up";
        let result = formatter.apply_line_length(long_line);

        // Should break the line
        assert!(result.contains('\n'));
        assert!(result.lines().count() > 1);
    }

    #[test]
    fn test_indentation_formatting() {
        let config = FormatConfig {
            indent_size: 2,
            use_tabs: false,
            ..Default::default()
        };

        let formatter = GenericFormatter::new(config);
        let code = "  function() {\n    return true;\n  }";
        let result = formatter.apply_indentation(code);

        assert!(result.contains("  function"));
        assert!(result.contains("    return"));
    }

    #[test]
    fn test_brace_style_formatting() {
        let config = FormatConfig {
            brace_style: BraceStyle::SameLine,
            ..Default::default()
        };

        let formatter = GenericFormatter::new(config);
        let code = "function()\n{\n  return true;\n}";
        let result = formatter.apply_braces(code);

        assert!(result.contains("function() {"));
        assert!(result.contains("return true; }"));
    }

    #[test]
    fn test_formatter_factory() {
        let config = FormatConfig::default();

        let rust_formatter = FormatterFactory::create_formatter("rust", config.clone());
        assert_eq!(rust_formatter.get_config().max_line_length, 100);

        let generic_formatter = FormatterFactory::create_formatter("javascript", config);
        assert_eq!(generic_formatter.get_config().max_line_length, 100);
    }

    #[test]
    fn test_format_config_defaults() {
        let config = FormatConfig::default();

        assert_eq!(config.max_line_length, 100);
        assert_eq!(config.indent_size, 4);
        assert!(!config.use_tabs);
        assert!(matches!(config.brace_style, BraceStyle::SameLine));
        assert!(matches!(config.newline_style, NewlineStyle::Unix));
        assert!(matches!(config.trailing_comma, TrailingCommaStyle::Vertical));
        assert!(config.spaces_around_operators);
        assert!(!config.align_items);
        assert!(config.group_imports);
        assert!(config.sort_imports);
        assert!(config.remove_unused_imports);
    }

    #[test]
    fn test_format_result_structure() {
        let result = FormatResult {
            is_formatted: false,
            formatted_code: Some("formatted code".to_string()),
            issues: vec![FormatIssue {
                line: 1,
                column: 5,
                message: "Test issue".to_string(),
                severity: FormatSeverity::Warning,
                suggestion: "Fix it".to_string(),
            }],
            file_path: "test.rs".to_string(),
        };

        assert!(!result.is_formatted);
        assert!(result.formatted_code.is_some());
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.file_path, "test.rs");
    }
}
