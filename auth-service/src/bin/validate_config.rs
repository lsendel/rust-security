//! # Security Configuration Validator CLI
//!
//! Command-line tool to validate security configurations before deployment.
//!
//! ## Usage
//!
//! ```bash
//! # Validate with production settings
//! cargo run --bin validate_config -- --production
//!
//! # Validate with development settings  
//! cargo run --bin validate_config -- --development
//!
//! # Generate report file
//! cargo run --bin validate_config -- --production --output report.md
//!
//! # Strict validation (fail on warnings)
//! cargo run --bin validate_config -- --strict
//! ```

use auth_service::security::{SecurityConfigValidator, ValidationSeverity};
use clap::{Arg, Command};
use std::fs;
use std::process;
use tracing::{info, error, Level};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let matches = Command::new("Security Configuration Validator")
        .version("1.0.0")
        .about("Validates security configurations for the authentication service")
        .arg(
            Arg::new("production")
                .long("production")
                .help("Use production validation rules")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("development"),
        )
        .arg(
            Arg::new("development")
                .long("development")
                .help("Use development validation rules")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("production"),
        )
        .arg(
            Arg::new("strict")
                .long("strict")
                .help("Enable strict validation (fail on high priority issues)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .long("output")
                .short('o')
                .value_name("FILE")
                .help("Write report to file")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format: text, json, markdown")
                .value_parser(["text", "json", "markdown"])
                .default_value("text"),
        )
        .get_matches();

    let production_mode = matches.get_flag("production");
    let development_mode = matches.get_flag("development");
    let strict_mode = matches.get_flag("strict");
    let output_file = matches.get_one::<String>("output");
    let format = matches.get_one::<String>("format").unwrap();

    // Create validator based on command line options
    let validator = if production_mode {
        info!("Running validation with production settings");
        SecurityConfigValidator::production()
    } else if development_mode {
        info!("Running validation with development settings");
        SecurityConfigValidator::development()
    } else {
        info!("Running validation with environment-detected settings");
        SecurityConfigValidator::new()
    };

    // Run validation
    info!("Starting security configuration validation...");
    let result = validator.validate_all_configurations().await;

    // Generate output based on format
    let output = match format.as_str() {
        "json" => serde_json::to_string_pretty(&result).unwrap_or_else(|_| "JSON serialization failed".to_string()),
        "markdown" => validator.generate_report(&result),
        _ => generate_text_report(&result),
    };

    // Write to file or stdout
    if let Some(file_path) = output_file {
        match fs::write(file_path, &output) {
            Ok(_) => info!("Report written to {}", file_path),
            Err(e) => {
                error!("Failed to write report to {}: {}", file_path, e);
                process::exit(1);
            }
        }
    } else {
        println!("{}", output);
    }

    // Determine exit code based on validation results and strictness
    let exit_code = if result.has_critical_issues() {
        error!("Validation FAILED: {} critical security issues found", result.critical_count);
        1
    } else if strict_mode && result.has_blocking_issues() {
        error!("Validation FAILED (strict mode): {} high priority issues found", result.high_count);
        1
    } else if result.high_count > 0 || result.medium_count > 0 {
        info!("Validation completed with {} high and {} medium priority issues", result.high_count, result.medium_count);
        0
    } else {
        info!("Validation PASSED: No security issues found");
        0
    };

    process::exit(exit_code);
}

fn generate_text_report(result: &auth_service::security::ValidationResult) -> String {
    let mut output = String::new();
    
    output.push_str("=== Security Configuration Validation Report ===\n\n");
    
    // Summary
    output.push_str(&format!("CRITICAL: {}\n", result.critical_count));
    output.push_str(&format!("HIGH:     {}\n", result.high_count));
    output.push_str(&format!("MEDIUM:   {}\n", result.medium_count));
    output.push_str(&format!("LOW:      {}\n", result.low_count));
    output.push_str(&format!("STATUS:   {}\n\n", if result.passed { "PASSED" } else { "FAILED" }));

    if result.issues.is_empty() {
        output.push_str("✅ No security configuration issues found!\n");
        return output;
    }

    // Group issues by severity
    let mut critical_issues = Vec::new();
    let mut high_issues = Vec::new();
    let mut medium_issues = Vec::new();
    let mut low_issues = Vec::new();

    for issue in &result.issues {
        match issue.severity {
            ValidationSeverity::Critical => critical_issues.push(issue),
            ValidationSeverity::High => high_issues.push(issue),
            ValidationSeverity::Medium => medium_issues.push(issue),
            ValidationSeverity::Low => low_issues.push(issue),
            ValidationSeverity::Info => {}
        }
    }

    // Display critical issues first
    if !critical_issues.is_empty() {
        output.push_str("🔴 CRITICAL ISSUES (Must Fix Before Production):\n");
        output.push_str("=" .repeat(60));
        output.push('\n');
        for issue in critical_issues {
            output.push_str(&format_issue_text(issue));
        }
        output.push('\n');
    }

    // Display high priority issues
    if !high_issues.is_empty() {
        output.push_str("🟡 HIGH PRIORITY ISSUES:\n");
        output.push_str("-".repeat(30));
        output.push('\n');
        for issue in high_issues {
            output.push_str(&format_issue_text(issue));
        }
        output.push('\n');
    }

    // Display medium priority issues
    if !medium_issues.is_empty() {
        output.push_str("🔵 MEDIUM PRIORITY ISSUES:\n");
        output.push_str("-".repeat(30));
        output.push('\n');
        for issue in medium_issues {
            output.push_str(&format_issue_text(issue));
        }
        output.push('\n');
    }

    // Display low priority issues
    if !low_issues.is_empty() {
        output.push_str("⚪ LOW PRIORITY ISSUES:\n");
        output.push_str("-".repeat(30));
        output.push('\n');
        for issue in low_issues {
            output.push_str(&format_issue_text(issue));
        }
    }

    output
}

fn format_issue_text(issue: &auth_service::security::ValidationIssue) -> String {
    let mut text = String::new();
    
    text.push_str(&format!("[{}] {}\n", issue.category, issue.parameter));
    text.push_str(&format!("  Issue: {}\n", issue.message));
    text.push_str(&format!("  Fix:   {}\n", issue.recommendation));
    
    if let Some(ref current) = issue.current_value {
        text.push_str(&format!("  Current: {}\n", current));
    }
    
    if let Some(ref recommended) = issue.recommended_value {
        text.push_str(&format!("  Recommended: {}\n", recommended));
    }
    
    text.push('\n');
    text
}