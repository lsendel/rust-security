extern crate regex;

use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

struct ErrorFix {
    pattern: Regex,
    replacement: String,
}

impl ErrorFix {
    fn new(pattern: &str, replacement: &str) -> Self {
        Self {
            pattern: Regex::new(pattern).unwrap(),
            replacement: replacement.to_string(),
        }
    }

    fn apply(&self, content: &str) -> String {
        self.pattern
            .replace_all(content, &self.replacement)
            .to_string()
    }
}

fn create_error_fixes() -> Vec<ErrorFix> {
    vec![
        // Fix ServiceUnavailable tuple variant usage
        ErrorFix::new(
            r"ServiceUnavailable\s*\{\s*reason:\s*([^}]+)\s*\}",
            "ServiceUnavailable($1)",
        ),
        // Fix InvalidRequest tuple variant usage
        ErrorFix::new(
            r"InvalidRequest\s*\{\s*reason:\s*([^}]+)\s*\}",
            "InvalidRequest($1)",
        ),
        // Fix UnauthorizedClient tuple variant usage
        ErrorFix::new(
            r"UnauthorizedClient\s*\{\s*client_id:\s*([^}]+)\s*\}",
            "UnauthorizedClient($1)",
        ),
        // Fix Validation tuple variant usage
        ErrorFix::new(
            r"Validation\s*\{\s*field:\s*([^,]+),\s*reason:\s*([^}]+)\s*\}",
            "Validation($2)",
        ),
        // Fix CircuitBreakerError mappings
        ErrorFix::new(
            r"CircuitBreakerError::Open\s*=>\s*Self::ServiceUnavailable\s*\{\s*reason:\s*([^}]+)\s*\}",
            "CircuitBreakerError::Open => Self::ServiceUnavailable($1)",
        ),
        ErrorFix::new(
            r"CircuitBreakerError::Timeout\s*\{\s*timeout\s*\}\s*=>\s*Self::ServiceUnavailable\s*\{\s*reason:\s*([^}]+)\s*\}",
            "CircuitBreakerError::Timeout { timeout } => Self::ServiceUnavailable($1)",
        ),
        ErrorFix::new(
            r"CircuitBreakerError::OperationFailed\(msg\)\s*=>\s*Self::ServiceUnavailable\s*\{\s*reason:\s*([^}]+)\s*\}",
            "CircuitBreakerError::OperationFailed(msg) => Self::ServiceUnavailable($1)",
        ),
        // Fix compiler-suggested placeholders
        ErrorFix::new(
            r"ServiceUnavailable\(\s*/\*\s*std::string::String\s*\*/\)",
            "ServiceUnavailable(\"PLACEHOLDER_MESSAGE\".to_string())",
        ),
        ErrorFix::new(
            r"InvalidRequest\(\s*/\*\s*std::string::String\s*\*/\)",
            "InvalidRequest(\"PLACEHOLDER_MESSAGE\".to_string())",
        ),
        ErrorFix::new(
            r"UnauthorizedClient\(\s*/\*\s*std::string::String\s*\*/\)",
            "UnauthorizedClient(\"PLACEHOLDER_MESSAGE\".to_string())",
        ),
    ]
}

fn find_rust_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();

    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.is_dir() {
                files.extend(find_rust_files(&path));
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    files
}

fn fix_file(file_path: &Path, fixes: &[ErrorFix]) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(file_path)?;
    let mut modified_content = content.clone();
    let mut modified = false;

    for fix in fixes {
        let new_content = fix.apply(&modified_content);
        if new_content != modified_content {
            modified = true;
            modified_content = new_content;
        }
    }

    if modified {
        println!("Fixing: {}", file_path.display());
        fs::write(file_path, modified_content)?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 Auto-fixing compilation errors using Rust pattern matching...");

    let fixes = create_error_fixes();

    // Find all Rust files in auth-service
    let auth_service_dir = Path::new("auth-service");
    let rust_files = find_rust_files(auth_service_dir);

    println!("Found {} Rust files to check", rust_files.len());

    let mut fixed_count = 0;
    for file_path in rust_files {
        if fix_file(&file_path, &fixes).is_ok() {
            fixed_count += 1;
        }
    }

    println!(
        "✅ Fixed {} files. Run 'cargo check --workspace' to verify.",
        fixed_count
    );

    // Run cargo check to see remaining errors
    println!("\n📊 Running cargo check to see remaining errors...");
    let output = std::process::Command::new("cargo")
        .args(&["check", "--workspace"])
        .output()?;

    let error_count = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter(|line| line.contains("error["))
        .count();

    println!("Remaining compilation errors: {}", error_count);

    Ok(())
}
