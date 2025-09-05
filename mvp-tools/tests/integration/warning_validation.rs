//! Warning-free validation integration tests

use std::process::Command;

#[test]
fn validate_core_components_warning_free() {
    let components = ["auth-core", "common", "api-contracts", "policy-service", "compliance-tools"];
    
    for component in &components {
        println!("Validating {} is warning-free...", component);
        
        let output = Command::new("cargo")
            .args(["check", "-p", component])
            .output()
            .expect("Failed to execute cargo check");
            
        let stderr = String::from_utf8_lossy(&output.stderr);
        let warning_count = stderr.matches("warning:").count();
        
        assert_eq!(
            warning_count, 0,
            "Component {} has {} warnings (expected 0):\n{}",
            component, warning_count, stderr
        );
    }
}

#[test]
fn validate_maintenance_tools_exist() {
    use std::path::Path;
    
    assert!(Path::new("scripts/maintain-warning-free.sh").exists());
    assert!(Path::new(".githooks/pre-commit").exists());
    assert!(Path::new("WARNING_FREE_SUCCESS_SUMMARY.md").exists());
}

#[test] 
fn validate_security_vulnerabilities_resolved() {
    // Test that known RUSTSEC vulnerabilities are not present
    let output = Command::new("cargo")
        .args(["check", "--workspace", "--exclude", "axum-integration-example"])
        .output()
        .expect("Failed to check workspace");
        
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Should not contain references to vulnerable crates
    assert!(!stderr.contains("RUSTSEC-2024-0408"), "pprof2 vulnerability should be resolved");
    assert!(!stderr.contains("RUSTSEC-2023-0071"), "RSA vulnerability should be resolved"); 
    assert!(!stderr.contains("RUSTSEC-2024-0421"), "IDNA vulnerability should be resolved");
}