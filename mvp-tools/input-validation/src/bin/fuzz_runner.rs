//! Fuzz testing runner for the input validation framework
//!
//! This binary provides a command-line interface for running fuzz tests
//! against all critical parsers and validators.

use clap::{Arg, ArgMatches, Command};
use input_validation::fuzzing::{
    FuzzConfig, FuzzTestSuite, JwtFuzzTarget, OAuthFuzzTarget, ScimFilterFuzzTarget,
    ValidationFuzzTarget,
};
use input_validation::validation::InputType;
use std::env;
use std::time::Duration;

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::init();

    let matches = Command::new("fuzz-runner")
        .version("0.1.0")
        .about("Fuzz testing runner for input validation framework")
        .arg(
            Arg::new("iterations")
                .short('i')
                .long("iterations")
                .value_name("COUNT")
                .help("Number of iterations per target")
                .default_value("10000"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("SECONDS")
                .help("Total timeout in seconds")
                .default_value("300"),
        )
        .arg(
            Arg::new("target")
                .long("target")
                .value_name("TARGET")
                .help("Specific target to fuzz (scim, oauth, jwt, validation)")
                .required(false),
        )
        .arg(
            Arg::new("structured")
                .long("structured")
                .help("Enable structured fuzzing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for results (JSON format)")
                .required(false),
        )
        .get_matches();

    // Parse arguments
    let iterations: usize =
        matches.get_one::<String>("iterations").unwrap().parse().expect("Invalid iterations count");

    let timeout_secs: u64 =
        matches.get_one::<String>("timeout").unwrap().parse().expect("Invalid timeout");

    let structured_fuzzing = matches.get_flag("structured");

    let target_filter = matches.get_one::<String>("target");

    // Create fuzz configuration
    let config = FuzzConfig {
        max_iterations: iterations,
        total_timeout: Duration::from_secs(timeout_secs),
        structured_fuzzing,
        ..Default::default()
    };

    println!("🚀 Starting fuzz testing with {} iterations per target", iterations);
    println!("⏰ Total timeout: {} seconds", timeout_secs);
    println!("🏗️  Structured fuzzing: {}", if structured_fuzzing { "enabled" } else { "disabled" });

    // Create fuzz test suite
    let mut suite = FuzzTestSuite::new(config);

    // Add targets based on filter
    match target_filter {
        Some(target) => match target.as_str() {
            "scim" => {
                println!("🎯 Fuzzing SCIM filter parser only");
                suite.add_target(ScimFilterFuzzTarget::new()?);
            }
            "oauth" => {
                println!("🎯 Fuzzing OAuth parameter parser only");
                suite.add_target(OAuthFuzzTarget::new()?);
            }
            "jwt" => {
                println!("🎯 Fuzzing JWT token parser only");
                suite.add_target(JwtFuzzTarget::new()?);
            }
            "validation" => {
                println!("🎯 Fuzzing input validation only");
                suite.add_target(ValidationFuzzTarget::new(InputType::Email)?);
                suite.add_target(ValidationFuzzTarget::new(InputType::Text)?);
                suite.add_target(ValidationFuzzTarget::new(InputType::Username)?);
            }
            _ => {
                eprintln!(
                    "❌ Unknown target: {}. Valid targets: scim, oauth, jwt, validation",
                    target
                );
                std::process::exit(1);
            }
        },
        None => {
            println!("🎯 Fuzzing all targets");
            suite.add_standard_targets()?;
        }
    }

    // Run fuzz tests
    let results = suite.run_all();

    // Print results
    println!("\n📊 FUZZ TEST RESULTS");
    println!("=====================================");

    let mut total_iterations = 0;
    let mut total_crashes = 0;
    let mut total_hangs = 0;
    let mut total_security_violations = 0;

    for result in &results {
        println!("\n🎯 Target: {}", result.target);
        println!("   Iterations: {}", result.iterations);
        println!("   Crashes: {}", result.crashes);
        println!("   Hangs: {}", result.hangs);
        println!("   Security violations: {}", result.security_violations);
        println!("   Duration: {:?}", result.duration);

        if !result.error_types.is_empty() {
            println!("   Error types:");
            for (error_type, count) in &result.error_types {
                println!("     {}: {}", error_type, count);
            }
        }

        if !result.crash_samples.is_empty() {
            println!("   Sample crashes:");
            for (i, sample) in result.crash_samples.iter().take(3).enumerate() {
                println!("     {}. {} ({})", i + 1, sample.error_type, sample.input_size);
            }
        }

        total_iterations += result.iterations;
        total_crashes += result.crashes;
        total_hangs += result.hangs;
        total_security_violations += result.security_violations;
    }

    println!("\n📈 SUMMARY");
    println!("=====================================");
    println!("Total iterations: {}", total_iterations);
    println!("Total crashes: {}", total_crashes);
    println!("Total hangs: {}", total_hangs);
    println!("Total security violations: {}", total_security_violations);

    if total_crashes > 0 || total_hangs > 0 {
        println!("⚠️  Issues found! Check the detailed results above.");
    } else if total_security_violations > 0 {
        println!("🔒 Security violations detected (expected for security testing)");
    } else {
        println!("✅ All tests completed without crashes or hangs!");
    }

    // Write results to file if requested
    if let Some(output_file) = matches.get_one::<String>("output") {
        let json_results = serde_json::to_string_pretty(&results)?;
        std::fs::write(output_file, json_results)?;
        println!("📁 Results saved to: {}", output_file);
    }

    // Exit with non-zero code if critical issues found
    if total_crashes > 0 || total_hangs > 0 {
        std::process::exit(1);
    }

    Ok(())
}
