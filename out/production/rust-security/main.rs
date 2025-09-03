//! Red Team Exercise Suite for Rust Authentication Service
//!
//! This comprehensive suite validates all implemented security measures through
//! realistic attack scenarios that mirror actual threat actor techniques.

use clap::{Arg, ArgMatches, Command};
use colored::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

mod attack_framework;
mod reporting;
mod scenarios;
mod tools;
mod validation;

use attack_framework::RedTeamFramework;
use reporting::RedTeamReporter;
use scenarios::*;
use validation::SecurityControlValidator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize enhanced tracing
    tracing_subscriber::fmt()
        .with_env_filter("info,red_team_exercises=debug")
        .with_target(true)
        .with_thread_ids(true)
        .init();

    let matches = Command::new("Red Team Exercise Suite")
        .version("1.0")
        .author("Security Team")
        .about("Comprehensive red team exercises for Rust authentication service")
        .arg(
            Arg::new("target")
                .short('t')
                .long("target")
                .value_name("URL")
                .help("Target authentication service URL")
                .default_value("http://localhost:8080"),
        )
        .arg(
            Arg::new("scenario")
                .short('s')
                .long("scenario")
                .value_name("SCENARIO")
                .help("Specific scenario to run (all, auth, mfa, idor, etc.)")
                .default_value("all"),
        )
        .arg(
            Arg::new("intensity")
                .short('i')
                .long("intensity")
                .value_name("LEVEL")
                .help("Attack intensity level (low, medium, high)")
                .default_value("medium"),
        )
        .arg(
            Arg::new("duration")
                .short('d')
                .long("duration")
                .value_name("SECONDS")
                .help("Exercise duration in seconds")
                .default_value("300"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output report file path")
                .default_value("red_team_report.json"),
        )
        .arg(
            Arg::new("validate-only")
                .long("validate-only")
                .help("Only validate security controls without attacks")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    println!("{}", "🔴 RED TEAM EXERCISE SUITE INITIATED".red().bold());
    println!("{}", "==========================================".red());

    let target_url = matches.get_one::<String>("target").unwrap();
    let scenario = matches.get_one::<String>("scenario").unwrap();
    let intensity = matches.get_one::<String>("intensity").unwrap();
    let duration: u64 = matches.get_one::<String>("duration").unwrap().parse()?;
    let output_path = matches.get_one::<String>("output").unwrap();
    let validate_only = matches.get_flag("validate-only");

    info!("Target: {}", target_url);
    info!("Scenario: {}", scenario);
    info!("Intensity: {}", intensity);
    info!("Duration: {} seconds", duration);

    // Initialize red team framework
    let mut framework = RedTeamFramework::new(target_url.clone()).await?;
    let mut reporter = RedTeamReporter::new();

    if validate_only {
        println!("{}", "🔍 VALIDATING SECURITY CONTROLS ONLY".yellow().bold());
        let validator = SecurityControlValidator::new(target_url.clone()).await?;
        let validation_results = validator.validate_all_controls().await?;
        reporter.add_validation_results(validation_results);
    } else {
        // Run comprehensive red team exercises
        let start_time = Instant::now();

        match scenario.as_str() {
            "all" => {
                run_all_scenarios(&mut framework, &mut reporter, intensity, duration).await?;
            }
            "auth" => {
                run_authentication_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "mfa" => {
                run_mfa_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "idor" => {
                run_idor_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "oauth" => {
                run_oauth_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "session" => {
                run_session_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "rate_limit" => {
                run_rate_limit_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "token" => {
                run_token_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            "social" => {
                run_social_engineering_scenarios(&mut framework, &mut reporter, intensity).await?;
            }
            _ => {
                error!("Unknown scenario: {}", scenario);
                return Err(anyhow::anyhow!("Invalid scenario specified"));
            }
        }

        let exercise_duration = start_time.elapsed();
        reporter.set_exercise_duration(exercise_duration);
    }

    // Generate and save comprehensive report
    let report = reporter.generate_report();
    report.save_to_file(output_path).await?;
    report.print_summary();

    println!("{}", "🎯 RED TEAM EXERCISE COMPLETED".green().bold());
    println!("📊 Report saved to: {}", output_path);

    Ok(())
}

async fn run_all_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
    duration: u64,
) -> anyhow::Result<()> {
    println!("{}", "🚀 RUNNING ALL ATTACK SCENARIOS".blue().bold());

    let scenarios = vec![
        ("Authentication Bypass", run_authentication_scenarios),
        ("MFA Bypass", run_mfa_scenarios),
        ("IDOR Attacks", run_idor_scenarios),
        ("OAuth2/OIDC Manipulation", run_oauth_scenarios),
        ("Session Management", run_session_scenarios),
        ("Rate Limiting Bypass", run_rate_limit_scenarios),
        ("Token Manipulation", run_token_scenarios),
        ("Social Engineering", run_social_engineering_scenarios),
    ];

    let scenario_duration = duration / scenarios.len() as u64;

    for (name, scenario_fn) in scenarios {
        println!("\n{} {}", "▶".blue(), name.cyan().bold());

        let start = Instant::now();
        if let Err(e) = scenario_fn(framework, reporter, intensity).await {
            error!("Scenario '{}' failed: {}", name, e);
            reporter.add_scenario_error(name, e.to_string());
        }

        let elapsed = start.elapsed();
        info!("Scenario '{}' completed in {:?}", name, elapsed);

        // Respect scenario duration limits
        if elapsed < Duration::from_secs(scenario_duration) {
            tokio::time::sleep(Duration::from_secs(scenario_duration) - elapsed).await;
        }
    }

    Ok(())
}
