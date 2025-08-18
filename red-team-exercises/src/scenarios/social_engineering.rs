//! Social Engineering Attack Simulation Scenarios

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use tracing::{info, warn};

pub async fn run_social_engineering_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🔐 Starting Social Engineering Simulation Scenarios");

    phishing_simulation(framework, reporter).await?;
    pretexting_attacks(framework, reporter).await?;
    information_disclosure_tests(framework, reporter).await?;
    user_enumeration_attacks(framework, reporter, intensity).await?;

    Ok(())
}

async fn phishing_simulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Simulating phishing attacks");

    let session = framework.create_attack_session().await?;
    let mut phishing_results = Vec::new();

    // Test information disclosure in error messages
    let phishing_attempts = vec![
        (
            "credential_harvesting",
            "/oauth/token",
            "grant_type=client_credentials&client_id=user@company.com&client_secret=password123",
        ),
        ("fake_reset", "/oauth/token", "grant_type=password&username=admin&password=reset123"),
        (
            "social_login",
            "/oauth/authorize",
            "response_type=code&client_id=facebook&redirect_uri=http://evil.com",
        ),
    ];

    for (attack_type, endpoint, payload) in phishing_attempts {
        let result = framework
            .execute_attack(
                "phishing_simulation",
                "POST",
                endpoint,
                None,
                Some(payload.to_string()),
                Some(&session),
            )
            .await?;

        // Check for information disclosure in error responses
        let response_lower = result.response_body.to_lowercase();
        if response_lower.contains("user")
            || response_lower.contains("email")
            || response_lower.contains("username")
            || response_lower.contains("exists")
            || response_lower.contains("invalid") && response_lower.contains("credentials")
        {
            phishing_results.push(format!(
                "Information disclosure in {} attack: potential user enumeration",
                attack_type
            ));
        }

        // Check for verbose error messages that could aid attackers
        if result.response_body.len() > 200
            && (response_lower.contains("database")
                || response_lower.contains("sql")
                || response_lower.contains("internal")
                || response_lower.contains("stack"))
        {
            phishing_results.push(format!("Verbose error message in {} attack", attack_type));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("phishing_results".to_string(), json!(phishing_results));
    scenario_data.insert("attempts_tested".to_string(), json!(phishing_attempts.len()));

    reporter.add_scenario_result("phishing_simulation", phishing_results.is_empty(), scenario_data);
    Ok(())
}

async fn pretexting_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing pretexting attack vectors");

    let session = framework.create_attack_session().await?;
    let mut pretexting_results = Vec::new();

    // Test various pretexting scenarios through HTTP headers and parameters
    let pretexting_scenarios = vec![
        ("internal_request", vec![("X-Internal-Request", "true"), ("X-From-Support", "helpdesk")]),
        ("emergency_access", vec![("X-Emergency", "true"), ("X-Override", "admin")]),
        ("testing_mode", vec![("X-Test-Mode", "enabled"), ("X-Debug", "true")]),
        ("maintenance_window", vec![("X-Maintenance", "active"), ("X-Service-Mode", "bypass")]),
        ("developer_access", vec![("X-Developer", "true"), ("X-Internal-Tool", "enabled")]),
    ];

    for (scenario_name, headers) in pretexting_scenarios {
        let mut request_headers = reqwest::header::HeaderMap::new();

        for (header_name, header_value) in headers {
            request_headers
                .insert(header_name, reqwest::header::HeaderValue::from_str(header_value)?);
        }

        // Test on admin endpoints
        let result = framework
            .execute_attack(
                "pretexting_attack",
                "GET",
                "/admin/keys/rotation/status",
                Some(request_headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            pretexting_results.push(format!("Pretexting successful: {} scenario", scenario_name));
            warn!("🚨 Pretexting vulnerability: {}", scenario_name);
        }

        // Also test on token endpoints
        let token_headers = request_headers.clone();
        let token_result = framework
            .execute_attack(
                "pretexting_token_attack",
                "POST",
                "/oauth/token",
                Some(token_headers),
                Some(
                    "grant_type=client_credentials&client_id=internal&client_secret=bypass"
                        .to_string(),
                ),
                Some(&session),
            )
            .await?;

        if token_result.success {
            pretexting_results
                .push(format!("Token endpoint pretexting successful: {}", scenario_name));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("pretexting_results".to_string(), json!(pretexting_results));
    scenario_data.insert("scenarios_tested".to_string(), json!(pretexting_scenarios.len()));

    reporter.add_scenario_result(
        "pretexting_attacks",
        pretexting_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn information_disclosure_tests(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing information disclosure vulnerabilities");

    let session = framework.create_attack_session().await?;
    let mut disclosure_results = Vec::new();

    // Test endpoints for information disclosure
    let test_endpoints = vec![
        ("/.well-known/oauth-authorization-server", "OAuth metadata"),
        ("/.well-known/openid-configuration", "OIDC metadata"),
        ("/jwks.json", "JSON Web Key Set"),
        ("/health", "Health endpoint"),
        ("/metrics", "Metrics endpoint"),
        ("/.env", "Environment file"),
        ("/config", "Configuration endpoint"),
        ("/debug", "Debug information"),
        ("/status", "Status information"),
        ("/version", "Version information"),
    ];

    for (endpoint, description) in test_endpoints {
        let result = framework
            .execute_attack("information_disclosure", "GET", endpoint, None, None, Some(&session))
            .await?;

        if result.success && result.response_body.len() > 50 {
            // Analyze response for sensitive information
            let response_lower = result.response_body.to_lowercase();
            let mut sensitive_info = Vec::new();

            if response_lower.contains("password") || response_lower.contains("secret") {
                sensitive_info.push("credentials");
            }
            if response_lower.contains("key")
                && (response_lower.contains("private") || response_lower.contains("secret"))
            {
                sensitive_info.push("cryptographic_keys");
            }
            if response_lower.contains("database") || response_lower.contains("connection") {
                sensitive_info.push("database_info");
            }
            if response_lower.contains("internal") || response_lower.contains("localhost") {
                sensitive_info.push("internal_info");
            }
            if response_lower.contains("user")
                && (response_lower.contains("admin") || response_lower.contains("email"))
            {
                sensitive_info.push("user_data");
            }
            if response_lower.contains("token") && response_lower.contains("endpoint") {
                sensitive_info.push("endpoint_info");
            }

            if !sensitive_info.is_empty() {
                disclosure_results.push(format!(
                    "{} ({}): {}",
                    description,
                    endpoint,
                    sensitive_info.join(", ")
                ));
                warn!("🚨 Information disclosure at {}: {}", endpoint, sensitive_info.join(", "));
            } else if result.response_body.len() > 500 {
                // Large response might contain useful information for attackers
                disclosure_results.push(format!(
                    "{} ({}): verbose response ({} chars)",
                    description,
                    endpoint,
                    result.response_body.len()
                ));
            }
        }
    }

    // Test for stack traces and error information
    let error_inducing_requests = vec![
        ("/oauth/token", "malformed_json_body", "application/json"),
        ("/oauth/introspect", "invalid_content_type", "text/plain"),
        ("/admin/nonexistent", "", "application/json"),
        ("/oauth/authorize", "response_type=invalid&client_id='; DROP TABLE", ""),
    ];

    for (endpoint, body, content_type) in error_inducing_requests {
        let mut headers = reqwest::header::HeaderMap::new();
        if !content_type.is_empty() {
            headers.insert("Content-Type", reqwest::header::HeaderValue::from_str(content_type)?);
        }

        let result = framework
            .execute_attack(
                "error_information_disclosure",
                "POST",
                endpoint,
                Some(headers),
                Some(body.to_string()),
                Some(&session),
            )
            .await?;

        // Check for stack traces or detailed error information
        if result.response_body.contains("Backtrace")
            || result.response_body.contains("stack trace")
            || result.response_body.contains("panicked at")
            || result.response_body.contains("src/")
            || result.response_body.contains(".rs:")
        {
            disclosure_results.push(format!("Stack trace disclosure at {}", endpoint));
        }

        // Check for database errors
        if result.response_body.to_lowercase().contains("sql")
            || result.response_body.to_lowercase().contains("database")
            || result.response_body.to_lowercase().contains("connection")
        {
            disclosure_results.push(format!("Database error disclosure at {}", endpoint));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("disclosure_results".to_string(), json!(disclosure_results));
    scenario_data.insert("endpoints_tested".to_string(), json!(test_endpoints.len()));

    reporter.add_scenario_result(
        "information_disclosure_tests",
        disclosure_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn user_enumeration_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🎯 Testing user enumeration vulnerabilities");

    let session = framework.create_attack_session().await?;
    let mut enumeration_results = Vec::new();

    let user_count = match intensity {
        "high" => 100,
        "medium" => 50,
        _ => 20,
    };

    // Common usernames to test
    let mut test_usernames = vec![
        "admin",
        "administrator",
        "root",
        "user",
        "test",
        "demo",
        "guest",
        "service",
        "system",
        "api",
        "oauth",
        "auth",
        "support",
        "help",
        "info",
        "contact",
        "sales",
        "marketing",
        "hr",
        "it",
    ];

    // Add numbered variations for higher intensity
    if user_count > 20 {
        for i in 1..=(user_count - 20) {
            test_usernames.push(&format!("user{}", i));
            test_usernames.push(&format!("admin{}", i));
            test_usernames.push(&format!("test{}", i));
        }
    }

    // Test user enumeration through different endpoints
    let enumeration_endpoints = vec![
        ("/oauth/token", "client_credentials"),
        ("/mfa/totp/verify", "totp_verification"),
        ("/session/create", "session_creation"),
    ];

    for (endpoint, test_type) in enumeration_endpoints {
        let mut timing_differences = Vec::new();

        for username in &test_usernames[..user_count.min(test_usernames.len())] {
            let start_time = std::time::Instant::now();

            let (body, description) = match test_type {
                "client_credentials" => (
                    format!(
                        "grant_type=client_credentials&client_id={}&client_secret=test",
                        username
                    ),
                    "OAuth client credentials",
                ),
                "totp_verification" => (
                    json!({"user_id": username, "code": "123456"}).to_string(),
                    "TOTP verification",
                ),
                "session_creation" => (
                    json!({"user_id": username, "client_id": "test"}).to_string(),
                    "Session creation",
                ),
                _ => continue,
            };

            let result = framework
                .execute_attack(
                    "user_enumeration",
                    "POST",
                    endpoint,
                    None,
                    Some(body),
                    Some(&session),
                )
                .await?;

            let response_time = start_time.elapsed();
            timing_differences.push((
                username,
                response_time,
                result.http_status,
                result.response_body.len(),
            ));

            // Check for different error messages that might indicate user existence
            let response_lower = result.response_body.to_lowercase();
            if response_lower.contains("user not found")
                || response_lower.contains("invalid user")
                || response_lower.contains("user does not exist")
                || (response_lower.contains("invalid")
                    && response_lower.contains("credentials")
                    && !response_lower.contains("client"))
            {
                enumeration_results.push(format!(
                    "User enumeration via error message in {} for user: {}",
                    description, username
                ));
            }

            // Small delay to be respectful
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Analyze timing differences
        if timing_differences.len() >= 5 {
            let avg_time: u128 =
                timing_differences.iter().map(|(_, time, _, _)| time.as_millis()).sum::<u128>()
                    / timing_differences.len() as u128;
            let significant_differences: Vec<_> = timing_differences
                .iter()
                .filter(|(_, time, _, _)| {
                    let diff = time.as_millis() as i128 - avg_time as i128;
                    diff.abs() > 100 // More than 100ms difference
                })
                .collect();

            if !significant_differences.is_empty() {
                enumeration_results.push(format!("Timing-based user enumeration possible in {} - {} users with significant timing differences", test_type, significant_differences.len()));
            }
        }

        // Analyze response size differences
        let response_sizes: Vec<_> =
            timing_differences.iter().map(|(_, _, _, size)| *size).collect();
        let unique_sizes: std::collections::HashSet<_> = response_sizes.iter().collect();
        if unique_sizes.len() > 1 {
            enumeration_results.push(format!(
                "Response size variation in {} may allow user enumeration",
                test_type
            ));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("enumeration_results".to_string(), json!(enumeration_results));
    scenario_data.insert("usernames_tested".to_string(), json!(user_count));
    scenario_data.insert("endpoints_tested".to_string(), json!(enumeration_endpoints.len()));

    reporter.add_scenario_result(
        "user_enumeration_attacks",
        enumeration_results.is_empty(),
        scenario_data,
    );
    Ok(())
}
