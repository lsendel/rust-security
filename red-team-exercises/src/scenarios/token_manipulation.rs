//! Token Manipulation Attack Scenarios
//!
//! This module implements comprehensive token manipulation attack scenarios designed to test
//! the security posture of authentication systems. The scenarios cover:
//!
//! ## Attack Categories
//!
//! ### JWT Manipulation Attacks
//! - Algorithm confusion attacks (none, weak secret)
//! - Payload modification attacks  
//! - Key confusion attacks (RS256 -> HS256)
//! - Signature bypass attempts
//!
//! ### JWT Timing Attacks
//! - Signature validation timing analysis
//! - Detection of cryptographic timing leaks
//! - Statistical analysis of response times
//!
//! ### Token Substitution Attacks  
//! - Common token pattern testing
//! - Authorization header type confusion
//! - Hardcoded token enumeration
//!
//! ### Token Replay Attacks
//! - Immediate token replay
//! - Cross-session replay attempts
//! - Expired token acceptance testing
//!
//! ### Token Enumeration Attacks
//! - Sequential token pattern discovery
//! - UUID-based token guessing
//! - Rate-limited enumeration with evasion
//!
//! ### Token Binding Bypass
//! - IP address binding bypass
//! - User-Agent binding bypass  
//! - Session fingerprint evasion
//!
//! ### Token Validation Bypass
//! - SQL injection in token validation
//! - NoSQL injection attacks
//! - Path traversal attempts
//!
//! ## Usage
//!
//! The scenarios are designed to run against a live authentication service and will
//! attempt various attack patterns while monitoring for detection and blocking.
//! Results are reported with detailed metrics for security assessment.
//!
//! ## Security Notice
//!
//! These scenarios are for defensive security testing only. They should only be run
//! against systems you own or have explicit permission to test.

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub async fn run_token_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🔐 Starting Token Manipulation Scenarios");

    jwt_manipulation_attacks(framework, reporter).await?;
    jwt_timing_attacks(framework, reporter).await?;
    token_substitution_attacks(framework, reporter).await?;
    token_replay_attacks(framework, reporter).await?;
    token_enumeration_attacks(framework, reporter, intensity).await?;
    token_binding_attacks(framework, reporter).await?;
    token_validation_bypass(framework, reporter).await?;

    Ok(())
}

async fn jwt_manipulation_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing JWT manipulation attacks");

    let session = framework.create_attack_session().await?;
    let mut manipulation_results = Vec::new();

    // Test various JWT manipulations
    let jwt_attacks = vec![
        ("none_algorithm", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYzMDAwMDAwMCwiZXhwIjoxNjMwMDAwMDAwfQ."),
        ("weak_secret", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTYzMDAwMDAwMCwiZXhwIjoxOTMwMDAwMDAwfQ.invalid_signature"),
        ("modified_payload", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYzMDAwMDAwMCwiZXhwIjoxOTMwMDAwMDAwfQ.fake_signature"),
        ("key_confusion", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjMwMDAwMDAwLCJleHAiOjE5MzAwMDAwMDB9.fake_hmac_signature"),
    ];

    for (attack_type, malicious_jwt) in &jwt_attacks {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", malicious_jwt))?,
        );

        let result = framework
            .execute_attack(
                "jwt_manipulation",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            manipulation_results.push(format!("JWT {} attack successful", attack_type));
            warn!("🚨 JWT vulnerability detected: {}", attack_type);
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));
    scenario_data.insert("attacks_tested".to_string(), json!(jwt_attacks.len()));

    reporter.add_scenario_result(
        "jwt_manipulation_attacks",
        manipulation_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn token_substitution_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing token substitution attacks");

    let session = framework.create_attack_session().await?;
    let mut substitution_results = Vec::new();

    // Test token substitution with various token formats
    let substitute_tokens = vec![
        "admin_token",
        "root_access_token",
        "system_token_12345",
        "debug_token",
        "test_admin_token",
        "bearer_admin",
        "tk_admin_override",
        "session_admin_12345",
    ];

    for token in substitute_tokens {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?,
        );

        let result = framework
            .execute_attack(
                "token_substitution",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            substitution_results.push(format!("Token substitution successful with: {}", token));
            warn!("🚨 Token substitution vulnerability: {}", token);
        }
    }

    // Test with different token types in Authorization header
    let auth_types = vec!["Bearer", "Basic", "Token", "API-Key", "Custom"];
    for auth_type in auth_types {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("{} admin_token", auth_type))?,
        );

        let result = framework
            .execute_attack(
                "auth_type_substitution",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            substitution_results
                .push(format!("Authorization type substitution successful: {}", auth_type));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("substitution_results".to_string(), json!(substitution_results));

    reporter.add_scenario_result(
        "token_substitution_attacks",
        substitution_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn token_replay_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing token replay attacks");

    let session = framework.create_attack_session().await?;
    let mut replay_results = Vec::new();

    // First, try to obtain a legitimate token
    if let Ok((valid_token, _)) = framework.attempt_client_credentials_flow("test", "test").await {
        // Test immediate replay
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", valid_token))?,
        );

        // First use
        let first_result = framework
            .execute_attack(
                "token_first_use",
                "POST",
                "/oauth/introspect",
                Some(headers.clone()),
                Some(json!({"token": "test_token"}).to_string()),
                Some(&session),
            )
            .await?;

        // Immediate replay
        let replay_result = framework
            .execute_attack(
                "token_immediate_replay",
                "POST",
                "/oauth/introspect",
                Some(headers.clone()),
                Some(json!({"token": "test_token"}).to_string()),
                Some(&session),
            )
            .await?;

        if replay_result.success {
            replay_results.push("Token immediate replay successful".to_string());
        }

        // Cross-session replay
        let new_session = framework.create_attack_session().await?;
        let cross_session_result = framework
            .execute_attack(
                "token_cross_session_replay",
                "POST",
                "/oauth/introspect",
                Some(headers),
                Some(json!({"token": "test_token"}).to_string()),
                Some(&new_session),
            )
            .await?;

        if cross_session_result.success {
            replay_results.push("Token cross-session replay successful".to_string());
        }
    }

    // Test with expired tokens (simulated)
    let expired_tokens = vec![
        "tk_expired_12345",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxfQ.signature", // exp: 1 (1970)
    ];

    for expired_token in expired_tokens {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", expired_token))?,
        );

        let result = framework
            .execute_attack(
                "expired_token_replay",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            replay_results.push(format!("Expired token accepted: {}", expired_token));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("replay_results".to_string(), json!(replay_results));

    reporter.add_scenario_result("token_replay_attacks", replay_results.is_empty(), scenario_data);
    Ok(())
}

async fn token_enumeration_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🎯 Testing token enumeration attacks");

    let session = framework.create_attack_session().await?;
    let mut enumeration_results = Vec::new();

    let range = match intensity {
        "high" => 1000,
        "medium" => 100,
        _ => 20,
    };

    // Test sequential token patterns
    let token_patterns = vec!["tk_{}", "token_{}", "access_{}", "session_{}", "auth_{}"];

    for pattern in &token_patterns {
        let mut valid_tokens = Vec::new();

        for i in 0..(range / token_patterns.len() as u32) {
            let token = pattern.replace("{}", &format!("{:06}", i));

            let introspect_body = json!({
                "token": token
            });

            // Use basic auth for introspection
            let mut headers = reqwest::header::HeaderMap::new();
            let auth = general_purpose::STANDARD.encode("test:test");
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&format!("Basic {}", auth))?,
            );

            let result = framework
                .execute_attack(
                    "token_enumeration",
                    "POST",
                    "/oauth/introspect",
                    Some(headers),
                    Some(introspect_body.to_string()),
                    Some(&session),
                )
                .await?;

            if result.success {
                if let Ok(response_json) =
                    serde_json::from_str::<serde_json::Value>(&result.response_body)
                {
                    if let Some(active) = response_json["active"].as_bool() {
                        if active {
                            valid_tokens.push(token.clone());
                            warn!("🚨 Valid token found via enumeration: {}", token);
                        }
                    }
                }
            }

            // Brief delay to avoid overwhelming
            if i % 10 == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        if !valid_tokens.is_empty() {
            enumeration_results.push(format!(
                "Token enumeration successful with pattern '{}': {} valid tokens",
                pattern,
                valid_tokens.len()
            ));
        }
    }

    // Test UUID-like patterns
    let uuid_patterns = vec![
        "00000000-0000-0000-0000-{:012}",
        "11111111-1111-1111-1111-{:012}",
        "aaaaaaaa-aaaa-aaaa-aaaa-{:012}",
    ];

    for pattern in &uuid_patterns {
        for i in 0..10 {
            let token = pattern.replace("{:012}", &format!("{:012}", i));

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token))?,
            );

            let result = framework
                .execute_attack(
                    "uuid_token_enumeration",
                    "GET",
                    "/admin/keys/rotation/status",
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;

            if result.success {
                enumeration_results
                    .push(format!("UUID-pattern token enumeration successful: {}", token));
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("enumeration_results".to_string(), json!(enumeration_results));
    scenario_data
        .insert("patterns_tested".to_string(), json!(token_patterns.len() + uuid_patterns.len()));

    reporter.add_scenario_result(
        "token_enumeration_attacks",
        enumeration_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn jwt_timing_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing JWT timing attacks for signature validation");

    let session = framework.create_attack_session().await?;
    let mut timing_results: Vec<String> = Vec::new();

    // Test signature validation timing
    let jwt_header = general_purpose::STANDARD_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let jwt_payload = general_purpose::STANDARD_NO_PAD
        .encode(r#"{"sub":"admin","role":"admin","exp":9999999999}"#);

    let timing_samples = vec![
        ("valid_length_sig", "a".repeat(43)), // Valid base64 length
        ("short_sig", "abc".to_string()),     // Short signature
        ("long_sig", "a".repeat(100)),        // Long signature
        ("invalid_chars", "invalid_sig!@#".to_string()), // Invalid base64 chars
        ("empty_sig", "".to_string()),        // Empty signature
    ];

    for (test_name, signature) in timing_samples {
        let mut response_times = Vec::new();

        // Take multiple timing measurements
        for _ in 0..10 {
            let malicious_jwt = format!("{}.{}.{}", jwt_header, jwt_payload, signature);

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", malicious_jwt))?,
            );

            let start = Instant::now();
            let result = framework
                .execute_attack(
                    "jwt_timing_attack",
                    "GET",
                    "/admin/keys/rotation/status",
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;
            let elapsed = start.elapsed();

            response_times.push(elapsed.as_nanos() as f64);

            // Small delay between requests
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let avg_time = response_times.iter().sum::<f64>() / response_times.len() as f64;
        debug!("Average response time for {}: {:.2}ns", test_name, avg_time);

        // Look for significant timing differences (>10% variance from baseline)
        if test_name != "valid_length_sig" {
            if let Some(baseline) = timing_results.first() {
                let baseline_time = baseline.parse::<f64>().unwrap_or(avg_time);
                let variance = ((avg_time - baseline_time) / baseline_time).abs();
                if variance > 0.1 {
                    timing_results.push(format!(
                        "Timing leak detected in {}: {:.1}% variance",
                        test_name,
                        variance * 100.0
                    ));
                    warn!("🚨 JWT timing vulnerability detected: {}", test_name);
                }
            }
        } else {
            timing_results.insert(0, avg_time.to_string()); // Store baseline
        }
    }

    // Remove baseline from results for reporting
    if !timing_results.is_empty() && timing_results[0].parse::<f64>().is_ok() {
        timing_results.remove(0);
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("timing_results".to_string(), json!(timing_results));

    reporter.add_scenario_result("jwt_timing_attacks", timing_results.is_empty(), scenario_data);
    Ok(())
}

async fn token_binding_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing token binding bypass attacks");

    let session = framework.create_attack_session().await?;
    let mut binding_results = Vec::new();

    // First, try to get a valid token
    if let Ok((valid_token, _)) = framework.attempt_client_credentials_flow("test", "test").await {
        // Test using token from different IP
        let spoofed_ips = vec![
            "192.168.1.100",
            "10.0.0.50",
            "172.16.0.25",
            "127.0.0.1",
            "203.0.113.10", // RFC 5737 test IP
        ];

        for spoofed_ip in spoofed_ips {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", valid_token))?,
            );
            headers.insert("X-Forwarded-For", reqwest::header::HeaderValue::from_str(spoofed_ip)?);
            headers.insert("X-Real-IP", reqwest::header::HeaderValue::from_str(spoofed_ip)?);

            let result = framework
                .execute_attack(
                    "token_ip_binding_bypass",
                    "GET",
                    "/admin/keys/rotation/status",
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;

            if result.success {
                binding_results.push(format!("Token accepted from different IP: {}", spoofed_ip));
                warn!("🚨 Token binding bypass from IP: {}", spoofed_ip);
            }
        }

        // Test using token with different User-Agent
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "curl/7.68.0",
            "PostmanRuntime/7.28.0",
            "python-requests/2.25.1",
        ];

        for user_agent in user_agents {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", valid_token))?,
            );
            headers.insert("User-Agent", reqwest::header::HeaderValue::from_str(user_agent)?);

            let result = framework
                .execute_attack(
                    "token_useragent_binding_bypass",
                    "GET",
                    "/admin/keys/rotation/status",
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;

            if result.success {
                binding_results
                    .push(format!("Token accepted with different User-Agent: {}", user_agent));
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("binding_results".to_string(), json!(binding_results));

    reporter.add_scenario_result(
        "token_binding_attacks",
        binding_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn token_validation_bypass(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing token validation bypass techniques");

    let session = framework.create_attack_session().await?;
    let mut bypass_results = Vec::new();

    // Test SQL injection in token validation
    let sql_injection_tokens = vec![
        "' OR '1'='1",
        "'; DROP TABLE tokens; --",
        "1' UNION SELECT 'admin' --",
        "token' OR 1=1 --",
    ];

    for malicious_token in sql_injection_tokens {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", malicious_token))?,
        );

        let result = framework
            .execute_attack(
                "token_sql_injection",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            bypass_results.push(format!("SQL injection successful with: {}", malicious_token));
            warn!("🚨 SQL injection in token validation: {}", malicious_token);
        }
    }

    // Test NoSQL injection
    let nosql_injection_tokens =
        vec![r#"{"$ne": null}"#, r#"{"$gt": ""}"#, r#"{"$regex": ".*"}"#, r#"{"$where": "1==1"}"#];

    for malicious_token in nosql_injection_tokens {
        let encoded_token = general_purpose::STANDARD.encode(malicious_token);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", encoded_token))?,
        );

        let result = framework
            .execute_attack(
                "token_nosql_injection",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            bypass_results.push(format!("NoSQL injection successful with: {}", malicious_token));
        }
    }

    // Test path traversal in token storage
    let path_traversal_tokens = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/var/log/auth.log",
        "../../../../proc/version",
    ];

    for traversal_token in path_traversal_tokens {
        let encoded_token = general_purpose::STANDARD.encode(traversal_token);

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Authorization",
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", encoded_token))?,
        );

        let result = framework
            .execute_attack(
                "token_path_traversal",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success
            || result.response_body.contains("root:")
            || result.response_body.contains("Linux version")
        {
            bypass_results.push(format!("Path traversal successful: {}", traversal_token));
            warn!("🚨 Path traversal vulnerability in token validation");
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("bypass_results".to_string(), json!(bypass_results));

    reporter.add_scenario_result(
        "token_validation_bypass",
        bypass_results.is_empty(),
        scenario_data,
    );
    Ok(())
}
