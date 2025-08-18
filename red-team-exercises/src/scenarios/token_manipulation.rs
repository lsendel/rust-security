//! Token Manipulation Attack Scenarios

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use tracing::{info, warn};

pub async fn run_token_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🔐 Starting Token Manipulation Scenarios");

    jwt_manipulation_attacks(framework, reporter).await?;
    token_substitution_attacks(framework, reporter).await?;
    token_replay_attacks(framework, reporter).await?;
    token_enumeration_attacks(framework, reporter, intensity).await?;

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

    for (attack_type, malicious_jwt) in jwt_attacks {
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

    for pattern in token_patterns {
        let mut valid_tokens = Vec::new();

        for i in 0..(range / token_patterns.len()) {
            let token = pattern.replace("{}", &format!("{:06}", i));

            let introspect_body = json!({
                "token": token
            });

            // Use basic auth for introspection
            let mut headers = reqwest::header::HeaderMap::new();
            let auth = base64::encode("test:test");
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

    for pattern in uuid_patterns {
        for i in 0..10 {
            let token = format!(pattern, i);

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
