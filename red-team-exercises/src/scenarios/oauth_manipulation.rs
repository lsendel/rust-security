//! OAuth2/OIDC Flow Manipulation Attack Scenarios
//!
//! Comprehensive testing of OAuth2 and OpenID Connect implementations for:
//! - Authorization code flow manipulation
//! - PKCE bypass and downgrade attacks  
//! - Redirect URI validation bypass
//! - State parameter CSRF protection
//! - Scope elevation and injection attacks
//! - Client authentication bypass
//! - Token exchange vulnerabilities
//! - OIDC-specific attack vectors

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn, debug};
use base64::{Engine, engine::general_purpose};

pub async fn run_oauth_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🔐 Starting OAuth2/OIDC Manipulation Scenarios");

    oauth_flow_manipulation(framework, reporter).await?;
    pkce_downgrade_attacks(framework, reporter).await?;
    redirect_uri_manipulation(framework, reporter).await?;
    state_parameter_attacks(framework, reporter).await?;
    scope_manipulation(framework, reporter).await?;
    client_authentication_bypass(framework, reporter).await?;
    token_exchange_attacks(framework, reporter).await?;
    oidc_specific_attacks(framework, reporter).await?;
    authorization_code_injection(framework, reporter).await?;

    Ok(())
}

async fn oauth_flow_manipulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing OAuth flow manipulation");

    let session = framework.create_attack_session().await?;
    let mut manipulation_results = Vec::new();

    // Test invalid response types
    let invalid_response_types = vec!["token", "code token", "invalid", ""];

    for response_type in invalid_response_types {
        let auth_url = format!(
            "/oauth/authorize?response_type={}&client_id=test&redirect_uri=http://localhost",
            urlencoding::encode(response_type)
        );

        let result = framework
            .execute_attack(
                "oauth_response_type_manipulation",
                "GET",
                &auth_url,
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            manipulation_results
                .push(format!("Invalid response_type '{}' accepted", response_type));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));

    reporter.add_scenario_result(
        "oauth_flow_manipulation",
        manipulation_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn pkce_downgrade_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing PKCE downgrade attacks");

    let session = framework.create_attack_session().await?;
    let mut downgrade_attempts = Vec::new();

    // Test plain PKCE method
    let auth_url = "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost&code_challenge=test&code_challenge_method=plain";

    let result = framework
        .execute_attack("pkce_downgrade", "GET", auth_url, None, None, Some(&session))
        .await?;

    if result.success && !result.response_body.contains("not supported") {
        downgrade_attempts.push("PKCE plain method accepted".to_string());
        warn!("🚨 PKCE downgrade vulnerability detected");
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("downgrade_attempts".to_string(), json!(downgrade_attempts));

    reporter.add_scenario_result(
        "pkce_downgrade_attacks",
        downgrade_attempts.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn redirect_uri_manipulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing redirect URI manipulation");

    let session = framework.create_attack_session().await?;
    let mut manipulation_results = Vec::new();

    let malicious_redirects = vec![
        "http://evil.com",
        "https://attacker.example.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "http://localhost:8080@evil.com",
        "http://localhost:8080/../evil.com",
    ];

    for redirect_uri in malicious_redirects {
        let auth_url = format!(
            "/oauth/authorize?response_type=code&client_id=test&redirect_uri={}",
            urlencoding::encode(redirect_uri)
        );

        let result = framework
            .execute_attack(
                "redirect_uri_manipulation",
                "GET",
                &auth_url,
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            manipulation_results.push(format!("Malicious redirect URI accepted: {}", redirect_uri));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));

    reporter.add_scenario_result(
        "redirect_uri_manipulation",
        manipulation_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn state_parameter_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing state parameter attacks");

    let session = framework.create_attack_session().await?;
    let mut state_attacks = Vec::new();

    // Test CSRF via missing/predictable state
    let csrf_tests = vec![
        ("", "Missing state parameter"),
        ("123", "Predictable state"),
        ("admin", "Guessable state"),
    ];

    for (state_value, description) in csrf_tests {
        let auth_url = if state_value.is_empty() {
            "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost"
                .to_string()
        } else {
            format!("/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost&state={}", state_value)
        };

        let result = framework
            .execute_attack("state_parameter_attack", "GET", &auth_url, None, None, Some(&session))
            .await?;

        if result.success {
            state_attacks.push(format!("{}: {}", description, state_value));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("state_attacks".to_string(), json!(state_attacks));

    reporter.add_scenario_result(
        "state_parameter_attacks",
        state_attacks.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn scope_manipulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing scope manipulation");

    let session = framework.create_attack_session().await?;
    let mut scope_manipulations = Vec::new();

    let malicious_scopes = vec![
        "admin",
        "root",
        "system",
        "read write admin",
        "openid profile email admin",
        "../admin",
        "scope'; DROP TABLE scopes; --",
    ];

    for scope in malicious_scopes {
        let auth_url = format!(
            "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost&scope={}",
            urlencoding::encode(scope)
        );

        let result = framework
            .execute_attack("scope_manipulation", "GET", &auth_url, None, None, Some(&session))
            .await?;

        if result.success {
            scope_manipulations.push(format!("Malicious scope accepted: {}", scope));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("scope_manipulations".to_string(), json!(scope_manipulations));

    reporter.add_scenario_result(
        "scope_manipulation",
        scope_manipulations.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn client_authentication_bypass(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing client authentication bypass");

    let session = framework.create_attack_session().await?;
    let mut bypass_results = Vec::new();

    // Test various client authentication bypass techniques
    let bypass_attempts = vec![
        ("none", "No authentication", None, None),
        ("basic_empty", "Empty basic auth", Some(""), Some("")),
        ("basic_null", "Null basic auth", Some("null"), Some("null")),
        ("jwt_none", "JWT none algorithm", Some("test"), Some("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0In0.")),
        ("client_secret_guess", "Guessed secret", Some("test"), Some("secret")),
        ("client_secret_weak", "Weak secret", Some("test"), Some("123456")),
    ];

    for (attack_type, description, client_id, client_secret) in bypass_attempts {
        let mut headers = reqwest::header::HeaderMap::new();
        
        if let (Some(id), Some(secret)) = (client_id, client_secret) {
            if secret.starts_with("eyJ") {
                // JWT client assertion
                headers.insert(
                    "Content-Type",
                    reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
            } else {
                // Basic auth
                let auth = general_purpose::STANDARD.encode(format!("{}:{}", id, secret));
                headers.insert(
                    "Authorization",
                    reqwest::header::HeaderValue::from_str(&format!("Basic {}", auth))?,
                );
            }
        }

        let body = if let (Some(id), Some(secret)) = (client_id, client_secret) {
            if secret.starts_with("eyJ") {
                format!("grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={}", secret)
            } else {
                "grant_type=client_credentials".to_string()
            }
        } else {
            "grant_type=client_credentials".to_string()
        };

        let result = framework
            .execute_attack(
                "client_auth_bypass",
                "POST",
                "/oauth/token",
                Some(headers),
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success && result.response_body.contains("access_token") {
            bypass_results.push(format!("{}: {}", description, attack_type));
            warn!("🚨 Client authentication bypass: {}", description);
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("bypass_results".to_string(), json!(bypass_results));

    reporter.add_scenario_result(
        "client_authentication_bypass",
        bypass_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn token_exchange_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing token exchange attacks");

    let session = framework.create_attack_session().await?;
    let mut exchange_attacks = Vec::new();

    // First try to get a valid token for exchange attacks
    if let Ok((valid_token, _)) = framework.attempt_client_credentials_flow("test", "test").await {
        // Test token elevation via exchange
        let elevation_attempts = vec![
            ("admin_token", "urn:ietf:params:oauth:token-type:access_token"),
            ("system_token", "urn:ietf:params:oauth:token-type:refresh_token"),
            ("elevated_scope", "urn:ietf:params:oauth:token-type:id_token"),
        ];

        for (subject_token, token_type) in elevation_attempts {
            let body = format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type={}&requested_token_type={}&scope=admin",
                valid_token, token_type, token_type
            );

            let result = framework
                .execute_attack(
                    "token_exchange_elevation",
                    "POST",
                    "/oauth/token",
                    None,
                    Some(body),
                    Some(&session),
                )
                .await?;

            if result.success && result.response_body.contains("access_token") {
                exchange_attacks.push(format!("Token elevation successful: {}", subject_token));
            }
        }

        // Test token substitution
        let malicious_tokens = vec![
            "fake_admin_token",
            "system_override_token",
            "debug_access_token",
        ];

        for malicious_token in malicious_tokens {
            let body = format!(
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token={}&subject_token_type=urn:ietf:params:oauth:token-type:access_token&requested_token_type=urn:ietf:params:oauth:token-type:access_token",
                malicious_token
            );

            let result = framework
                .execute_attack(
                    "token_substitution",
                    "POST",
                    "/oauth/token",
                    None,
                    Some(body),
                    Some(&session),
                )
                .await?;

            if result.success {
                exchange_attacks.push(format!("Token substitution accepted: {}", malicious_token));
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("exchange_attacks".to_string(), json!(exchange_attacks));

    reporter.add_scenario_result(
        "token_exchange_attacks",
        exchange_attacks.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn oidc_specific_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing OIDC-specific attacks");

    let session = framework.create_attack_session().await?;
    let mut oidc_attacks = Vec::new();

    // Test ID token manipulation
    let malicious_nonce_values = vec![
        "",  // Missing nonce
        "predictable_nonce_123",
        "admin_override",
        "../../../etc/passwd",
        "'; DROP TABLE users; --",
    ];

    for nonce in malicious_nonce_values {
        let auth_url = format!(
            "/oauth/authorize?response_type=id_token&client_id=test&redirect_uri=http://localhost&scope=openid&nonce={}",
            urlencoding::encode(nonce)
        );

        let result = framework
            .execute_attack(
                "oidc_nonce_manipulation",
                "GET",
                &auth_url,
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            oidc_attacks.push(format!("Malicious nonce accepted: {}", nonce));
        }
    }

    // Test userinfo endpoint attacks
    if let Ok((valid_token, _)) = framework.attempt_client_credentials_flow("test", "test").await {
        let userinfo_attacks = vec![
            ("token_injection", format!("{}'; DROP TABLE users; --", valid_token)),
            ("path_traversal", "../../../admin/userinfo".to_string()),
            ("privilege_escalation", format!("{}&admin=true", valid_token)),
        ];

        for (attack_type, token_param) in userinfo_attacks {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                "Authorization",
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token_param))?,
            );

            let result = framework
                .execute_attack(
                    "oidc_userinfo_attack",
                    "GET",
                    "/oauth/userinfo",
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;

            if result.success && (result.response_body.contains("admin") || result.response_body.contains("root")) {
                oidc_attacks.push(format!("Userinfo attack successful: {}", attack_type));
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("oidc_attacks".to_string(), json!(oidc_attacks));

    reporter.add_scenario_result(
        "oidc_specific_attacks",
        oidc_attacks.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn authorization_code_injection(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing authorization code injection attacks");

    let session = framework.create_attack_session().await?;
    let mut injection_results = Vec::new();

    // Test various code injection techniques
    let malicious_codes = vec![
        "admin_code_12345",
        "debug_override_code",
        "system_access_code",
        "'; DROP TABLE authorization_codes; --",
        "../../../admin/codes",
        "code'; INSERT INTO users (username, role) VALUES ('hacker', 'admin'); --",
    ];

    for code in malicious_codes {
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri=http://localhost&client_id=test",
            urlencoding::encode(code)
        );

        let result = framework
            .execute_attack(
                "auth_code_injection",
                "POST",
                "/oauth/token",
                None,
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success && result.response_body.contains("access_token") {
            injection_results.push(format!("Code injection successful: {}", code));
            warn!("🚨 Authorization code injection vulnerability: {}", code);
        }
    }

    // Test code replay attacks
    let replay_codes = vec![
        "previously_used_code_123",
        "expired_code_456",
        "shared_code_789",
    ];

    for code in replay_codes {
        // First attempt
        let body = format!(
            "grant_type=authorization_code&code={}&redirect_uri=http://localhost&client_id=test",
            code
        );

        let _first_result = framework
            .execute_attack(
                "auth_code_first_use",
                "POST",
                "/oauth/token",
                None,
                Some(body.clone()),
                Some(&session),
            )
            .await?;

        // Immediate replay
        let replay_result = framework
            .execute_attack(
                "auth_code_replay",
                "POST",
                "/oauth/token",
                None,
                Some(body),
                Some(&session),
            )
            .await?;

        if replay_result.success && replay_result.response_body.contains("access_token") {
            injection_results.push(format!("Code replay successful: {}", code));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("injection_results".to_string(), json!(injection_results));

    reporter.add_scenario_result(
        "authorization_code_injection",
        injection_results.is_empty(),
        scenario_data,
    );
    Ok(())
}
