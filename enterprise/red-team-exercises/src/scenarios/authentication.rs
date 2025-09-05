//! Authentication Bypass Attack Scenarios
//!
//! Tests various authentication bypass techniques against the implemented controls

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use base64::{engine::general_purpose, Engine};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

pub async fn run_authentication_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🔐 Starting Authentication Bypass Scenarios");

    // Scenario 1: Credential Stuffing Attack
    credential_stuffing_attack(framework, reporter, intensity).await?;

    // Scenario 2: Brute Force Attack
    brute_force_attack(framework, reporter, intensity).await?;

    // Scenario 3: Client Credentials Manipulation
    client_credentials_manipulation(framework, reporter).await?;

    // Scenario 4: Authorization Header Manipulation
    authorization_header_manipulation(framework, reporter).await?;

    // Scenario 5: HTTP Basic Auth Bypass
    http_basic_auth_bypass(framework, reporter).await?;

    // Scenario 6: Default/Weak Credentials Testing
    default_credentials_testing(framework, reporter).await?;

    // Scenario 7: Authentication State Confusion
    authentication_state_confusion(framework, reporter).await?;

    Ok(())
}

async fn credential_stuffing_attack(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🎯 Executing credential stuffing attack");

    // Common username/password combinations from breached databases
    let credential_list = get_credential_stuffing_list(intensity);
    let session = framework.create_attack_session().await?;

    let mut successful_logins = 0;
    let mut blocked_attempts = 0;
    let mut rate_limited = 0;

    for (client_id, client_secret) in &credential_list {
        // Test OAuth2 client credentials flow
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            client_id, client_secret
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));

        let _result = framework
            .execute_attack(
                "credential_stuffing",
                "POST",
                "/oauth/token",
                Some(headers),
                Some(body),
                Some(&session),
            )
            .await?;

        match result.http_status {
            200 => {
                successful_logins += 1;
                warn!(
                    "🚨 CRITICAL: Credential stuffing successful with {}:{}",
                    client_id, client_secret
                );
            }
            429 => {
                rate_limited += 1;
                debug!("Rate limited - attack detected");
            }
            403 | 423 => {
                blocked_attempts += 1;
                debug!("Access blocked - security control active");
            }
            _ => {}
        }

        // Realistic delay between attempts
        let delay = match intensity {
            "high" => Duration::from_millis(100),
            "medium" => Duration::from_millis(500),
            _ => Duration::from_millis(1000),
        };
        tokio::time::sleep(delay).await;
    }

    // Report results
    let mut scenario_data = HashMap::new();
    scenario_data.insert("total_attempts".to_string(), json!(credential_list.len()));
    scenario_data.insert("successful_logins".to_string(), json!(successful_logins));
    scenario_data.insert("blocked_attempts".to_string(), json!(blocked_attempts));
    scenario_data.insert("rate_limited".to_string(), json!(rate_limited));

    let detection_rate = (blocked_attempts + rate_limited) as f64 / credential_list.len() as f64;
    scenario_data.insert("detection_rate".to_string(), json!(detection_rate));

    reporter.add_scenario_result("credential_stuffing", successful_logins == 0, scenario_data);

    Ok(())
}

async fn brute_force_attack(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🎯 Executing brute force attack");

    let session = framework.create_attack_session().await?;
    let base_client_id = "admin";
    let password_list = get_password_list(intensity);

    let mut attempts = 0;
    let mut successful = false;
    let mut first_block_attempt = None;

    for password in &password_list {
        attempts += 1;

        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            base_client_id, password
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));

        let _result = framework
            .execute_attack(
                "brute_force",
                "POST",
                "/oauth/token",
                Some(headers),
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success {
            successful = true;
            warn!("🚨 CRITICAL: Brute force successful after {} attempts", attempts);
            break;
        }

        if result.blocked && first_block_attempt.is_none() {
            first_block_attempt = Some(attempts);
            info!("🛡️ Brute force blocked after {} attempts", attempts);
        }

        // Rate limiting check
        if result.http_status == 429 {
            info!("🛡️ Rate limiting activated after {} attempts", attempts);
            break;
        }

        // Adaptive delay based on response time (detection evasion)
        let delay = if result.response_time_ms > 1000 {
            Duration::from_millis(2000) // Slower if service is responding slowly
        } else {
            Duration::from_millis(100)
        };
        tokio::time::sleep(delay).await;
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("total_attempts".to_string(), json!(attempts));
    scenario_data.insert("successful".to_string(), json!(successful));
    scenario_data.insert("blocked_after_attempts".to_string(), json!(first_block_attempt));

    reporter.add_scenario_result("brute_force", !successful, scenario_data);

    Ok(())
}

async fn client_credentials_manipulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing client credentials manipulation");

    let session = framework.create_attack_session().await?;
    let mut vulnerabilities_found = Vec::new();

    // Test 1: SQL Injection in client_id
    let sql_payloads = vec![
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT password FROM users WHERE username='admin' --",
        "admin'--",
    ];

    for payload in &sql_payloads {
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret=test",
            urlencoding::encode(payload)
        );

        let _result = framework
            .execute_attack(
                "sql_injection",
                "POST",
                "/oauth/token",
                None,
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success || result.response_body.contains("syntax error") {
            vulnerabilities_found
                .push(format!("SQL Injection vulnerability with payload: {}", payload));
        }
    }

    // Test 2: NoSQL Injection
    let nosql_payloads = vec![r#"{"$ne": null}"#, r#"{"$gt": ""}"#, r#"{"$regex": ".*"}"#];

    for payload in &nosql_payloads {
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret=test",
            urlencoding::encode(payload)
        );

        let _result = framework
            .execute_attack(
                "nosql_injection",
                "POST",
                "/oauth/token",
                None,
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success {
            vulnerabilities_found
                .push(format!("NoSQL Injection vulnerability with payload: {}", payload));
        }
    }

    // Test 3: LDAP Injection
    let ldap_payloads = vec!["*)(cn=*", "*)(|(cn=*", "*)(&(cn=*"];

    for payload in &ldap_payloads {
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret=test",
            urlencoding::encode(payload)
        );

        let _result = framework
            .execute_attack(
                "ldap_injection",
                "POST",
                "/oauth/token",
                None,
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success {
            vulnerabilities_found
                .push(format!("LDAP Injection vulnerability with payload: {}", payload));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("vulnerabilities_found".to_string(), json!(vulnerabilities_found));
    scenario_data.insert("injection_types_tested".to_string(), json!(["SQL", "NoSQL", "LDAP"]));

    reporter.add_scenario_result(
        "client_credentials_manipulation",
        vulnerabilities_found.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn authorization_header_manipulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing authorization header manipulation");

    let session = framework.create_attack_session().await?;
    let mut bypass_attempts = Vec::new();

    // Test various authorization header manipulations
    let auth_headers = vec![
        ("Basic", "YWRtaW46YWRtaW4="), // admin:admin
        ("Bearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        ("Digest", "username=\"admin\", realm=\"example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/oauth/token\", response=\"6629fae49393a05397450978507c4ef1\""),
        ("Negotiate", "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="),
        ("OAuth", "oauth_consumer_key=\"key\", oauth_token=\"token\", oauth_signature_method=\"HMAC-SHA1\", oauth_signature=\"signature\""),
    ];

    for (auth_type, auth_value) in &auth_headers {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("{} {}", auth_type, auth_value))?,
        );

        let _result = framework
            .execute_attack(
                "auth_header_manipulation",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            bypass_attempts.push(format!("Authorization bypass with {} auth", auth_type));
        }
    }

    // Test header injection
    let injection_headers = vec![
        "Bearer token\r\nX-Admin: true",
        "Bearer token\nX-Bypass: admin",
        "Bearer token%0aX-Role: admin",
        "Bearer token%0d%0aX-Privilege: elevated",
    ];

    for injected_header in &injection_headers {
        let mut headers = HeaderMap::new();
        if let Ok(header_value) = HeaderValue::from_str(injected_header) {
            headers.insert(AUTHORIZATION, header_value);

            let _result = framework
                .execute_attack(
                    "header_injection",
                    "GET",
                    "/admin/keys/rotation/status",
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;

            if result.success {
                bypass_attempts.push("Header injection successful".to_string());
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("bypass_attempts".to_string(), json!(bypass_attempts));
    scenario_data.insert(
        "auth_types_tested".to_string(),
        json!(["Basic", "Bearer", "Digest", "Negotiate", "OAuth"]),
    );

    reporter.add_scenario_result(
        "authorization_header_manipulation",
        bypass_attempts.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn http_basic_auth_bypass(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing HTTP Basic Auth bypass techniques");

    let session = framework.create_attack_session().await?;
    let mut bypass_methods = Vec::new();

    // Test 1: Missing password
    let basic_tests = vec![
        ("admin", ""),                  // Empty password
        ("admin", " "),                 // Space password
        ("", "password"),               // Empty username
        ("admin:", ""),                 // Malformed
        ("admin\x00", "password"),      // Null byte injection
        ("admin\x00admin", "password"), // Null byte in username
    ];

    for (username, password) in &basic_tests {
        let credentials = general_purpose::STANDARD.encode(format!("{}:{}", username, password));
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Basic {}", credentials))?);

        let _result = framework
            .execute_attack(
                "basic_auth_bypass",
                "POST",
                "/oauth/introspect",
                Some(headers),
                Some("token=test".to_string()),
                Some(&session),
            )
            .await?;

        if result.success {
            bypass_methods
                .push(format!("Basic auth bypass with credentials: {}:{}", username, password));
        }
    }

    // Test 2: Case sensitivity bypass
    let case_tests = vec![
        "basic", "Basic", "BASIC", "bAsIc", "bearer", // Wrong scheme
        "Bearer",
    ];

    for scheme in &case_tests {
        let credentials = general_purpose::STANDARD.encode("admin:admin");
        let mut headers = HeaderMap::new();
        headers
            .insert(AUTHORIZATION, HeaderValue::from_str(&format!("{} {}", scheme, credentials))?);

        let _result = framework
            .execute_attack(
                "auth_scheme_bypass",
                "POST",
                "/oauth/introspect",
                Some(headers),
                Some("token=test".to_string()),
                Some(&session),
            )
            .await?;

        if result.success {
            bypass_methods.push(format!("Auth scheme case bypass with: {}", scheme));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("bypass_methods".to_string(), json!(bypass_methods));
    scenario_data
        .insert("tests_performed".to_string(), json!(basic_tests.len() + case_tests.len()));

    reporter.add_scenario_result(
        "http_basic_auth_bypass",
        bypass_methods.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn default_credentials_testing(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing default and weak credentials");

    let session = framework.create_attack_session().await?;
    let mut found_credentials = Vec::new();

    // Common default credentials for various systems
    let default_creds = vec![
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "12345"),
        ("administrator", "administrator"),
        ("root", "root"),
        ("test", "test"),
        ("demo", "demo"),
        ("guest", "guest"),
        ("service", "service"),
        ("client", "client"),
        ("api", "api"),
        ("oauth", "oauth"),
        ("auth", "auth"),
        ("user", "user"),
        ("default", "default"),
        ("", ""),      // Empty credentials
        ("admin", ""), // Empty password
        ("", "admin"), // Empty username
    ];

    for (client_id, client_secret) in &default_creds {
        let body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            client_id, client_secret
        );

        let _result = framework
            .execute_attack(
                "default_credentials",
                "POST",
                "/oauth/token",
                None,
                Some(body),
                Some(&session),
            )
            .await?;

        if result.success {
            found_credentials.push(format!("{}:{}", client_id, client_secret));
            warn!("🚨 CRITICAL: Default credentials found: {}:{}", client_id, client_secret);
        }

        // Small delay to avoid overwhelming rate limits
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("found_credentials".to_string(), json!(found_credentials));
    scenario_data.insert("credentials_tested".to_string(), json!(default_creds.len()));

    reporter.add_scenario_result(
        "default_credentials",
        found_credentials.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn authentication_state_confusion(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing authentication state confusion");

    let session = framework.create_attack_session().await?;
    let mut state_bypass_attempts = Vec::new();

    // Test 1: Session fixation
    let fixed_session_id = "FIXED_SESSION_12345";
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::COOKIE,
        HeaderValue::from_str(&format!("session_id={}", fixed_session_id))?,
    );

    let _result = framework
        .execute_attack(
            "session_fixation",
            "GET",
            "/session/create",
            Some(headers),
            None,
            Some(&session),
        )
        .await?;

    if result.response_body.contains(fixed_session_id) {
        state_bypass_attempts.push("Session fixation vulnerability".to_string());
    }

    // Test 2: Authentication bypass via state manipulation
    let state_manipulation_tests = vec![
        ("X-Authenticated", "true"),
        ("X-User-Role", "admin"),
        ("X-Bypass-Auth", "1"),
        ("X-Internal-Request", "true"),
        ("X-Admin-Panel", "allowed"),
        ("X-Debug-Mode", "enabled"),
    ];

    for (header_name, header_value) in &state_manipulation_tests {
        let mut headers = HeaderMap::new();
        headers.insert(*header_name, HeaderValue::from_str(header_value)?);

        let _result = framework
            .execute_attack(
                "state_manipulation",
                "GET",
                "/admin/keys/rotation/status",
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            state_bypass_attempts
                .push(format!("State bypass via header: {}: {}", header_name, header_value));
        }
    }

    // Test 3: Multiple authentication headers
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::AUTHORIZATION, HeaderValue::from_str("Bearer invalid_token")?);
    headers.insert(
        reqwest::header::HeaderName::from_static("x-api-key"),
        HeaderValue::from_str("admin_key")?,
    );
    headers.insert(reqwest::header::COOKIE, HeaderValue::from_str("auth_token=admin_session")?);

    let _result = framework
        .execute_attack(
            "multiple_auth_bypass",
            "GET",
            "/admin/keys/rotation/status",
            Some(headers),
            None,
            Some(&session),
        )
        .await?;

    if result.success {
        state_bypass_attempts.push("Multiple authentication headers bypass".to_string());
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("bypass_attempts".to_string(), json!(state_bypass_attempts));
    scenario_data
        .insert("state_tests_performed".to_string(), json!(state_manipulation_tests.len() + 2));

    reporter.add_scenario_result(
        "authentication_state_confusion",
        state_bypass_attempts.is_empty(),
        scenario_data,
    );

    Ok(())
}

fn get_credential_stuffing_list(intensity: &str) -> Vec<(String, String)> {
    let mut base_list = vec![
        ("admin".to_string(), "password".to_string()),
        ("admin".to_string(), "123456".to_string()),
        ("admin".to_string(), "admin".to_string()),
        ("test".to_string(), "test".to_string()),
        ("user".to_string(), "password".to_string()),
        ("guest".to_string(), "guest".to_string()),
        ("demo".to_string(), "demo".to_string()),
        ("service".to_string(), "service".to_string()),
    ];

    match intensity {
        "high" => {
            // Add more sophisticated combinations
            for i in 0..100 {
                base_list.push((format!("user{}", i), "password123".to_string()));
                base_list.push((format!("client{}", i), format!("secret{}", i)));
            }
            base_list
        }
        "medium" => {
            for i in 0..20 {
                base_list.push((format!("test{}", i), "password".to_string()));
            }
            base_list
        }
        _ => base_list,
    }
}

fn get_password_list(intensity: &str) -> Vec<String> {
    let mut base_passwords = vec![
        "password".to_string(),
        "123456".to_string(),
        "password123".to_string(),
        "admin".to_string(),
        "letmein".to_string(),
        "welcome".to_string(),
        "monkey".to_string(),
        "dragon".to_string(),
        "qwerty".to_string(),
        "123456789".to_string(),
    ];

    match intensity {
        "high" => {
            // Add common password variations
            base_passwords.extend(vec![
                "Password1".to_string(),
                "Password!".to_string(),
                "password1".to_string(),
                "admin123".to_string(),
                "welcome123".to_string(),
                "letmein123".to_string(),
                "qwerty123".to_string(),
                "abc123".to_string(),
                "password2023".to_string(),
                "summer2023".to_string(),
                "spring2023".to_string(),
                "winter2023".to_string(),
            ]);
            base_passwords
        }
        "medium" => {
            base_passwords.extend(vec![
                "Password1".to_string(),
                "admin123".to_string(),
                "welcome123".to_string(),
            ]);
            base_passwords
        }
        _ => base_passwords,
    }
}
