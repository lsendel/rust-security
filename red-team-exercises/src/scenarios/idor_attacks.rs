//! IDOR (Insecure Direct Object Reference) Attack Scenarios
//!
//! Tests the IDOR protection mechanisms and validates authorization controls

use crate::attack_framework::{AttackSession, RedTeamFramework};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::json;
use std::collections::HashMap;
use tracing::{debug, info, warn};
use base64::{Engine, engine::general_purpose};

pub async fn run_idor_scenarios(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🔍 Starting IDOR Attack Scenarios");

    // Scenario 1: Session ID Enumeration
    session_id_enumeration(framework, reporter, intensity).await?;

    // Scenario 2: User ID Parameter Tampering
    user_id_parameter_tampering(framework, reporter).await?;

    // Scenario 3: Token Introspection Bypass
    token_introspection_bypass(framework, reporter).await?;

    // Scenario 4: Admin Endpoint Access
    admin_endpoint_access(framework, reporter).await?;

    // Scenario 5: Cross-User Data Access
    cross_user_data_access(framework, reporter).await?;

    // Scenario 6: Resource ID Manipulation
    resource_id_manipulation(framework, reporter).await?;

    // Enhanced IDOR scenarios
    uuid_manipulation_attacks(framework, reporter).await?;
    database_enumeration_attacks(framework, reporter, intensity).await?;
    file_path_traversal_attacks(framework, reporter).await?;
    privilege_escalation_attacks(framework, reporter).await?;
    tenant_isolation_bypass(framework, reporter).await?;

    Ok(())
}

async fn session_id_enumeration(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🎯 Testing session ID enumeration protection");

    let session = framework.create_attack_session().await?;
    let mut enumeration_results = Vec::new();

    // First, create a legitimate session to understand the format
    let create_body = json!({
        "user_id": "redteam_enum_user",
        "client_id": "test_client"
    });

    let create_result = framework
        .execute_attack(
            "session_create",
            "POST",
            "/session/create",
            None,
            Some(create_body.to_string()),
            Some(&session),
        )
        .await?;

    let mut legitimate_session_id = None;
    if create_result.success {
        if let Ok(response_json) =
            serde_json::from_str::<serde_json::Value>(&create_result.response_body)
        {
            legitimate_session_id = response_json["session_id"].as_str().map(|s| s.to_string());
        }
    }

    // Generate session ID variants for enumeration
    let session_ids = generate_session_id_variants(legitimate_session_id.as_ref(), intensity);

    let mut accessible_sessions = Vec::new();
    let mut blocked_attempts = 0;

    for session_id in &session_ids {
        let result = framework
            .execute_attack(
                "session_enumeration",
                "GET",
                &format!("/session/{}", session_id),
                None,
                None,
                Some(&session),
            )
            .await?;

        match result.http_status {
            200 => {
                accessible_sessions.push(session_id.clone());
                warn!("🚨 IDOR: Accessible session found: {}", session_id);

                // Check if it contains sensitive data
                if result.response_body.contains("user_id")
                    || result.response_body.contains("session")
                    || result.response_body.len() > 100
                {
                    enumeration_results
                        .push(format!("Session {} contains sensitive data", session_id));
                }
            }
            403 | 401 => {
                blocked_attempts += 1;
                debug!("Access denied for session: {}", session_id);
            }
            404 => {
                debug!("Session not found: {}", session_id);
            }
            _ => {}
        }

        // Small delay to avoid overwhelming the service
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("sessions_tested".to_string(), json!(session_ids.len()));
    scenario_data.insert("accessible_sessions".to_string(), json!(accessible_sessions));
    scenario_data.insert("blocked_attempts".to_string(), json!(blocked_attempts));
    scenario_data.insert("enumeration_results".to_string(), json!(enumeration_results));

    let protection_effective = accessible_sessions.is_empty();
    reporter.add_scenario_result("session_id_enumeration", protection_effective, scenario_data);

    Ok(())
}

async fn user_id_parameter_tampering(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing user ID parameter tampering");

    let session = framework.create_attack_session().await?;
    let mut tampering_results = Vec::new();

    // Test various user ID manipulation techniques
    let user_ids = vec![
        "1",
        "2",
        "3",
        "100",
        "999", // Sequential
        "admin",
        "root",
        "administrator",
        "system", // Administrative
        "0",
        "-1",
        "null",
        "undefined", // Edge cases
        "'admin'",
        "admin'--",
        "1 OR 1=1", // SQL injection
        "../admin",
        "../../root", // Path traversal
        "%00admin",
        "admin%00", // Null byte injection
        "user\x00admin",
        "admin\x00", // Embedded nulls
    ];

    for user_id in &user_ids {
        // Test user ID in session invalidation endpoint
        let result = framework
            .execute_attack(
                "user_id_tampering",
                "POST",
                &format!("/session/invalidate-user/{}", urlencoding::encode(user_id)),
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            tampering_results.push(format!("User ID tampering successful: {}", user_id));
            warn!("🚨 IDOR: User ID tampering successful for: {}", user_id);

            // Check response for information disclosure
            if result.response_body.contains("invalidated") {
                let response_json: Result<serde_json::Value, _> =
                    serde_json::from_str(&result.response_body);
                if let Ok(json) = response_json {
                    if let Some(count) = json["invalidated_count"].as_u64() {
                        if count > 0 {
                            tampering_results.push(format!(
                                "Successfully invalidated {} sessions for user {}",
                                count, user_id
                            ));
                        }
                    }
                }
            }
        }

        // Test user ID in other endpoints
        let endpoints_to_test = vec![
            format!("/v1/authorize?user_id={}", urlencoding::encode(user_id)),
            format!("/oauth/userinfo?user_id={}", urlencoding::encode(user_id)),
        ];

        for endpoint in &endpoints_to_test {
            let endpoint_result = framework
                .execute_attack(
                    "user_id_endpoint_tampering",
                    "GET",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                )
                .await?;

            if endpoint_result.success && endpoint_result.response_body.len() > 50 {
                tampering_results.push(format!(
                    "User data exposed via endpoint {} with user_id {}",
                    endpoint, user_id
                ));
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("user_ids_tested".to_string(), json!(user_ids.len()));
    scenario_data.insert("tampering_results".to_string(), json!(tampering_results));

    reporter.add_scenario_result(
        "user_id_parameter_tampering",
        tampering_results.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn token_introspection_bypass(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing token introspection bypass");

    let session = framework.create_attack_session().await?;
    let mut bypass_results = Vec::new();

    // Generate various token formats to test
    let test_tokens = vec![
        "tk_00000000-0000-0000-0000-000000000000", // UUID format
        "tk_11111111-1111-1111-1111-111111111111",
        "tk_admin-token-12345",
        "tk_test",
        "tk_demo",
        "tk_guest",
        "Bearer_token_123",
        "access_token_456",
        "jwt.header.payload.signature",
        "invalid_token",
        "null",
        "undefined",
        "",
        format!("tk_{}", "a".repeat(100)),   // Long token
        "../../../etc/passwd",      // Path traversal
        "'; DROP TABLE tokens; --", // SQL injection
    ];

    for token in &test_tokens {
        let introspect_body = json!({
            "token": token
        });

        // Need to provide valid client credentials for introspection
        let mut headers = HeaderMap::new();
        let auth_header = general_purpose::STANDARD.encode("admin:admin");
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Basic {}", auth_header))?);

        let result = framework
            .execute_attack(
                "token_introspection_bypass",
                "POST",
                "/oauth/introspect",
                Some(headers),
                Some(introspect_body.to_string()),
                Some(&session),
            )
            .await?;

        if result.success {
            let response_json: Result<serde_json::Value, _> =
                serde_json::from_str(&result.response_body);
            if let Ok(json) = response_json {
                if let Some(active) = json["active"].as_bool() {
                    if active {
                        bypass_results.push(format!(
                            "Token introspection bypass: {} reported as active",
                            token
                        ));
                        warn!("🚨 IDOR: Token {} incorrectly reported as active", token);
                    }
                }

                // Check for information disclosure
                if json.get("client_id").is_some() || json.get("scope").is_some() {
                    bypass_results.push(format!("Information disclosure for token: {}", token));
                }
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("tokens_tested".to_string(), json!(test_tokens.len()));
    scenario_data.insert("bypass_results".to_string(), json!(bypass_results));

    reporter.add_scenario_result(
        "token_introspection_bypass",
        bypass_results.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn admin_endpoint_access(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing unauthorized admin endpoint access");

    let session = framework.create_attack_session().await?;
    let mut unauthorized_access = Vec::new();

    // Admin endpoints to test
    let admin_endpoints = vec![
        "/admin/keys/rotation/status",
        "/admin/keys/rotation/force",
        "/admin/rate-limit/stats",
        "/admin/security/alerts",
        "/admin/security/config",
        "/admin/users",
        "/admin/logs",
        "/admin/metrics",
        "/admin/health",
    ];

    for endpoint in &admin_endpoints {
        // Test without any authentication
        let result = framework
            .execute_attack("admin_no_auth", "GET", endpoint, None, None, Some(&session))
            .await?;

        if result.success {
            unauthorized_access
                .push(format!("Admin endpoint accessible without auth: {}", endpoint));
            warn!("🚨 IDOR: Admin endpoint {} accessible without authentication", endpoint);
        }

        // Test with invalid bearer token
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer invalid_token"));

        let invalid_result = framework
            .execute_attack(
                "admin_invalid_token",
                "GET",
                endpoint,
                Some(headers),
                None,
                Some(&session),
            )
            .await?;

        if invalid_result.success {
            unauthorized_access
                .push(format!("Admin endpoint accessible with invalid token: {}", endpoint));
        }

        // Test with manipulated authorization headers
        let manipulation_headers = vec![
            ("Authorization", "Bearer admin"),
            ("X-Admin-Token", "admin"),
            ("X-Internal-Auth", "true"),
            ("Cookie", "admin_session=true"),
        ];

        for (header_name, header_value) in &manipulation_headers {
            let mut headers = HeaderMap::new();
            headers.insert(header_name, HeaderValue::from_str(header_value)?);

            let manip_result = framework
                .execute_attack(
                    "admin_header_manipulation",
                    "GET",
                    endpoint,
                    Some(headers),
                    None,
                    Some(&session),
                )
                .await?;

            if manip_result.success {
                unauthorized_access.push(format!(
                    "Admin endpoint accessible via header {}: {} for {}",
                    header_name, header_value, endpoint
                ));
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("endpoints_tested".to_string(), json!(admin_endpoints.len()));
    scenario_data.insert("unauthorized_access".to_string(), json!(unauthorized_access));

    reporter.add_scenario_result(
        "admin_endpoint_access",
        unauthorized_access.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn cross_user_data_access(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing cross-user data access");

    let session = framework.create_attack_session().await?;
    let mut cross_access_results = Vec::new();

    // Simulate multiple user scenarios
    let test_users =
        vec!["user1", "user2", "admin_user", "test_user", "guest_user", "demo_user", "system_user"];

    for target_user in &test_users {
        // Test accessing user-specific endpoints
        let user_endpoints = vec![
            format!("/session/invalidate-user/{}", target_user),
            format!("/oauth/userinfo?sub={}", target_user),
            format!("/mfa/totp/verify?user_id={}", target_user),
        ];

        for endpoint in &user_endpoints {
            let result = framework
                .execute_attack("cross_user_access", "GET", &endpoint, None, None, Some(&session))
                .await?;

            if result.success && result.response_body.len() > 50 {
                cross_access_results.push(format!(
                    "Cross-user data access successful for {} via {}",
                    target_user, endpoint
                ));
                warn!("🚨 IDOR: Cross-user data access for user {} via {}", target_user, endpoint);

                // Check for PII or sensitive data
                let response_lower = result.response_body.to_lowercase();
                if response_lower.contains("email")
                    || response_lower.contains("phone")
                    || response_lower.contains("address")
                    || response_lower.contains("ssn")
                {
                    cross_access_results
                        .push(format!("PII exposed for user {} via {}", target_user, endpoint));
                }
            }
        }

        // Test session creation for other users
        let create_body = json!({
            "user_id": target_user,
            "client_id": "test_client"
        });

        let create_result = framework
            .execute_attack(
                "cross_user_session",
                "POST",
                "/session/create",
                None,
                Some(create_body.to_string()),
                Some(&session),
            )
            .await?;

        if create_result.success {
            cross_access_results.push(format!("Session created for other user: {}", target_user));

            // Try to use the created session
            if let Ok(response_json) =
                serde_json::from_str::<serde_json::Value>(&create_result.response_body)
            {
                if let Some(session_id) = response_json["session_id"].as_str() {
                    let session_result = framework
                        .execute_attack(
                            "use_cross_user_session",
                            "GET",
                            &format!("/session/{}", session_id),
                            None,
                            None,
                            Some(&session),
                        )
                        .await?;

                    if session_result.success {
                        cross_access_results
                            .push(format!("Successfully used session for user: {}", target_user));
                    }
                }
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("users_tested".to_string(), json!(test_users.len()));
    scenario_data.insert("cross_access_results".to_string(), json!(cross_access_results));

    reporter.add_scenario_result(
        "cross_user_data_access",
        cross_access_results.is_empty(),
        scenario_data,
    );

    Ok(())
}

async fn resource_id_manipulation(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing resource ID manipulation");

    let session = framework.create_attack_session().await?;
    let mut manipulation_results = Vec::new();

    // Test various resource ID manipulation techniques
    let resource_ids = vec![
        // Sequential IDs
        "1",
        "2",
        "10",
        "100",
        "999",
        // UUIDs
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        // Administrative IDs
        "admin",
        "root",
        "system",
        // Injection attempts
        "1'; DROP TABLE sessions; --",
        "1 OR 1=1",
        "' UNION SELECT * FROM users --",
        // Path traversal
        "../admin",
        "../../root",
        // Encoded values
        "%2e%2e%2fadmin",
        "%00admin",
        // Special characters
        "id<script>alert(1)</script>",
        "id`; ls -la`",
    ];

    let endpoints_with_ids =
        vec!["/session/{}", "/session/{}/refresh", "/admin/security/alerts/{}/resolve"];

    for endpoint_template in &endpoints_with_ids {
        for resource_id in &resource_ids {
            let endpoint = endpoint_template.replace("{}", &urlencoding::encode(resource_id));

            // Test GET request
            let get_result = framework
                .execute_attack(
                    "resource_id_manipulation_get",
                    "GET",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                )
                .await?;

            if get_result.success && get_result.response_body.len() > 50 {
                manipulation_results.push(format!(
                    "Resource access successful: {} with ID {}",
                    endpoint, resource_id
                ));

                // Check for sensitive data exposure
                if get_result.response_body.contains("user_id")
                    || get_result.response_body.contains("session")
                    || get_result.response_body.contains("admin")
                {
                    manipulation_results.push(format!(
                        "Sensitive data exposed via: {} with ID {}",
                        endpoint, resource_id
                    ));
                }
            }

            // Test POST/DELETE operations if applicable
            if endpoint.contains("refresh") {
                let refresh_body = json!({"duration": 3600});
                let post_result = framework
                    .execute_attack(
                        "resource_id_manipulation_post",
                        "POST",
                        &endpoint,
                        None,
                        Some(refresh_body.to_string()),
                        Some(&session),
                    )
                    .await?;

                if post_result.success {
                    manipulation_results.push(format!(
                        "Resource modification successful: {} with ID {}",
                        endpoint, resource_id
                    ));
                }
            }

            if endpoint.contains("session/")
                && !endpoint.contains("refresh")
                && !endpoint.contains("resolve")
            {
                let delete_result = framework
                    .execute_attack(
                        "resource_id_manipulation_delete",
                        "DELETE",
                        &endpoint,
                        None,
                        None,
                        Some(&session),
                    )
                    .await?;

                if delete_result.success {
                    manipulation_results.push(format!(
                        "Resource deletion successful: {} with ID {}",
                        endpoint, resource_id
                    ));
                    warn!("🚨 IDOR: Resource deletion successful for ID: {}", resource_id);
                }
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("resource_ids_tested".to_string(), json!(resource_ids.len()));
    scenario_data.insert("endpoints_tested".to_string(), json!(endpoints_with_ids.len()));
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));

    reporter.add_scenario_result(
        "resource_id_manipulation",
        manipulation_results.is_empty(),
        scenario_data,
    );

    Ok(())
}

fn generate_session_id_variants(base_session_id: Option<&String>, intensity: &str) -> Vec<String> {
    let mut variants = Vec::new();

    // Base variants
    let base_variants = vec![
        "00000000-0000-0000-0000-000000000000".to_string(),
        "11111111-1111-1111-1111-111111111111".to_string(),
        "session_001".to_string(),
        "session_admin".to_string(),
        "admin_session".to_string(),
        "test_session".to_string(),
        "demo_session".to_string(),
    ];
    variants.extend(base_variants);

    // If we have a legitimate session ID, create variants based on it
    if let Some(session_id) = base_session_id {
        // Sequential variants (increment/decrement)
        if let Some(last_char) = session_id.chars().last() {
            if let Some(digit) = last_char.to_digit(10) {
                for i in 0..10 {
                    if i != digit {
                        let mut variant = session_id.clone();
                        variant.pop();
                        variant.push_str(&i.to_string());
                        variants.push(variant);
                    }
                }
            }
        }

        // Pattern-based variants
        variants.push(session_id.replace("user", "admin"));
        variants.push(session_id.replace("test", "prod"));
        variants.push(session_id.replace("guest", "admin"));
    }

    match intensity {
        "high" => {
            // Add more sophisticated variants for high intensity
            for i in 0..1000 {
                variants.push(format!("session_{:04}", i));
                variants.push(format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    i,
                    i % 10000,
                    i % 10000,
                    i % 10000,
                    i as u64
                ));
            }
        }
        "medium" => {
            for i in 0..100 {
                variants.push(format!("session_{:03}", i));
            }
        }
        _ => {} // Low intensity uses just the base variants
    }

    variants
}

async fn uuid_manipulation_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing UUID/GUID manipulation attacks");

    let session = framework.create_attack_session().await?;
    let mut uuid_attacks = Vec::new();

    // Generate various UUID manipulation patterns
    let uuid_patterns = vec![
        // Null UUIDs
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        // Administrative UUIDs (common patterns)
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "deadbeef-dead-beef-dead-beefdeadbeef",
        // Sequential manipulation
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
        "99999999-9999-9999-9999-999999999999",
        // Version manipulation (v1, v4, v5)
        "12345678-1234-1234-1234-123456789012",
        "12345678-1234-4234-1234-123456789012",
        "12345678-1234-5234-1234-123456789012",
        // MAC address based (v1 UUIDs)
        "01234567-89ab-1def-0123-456789abcdef",
        // Timestamp manipulation
        "1e4e01b0-7d1c-11ee-b962-0242ac120002",
    ];

    let uuid_endpoints = vec![
        "/session/{}",
        "/oauth/userinfo?sub={}",
        "/admin/security/alerts/{}",
        "/session/{}/refresh",
    ];

    for endpoint_template in &uuid_endpoints {
        for uuid in &uuid_patterns {
            let endpoint = endpoint_template.replace("{}", uuid);

            let result = framework
                .execute_attack(
                    "uuid_manipulation",
                    "GET",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                )
                .await?;

            if result.success && result.response_body.len() > 50 {
                uuid_attacks.push(format!("UUID manipulation successful: {} -> {}", uuid, endpoint));
                warn!("🚨 IDOR: UUID manipulation successful for {}", uuid);

                // Check for admin or sensitive data
                let response_lower = result.response_body.to_lowercase();
                if response_lower.contains("admin") || response_lower.contains("system") {
                    uuid_attacks.push(format!("Administrative data exposed via UUID: {}", uuid));
                }
            }
        }
    }

    // Test UUID version confusion
    let base_uuid = "12345678-1234-4234-8234-123456789012";
    for version in 1..=5 {
        let version_uuid = base_uuid.replace("4234", &format!("{version}234"));
        
        let result = framework
            .execute_attack(
                "uuid_version_confusion",
                "GET",
                &format!("/session/{}", version_uuid),
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            uuid_attacks.push(format!("UUID v{} accepted: {}", version, version_uuid));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("uuid_attacks".to_string(), json!(uuid_attacks));
    scenario_data.insert("patterns_tested".to_string(), json!(uuid_patterns.len()));

    reporter.add_scenario_result("uuid_manipulation_attacks", uuid_attacks.is_empty(), scenario_data);
    Ok(())
}

async fn database_enumeration_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
    intensity: &str,
) -> Result<()> {
    info!("🎯 Testing database record enumeration via IDOR");

    let session = framework.create_attack_session().await?;
    let mut enumeration_results = Vec::new();

    let enumeration_range = match intensity {
        "high" => 10000,
        "medium" => 1000,
        _ => 100,
    };

    // Test sequential database ID enumeration
    let database_endpoints = vec![
        "/session/{}",
        "/oauth/userinfo?sub={}",
        "/admin/security/alerts/{}",
        "/admin/users/{}",
        "/api/v1/records/{}",
    ];

    for endpoint_template in &database_endpoints {
        let mut discovered_records = Vec::new();
        let mut last_successful_id = None;

        // Smart enumeration with exponential probing
        let probe_points = vec![1, 10, 100, 1000, 5000, 10000];
        
        for &probe_id in &probe_points {
            if probe_id > enumeration_range {
                break;
            }

            let endpoint = endpoint_template.replace("{}", &probe_id.to_string());
            
            let result = framework
                .execute_attack(
                    "database_enumeration_probe",
                    "GET",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                )
                .await?;

            if result.success && result.response_body.len() > 20 {
                discovered_records.push(probe_id);
                last_successful_id = Some(probe_id);
                info!("Database record found at ID: {}", probe_id);
            }
        }

        // If we found records, do focused enumeration around successful IDs
        if let Some(successful_id) = last_successful_id {
            let start = successful_id.saturating_sub(50);
            let end = std::cmp::min(successful_id + 50, enumeration_range);

            for id in start..=end {
                let endpoint = endpoint_template.replace("{}", &id.to_string());
                
                let result = framework
                    .execute_attack(
                        "database_enumeration_focused",
                        "GET",
                        &endpoint,
                        None,
                        None,
                        Some(&session),
                    )
                    .await?;

                if result.success && result.response_body.len() > 20 {
                    discovered_records.push(id);

                    // Check for sensitive data patterns
                    let response_lower = result.response_body.to_lowercase();
                    if response_lower.contains("password") 
                        || response_lower.contains("secret")
                        || response_lower.contains("token")
                        || response_lower.contains("private") {
                        enumeration_results.push(format!(
                            "Sensitive data exposed at ID {}: {}", 
                            id, endpoint_template
                        ));
                    }
                }

                // Rate limiting protection
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }

        if !discovered_records.is_empty() {
            enumeration_results.push(format!(
                "Database enumeration successful for {}: {} records found",
                endpoint_template,
                discovered_records.len()
            ));
            warn!("🚨 IDOR: Database enumeration found {} records for {}", 
                discovered_records.len(), endpoint_template);
        }
    }

    // Test database table enumeration
    let table_suffixes = vec![
        "_backup", "_temp", "_old", "_v2", "_staging", "_dev", "_test"
    ];

    for suffix in &table_suffixes {
        let modified_endpoint = format!("/admin/users{}/1", suffix);
        
        let result = framework
            .execute_attack(
                "table_enumeration",
                "GET",
                &modified_endpoint,
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success {
            enumeration_results.push(format!("Database table variation accessible: {}", suffix));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("enumeration_results".to_string(), json!(enumeration_results));
    scenario_data.insert("enumeration_range".to_string(), json!(enumeration_range));

    reporter.add_scenario_result(
        "database_enumeration_attacks",
        enumeration_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn file_path_traversal_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing file path traversal via object references");

    let session = framework.create_attack_session().await?;
    let mut traversal_results = Vec::new();

    // Path traversal payloads
    let traversal_payloads = vec![
        // Basic path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        // URL encoded
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam",
        // Double encoding
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        // Unicode encoding
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        // Null byte injection
        "../../../etc/passwd%00.jpg",
        // Filter bypass
        "....//....//....//etc/passwd",
        "..././..././..././etc/passwd",
        // Absolute paths
        "/etc/passwd",
        "/var/log/auth.log",
        "/proc/version",
        "/etc/shadow",
        // Windows paths
        "c:\\windows\\system32\\drivers\\etc\\hosts",
        "c:/windows/system.ini",
    ];

    let file_endpoints = vec![
        "/admin/logs/{}",
        "/session/{}/export",
        "/admin/security/alerts/{}/download",
        "/api/v1/files/{}",
    ];

    for endpoint_template in &file_endpoints {
        for payload in &traversal_payloads {
            let endpoint = endpoint_template.replace("{}", &urlencoding::encode(payload));

            let result = framework
                .execute_attack(
                    "path_traversal",
                    "GET",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                )
                .await?;

            if result.success {
                // Check for file system indicators
                let response_lower = result.response_body.to_lowercase();
                if response_lower.contains("root:") 
                    || response_lower.contains("administrator")
                    || response_lower.contains("linux version")
                    || response_lower.contains("microsoft windows")
                    || response_lower.contains("[autorun]") {
                    
                    traversal_results.push(format!(
                        "Path traversal successful: {} via {}",
                        payload, endpoint_template
                    ));
                    warn!("🚨 IDOR: Path traversal successful with payload: {}", payload);
                }
            }
        }
    }

    // Test directory traversal with resource IDs
    let directory_payloads = vec![
        "../",
        "../../",
        "../../../",
        "..\\",
        "..\\..\\",
        "..\\..\\..\\",
    ];

    for payload in &directory_payloads {
        let directory_endpoint = format!("/session/{}config.json", payload);
        
        let result = framework
            .execute_attack(
                "directory_traversal",
                "GET",
                &directory_endpoint,
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success && result.response_body.contains("{") {
            traversal_results.push(format!("Directory traversal successful: {}", payload));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("traversal_results".to_string(), json!(traversal_results));
    scenario_data.insert("payloads_tested".to_string(), json!(traversal_payloads.len()));

    reporter.add_scenario_result(
        "file_path_traversal_attacks",
        traversal_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn privilege_escalation_attacks(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing privilege escalation via IDOR");

    let session = framework.create_attack_session().await?;
    let mut escalation_results = Vec::new();

    // Test privilege escalation through user ID manipulation
    let privilege_targets = vec![
        ("admin", "Administrator account access"),
        ("root", "Root account access"),
        ("system", "System account access"),
        ("superuser", "Superuser account access"),
        ("0", "UID 0 (root) access"),
        ("1", "System daemon access"),
    ];

    for (target_id, description) in &privilege_targets {
        // Test user info access
        let userinfo_endpoint = format!("/oauth/userinfo?sub={}", target_id);
        
        let result = framework
            .execute_attack(
                "privilege_escalation_userinfo",
                "GET",
                &userinfo_endpoint,
                None,
                None,
                Some(&session),
            )
            .await?;

        if result.success && result.response_body.len() > 50 {
            escalation_results.push(format!("Privilege escalation: {}", description));
            
            // Check for administrative privileges in response
            let response_lower = result.response_body.to_lowercase();
            if response_lower.contains("admin") || response_lower.contains("privilege") {
                escalation_results.push(format!("Administrative data exposed for: {}", target_id));
            }
        }

        // Test session creation for privileged users
        let create_body = json!({
            "user_id": target_id,
            "client_id": "test_client"
        });

        let create_result = framework
            .execute_attack(
                "privilege_escalation_session",
                "POST",
                "/session/create",
                None,
                Some(create_body.to_string()),
                Some(&session),
            )
            .await?;

        if create_result.success {
            escalation_results.push(format!("Session created for privileged user: {}", target_id));
            
            // Try to use the privileged session
            if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&create_result.response_body) {
                if let Some(session_id) = response_json["session_id"].as_str() {
                    let admin_result = framework
                        .execute_attack(
                            "privilege_escalation_admin",
                            "GET",
                            "/admin/keys/rotation/status",
                            None,
                            None,
                            Some(&session),
                        )
                        .await?;

                    if admin_result.success {
                        escalation_results.push(format!(
                            "Administrative access gained via user: {}", 
                            target_id
                        ));
                        warn!("🚨 IDOR: Privilege escalation successful for user: {}", target_id);
                    }
                }
            }
        }
    }

    // Test role-based privilege escalation
    let role_modifications = vec![
        ("role", "admin"),
        ("role", "administrator"),
        ("permissions", "all"),
        ("access_level", "admin"),
        ("user_type", "admin"),
        ("privilege_level", "high"),
    ];

    for (param_name, param_value) in &role_modifications {
        let role_body = json!({
            "user_id": "redteam_role_user",
            param_name: param_value
        });

        let role_result = framework
            .execute_attack(
                "privilege_escalation_role",
                "POST",
                "/session/create",
                None,
                Some(role_body.to_string()),
                Some(&session),
            )
            .await?;

        if role_result.success {
            escalation_results.push(format!(
                "Role-based escalation: {}={}", 
                param_name, param_value
            ));
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("escalation_results".to_string(), json!(escalation_results));
    scenario_data.insert("targets_tested".to_string(), json!(privilege_targets.len()));

    reporter.add_scenario_result(
        "privilege_escalation_attacks",
        escalation_results.is_empty(),
        scenario_data,
    );
    Ok(())
}

async fn tenant_isolation_bypass(
    framework: &mut RedTeamFramework,
    reporter: &mut RedTeamReporter,
) -> Result<()> {
    info!("🎯 Testing tenant isolation bypass via IDOR");

    let session = framework.create_attack_session().await?;
    let mut isolation_bypass = Vec::new();

    // Test multi-tenant isolation
    let tenant_ids = vec![
        "tenant_001", "tenant_002", "tenant_admin", "tenant_system",
        "org_001", "org_002", "company_a", "company_b",
        "client_001", "client_002", "customer_vip"
    ];

    let tenant_endpoints = vec![
        "/api/v1/tenant/{}/users",
        "/api/v1/tenant/{}/sessions", 
        "/admin/tenant/{}/config",
        "/oauth/tenant/{}/clients",
    ];

    for endpoint_template in &tenant_endpoints {
        for tenant_id in &tenant_ids {
            let endpoint = endpoint_template.replace("{}", tenant_id);

            let result = framework
                .execute_attack(
                    "tenant_isolation_bypass",
                    "GET",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                )
                .await?;

            if result.success && result.response_body.len() > 50 {
                isolation_bypass.push(format!(
                    "Tenant isolation bypass: {} accessible",
                    endpoint
                ));

                // Check for sensitive tenant data
                let response_lower = result.response_body.to_lowercase();
                if response_lower.contains("users") 
                    || response_lower.contains("config")
                    || response_lower.contains("secret") {
                    isolation_bypass.push(format!(
                        "Sensitive tenant data exposed: {}",
                        tenant_id
                    ));
                    warn!("🚨 IDOR: Tenant isolation bypass for: {}", tenant_id);
                }
            }
        }
    }

    // Test cross-tenant session access
    for tenant_id in &tenant_ids {
        let create_body = json!({
            "user_id": format!("user@{}", tenant_id),
            "tenant_id": tenant_id,
            "client_id": "test_client"
        });

        let create_result = framework
            .execute_attack(
                "cross_tenant_session",
                "POST",
                "/session/create",
                None,
                Some(create_body.to_string()),
                Some(&session),
            )
            .await?;

        if create_result.success {
            isolation_bypass.push(format!(
                "Cross-tenant session created for: {}",
                tenant_id
            ));

            // Test accessing other tenant's data with this session
            if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&create_result.response_body) {
                if let Some(session_id) = response_json["session_id"].as_str() {
                    for other_tenant in &tenant_ids {
                        if other_tenant != tenant_id {
                            let cross_access_endpoint = format!("/api/v1/tenant/{}/users", other_tenant);
                            
                            let cross_result = framework
                                .execute_attack(
                                    "cross_tenant_access",
                                    "GET",
                                    &cross_access_endpoint,
                                    None,
                                    None,
                                    Some(&session),
                                )
                                .await?;

                            if cross_result.success {
                                isolation_bypass.push(format!(
                                    "Cross-tenant data access: {} -> {}",
                                    tenant_id, other_tenant
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    let mut scenario_data = HashMap::new();
    scenario_data.insert("isolation_bypass".to_string(), json!(isolation_bypass));
    scenario_data.insert("tenants_tested".to_string(), json!(tenant_ids.len()));

    reporter.add_scenario_result(
        "tenant_isolation_bypass",
        isolation_bypass.is_empty(),
        scenario_data,
    );
    Ok(())
}
