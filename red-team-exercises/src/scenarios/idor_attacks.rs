//! IDOR (Insecure Direct Object Reference) Attack Scenarios
//! 
//! Tests the IDOR protection mechanisms and validates authorization controls

use crate::attack_framework::{RedTeamFramework, AttackSession};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::json;
use std::collections::HashMap;
use tracing::{debug, info, warn};

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
    
    let create_result = framework.execute_attack(
        "session_create",
        "POST",
        "/session/create",
        None,
        Some(create_body.to_string()),
        Some(&session),
    ).await?;
    
    let mut legitimate_session_id = None;
    if create_result.success {
        if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&create_result.response_body) {
            legitimate_session_id = response_json["session_id"].as_str().map(|s| s.to_string());
        }
    }
    
    // Generate session ID variants for enumeration
    let session_ids = generate_session_id_variants(legitimate_session_id.as_ref(), intensity);
    
    let mut accessible_sessions = Vec::new();
    let mut blocked_attempts = 0;
    
    for session_id in session_ids {
        let result = framework.execute_attack(
            "session_enumeration",
            "GET",
            &format!("/session/{}", session_id),
            None,
            None,
            Some(&session),
        ).await?;
        
        match result.http_status {
            200 => {
                accessible_sessions.push(session_id.clone());
                warn!("🚨 IDOR: Accessible session found: {}", session_id);
                
                // Check if it contains sensitive data
                if result.response_body.contains("user_id") || 
                   result.response_body.contains("session") ||
                   result.response_body.len() > 100 {
                    enumeration_results.push(format!("Session {} contains sensitive data", session_id));
                }
            },
            403 | 401 => {
                blocked_attempts += 1;
                debug!("Access denied for session: {}", session_id);
            },
            404 => {
                debug!("Session not found: {}", session_id);
            },
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
        "1", "2", "3", "100", "999", // Sequential
        "admin", "root", "administrator", "system", // Administrative
        "0", "-1", "null", "undefined", // Edge cases
        "'admin'", "admin'--", "1 OR 1=1", // SQL injection
        "../admin", "../../root", // Path traversal
        "%00admin", "admin%00", // Null byte injection
        "user\x00admin", "admin\x00", // Embedded nulls
    ];
    
    for user_id in user_ids {
        // Test user ID in session invalidation endpoint
        let result = framework.execute_attack(
            "user_id_tampering",
            "POST",
            &format!("/session/invalidate-user/{}", urlencoding::encode(user_id)),
            None,
            None,
            Some(&session),
        ).await?;
        
        if result.success {
            tampering_results.push(format!("User ID tampering successful: {}", user_id));
            warn!("🚨 IDOR: User ID tampering successful for: {}", user_id);
            
            // Check response for information disclosure
            if result.response_body.contains("invalidated") {
                let response_json: Result<serde_json::Value, _> = serde_json::from_str(&result.response_body);
                if let Ok(json) = response_json {
                    if let Some(count) = json["invalidated_count"].as_u64() {
                        if count > 0 {
                            tampering_results.push(format!("Successfully invalidated {} sessions for user {}", count, user_id));
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
        
        for endpoint in endpoints_to_test {
            let endpoint_result = framework.execute_attack(
                "user_id_endpoint_tampering",
                "GET",
                &endpoint,
                None,
                None,
                Some(&session),
            ).await?;
            
            if endpoint_result.success && endpoint_result.response_body.len() > 50 {
                tampering_results.push(format!("User data exposed via endpoint {} with user_id {}", endpoint, user_id));
            }
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("user_ids_tested".to_string(), json!(user_ids.len()));
    scenario_data.insert("tampering_results".to_string(), json!(tampering_results));
    
    reporter.add_scenario_result("user_id_parameter_tampering", tampering_results.is_empty(), scenario_data);
    
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
        "tk_test", "tk_demo", "tk_guest",
        "Bearer_token_123", "access_token_456",
        "jwt.header.payload.signature",
        "invalid_token", "null", "undefined", "",
        "tk_" + &"a".repeat(100), // Long token
        "../../../etc/passwd", // Path traversal
        "'; DROP TABLE tokens; --", // SQL injection
    ];
    
    for token in test_tokens {
        let introspect_body = json!({
            "token": token
        });
        
        // Need to provide valid client credentials for introspection
        let mut headers = HeaderMap::new();
        let auth_header = base64::encode("admin:admin");
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Basic {}", auth_header))?);
        
        let result = framework.execute_attack(
            "token_introspection_bypass",
            "POST",
            "/oauth/introspect",
            Some(headers),
            Some(introspect_body.to_string()),
            Some(&session),
        ).await?;
        
        if result.success {
            let response_json: Result<serde_json::Value, _> = serde_json::from_str(&result.response_body);
            if let Ok(json) = response_json {
                if let Some(active) = json["active"].as_bool() {
                    if active {
                        bypass_results.push(format!("Token introspection bypass: {} reported as active", token));
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
    
    reporter.add_scenario_result("token_introspection_bypass", bypass_results.is_empty(), scenario_data);
    
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
    
    for endpoint in admin_endpoints {
        // Test without any authentication
        let result = framework.execute_attack(
            "admin_no_auth",
            "GET",
            endpoint,
            None,
            None,
            Some(&session),
        ).await?;
        
        if result.success {
            unauthorized_access.push(format!("Admin endpoint accessible without auth: {}", endpoint));
            warn!("🚨 IDOR: Admin endpoint {} accessible without authentication", endpoint);
        }
        
        // Test with invalid bearer token
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer invalid_token"));
        
        let invalid_result = framework.execute_attack(
            "admin_invalid_token",
            "GET",
            endpoint,
            Some(headers),
            None,
            Some(&session),
        ).await?;
        
        if invalid_result.success {
            unauthorized_access.push(format!("Admin endpoint accessible with invalid token: {}", endpoint));
        }
        
        // Test with manipulated authorization headers
        let manipulation_headers = vec![
            ("Authorization", "Bearer admin"),
            ("X-Admin-Token", "admin"),
            ("X-Internal-Auth", "true"),
            ("Cookie", "admin_session=true"),
        ];
        
        for (header_name, header_value) in manipulation_headers {
            let mut headers = HeaderMap::new();
            headers.insert(header_name, HeaderValue::from_str(header_value)?);
            
            let manip_result = framework.execute_attack(
                "admin_header_manipulation",
                "GET",
                endpoint,
                Some(headers),
                None,
                Some(&session),
            ).await?;
            
            if manip_result.success {
                unauthorized_access.push(format!("Admin endpoint accessible via header {}: {} for {}", header_name, header_value, endpoint));
            }
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("endpoints_tested".to_string(), json!(admin_endpoints.len()));
    scenario_data.insert("unauthorized_access".to_string(), json!(unauthorized_access));
    
    reporter.add_scenario_result("admin_endpoint_access", unauthorized_access.is_empty(), scenario_data);
    
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
    let test_users = vec![
        "user1", "user2", "admin_user", "test_user", 
        "guest_user", "demo_user", "system_user"
    ];
    
    for target_user in test_users {
        // Test accessing user-specific endpoints
        let user_endpoints = vec![
            format!("/session/invalidate-user/{}", target_user),
            format!("/oauth/userinfo?sub={}", target_user),
            format!("/mfa/totp/verify?user_id={}", target_user),
        ];
        
        for endpoint in user_endpoints {
            let result = framework.execute_attack(
                "cross_user_access",
                "GET",
                &endpoint,
                None,
                None,
                Some(&session),
            ).await?;
            
            if result.success && result.response_body.len() > 50 {
                cross_access_results.push(format!("Cross-user data access successful for {} via {}", target_user, endpoint));
                warn!("🚨 IDOR: Cross-user data access for user {} via {}", target_user, endpoint);
                
                // Check for PII or sensitive data
                let response_lower = result.response_body.to_lowercase();
                if response_lower.contains("email") || 
                   response_lower.contains("phone") ||
                   response_lower.contains("address") ||
                   response_lower.contains("ssn") {
                    cross_access_results.push(format!("PII exposed for user {} via {}", target_user, endpoint));
                }
            }
        }
        
        // Test session creation for other users
        let create_body = json!({
            "user_id": target_user,
            "client_id": "test_client"
        });
        
        let create_result = framework.execute_attack(
            "cross_user_session",
            "POST",
            "/session/create",
            None,
            Some(create_body.to_string()),
            Some(&session),
        ).await?;
        
        if create_result.success {
            cross_access_results.push(format!("Session created for other user: {}", target_user));
            
            // Try to use the created session
            if let Ok(response_json) = serde_json::from_str::<serde_json::Value>(&create_result.response_body) {
                if let Some(session_id) = response_json["session_id"].as_str() {
                    let session_result = framework.execute_attack(
                        "use_cross_user_session",
                        "GET",
                        &format!("/session/{}", session_id),
                        None,
                        None,
                        Some(&session),
                    ).await?;
                    
                    if session_result.success {
                        cross_access_results.push(format!("Successfully used session for user: {}", target_user));
                    }
                }
            }
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("users_tested".to_string(), json!(test_users.len()));
    scenario_data.insert("cross_access_results".to_string(), json!(cross_access_results));
    
    reporter.add_scenario_result("cross_user_data_access", cross_access_results.is_empty(), scenario_data);
    
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
        "1", "2", "10", "100", "999",
        // UUIDs
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        // Administrative IDs
        "admin", "root", "system",
        // Injection attempts
        "1'; DROP TABLE sessions; --",
        "1 OR 1=1",
        "' UNION SELECT * FROM users --",
        // Path traversal
        "../admin", "../../root",
        // Encoded values
        "%2e%2e%2fadmin", "%00admin",
        // Special characters
        "id<script>alert(1)</script>",
        "id`; ls -la`",
    ];
    
    let endpoints_with_ids = vec![
        "/session/{}",
        "/session/{}/refresh",
        "/admin/security/alerts/{}/resolve",
    ];
    
    for endpoint_template in endpoints_with_ids {
        for resource_id in &resource_ids {
            let endpoint = endpoint_template.replace("{}", &urlencoding::encode(resource_id));
            
            // Test GET request
            let get_result = framework.execute_attack(
                "resource_id_manipulation_get",
                "GET",
                &endpoint,
                None,
                None,
                Some(&session),
            ).await?;
            
            if get_result.success && get_result.response_body.len() > 50 {
                manipulation_results.push(format!("Resource access successful: {} with ID {}", endpoint, resource_id));
                
                // Check for sensitive data exposure
                if get_result.response_body.contains("user_id") ||
                   get_result.response_body.contains("session") ||
                   get_result.response_body.contains("admin") {
                    manipulation_results.push(format!("Sensitive data exposed via: {} with ID {}", endpoint, resource_id));
                }
            }
            
            // Test POST/DELETE operations if applicable
            if endpoint.contains("refresh") {
                let refresh_body = json!({"duration": 3600});
                let post_result = framework.execute_attack(
                    "resource_id_manipulation_post",
                    "POST",
                    &endpoint,
                    None,
                    Some(refresh_body.to_string()),
                    Some(&session),
                ).await?;
                
                if post_result.success {
                    manipulation_results.push(format!("Resource modification successful: {} with ID {}", endpoint, resource_id));
                }
            }
            
            if endpoint.contains("session/") && !endpoint.contains("refresh") && !endpoint.contains("resolve") {
                let delete_result = framework.execute_attack(
                    "resource_id_manipulation_delete",
                    "DELETE",
                    &endpoint,
                    None,
                    None,
                    Some(&session),
                ).await?;
                
                if delete_result.success {
                    manipulation_results.push(format!("Resource deletion successful: {} with ID {}", endpoint, resource_id));
                    warn!("🚨 IDOR: Resource deletion successful for ID: {}", resource_id);
                }
            }
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("resource_ids_tested".to_string(), json!(resource_ids.len()));
    scenario_data.insert("endpoints_tested".to_string(), json!(endpoints_with_ids.len()));
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));
    
    reporter.add_scenario_result("resource_id_manipulation", manipulation_results.is_empty(), scenario_data);
    
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
                variants.push(format!("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}", 
                    i, i % 10000, i % 10000, i % 10000, i as u64));
            }
        },
        "medium" => {
            for i in 0..100 {
                variants.push(format!("session_{:03}", i));
            }
        },
        _ => {} // Low intensity uses just the base variants
    }
    
    variants
}
