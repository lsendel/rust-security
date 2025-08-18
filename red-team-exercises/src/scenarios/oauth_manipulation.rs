//! OAuth2/OIDC Flow Manipulation Attack Scenarios

use crate::attack_framework::{RedTeamFramework, AttackSession};
use crate::reporting::RedTeamReporter;
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use tracing::{info, warn};

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
        
        let result = framework.execute_attack(
            "oauth_response_type_manipulation",
            "GET",
            &auth_url,
            None,
            None,
            Some(&session),
        ).await?;
        
        if result.success {
            manipulation_results.push(format!("Invalid response_type '{}' accepted", response_type));
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));
    
    reporter.add_scenario_result("oauth_flow_manipulation", manipulation_results.is_empty(), scenario_data);
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
    
    let result = framework.execute_attack(
        "pkce_downgrade",
        "GET",
        auth_url,
        None,
        None,
        Some(&session),
    ).await?;
    
    if result.success && !result.response_body.contains("not supported") {
        downgrade_attempts.push("PKCE plain method accepted".to_string());
        warn!("🚨 PKCE downgrade vulnerability detected");
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("downgrade_attempts".to_string(), json!(downgrade_attempts));
    
    reporter.add_scenario_result("pkce_downgrade_attacks", downgrade_attempts.is_empty(), scenario_data);
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
        
        let result = framework.execute_attack(
            "redirect_uri_manipulation",
            "GET",
            &auth_url,
            None,
            None,
            Some(&session),
        ).await?;
        
        if result.success {
            manipulation_results.push(format!("Malicious redirect URI accepted: {}", redirect_uri));
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("manipulation_results".to_string(), json!(manipulation_results));
    
    reporter.add_scenario_result("redirect_uri_manipulation", manipulation_results.is_empty(), scenario_data);
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
            "/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost".to_string()
        } else {
            format!("/oauth/authorize?response_type=code&client_id=test&redirect_uri=http://localhost&state={}", state_value)
        };
        
        let result = framework.execute_attack(
            "state_parameter_attack",
            "GET",
            &auth_url,
            None,
            None,
            Some(&session),
        ).await?;
        
        if result.success {
            state_attacks.push(format!("{}: {}", description, state_value));
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("state_attacks".to_string(), json!(state_attacks));
    
    reporter.add_scenario_result("state_parameter_attacks", state_attacks.is_empty(), scenario_data);
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
        
        let result = framework.execute_attack(
            "scope_manipulation",
            "GET",
            &auth_url,
            None,
            None,
            Some(&session),
        ).await?;
        
        if result.success {
            scope_manipulations.push(format!("Malicious scope accepted: {}", scope));
        }
    }
    
    let mut scenario_data = HashMap::new();
    scenario_data.insert("scope_manipulations".to_string(), json!(scope_manipulations));
    
    reporter.add_scenario_result("scope_manipulation", scope_manipulations.is_empty(), scenario_data);
    Ok(())
}
