//! Security Coverage Analyzer Tool

use super::{RedTeamTool, ToolConfig, ToolResult};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, info};

pub struct CoverageAnalyzer {
    client: Client,
}

impl CoverageAnalyzer {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn discover_endpoints(&self, target: &str) -> Result<Vec<String>> {
        info!("🔍 Discovering available endpoints");

        let mut discovered_endpoints = HashSet::new();

        // Known OAuth2/OIDC endpoints
        let standard_endpoints = vec![
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/introspect",
            "/oauth/revoke",
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
            "/jwks.json",
            "/userinfo",
            "/health",
            "/metrics",
            "/admin/keys/rotation/status",
            "/admin/keys/rotation/force",
            "/admin/rate-limit/stats",
            "/mfa/totp/register",
            "/mfa/totp/verify",
            "/mfa/totp/backup-codes/generate",
            "/mfa/otp/send",
            "/mfa/otp/verify",
            "/mfa/session/verify",
            "/session/create",
            "/session/refresh",
            "/session/invalidate",
        ];

        for endpoint in standard_endpoints {
            let _result = self.client.get(&format!("{}{}", target, endpoint)).send().await;

            if let Ok(response) = result {
                // Consider endpoint discovered if it doesn't return 404
                if response.status().as_u16() != 404 {
                    discovered_endpoints.insert(endpoint.to_string());
                }
            }
        }

        // Try to discover additional endpoints through common patterns
        let endpoint_patterns = vec![
            "/v1/authorize",
            "/v2/authorize",
            "/api/token",
            "/api/oauth/token",
            "/auth/login",
            "/auth/logout",
            "/admin/users",
            "/admin/logs",
            "/debug",
            "/status",
            "/version",
        ];

        for pattern in endpoint_patterns {
            let _result = self.client.get(&format!("{}{}", target, pattern)).send().await;

            if let Ok(response) = result {
                if response.status().as_u16() != 404 {
                    discovered_endpoints.insert(pattern.to_string());
                }
            }
        }

        Ok(discovered_endpoints.into_iter().collect())
    }

    async fn analyze_endpoint_security(
        &self,
        target: &str,
        endpoint: &str,
    ) -> Result<EndpointSecurityAnalysis> {
        debug!("🔍 Analyzing security for endpoint: {}", endpoint);

        let mut analysis = EndpointSecurityAnalysis::new(endpoint);

        // Test 1: Check if endpoint requires authentication
        let unauth_result = self.client.get(&format!("{}{}", target, endpoint)).send().await;

        if let Ok(response) = unauth_result {
            let status = response.status().as_u16();
            analysis.requires_authentication = status == 401 || status == 403;
            analysis.response_codes.insert("unauthenticated".to_string(), status);

            if status == 200 && response.content_length().unwrap_or(0) > 0 {
                analysis
                    .security_issues
                    .push("Endpoint accessible without authentication".to_string());
            }
        }

        // Test 2: Test with invalid authentication
        let invalid_auth_result = self
            .client
            .get(&format!("{}{}", target, endpoint))
            .header("Authorization", "Bearer invalid_token")
            .send()
            .await;

        if let Ok(response) = invalid_auth_result {
            let status = response.status().as_u16();
            analysis.response_codes.insert("invalid_auth".to_string(), status);

            if status == 200 {
                analysis
                    .security_issues
                    .push("Endpoint accepts invalid authentication".to_string());
            }
        }

        // Test 3: Check for verbose error messages
        let malformed_result = self
            .client
            .post(&format!("{}{}", target, endpoint))
            .header("Content-Type", "application/json")
            .body(r#"{"malformed": json}"#)
            .send()
            .await;

        if let Ok(response) = malformed_result {
            let body = response.text().await.unwrap_or_default();
            if body.len() > 200
                && (body.contains("stack")
                    || body.contains("panic")
                    || body.contains("src/")
                    || body.contains("database")
                    || body.contains("internal"))
            {
                analysis
                    .security_issues
                    .push("Verbose error messages may leak information".to_string());
            }
        }

        // Test 4: Check HTTP methods allowed
        let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"];
        for method in methods {
            let _result = match method {
                "GET" => self.client.get(&format!("{}{}", target, endpoint)).send().await,
                "POST" => self.client.post(&format!("{}{}", target, endpoint)).send().await,
                "PUT" => self.client.put(&format!("{}{}", target, endpoint)).send().await,
                "DELETE" => self.client.delete(&format!("{}{}", target, endpoint)).send().await,
                "PATCH" => self.client.patch(&format!("{}{}", target, endpoint)).send().await,
                "OPTIONS" => {
                    self.client
                        .request(reqwest::Method::OPTIONS, &format!("{}{}", target, endpoint))
                        .send()
                        .await
                }
                _ => continue,
            };

            if let Ok(response) = result {
                let status = response.status().as_u16();
                if status != 404 && status != 405 {
                    analysis.allowed_methods.push(method.to_string());
                }
            }
        }

        // Test 5: Check for security headers
        let headers_result = self.client.get(&format!("{}{}", target, endpoint)).send().await;

        if let Ok(response) = headers_result {
            let headers = response.headers();
            let security_headers = vec![
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Rate-Limit-Limit",
                "X-Request-ID",
            ];

            for header in security_headers {
                if headers.contains_key(header) {
                    analysis.security_headers.push(header.to_string());
                }
            }
        }

        // Calculate security score
        analysis.security_score = analysis.calculate_security_score();

        Ok(analysis)
    }

    fn analyze_attack_surface(
        &self,
        endpoint_analyses: &[EndpointSecurityAnalysis],
    ) -> AttackSurfaceAnalysis {
        let total_endpoints = endpoint_analyses.len();
        let unauthenticated_endpoints =
            endpoint_analyses.iter().filter(|a| !a.requires_authentication).count();

        let high_risk_endpoints =
            endpoint_analyses.iter().filter(|a| a.security_score < 0.5).count();

        let endpoints_with_issues =
            endpoint_analyses.iter().filter(|a| !a.security_issues.is_empty()).count();

        let total_security_issues: usize =
            endpoint_analyses.iter().map(|a| a.security_issues.len()).sum();

        let admin_endpoints =
            endpoint_analyses.iter().filter(|a| a.endpoint.contains("/admin/")).count();

        let mfa_endpoints =
            endpoint_analyses.iter().filter(|a| a.endpoint.contains("/mfa/")).count();

        let oauth_endpoints =
            endpoint_analyses.iter().filter(|a| a.endpoint.contains("/oauth/")).count();

        // Calculate overall security posture
        let security_posture = if high_risk_endpoints == 0 && total_security_issues == 0 {
            "Excellent".to_string()
        } else if high_risk_endpoints <= 2 && total_security_issues <= 5 {
            "Good".to_string()
        } else if high_risk_endpoints <= 5 && total_security_issues <= 10 {
            "Fair".to_string()
        } else {
            "Poor".to_string()
        };

        AttackSurfaceAnalysis {
            total_endpoints,
            unauthenticated_endpoints,
            high_risk_endpoints,
            endpoints_with_issues,
            total_security_issues,
            admin_endpoints,
            mfa_endpoints,
            oauth_endpoints,
            security_posture,
        }
    }
}

#[async_trait]
impl RedTeamTool for CoverageAnalyzer {
    fn name(&self) -> &str {
        "coverage_analyzer"
    }

    fn description(&self) -> &str {
        "Analyzes security coverage and attack surface of the target service"
    }

    async fn execute(&self, target: &str, config: &ToolConfig) -> Result<ToolResult> {
        // Step 1: Discover available endpoints
        let endpoints = self.discover_endpoints(target).await?;
        info!("Discovered {} endpoints", endpoints.len());

        // Step 2: Analyze security of each endpoint
        let mut endpoint_analyses = Vec::new();
        for endpoint in &endpoints {
            if let Ok(analysis) = self.analyze_endpoint_security(target, endpoint).await {
                endpoint_analyses.push(analysis);
            }

            // Small delay to be respectful
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Step 3: Analyze overall attack surface
        let attack_surface = self.analyze_attack_surface(&endpoint_analyses);

        // Prepare metrics
        let mut metrics = HashMap::new();
        metrics.insert("total_endpoints".to_string(), attack_surface.total_endpoints as f64);
        metrics.insert(
            "unauthenticated_endpoints".to_string(),
            attack_surface.unauthenticated_endpoints as f64,
        );
        metrics
            .insert("high_risk_endpoints".to_string(), attack_surface.high_risk_endpoints as f64);
        metrics.insert(
            "total_security_issues".to_string(),
            attack_surface.total_security_issues as f64,
        );
        metrics.insert("admin_endpoints".to_string(), attack_surface.admin_endpoints as f64);
        metrics.insert(
            "coverage_percentage".to_string(),
            if attack_surface.total_endpoints > 0 {
                (attack_surface.total_endpoints - attack_surface.high_risk_endpoints) as f64
                    / attack_surface.total_endpoints as f64
                    * 100.0
            } else {
                0.0
            },
        );

        // Generate findings
        let mut findings = Vec::new();

        if attack_surface.unauthenticated_endpoints > 0 {
            findings.push(format!(
                "{} endpoints accessible without authentication",
                attack_surface.unauthenticated_endpoints
            ));
        }

        if attack_surface.high_risk_endpoints > 0 {
            findings.push(format!(
                "{} high-risk endpoints identified",
                attack_surface.high_risk_endpoints
            ));
        }

        if attack_surface.total_security_issues > 10 {
            findings.push(format!(
                "High number of security issues found: {}",
                attack_surface.total_security_issues
            ));
        }

        // Add specific endpoint issues
        for analysis in &endpoint_analyses {
            if !analysis.security_issues.is_empty() {
                findings.push(format!(
                    "{}: {}",
                    analysis.endpoint,
                    analysis.security_issues.join(", ")
                ));
            }
        }

        // Success if security posture is good and no critical issues
        let success = attack_surface.security_posture == "Excellent"
            || (attack_surface.security_posture == "Good"
                && attack_surface.high_risk_endpoints == 0);

        let raw_data = json!({
            "discovered_endpoints": endpoints,
            "endpoint_analyses": endpoint_analyses.iter().map(|a| json!({
                "endpoint": a.endpoint,
                "requires_authentication": a.requires_authentication,
                "security_score": a.security_score,
                "security_issues": a.security_issues,
                "allowed_methods": a.allowed_methods,
                "security_headers": a.security_headers,
                "response_codes": a.response_codes
            })).collect::<Vec<_>>(),
            "attack_surface": json!({
                "total_endpoints": attack_surface.total_endpoints,
                "unauthenticated_endpoints": attack_surface.unauthenticated_endpoints,
                "high_risk_endpoints": attack_surface.high_risk_endpoints,
                "endpoints_with_issues": attack_surface.endpoints_with_issues,
                "total_security_issues": attack_surface.total_security_issues,
                "admin_endpoints": attack_surface.admin_endpoints,
                "mfa_endpoints": attack_surface.mfa_endpoints,
                "oauth_endpoints": attack_surface.oauth_endpoints,
                "security_posture": attack_surface.security_posture
            })
        });

        Ok(ToolResult { tool_name: self.name().to_string(), success, metrics, findings, raw_data })
    }
}

impl Default for CoverageAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct EndpointSecurityAnalysis {
    endpoint: String,
    requires_authentication: bool,
    security_score: f64,
    security_issues: Vec<String>,
    allowed_methods: Vec<String>,
    security_headers: Vec<String>,
    response_codes: HashMap<String, u16>,
}

impl EndpointSecurityAnalysis {
    fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            requires_authentication: false,
            security_score: 0.0,
            security_issues: Vec::new(),
            allowed_methods: Vec::new(),
            security_headers: Vec::new(),
            response_codes: HashMap::new(),
        }
    }

    fn calculate_security_score(&self) -> f64 {
        let mut score = 1.0;

        // Deduct points for security issues
        score -= self.security_issues.len() as f64 * 0.2;

        // Deduct points if authentication not required for sensitive endpoints
        if !self.requires_authentication
            && (self.endpoint.contains("/admin/")
                || self.endpoint.contains("/oauth/token")
                || self.endpoint.contains("/oauth/introspect"))
        {
            score -= 0.5;
        }

        // Add points for security headers
        score += self.security_headers.len() as f64 * 0.1;

        // Ensure score is between 0 and 1
        score.max(0.0).min(1.0)
    }
}

#[derive(Debug)]
struct AttackSurfaceAnalysis {
    total_endpoints: usize,
    unauthenticated_endpoints: usize,
    high_risk_endpoints: usize,
    endpoints_with_issues: usize,
    total_security_issues: usize,
    admin_endpoints: usize,
    mfa_endpoints: usize,
    oauth_endpoints: usize,
    security_posture: String,
}
