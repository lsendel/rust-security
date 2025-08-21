use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{error, info, warn};

/// Advanced Security End-to-End Testing Suite
/// Simulates real-world attacks and validates security controls
#[derive(Debug, Clone)]
pub struct SecurityE2ETestSuite {
    config: TestConfig,
    client: Client,
    attack_scenarios: Vec<AttackScenario>,
    detection_validators: Vec<DetectionValidator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub target_base_url: String,
    pub auth_service_url: String,
    pub policy_service_url: String,
    pub timeout_seconds: u64,
    pub concurrent_requests: usize,
    pub attack_duration_seconds: u64,
    pub detection_timeout_seconds: u64,
    pub valid_credentials: HashMap<String, String>,
    pub test_environment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackScenario {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attack_type: AttackType,
    pub severity: Severity,
    pub owasp_category: String,
    pub mitre_technique: String,
    pub parameters: AttackParameters,
    pub expected_detections: Vec<ExpectedDetection>,
    pub success_criteria: SuccessCriteria,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackType {
    CredentialStuffing,
    TokenReplay,
    JwtTampering,
    SqlInjection,
    XssAttack,
    CsrfAttack,
    PathTraversal,
    CommandInjection,
    AuthenticationBypass,
    AuthorizationEscalation,
    SessionHijacking,
    BruteForceAttack,
    DdosAttack,
    ApiAbuse,
    DataExfiltration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackParameters {
    pub target_endpoints: Vec<String>,
    pub request_rate: u32,
    pub payload_variations: Vec<String>,
    pub headers: HashMap<String, String>,
    pub auth_methods: Vec<String>,
    pub custom_parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedDetection {
    pub detection_type: DetectionType,
    pub confidence_threshold: f64,
    pub detection_time_seconds: u64,
    pub alert_severity: Severity,
    pub mitigation_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionType {
    AnomalousTraffic,
    SuspiciousAuthentication,
    MaliciousPayload,
    RateLimitViolation,
    UnauthorizedAccess,
    DataLeakage,
    PolicyViolation,
    SecurityEventCorrelation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessCriteria {
    pub max_allowed_failures: u32,
    pub required_detection_rate: f64,
    pub max_false_positives: u32,
    pub max_response_time_ms: u64,
    pub security_controls_validated: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DetectionValidator {
    pub name: String,
    pub endpoint: String,
    pub query_method: QueryMethod,
    pub expected_events: Vec<SecurityEvent>,
}

#[derive(Debug, Clone)]
pub enum QueryMethod {
    RestApi,
    ElasticsearchQuery,
    PrometheusQuery,
    GraphqlQuery,
    DatabaseQuery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub severity: Severity,
    pub source_ip: String,
    pub target_endpoint: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub details: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub scenario_id: String,
    pub scenario_name: String,
    pub status: TestStatus,
    pub duration_seconds: f64,
    pub attack_metrics: AttackMetrics,
    pub detection_results: Vec<DetectionResult>,
    pub security_controls_status: Vec<SecurityControlStatus>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Passed,
    Failed,
    PartiallyPassed,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMetrics {
    pub requests_sent: u32,
    pub successful_attacks: u32,
    pub blocked_attempts: u32,
    pub false_positives: u32,
    pub average_response_time_ms: f64,
    pub detection_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub detection_type: DetectionType,
    pub detected: bool,
    pub detection_time_seconds: Option<f64>,
    pub confidence_score: f64,
    pub alert_generated: bool,
    pub mitigation_triggered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityControlStatus {
    pub control_name: String,
    pub control_type: String,
    pub status: ControlStatus,
    pub effectiveness_score: f64,
    pub bypass_attempts: u32,
    pub successful_bypasses: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlStatus {
    Effective,
    PartiallyEffective,
    Ineffective,
    Bypassed,
    NotTested,
}

impl SecurityE2ETestSuite {
    pub async fn new(config: TestConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .context("Failed to create HTTP client")?;

        let attack_scenarios = Self::load_attack_scenarios(&config).await?;
        let detection_validators = Self::setup_detection_validators(&config).await?;

        Ok(Self { config, client, attack_scenarios, detection_validators })
    }

    /// Execute complete security testing suite
    pub async fn run_complete_suite(&self) -> Result<Vec<TestResult>> {
        info!("Starting comprehensive security E2E test suite");

        let mut results = Vec::new();

        for scenario in &self.attack_scenarios {
            info!(
                scenario_id = %scenario.id,
                scenario_name = %scenario.name,
                attack_type = ?scenario.attack_type,
                "Executing security test scenario"
            );

            let start_time = Instant::now();

            match self.execute_scenario(scenario).await {
                Ok(result) => {
                    let duration = start_time.elapsed();
                    let mut final_result = result;
                    final_result.duration_seconds = duration.as_secs_f64();

                    info!(
                        scenario_id = %scenario.id,
                        status = ?final_result.status,
                        duration_seconds = final_result.duration_seconds,
                        "Security test scenario completed"
                    );

                    results.push(final_result);
                }
                Err(e) => {
                    error!(
                        scenario_id = %scenario.id,
                        error = %e,
                        "Security test scenario failed"
                    );

                    results.push(TestResult {
                        scenario_id: scenario.id.clone(),
                        scenario_name: scenario.name.clone(),
                        status: TestStatus::Error,
                        duration_seconds: start_time.elapsed().as_secs_f64(),
                        attack_metrics: AttackMetrics {
                            requests_sent: 0,
                            successful_attacks: 0,
                            blocked_attempts: 0,
                            false_positives: 0,
                            average_response_time_ms: 0.0,
                            detection_rate: 0.0,
                        },
                        detection_results: Vec::new(),
                        security_controls_status: Vec::new(),
                        recommendations: vec![format!("Investigation required: {}", e)],
                    });
                }
            }

            // Brief pause between scenarios to avoid overwhelming the system
            sleep(Duration::from_secs(2)).await;
        }

        self.generate_security_report(&results).await?;

        Ok(results)
    }

    async fn execute_scenario(&self, scenario: &AttackScenario) -> Result<TestResult> {
        match scenario.attack_type {
            AttackType::CredentialStuffing => self.execute_credential_stuffing(scenario).await,
            AttackType::TokenReplay => self.execute_token_replay(scenario).await,
            AttackType::JwtTampering => self.execute_jwt_tampering(scenario).await,
            AttackType::SqlInjection => self.execute_sql_injection(scenario).await,
            AttackType::XssAttack => self.execute_xss_attack(scenario).await,
            AttackType::CsrfAttack => self.execute_csrf_attack(scenario).await,
            AttackType::PathTraversal => self.execute_path_traversal(scenario).await,
            AttackType::AuthenticationBypass => self.execute_auth_bypass(scenario).await,
            AttackType::BruteForceAttack => self.execute_brute_force(scenario).await,
            AttackType::ApiAbuse => self.execute_api_abuse(scenario).await,
            _ => Err(anyhow::anyhow!("Attack type not implemented: {:?}", scenario.attack_type)),
        }
    }

    /// Simulate credential stuffing attacks with known compromised credentials
    async fn execute_credential_stuffing(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing credential stuffing attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let common_credentials = vec![
            ("admin", "password"),
            ("admin", "admin"),
            ("user", "password"),
            ("test", "test"),
            ("admin", "123456"),
            ("root", "password"),
            ("administrator", "password"),
        ];

        let mut response_times = Vec::new();
        let attack_start = Instant::now();

        for (username, password) in common_credentials {
            let request_start = Instant::now();

            let auth_request = serde_json::json!({
                "username": username,
                "password": password,
                "grant_type": "password"
            });

            let response = self
                .client
                .post(&format!("{}/oauth/token", self.config.auth_service_url))
                .header("Content-Type", "application/json")
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                .json(&auth_request)
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        attack_metrics.successful_attacks += 1;
                        warn!(
                            username = username,
                            password = password,
                            "Credential stuffing succeeded - SECURITY VULNERABILITY"
                        );
                    } else if resp.status() == 429 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("Request blocked by rate limiting or security controls");
                    }
                }
                Err(e) => {
                    warn!("Request failed: {}", e);
                }
            }

            // Realistic delay between attempts
            sleep(Duration::from_millis(500)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        // Wait for detection systems to process
        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        // Validate detections
        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        // Validate security controls
        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;

        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0, // Will be set by caller
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Simulate token replay attacks using captured authentication tokens
    async fn execute_token_replay(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing token replay attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        // First, obtain a legitimate token
        let valid_creds = self
            .config
            .valid_credentials
            .iter()
            .next()
            .context("No valid credentials configured for testing")?;

        let auth_request = serde_json::json!({
            "username": valid_creds.0,
            "password": valid_creds.1,
            "grant_type": "password"
        });

        let token_response = self
            .client
            .post(&format!("{}/oauth/token", self.config.auth_service_url))
            .json(&auth_request)
            .send()
            .await?;

        let token_data: serde_json::Value = token_response.json().await?;
        let access_token =
            token_data["access_token"].as_str().context("Failed to extract access token")?;

        // Wait for token to potentially expire or simulate old token
        sleep(Duration::from_secs(5)).await;

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        // Attempt multiple replays from different IP addresses (simulated)
        for i in 0..10 {
            let request_start = Instant::now();

            let response = self.client
                .get(&format!("{}/profile", self.config.auth_service_url))
                .header("Authorization", format!("Bearer {}", access_token))
                .header("X-Forwarded-For", format!("192.168.1.{}", 100 + i)) // Simulate different IPs
                .header("User-Agent", format!("AttackBot/{}", i))
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        attack_metrics.successful_attacks += 1;
                        warn!("Token replay succeeded - potential security issue");
                    } else if resp.status() == 401 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("Token replay blocked by security controls");
                    }
                }
                Err(e) => {
                    warn!("Token replay request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(200)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Simulate JWT tampering attacks with modified tokens
    async fn execute_jwt_tampering(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing JWT tampering attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        // Get a legitimate token
        let valid_creds = self
            .config
            .valid_credentials
            .iter()
            .next()
            .context("No valid credentials configured")?;

        let auth_request = serde_json::json!({
            "username": valid_creds.0,
            "password": valid_creds.1,
            "grant_type": "password"
        });

        let token_response = self
            .client
            .post(&format!("{}/oauth/token", self.config.auth_service_url))
            .json(&auth_request)
            .send()
            .await?;

        let token_data: serde_json::Value = token_response.json().await?;
        let original_token =
            token_data["access_token"].as_str().context("Failed to extract access token")?;

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        // Generate various tampered tokens
        let tampered_tokens = self.generate_tampered_jwts(original_token);

        for (tamper_type, tampered_token) in tampered_tokens {
            let request_start = Instant::now();

            let response = self
                .client
                .get(&format!("{}/admin/users", self.config.auth_service_url))
                .header("Authorization", format!("Bearer {}", tampered_token))
                .header("X-Attack-Type", format!("JWT-Tampering-{}", tamper_type))
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        attack_metrics.successful_attacks += 1;
                        warn!(
                            tamper_type = tamper_type,
                            "JWT tampering succeeded - CRITICAL VULNERABILITY"
                        );
                    } else if resp.status() == 401 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("Tampered JWT rejected by security controls");
                    }
                }
                Err(e) => {
                    warn!("JWT tampering request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(300)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute SQL injection attack patterns
    async fn execute_sql_injection(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing SQL injection attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let sql_payloads = vec![
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "admin'--",
            "' OR 1=1#",
            "' OR 'a'='a",
            "') OR ('1'='1",
        ];

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        for payload in sql_payloads {
            let request_start = Instant::now();

            // Test against search endpoint
            let response = self
                .client
                .get(&format!("{}/search", self.config.target_base_url))
                .query(&[("q", payload)])
                .header("X-Attack-Type", "SQL-Injection")
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        if self.detect_sql_injection_success(&body) {
                            attack_metrics.successful_attacks += 1;
                            warn!(
                                payload = payload,
                                "SQL injection succeeded - CRITICAL VULNERABILITY"
                            );
                        }
                    } else if resp.status() == 400 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("SQL injection blocked by input validation");
                    }
                }
                Err(e) => {
                    warn!("SQL injection request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(400)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute XSS attack simulation
    async fn execute_xss_attack(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing XSS attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let xss_payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>",
        ];

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        for payload in xss_payloads {
            let request_start = Instant::now();

            let response = self
                .client
                .post(&format!("{}/comments", self.config.target_base_url))
                .json(&serde_json::json!({
                    "content": payload,
                    "title": "Test Comment"
                }))
                .header("X-Attack-Type", "XSS")
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        if body.contains("<script>") || body.contains("javascript:") {
                            attack_metrics.successful_attacks += 1;
                            warn!(
                                payload = payload,
                                "XSS attack succeeded - potential vulnerability"
                            );
                        }
                    } else if resp.status() == 400 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("XSS payload blocked by input validation");
                    }
                }
                Err(e) => {
                    warn!("XSS attack request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(300)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute CSRF attack simulation
    async fn execute_csrf_attack(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing CSRF attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        // Get legitimate session first
        let valid_creds = self
            .config
            .valid_credentials
            .iter()
            .next()
            .context("No valid credentials configured")?;

        let auth_response = self
            .client
            .post(&format!("{}/login", self.config.auth_service_url))
            .json(&serde_json::json!({
                "username": valid_creds.0,
                "password": valid_creds.1
            }))
            .send()
            .await?;

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        // Attempt CSRF attacks without proper tokens
        let csrf_requests = vec![
            (
                "POST",
                "/admin/create-user",
                serde_json::json!({"username": "hacker", "role": "admin"}),
            ),
            ("DELETE", "/admin/users/1", serde_json::json!({})),
            ("PUT", "/settings/password", serde_json::json!({"new_password": "hacked123"})),
            ("POST", "/transfer", serde_json::json!({"to": "attacker", "amount": 1000})),
        ];

        for (method, endpoint, payload) in csrf_requests {
            let request_start = Instant::now();

            let response = match method {
                "POST" => {
                    self.client
                        .post(&format!("{}{}", self.config.target_base_url, endpoint))
                        .json(&payload)
                        .header("Origin", "http://evil-site.com")
                        .header("Referer", "http://evil-site.com/csrf-attack.html")
                        .header("X-Attack-Type", "CSRF")
                        .send()
                        .await
                }
                "DELETE" => {
                    self.client
                        .delete(&format!("{}{}", self.config.target_base_url, endpoint))
                        .header("Origin", "http://evil-site.com")
                        .header("X-Attack-Type", "CSRF")
                        .send()
                        .await
                }
                "PUT" => {
                    self.client
                        .put(&format!("{}{}", self.config.target_base_url, endpoint))
                        .json(&payload)
                        .header("Origin", "http://evil-site.com")
                        .header("X-Attack-Type", "CSRF")
                        .send()
                        .await
                }
                _ => continue,
            };

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        attack_metrics.successful_attacks += 1;
                        warn!(
                            method = method,
                            endpoint = endpoint,
                            "CSRF attack succeeded - missing CSRF protection"
                        );
                    } else if resp.status() == 403 || resp.status() == 400 {
                        attack_metrics.blocked_attempts += 1;
                        info!("CSRF attack blocked by security controls");
                    }
                }
                Err(e) => {
                    warn!("CSRF attack request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(500)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute path traversal attack simulation
    async fn execute_path_traversal(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing path traversal attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let path_traversal_payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\\\\....\\\\....\\\\etc\\\\passwd",
        ];

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        for payload in path_traversal_payloads {
            let request_start = Instant::now();

            let response = self
                .client
                .get(&format!("{}/files", self.config.target_base_url))
                .query(&[("path", payload)])
                .header("X-Attack-Type", "Path-Traversal")
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        if self.detect_path_traversal_success(&body) {
                            attack_metrics.successful_attacks += 1;
                            warn!(
                                payload = payload,
                                "Path traversal succeeded - CRITICAL VULNERABILITY"
                            );
                        }
                    } else if resp.status() == 400 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("Path traversal blocked by security controls");
                    }
                }
                Err(e) => {
                    warn!("Path traversal request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(400)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute authentication bypass attempts
    async fn execute_auth_bypass(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing authentication bypass attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        // Test various bypass techniques
        let bypass_techniques = vec![
            ("header-injection", vec![("X-User-Id", "1"), ("X-Role", "admin")]),
            ("empty-password", vec![]),
            ("null-session", vec![]),
            ("cookie-manipulation", vec![]),
        ];

        for (technique, headers) in bypass_techniques {
            let request_start = Instant::now();

            let mut request = self
                .client
                .get(&format!("{}/admin/dashboard", self.config.target_base_url))
                .header("X-Attack-Type", format!("Auth-Bypass-{}", technique));

            for (key, value) in headers {
                request = request.header(key, value);
            }

            let response = request.send().await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        attack_metrics.successful_attacks += 1;
                        warn!(
                            technique = technique,
                            "Authentication bypass succeeded - CRITICAL VULNERABILITY"
                        );
                    } else if resp.status() == 401 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("Authentication bypass blocked");
                    }
                }
                Err(e) => {
                    warn!("Auth bypass request failed: {}", e);
                }
            }

            sleep(Duration::from_millis(600)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute brute force attack simulation
    async fn execute_brute_force(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing brute force attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let common_passwords = vec![
            "password",
            "123456",
            "password123",
            "admin",
            "qwerty",
            "letmein",
            "welcome",
            "monkey",
            "1234567890",
            "abc123",
        ];

        let target_username = "admin";
        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        for password in common_passwords {
            let request_start = Instant::now();

            let response = self
                .client
                .post(&format!("{}/oauth/token", self.config.auth_service_url))
                .json(&serde_json::json!({
                    "username": target_username,
                    "password": password,
                    "grant_type": "password"
                }))
                .header("X-Attack-Type", "Brute-Force")
                .header("User-Agent", "BruteForceBot/1.0")
                .send()
                .await;

            let response_time = request_start.elapsed().as_millis() as f64;
            response_times.push(response_time);
            attack_metrics.requests_sent += 1;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        attack_metrics.successful_attacks += 1;
                        warn!(
                            username = target_username,
                            password = password,
                            "Brute force succeeded - weak password detected"
                        );
                        break; // Stop on success
                    } else if resp.status() == 429 || resp.status() == 403 {
                        attack_metrics.blocked_attempts += 1;
                        info!("Brute force blocked by rate limiting");
                        break; // Rate limited, stop attack
                    }
                }
                Err(e) => {
                    warn!("Brute force request failed: {}", e);
                }
            }

            // Aggressive attempt rate
            sleep(Duration::from_millis(100)).await;
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    /// Execute API abuse attack simulation
    async fn execute_api_abuse(&self, scenario: &AttackScenario) -> Result<TestResult> {
        info!("Executing API abuse attack simulation");

        let mut attack_metrics = AttackMetrics {
            requests_sent: 0,
            successful_attacks: 0,
            blocked_attempts: 0,
            false_positives: 0,
            average_response_time_ms: 0.0,
            detection_rate: 0.0,
        };

        let attack_start = Instant::now();
        let mut response_times = Vec::new();

        // Rapid API requests to test rate limiting
        let endpoints = vec!["/api/users", "/api/search", "/api/reports", "/api/data/export"];

        for _ in 0..100 {
            // High volume requests
            for endpoint in &endpoints {
                let request_start = Instant::now();

                let response = self
                    .client
                    .get(&format!("{}{}", self.config.target_base_url, endpoint))
                    .header("X-Attack-Type", "API-Abuse")
                    .header("User-Agent", "APIBot/1.0")
                    .send()
                    .await;

                let response_time = request_start.elapsed().as_millis() as f64;
                response_times.push(response_time);
                attack_metrics.requests_sent += 1;

                match response {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            attack_metrics.successful_attacks += 1;
                        } else if resp.status() == 429 {
                            attack_metrics.blocked_attempts += 1;
                            info!("API abuse blocked by rate limiting");
                            // Don't break, continue testing
                        }
                    }
                    Err(e) => {
                        warn!("API abuse request failed: {}", e);
                    }
                }

                // Very rapid requests
                sleep(Duration::from_millis(10)).await;
            }
        }

        attack_metrics.average_response_time_ms =
            response_times.iter().sum::<f64>() / response_times.len() as f64;

        sleep(Duration::from_secs(self.config.detection_timeout_seconds)).await;

        let detection_results = self.validate_detections(scenario, &attack_start).await?;
        attack_metrics.detection_rate = self.calculate_detection_rate(&detection_results);

        let security_controls_status =
            self.validate_security_controls(scenario, &attack_metrics).await?;
        let status = self.determine_test_status(
            scenario,
            &attack_metrics,
            &detection_results,
            &security_controls_status,
        );

        Ok(TestResult {
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            status,
            duration_seconds: 0.0,
            attack_metrics,
            detection_results,
            security_controls_status,
            recommendations: self.generate_recommendations(scenario, &attack_metrics).await,
        })
    }

    // Helper methods

    fn generate_tampered_jwts(&self, original_token: &str) -> Vec<(String, String)> {
        let mut tampered_tokens = Vec::new();

        // Split JWT into parts
        let parts: Vec<&str> = original_token.split('.').collect();
        if parts.len() != 3 {
            return tampered_tokens;
        }

        // Algorithm confusion attack (change alg to none)
        let none_header = base64::encode(r#"{"alg":"none","typ":"JWT"}"#);
        tampered_tokens.push((
            "none-algorithm".to_string(),
            format!("{}.{}.signature-removed", none_header, parts[1]),
        ));

        // Modify claims (change role to admin)
        let admin_payload = base64::encode(r#"{"sub":"user","role":"admin","exp":9999999999}"#);
        tampered_tokens.push((
            "privilege-escalation".to_string(),
            format!("{}.{}.{}", parts[0], admin_payload, parts[2]),
        ));

        // Invalid signature
        tampered_tokens.push((
            "invalid-signature".to_string(),
            format!("{}.{}.invalid-signature", parts[0], parts[1]),
        ));

        // Weak secret (try common secrets)
        tampered_tokens.push((
            "weak-secret".to_string(),
            original_token.to_string(), // Would need proper JWT signing with weak secret
        ));

        tampered_tokens
    }

    fn detect_sql_injection_success(&self, response_body: &str) -> bool {
        // Look for database error messages or unexpected data
        response_body.contains("SQL syntax")
            || response_body.contains("mysql_fetch")
            || response_body.contains("ORA-")
            || response_body.contains("Microsoft SQL")
            || response_body.contains("PostgreSQL")
            || response_body.contains("root:x:0:0")
    }

    fn detect_path_traversal_success(&self, response_body: &str) -> bool {
        // Look for system file contents
        response_body.contains("root:x:0:0")
            || response_body.contains("[boot loader]")
            || response_body.contains("# /etc/passwd")
            || response_body.contains("daemon:x:1:1")
    }

    async fn validate_detections(
        &self,
        scenario: &AttackScenario,
        attack_start: &Instant,
    ) -> Result<Vec<DetectionResult>> {
        let mut detection_results = Vec::new();

        for expected_detection in &scenario.expected_detections {
            let detected = self.query_detection_system(&expected_detection, attack_start).await?;

            detection_results.push(DetectionResult {
                detection_type: expected_detection.detection_type.clone(),
                detected,
                detection_time_seconds: if detected { Some(30.0) } else { None },
                confidence_score: if detected { 0.95 } else { 0.0 },
                alert_generated: detected,
                mitigation_triggered: detected
                    && matches!(
                        expected_detection.alert_severity,
                        Severity::Critical | Severity::High
                    ),
            });
        }

        Ok(detection_results)
    }

    async fn query_detection_system(
        &self,
        expected_detection: &ExpectedDetection,
        attack_start: &Instant,
    ) -> Result<bool> {
        // In a real implementation, this would query the actual detection systems
        // For simulation, we'll return based on detection type and attack pattern
        let detected = match expected_detection.detection_type {
            DetectionType::AnomalousTraffic => true,
            DetectionType::SuspiciousAuthentication => true,
            DetectionType::MaliciousPayload => true,
            DetectionType::RateLimitViolation => true,
            DetectionType::UnauthorizedAccess => false, // Simulate missed detection
            _ => true,
        };

        Ok(detected)
    }

    async fn validate_security_controls(
        &self,
        scenario: &AttackScenario,
        attack_metrics: &AttackMetrics,
    ) -> Result<Vec<SecurityControlStatus>> {
        let mut controls = Vec::new();

        // Rate limiting control
        controls.push(SecurityControlStatus {
            control_name: "Rate Limiting".to_string(),
            control_type: "Traffic Control".to_string(),
            status: if attack_metrics.blocked_attempts > 0 {
                ControlStatus::Effective
            } else {
                ControlStatus::Ineffective
            },
            effectiveness_score: (attack_metrics.blocked_attempts as f64
                / attack_metrics.requests_sent as f64)
                * 100.0,
            bypass_attempts: attack_metrics.requests_sent,
            successful_bypasses: attack_metrics.successful_attacks,
        });

        // Input validation control
        controls.push(SecurityControlStatus {
            control_name: "Input Validation".to_string(),
            control_type: "Data Validation".to_string(),
            status: if attack_metrics.successful_attacks == 0 {
                ControlStatus::Effective
            } else {
                ControlStatus::PartiallyEffective
            },
            effectiveness_score: ((attack_metrics.requests_sent - attack_metrics.successful_attacks)
                as f64
                / attack_metrics.requests_sent as f64)
                * 100.0,
            bypass_attempts: attack_metrics.requests_sent,
            successful_bypasses: attack_metrics.successful_attacks,
        });

        // Authentication control
        controls.push(SecurityControlStatus {
            control_name: "Authentication".to_string(),
            control_type: "Access Control".to_string(),
            status: match scenario.attack_type {
                AttackType::CredentialStuffing | AttackType::BruteForceAttack => {
                    if attack_metrics.successful_attacks == 0 {
                        ControlStatus::Effective
                    } else {
                        ControlStatus::Ineffective
                    }
                }
                _ => ControlStatus::NotTested,
            },
            effectiveness_score: if matches!(
                scenario.attack_type,
                AttackType::CredentialStuffing | AttackType::BruteForceAttack
            ) {
                ((attack_metrics.requests_sent - attack_metrics.successful_attacks) as f64
                    / attack_metrics.requests_sent as f64)
                    * 100.0
            } else {
                0.0
            },
            bypass_attempts: attack_metrics.requests_sent,
            successful_bypasses: attack_metrics.successful_attacks,
        });

        Ok(controls)
    }

    fn calculate_detection_rate(&self, detection_results: &[DetectionResult]) -> f64 {
        if detection_results.is_empty() {
            return 0.0;
        }

        let detected_count = detection_results.iter().filter(|d| d.detected).count();
        (detected_count as f64 / detection_results.len() as f64) * 100.0
    }

    fn determine_test_status(
        &self,
        scenario: &AttackScenario,
        attack_metrics: &AttackMetrics,
        detection_results: &[DetectionResult],
        security_controls: &[SecurityControlStatus],
    ) -> TestStatus {
        let critical_bypasses =
            attack_metrics.successful_attacks > scenario.success_criteria.max_allowed_failures;
        let poor_detection =
            attack_metrics.detection_rate < scenario.success_criteria.required_detection_rate;
        let controls_failed = security_controls
            .iter()
            .any(|c| matches!(c.status, ControlStatus::Ineffective | ControlStatus::Bypassed));

        if critical_bypasses || (poor_detection && controls_failed) {
            TestStatus::Failed
        } else if poor_detection || controls_failed {
            TestStatus::PartiallyPassed
        } else {
            TestStatus::Passed
        }
    }

    async fn generate_recommendations(
        &self,
        scenario: &AttackScenario,
        attack_metrics: &AttackMetrics,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        match scenario.attack_type {
            AttackType::CredentialStuffing => {
                if attack_metrics.successful_attacks > 0 {
                    recommendations.push("Implement account lockout policies".to_string());
                    recommendations.push("Deploy multi-factor authentication".to_string());
                    recommendations.push("Implement CAPTCHA after failed attempts".to_string());
                }
            }
            AttackType::TokenReplay => {
                if attack_metrics.successful_attacks > 0 {
                    recommendations.push("Implement token binding".to_string());
                    recommendations.push("Add device fingerprinting".to_string());
                    recommendations.push("Implement nonce/jti claims in JWT".to_string());
                }
            }
            AttackType::JwtTampering => {
                if attack_metrics.successful_attacks > 0 {
                    recommendations.push("Use strong JWT signing algorithms (RS256)".to_string());
                    recommendations.push("Implement proper signature verification".to_string());
                    recommendations.push("Validate all JWT claims thoroughly".to_string());
                }
            }
            AttackType::SqlInjection => {
                if attack_metrics.successful_attacks > 0 {
                    recommendations.push("Use parameterized queries".to_string());
                    recommendations.push("Implement input validation and sanitization".to_string());
                    recommendations.push("Deploy Web Application Firewall (WAF)".to_string());
                }
            }
            AttackType::XssAttack => {
                if attack_metrics.successful_attacks > 0 {
                    recommendations.push("Implement Content Security Policy (CSP)".to_string());
                    recommendations.push("Use proper output encoding".to_string());
                    recommendations.push("Sanitize user inputs".to_string());
                }
            }
            _ => {
                recommendations.push("Review security controls for this attack type".to_string());
            }
        }

        if attack_metrics.blocked_attempts == 0 {
            recommendations.push("Implement rate limiting controls".to_string());
        }

        if attack_metrics.detection_rate < 80.0 {
            recommendations.push("Improve security monitoring and alerting".to_string());
            recommendations.push("Tune detection rules for better coverage".to_string());
        }

        recommendations
    }

    async fn generate_security_report(&self, results: &[TestResult]) -> Result<()> {
        let total_tests = results.len();
        let passed = results.iter().filter(|r| matches!(r.status, TestStatus::Passed)).count();
        let failed = results.iter().filter(|r| matches!(r.status, TestStatus::Failed)).count();
        let partial =
            results.iter().filter(|r| matches!(r.status, TestStatus::PartiallyPassed)).count();

        info!(
            total_tests = total_tests,
            passed = passed,
            failed = failed,
            partially_passed = partial,
            "Security E2E test suite completed"
        );

        // Generate detailed report (would write to file in real implementation)
        for result in results {
            if matches!(result.status, TestStatus::Failed) {
                error!(
                    scenario = %result.scenario_name,
                    successful_attacks = result.attack_metrics.successful_attacks,
                    detection_rate = result.attack_metrics.detection_rate,
                    "SECURITY TEST FAILED"
                );
            }
        }

        Ok(())
    }

    async fn load_attack_scenarios(config: &TestConfig) -> Result<Vec<AttackScenario>> {
        // In a real implementation, this would load from configuration files
        Ok(vec![
            AttackScenario {
                id: "cred-stuffing-001".to_string(),
                name: "Credential Stuffing Attack".to_string(),
                description: "Test credential stuffing with common username/password combinations"
                    .to_string(),
                attack_type: AttackType::CredentialStuffing,
                severity: Severity::High,
                owasp_category: "A07:2021 – Identification and Authentication Failures".to_string(),
                mitre_technique: "T1110.004 - Credential Stuffing".to_string(),
                parameters: AttackParameters {
                    target_endpoints: vec!["/oauth/token".to_string()],
                    request_rate: 10,
                    payload_variations: vec![],
                    headers: HashMap::new(),
                    auth_methods: vec!["password".to_string()],
                    custom_parameters: HashMap::new(),
                },
                expected_detections: vec![ExpectedDetection {
                    detection_type: DetectionType::SuspiciousAuthentication,
                    confidence_threshold: 0.8,
                    detection_time_seconds: 30,
                    alert_severity: Severity::High,
                    mitigation_actions: vec![
                        "account_lockout".to_string(),
                        "rate_limit".to_string(),
                    ],
                }],
                success_criteria: SuccessCriteria {
                    max_allowed_failures: 0,
                    required_detection_rate: 90.0,
                    max_false_positives: 1,
                    max_response_time_ms: 5000,
                    security_controls_validated: vec![
                        "rate_limiting".to_string(),
                        "account_lockout".to_string(),
                    ],
                },
            },
            AttackScenario {
                id: "jwt-tampering-001".to_string(),
                name: "JWT Token Tampering".to_string(),
                description: "Test JWT token tampering and signature validation".to_string(),
                attack_type: AttackType::JwtTampering,
                severity: Severity::Critical,
                owasp_category: "A02:2021 – Cryptographic Failures".to_string(),
                mitre_technique: "T1552.001 - Unsecured Credentials".to_string(),
                parameters: AttackParameters {
                    target_endpoints: vec!["/admin/users".to_string()],
                    request_rate: 5,
                    payload_variations: vec![],
                    headers: HashMap::new(),
                    auth_methods: vec!["bearer".to_string()],
                    custom_parameters: HashMap::new(),
                },
                expected_detections: vec![ExpectedDetection {
                    detection_type: DetectionType::MaliciousPayload,
                    confidence_threshold: 0.9,
                    detection_time_seconds: 15,
                    alert_severity: Severity::Critical,
                    mitigation_actions: vec![
                        "block_request".to_string(),
                        "invalidate_session".to_string(),
                    ],
                }],
                success_criteria: SuccessCriteria {
                    max_allowed_failures: 0,
                    required_detection_rate: 95.0,
                    max_false_positives: 0,
                    max_response_time_ms: 3000,
                    security_controls_validated: vec![
                        "jwt_validation".to_string(),
                        "signature_verification".to_string(),
                    ],
                },
            },
        ])
    }

    async fn setup_detection_validators(config: &TestConfig) -> Result<Vec<DetectionValidator>> {
        Ok(vec![
            DetectionValidator {
                name: "Prometheus Alerts".to_string(),
                endpoint: "http://prometheus:9090/api/v1/alerts".to_string(),
                query_method: QueryMethod::PrometheusQuery,
                expected_events: vec![],
            },
            DetectionValidator {
                name: "Elasticsearch SIEM".to_string(),
                endpoint: "http://elasticsearch:9200/_search".to_string(),
                query_method: QueryMethod::ElasticsearchQuery,
                expected_events: vec![],
            },
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_test_suite_creation() {
        let config = TestConfig {
            target_base_url: "http://localhost:8080".to_string(),
            auth_service_url: "http://localhost:8080".to_string(),
            policy_service_url: "http://localhost:8081".to_string(),
            timeout_seconds: 30,
            concurrent_requests: 10,
            attack_duration_seconds: 60,
            detection_timeout_seconds: 30,
            valid_credentials: HashMap::from([(
                "test_user".to_string(),
                "test_password".to_string(),
            )]),
            test_environment: "development".to_string(),
        };

        let test_suite = SecurityE2ETestSuite::new(config).await;
        assert!(test_suite.is_ok());
    }

    #[test]
    fn test_jwt_tampering_generation() {
        let suite = SecurityE2ETestSuite {
            config: Arc::new(TestConfig {
                target_base_url: "http://localhost:8080".to_string(),
                auth_service_url: "http://localhost:8080".to_string(),
                policy_service_url: "http://localhost:8081".to_string(),
                timeout_seconds: 30,
                concurrent_requests: 10,
                attack_duration_seconds: 60,
                detection_timeout_seconds: 30,
                valid_credentials: HashMap::new(),
                test_environment: "test".to_string(),
            }),
            client: Client::new(),
            attack_scenarios: vec![],
            detection_validators: vec![],
        };

        let original_token =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicm9sZSI6InVzZXIifQ.signature";
        let tampered_tokens = suite.generate_tampered_jwts(original_token);

        assert!(!tampered_tokens.is_empty());
        assert!(tampered_tokens.iter().any(|(t, _)| t == "none-algorithm"));
        assert!(tampered_tokens.iter().any(|(t, _)| t == "privilege-escalation"));
    }
}
