//! Automated Attack Simulator Tool

use super::{RedTeamTool, ToolConfig, ToolResult};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

pub struct AttackSimulator {
    client: Client,
}

impl AttackSimulator {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    async fn simulate_credential_stuffing(
        &self,
        target: &str,
        config: &ToolConfig,
    ) -> Result<AttackMetrics> {
        info!("🎯 Simulating credential stuffing attack");

        let credentials = self.generate_credential_list(&config.intensity);
        let semaphore = Arc::new(Semaphore::new(config.concurrent_threads as usize));
        let mut handles = Vec::new();

        for (client_id, client_secret) in credentials {
            let permit = semaphore.clone().acquire_owned().await?;
            let client = self.client.clone();
            let target = target.to_string();

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let start = Instant::now();

                let body = format!(
                    "grant_type=client_credentials&client_id={}&client_secret={}",
                    client_id, client_secret
                );

                let _result = client
                    .post(&format!("{}/oauth/token", target))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await;

                let duration = start.elapsed();

                match result {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let success = status == 200;
                        let detected = status == 429 || status == 403;

                        AttackAttempt {
                            success,
                            detected,
                            response_time_ms: duration.as_millis() as u64,
                            status_code: status,
                            credentials: format!("{}:{}", client_id, client_secret),
                        }
                    }
                    Err(_) => AttackAttempt {
                        success: false,
                        detected: false,
                        response_time_ms: duration.as_millis() as u64,
                        status_code: 0,
                        credentials: format!("{}:{}", client_id, client_secret),
                    },
                }
            });

            handles.push(handle);
        }

        let mut metrics = AttackMetrics::new("credential_stuffing");
        for handle in handles {
            if let Ok(attempt) = handle.await {
                metrics.add_attempt(attempt);
            }
        }

        Ok(metrics)
    }

    async fn simulate_brute_force(
        &self,
        target: &str,
        config: &ToolConfig,
    ) -> Result<AttackMetrics> {
        info!("🎯 Simulating brute force attack");

        let passwords = self.generate_password_list(&config.intensity);
        let target_user = "admin";
        let mut metrics = AttackMetrics::new("brute_force");

        for password in passwords {
            let start = Instant::now();

            let body = format!(
                "grant_type=client_credentials&client_id={}&client_secret={}",
                target_user, password
            );

            let _result = self
                .client
                .post(&format!("{}/oauth/token", target))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await;

            let duration = start.elapsed();

            let attempt = match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let success = status == 200;
                    let detected = status == 429 || status == 403;

                    AttackAttempt {
                        success,
                        detected,
                        response_time_ms: duration.as_millis() as u64,
                        status_code: status,
                        credentials: format!("{}:{}", target_user, password),
                    }
                }
                Err(_) => AttackAttempt {
                    success: false,
                    detected: false,
                    response_time_ms: duration.as_millis() as u64,
                    status_code: 0,
                    credentials: format!("{}:{}", target_user, password),
                },
            };

            metrics.add_attempt(attempt);

            // Stop if detected or successful
            if metrics.attempts.last().unwrap().detected || metrics.attempts.last().unwrap().success
            {
                break;
            }

            // Adaptive delay
            let delay = if duration > Duration::from_millis(1000) {
                Duration::from_millis(200)
            } else {
                Duration::from_millis(100)
            };
            tokio::time::sleep(delay).await;
        }

        Ok(metrics)
    }

    async fn simulate_idor_testing(
        &self,
        target: &str,
        config: &ToolConfig,
    ) -> Result<AttackMetrics> {
        info!("🎯 Simulating IDOR testing");

        let mut metrics = AttackMetrics::new("idor_testing");
        let session_ids = self.generate_session_ids(&config.intensity);

        for session_id in session_ids {
            let start = Instant::now();

            let _result = self
                .client
                .get(&format!("{}/session/{}", target, session_id))
                .header("Authorization", "Bearer fake_token")
                .send()
                .await;

            let duration = start.elapsed();

            let attempt = match result {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let success = status == 200;
                    let detected = status == 403 || status == 401;

                    AttackAttempt {
                        success,
                        detected,
                        response_time_ms: duration.as_millis() as u64,
                        status_code: status,
                        credentials: session_id.clone(),
                    }
                }
                Err(_) => AttackAttempt {
                    success: false,
                    detected: false,
                    response_time_ms: duration.as_millis() as u64,
                    status_code: 0,
                    credentials: session_id,
                },
            };

            metrics.add_attempt(attempt);

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(metrics)
    }

    fn generate_credential_list(&self, intensity: &str) -> Vec<(String, String)> {
        let base_credentials = vec![
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("test", "test"),
            ("user", "password"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("service", "service"),
        ];

        match intensity {
            "high" => {
                let mut extended = base_credentials
                    .into_iter()
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .collect::<Vec<_>>();
                for i in 0..100 {
                    extended.push((format!("user{}", i), "password123".to_string()));
                    extended.push((format!("client{}", i), format!("secret{}", i)));
                }
                extended
            }
            "medium" => {
                let mut medium = base_credentials
                    .into_iter()
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .collect::<Vec<_>>();
                for i in 0..20 {
                    medium.push((format!("test{}", i), "password".to_string()));
                }
                medium
            }
            _ => {
                base_credentials.into_iter().map(|(u, p)| (u.to_string(), p.to_string())).collect()
            }
        }
    }

    fn generate_password_list(&self, intensity: &str) -> Vec<String> {
        let base_passwords = vec![
            "password",
            "123456",
            "password123",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "qwerty",
            "123456789",
        ];

        match intensity {
            "high" => {
                let mut extended =
                    base_passwords.into_iter().map(|s| s.to_string()).collect::<Vec<_>>();
                extended.extend(
                    vec![
                        "Password1",
                        "Password!",
                        "password1",
                        "admin123",
                        "welcome123",
                        "letmein123",
                        "qwerty123",
                        "abc123",
                        "password2023",
                        "summer2023",
                        "spring2023",
                        "winter2023",
                    ]
                    .into_iter()
                    .map(|s| s.to_string()),
                );
                extended
            }
            "medium" => {
                let mut medium =
                    base_passwords.into_iter().map(|s| s.to_string()).collect::<Vec<_>>();
                medium.extend(
                    vec!["Password1", "admin123", "welcome123"].into_iter().map(|s| s.to_string()),
                );
                medium
            }
            _ => base_passwords.into_iter().map(|s| s.to_string()).collect(),
        }
    }

    fn generate_session_ids(&self, intensity: &str) -> Vec<String> {
        let mut session_ids = vec![
            "00000000-0000-0000-0000-000000000000".to_string(),
            "11111111-1111-1111-1111-111111111111".to_string(),
            "session_001".to_string(),
            "session_admin".to_string(),
            "admin_session".to_string(),
        ];

        match intensity {
            "high" => {
                for i in 0..1000 {
                    session_ids.push(format!("session_{:04}", i));
                    session_ids.push(format!(
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
                    session_ids.push(format!("session_{:03}", i));
                }
            }
            _ => {}
        }

        session_ids
    }
}

#[async_trait]
impl RedTeamTool for AttackSimulator {
    fn name(&self) -> &str {
        "attack_simulator"
    }

    fn description(&self) -> &str {
        "Automated attack simulation tool for testing security controls"
    }

    async fn execute(&self, target: &str, config: &ToolConfig) -> Result<ToolResult> {
        let start_time = Instant::now();

        // Run different attack simulations
        let credential_stuffing = self.simulate_credential_stuffing(target, config).await?;
        let brute_force = self.simulate_brute_force(target, config).await?;
        let idor_testing = self.simulate_idor_testing(target, config).await?;

        let duration = start_time.elapsed();

        // Combine metrics
        let total_attempts = credential_stuffing.total_attempts()
            + brute_force.total_attempts()
            + idor_testing.total_attempts();
        let total_successful = credential_stuffing.successful_attempts()
            + brute_force.successful_attempts()
            + idor_testing.successful_attempts();
        let total_detected = credential_stuffing.detected_attempts()
            + brute_force.detected_attempts()
            + idor_testing.detected_attempts();

        let success_rate =
            if total_attempts > 0 { total_successful as f64 / total_attempts as f64 } else { 0.0 };
        let detection_rate =
            if total_attempts > 0 { total_detected as f64 / total_attempts as f64 } else { 0.0 };

        let mut metrics = HashMap::new();
        metrics.insert("total_attempts".to_string(), total_attempts as f64);
        metrics.insert("success_rate".to_string(), success_rate);
        metrics.insert("detection_rate".to_string(), detection_rate);
        metrics.insert("duration_seconds".to_string(), duration.as_secs_f64());

        let mut findings = Vec::new();

        if success_rate > 0.1 {
            findings.push(
                "High attack success rate detected - security controls may be insufficient"
                    .to_string(),
            );
        }

        if detection_rate < 0.5 {
            findings.push(
                "Low detection rate - monitoring and alerting may need improvement".to_string(),
            );
        }

        if credential_stuffing.successful_attempts() > 0 {
            findings.push(format!(
                "Credential stuffing successful: {} attempts",
                credential_stuffing.successful_attempts()
            ));
        }

        if brute_force.successful_attempts() > 0 {
            findings.push(format!(
                "Brute force successful: {} attempts",
                brute_force.successful_attempts()
            ));
        }

        if idor_testing.successful_attempts() > 0 {
            findings.push(format!(
                "IDOR vulnerabilities found: {} accessible resources",
                idor_testing.successful_attempts()
            ));
        }

        let raw_data = json!({
            "credential_stuffing": credential_stuffing.to_json(),
            "brute_force": brute_force.to_json(),
            "idor_testing": idor_testing.to_json(),
            "summary": {
                "total_attempts": total_attempts,
                "total_successful": total_successful,
                "total_detected": total_detected,
                "success_rate": success_rate,
                "detection_rate": detection_rate,
                "duration_seconds": duration.as_secs_f64()
            }
        });

        Ok(ToolResult {
            tool_name: self.name().to_string(),
            success: findings.is_empty(),
            metrics,
            findings,
            raw_data,
        })
    }
}

impl Default for AttackSimulator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct AttackAttempt {
    success: bool,
    detected: bool,
    response_time_ms: u64,
    status_code: u16,
    credentials: String,
}

#[derive(Debug)]
struct AttackMetrics {
    attack_type: String,
    attempts: Vec<AttackAttempt>,
}

impl AttackMetrics {
    fn new(attack_type: &str) -> Self {
        Self { attack_type: attack_type.to_string(), attempts: Vec::new() }
    }

    fn add_attempt(&mut self, attempt: AttackAttempt) {
        self.attempts.push(attempt);
    }

    fn total_attempts(&self) -> usize {
        self.attempts.len()
    }

    fn successful_attempts(&self) -> usize {
        self.attempts.iter().filter(|a| a.success).count()
    }

    fn detected_attempts(&self) -> usize {
        self.attempts.iter().filter(|a| a.detected).count()
    }

    fn average_response_time(&self) -> f64 {
        if self.attempts.is_empty() {
            return 0.0;
        }
        let total: u64 = self.attempts.iter().map(|a| a.response_time_ms).sum();
        total as f64 / self.attempts.len() as f64
    }

    fn to_json(&self) -> serde_json::Value {
        json!({
            "attack_type": self.attack_type,
            "total_attempts": self.total_attempts(),
            "successful_attempts": self.successful_attempts(),
            "detected_attempts": self.detected_attempts(),
            "average_response_time_ms": self.average_response_time(),
            "success_rate": if self.total_attempts() > 0 { self.successful_attempts() as f64 / self.total_attempts() as f64 } else { 0.0 },
            "detection_rate": if self.total_attempts() > 0 { self.detected_attempts() as f64 / self.total_attempts() as f64 } else { 0.0 },
        })
    }
}
