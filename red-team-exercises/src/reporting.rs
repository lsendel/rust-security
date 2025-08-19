//! Red Team Exercise Reporting Framework
//!
//! Generates comprehensive reports on attack scenarios and security control validation

use crate::validation::{RiskLevel, ValidationResult};
use anyhow::Result;
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tabular::{Row, Table};
use tracing::info;
use chrono;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamReport {
    pub exercise_metadata: ExerciseMetadata,
    pub executive_summary: ExecutiveSummary,
    pub attack_scenarios: Vec<ScenarioResult>,
    pub validation_results: Vec<ValidationResult>,
    pub security_metrics: SecurityMetrics,
    pub recommendations: Vec<Recommendation>,
    pub detailed_findings: Vec<DetailedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExerciseMetadata {
    pub timestamp: String,
    pub target_url: String,
    pub exercise_duration: Duration,
    pub scenarios_executed: u32,
    pub controls_validated: u32,
    pub red_team_framework_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub overall_security_posture: SecurityPosture,
    pub critical_findings: u32,
    pub high_findings: u32,
    pub medium_findings: u32,
    pub low_findings: u32,
    pub controls_passing: u32,
    pub controls_failing: u32,
    pub attack_success_rate: f64,
    pub detection_rate: f64,
    pub response_effectiveness: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityPosture {
    Excellent,
    Good,
    Fair,
    Poor,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub scenario_name: String,
    pub success: bool,
    pub attacks_attempted: u32,
    pub attacks_successful: u32,
    pub attacks_detected: u32,
    pub attacks_blocked: u32,
    pub scenario_data: HashMap<String, serde_json::Value>,
    pub key_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub detection_accuracy: f64,
    pub false_positive_rate: f64,
    pub response_time_ms: u64,
    pub attack_surface_coverage: f64,
    pub control_effectiveness: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub category: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub effort: Effort,
    pub implementation_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effort {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedFinding {
    pub id: String,
    pub title: String,
    pub severity: RiskLevel,
    pub category: String,
    pub description: String,
    pub attack_vector: String,
    pub impact: String,
    pub evidence: Vec<String>,
    pub remediation: String,
    pub cve_references: Vec<String>,
    pub owasp_mapping: Vec<String>,
}

pub struct RedTeamReporter {
    scenarios: Vec<ScenarioResult>,
    validation_results: Vec<ValidationResult>,
    scenario_errors: Vec<(String, String)>,
    exercise_start: std::time::Instant,
    exercise_duration: Option<Duration>,
}

impl RedTeamReporter {
    pub fn new() -> Self {
        Self {
            scenarios: Vec::new(),
            validation_results: Vec::new(),
            scenario_errors: Vec::new(),
            exercise_start: std::time::Instant::now(),
            exercise_duration: None,
        }
    }

    pub fn add_scenario_result(
        &mut self,
        scenario_name: &str,
        success: bool,
        data: HashMap<String, serde_json::Value>,
    ) {
        let attacks_attempted = data
            .get("total_attempts")
            .or_else(|| data.get("attempts"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let attacks_successful = data
            .get("successful_attacks")
            .or_else(|| data.get("successful_logins"))
            .or_else(|| data.get("successful"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let attacks_detected = data
            .get("detected_attacks")
            .or_else(|| data.get("blocked_attempts"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let attacks_blocked = data
            .get("blocked_attacks")
            .or_else(|| data.get("rate_limited"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let key_findings = self.extract_key_findings(&data);

        let scenario = ScenarioResult {
            scenario_name: scenario_name.to_string(),
            success,
            attacks_attempted,
            attacks_successful,
            attacks_detected,
            attacks_blocked,
            scenario_data: data,
            key_findings,
        };

        self.scenarios.push(scenario);
    }

    pub fn add_validation_results(&mut self, results: Vec<ValidationResult>) {
        self.validation_results.extend(results);
    }

    pub fn add_scenario_error(&mut self, scenario_name: &str, error: String) {
        self.scenario_errors.push((scenario_name.to_string(), error));
    }

    pub fn set_exercise_duration(&mut self, duration: Duration) {
        self.exercise_duration = Some(duration);
    }

    pub fn generate_report(&self) -> RedTeamReport {
        let duration = self.exercise_duration.unwrap_or_else(|| self.exercise_start.elapsed());

        let metadata = ExerciseMetadata {
            timestamp: chrono::Utc::now().to_rfc3339(),
            target_url: "configured_target".to_string(), // Would be passed in
            exercise_duration: duration,
            scenarios_executed: self.scenarios.len() as u32,
            controls_validated: self.validation_results.len() as u32,
            red_team_framework_version: "1.0.0".to_string(),
        };

        let executive_summary = self.generate_executive_summary();
        let security_metrics = self.calculate_security_metrics();
        let recommendations = self.generate_recommendations();
        let detailed_findings = self.generate_detailed_findings();

        RedTeamReport {
            exercise_metadata: metadata,
            executive_summary,
            attack_scenarios: self.scenarios.clone(),
            validation_results: self.validation_results.clone(),
            security_metrics,
            recommendations,
            detailed_findings,
        }
    }

    fn generate_executive_summary(&self) -> ExecutiveSummary {
        let mut critical_findings = 0;
        let mut high_findings = 0;
        let mut medium_findings = 0;
        let mut low_findings = 0;

        // Count validation results by severity
        for result in &self.validation_results {
            if !result.passed {
                match result.risk_level {
                    RiskLevel::Critical => critical_findings += 1,
                    RiskLevel::High => high_findings += 1,
                    RiskLevel::Medium => medium_findings += 1,
                    RiskLevel::Low => low_findings += 1,
                    RiskLevel::Info => {}
                }
            }
        }

        // Count successful attacks as findings
        for scenario in &self.scenarios {
            if scenario.attacks_successful > 0 {
                critical_findings += scenario.attacks_successful;
            }
        }

        let controls_passing = self.validation_results.iter().filter(|r| r.passed).count() as u32;
        let controls_failing = self.validation_results.iter().filter(|r| !r.passed).count() as u32;

        let total_attacks: u32 = self.scenarios.iter().map(|s| s.attacks_attempted).sum();
        let successful_attacks: u32 = self.scenarios.iter().map(|s| s.attacks_successful).sum();
        let detected_attacks: u32 = self.scenarios.iter().map(|s| s.attacks_detected).sum();

        let attack_success_rate =
            if total_attacks > 0 { successful_attacks as f64 / total_attacks as f64 } else { 0.0 };

        let detection_rate =
            if total_attacks > 0 { detected_attacks as f64 / total_attacks as f64 } else { 0.0 };

        let response_effectiveness = if detected_attacks > 0 {
            (detected_attacks - successful_attacks) as f64 / detected_attacks as f64
        } else {
            0.0
        };

        let overall_security_posture = match (critical_findings, high_findings, attack_success_rate)
        {
            (0, 0, rate) if rate < 0.1 => SecurityPosture::Excellent,
            (0, h, rate) if h <= 2 && rate < 0.2 => SecurityPosture::Good,
            (c, _, rate) if c == 0 && rate < 0.3 => SecurityPosture::Fair,
            (c, _, rate) if c <= 2 || rate < 0.5 => SecurityPosture::Poor,
            _ => SecurityPosture::Critical,
        };

        ExecutiveSummary {
            overall_security_posture,
            critical_findings,
            high_findings,
            medium_findings,
            low_findings,
            controls_passing,
            controls_failing,
            attack_success_rate,
            detection_rate,
            response_effectiveness,
        }
    }

    fn calculate_security_metrics(&self) -> SecurityMetrics {
        let total_attacks: u32 = self.scenarios.iter().map(|s| s.attacks_attempted).sum();
        let detected_attacks: u32 = self.scenarios.iter().map(|s| s.attacks_detected).sum();
        let successful_attacks: u32 = self.scenarios.iter().map(|s| s.attacks_successful).sum();

        let detection_accuracy =
            if total_attacks > 0 { detected_attacks as f64 / total_attacks as f64 } else { 0.0 };

        // Estimate false positive rate (would need more sophisticated analysis in practice)
        let false_positive_rate = if detection_accuracy > 0.8 { 0.05 } else { 0.1 };

        // Average response time (simplified)
        let response_time_ms = 250; // Would calculate from actual metrics

        // Attack surface coverage (percentage of endpoints tested)
        let attack_surface_coverage = 0.85; // Would calculate based on actual coverage

        let mut control_effectiveness = HashMap::new();
        for result in &self.validation_results {
            let category = &result.control_name;
            let effectiveness = if result.passed { 1.0 } else { 0.0 };
            control_effectiveness.insert(category.clone(), effectiveness);
        }

        SecurityMetrics {
            detection_accuracy,
            false_positive_rate,
            response_time_ms,
            attack_surface_coverage,
            control_effectiveness,
        }
    }

    fn generate_recommendations(&self) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Analyze validation results for recommendations
        for result in &self.validation_results {
            if !result.passed {
                if let Some(remediation) = &result.remediation {
                    let priority = match result.risk_level {
                        RiskLevel::Critical => Priority::Critical,
                        RiskLevel::High => Priority::High,
                        RiskLevel::Medium => Priority::Medium,
                        RiskLevel::Low => Priority::Low,
                        RiskLevel::Info => Priority::Low,
                    };

                    let recommendation = Recommendation {
                        priority,
                        category: result.control_name.clone(),
                        title: format!("Fix: {}", result.test_name),
                        description: remediation.clone(),
                        impact: format!(
                            "Addresses {} risk in {}",
                            match result.risk_level {
                                RiskLevel::Critical => "critical",
                                RiskLevel::High => "high",
                                RiskLevel::Medium => "medium",
                                RiskLevel::Low => "low",
                                RiskLevel::Info => "informational",
                            },
                            result.control_name
                        ),
                        effort: Effort::Medium, // Would analyze complexity
                        implementation_steps: vec![
                            "Review current implementation".to_string(),
                            "Implement recommended changes".to_string(),
                            "Test and validate fixes".to_string(),
                        ],
                    };

                    recommendations.push(recommendation);
                }
            }
        }

        // Add scenario-based recommendations
        for scenario in &self.scenarios {
            if scenario.attacks_successful > 0 {
                let recommendation = Recommendation {
                    priority: Priority::High,
                    category: "Attack Prevention".to_string(),
                    title: format!("Strengthen defenses against {}", scenario.scenario_name),
                    description: format!(
                        "The {} scenario had {} successful attacks out of {} attempts",
                        scenario.scenario_name,
                        scenario.attacks_successful,
                        scenario.attacks_attempted
                    ),
                    impact: "Reduces risk of successful attacks".to_string(),
                    effort: Effort::Medium,
                    implementation_steps: vec![
                        "Analyze attack patterns".to_string(),
                        "Implement additional controls".to_string(),
                        "Enhance monitoring and detection".to_string(),
                    ],
                };

                recommendations.push(recommendation);
            }
        }

        recommendations
    }

    fn generate_detailed_findings(&self) -> Vec<DetailedFinding> {
        let mut findings = Vec::new();
        let mut finding_id = 1;

        // Convert validation failures to detailed findings
        for result in &self.validation_results {
            if !result.passed {
                let finding = DetailedFinding {
                    id: format!("RTX-{:04}", finding_id),
                    title: format!("{} - {}", result.control_name, result.test_name),
                    severity: result.risk_level.clone(),
                    category: result.control_name.clone(),
                    description: result.description.clone(),
                    attack_vector: "Security Control Failure".to_string(),
                    impact: format!(
                        "Expected: {} | Actual: {}",
                        result.expected_behavior, result.actual_behavior
                    ),
                    evidence: result.evidence.clone(),
                    remediation: result.remediation.clone().unwrap_or_default(),
                    cve_references: Vec::new(), // Would map to relevant CVEs
                    owasp_mapping: self.map_to_owasp(&result.control_name),
                };

                findings.push(finding);
                finding_id += 1;
            }
        }

        // Convert successful attacks to detailed findings
        for scenario in &self.scenarios {
            if scenario.attacks_successful > 0 {
                let finding = DetailedFinding {
                    id: format!("RTX-{:04}", finding_id),
                    title: format!("Successful Attack: {}", scenario.scenario_name),
                    severity: RiskLevel::High,
                    category: "Attack Success".to_string(),
                    description: format!(
                        "Attack scenario '{}' succeeded {} times",
                        scenario.scenario_name, scenario.attacks_successful
                    ),
                    attack_vector: scenario.scenario_name.clone(),
                    impact: format!(
                        "Security controls failed to prevent {} attacks",
                        scenario.attacks_successful
                    ),
                    evidence: scenario.key_findings.clone(),
                    remediation: "Strengthen security controls and detection capabilities"
                        .to_string(),
                    cve_references: Vec::new(),
                    owasp_mapping: self.map_scenario_to_owasp(&scenario.scenario_name),
                };

                findings.push(finding);
                finding_id += 1;
            }
        }

        findings
    }

    fn extract_key_findings(&self, data: &HashMap<String, serde_json::Value>) -> Vec<String> {
        let mut findings = Vec::new();

        // Extract key information from scenario data
        if let Some(vulnerabilities) = data.get("vulnerabilities_found") {
            if let Some(vulns) = vulnerabilities.as_array() {
                for vuln in vulns {
                    if let Some(vuln_str) = vuln.as_str() {
                        findings.push(vuln_str.to_string());
                    }
                }
            }
        }

        if let Some(bypass_attempts) = data.get("bypass_attempts") {
            if let Some(attempts) = bypass_attempts.as_array() {
                for attempt in attempts {
                    if let Some(attempt_str) = attempt.as_str() {
                        findings.push(attempt_str.to_string());
                    }
                }
            }
        }

        if let Some(credentials) = data.get("found_credentials") {
            if let Some(creds) = credentials.as_array() {
                for cred in creds {
                    if let Some(cred_str) = cred.as_str() {
                        findings.push(format!("Credential found: {}", cred_str));
                    }
                }
            }
        }

        findings
    }

    fn map_to_owasp(&self, control_name: &str) -> Vec<String> {
        match control_name {
            "IDOR Protection" => vec!["A01:2021-Broken Access Control".to_string()],
            "TOTP Replay Prevention" => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            "PKCE Downgrade Protection" => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            "Rate Limiting" => vec!["A04:2021-Insecure Design".to_string()],
            "Input Validation" => vec!["A03:2021-Injection".to_string()],
            "Session Management" => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            _ => vec!["A04:2021-Insecure Design".to_string()],
        }
    }

    fn map_scenario_to_owasp(&self, scenario_name: &str) -> Vec<String> {
        match scenario_name {
            name if name.contains("authentication") => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            name if name.contains("idor") => vec!["A01:2021-Broken Access Control".to_string()],
            name if name.contains("mfa") => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            name if name.contains("oauth") => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            name if name.contains("session") => {
                vec!["A07:2021-Identification and Authentication Failures".to_string()]
            }
            name if name.contains("rate") => vec!["A04:2021-Insecure Design".to_string()],
            name if name.contains("token") => vec!["A02:2021-Cryptographic Failures".to_string()],
            _ => vec!["A04:2021-Insecure Design".to_string()],
        }
    }
}

impl RedTeamReport {
    pub async fn save_to_file(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(path, json).await?;
        info!("Report saved to: {}", path);
        Ok(())
    }

    pub fn print_summary(&self) {
        println!("\n{}", "🎯 RED TEAM EXERCISE SUMMARY".blue().bold());
        println!("{}", "=".repeat(50).blue());

        // Executive Summary
        println!("\n{}", "📊 Executive Summary".yellow().bold());
        let posture_color = match self.executive_summary.overall_security_posture {
            SecurityPosture::Excellent => "green",
            SecurityPosture::Good => "green",
            SecurityPosture::Fair => "yellow",
            SecurityPosture::Poor => "red",
            SecurityPosture::Critical => "red",
        };
        println!(
            "Security Posture: {}",
            format!("{:?}", self.executive_summary.overall_security_posture)
                .color(posture_color)
                .bold()
        );
        println!("Attack Success Rate: {:.1}%", self.executive_summary.attack_success_rate * 100.0);
        println!("Detection Rate: {:.1}%", self.executive_summary.detection_rate * 100.0);

        // Findings Summary
        println!("\n{}", "🔍 Findings Summary".yellow().bold());
        let mut table = Table::new("{:<} {:<} {:<}");
        table.add_row(Row::new().with_cell("Severity").with_cell("Count").with_cell("Status"));
        table.add_row(Row::new().with_cell("--------").with_cell("-----").with_cell("------"));

        if self.executive_summary.critical_findings > 0 {
            table.add_row(
                Row::new()
                    .with_cell("Critical")
                    .with_cell(self.executive_summary.critical_findings)
                    .with_cell("🚨 IMMEDIATE ACTION REQUIRED"),
            );
        }
        if self.executive_summary.high_findings > 0 {
            table.add_row(
                Row::new()
                    .with_cell("High")
                    .with_cell(self.executive_summary.high_findings)
                    .with_cell("⚠️  High Priority"),
            );
        }
        if self.executive_summary.medium_findings > 0 {
            table.add_row(
                Row::new()
                    .with_cell("Medium")
                    .with_cell(self.executive_summary.medium_findings)
                    .with_cell("📋 Medium Priority"),
            );
        }
        if self.executive_summary.low_findings > 0 {
            table.add_row(
                Row::new()
                    .with_cell("Low")
                    .with_cell(self.executive_summary.low_findings)
                    .with_cell("ℹ️  Low Priority"),
            );
        }

        print!("{}", table);

        // Security Controls
        println!("\n{}", "🛡️  Security Controls".yellow().bold());
        println!(
            "Controls Passing: {} ✅",
            self.executive_summary.controls_passing.to_string().green()
        );
        println!(
            "Controls Failing: {} ❌",
            self.executive_summary.controls_failing.to_string().red()
        );

        // Top Recommendations
        println!("\n{}", "💡 Top Recommendations".yellow().bold());
        let critical_recommendations: Vec<_> = self
            .recommendations
            .iter()
            .filter(|r| matches!(r.priority, Priority::Critical))
            .take(3)
            .collect();

        if critical_recommendations.is_empty() {
            let high_recommendations: Vec<_> = self
                .recommendations
                .iter()
                .filter(|r| matches!(r.priority, Priority::High))
                .take(3)
                .collect();

            for (i, rec) in high_recommendations.iter().enumerate() {
                println!("{}. {} - {}", i + 1, rec.title.yellow(), rec.category);
            }
        } else {
            for (i, rec) in critical_recommendations.iter().enumerate() {
                println!("{}. {} - {}", i + 1, rec.title.red().bold(), rec.category);
            }
        }

        // Exercise Metadata
        println!("\n{}", "📈 Exercise Details".yellow().bold());
        println!("Duration: {:?}", self.exercise_metadata.exercise_duration);
        println!("Scenarios Executed: {}", self.exercise_metadata.scenarios_executed);
        println!("Controls Validated: {}", self.exercise_metadata.controls_validated);
        println!("Target: {}", self.exercise_metadata.target_url);

        println!(
            "\n{}",
            "📋 For detailed findings and remediation steps, see the full JSON report.".cyan()
        );
    }
}

impl Default for RedTeamReporter {
    fn default() -> Self {
        Self::new()
    }
}
