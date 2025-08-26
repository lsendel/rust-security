use crate::attack_framework::RedTeamFramework;
use crate::reporting::RedTeamReporter;
use crate::scenarios::mfa_bypass::types::*;
use crate::scenarios::mfa_bypass::config::MfaBypassConfig;
use crate::scenarios::mfa_bypass::totp::TotpAttackEngine;
use anyhow::Result;
use std::time::SystemTime;
use tracing::{info, warn};

/// Main coordinator for MFA bypass attack scenarios
pub struct MfaBypassCoordinator {
    config: MfaBypassConfig,
    totp_engine: TotpAttackEngine,
    statistics: AttackStatistics,
}

impl MfaBypassCoordinator {
    /// Create a new MFA bypass coordinator
    pub fn new(config: MfaBypassConfig) -> Self {
        let totp_engine = TotpAttackEngine::new(config.totp_config.clone());
        
        Self {
            config,
            totp_engine,
            statistics: AttackStatistics {
                total_attacks: 0,
                successful_bypasses: 0,
                failed_attempts: 0,
                vulnerabilities_found: 0,
                average_attack_time: std::time::Duration::from_secs(0),
                attack_success_rate: 0.0,
            },
        }
    }

    /// Run all MFA bypass scenarios
    pub async fn run_all_scenarios(
        &mut self,
        framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
        intensity: AttackIntensity,
    ) -> Result<()> {
        info!("🔐 Starting Comprehensive MFA Bypass Scenarios (Intensity: {:?})", intensity);
        
        let start_time = SystemTime::now();
        let mut results = Vec::new();

        // Scenario 1: TOTP Replay Attack
        info!("📱 Executing TOTP Attack Scenarios");
        match self.totp_engine.totp_replay_attack(framework, reporter).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("TOTP Replay Attack failed: {}", e),
        }

        // Scenario 2: TOTP Brute Force Attack
        match self.totp_engine.totp_brute_force_attack(framework, reporter, &intensity).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("TOTP Brute Force Attack failed: {}", e),
        }

        // Scenario 3: Time Window Exploitation
        match self.totp_engine.time_window_exploitation(framework, reporter).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("Time Window Exploitation failed: {}", e),
        }

        // Scenario 4: Backup Code Enumeration
        info!("🔑 Executing Backup Code Attack Scenarios");
        match self.backup_code_enumeration(framework, reporter, &intensity).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("Backup Code Enumeration failed: {}", e),
        }

        // Scenario 5: MFA Header Bypass
        info!("🌐 Executing Header Manipulation Scenarios");
        match self.mfa_header_bypass(framework, reporter).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("MFA Header Bypass failed: {}", e),
        }

        // Scenario 6: OTP Interception Simulation
        info!("📞 Executing OTP Interception Scenarios");
        match self.otp_interception_simulation(framework, reporter).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("OTP Interception failed: {}", e),
        }

        // Scenario 7: MFA State Confusion
        info!("🔄 Executing State Confusion Scenarios");
        match self.mfa_state_confusion(framework, reporter).await {
            Ok(result) => {
                self.update_statistics(&result);
                results.push(result);
            }
            Err(e) => warn!("MFA State Confusion failed: {}", e),
        }

        // Calculate final statistics
        self.finalize_statistics(start_time, &results);
        
        // Generate comprehensive report
        self.generate_final_report(reporter, &results).await?;

        info!("🏁 MFA Bypass Scenarios completed. Success rate: {:.1}%", 
              self.statistics.attack_success_rate * 100.0);

        Ok(())
    }

    /// Execute backup code enumeration attack (placeholder)
    async fn backup_code_enumeration(
        &self,
        _framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
        _intensity: &AttackIntensity,
    ) -> Result<MfaBypassResult> {
        info!("🔑 Starting Backup Code Enumeration Attack");
        
        // Placeholder implementation - would be extracted from original file
        let result = MfaBypassResult::new(MfaAttackType::BackupCodeEnumeration);
        
        reporter.log_attack_result("Backup Code Enumeration", false, "Not implemented yet").await;
        Ok(result)
    }

    /// Execute MFA header bypass attack (placeholder)
    async fn mfa_header_bypass(
        &self,
        _framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
    ) -> Result<MfaBypassResult> {
        info!("🌐 Starting MFA Header Bypass Attack");
        
        // Placeholder implementation
        let result = MfaBypassResult::new(MfaAttackType::HeaderManipulation);
        
        reporter.log_attack_result("MFA Header Bypass", false, "Not implemented yet").await;
        Ok(result)
    }

    /// Execute OTP interception simulation (placeholder)
    async fn otp_interception_simulation(
        &self,
        _framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
    ) -> Result<MfaBypassResult> {
        info!("📞 Starting OTP Interception Simulation");
        
        // Placeholder implementation
        let result = MfaBypassResult::new(MfaAttackType::OtpInterception);
        
        reporter.log_attack_result("OTP Interception", false, "Not implemented yet").await;
        Ok(result)
    }

    /// Execute MFA state confusion attack (placeholder)
    async fn mfa_state_confusion(
        &self,
        _framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
    ) -> Result<MfaBypassResult> {
        info!("🔄 Starting MFA State Confusion Attack");
        
        // Placeholder implementation
        let result = MfaBypassResult::new(MfaAttackType::StateConfusion);
        
        reporter.log_attack_result("MFA State Confusion", false, "Not implemented yet").await;
        Ok(result)
    }

    /// Update attack statistics
    fn update_statistics(&mut self, result: &MfaBypassResult) {
        self.statistics.total_attacks += 1;
        
        if result.success {
            self.statistics.successful_bypasses += 1;
        } else {
            self.statistics.failed_attempts += 1;
        }

        if result.vulnerability_details.is_some() {
            self.statistics.vulnerabilities_found += 1;
        }

        // Update average attack time
        let current_avg = self.statistics.average_attack_time.as_millis() as f64;
        let new_time = result.time_taken.as_millis() as f64;
        let new_avg = (current_avg * (self.statistics.total_attacks - 1) as f64 + new_time) 
                     / self.statistics.total_attacks as f64;
        
        self.statistics.average_attack_time = std::time::Duration::from_millis(new_avg as u64);
    }

    /// Finalize statistics calculation
    fn finalize_statistics(&mut self, start_time: SystemTime, results: &[MfaBypassResult]) {
        if self.statistics.total_attacks > 0 {
            self.statistics.attack_success_rate = 
                self.statistics.successful_bypasses as f64 / self.statistics.total_attacks as f64;
        }

        info!("📊 Attack Statistics:");
        info!("   Total Attacks: {}", self.statistics.total_attacks);
        info!("   Successful Bypasses: {}", self.statistics.successful_bypasses);
        info!("   Vulnerabilities Found: {}", self.statistics.vulnerabilities_found);
        info!("   Success Rate: {:.1}%", self.statistics.attack_success_rate * 100.0);
        info!("   Average Attack Time: {:.2}s", self.statistics.average_attack_time.as_secs_f64());
    }

    /// Generate comprehensive final report
    async fn generate_final_report(
        &self,
        reporter: &mut RedTeamReporter,
        results: &[MfaBypassResult],
    ) -> Result<()> {
        info!("📋 Generating MFA Bypass Assessment Report");

        // Count vulnerabilities by severity
        let mut critical_vulns = 0;
        let mut high_vulns = 0;
        let mut medium_vulns = 0;
        let mut low_vulns = 0;

        for result in results {
            if let Some(vuln) = &result.vulnerability_details {
                match vuln.severity {
                    SeverityLevel::Critical => critical_vulns += 1,
                    SeverityLevel::High => high_vulns += 1,
                    SeverityLevel::Medium => medium_vulns += 1,
                    SeverityLevel::Low => low_vulns += 1,
                }
            }
        }

        let report_summary = format!(
            "MFA Security Assessment Summary:\n\
             • Total Attack Scenarios: {}\n\
             • Successful Bypasses: {}\n\
             • Critical Vulnerabilities: {}\n\
             • High Vulnerabilities: {}\n\
             • Medium Vulnerabilities: {}\n\
             • Low Vulnerabilities: {}\n\
             • Overall Security Posture: {}",
            self.statistics.total_attacks,
            self.statistics.successful_bypasses,
            critical_vulns,
            high_vulns,
            medium_vulns,
            low_vulns,
            if critical_vulns > 0 { "CRITICAL - Immediate Action Required" }
            else if high_vulns > 0 { "HIGH RISK - Urgent Remediation Needed" }
            else if medium_vulns > 0 { "MEDIUM RISK - Improvements Recommended" }
            else { "GOOD - MFA Implementation Secure" }
        );

        reporter.log_attack_result("MFA Bypass Assessment", true, &report_summary).await;

        Ok(())
    }

    /// Get current attack statistics
    pub fn get_statistics(&self) -> &AttackStatistics {
        &self.statistics
    }

    /// Update configuration at runtime
    pub fn update_config(&mut self, config: MfaBypassConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coordinator_creation() {
        let config = MfaBypassConfig::default();
        let coordinator = MfaBypassCoordinator::new(config);
        assert_eq!(coordinator.statistics.total_attacks, 0);
    }

    #[test]
    fn test_statistics_update() {
        let config = MfaBypassConfig::default();
        let mut coordinator = MfaBypassCoordinator::new(config);
        
        let result = MfaBypassResult::new(MfaAttackType::TotpReplay)
            .with_success(true, Some("Test success".to_string()));
        
        coordinator.update_statistics(&result);
        
        assert_eq!(coordinator.statistics.total_attacks, 1);
        assert_eq!(coordinator.statistics.successful_bypasses, 1);
        assert_eq!(coordinator.statistics.attack_success_rate, 1.0);
    }
}
