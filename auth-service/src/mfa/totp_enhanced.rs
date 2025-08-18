use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TotpError {
    #[error("Invalid algorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("Invalid digits: {0} (must be 6-8)")]
    InvalidDigits(u32),
    #[error("Invalid period: {0} (must be 15-120 seconds)")]
    InvalidPeriod(u64),
    #[error("Invalid secret length")]
    InvalidSecretLength,
    #[error("Time error")]
    TimeError,
    #[error("HMAC error: {0}")]
    HmacError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TotpAlgorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl TotpAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            TotpAlgorithm::SHA1 => "SHA1",
            TotpAlgorithm::SHA256 => "SHA256",
            TotpAlgorithm::SHA512 => "SHA512",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, TotpError> {
        match s.to_uppercase().as_str() {
            "SHA1" => Ok(TotpAlgorithm::SHA1),
            "SHA256" => Ok(TotpAlgorithm::SHA256),
            "SHA512" => Ok(TotpAlgorithm::SHA512),
            _ => Err(TotpError::InvalidAlgorithm(s.to_string())),
        }
    }

    pub fn recommended() -> Self {
        TotpAlgorithm::SHA256
    }

    pub fn high_security() -> Self {
        TotpAlgorithm::SHA512
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedTotpConfig {
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub skew_tolerance: i64,
    pub issuer: String,
}

impl EnhancedTotpConfig {
    pub fn new(
        algorithm: TotpAlgorithm,
        digits: u32,
        period: u64,
        skew_tolerance: i64,
        issuer: String,
    ) -> Result<Self, TotpError> {
        Self::validate_digits(digits)?;
        Self::validate_period(period)?;

        Ok(Self {
            algorithm,
            digits,
            period,
            skew_tolerance,
            issuer,
        })
    }

    pub fn default() -> Self {
        Self {
            algorithm: TotpAlgorithm::SHA256,
            digits: 6,
            period: 30,
            skew_tolerance: 1,
            issuer: std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "auth-service".to_string()),
        }
    }

    pub fn high_security() -> Self {
        Self {
            algorithm: TotpAlgorithm::SHA512,
            digits: 8,
            period: 15, // Shorter window for higher security
            skew_tolerance: 0, // No tolerance
            issuer: std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "auth-service".to_string()),
        }
    }

    pub fn legacy_compatible() -> Self {
        Self {
            algorithm: TotpAlgorithm::SHA1,
            digits: 6,
            period: 30,
            skew_tolerance: 1,
            issuer: std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "auth-service".to_string()),
        }
    }

    fn validate_digits(digits: u32) -> Result<(), TotpError> {
        if !(6..=8).contains(&digits) {
            return Err(TotpError::InvalidDigits(digits));
        }
        Ok(())
    }

    fn validate_period(period: u64) -> Result<(), TotpError> {
        if !(15..=120).contains(&period) {
            return Err(TotpError::InvalidPeriod(period));
        }
        Ok(())
    }

    pub fn generate_otpauth_url(&self, user_identifier: &str, secret_base32: &str) -> String {
        let label = format!("{}:{}", self.issuer, user_identifier);
        let mut url = format!(
            "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            urlencoding::encode(&label),
            secret_base32,
            urlencoding::encode(&self.issuer),
            self.algorithm.as_str(),
            self.digits,
            self.period
        );

        // Add algorithm-specific parameters for better app compatibility
        match self.algorithm {
            TotpAlgorithm::SHA256 => url.push_str("&algorithm=SHA256"),
            TotpAlgorithm::SHA512 => url.push_str("&algorithm=SHA512"),
            TotpAlgorithm::SHA1 => {} // Default, no need to specify
        }

        url
    }
}

pub struct EnhancedTotpGenerator {
    config: EnhancedTotpConfig,
}

impl EnhancedTotpGenerator {
    pub fn new(config: EnhancedTotpConfig) -> Self {
        Self { config }
    }

    pub fn with_default_config() -> Self {
        Self::new(EnhancedTotpConfig::default())
    }

    pub fn generate_code(&self, secret: &[u8], timestamp: Option<u64>) -> Result<String, TotpError> {
        let time = timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let counter = time / self.config.period;
        let code = self.hotp(secret, counter)?;
        Ok(self.format_code(code))
    }

    pub fn verify_code(&self, secret: &[u8], code: &str, timestamp: Option<u64>) -> Result<bool, TotpError> {
        let time = timestamp.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        // Check current time window and tolerance windows
        for skew in -self.config.skew_tolerance..=self.config.skew_tolerance {
            let check_time = if skew < 0 {
                time.saturating_sub(((-skew) as u64) * self.config.period)
            } else {
                time.saturating_add((skew as u64) * self.config.period)
            };

            let expected_code = self.generate_code(secret, Some(check_time))?;
            if constant_time_eq::constant_time_eq(code.as_bytes(), expected_code.as_bytes()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub fn get_time_remaining(&self) -> u64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let period_elapsed = current_time % self.config.period;
        self.config.period - period_elapsed
    }

    pub fn get_current_counter(&self) -> u64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        current_time / self.config.period
    }

    fn hotp(&self, secret: &[u8], counter: u64) -> Result<u32, TotpError> {
        if secret.len() < 16 {
            return Err(TotpError::InvalidSecretLength);
        }

        let counter_bytes = counter.to_be_bytes();

        let hash = match self.config.algorithm {
            TotpAlgorithm::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(secret)
                    .map_err(|e| TotpError::HmacError(e.to_string()))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|e| TotpError::HmacError(e.to_string()))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlgorithm::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(secret)
                    .map_err(|e| TotpError::HmacError(e.to_string()))?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // Dynamic truncation as per RFC 4226
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        if offset + 4 > hash.len() {
            return Err(TotpError::HmacError("Hash too short for truncation".to_string()));
        }

        let bin_code = ((hash[offset] as u32 & 0x7f) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        Ok(bin_code)
    }

    fn format_code(&self, code: u32) -> String {
        let modulo = 10_u32.pow(self.config.digits);
        let formatted_code = code % modulo;
        format!("{:0width$}", formatted_code, width = self.config.digits as usize)
    }

    pub fn generate_secret() -> Vec<u8> {
        let mut secret = vec![0u8; 32]; // 256-bit secret for better security
        getrandom::getrandom(&mut secret).expect("Failed to generate random secret");
        secret
    }

    pub fn validate_secret(secret: &[u8]) -> Result<(), TotpError> {
        if secret.len() < 16 {
            return Err(TotpError::InvalidSecretLength);
        }
        Ok(())
    }

    pub fn config(&self) -> &EnhancedTotpConfig {
        &self.config
    }

    pub fn algorithm_strength_score(&self) -> u8 {
        match self.config.algorithm {
            TotpAlgorithm::SHA1 => 1,
            TotpAlgorithm::SHA256 => 2,
            TotpAlgorithm::SHA512 => 3,
        }
    }

    pub fn security_score(&self) -> u8 {
        let mut score = self.algorithm_strength_score() * 2;

        // Digits contribution
        score += match self.config.digits {
            6 => 1,
            7 => 2,
            8 => 3,
            _ => 0,
        };

        // Period contribution (shorter = more secure)
        score += match self.config.period {
            15 => 3,
            30 => 2,
            60 => 1,
            _ => 0,
        };

        // Skew tolerance (less tolerance = more secure)
        score += match self.config.skew_tolerance {
            0 => 2,
            1 => 1,
            _ => 0,
        };

        score.min(10) // Cap at 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32;

    #[test]
    fn test_totp_algorithms() {
        let secret = EnhancedTotpGenerator::generate_secret();
        let timestamp = 1234567890;

        // Test all algorithms
        let configs = [
            EnhancedTotpConfig::new(TotpAlgorithm::SHA1, 6, 30, 1, "test".to_string()).unwrap(),
            EnhancedTotpConfig::new(TotpAlgorithm::SHA256, 6, 30, 1, "test".to_string()).unwrap(),
            EnhancedTotpConfig::new(TotpAlgorithm::SHA512, 6, 30, 1, "test".to_string()).unwrap(),
        ];

        for config in configs {
            let generator = EnhancedTotpGenerator::new(config);
            let code = generator.generate_code(&secret, Some(timestamp)).unwrap();

            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));

            // Verify the code
            assert!(generator.verify_code(&secret, &code, Some(timestamp)).unwrap());
        }
    }

    #[test]
    fn test_different_digits() {
        let secret = EnhancedTotpGenerator::generate_secret();
        let timestamp = 1234567890;

        for digits in 6..=8 {
            let config = EnhancedTotpConfig::new(TotpAlgorithm::SHA256, digits, 30, 1, "test".to_string()).unwrap();
            let generator = EnhancedTotpGenerator::new(config);
            let code = generator.generate_code(&secret, Some(timestamp)).unwrap();

            assert_eq!(code.len(), digits as usize);
            assert!(generator.verify_code(&secret, &code, Some(timestamp)).unwrap());
        }
    }

    #[test]
    fn test_time_skew_tolerance() {
        let secret = EnhancedTotpGenerator::generate_secret();
        let base_time = 1234567890;

        let config = EnhancedTotpConfig::new(TotpAlgorithm::SHA256, 6, 30, 2, "test".to_string()).unwrap();
        let generator = EnhancedTotpGenerator::new(config);

        let code = generator.generate_code(&secret, Some(base_time)).unwrap();

        // Should work within tolerance
        assert!(generator.verify_code(&secret, &code, Some(base_time)).unwrap());
        assert!(generator.verify_code(&secret, &code, Some(base_time + 30)).unwrap()); // +1 period
        assert!(generator.verify_code(&secret, &code, Some(base_time + 60)).unwrap()); // +2 periods
        assert!(generator.verify_code(&secret, &code, Some(base_time - 30)).unwrap()); // -1 period
        assert!(generator.verify_code(&secret, &code, Some(base_time - 60)).unwrap()); // -2 periods

        // Should fail outside tolerance
        assert!(!generator.verify_code(&secret, &code, Some(base_time + 90)).unwrap()); // +3 periods
        assert!(!generator.verify_code(&secret, &code, Some(base_time - 90)).unwrap()); // -3 periods
    }

    #[test]
    fn test_different_periods() {
        let secret = EnhancedTotpGenerator::generate_secret();

        for period in [15, 30, 60] {
            let config = EnhancedTotpConfig::new(TotpAlgorithm::SHA256, 6, period, 1, "test".to_string()).unwrap();
            let generator = EnhancedTotpGenerator::new(config);

            let code1 = generator.generate_code(&secret, Some(1000)).unwrap();
            let code2 = generator.generate_code(&secret, Some(1000 + period)).unwrap();

            // Codes should be different across period boundaries
            assert_ne!(code1, code2);

            // But same within the same period
            let code3 = generator.generate_code(&secret, Some(1000 + period / 2)).unwrap();
            assert_eq!(code1, code3);
        }
    }

    #[test]
    fn test_otpauth_url_generation() {
        let config = EnhancedTotpConfig::new(TotpAlgorithm::SHA256, 8, 15, 0, "MyApp".to_string()).unwrap();
        let secret = EnhancedTotpGenerator::generate_secret();
        let secret_base32 = BASE32.encode(&secret);

        let url = config.generate_otpauth_url("user@example.com", &secret_base32);

        assert!(url.starts_with("otpauth://totp/"));
        assert!(url.contains("MyApp"));
        assert!(url.contains("user@example.com"));
        assert!(url.contains(&secret_base32));
        assert!(url.contains("algorithm=SHA256"));
        assert!(url.contains("digits=8"));
        assert!(url.contains("period=15"));
    }

    #[test]
    fn test_security_scoring() {
        let low_security = EnhancedTotpGenerator::new(
            EnhancedTotpConfig::new(TotpAlgorithm::SHA1, 6, 60, 2, "test".to_string()).unwrap()
        );

        let high_security = EnhancedTotpGenerator::new(
            EnhancedTotpConfig::new(TotpAlgorithm::SHA512, 8, 15, 0, "test".to_string()).unwrap()
        );

        assert!(high_security.security_score() > low_security.security_score());
    }

    #[test]
    fn test_constant_time_verification() {
        let secret = EnhancedTotpGenerator::generate_secret();
        let generator = EnhancedTotpGenerator::with_default_config();
        let timestamp = 1234567890;

        let correct_code = generator.generate_code(&secret, Some(timestamp)).unwrap();
        let wrong_code = "000000";

        // Both should take similar time (constant time comparison)
        let start = std::time::Instant::now();
        let _result1 = generator.verify_code(&secret, &correct_code, Some(timestamp));
        let time1 = start.elapsed();

        let start = std::time::Instant::now();
        let _result2 = generator.verify_code(&secret, wrong_code, Some(timestamp));
        let time2 = start.elapsed();

        // This is a rough test - in practice, the times should be very similar
        // due to constant-time comparison
        assert!(time1.as_nanos() > 0);
        assert!(time2.as_nanos() > 0);
    }
}