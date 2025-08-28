use crate::mfa::{
    adaptive::{AdaptiveMfaPolicy, AdaptiveSecurityConfig, AuthContext},
    audit::{MfaAuditor, MfaAuditEvent},
    crypto::SecretManager,
    errors::{MfaError, MfaResult},
    rate_limiting::{MfaRateLimiter, RateLimitConfig},
    replay_protection::ReplayProtection,
    storage::{MfaStorage, TotpConfiguration},
    totp_enhanced::{EnhancedTotpConfig, EnhancedTotpGenerator, TotpAlgorithm},
    webauthn::WebAuthnMfa,
};
use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{event, Level};

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpRegistrationRequest {
    pub user_id: String,
    pub display_name: String,
    pub security_level: Option<SecurityLevel>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpRegistrationResponse {
    pub secret_base32: String,
    pub otpauth_url: String,
    pub backup_codes: Vec<String>,
    pub qr_code_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpVerificationRequest {
    pub user_id: String,
    pub code: String,
    pub remember_device: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpVerificationResponse {
    pub verified: bool,
    pub reason: Option<String>,
    pub session_timeout: Option<u64>,
    pub requires_step_up: bool,
    pub backup_codes_remaining: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupCodeGenerationRequest {
    pub user_id: String,
    pub replace_existing: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupCodeGenerationResponse {
    pub codes: Vec<String>,
    pub generated_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SecurityLevel {
    Standard,
    High,
    Maximum,
}

impl SecurityLevel {
    fn to_totp_config(&self) -> EnhancedTotpConfig {
        match self {
            SecurityLevel::Standard => EnhancedTotpConfig::default(),
            SecurityLevel::High => EnhancedTotpConfig::new(
                TotpAlgorithm::SHA512,
                8,
                30,
                1,
                "auth-service".to_string(),
            ).unwrap(),
            SecurityLevel::Maximum => EnhancedTotpConfig::new(
                TotpAlgorithm::SHA512,
                8,
                15,
                0,
                "auth-service".to_string(),
            ).unwrap(),
        }
    }
}

pub struct HighPerformanceMfaService {
    storage: Arc<MfaStorage>,
    secret_manager: Arc<SecretManager>,
    rate_limiter: Arc<MfaRateLimiter>,
    replay_protection: Arc<ReplayProtection>,
    adaptive_policy: Arc<AdaptiveMfaPolicy>,
    webauthn: Arc<WebAuthnMfa>,
    auditor: Arc<MfaAuditor>,
    cache: Arc<MfaCache>,
    metrics: Arc<MfaMetrics>,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl HighPerformanceMfaService {
    pub async fn new() -> MfaResult<Self> {
        let secret_manager = Arc::new(SecretManager::from_env()?);
        let storage = Arc::new(MfaStorage::new((*secret_manager).clone()).await);
        let rate_limiter = Arc::new(MfaRateLimiter::with_defaults().await);
        let replay_protection = Arc::new(ReplayProtection::new().await);
        let adaptive_policy = Arc::new(AdaptiveMfaPolicy::new(AdaptiveSecurityConfig::default()));
        let webauthn = Arc::new(WebAuthnMfa::new(
            std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Auth Service".to_string()),
            std::env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".to_string()),
        ).await);
        let auditor = Arc::new(MfaAuditor::new());
        let cache = Arc::new(MfaCache::new().await);
        let metrics = Arc::new(MfaMetrics::new());
        let circuit_breaker = Arc::new(CircuitBreaker::new());

        Ok(Self {
            storage,
            secret_manager,
            rate_limiter,
            replay_protection,
            adaptive_policy,
            webauthn,
            auditor,
            cache,
            metrics,
            circuit_breaker,
        })
    }

    pub async fn register_totp(&self, request: TotpRegistrationRequest, context: AuthContext) -> MfaResult<TotpRegistrationResponse> {
        // Start performance monitoring
        let _timer = self.metrics.start_timer("totp_registration");

        // Rate limiting check
        let rate_limit_result = self.rate_limiter.check_registration_attempts(&request.user_id).await?;
        if !rate_limit_operation_result.allowed {
            let audit_event = MfaAuditEvent::rate_limit_exceeded(request.user_id.clone(), crate::mfa::audit::MfaMethod::TOTP)
                .with_context("operation".to_string(), serde_json::Value::String("registration".to_string()));
            self.auditor.log_mfa_event(audit_event).await?;

            return Err(MfaError::rate_limit_exceeded(
                "registration",
                rate_limit_operation_result.retry_after_secs.unwrap_or(3600),
                rate_limit_operation_result.remaining_attempts,
            ));
        }

        // Adaptive security assessment
        let mfa_requirements = self.adaptive_policy.evaluate_mfa_requirements(&context).await?;
        let totp_config = request.security_level
            .map(|level| level.to_totp_config())
            .unwrap_or(mfa_requirements.totp_config);

        // Generate secure secret
        let secret = EnhancedTotpGenerator::generate_secret();
        EnhancedTotpGenerator::validate_secret(&secret)?;

        // Create and store MFA user record
        let totp_storage_config = TotpConfiguration {
            algorithm: totp_config.algorithm.as_str().to_string(),
            digits: totp_config.digits,
            period: totp_config.period,
            skew_tolerance: totp_config.skew_tolerance,
        };

        let user_record = self.storage.create_user_mfa(&request.user_id, &secret, Some(totp_storage_config)).await?;

        // Generate backup codes
        let backup_codes = self.generate_backup_codes();
        let hashed_codes = backup_codes.iter()
            .map(|code| self.hash_backup_code(code))
            .collect();
        self.storage.update_backup_codes(&request.user_id, hashed_codes).await?;

        // Generate response data
        let secret_base32 = data_encoding::BASE32.encode(&secret);
        let otpauth_url = totp_config.generate_otpauth_url(&request.display_name, &secret_base32);

        // Generate QR code URL (optional)
        let qr_code_url = self.generate_qr_code_url(&otpauth_url).await?;

        // Audit logging
        let audit_event = MfaAuditEvent::new(
            crate::mfa::audit::MfaEventType::Registration,
            request.user_id.clone(),
            crate::mfa::audit::MfaMethod::TOTP,
            crate::mfa::audit::MfaResult::Success,
        )
        .with_context("algorithm".to_string(), serde_json::Value::String(totp_config.algorithm.as_str().to_string()))
        .with_context("digits".to_string(), serde_json::Value::Number(totp_config.digits.into()));

        self.auditor.log_mfa_event(audit_event).await?;

        // Update metrics
        self.metrics.increment_counter("totp_registrations_total");

        Ok(TotpRegistrationResponse {
            secret_base32,
            otpauth_url,
            backup_codes,
            qr_code_url,
        })
    }

    pub async fn verify_totp(&self, request: TotpVerificationRequest, context: AuthContext) -> MfaResult<TotpVerificationResponse> {
        // Start performance monitoring
        let _timer = self.metrics.start_timer("totp_verification");

        // Circuit breaker check
        if !self.circuit_breaker.is_closed("totp_verify").await {
            return Err(MfaError::ServiceUnavailable {
                service: "TOTP verification".to_string(),
            });
        }

        // Rate limiting check (fast path)
        let rate_limit_result = self.rate_limiter.check_verification_attempts(&request.user_id).await?;
        if !rate_limit_operation_result.allowed {
            let audit_event = MfaAuditEvent::rate_limit_exceeded(request.user_id.clone(), crate::mfa::audit::MfaMethod::TOTP);
            self.auditor.log_mfa_event(audit_event).await?;

            return Ok(TotpVerificationResponse {
                verified: false,
                reason: Some("rate_limited".to_string()),
                session_timeout: None,
                requires_step_up: false,
                backup_codes_remaining: None,
            });
        }

        // Check if it's a backup code first (fast path)
        if let Ok(backup_code_result) = self.verify_backup_code(&request.user_id, &request.code).await {
            if backup_code_result {
                return self.handle_successful_verification(&request, &context, true).await;
            }
        }

        // Replay protection check (Redis SET NX operation)
        if !self.replay_protection.check_and_mark_used(&request.user_id, &request.code, 90).await? {
            let audit_event = MfaAuditEvent::replay_attempt_detected(request.user_id.clone());
            self.auditor.log_mfa_event(audit_event).await?;

            return Ok(TotpVerificationResponse {
                verified: false,
                reason: Some("code_reused".to_string()),
                session_timeout: None,
                requires_step_up: false,
                backup_codes_remaining: None,
            });
        }

        // Get user's TOTP configuration and secret (with caching)
        let (secret, totp_config) = self.get_user_totp_data(&request.user_id).await?;

        // Create TOTP generator with user's configuration
        let totp_generator = EnhancedTotpGenerator::new(totp_config);

        // Verify TOTP code
        let verification_result = totp_generator.verify_code(&secret, &request.code, None)?;

        if verification_result {
            self.handle_successful_verification(&request, &context, false).await
        } else {
            self.handle_failed_verification(&request, &context).await
        }
    }

    async fn handle_successful_verification(
        &self,
        request: &TotpVerificationRequest,
        context: &AuthContext,
        is_backup_code: bool,
    ) -> MfaResult<TotpVerificationResponse> {
        // Mark user as verified
        self.storage.mark_user_verified(&request.user_id).await?;

        // Determine session timeout based on risk assessment
        let session_timeout = self.adaptive_policy.get_session_timeout(context).await?;

        // Check if step-up authentication is required
        let requires_step_up = self.adaptive_policy.should_require_additional_verification(context).await?;

        // Get backup codes count
        let backup_codes = self.storage.get_backup_codes(&request.user_id).await?;
        let backup_codes_remaining = if is_backup_code {
            Some(backup_codes.len().saturating_sub(1))
        } else {
            Some(backup_codes.len())
        };

        // Audit logging
        let audit_event = if is_backup_code {
            MfaAuditEvent::backup_code_used(request.user_id.clone())
        } else {
            MfaAuditEvent::totp_verification_success(request.user_id.clone())
        }
        .with_context("session_timeout".to_string(), serde_json::Value::Number(session_timeout.as_secs().into()))
        .with_context("requires_step_up".to_string(), serde_json::Value::Bool(requires_step_up));

        self.auditor.log_mfa_event(audit_event).await?;

        // Update metrics
        self.metrics.increment_counter("totp_verifications_success_total");
        if is_backup_code {
            self.metrics.increment_counter("backup_codes_used_total");
        }

        // Record successful authentication for future risk assessment
        self.record_successful_auth(&request.user_id, context).await?;

        Ok(TotpVerificationResponse {
            verified: true,
            reason: None,
            session_timeout: Some(session_timeout.as_secs()),
            requires_step_up,
            backup_codes_remaining,
        })
    }

    async fn handle_failed_verification(
        &self,
        request: &TotpVerificationRequest,
        context: &AuthContext,
    ) -> MfaResult<TotpVerificationResponse> {
        // Audit logging
        let audit_event = MfaAuditEvent::totp_verification_failure(request.user_id.clone())
            .with_context("code_length".to_string(), serde_json::Value::Number(request.code.len().into()));

        self.auditor.log_mfa_event(audit_event).await?;

        // Update metrics
        self.metrics.increment_counter("totp_verifications_failure_total");

        // Record failed attempt for risk assessment
        self.record_failed_auth(&request.user_id, context).await?;

        // Update circuit breaker
        self.circuit_breaker.record_failure("totp_verify").await;

        Ok(TotpVerificationResponse {
            verified: false,
            reason: Some("invalid_code".to_string()),
            session_timeout: None,
            requires_step_up: false,
            backup_codes_remaining: None,
        })
    }

    pub async fn generate_backup_codes_endpoint(&self, request: BackupCodeGenerationRequest) -> MfaResult<BackupCodeGenerationResponse> {
        let _timer = self.metrics.start_timer("backup_code_generation");

        // Check rate limiting
        let rate_limit_result = self.rate_limiter.check_backup_code_attempts(&request.user_id).await?;
        if !rate_limit_operation_result.allowed {
            return Err(MfaError::rate_limit_exceeded(
                "backup_code_generation",
                rate_limit_operation_result.retry_after_secs.unwrap_or(3600),
                rate_limit_operation_result.remaining_attempts,
            ));
        }

        // Generate new backup codes
        let backup_codes = self.generate_backup_codes();
        let hashed_codes = backup_codes.iter()
            .map(|code| self.hash_backup_code(code))
            .collect();

        // Store backup codes
        self.storage.update_backup_codes(&request.user_id, hashed_codes).await?;

        let generated_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expires_at = if let Ok(ttl_str) = std::env::var("MFA_BACKUP_CODE_TTL_SECS") {
            ttl_str.parse::<u64>().ok().map(|ttl| generated_at + ttl)
        } else {
            None
        };

        // Audit logging
        let audit_event = MfaAuditEvent::new(
            crate::mfa::audit::MfaEventType::BackupCodeGeneration,
            request.user_id.clone(),
            crate::mfa::audit::MfaMethod::BackupCode,
            crate::mfa::audit::MfaResult::Success,
        )
        .with_context("codes_count".to_string(), serde_json::Value::Number(backup_codes.len().into()))
        .with_context("replace_existing".to_string(), serde_json::Value::Bool(request.replace_existing));

        self.auditor.log_mfa_event(audit_event).await?;

        // Update metrics
        self.metrics.increment_counter("backup_codes_generated_total");

        Ok(BackupCodeGenerationResponse {
            codes: backup_codes,
            generated_at,
            expires_at,
        })
    }

    // Helper methods
    async fn get_user_totp_data(&self, user_id: &str) -> MfaResult<(Vec<u8>, EnhancedTotpConfig)> {
        // Try cache first
        if let Some(cached_data) = self.cache.get_totp_data(user_id).await? {
            return Ok(cached_data);
        }

        // Fetch from storage
        let secret = self.storage.get_decrypted_secret(user_id).await?;
        let totp_config_storage = self.storage.get_totp_config(user_id).await?;

        let enhanced_config = EnhancedTotpConfig::new(
            TotpAlgorithm::from_str(&totp_config_storage.algorithm)?,
            totp_config_storage.digits,
            totp_config_storage.period,
            totp_config_storage.skew_tolerance,
            std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "auth-service".to_string()),
        )?;

        let data = (secret, enhanced_config);

        // Cache the result
        self.cache.set_totp_data(user_id, &data).await?;

        Ok(data)
    }

    async fn verify_backup_code(&self, user_id: &str, code: &str) -> MfaResult<bool> {
        let stored_codes = self.storage.get_backup_codes(user_id).await?;

        for stored_hash in &stored_codes {
            if self.verify_backup_code_hash(code, stored_hash) {
                // Remove the used backup code
                let mut updated_codes = stored_codes.clone();
                updated_codes.remove(stored_hash);
                self.storage.update_backup_codes(user_id, updated_codes).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn generate_backup_codes(&self) -> Vec<String> {
        let mut codes = Vec::new();
        let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No ambiguous characters

        for _ in 0..8 {
            let mut code = String::new();
            for _ in 0..10 {
                let mut byte = [0u8; 1];
                use rand::rngs::OsRng;
                OsRng.fill_bytes(&mut byte);
                let char_index = byte[0] as usize % alphabet.len();
                code.push(alphabet[char_index] as char);
            }
            codes.push(code);
        }

        codes
    }

    fn hash_backup_code(&self, code: &str) -> String {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::{rand_core::OsRng, SaltString};

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2.hash_password(code.as_bytes(), &salt)
            .expect("Failed to hash backup code")
            .to_string()
    }

    fn verify_backup_code_hash(&self, code: &str, hash: &str) -> bool {
        use argon2::{Argon2, PasswordHash, PasswordVerifier};

        if let Ok(parsed_hash) = PasswordHash::new(hash) {
            let argon2 = Argon2::default();
            argon2.verify_password(code.as_bytes(), &parsed_hash).is_ok()
        } else {
            false
        }
    }

    async fn generate_qr_code_url(&self, otpauth_url: &str) -> MfaResult<Option<String>> {
        // In a real implementation, you might generate QR codes using a service
        // For now, return a URL that can be used by the frontend
        let encoded_url = urlencoding::encode(otpauth_url);
        Ok(Some(format!("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={}", encoded_url)))
    }

    async fn record_successful_auth(&self, user_id: &str, context: &AuthContext) -> MfaResult<()> {
        // Record authentication data for future risk assessment
        // This would update user patterns in Redis
        Ok(())
    }

    async fn record_failed_auth(&self, user_id: &str, context: &AuthContext) -> MfaResult<()> {
        // Record failed authentication for risk assessment
        // This would update failure patterns and potentially trigger alerts
        Ok(())
    }

    pub async fn health_check(&self) -> MfaResult<HealthStatus> {
        let storage_health = self.storage.health_check().await?;
        let cache_health = self.cache.health_check().await;
        let circuit_breaker_status = self.circuit_breaker.get_status().await;

        Ok(HealthStatus {
            storage_available: storage_health.redis_available,
            cache_available: cache_health.is_ok(),
            circuit_breaker_closed: circuit_breaker_status.is_closed,
            total_users: storage_health.total_users,
        })
    }
}

// Supporting structures
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub storage_available: bool,
    pub cache_available: bool,
    pub circuit_breaker_closed: bool,
    pub total_users: usize,
}

// Mock implementations for supporting components
pub struct MfaCache {
    // In reality, this would use Redis or another caching layer
}

impl MfaCache {
    pub async fn new() -> Self {
        Self {}
    }

    pub async fn get_totp_data(&self, _user_id: &str) -> MfaResult<Option<(Vec<u8>, EnhancedTotpConfig)>> {
        // Mock implementation
        Ok(None)
    }

    pub async fn set_totp_data(&self, _user_id: &str, _data: &(Vec<u8>, EnhancedTotpConfig)) -> MfaResult<()> {
        // Mock implementation
        Ok(())
    }

    pub async fn health_check(&self) -> Result<(), ()> {
        Ok(())
    }
}

pub struct MfaMetrics {
    // In reality, this would integrate with Prometheus/metrics
}

impl MfaMetrics {
    pub fn new() -> Self {
        Self {}
    }

    pub fn start_timer(&self, _operation: &str) -> MetricsTimer {
        MetricsTimer::new()
    }

    pub fn increment_counter(&self, _counter: &str) {
        // Mock implementation
    }
}

pub struct MetricsTimer {
    start_time: SystemTime,
}

impl MetricsTimer {
    fn new() -> Self {
        Self {
            start_time: SystemTime::now(),
        }
    }
}

impl Drop for MetricsTimer {
    fn drop(&mut self) {
        let _duration = self.start_time.elapsed().unwrap_or(Duration::from_secs(0));
        // Record timing metric
    }
}

pub struct CircuitBreaker {
    // Mock circuit breaker implementation
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn is_closed(&self, _service: &str) -> bool {
        true // Always closed for mock
    }

    pub async fn record_failure(&self, _service: &str) {
        // Mock implementation
    }

    pub async fn get_status(&self) -> CircuitBreakerStatus {
        CircuitBreakerStatus { is_closed: true }
    }
}

pub struct CircuitBreakerStatus {
    pub is_closed: bool,
}

// Helper function to extract AuthContext from HTTP request
pub fn extract_auth_context(headers: &HeaderMap, user_id: String) -> AuthContext {
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|ip_str| ip_str.parse::<IpAddr>().ok());

    let user_agent = headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    AuthContext {
        user_id,
        ip_address,
        user_agent,
        device_fingerprint: None, // Would be extracted from headers or session
        geolocation: None,        // Would be resolved from IP
        session_id: None,         // Would be extracted from session
        previous_auth_time: None, // Would be retrieved from storage
        failed_attempts_last_hour: 0, // Would be retrieved from storage
        is_new_device: false,     // Would be determined from device tracking
        is_vpn_or_proxy: false,   // Would be determined from IP analysis
        time_since_last_password_change: None, // Would be retrieved from user store
        account_age_days: 30,     // Would be calculated from user creation date
        is_privileged_user: false, // Would be determined from user roles
        current_time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backup_code_generation() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let codes = service.generate_backup_codes();

        assert_eq!(codes.len(), 8);
        for code in &codes {
            assert_eq!(code.len(), 10);
            assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
        }

        // Ensure codes are unique
        let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique_codes.len(), codes.len());
    }

    #[tokio::test]
    async fn test_backup_code_hashing() {
        let service = HighPerformanceMfaService::new().await.unwrap();
        let code = "ABCD123456";

        let hash1 = service.hash_backup_code(code);
        let hash2 = service.hash_backup_code(code);

        // Hashes should be different due to salt
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(service.verify_backup_code_hash(code, &hash1));
        assert!(service.verify_backup_code_hash(code, &hash2));

        // Wrong code should not verify
        assert!(!service.verify_backup_code_hash("WRONG12345", &hash1));
    }
}