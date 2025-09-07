//! Security hardening module
//!
//! Provides comprehensive security hardening configurations and policies
//! for production deployment with enterprise-grade security controls.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Production security hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHardeningConfig {
    /// Network security settings
    pub network: NetworkSecurityConfig,
    
    /// Authentication hardening
    pub authentication: AuthenticationHardeningConfig,
    
    /// Session management hardening
    pub session: SessionHardeningConfig,
    
    /// API security hardening
    pub api: ApiSecurityConfig,
    
    /// Monitoring and alerting
    pub monitoring: MonitoringConfig,
    
    /// Compliance requirements
    pub compliance: ComplianceConfig,
}

/// Network security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Enable TLS 1.3 only
    pub tls_1_3_only: bool,
    
    /// Require perfect forward secrecy
    pub require_pfs: bool,
    
    /// Enable HSTS with preload
    pub hsts_preload: bool,
    
    /// HSTS max age in seconds
    pub hsts_max_age: u64,
    
    /// Enable certificate pinning
    pub cert_pinning: bool,
    
    /// Allowed TLS cipher suites
    pub allowed_ciphers: Vec<String>,
    
    /// Enable OCSP stapling
    pub ocsp_stapling: bool,
    
    /// IP allowlist for admin endpoints
    pub admin_ip_allowlist: Vec<String>,
    
    /// Rate limiting configuration
    pub rate_limiting: RateLimitingHardening,
}

/// Rate limiting hardening
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingHardening {
    /// Global rate limit per IP per minute
    pub global_requests_per_minute: u32,
    
    /// Authentication endpoint rate limit
    pub auth_requests_per_minute: u32,
    
    /// Admin endpoint rate limit
    pub admin_requests_per_minute: u32,
    
    /// API endpoint rate limit
    pub api_requests_per_minute: u32,
    
    /// Enable adaptive rate limiting based on threat score
    pub adaptive_rate_limiting: bool,
    
    /// Ban duration for rate limit violations (seconds)
    pub ban_duration_seconds: u64,
    
    /// Enable distributed rate limiting
    pub distributed_limiting: bool,
}

/// Authentication hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationHardeningConfig {
    /// Require MFA for all accounts
    pub require_mfa_all_accounts: bool,
    
    /// Require MFA for admin accounts
    pub require_mfa_admin: bool,
    
    /// Maximum login attempts before lockout
    pub max_login_attempts: u32,
    
    /// Account lockout duration (seconds)
    pub lockout_duration_seconds: u64,
    
    /// Password policy enforcement
    pub password_policy: PasswordPolicyHardening,
    
    /// JWT security hardening
    pub jwt_hardening: JwtHardeningConfig,
    
    /// OAuth security hardening
    pub oauth_hardening: OAuthHardeningConfig,
    
    /// Enable device fingerprinting
    pub device_fingerprinting: bool,
    
    /// Enable geolocation-based restrictions
    pub geolocation_restrictions: bool,
    
    /// Require hardware security keys for admin
    pub require_hardware_keys_admin: bool,
}

/// Password policy hardening
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicyHardening {
    /// Minimum password length
    pub min_length: u32,
    
    /// Require password complexity
    pub require_complexity: bool,
    
    /// Password history count
    pub password_history_count: u32,
    
    /// Password expiration days (0 = no expiration)
    pub expiration_days: u32,
    
    /// Check against breach databases
    pub check_breach_databases: bool,
    
    /// Prohibit common passwords
    pub prohibit_common_passwords: bool,
    
    /// Require password rotation for privileged accounts
    pub require_privileged_rotation: bool,
}

/// JWT hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHardeningConfig {
    /// Short access token lifetime (seconds)
    pub access_token_lifetime: u64,
    
    /// Refresh token lifetime (seconds)
    pub refresh_token_lifetime: u64,
    
    /// Enable token binding
    pub enable_token_binding: bool,
    
    /// Enable token encryption (JWE)
    pub enable_token_encryption: bool,
    
    /// Require audience validation
    pub require_audience_validation: bool,
    
    /// Enable issuer validation
    pub enable_issuer_validation: bool,
    
    /// Rotate signing keys regularly
    pub rotate_signing_keys: bool,
    
    /// Key rotation interval (hours)
    pub key_rotation_interval_hours: u64,
}

/// OAuth hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthHardeningConfig {
    /// Require PKCE for all flows
    pub require_pkce: bool,
    
    /// Require state parameter
    pub require_state: bool,
    
    /// Enable dynamic client registration
    pub enable_dynamic_registration: bool,
    
    /// Client authentication methods
    pub allowed_client_auth_methods: Vec<String>,
    
    /// Authorization code lifetime (seconds)
    pub auth_code_lifetime: u64,
    
    /// Require redirect URI exact match
    pub require_exact_redirect_match: bool,
}

/// Session hardening configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHardeningConfig {
    /// Session timeout (seconds)
    pub session_timeout: u64,
    
    /// Idle session timeout (seconds)
    pub idle_timeout: u64,
    
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,
    
    /// Session rotation interval (seconds)
    pub rotation_interval: u64,
    
    /// Enable secure session cookies
    pub secure_cookies: bool,
    
    /// Enable HttpOnly cookies
    pub httponly_cookies: bool,
    
    /// Cookie SameSite attribute
    pub samesite_attribute: String,
    
    /// Enable session fingerprinting
    pub enable_fingerprinting: bool,
    
    /// Session storage encryption
    pub encrypt_session_storage: bool,
}

/// API security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSecurityConfig {
    /// Enable request signing
    pub enable_request_signing: bool,
    
    /// Request replay prevention window (seconds)
    pub replay_prevention_window: u64,
    
    /// Enable request size limits
    pub enable_size_limits: bool,
    
    /// Maximum request size (bytes)
    pub max_request_size: u64,
    
    /// Enable response filtering
    pub enable_response_filtering: bool,
    
    /// API versioning enforcement
    pub enforce_api_versioning: bool,
    
    /// Content-Type validation
    pub validate_content_type: bool,
    
    /// Enable CORS restrictions
    pub enable_cors_restrictions: bool,
    
    /// Allowed CORS origins
    pub cors_allowed_origins: Vec<String>,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable security event logging
    pub enable_security_logging: bool,
    
    /// Enable real-time alerting
    pub enable_real_time_alerting: bool,
    
    /// Enable threat detection
    pub enable_threat_detection: bool,
    
    /// Enable anomaly detection
    pub enable_anomaly_detection: bool,
    
    /// Log retention period (days)
    pub log_retention_days: u32,
    
    /// Enable SIEM integration
    pub enable_siem_integration: bool,
    
    /// SIEM endpoints
    pub siem_endpoints: Vec<String>,
    
    /// Enable performance monitoring
    pub enable_performance_monitoring: bool,
    
    /// Enable security metrics dashboard
    pub enable_security_dashboard: bool,
    
    /// Alert thresholds
    pub alert_thresholds: AlertThresholds,
}

/// Alert threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Failed login attempts threshold
    pub failed_login_threshold: u32,
    
    /// Suspicious activity threshold
    pub suspicious_activity_threshold: u32,
    
    /// Rate limit violation threshold
    pub rate_limit_violation_threshold: u32,
    
    /// Security policy violation threshold
    pub security_violation_threshold: u32,
    
    /// High-value transaction threshold
    pub high_value_transaction_threshold: u64,
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Enable SOC 2 compliance
    pub enable_soc2: bool,
    
    /// Enable PCI DSS compliance
    pub enable_pci_dss: bool,
    
    /// Enable GDPR compliance
    pub enable_gdpr: bool,
    
    /// Enable HIPAA compliance
    pub enable_hipaa: bool,
    
    /// Enable CCPA compliance
    pub enable_ccpa: bool,
    
    /// Enable audit logging
    pub enable_audit_logging: bool,
    
    /// Audit log retention (days)
    pub audit_retention_days: u32,
    
    /// Enable data encryption at rest
    pub enable_encryption_at_rest: bool,
    
    /// Enable data encryption in transit
    pub enable_encryption_in_transit: bool,
    
    /// Data residency requirements
    pub data_residency_regions: Vec<String>,
    
    /// Enable right to be forgotten
    pub enable_right_to_be_forgotten: bool,
}

impl Default for SecurityHardeningConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl SecurityHardeningConfig {
    /// Production-hardened security configuration
    pub fn production() -> Self {
        Self {
            network: NetworkSecurityConfig {
                tls_1_3_only: true,
                require_pfs: true,
                hsts_preload: true,
                hsts_max_age: 63072000, // 2 years
                cert_pinning: true,
                allowed_ciphers: vec![
                    "TLS_AES_256_GCM_SHA384".to_string(),
                    "TLS_CHACHA20_POLY1305_SHA256".to_string(),
                    "TLS_AES_128_GCM_SHA256".to_string(),
                ],
                ocsp_stapling: true,
                admin_ip_allowlist: vec![], // Must be configured per deployment
                rate_limiting: RateLimitingHardening {
                    global_requests_per_minute: 1000,
                    auth_requests_per_minute: 100,
                    admin_requests_per_minute: 50,
                    api_requests_per_minute: 500,
                    adaptive_rate_limiting: true,
                    ban_duration_seconds: 3600, // 1 hour
                    distributed_limiting: true,
                },
            },
            authentication: AuthenticationHardeningConfig {
                require_mfa_all_accounts: false,
                require_mfa_admin: true,
                max_login_attempts: 5,
                lockout_duration_seconds: 900, // 15 minutes
                password_policy: PasswordPolicyHardening {
                    min_length: 16,
                    require_complexity: true,
                    password_history_count: 24,
                    expiration_days: 90,
                    check_breach_databases: true,
                    prohibit_common_passwords: true,
                    require_privileged_rotation: true,
                },
                jwt_hardening: JwtHardeningConfig {
                    access_token_lifetime: 900,  // 15 minutes
                    refresh_token_lifetime: 3600, // 1 hour
                    enable_token_binding: true,
                    enable_token_encryption: true,
                    require_audience_validation: true,
                    enable_issuer_validation: true,
                    rotate_signing_keys: true,
                    key_rotation_interval_hours: 24,
                },
                oauth_hardening: OAuthHardeningConfig {
                    require_pkce: true,
                    require_state: true,
                    enable_dynamic_registration: false,
                    allowed_client_auth_methods: vec![
                        "client_secret_jwt".to_string(),
                        "private_key_jwt".to_string(),
                    ],
                    auth_code_lifetime: 300, // 5 minutes
                    require_exact_redirect_match: true,
                },
                device_fingerprinting: true,
                geolocation_restrictions: true,
                require_hardware_keys_admin: true,
            },
            session: SessionHardeningConfig {
                session_timeout: 3600, // 1 hour
                idle_timeout: 1800, // 30 minutes
                max_concurrent_sessions: 3,
                rotation_interval: 900, // 15 minutes
                secure_cookies: true,
                httponly_cookies: true,
                samesite_attribute: "Strict".to_string(),
                enable_fingerprinting: true,
                encrypt_session_storage: true,
            },
            api: ApiSecurityConfig {
                enable_request_signing: true,
                replay_prevention_window: 300, // 5 minutes
                enable_size_limits: true,
                max_request_size: 1024 * 1024, // 1MB
                enable_response_filtering: true,
                enforce_api_versioning: true,
                validate_content_type: true,
                enable_cors_restrictions: true,
                cors_allowed_origins: vec![], // Must be configured per deployment
            },
            monitoring: MonitoringConfig {
                enable_security_logging: true,
                enable_real_time_alerting: true,
                enable_threat_detection: true,
                enable_anomaly_detection: true,
                log_retention_days: 365,
                enable_siem_integration: true,
                siem_endpoints: vec![], // Configure per deployment
                enable_performance_monitoring: true,
                enable_security_dashboard: true,
                alert_thresholds: AlertThresholds {
                    failed_login_threshold: 10,
                    suspicious_activity_threshold: 5,
                    rate_limit_violation_threshold: 100,
                    security_violation_threshold: 1,
                    high_value_transaction_threshold: 10000,
                },
            },
            compliance: ComplianceConfig {
                enable_soc2: true,
                enable_pci_dss: false, // Enable if processing payments
                enable_gdpr: true,
                enable_hipaa: false, // Enable if handling health data
                enable_ccpa: true,
                enable_audit_logging: true,
                audit_retention_days: 2555, // 7 years
                enable_encryption_at_rest: true,
                enable_encryption_in_transit: true,
                data_residency_regions: vec![], // Configure per deployment
                enable_right_to_be_forgotten: true,
            },
        }
    }

    /// High-security configuration for sensitive environments
    pub fn high_security() -> Self {
        let mut config = Self::production();
        
        // Enhanced authentication requirements
        config.authentication.require_mfa_all_accounts = true;
        config.authentication.max_login_attempts = 3;
        config.authentication.lockout_duration_seconds = 3600; // 1 hour
        config.authentication.password_policy.min_length = 20;
        config.authentication.password_policy.expiration_days = 60;
        config.authentication.jwt_hardening.access_token_lifetime = 300; // 5 minutes
        config.authentication.jwt_hardening.refresh_token_lifetime = 1800; // 30 minutes
        
        // Stricter session management
        config.session.session_timeout = 1800; // 30 minutes
        config.session.idle_timeout = 600; // 10 minutes
        config.session.max_concurrent_sessions = 1;
        config.session.rotation_interval = 300; // 5 minutes
        
        // Enhanced monitoring
        config.monitoring.alert_thresholds.failed_login_threshold = 3;
        config.monitoring.alert_thresholds.suspicious_activity_threshold = 1;
        
        // Additional compliance
        config.compliance.enable_pci_dss = true;
        config.compliance.enable_hipaa = true;
        config.compliance.audit_retention_days = 3650; // 10 years
        
        config
    }

    /// Development configuration with security but usability
    pub fn development() -> Self {
        let mut config = Self::production();
        
        // Relaxed for development
        config.network.tls_1_3_only = false;
        config.authentication.require_mfa_admin = false;
        config.authentication.max_login_attempts = 10;
        config.authentication.lockout_duration_seconds = 300; // 5 minutes
        config.authentication.jwt_hardening.access_token_lifetime = 3600; // 1 hour
        config.authentication.jwt_hardening.refresh_token_lifetime = 86400; // 24 hours
        
        config.session.session_timeout = 7200; // 2 hours
        config.session.idle_timeout = 3600; // 1 hour
        
        config.monitoring.log_retention_days = 30;
        config.compliance.audit_retention_days = 90;
        
        config
    }

    /// Validate configuration for security issues
    pub fn validate(&self) -> Result<(), String> {
        // JWT token lifetime validation
        if self.authentication.jwt_hardening.access_token_lifetime > 3600 {
            return Err("Access token lifetime should not exceed 1 hour for security".to_string());
        }

        // Session timeout validation
        if self.session.session_timeout > 14400 {
            return Err("Session timeout should not exceed 4 hours".to_string());
        }

        // Password policy validation
        if self.authentication.password_policy.min_length < 12 {
            return Err("Password minimum length should be at least 12 characters".to_string());
        }

        // Rate limiting validation
        if self.network.rate_limiting.auth_requests_per_minute > 1000 {
            return Err("Authentication rate limit too high - security risk".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config_validation() {
        let config = SecurityHardeningConfig::production();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_high_security_config_validation() {
        let config = SecurityHardeningConfig::high_security();
        assert!(config.validate().is_ok());
        
        // Verify enhanced security settings
        assert!(config.authentication.require_mfa_all_accounts);
        assert_eq!(config.authentication.max_login_attempts, 3);
        assert_eq!(config.session.max_concurrent_sessions, 1);
    }

    #[test]
    fn test_development_config_validation() {
        let config = SecurityHardeningConfig::development();
        assert!(config.validate().is_ok());
        
        // Verify relaxed settings for development
        assert!(!config.network.tls_1_3_only);
        assert!(!config.authentication.require_mfa_admin);
    }

    #[test]
    fn test_invalid_config_validation() {
        let mut config = SecurityHardeningConfig::production();
        config.authentication.jwt_hardening.access_token_lifetime = 7200; // 2 hours - too long
        
        assert!(config.validate().is_err());
    }
}