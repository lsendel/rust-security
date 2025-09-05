//! Secure defaults for the unified security configuration
//!
//! This module provides secure defaults based on current security best practices
//! and recommendations from security standards like OWASP, NIST, and industry guidelines.

use super::*;

impl Default for UnifiedSecurityConfig {
    /// Create a secure default configuration
    ///
    /// These defaults are based on current security best practices:
    /// - JWT tokens expire quickly (15 minutes access, 24 hours refresh)
    /// - Strong rate limiting to prevent abuse
    /// - All security headers enabled
    /// - Strict CORS policy (no origins allowed by default)
    /// - Strong password policy with Argon2
    /// - TLS 1.3 required
    /// - AES-256-GCM encryption
    ///
    /// # Note
    /// This configuration requires environment variables to be set for secrets.
    /// Use `UnifiedSecurityConfig::from_env()` for production usage.
    fn default() -> Self {
        Self {
            jwt: JwtConfig::default(),
            request_signing: RequestSigningConfig::default(),
            session: SessionConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            headers: SecurityHeaders::default(),
            cors: CorsConfig::default(),
            password_policy: PasswordPolicy::default(),
            tls: TlsConfig::default(),
            encryption: EncryptionConfig::default(),
        }
    }
}

impl Default for JwtConfig {
    /// Secure JWT defaults
    ///
    /// - 15 minute access tokens (900 seconds)
    /// - 24 hour refresh tokens (86400 seconds)  
    /// - HS256 algorithm (secure and widely supported)
    /// - Token binding enabled for additional security
    fn default() -> Self {
        Self {
            secret: "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED".to_string(),
            access_token_ttl_seconds: 900, // 15 minutes - secure default
            refresh_token_ttl_seconds: 86400, // 24 hours - balance security/usability
            algorithm: JwtAlgorithm::HS256,
            issuer: "rust-security-platform".to_string(),
            audience: None,
            enable_token_binding: true,
        }
    }
}

impl Default for RequestSigningConfig {
    /// Secure request signing defaults
    ///
    /// - 5 minute timestamp window (300 seconds)
    /// - Enabled by default (can be disabled in development)
    fn default() -> Self {
        Self {
            secret: "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED".to_string(),
            timestamp_window_seconds: 300, // 5 minutes - balance security/clock skew
            enabled: true,
        }
    }
}

impl Default for SessionConfig {
    /// Secure session defaults
    ///
    /// - 1 hour session TTL (3600 seconds)
    /// - 15 minute rotation interval (900 seconds)
    /// - Secure cookies enabled
    /// - Hybrid storage (memory + persistent backup)
    fn default() -> Self {
        Self {
            ttl_seconds: 3600,              // 1 hour - reasonable for most applications
            rotation_interval_seconds: 900, // 15 minutes - frequent rotation for security
            secure_cookies: true,
            storage_backend: SessionStorage::Hybrid,
        }
    }
}

impl Default for RateLimitingConfig {
    /// Conservative rate limiting defaults
    ///
    /// These defaults prioritize security over convenience:
    /// - 60 requests per minute per IP (general endpoints)
    /// - 10 requests per minute for OAuth (token endpoints are expensive)
    /// - 5 requests per minute for admin (very restrictive)
    /// - Small burst allowance
    /// - Aggressive banning for abuse
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute_per_ip: 60, // Conservative default
            oauth_requests_per_minute: 10,  // OAuth endpoints are expensive
            admin_requests_per_minute: 5,   // Very restrictive for admin
            burst_size: 10,                 // Small burst allowance
            ban_threshold: 1000,            // Ban after 1000 requests
            ban_duration_seconds: 3600,     // 1 hour ban
        }
    }
}

impl Default for SecurityHeaders {
    /// Secure headers defaults
    ///
    /// - HSTS enabled with 1 year max age
    /// - All XSS and content type protections enabled
    /// - Strict referrer policy
    /// - X-Frame-Options: DENY
    /// - No default CSP (must be configured per application)
    fn default() -> Self {
        Self {
            enabled: true,
            hsts_max_age_seconds: 31536000, // 1 year minimum for HSTS
            content_type_options_nosniff: true,
            frame_options: FrameOptions::Deny,
            xss_protection: true,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            content_security_policy: None, // Must be configured per application
        }
    }
}

impl Default for CorsConfig {
    /// Secure CORS defaults
    ///
    /// - No origins allowed by default (must be explicitly configured)
    /// - Standard HTTP methods only
    /// - Essential headers only
    /// - No credentials allowed
    /// - 1 hour preflight cache
    fn default() -> Self {
        Self {
            allowed_origins: vec![], // No origins by default - must be explicit
            allowed_methods: vec!["GET".to_string(), "POST".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec!["Content-Type".to_string(), "Authorization".to_string()],
            allow_credentials: false, // More secure default
            max_age_seconds: 3600,    // 1 hour preflight cache
        }
    }
}

impl Default for PasswordPolicy {
    /// Strong password policy defaults
    ///
    /// Based on current NIST and OWASP recommendations:
    /// - 12 character minimum (longer than traditional 8)
    /// - All character types required
    /// - Strong Argon2 configuration
    fn default() -> Self {
        Self {
            min_length: 12, // Modern recommendation (up from 8)
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            argon2: Argon2Config::default(),
        }
    }
}

impl Default for Argon2Config {
    /// Secure Argon2 defaults
    ///
    /// Based on current recommendations for Argon2id:
    /// - 64MB memory cost (good security/performance balance)
    /// - 3 iterations (time cost)
    /// - 4 threads (parallelism)
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64MB - good balance of security and performance
            time_cost: 3,       // 3 iterations - current recommendation
            parallelism: 4,     // 4 threads - works well on most systems
        }
    }
}

impl Default for TlsConfig {
    /// Secure TLS defaults
    ///
    /// - TLS enabled
    /// - TLS 1.3 minimum (most secure)
    /// - Empty cipher suites (use system secure defaults)
    fn default() -> Self {
        Self {
            enabled: true,
            cert_path: None,                  // Must be configured for production
            key_path: None,                   // Must be configured for production
            min_version: TlsVersion::TLSv1_3, // Most secure version
            cipher_suites: vec![],            // Use system secure defaults
        }
    }
}

impl Default for EncryptionConfig {
    /// Secure encryption defaults
    ///
    /// - AES-256-GCM (industry standard)
    /// - Placeholder secrets (must be replaced in production)
    fn default() -> Self {
        Self {
            key: "REPLACE_IN_PRODUCTION_MIN_32_CHARS_REQUIRED".to_string(),
            token_binding_salt: "default-salt-change-in-production".to_string(),
            algorithm: EncryptionAlgorithm::AES256GCM,
        }
    }
}

/// Development configuration with relaxed security for testing
impl UnifiedSecurityConfig {
    /// Create a development configuration with relaxed security settings
    ///
    /// This configuration is suitable for development and testing but should
    /// never be used in production. It includes:
    /// - Longer token TTLs for easier development
    /// - Disabled TLS requirement
    /// - Relaxed rate limiting
    /// - Development-friendly secrets
    ///
    /// # Warning
    /// This configuration is NOT secure and must not be used in production!
    pub fn development() -> Self {
        Self {
            jwt: JwtConfig {
                secret: "development-jwt-secret-32-chars-min".to_string(),
                access_token_ttl_seconds: 3600, // 1 hour for development convenience
                refresh_token_ttl_seconds: 86400, // 24 hours
                ..Default::default()
            },
            request_signing: RequestSigningConfig {
                secret: "development-request-signing-secret-32-chars".to_string(),
                enabled: false, // Disabled for development convenience
                ..Default::default()
            },
            session: SessionConfig {
                secure_cookies: false, // Allow non-HTTPS in development
                ..Default::default()
            },
            rate_limiting: RateLimitingConfig {
                enabled: false, // Disabled for development convenience
                ..Default::default()
            },
            tls: TlsConfig {
                enabled: false, // Allow HTTP in development
                ..Default::default()
            },
            encryption: EncryptionConfig {
                key: "development-encryption-key-32-chars-minimum".to_string(),
                token_binding_salt: "development-salt".to_string(),
                ..Default::default()
            },
            cors: CorsConfig {
                allowed_origins: vec!["http://localhost:3000".to_string()], // Common dev frontend
                allow_credentials: true, // Allow credentials for development
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Create a testing configuration optimized for unit/integration tests
    ///
    /// This configuration is optimized for fast test execution:
    /// - Very short token TTLs for testing expiration
    /// - Minimal Argon2 settings for fast password hashing
    /// - All security features enabled but with test-friendly settings
    pub fn testing() -> Self {
        Self {
            jwt: JwtConfig {
                secret: "test-jwt-secret-32-characters-minimum-length".to_string(),
                access_token_ttl_seconds: 60, // 1 minute for testing expiration
                refresh_token_ttl_seconds: 300, // 5 minutes
                ..Default::default()
            },
            request_signing: RequestSigningConfig {
                secret: "test-request-signing-secret-32-characters-minimum".to_string(),
                timestamp_window_seconds: 60, // Wider window for test timing
                enabled: true,                // Test security features
            },
            session: SessionConfig {
                ttl_seconds: 300,                        // 5 minutes
                rotation_interval_seconds: 60,           // 1 minute
                secure_cookies: false,                   // Allow HTTP in tests
                storage_backend: SessionStorage::Memory, // Fast memory storage
            },
            rate_limiting: RateLimitingConfig {
                enabled: true,                    // Test rate limiting
                requests_per_minute_per_ip: 1000, // High limit for fast tests
                oauth_requests_per_minute: 100,
                admin_requests_per_minute: 50,
                burst_size: 100,
                ban_threshold: 10000,
                ban_duration_seconds: 60,
            },
            password_policy: PasswordPolicy {
                argon2: Argon2Config {
                    memory_cost: 32768, // 32MB - faster for tests
                    time_cost: 2,       // Minimum time cost
                    parallelism: 2,     // Fewer threads
                },
                ..Default::default()
            },
            tls: TlsConfig {
                enabled: false, // Allow HTTP in tests
                ..Default::default()
            },
            encryption: EncryptionConfig {
                key: "test-encryption-key-32-characters-minimum".to_string(),
                token_binding_salt: "test-salt".to_string(),
                ..Default::default()
            },
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()], // Allow all for tests
                allow_credentials: true,
                ..Default::default()
            },
            headers: SecurityHeaders {
                enabled: true,              // Test security headers
                hsts_max_age_seconds: 3600, // 1 hour for tests
                ..Default::default()
            },
        }
    }
}
