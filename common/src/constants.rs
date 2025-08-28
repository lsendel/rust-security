//! Centralized constants for the rust-security project
//!
//! This module contains all shared constants used across different services
//! to ensure consistency and prevent configuration drift.

/// Security-related constants
pub mod security {
    /// Maximum request body size in bytes (1MB)
    pub const MAX_REQUEST_BODY_SIZE: usize = 1_048_576;

    /// Default session TTL in seconds (1 hour)
    pub const DEFAULT_SESSION_TTL: i64 = 3600;

    /// Rate limiting window in seconds
    pub const RATE_LIMIT_WINDOW: u64 = 60;

    /// Maximum token length in characters
    pub const MAX_TOKEN_LENGTH: usize = 1024;

    /// Minimum password length
    pub const MIN_PASSWORD_LENGTH: usize = 8;

    /// Maximum password length
    pub const MAX_PASSWORD_LENGTH: usize = 128;

    /// JWT token expiry time in seconds (15 minutes)
    pub const JWT_TOKEN_EXPIRY: i64 = 900;

    /// Refresh token expiry time in seconds (7 days)
    pub const REFRESH_TOKEN_EXPIRY: i64 = 604_800;

    /// Maximum number of login attempts before lockout
    pub const MAX_LOGIN_ATTEMPTS: u32 = 5;

    /// Account lockout duration in seconds (30 minutes)
    pub const ACCOUNT_LOCKOUT_DURATION: u64 = 1800;

    /// PKCE code verifier minimum length
    pub const PKCE_VERIFIER_MIN_LENGTH: usize = 43;

    /// PKCE code verifier maximum length
    pub const PKCE_VERIFIER_MAX_LENGTH: usize = 128;

    /// Request signature validation window in seconds (5 minutes)
    pub const REQUEST_SIGNATURE_WINDOW: i64 = 300;
}

/// Redis-related constants
pub mod redis {
    /// Default Redis connection pool size
    pub const DEFAULT_POOL_SIZE: u32 = 10;

    /// Maximum Redis connection pool size
    pub const MAX_POOL_SIZE: u32 = 100;

    /// Default connection timeout in milliseconds
    pub const DEFAULT_TIMEOUT_MS: u64 = 5000;

    /// Default key TTL in seconds
    pub const DEFAULT_TTL_SECS: i64 = 300;

    /// Session key TTL in seconds (1 hour)
    pub const SESSION_TTL_SECS: i64 = 3600;

    /// Cache key TTL in seconds (15 minutes)
    pub const CACHE_TTL_SECS: i64 = 900;

    /// Rate limit key TTL in seconds (1 minute)
    pub const RATE_LIMIT_TTL_SECS: i64 = 60;
}

/// Database-related constants
pub mod database {
    /// Default database connection pool size
    pub const DEFAULT_DB_POOL_SIZE: u32 = 10;

    /// Maximum database connection pool size
    pub const MAX_DB_POOL_SIZE: u32 = 50;

    /// Database connection timeout in seconds
    pub const DB_CONNECTION_TIMEOUT_SECS: u64 = 30;

    /// Query timeout in seconds
    pub const QUERY_TIMEOUT_SECS: u64 = 10;

    /// Migration lock timeout in seconds
    pub const MIGRATION_LOCK_TIMEOUT_SECS: u64 = 300;
}

/// HTTP-related constants
pub mod http {
    /// Default server port
    pub const DEFAULT_PORT: u16 = 3000;

    /// Request timeout in seconds
    pub const REQUEST_TIMEOUT_SECS: u64 = 30;

    /// Keep-alive timeout in seconds
    pub const KEEP_ALIVE_TIMEOUT_SECS: u64 = 60;

    /// Maximum concurrent connections
    pub const MAX_CONNECTIONS: usize = 1000;

    /// Request header size limit in bytes
    pub const MAX_HEADER_SIZE: usize = 8192;
}

/// Cryptographic constants
pub mod crypto {
    /// Minimum salt length for password hashing
    pub const MIN_SALT_LENGTH: usize = 16;

    /// Default salt length for password hashing
    pub const DEFAULT_SALT_LENGTH: usize = 32;

    /// Argon2 memory cost (64 MB)
    pub const ARGON2_MEMORY_COST: u32 = 65536;

    /// Argon2 time cost
    pub const ARGON2_TIME_COST: u32 = 3;

    /// Argon2 parallelism
    pub const ARGON2_PARALLELISM: u32 = 4;

    /// AES key size in bytes
    pub const AES_KEY_SIZE: usize = 32;

    /// IV size in bytes
    pub const IV_SIZE: usize = 12;

    /// HMAC key minimum size in bytes
    pub const HMAC_KEY_MIN_SIZE: usize = 32;
}

/// Rate limiting constants
pub mod rate_limiting {
    /// Number of rate limiter shards for reducing contention
    pub const RATE_LIMITER_SHARDS: usize = 64;

    /// Default rate limit per minute
    pub const DEFAULT_RATE_LIMIT: u32 = 100;

    /// Burst capacity multiplier
    pub const BURST_MULTIPLIER: f64 = 1.5;

    /// Rate limiter cleanup interval in seconds
    pub const CLEANUP_INTERVAL_SECS: u64 = 60;
}

/// Caching constants
pub mod caching {
    /// L1 cache maximum entries
    pub const L1_CACHE_MAX_ENTRIES: usize = 1000;

    /// L2 cache maximum entries
    pub const L2_CACHE_MAX_ENTRIES: usize = 10000;

    /// Cache entry TTL in seconds
    pub const CACHE_ENTRY_TTL_SECS: u64 = 300;

    /// Cache cleanup interval in seconds
    pub const CACHE_CLEANUP_INTERVAL_SECS: u64 = 60;
}

/// Monitoring and observability constants
pub mod monitoring {
    /// Metrics collection interval in seconds
    pub const METRICS_COLLECTION_INTERVAL_SECS: u64 = 10;

    /// Health check interval in seconds
    pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

    /// Tracing sample rate (10%)
    pub const TRACING_SAMPLE_RATE: f64 = 0.1;

    /// Maximum trace spans to keep in memory
    pub const MAX_TRACE_SPANS: usize = 1000;
}

/// Thread pool constants
pub mod threading {
    /// Default number of worker threads (CPU cores)
    pub const DEFAULT_WORKER_THREADS: usize = 4; // Default to 4 threads, can be overridden at runtime

    /// Maximum number of blocking threads
    pub const MAX_BLOCKING_THREADS: usize = 512;

    /// Thread keep-alive time in seconds
    pub const THREAD_KEEP_ALIVE_SECS: u64 = 60;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_constants() {
        assert!(security::MAX_REQUEST_BODY_SIZE > 0);
        assert!(security::DEFAULT_SESSION_TTL > 0);
        assert!(security::JWT_TOKEN_EXPIRY < security::REFRESH_TOKEN_EXPIRY);
        assert!(security::MIN_PASSWORD_LENGTH <= security::MAX_PASSWORD_LENGTH);
    }

    #[test]
    fn test_redis_constants() {
        assert!(redis::DEFAULT_POOL_SIZE <= redis::MAX_POOL_SIZE);
        assert!(redis::DEFAULT_TIMEOUT_MS > 0);
        assert!(redis::SESSION_TTL_SECS > redis::CACHE_TTL_SECS);
    }

    #[test]
    fn test_crypto_constants() {
        assert!(crypto::MIN_SALT_LENGTH <= crypto::DEFAULT_SALT_LENGTH);
        assert!(crypto::ARGON2_MEMORY_COST > 0);
        assert!(crypto::AES_KEY_SIZE == 32); // 256-bit key
    }

    #[test]
    fn test_rate_limiting_constants() {
        assert!(rate_limiting::RATE_LIMITER_SHARDS.is_power_of_two());
        assert!(rate_limiting::DEFAULT_RATE_LIMIT > 0);
        assert!(rate_limiting::BURST_MULTIPLIER >= 1.0);
    }
}
