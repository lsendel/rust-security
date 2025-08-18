use crate::circuit_breaker::{CircuitBreakerConfig, RetryConfig, TimeoutConfig};
use crate::resilient_http::ResilientHttpConfig;
use crate::resilient_store::ResilientRedisConfig;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    pub redis: ResilientRedisConfig,
    pub oidc_providers: OidcProviderResilienceConfig,
    pub default_http: ResilientHttpConfig,
    pub external_apis: ExternalApiResilienceConfig,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            redis: ResilientRedisConfig::default(),
            oidc_providers: OidcProviderResilienceConfig::default(),
            default_http: ResilientHttpConfig::default(),
            external_apis: ExternalApiResilienceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderResilienceConfig {
    pub google: ResilientHttpConfig,
    pub microsoft: ResilientHttpConfig,
    pub github: ResilientHttpConfig,
}

impl Default for OidcProviderResilienceConfig {
    fn default() -> Self {
        let base_config = ResilientHttpConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 3,
                recovery_timeout: Duration::from_secs(60),
                request_timeout: Duration::from_secs(30),
                half_open_max_calls: 2,
                minimum_request_threshold: 5,
            },
            timeouts: TimeoutConfig {
                connect_timeout: Duration::from_secs(10),
                request_timeout: Duration::from_secs(30),
                read_timeout: Duration::from_secs(30),
                write_timeout: Duration::from_secs(10),
            },
            retry: RetryConfig {
                max_retries: 2,
                base_delay: Duration::from_millis(1000),
                max_delay: Duration::from_secs(10),
                backoff_multiplier: 2.0,
                jitter: true,
            },
            max_redirects: 10,
            user_agent: "auth-service/1.0".to_string(),
        };

        Self {
            google: ResilientHttpConfig {
                user_agent: "auth-service/1.0 (OIDC-Google)".to_string(),
                ..base_config.clone()
            },
            microsoft: ResilientHttpConfig {
                user_agent: "auth-service/1.0 (OIDC-Microsoft)".to_string(),
                ..base_config.clone()
            },
            github: ResilientHttpConfig {
                user_agent: "auth-service/1.0 (OIDC-GitHub)".to_string(),
                ..base_config.clone()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalApiResilienceConfig {
    pub policy_service: ResilientHttpConfig,
    pub webhook_notifications: ResilientHttpConfig,
    pub audit_logging: ResilientHttpConfig,
}

impl Default for ExternalApiResilienceConfig {
    fn default() -> Self {
        Self {
            policy_service: ResilientHttpConfig {
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 5,
                    recovery_timeout: Duration::from_secs(30),
                    request_timeout: Duration::from_secs(10),
                    half_open_max_calls: 3,
                    minimum_request_threshold: 10,
                },
                timeouts: TimeoutConfig {
                    connect_timeout: Duration::from_secs(5),
                    request_timeout: Duration::from_secs(10),
                    read_timeout: Duration::from_secs(10),
                    write_timeout: Duration::from_secs(5),
                },
                retry: RetryConfig {
                    max_retries: 3,
                    base_delay: Duration::from_millis(500),
                    max_delay: Duration::from_secs(10),
                    backoff_multiplier: 2.0,
                    jitter: true,
                },
                user_agent: "auth-service/1.0 (Policy-Service)".to_string(),
                ..Default::default()
            },
            webhook_notifications: ResilientHttpConfig {
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 10,
                    recovery_timeout: Duration::from_secs(60),
                    request_timeout: Duration::from_secs(30),
                    half_open_max_calls: 5,
                    minimum_request_threshold: 20,
                },
                retry: RetryConfig {
                    max_retries: 5,
                    base_delay: Duration::from_secs(1),
                    max_delay: Duration::from_secs(60),
                    backoff_multiplier: 2.0,
                    jitter: true,
                },
                user_agent: "auth-service/1.0 (Webhooks)".to_string(),
                ..Default::default()
            },
            audit_logging: ResilientHttpConfig {
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 3,
                    recovery_timeout: Duration::from_secs(30),
                    request_timeout: Duration::from_secs(5),
                    half_open_max_calls: 2,
                    minimum_request_threshold: 5,
                },
                retry: RetryConfig {
                    max_retries: 2,
                    base_delay: Duration::from_millis(100),
                    max_delay: Duration::from_secs(5),
                    backoff_multiplier: 2.0,
                    jitter: true,
                },
                user_agent: "auth-service/1.0 (Audit-Logging)".to_string(),
                ..Default::default()
            },
        }
    }
}

impl ResilienceConfig {
    pub fn from_env() -> Self {
        // Load configuration from environment variables
        let mut config = Self::default();

        // Redis configuration
        if let Ok(threshold) = std::env::var("REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD") {
            if let Ok(t) = threshold.parse() {
                config.redis.circuit_breaker.failure_threshold = t;
            }
        }

        if let Ok(timeout) = std::env::var("REDIS_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_SECS") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.redis.circuit_breaker.recovery_timeout = Duration::from_secs(t);
            }
        }

        if let Ok(timeout) = std::env::var("REDIS_REQUEST_TIMEOUT_SECS") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.redis.circuit_breaker.request_timeout = Duration::from_secs(t);
                config.redis.timeouts.request_timeout = Duration::from_secs(t);
            }
        }

        if let Ok(retries) = std::env::var("REDIS_MAX_RETRIES") {
            if let Ok(r) = retries.parse() {
                config.redis.retry.max_retries = r;
            }
        }

        // OIDC provider configuration
        if let Ok(timeout) = std::env::var("OIDC_REQUEST_TIMEOUT_SECS") {
            if let Ok(t) = timeout.parse::<u64>() {
                let timeout_duration = Duration::from_secs(t);
                config.oidc_providers.google.circuit_breaker.request_timeout = timeout_duration;
                config.oidc_providers.microsoft.circuit_breaker.request_timeout = timeout_duration;
                config.oidc_providers.github.circuit_breaker.request_timeout = timeout_duration;
            }
        }

        if let Ok(threshold) = std::env::var("OIDC_CIRCUIT_BREAKER_FAILURE_THRESHOLD") {
            if let Ok(t) = threshold.parse() {
                config.oidc_providers.google.circuit_breaker.failure_threshold = t;
                config.oidc_providers.microsoft.circuit_breaker.failure_threshold = t;
                config.oidc_providers.github.circuit_breaker.failure_threshold = t;
            }
        }

        // Policy service configuration
        if let Ok(timeout) = std::env::var("POLICY_SERVICE_REQUEST_TIMEOUT_SECS") {
            if let Ok(t) = timeout.parse::<u64>() {
                config.external_apis.policy_service.circuit_breaker.request_timeout =
                    Duration::from_secs(t);
            }
        }

        config
    }

    pub fn validate(&self) -> Result<(), String> {
        // Validate Redis configuration
        if self.redis.circuit_breaker.failure_threshold == 0 {
            return Err("Redis circuit breaker failure threshold must be > 0".to_string());
        }

        if self.redis.circuit_breaker.request_timeout.is_zero() {
            return Err("Redis request timeout must be > 0".to_string());
        }

        // Validate OIDC configurations
        for (name, config) in [
            ("google", &self.oidc_providers.google),
            ("microsoft", &self.oidc_providers.microsoft),
            ("github", &self.oidc_providers.github),
        ] {
            if config.circuit_breaker.failure_threshold == 0 {
                return Err(format!("{} OIDC circuit breaker failure threshold must be > 0", name));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_resilience_config() {
        let config = ResilienceConfig::default();

        // Test Redis defaults
        assert_eq!(config.redis.circuit_breaker.failure_threshold, 5);
        assert_eq!(config.redis.timeouts.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.redis.retry.max_retries, 3);

        // Test OIDC defaults
        assert_eq!(config.oidc_providers.google.circuit_breaker.failure_threshold, 3);
        assert_eq!(config.oidc_providers.microsoft.circuit_breaker.failure_threshold, 3);
        assert_eq!(config.oidc_providers.github.circuit_breaker.failure_threshold, 3);

        // Test validation
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = ResilienceConfig::default();

        // Test invalid Redis config
        config.redis.circuit_breaker.failure_threshold = 0;
        assert!(config.validate().is_err());

        // Reset and test zero timeout
        config = ResilienceConfig::default();
        config.redis.circuit_breaker.request_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_oidc_provider_configs() {
        let config = OidcProviderResilienceConfig::default();

        assert!(config.google.user_agent.contains("OIDC-Google"));
        assert!(config.microsoft.user_agent.contains("OIDC-Microsoft"));
        assert!(config.github.user_agent.contains("OIDC-GitHub"));
    }
}
