use crate::circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, RetryBackoff, RetryConfig,
    TimeoutConfig,
};
use crate::shared::error::AppError;
use crate::pii_protection::redact_log;
use redis::{aio::ConnectionManager, AsyncCommands};
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResilientRedisConfig {
    pub circuit_breaker: CircuitBreakerConfig,
    pub timeouts: TimeoutConfig,
    pub retry: RetryConfig,
    pub connection_pool_size: u32,
    pub max_connection_lifetime: Duration,
}

impl Default for ResilientRedisConfig {
    fn default() -> Self {
        Self {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 5,
                recovery_timeout: Duration::from_secs(30),
                request_timeout: Duration::from_secs(5),
                half_open_max_calls: 2,
                minimum_request_threshold: 10,
            },
            timeouts: TimeoutConfig {
                connect_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(5),
                read_timeout: Duration::from_secs(10),
                write_timeout: Duration::from_secs(5),
            },
            retry: RetryConfig {
                max_retries: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(5),
                backoff_multiplier: 2.0,
                jitter: true,
            },
            connection_pool_size: 10,
            max_connection_lifetime: Duration::from_secs(3600),
        }
    }
}

pub struct ResilientRedisClient {
    connection_manager: ConnectionManager,
    circuit_breaker: CircuitBreaker,
    config: ResilientRedisConfig,
}

impl ResilientRedisClient {
    /// Create a new resilient Redis client with circuit breaker and retry logic
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError::ServiceUnavailable` if:
    /// - Redis client creation fails due to invalid URL
    /// - Connection manager creation times out
    /// - Initial connection to Redis server fails
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation.
    pub async fn new(redis_url: &str, config: ResilientRedisConfig) -> Result<Self, crate::shared::error::AppError> {
        let client = redis::Client::open(redis_url).map_err(|e| crate::shared::error::AppError::ServiceUnavailable {
            reason: format!("Failed to create Redis client: {}", e),
        })?;

        let connection_manager = timeout(
            config.timeouts.connect_timeout,
            client.get_connection_manager(),
        )
        .await
        .map_err(|_| crate::shared::error::AppError::ServiceUnavailable {
            reason: "Redis connection timeout".to_string(),
        })?
        .map_err(|e| crate::shared::error::AppError::ServiceUnavailable {
            reason: format!("Failed to create Redis connection manager: {}", e),
        })?;

        let circuit_breaker = CircuitBreaker::new("redis", config.circuit_breaker.clone());

        Ok(Self {
            connection_manager,
            circuit_breaker,
            config,
        })
    }

    /// Get a value from Redis with circuit breaker protection
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError::CircuitBreakerOpen` if the circuit breaker is open.
    /// Returns `crate::shared::error::AppError::ServiceUnavailable` if:
    /// - Redis connection fails
    /// - Operation times out
    /// - Deserialization fails
    ///
    /// # Panics
    ///
    /// This function does not panic under normal operation.
    pub async fn get<K, V>(&self, key: K) -> Result<Option<V>, crate::shared::error::AppError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
        V: redis::FromRedisValue + Send + Sync,
    {
        let key = key.clone();
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            async move { conn.get(key_clone).await }
        })
        .await
    }

    /// Set a value in Redis with retry logic
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Redis connection fails after all retries
    /// - Set operation fails due to Redis server error
    /// - Serialization of key or value fails
    pub async fn set<K, V>(&self, key: K, value: V) -> Result<(), crate::shared::error::AppError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
        V: redis::ToRedisArgs + Send + Sync + Clone + 'static,
    {
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            let value_clone = value.clone();
            async move {
                let _: () = conn.set(&key_clone, &value_clone).await?;
                Ok(())
            }
        })
        .await
    }

    /// Set a value with expiration time in Redis
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Redis connection fails after all retries
    /// - Set operation with expiration fails
    /// - Serialization of key or value fails
    pub async fn set_ex<K, V>(&self, key: K, value: V, seconds: u64) -> Result<(), crate::shared::error::AppError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
        V: redis::ToRedisArgs + Send + Sync + Clone + 'static,
    {
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            let value_clone = value.clone();
            async move {
                let _: () = conn.set_ex(&key_clone, &value_clone, seconds).await?;
                Ok(())
            }
        })
        .await
    }

    /// Delete a key from Redis
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Redis connection fails after all retries
    /// - Delete operation fails due to Redis server error
    pub async fn del<K>(&self, key: K) -> Result<u64, crate::shared::error::AppError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
    {
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            async move { conn.del(&key_clone).await }
        })
        .await
    }

    /// Check if a key exists in Redis
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Redis connection fails after all retries
    /// - Exists check operation fails
    pub async fn exists<K>(&self, key: K) -> Result<bool, crate::shared::error::AppError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
    {
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            async move {
                let count: u64 = conn.exists(&key_clone).await?;
                Ok(count > 0)
            }
        })
        .await
    }

    /// Set expiration time for a key in Redis
    ///
    /// # Errors
    ///
    /// Returns `crate::shared::error::AppError` if:
    /// - Redis connection fails after all retries
    /// - Expire operation fails due to Redis server error
    pub async fn expire<K>(&self, key: K, seconds: u64) -> Result<bool, crate::shared::error::AppError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
    {
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            async move { conn.expire(&key_clone, seconds as i64).await }
        })
        .await
    }

    pub async fn pipeline(&self) -> ResilientPipeline {
        ResilientPipeline::new(
            self.connection_manager.clone(),
            &self.circuit_breaker,
            &self.config,
        )
    }

    async fn execute_with_retry<F, R, Fut>(&self, operation: F) -> Result<R, crate::shared::error::AppError>
    where
        F: Fn(ConnectionManager) -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<R, redis::RedisError>> + Send,
        R: Send + Sync,
    {
        let mut backoff = RetryBackoff::new(self.config.retry.clone());

        loop {
            let conn = self.connection_manager.clone();

            let result = self.circuit_breaker.call(operation(conn)).await;

            match result {
                Ok(value) => return Ok(value),
                Err(CircuitBreakerError::Open) => {
                    return Err(crate::shared::error::AppError::ServiceUnavailable {
                        reason: "Redis circuit breaker is open".to_string(),
                    });
                }
                Err(CircuitBreakerError::Timeout { timeout }) => {
                    tracing::warn!(
                        timeout = ?timeout,
                        attempt = backoff.attempt(),
                        "Redis operation timeout"
                    );
                }
                Err(CircuitBreakerError::OperationFailed(msg)) => {
                    tracing::warn!(
                        error = %redact_log(&msg),
                        attempt = backoff.attempt(),
                        "Redis operation failed"
                    );
                }
                Err(CircuitBreakerError::TooManyRequests) => {
                    return Err(crate::shared::error::AppError::ServiceUnavailable {
                        reason: "Redis circuit breaker: too many requests".to_string(),
                    });
                }
            }

            // Try to get next delay for retry
            if backoff.next_delay().await.is_none() {
                return Err(crate::shared::error::AppError::ServiceUnavailable {
                    reason: "Redis operation failed after all retries".to_string(),
                });
            }
        }
    }

    pub fn stats(&self) -> crate::circuit_breaker::CircuitBreakerStats {
        self.circuit_breaker.stats()
    }
}

pub struct ResilientPipeline {
    pipe: redis::Pipeline,
    connection_manager: ConnectionManager,
    circuit_breaker: CircuitBreaker,
    config: ResilientRedisConfig,
}

impl ResilientPipeline {
    fn new(
        connection_manager: ConnectionManager,
        circuit_breaker: &CircuitBreaker,
        config: &ResilientRedisConfig,
    ) -> Self {
        Self {
            pipe: redis::pipe(),
            connection_manager,
            circuit_breaker: circuit_breaker.clone(),
            config: config.clone(),
        }
    }

    pub fn get<K>(&mut self, key: K) -> &mut Self
    where
        K: redis::ToRedisArgs,
    {
        self.pipe.get(key);
        self
    }

    pub fn set<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: redis::ToRedisArgs,
        V: redis::ToRedisArgs,
    {
        self.pipe.set(key, value);
        self
    }

    pub fn set_ex<K, V>(&mut self, key: K, value: V, seconds: u64) -> &mut Self
    where
        K: redis::ToRedisArgs,
        V: redis::ToRedisArgs,
    {
        self.pipe.set_ex(key, value, seconds);
        self
    }

    pub fn del<K>(&mut self, key: K) -> &mut Self
    where
        K: redis::ToRedisArgs,
    {
        self.pipe.del(key);
        self
    }

    pub async fn execute<T>(&mut self) -> Result<T, crate::shared::error::AppError>
    where
        T: redis::FromRedisValue + Send + Sync,
    {
        let mut backoff = RetryBackoff::new(self.config.retry.clone());

        loop {
            let conn = self.connection_manager.clone();
            let pipe = self.pipe.clone();

            let result = self
                .circuit_breaker
                .call(async move { pipe.query_async(&mut conn.clone()).await })
                .await;

            match result {
                Ok(value) => return Ok(value),
                Err(CircuitBreakerError::Open) => {
                    return Err(crate::shared::error::AppError::ServiceUnavailable {
                        reason: "Redis circuit breaker is open".to_string(),
                    });
                }
                Err(CircuitBreakerError::Timeout { timeout }) => {
                    tracing::warn!(
                        timeout = ?timeout,
                        attempt = backoff.attempt(),
                        "Redis pipeline timeout"
                    );
                }
                Err(CircuitBreakerError::OperationFailed(msg)) => {
                    tracing::warn!(
                        error = %redact_log(&msg),
                        attempt = backoff.attempt(),
                        "Redis pipeline failed"
                    );
                }
                Err(CircuitBreakerError::TooManyRequests) => {
                    return Err(crate::shared::error::AppError::ServiceUnavailable {
                        reason: "Redis circuit breaker: too many requests".to_string(),
                    });
                }
            }

            // Try to get next delay for retry
            if backoff.next_delay().await.is_none() {
                return Err(crate::shared::error::AppError::ServiceUnavailable {
                    reason: "Redis pipeline operation failed after all retries".to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;
    use uuid::Uuid;

    static INIT: Once = Once::new();

    fn init() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    // Mock Redis tests (would need a test Redis instance for full integration)
    #[tokio::test]
    async fn test_resilient_redis_config() {
        init();
        let config = ResilientRedisConfig::default();
        assert_eq!(config.circuit_breaker.failure_threshold, 5);
        assert_eq!(config.timeouts.connect_timeout, Duration::from_secs(5));
        assert_eq!(config.retry.max_retries, 3);
    }

    #[tokio::test]
    async fn test_circuit_breaker_integration() {
        init();
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            minimum_request_threshold: 1,
            request_timeout: Duration::from_millis(50),
            ..Default::default()
        };

        let circuit_breaker = CircuitBreaker::new("test-redis", config);

        // Simulate a slow operation that will timeout
        let result = circuit_breaker
            .call(async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<(), std::io::Error>(())
            })
            .await;

        assert!(matches!(result, Err(CircuitBreakerError::Timeout { .. })));
    }
}
