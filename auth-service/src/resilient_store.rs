use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, TimeoutConfig, RetryConfig, RetryBackoff};
use crate::errors::AuthError;
use std::time::Duration;
use std::sync::Arc;
use tokio::time::timeout;
use redis::{aio::ConnectionManager, AsyncCommands};

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

#[derive(Debug)]
pub struct ResilientRedisClient {
    connection_manager: ConnectionManager,
    circuit_breaker: CircuitBreaker,
    config: ResilientRedisConfig,
}

impl ResilientRedisClient {
    pub async fn new(redis_url: &str, config: ResilientRedisConfig) -> Result<Self, AuthError> {
        let client = redis::Client::open(redis_url).map_err(|e| AuthError::ServiceUnavailable {
            reason: format!("Failed to create Redis client: {}", e),
        })?;

        let connection_manager = timeout(
            config.timeouts.connect_timeout,
            client.get_connection_manager(),
        )
        .await
        .map_err(|_| AuthError::ServiceUnavailable {
            reason: "Redis connection timeout".to_string(),
        })?
        .map_err(|e| AuthError::ServiceUnavailable {
            reason: format!("Failed to create Redis connection manager: {}", e),
        })?;

        let circuit_breaker = CircuitBreaker::new("redis", config.circuit_breaker.clone());

        Ok(Self {
            connection_manager,
            circuit_breaker,
            config,
        })
    }

    pub async fn get<K, V>(&self, key: K) -> Result<Option<V>, AuthError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
        V: redis::FromRedisValue + Send + Sync,
    {
        let key = key.clone();
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            async move {
                conn.get(key_clone).await
            }
        })
        .await
    }

    pub async fn set<K, V>(&self, key: K, value: V) -> Result<(), AuthError>
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

    pub async fn set_ex<K, V>(&self, key: K, value: V, seconds: u64) -> Result<(), AuthError>
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

    pub async fn del<K>(&self, key: K) -> Result<u64, AuthError>
    where
        K: redis::ToRedisArgs + Send + Sync + Clone + 'static,
    {
        self.execute_with_retry(move |mut conn| {
            let key_clone = key.clone();
            async move {
                conn.del(&key_clone).await
            }
        })
        .await
    }

    pub async fn exists<K>(&self, key: K) -> Result<bool, AuthError>
    where
        K: redis::ToRedisArgs + Send + Sync,
    {
        self.execute_with_retry(|mut conn| async move {
            let count: u64 = conn.exists(&key).await?;
            Ok(count > 0)
        })
        .await
    }

    pub async fn expire<K>(&self, key: K, seconds: u64) -> Result<bool, AuthError>
    where
        K: redis::ToRedisArgs + Send + Sync,
    {
        self.execute_with_retry(|mut conn| async move {
            conn.expire(&key, seconds as i64).await
        })
        .await
    }

    pub async fn pipeline(&self) -> ResilientPipeline {
        ResilientPipeline::new(self.connection_manager.clone(), &self.circuit_breaker, &self.config)
    }

    async fn execute_with_retry<F, R, Fut>(&self, operation: F) -> Result<R, AuthError>
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
                    return Err(AuthError::ServiceUnavailable {
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
                        error = %msg,
                        attempt = backoff.attempt(),
                        "Redis operation failed"
                    );
                }
                Err(CircuitBreakerError::TooManyRequests) => {
                    return Err(AuthError::ServiceUnavailable {
                        reason: "Redis circuit breaker: too many requests".to_string(),
                    });
                }
            }

            // Try to get next delay for retry
            if backoff.next_delay().await.is_none() {
                return Err(AuthError::ServiceUnavailable {
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
    fn new(connection_manager: ConnectionManager, circuit_breaker: &CircuitBreaker, config: &ResilientRedisConfig) -> Self {
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

    pub async fn execute<T>(&mut self) -> Result<T, AuthError>
    where
        T: redis::FromRedisValue + Send + Sync,
    {
        let mut backoff = RetryBackoff::new(self.config.retry.clone());
        
        loop {
            let conn = self.connection_manager.clone();
            let pipe = self.pipe.clone();
            
            let result = self.circuit_breaker.call(async move {
                pipe.query_async(&mut conn.clone()).await
            }).await;
            
            match result {
                Ok(value) => return Ok(value),
                Err(CircuitBreakerError::Open) => {
                    return Err(AuthError::ServiceUnavailable {
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
                        error = %msg,
                        attempt = backoff.attempt(),
                        "Redis pipeline failed"
                    );
                }
                Err(CircuitBreakerError::TooManyRequests) => {
                    return Err(AuthError::ServiceUnavailable {
                        reason: "Redis circuit breaker: too many requests".to_string(),
                    });
                }
            }

            // Try to get next delay for retry
            if backoff.next_delay().await.is_none() {
                return Err(AuthError::ServiceUnavailable {
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
        let result = circuit_breaker.call(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<(), std::io::Error>(())
        }).await;

        assert!(matches!(result, Err(CircuitBreakerError::Timeout { .. })));
    }
}