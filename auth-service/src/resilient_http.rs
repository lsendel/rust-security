use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, TimeoutConfig, RetryConfig, RetryBackoff};
use crate::errors::AuthError;
use std::time::Duration;
use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use bytes::Bytes;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResilientHttpConfig {
    pub circuit_breaker: CircuitBreakerConfig,
    pub timeouts: TimeoutConfig,
    pub retry: RetryConfig,
    pub max_redirects: usize,
    pub user_agent: String,
}

impl Default for ResilientHttpConfig {
    fn default() -> Self {
        Self {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 5,
                recovery_timeout: Duration::from_secs(30),
                request_timeout: Duration::from_secs(30),
                half_open_max_calls: 3,
                minimum_request_threshold: 10,
            },
            timeouts: TimeoutConfig {
                connect_timeout: Duration::from_secs(10),
                request_timeout: Duration::from_secs(30),
                read_timeout: Duration::from_secs(30),
                write_timeout: Duration::from_secs(10),
            },
            retry: RetryConfig {
                max_retries: 3,
                base_delay: Duration::from_millis(500),
                max_delay: Duration::from_secs(30),
                backoff_multiplier: 2.0,
                jitter: true,
            },
            max_redirects: 10,
            user_agent: "auth-service/1.0".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct ResilientHttpClient {
    client: Client,
    circuit_breaker: CircuitBreaker,
    config: ResilientHttpConfig,
}

impl ResilientHttpClient {
    pub fn new(name: impl Into<String>, config: ResilientHttpConfig) -> Result<Self, AuthError> {
        let client = Client::builder()
            .timeout(config.timeouts.request_timeout)
            .connect_timeout(config.timeouts.connect_timeout)
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .user_agent(&config.user_agent)
            // Enable secure TLS settings
            .use_rustls_tls()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()
            .map_err(|e| AuthError::ServiceUnavailable {
                reason: format!("Failed to create HTTP client: {}", e),
            })?;

        let circuit_breaker = CircuitBreaker::new(name, config.circuit_breaker.clone());

        Ok(Self {
            client,
            circuit_breaker,
            config,
        })
    }

    pub fn get(&self, url: &str) -> ResilientRequestBuilder {
        ResilientRequestBuilder::new(
            self.client.get(url),
            &self.circuit_breaker,
            &self.config,
        )
    }

    pub fn post(&self, url: &str) -> ResilientRequestBuilder {
        ResilientRequestBuilder::new(
            self.client.post(url),
            &self.circuit_breaker,
            &self.config,
        )
    }

    pub fn put(&self, url: &str) -> ResilientRequestBuilder {
        ResilientRequestBuilder::new(
            self.client.put(url),
            &self.circuit_breaker,
            &self.config,
        )
    }

    pub fn delete(&self, url: &str) -> ResilientRequestBuilder {
        ResilientRequestBuilder::new(
            self.client.delete(url),
            &self.circuit_breaker,
            &self.config,
        )
    }

    pub fn stats(&self) -> crate::circuit_breaker::CircuitBreakerStats {
        self.circuit_breaker.stats()
    }
}

pub struct ResilientRequestBuilder {
    request_builder: RequestBuilder,
    circuit_breaker: CircuitBreaker,
    config: ResilientHttpConfig,
}

impl ResilientRequestBuilder {
    fn new(
        request_builder: RequestBuilder,
        circuit_breaker: &CircuitBreaker,
        config: &ResilientHttpConfig,
    ) -> Self {
        Self {
            request_builder,
            circuit_breaker: circuit_breaker.clone(),
            config: config.clone(),
        }
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.request_builder = self.request_builder.header(key.as_ref(), value.as_ref());
        self
    }

    pub fn headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self.request_builder = self.request_builder.headers(headers);
        self
    }

    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.request_builder = self.request_builder.bearer_auth(token);
        self
    }

    pub fn basic_auth<U, P>(mut self, username: U, password: Option<P>) -> Self
    where
        U: std::fmt::Display,
        P: std::fmt::Display,
    {
        self.request_builder = self.request_builder.basic_auth(username, password);
        self
    }

    pub fn json<T: Serialize + ?Sized>(mut self, json: &T) -> Self {
        self.request_builder = self.request_builder.json(json);
        self
    }

    pub fn form<T: Serialize + ?Sized>(mut self, form: &T) -> Self {
        self.request_builder = self.request_builder.form(form);
        self
    }

    pub fn body<T: Into<reqwest::Body>>(mut self, body: T) -> Self {
        self.request_builder = self.request_builder.body(body);
        self
    }

    pub async fn send(self) -> Result<ResilientResponse, AuthError> {
        let mut backoff = RetryBackoff::new(self.config.retry.clone());

        loop {
            // Clone request builder for retry attempts
            let request = self.request_builder.try_clone()
                .ok_or_else(|| AuthError::ServiceUnavailable {
                    reason: "Cannot retry request with streaming body".to_string(),
                })?;

            let result = self.circuit_breaker.call(async move {
                request.send().await
            }).await;

            match result {
                Ok(response) => {
                    return Ok(ResilientResponse { response });
                }
                Err(CircuitBreakerError::Open) => {
                    return Err(AuthError::ServiceUnavailable {
                        reason: "HTTP circuit breaker is open".to_string(),
                    });
                }
                Err(CircuitBreakerError::Timeout { timeout }) => {
                    tracing::warn!(
                        timeout = ?timeout,
                        attempt = backoff.attempt(),
                        "HTTP request timeout"
                    );
                }
                Err(CircuitBreakerError::OperationFailed(msg)) => {
                    tracing::warn!(
                        error = %msg,
                        attempt = backoff.attempt(),
                        "HTTP request failed"
                    );
                }
                Err(CircuitBreakerError::TooManyRequests) => {
                    return Err(AuthError::ServiceUnavailable {
                        reason: "HTTP circuit breaker: too many requests".to_string(),
                    });
                }
            }

            // Try to get next delay for retry
            if backoff.next_delay().await.is_none() {
                return Err(AuthError::ServiceUnavailable {
                    reason: "HTTP request failed after all retries".to_string(),
                });
            }
        }
    }
}

pub struct ResilientResponse {
    response: Response,
}

impl ResilientResponse {
    pub fn status(&self) -> reqwest::StatusCode {
        self.response.status()
    }

    pub fn headers(&self) -> &reqwest::header::HeaderMap {
        self.response.headers()
    }

    pub fn url(&self) -> &reqwest::Url {
        self.response.url()
    }

    pub async fn text(self) -> Result<String, AuthError> {
        self.response.text().await.map_err(|e| AuthError::ServiceUnavailable {
            reason: format!("Failed to read response text: {}", e),
        })
    }

    pub async fn bytes(self) -> Result<Bytes, AuthError> {
        self.response.bytes().await.map_err(|e| AuthError::ServiceUnavailable {
            reason: format!("Failed to read response bytes: {}", e),
        })
    }

    pub async fn json<T: for<'de> Deserialize<'de>>(self) -> Result<T, AuthError> {
        self.response.json().await.map_err(|e| AuthError::ValidationError {
            field: "response".to_string(),
            reason: format!("Failed to parse JSON response: {}", e),
        })
    }

    pub fn error_for_status(self) -> Result<Self, AuthError> {
        let status = self.response.status();
        
        if status.is_client_error() || status.is_server_error() {
            Err(AuthError::ServiceUnavailable {
                reason: format!("HTTP error {}: {}", status.as_u16(), status.canonical_reason().unwrap_or("Unknown")),
            })
        } else {
            Ok(self)
        }
    }
}

// Pre-configured HTTP clients for common services
pub struct OidcHttpClient {
    client: ResilientHttpClient,
}

impl OidcHttpClient {
    pub fn new(provider: &str) -> Result<Self, AuthError> {
        let config = ResilientHttpConfig {
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
                ..Default::default()
            },
            retry: RetryConfig {
                max_retries: 2,
                base_delay: Duration::from_millis(1000),
                max_delay: Duration::from_secs(10),
                ..Default::default()
            },
            user_agent: format!("auth-service/1.0 (OIDC-{})", provider),
            ..Default::default()
        };

        let client = ResilientHttpClient::new(format!("oidc-{}", provider), config)?;
        Ok(Self { client })
    }

    pub fn get(&self, url: &str) -> ResilientRequestBuilder {
        self.client.get(url)
    }

    pub fn post(&self, url: &str) -> ResilientRequestBuilder {
        self.client.post(url)
    }

    pub fn stats(&self) -> crate::circuit_breaker::CircuitBreakerStats {
        self.client.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resilient_http_config() {
        let config = ResilientHttpConfig::default();
        assert_eq!(config.circuit_breaker.failure_threshold, 5);
        assert_eq!(config.timeouts.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.retry.max_retries, 3);
        assert_eq!(config.max_redirects, 10);
    }

    #[test]
    fn test_oidc_client_creation() {
        let client = OidcHttpClient::new("google");
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_circuit_breaker_integration() {
        let config = ResilientHttpConfig {
            circuit_breaker: CircuitBreakerConfig {
                failure_threshold: 1,
                minimum_request_threshold: 1,
                request_timeout: Duration::from_millis(50),
                ..Default::default()
            },
            ..Default::default()
        };

        // This test would require a mock HTTP server to be fully functional
        // For now, we just test that the client can be created
        let result = ResilientHttpClient::new("test", config);
        assert!(result.is_ok());
    }
}