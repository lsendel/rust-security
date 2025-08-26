// Optimized Service Client for High-Performance Inter-Service Communication
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::{RwLock, Semaphore};
use reqwest::{Client, ClientBuilder, Response};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// High-performance service client with connection pooling, circuit breaking, and caching
#[derive(Clone)]
pub struct OptimizedServiceClient {
    client: Client,
    base_url: String,
    circuit_breaker: Arc<CircuitBreaker>,
    cache: Arc<RwLock<HashMap<String, CachedResponse>>>,
    semaphore: Arc<Semaphore>,
    metrics: Arc<ClientMetrics>,
}

#[derive(Debug, Clone)]
struct CachedResponse {
    data: serde_json::Value,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct ClientMetrics {
    pub requests_total: prometheus::Counter,
    pub request_duration: prometheus::Histogram,
    pub cache_hits: prometheus::Counter,
    pub cache_misses: prometheus::Counter,
    pub circuit_breaker_opens: prometheus::Counter,
}

impl OptimizedServiceClient {
    pub fn new(base_url: String, max_concurrent_requests: usize) -> Result<Self, Box<dyn std::error::Error>> {
        // Build optimized HTTP client
        let client = ClientBuilder::new()
            .timeout(Duration::from_millis(100))  // Aggressive timeout for sub-5ms target
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(20)
            .http2_prior_knowledge()  // Force HTTP/2 for better multiplexing
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true)  // Disable Nagle's algorithm for lower latency
            .connection_verbose(false)
            .build()?;

        let circuit_breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            timeout: Duration::from_millis(1000),
            recovery_timeout: Duration::from_secs(30),
        }));

        let cache = Arc::new(RwLock::new(HashMap::new()));
        let semaphore = Arc::new(Semaphore::new(max_concurrent_requests));

        let metrics = Arc::new(ClientMetrics::new()?);

        Ok(Self {
            client,
            base_url,
            circuit_breaker,
            cache,
            semaphore,
            metrics,
        })
    }

    /// High-performance policy evaluation with caching and batching
    pub async fn evaluate_policy(&self, request: PolicyRequest) -> Result<PolicyResponse, ClientError> {
        let start = Instant::now();
        let request_id = Uuid::new_v4();
        
        debug!("Starting policy evaluation for request {}", request_id);

        // Check cache first
        let cache_key = self.generate_cache_key(&request);
        if let Some(cached) = self.get_cached_response(&cache_key).await {
            self.metrics.cache_hits.inc();
            debug!("Cache hit for request {}", request_id);
            return Ok(serde_json::from_value(cached.data)?);
        }
        self.metrics.cache_misses.inc();

        // Acquire semaphore for rate limiting
        let _permit = self.semaphore.acquire().await.map_err(|_| ClientError::RateLimited)?;

        // Execute request through circuit breaker
        let response = self.circuit_breaker.call(async {
            self.execute_policy_request(request).await
        }).await?;

        // Cache successful responses
        if response.decision == PolicyDecision::Allow {
            self.cache_response(&cache_key, &response, Duration::from_secs(300)).await;
        }

        let duration = start.elapsed();
        self.metrics.request_duration.observe(duration.as_secs_f64());
        self.metrics.requests_total.inc();

        debug!("Policy evaluation completed in {:?} for request {}", duration, request_id);
        Ok(response)
    }

    /// Batch multiple policy requests for better throughput
    pub async fn evaluate_policies_batch(&self, requests: Vec<PolicyRequest>) -> Result<Vec<PolicyResponse>, ClientError> {
        let start = Instant::now();
        let batch_id = Uuid::new_v4();
        
        info!("Starting batch policy evaluation for {} requests (batch {})", requests.len(), batch_id);

        // Split into cached and non-cached requests
        let mut cached_responses = Vec::new();
        let mut uncached_requests = Vec::new();
        let mut request_indices = Vec::new();

        for (index, request) in requests.iter().enumerate() {
            let cache_key = self.generate_cache_key(request);
            if let Some(cached) = self.get_cached_response(&cache_key).await {
                cached_responses.push((index, serde_json::from_value(cached.data)?));
                self.metrics.cache_hits.inc();
            } else {
                uncached_requests.push(request.clone());
                request_indices.push(index);
                self.metrics.cache_misses.inc();
            }
        }

        // Execute uncached requests in parallel
        let mut futures = Vec::new();
        for request in uncached_requests {
            let client = self.clone();
            futures.push(tokio::spawn(async move {
                client.execute_policy_request(request).await
            }));
        }

        let uncached_results = futures::future::join_all(futures).await;
        
        // Combine results maintaining original order
        let mut final_responses = vec![None; requests.len()];
        
        // Insert cached responses
        for (index, response) in cached_responses {
            final_responses[index] = Some(response);
        }

        // Insert uncached responses
        for (i, result) in uncached_results.into_iter().enumerate() {
            match result {
                Ok(Ok(response)) => {
                    let original_index = request_indices[i];
                    final_responses[original_index] = Some(response);
                }
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(ClientError::TaskJoinError(e.to_string())),
            }
        }

        let responses: Result<Vec<_>, _> = final_responses.into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(ClientError::InternalError("Missing responses".to_string()))?
            .into_iter()
            .collect::<Result<Vec<_>, _>>();

        let duration = start.elapsed();
        info!("Batch policy evaluation completed in {:?} for batch {}", duration, batch_id);

        responses
    }

    async fn execute_policy_request(&self, request: PolicyRequest) -> Result<PolicyResponse, ClientError> {
        let response = self.client
            .post(&format!("{}/evaluate", self.base_url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("User-Agent", "rust-security-client/1.0")
            .json(&request)
            .send()
            .await
            .map_err(ClientError::RequestError)?;

        if !response.status().is_success() {
            return Err(ClientError::HttpError(response.status().as_u16()));
        }

        let policy_response: PolicyResponse = response
            .json()
            .await
            .map_err(ClientError::DeserializationError)?;

        Ok(policy_response)
    }

    async fn get_cached_response(&self, key: &str) -> Option<CachedResponse> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(key) {
            if cached.expires_at > Instant::now() {
                return Some(cached.clone());
            }
        }
        None
    }

    async fn cache_response(&self, key: &str, response: &PolicyResponse, ttl: Duration) {
        let cached = CachedResponse {
            data: serde_json::to_value(response).unwrap_or_default(),
            expires_at: Instant::now() + ttl,
        };
        
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), cached);
        
        // Simple cache cleanup - remove expired entries
        cache.retain(|_, v| v.expires_at > Instant::now());
    }

    fn generate_cache_key(&self, request: &PolicyRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        request.hash(&mut hasher);
        format!("policy:{:x}", hasher.finish())
    }
}

/// Circuit breaker implementation for fault tolerance
#[derive(Debug)]
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitState>>,
    config: CircuitBreakerConfig,
}

#[derive(Debug)]
struct CircuitState {
    failures: u32,
    last_failure: Option<Instant>,
    state: BreakerState,
}

#[derive(Debug, PartialEq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub timeout: Duration,
    pub recovery_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitState {
                failures: 0,
                last_failure: None,
                state: BreakerState::Closed,
            })),
            config,
        }
    }

    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        // Check if circuit is open
        {
            let state = self.state.read().await;
            if state.state == BreakerState::Open {
                if let Some(last_failure) = state.last_failure {
                    if last_failure.elapsed() < self.config.recovery_timeout {
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                }
                // Transition to half-open
                drop(state);
                let mut state = self.state.write().await;
                state.state = BreakerState::HalfOpen;
            }
        }

        // Execute the function
        match f.await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(e) => {
                self.on_failure().await;
                Err(CircuitBreakerError::ServiceError(e))
            }
        }
    }

    async fn on_success(&self) {
        let mut state = self.state.write().await;
        state.failures = 0;
        state.state = BreakerState::Closed;
    }

    async fn on_failure(&self) {
        let mut state = self.state.write().await;
        state.failures += 1;
        state.last_failure = Some(Instant::now());

        if state.failures >= self.config.failure_threshold {
            state.state = BreakerState::Open;
            warn!("Circuit breaker opened after {} failures", state.failures);
        }
    }
}

impl ClientMetrics {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        use prometheus::{Counter, Histogram, HistogramOpts, Opts};

        let requests_total = Counter::with_opts(
            Opts::new("client_requests_total", "Total number of client requests")
        )?;

        let request_duration = Histogram::with_opts(
            HistogramOpts::new("client_request_duration_seconds", "Client request duration")
                .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5])
        )?;

        let cache_hits = Counter::with_opts(
            Opts::new("client_cache_hits_total", "Total cache hits")
        )?;

        let cache_misses = Counter::with_opts(
            Opts::new("client_cache_misses_total", "Total cache misses")
        )?;

        let circuit_breaker_opens = Counter::with_opts(
            Opts::new("client_circuit_breaker_opens_total", "Circuit breaker opens")
        )?;

        Ok(Self {
            requests_total,
            request_duration,
            cache_hits,
            cache_misses,
            circuit_breaker_opens,
        })
    }
}

// Request/Response types
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct PolicyRequest {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
    pub obligations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("HTTP error: {0}")]
    HttpError(u16),
    #[error("Deserialization error: {0}")]
    DeserializationError(reqwest::Error),
    #[error("Rate limited")]
    RateLimited,
    #[error("Task join error: {0}")]
    TaskJoinError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Circuit breaker error: {0}")]
    CircuitBreakerError(#[from] CircuitBreakerError<reqwest::Error>),
}

#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    #[error("Circuit breaker is open")]
    CircuitOpen,
    #[error("Service error: {0}")]
    ServiceError(E),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_circuit_breaker() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            timeout: Duration::from_millis(100),
            recovery_timeout: Duration::from_secs(1),
        };
        
        let breaker = CircuitBreaker::new(config);
        
        // Test successful calls
        let result = breaker.call(async { Ok::<_, ()>("success") }).await;
        assert!(result.is_ok());
        
        // Test failure threshold
        for _ in 0..3 {
            let _ = breaker.call(async { Err::<(), _>("failure") }).await;
        }
        
        // Circuit should be open now
        let result = breaker.call(async { Ok::<_, ()>("should_fail") }).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }

    #[test]
    async fn test_cache_functionality() {
        let client = OptimizedServiceClient::new(
            "http://localhost:8081".to_string(),
            10
        ).unwrap();
        
        let request = PolicyRequest {
            principal: "user:123".to_string(),
            action: "read".to_string(),
            resource: "document:456".to_string(),
            context: HashMap::new(),
        };
        
        let cache_key = client.generate_cache_key(&request);
        assert!(!cache_key.is_empty());
        
        // Test cache miss
        let cached = client.get_cached_response(&cache_key).await;
        assert!(cached.is_none());
    }
}
