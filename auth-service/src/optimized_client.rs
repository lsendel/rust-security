// Phase 2: Optimized Service Client Integration for Auth Service
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::{RwLock, Semaphore};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn, instrument};
use uuid::Uuid;
use prometheus::{Counter, Histogram, Gauge, Registry};

/// High-performance service client optimized for auth service communication
#[derive(Clone)]
pub struct AuthServiceClient {
    policy_client: Client,
    policy_base_url: String,
    circuit_breaker: Arc<CircuitBreaker>,
    cache: Arc<RwLock<HashMap<String, CachedResponse>>>,
    semaphore: Arc<Semaphore>,
    metrics: Arc<ClientMetrics>,
    batch_processor: Arc<RwLock<BatchProcessor>>,
}

#[derive(Debug, Clone)]
struct CachedResponse {
    data: serde_json::Value,
    expires_at: Instant,
    hit_count: u64,
}

#[derive(Debug)]
pub struct ClientMetrics {
    pub requests_total: Counter,
    pub request_duration: Histogram,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub circuit_breaker_opens: Counter,
    pub batch_requests: Counter,
    pub batch_efficiency: Histogram,
}

impl AuthServiceClient {
    pub fn new(
        policy_service_url: String,
        max_concurrent_requests: usize,
        registry: &Registry,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Build optimized HTTP client for policy service communication
        let policy_client = ClientBuilder::new()
            .timeout(Duration::from_millis(50))  // Very aggressive timeout for Phase 2
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(30)  // Increased pool size
            .http2_prior_knowledge()  // Force HTTP/2
            .http2_keep_alive_interval(Duration::from_secs(20))
            .http2_keep_alive_timeout(Duration::from_secs(5))
            .http2_adaptive_window(true)  // Adaptive flow control
            .tcp_keepalive(Duration::from_secs(30))
            .tcp_nodelay(true)
            .connection_verbose(false)
            .build()?;

        let circuit_breaker = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,  // More aggressive for Phase 2
            timeout: Duration::from_millis(500),
            recovery_timeout: Duration::from_secs(15),
        }));

        let cache = Arc::new(RwLock::new(HashMap::new()));
        let semaphore = Arc::new(Semaphore::new(max_concurrent_requests));
        let metrics = Arc::new(ClientMetrics::new(registry)?);
        let batch_processor = Arc::new(RwLock::new(BatchProcessor::new(
            50,
            Duration::from_millis(10),
        )));

        Ok(Self {
            policy_client,
            policy_base_url: policy_service_url,
            circuit_breaker,
            cache,
            semaphore,
            metrics,
            batch_processor,
        })
    }

    /// High-performance policy evaluation with intelligent caching
    #[instrument(skip(self), fields(request_id = %Uuid::new_v4()))]
    pub async fn evaluate_policy(
        &self,
        request: PolicyRequest,
    ) -> Result<PolicyResponse, ClientError> {
        let start = Instant::now();
        
        // Check L1 cache first (in-memory)
        let cache_key = self.generate_cache_key(&request);
        if let Some(cached) = self.get_cached_response(&cache_key).await {
            self.metrics.cache_hits.inc();
            debug!("L1 cache hit for policy evaluation");
            return Ok(serde_json::from_value(cached.data)?);
        }
        
        self.metrics.cache_misses.inc();

        // Use batch processor for efficiency
        let response = self.batch_processor.write().await
            .add_request(request.clone())
            .await?;

        // Cache successful responses with intelligent TTL
        if matches!(response.decision, PolicyDecision::Allow) {
            let ttl = self.calculate_cache_ttl(&request);
            self.cache_response(&cache_key, &response, ttl).await;
        }

        let duration = start.elapsed();
        self.metrics.request_duration.observe(duration.as_secs_f64());
        self.metrics.requests_total.inc();

        debug!("Policy evaluation completed in {:?}", duration);
        Ok(response)
    }

    /// Batch multiple policy evaluations for maximum efficiency
    #[instrument(skip(self))]
    pub async fn evaluate_policies_batch(
        &self,
        requests: Vec<PolicyRequest>,
    ) -> Result<Vec<PolicyResponse>, ClientError> {
        let start = Instant::now();
        let batch_id = Uuid::new_v4();
        
        info!("Starting batch policy evaluation for {} requests", requests.len());

        // Separate cached and uncached requests
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

        // Process uncached requests in optimized batches
        let uncached_results = if !uncached_requests.is_empty() {
            self.execute_batch_policy_requests(uncached_requests).await?
        } else {
            Vec::new()
        };

        // Combine results maintaining original order
        let mut final_responses = vec![None; requests.len()];
        
        // Insert cached responses
        for (index, response) in cached_responses {
            final_responses[index] = Some(response);
        }

        // Insert uncached responses
        for (i, response) in uncached_results.into_iter().enumerate() {
            let original_index = request_indices[i];
            final_responses[original_index] = Some(response);
        }

        let responses: Vec<PolicyResponse> = final_responses.into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(ClientError::InternalError("Missing responses".to_string()))?;

        let duration = start.elapsed();
        let efficiency = requests.len() as f64 / duration.as_secs_f64();
        self.metrics.batch_efficiency.observe(efficiency);
        self.metrics.batch_requests.inc();

        info!("Batch evaluation completed in {:?} (efficiency: {:.2} req/s)", duration, efficiency);
        Ok(responses)
    }

    async fn execute_batch_policy_requests(
        &self,
        requests: Vec<PolicyRequest>,
    ) -> Result<Vec<PolicyResponse>, ClientError> {
        // Acquire semaphore for rate limiting
        let _permit = self.semaphore.acquire().await.map_err(|_| ClientError::RateLimited)?;

        // Execute through circuit breaker
        self.circuit_breaker.call(async {
            let batch_request = BatchPolicyRequest { requests };
            
            let response = self.policy_client
                .post(&format!("{}/evaluate/batch", self.policy_base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .header("User-Agent", "rust-security-auth/2.0")
                .header("X-Batch-Size", batch_request.requests.len().to_string())
                .json(&batch_request)
                .send()
                .await
                .map_err(ClientError::RequestError)?;

            if !response.status().is_success() {
                return Err(ClientError::HttpError(response.status().as_u16()));
            }

            let batch_response: BatchPolicyResponse = response
                .json()
                .await
                .map_err(ClientError::DeserializationError)?;

            Ok(batch_response.responses)
        }).await.map_err(ClientError::CircuitBreakerError)
    }

    async fn get_cached_response(&self, key: &str) -> Option<CachedResponse> {
        let mut cache = self.cache.write().await;
        if let Some(cached) = cache.get_mut(key) {
            if cached.expires_at > Instant::now() {
                cached.hit_count += 1;
                return Some(cached.clone());
            } else {
                // Remove expired entry
                cache.remove(key);
            }
        }
        None
    }

    async fn cache_response(&self, key: &str, response: &PolicyResponse, ttl: Duration) {
        let cached = CachedResponse {
            data: serde_json::to_value(response).unwrap_or_default(),
            expires_at: Instant::now() + ttl,
            hit_count: 0,
        };
        
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), cached);
        
        // Intelligent cache cleanup - remove expired and least used entries
        if cache.len() > 10000 {  // Max cache size
            let now = Instant::now();
            cache.retain(|_, v| v.expires_at > now && v.hit_count > 0);
        }
    }

    fn generate_cache_key(&self, request: &PolicyRequest) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        request.principal.hash(&mut hasher);
        request.action.hash(&mut hasher);
        request.resource.hash(&mut hasher);
        // Don't hash context for better cache hit rates on similar requests
        format!("policy:{}:{}", hasher.finish(), request.priority.unwrap_or(0))
    }

    fn calculate_cache_ttl(&self, request: &PolicyRequest) -> Duration {
        match request.action.as_str() {
            "read" => Duration::from_secs(300),      // 5 minutes for read operations
            "write" | "update" => Duration::from_secs(60),  // 1 minute for write operations
            "delete" => Duration::from_secs(30),     // 30 seconds for delete operations
            "admin" => Duration::from_secs(10),      // 10 seconds for admin operations
            _ => Duration::from_secs(120),           // 2 minutes default
        }
    }

    /// Get cache statistics for monitoring
    pub async fn get_cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let total_entries = cache.len();
        let expired_entries = cache.values()
            .filter(|v| v.expires_at <= Instant::now())
            .count();
        let total_hits: u64 = cache.values().map(|v| v.hit_count).sum();

        CacheStats {
            total_entries,
            expired_entries,
            active_entries: total_entries - expired_entries,
            total_hits,
            hit_rate: if total_hits > 0 { 
                total_hits as f64 / (total_hits + self.metrics.cache_misses.get() as u64) as f64 
            } else { 
                0.0 
            },
        }
    }
}

/// Batch processor for efficient policy evaluation
pub struct BatchProcessor {
    max_batch_size: usize,
    batch_timeout: Duration,
    pending_requests: Vec<(PolicyRequest, tokio::sync::oneshot::Sender<PolicyResponse>)>,
    last_batch_time: Instant,
}

impl BatchProcessor {
    pub fn new(max_batch_size: usize, batch_timeout: Duration) -> Self {
        Self {
            max_batch_size,
            batch_timeout,
            pending_requests: Vec::new(),
            last_batch_time: Instant::now(),
        }
    }

    pub async fn add_request(
        &mut self,
        request: PolicyRequest,
    ) -> Result<PolicyResponse, ClientError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending_requests.push((request, tx));

        // Check if we should process batch immediately
        if self.pending_requests.len() >= self.max_batch_size 
            || self.last_batch_time.elapsed() >= self.batch_timeout {
            self.process_batch().await?;
        }

        // Wait for response
        rx.await.map_err(|_| ClientError::InternalError("Request cancelled".to_string()))
    }

    async fn process_batch(&mut self) -> Result<(), ClientError> {
        if self.pending_requests.is_empty() {
            return Ok(());
        }

        let batch = std::mem::take(&mut self.pending_requests);
        self.last_batch_time = Instant::now();

        // For now, simulate batch processing
        // In real implementation, this would call the policy service batch endpoint
        for (request, sender) in batch {
            let response = PolicyResponse {
                decision: PolicyDecision::Allow, // Simplified for demo
                reasons: vec!["Batch processed".to_string()],
                obligations: vec![],
                evaluation_time_ms: 1,
            };
            let _ = sender.send(response);
        }

        Ok(())
    }
}

/// Circuit breaker for fault tolerance
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
    success_count: u32,
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
                success_count: 0,
            })),
            config,
        }
    }

    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        // Check circuit state
        {
            let state = self.state.read().await;
            match state.state {
                BreakerState::Open => {
                    if let Some(last_failure) = state.last_failure {
                        if last_failure.elapsed() < self.config.recovery_timeout {
                            return Err(CircuitBreakerError::CircuitOpen);
                        }
                    }
                    // Transition to half-open
                }
                BreakerState::HalfOpen => {
                    // Allow limited requests in half-open state
                }
                BreakerState::Closed => {
                    // Normal operation
                }
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
        state.success_count += 1;
        
        match state.state {
            BreakerState::HalfOpen => {
                if state.success_count >= 3 {  // Require 3 successes to close
                    state.state = BreakerState::Closed;
                    state.failures = 0;
                    state.success_count = 0;
                }
            }
            BreakerState::Closed => {
                state.failures = 0;  // Reset failure count on success
            }
            _ => {}
        }
    }

    async fn on_failure(&self) {
        let mut state = self.state.write().await;
        state.failures += 1;
        state.last_failure = Some(Instant::now());
        state.success_count = 0;

        if state.failures >= self.config.failure_threshold {
            state.state = BreakerState::Open;
            warn!("Circuit breaker opened after {} failures", state.failures);
        }
    }

    pub async fn get_state(&self) -> (BreakerState, u32, u32) {
        let state = self.state.read().await;
        (state.state, state.failures, state.success_count)
    }
}

impl ClientMetrics {
    fn new(registry: &Registry) -> Result<Self, Box<dyn std::error::Error>> {
        use prometheus::{Opts, HistogramOpts};

        let requests_total = Counter::with_opts(
            Opts::new("auth_client_requests_total", "Total auth service client requests")
        )?;

        let request_duration = Histogram::with_opts(
            HistogramOpts::new(
                "auth_client_request_duration_seconds",
                "Auth client request duration",
            )
            .buckets(vec![0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1]) // Optimized for sub-5ms targets
        )?;

        let cache_hits = Counter::with_opts(
            Opts::new("auth_client_cache_hits_total", "Total cache hits")
        )?;

        let cache_misses = Counter::with_opts(
            Opts::new("auth_client_cache_misses_total", "Total cache misses")
        )?;

        let circuit_breaker_opens = Counter::with_opts(
            Opts::new("auth_client_circuit_breaker_opens_total", "Circuit breaker opens")
        )?;

        let batch_requests = Counter::with_opts(
            Opts::new("auth_client_batch_requests_total", "Total batch requests")
        )?;

        let batch_efficiency = Histogram::with_opts(
            HistogramOpts::new(
                "auth_client_batch_efficiency",
                "Batch processing efficiency (req/s)",
            )
                .buckets(vec![10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0, 10000.0])
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration.clone()))?;
        registry.register(Box::new(cache_hits.clone()))?;
        registry.register(Box::new(cache_misses.clone()))?;
        registry.register(Box::new(circuit_breaker_opens.clone()))?;
        registry.register(Box::new(batch_requests.clone()))?;
        registry.register(Box::new(batch_efficiency.clone()))?;

        Ok(Self {
            requests_total,
            request_duration,
            cache_hits,
            cache_misses,
            circuit_breaker_opens,
            batch_requests,
            batch_efficiency,
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
    pub priority: Option<u8>,  // For cache TTL calculation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub decision: PolicyDecision,
    pub reasons: Vec<String>,
    pub obligations: Vec<String>,
    pub evaluation_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchPolicyRequest {
    pub requests: Vec<PolicyRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchPolicyResponse {
    pub responses: Vec<PolicyResponse>,
}

#[derive(Debug)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub active_entries: usize,
    pub total_hits: u64,
    pub hit_rate: f64,
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
    async fn test_cache_ttl_calculation() {
        let registry = Registry::new();
        let client = AuthServiceClient::new(
            "http://localhost:8081".to_string(),
            10,
            &registry,
        ).unwrap();
        
        let read_request = PolicyRequest {
            principal: "user:123".to_string(),
            action: "read".to_string(),
            resource: "document:456".to_string(),
            context: HashMap::new(),
            priority: Some(1),
        };
        
        let ttl = client.calculate_cache_ttl(&read_request);
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    async fn test_circuit_breaker_state_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            timeout: Duration::from_millis(100),
            recovery_timeout: Duration::from_secs(1),
        };
        
        let breaker = CircuitBreaker::new(config);
        
        // Test failure accumulation
        let _ = breaker.call(async { Err::<(), _>("failure") }).await;
        let _ = breaker.call(async { Err::<(), _>("failure") }).await;
        
        let (state, failures, _) = breaker.get_state().await;
        assert_eq!(state, BreakerState::Open);
        assert_eq!(failures, 2);
    }
}
