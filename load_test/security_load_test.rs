use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;
use tracing::{info, warn, error};
use clap::{Parser, Subcommand};
use futures::future::join_all;
use std::collections::HashMap;

/// Comprehensive load testing suite for security endpoints
/// Tests various scenarios including normal load, burst traffic, and attack simulations

#[derive(Parser)]
#[command(name = "security-load-test")]
#[command(about = "Comprehensive security endpoint load testing")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Base URL of the auth service
    #[arg(short, long, default_value = "http://localhost:8080")]
    base_url: String,

    /// Number of concurrent clients
    #[arg(short, long, default_value = "100")]
    clients: usize,

    /// Test duration in seconds
    #[arg(short, long, default_value = "60")]
    duration: u64,

    /// Output results to file
    #[arg(short, long)]
    output: Option<String>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Test token endpoint performance
    TokenEndpoint {
        /// Requests per second per client
        #[arg(long, default_value = "10")]
        rps: u64,
    },
    /// Test introspection endpoint performance
    Introspection {
        /// Requests per second per client
        #[arg(long, default_value = "50")]
        rps: u64,
    },
    /// Simulate attack scenarios
    AttackSimulation {
        /// Type of attack to simulate
        #[arg(long, value_enum)]
        attack_type: AttackType,
    },
    /// Run comprehensive mixed workload test
    MixedWorkload {
        /// Distribution of request types
        #[arg(long, default_value = "token:20,introspect:70,userinfo:10")]
        distribution: String,
    },
    /// Test rate limiting effectiveness
    RateLimitTest {
        /// Requests per second to send
        #[arg(long, default_value = "1000")]
        target_rps: u64,
    },
    /// Test circuit breaker behavior
    CircuitBreakerTest,
    /// Stress test with gradually increasing load
    StressTest {
        /// Starting RPS
        #[arg(long, default_value = "10")]
        start_rps: u64,
        /// Maximum RPS
        #[arg(long, default_value = "1000")]
        max_rps: u64,
        /// RPS increment interval (seconds)
        #[arg(long, default_value = "30")]
        increment_interval: u64,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum AttackType {
    /// Credential stuffing attack simulation
    CredentialStuffing,
    /// Brute force attack simulation
    BruteForce,
    /// Token enumeration attack
    TokenEnumeration,
    /// Distributed denial of service
    DDoS,
}

#[derive(Debug, Clone)]
struct TestResult {
    endpoint: String,
    method: String,
    status: u16,
    duration: Duration,
    response_size: usize,
    timestamp: Instant,
    client_id: usize,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct TestMetrics {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    rate_limited_requests: u64,
    avg_response_time: Duration,
    max_response_time: Duration,
    min_response_time: Duration,
    p95_response_time: Duration,
    p99_response_time: Duration,
    throughput_rps: f64,
    error_rate: f64,
    status_codes: HashMap<u16, u64>,
}

struct LoadTestExecutor {
    client: Client,
    base_url: String,
    results: Arc<RwLock<Vec<TestResult>>>,
    semaphore: Arc<Semaphore>,
}

impl LoadTestExecutor {
    fn new(base_url: String, max_concurrent: usize) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(max_concurrent)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url,
            results: Arc::new(RwLock::new(Vec::new())),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    /// Execute token endpoint load test
    async fn test_token_endpoint(&self, clients: usize, duration: Duration, rps: u64) -> TestMetrics {
        info!("Starting token endpoint load test: {} clients, {} RPS, {:?} duration", 
              clients, rps, duration);

        let start_time = Instant::now();
        let mut handles = Vec::new();

        for client_id in 0..clients {
            let executor = self.clone();
            let handle = tokio::spawn(async move {
                executor.run_token_requests(client_id, duration, rps).await
            });
            handles.push(handle);
        }

        // Wait for all clients to complete
        join_all(handles).await;

        info!("Token endpoint load test completed in {:?}", start_time.elapsed());
        self.calculate_metrics().await
    }

    /// Execute introspection endpoint load test
    async fn test_introspection_endpoint(&self, clients: usize, duration: Duration, rps: u64) -> TestMetrics {
        info!("Starting introspection endpoint load test: {} clients, {} RPS, {:?} duration", 
              clients, rps, duration);

        // First, generate some tokens to introspect
        let tokens = self.generate_test_tokens(1000).await;
        if tokens.is_empty() {
            error!("Failed to generate test tokens");
            return self.calculate_metrics().await;
        }

        let start_time = Instant::now();
        let mut handles = Vec::new();
        let tokens = Arc::new(tokens);

        for client_id in 0..clients {
            let executor = self.clone();
            let tokens = tokens.clone();
            let handle = tokio::spawn(async move {
                executor.run_introspection_requests(client_id, duration, rps, tokens).await
            });
            handles.push(handle);
        }

        join_all(handles).await;
        info!("Introspection endpoint load test completed in {:?}", start_time.elapsed());
        self.calculate_metrics().await
    }

    /// Simulate attack scenarios
    async fn simulate_attack(&self, attack_type: AttackType, clients: usize, duration: Duration) -> TestMetrics {
        info!("Simulating {:?} attack with {} clients for {:?}", attack_type, clients, duration);

        let start_time = Instant::now();
        let mut handles = Vec::new();

        for client_id in 0..clients {
            let executor = self.clone();
            let attack_type = attack_type.clone();
            let handle = tokio::spawn(async move {
                executor.run_attack_simulation(client_id, attack_type, duration).await
            });
            handles.push(handle);
        }

        join_all(handles).await;
        info!("Attack simulation completed in {:?}", start_time.elapsed());
        self.calculate_metrics().await
    }

    /// Run mixed workload test
    async fn test_mixed_workload(&self, clients: usize, duration: Duration, distribution: &str) -> TestMetrics {
        info!("Starting mixed workload test: {} clients, {:?} duration", clients, duration);

        let dist = self.parse_distribution(distribution);
        let start_time = Instant::now();
        let mut handles = Vec::new();

        for client_id in 0..clients {
            let executor = self.clone();
            let dist = dist.clone();
            let handle = tokio::spawn(async move {
                executor.run_mixed_workload(client_id, duration, dist).await
            });
            handles.push(handle);
        }

        join_all(handles).await;
        info!("Mixed workload test completed in {:?}", start_time.elapsed());
        self.calculate_metrics().await
    }

    /// Test rate limiting effectiveness
    async fn test_rate_limiting(&self, target_rps: u64, duration: Duration) -> TestMetrics {
        info!("Testing rate limiting with target {} RPS for {:?}", target_rps, duration);

        let interval = Duration::from_nanos(1_000_000_000 / target_rps);
        let start_time = Instant::now();
        let end_time = start_time + duration;

        while Instant::now() < end_time {
            let request_start = Instant::now();
            
            let result = self.make_token_request(0).await;
            let duration = request_start.elapsed();

            self.record_result(TestResult {
                endpoint: "/oauth/token".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration,
                response_size: result.response_size,
                timestamp: request_start,
                client_id: 0,
                error: result.error,
            }).await;

            // Wait for next request
            if duration < interval {
                sleep(interval - duration).await;
            }
        }

        info!("Rate limiting test completed");
        self.calculate_metrics().await
    }

    /// Test circuit breaker behavior
    async fn test_circuit_breaker(&self, duration: Duration) -> TestMetrics {
        info!("Testing circuit breaker behavior for {:?}", duration);

        let start_time = Instant::now();
        let end_time = start_time + duration;

        // Phase 1: Normal requests to establish baseline
        info!("Phase 1: Normal requests");
        for _ in 0..50 {
            let result = self.make_token_request(0).await;
            self.record_result(TestResult {
                endpoint: "/oauth/token".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration: Duration::from_millis(1),
                response_size: result.response_size,
                timestamp: Instant::now(),
                client_id: 0,
                error: result.error,
            }).await;
        }

        // Phase 2: Trigger circuit breaker with bad requests
        info!("Phase 2: Triggering circuit breaker");
        for _ in 0..20 {
            let result = self.make_bad_request().await;
            self.record_result(TestResult {
                endpoint: "/oauth/token".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration: Duration::from_millis(1),
                response_size: result.response_size,
                timestamp: Instant::now(),
                client_id: 0,
                error: result.error,
            }).await;
        }

        // Phase 3: Test if circuit breaker is open
        info!("Phase 3: Testing circuit breaker state");
        while Instant::now() < end_time {
            let result = self.make_token_request(0).await;
            self.record_result(TestResult {
                endpoint: "/oauth/token".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration: Duration::from_millis(1),
                response_size: result.response_size,
                timestamp: Instant::now(),
                client_id: 0,
                error: result.error,
            }).await;

            sleep(Duration::from_millis(100)).await;
        }

        info!("Circuit breaker test completed");
        self.calculate_metrics().await
    }

    /// Stress test with gradually increasing load
    async fn stress_test(&self, start_rps: u64, max_rps: u64, increment_interval: Duration) -> TestMetrics {
        info!("Starting stress test: {} -> {} RPS, increment every {:?}", 
              start_rps, max_rps, increment_interval);

        let mut current_rps = start_rps;
        let increment = (max_rps - start_rps) / 10; // 10 steps

        while current_rps <= max_rps {
            info!("Stress testing at {} RPS", current_rps);
            
            let interval = Duration::from_nanos(1_000_000_000 / current_rps);
            let phase_start = Instant::now();
            let phase_end = phase_start + increment_interval;

            while Instant::now() < phase_end {
                let request_start = Instant::now();
                
                let result = self.make_token_request(0).await;
                self.record_result(TestResult {
                    endpoint: "/oauth/token".to_string(),
                    method: "POST".to_string(),
                    status: result.status_code,
                    duration: request_start.elapsed(),
                    response_size: result.response_size,
                    timestamp: request_start,
                    client_id: 0,
                    error: result.error,
                }).await;

                if request_start.elapsed() < interval {
                    sleep(interval - request_start.elapsed()).await;
                }
            }

            current_rps += increment;
        }

        info!("Stress test completed");
        self.calculate_metrics().await
    }

    // Helper methods for specific request types

    async fn run_token_requests(&self, client_id: usize, duration: Duration, rps: u64) {
        let interval = Duration::from_nanos(1_000_000_000 / rps);
        let start_time = Instant::now();
        let end_time = start_time + duration;

        while Instant::now() < end_time {
            let request_start = Instant::now();
            
            let result = self.make_token_request(client_id).await;
            let request_duration = request_start.elapsed();

            self.record_result(TestResult {
                endpoint: "/oauth/token".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration: request_duration,
                response_size: result.response_size,
                timestamp: request_start,
                client_id,
                error: result.error,
            }).await;

            // Rate limiting
            if request_duration < interval {
                sleep(interval - request_duration).await;
            }
        }
    }

    async fn run_introspection_requests(&self, client_id: usize, duration: Duration, rps: u64, tokens: Arc<Vec<String>>) {
        let interval = Duration::from_nanos(1_000_000_000 / rps);
        let start_time = Instant::now();
        let end_time = start_time + duration;

        while Instant::now() < end_time {
            let request_start = Instant::now();
            
            let token = &tokens[rand::random::<usize>() % tokens.len()];
            let result = self.make_introspection_request(token).await;
            let request_duration = request_start.elapsed();

            self.record_result(TestResult {
                endpoint: "/oauth/introspect".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration: request_duration,
                response_size: result.response_size,
                timestamp: request_start,
                client_id,
                error: result.error,
            }).await;

            if request_duration < interval {
                sleep(interval - request_duration).await;
            }
        }
    }

    async fn run_attack_simulation(&self, client_id: usize, attack_type: AttackType, duration: Duration) {
        let start_time = Instant::now();
        let end_time = start_time + duration;

        while Instant::now() < end_time {
            let request_start = Instant::now();
            
            let result = match attack_type {
                AttackType::CredentialStuffing => self.make_credential_stuffing_request(client_id).await,
                AttackType::BruteForce => self.make_brute_force_request(client_id).await,
                AttackType::TokenEnumeration => self.make_token_enumeration_request(client_id).await,
                AttackType::DDoS => self.make_ddos_request(client_id).await,
            };

            self.record_result(TestResult {
                endpoint: "/oauth/token".to_string(),
                method: "POST".to_string(),
                status: result.status_code,
                duration: request_start.elapsed(),
                response_size: result.response_size,
                timestamp: request_start,
                client_id,
                error: result.error,
            }).await;

            // Attack-specific delays
            let delay = match attack_type {
                AttackType::DDoS => Duration::from_millis(1),     // Rapid fire
                AttackType::BruteForce => Duration::from_millis(100),  // Moderate
                _ => Duration::from_millis(50),                   // Regular
            };
            sleep(delay).await;
        }
    }

    async fn run_mixed_workload(&self, client_id: usize, duration: Duration, distribution: HashMap<String, u32>) {
        let start_time = Instant::now();
        let end_time = start_time + duration;
        let total_weight: u32 = distribution.values().sum();

        while Instant::now() < end_time {
            let request_start = Instant::now();
            
            // Choose request type based on distribution
            let random_value = rand::random::<u32>() % total_weight;
            let mut current_weight = 0;
            let mut request_type = "token";

            for (req_type, weight) in &distribution {
                current_weight += weight;
                if random_value < current_weight {
                    request_type = req_type;
                    break;
                }
            }

            let result = match request_type {
                "token" => {
                    let res = self.make_token_request(client_id).await;
                    TestResult {
                        endpoint: "/oauth/token".to_string(),
                        method: "POST".to_string(),
                        status: res.status_code,
                        duration: request_start.elapsed(),
                        response_size: res.response_size,
                        timestamp: request_start,
                        client_id,
                        error: res.error,
                    }
                },
                "introspect" => {
                    let res = self.make_introspection_request("sample_token").await;
                    TestResult {
                        endpoint: "/oauth/introspect".to_string(),
                        method: "POST".to_string(),
                        status: res.status_code,
                        duration: request_start.elapsed(),
                        response_size: res.response_size,
                        timestamp: request_start,
                        client_id,
                        error: res.error,
                    }
                },
                "userinfo" => {
                    let res = self.make_userinfo_request("sample_token").await;
                    TestResult {
                        endpoint: "/oauth/userinfo".to_string(),
                        method: "GET".to_string(),
                        status: res.status_code,
                        duration: request_start.elapsed(),
                        response_size: res.response_size,
                        timestamp: request_start,
                        client_id,
                        error: res.error,
                    }
                },
                _ => continue,
            };

            self.record_result(result).await;
            sleep(Duration::from_millis(10)).await;
        }
    }

    // HTTP request methods

    async fn make_token_request(&self, client_id: usize) -> RequestResult {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        let payload = json!({
            "grant_type": "client_credentials",
            "client_id": format!("test_client_{}", client_id),
            "client_secret": "test_secret",
            "scope": "read write"
        });

        let response = self.client
            .post(&format!("{}/oauth/token", self.base_url))
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                RequestResult {
                    status_code: status,
                    response_size: size,
                    error: None,
                }
            }
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    async fn make_introspection_request(&self, token: &str) -> RequestResult {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        let payload = json!({
            "token": token,
            "token_type_hint": "access_token"
        });

        let response = self.client
            .post(&format!("{}/oauth/introspect", self.base_url))
            .basic_auth("test_client", Some("test_secret"))
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                RequestResult {
                    status_code: status,
                    response_size: size,
                    error: None,
                }
            }
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    async fn make_userinfo_request(&self, token: &str) -> RequestResult {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        let response = self.client
            .get(&format!("{}/oauth/userinfo", self.base_url))
            .bearer_auth(token)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                RequestResult {
                    status_code: status,
                    response_size: size,
                    error: None,
                }
            }
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    async fn make_bad_request(&self) -> RequestResult {
        let _permit = self.semaphore.acquire().await.unwrap();
        
        let payload = json!({
            "grant_type": "invalid_grant",
            "client_id": "invalid_client",
            "client_secret": "invalid_secret"
        });

        let response = self.client
            .post(&format!("{}/oauth/token", self.base_url))
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let size = resp.content_length().unwrap_or(0) as usize;
                RequestResult {
                    status_code: status,
                    response_size: size,
                    error: None,
                }
            }
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    // Attack simulation methods

    async fn make_credential_stuffing_request(&self, client_id: usize) -> RequestResult {
        // Simulate credential stuffing with common username/password combinations
        let credentials = [
            ("admin", "password"),
            ("user", "123456"),
            ("test", "test"),
            ("guest", "guest"),
        ];
        
        let (username, password) = credentials[client_id % credentials.len()];
        
        let payload = json!({
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": format!("stuffing_client_{}", client_id)
        });

        let response = self.client
            .post(&format!("{}/oauth/token", self.base_url))
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(resp) => RequestResult {
                status_code: resp.status().as_u16(),
                response_size: resp.content_length().unwrap_or(0) as usize,
                error: None,
            },
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    async fn make_brute_force_request(&self, client_id: usize) -> RequestResult {
        // Simulate brute force attack on a specific account
        let password_attempts = [
            "password123", "admin123", "qwerty", "letmein", "password1",
            "123456789", "welcome", "monkey", "dragon", "master"
        ];
        
        let password = password_attempts[client_id % password_attempts.len()];
        
        let payload = json!({
            "grant_type": "password",
            "username": "target_user",
            "password": password,
            "client_id": format!("brute_client_{}", client_id)
        });

        self.make_request_with_payload(&format!("{}/oauth/token", self.base_url), &payload).await
    }

    async fn make_token_enumeration_request(&self, client_id: usize) -> RequestResult {
        // Simulate token enumeration attack
        let fake_token = format!("tk_enumeration_attempt_{:06}", client_id);
        
        let payload = json!({
            "token": fake_token,
            "token_type_hint": "access_token"
        });

        let response = self.client
            .post(&format!("{}/oauth/introspect", self.base_url))
            .basic_auth("enum_client", Some("enum_secret"))
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(resp) => RequestResult {
                status_code: resp.status().as_u16(),
                response_size: resp.content_length().unwrap_or(0) as usize,
                error: None,
            },
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    async fn make_ddos_request(&self, client_id: usize) -> RequestResult {
        // Simulate DDoS with rapid requests from many IPs
        let fake_ip = format!("192.168.{}.{}", 
                             (client_id / 256) % 256, 
                             client_id % 256);
        
        let payload = json!({
            "grant_type": "client_credentials",
            "client_id": format!("ddos_client_{}", client_id),
            "client_secret": "ddos_secret"
        });

        let response = self.client
            .post(&format!("{}/oauth/token", self.base_url))
            .header("X-Forwarded-For", fake_ip)
            .json(&payload)
            .send()
            .await;

        match response {
            Ok(resp) => RequestResult {
                status_code: resp.status().as_u16(),
                response_size: resp.content_length().unwrap_or(0) as usize,
                error: None,
            },
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    async fn make_request_with_payload(&self, url: &str, payload: &serde_json::Value) -> RequestResult {
        let response = self.client
            .post(url)
            .json(payload)
            .send()
            .await;

        match response {
            Ok(resp) => RequestResult {
                status_code: resp.status().as_u16(),
                response_size: resp.content_length().unwrap_or(0) as usize,
                error: None,
            },
            Err(e) => RequestResult {
                status_code: 0,
                response_size: 0,
                error: Some(e.to_string()),
            }
        }
    }

    // Utility methods

    async fn generate_test_tokens(&self, count: usize) -> Vec<String> {
        let mut tokens = Vec::new();
        
        for i in 0..count {
            let payload = json!({
                "grant_type": "client_credentials",
                "client_id": format!("token_gen_client_{}", i),
                "client_secret": "token_gen_secret"
            });

            if let Ok(response) = self.client
                .post(&format!("{}/oauth/token", self.base_url))
                .json(&payload)
                .send()
                .await
            {
                if response.status().is_success() {
                    if let Ok(token_response) = response.json::<serde_json::Value>().await {
                        if let Some(token) = token_response.get("access_token").and_then(|t| t.as_str()) {
                            tokens.push(token.to_string());
                        }
                    }
                }
            }

            if i % 100 == 0 {
                info!("Generated {} test tokens", i);
            }
        }

        info!("Generated {} total test tokens", tokens.len());
        tokens
    }

    fn parse_distribution(&self, distribution: &str) -> HashMap<String, u32> {
        let mut dist = HashMap::new();
        
        for part in distribution.split(',') {
            if let Some((req_type, weight_str)) = part.split_once(':') {
                if let Ok(weight) = weight_str.parse::<u32>() {
                    dist.insert(req_type.to_string(), weight);
                }
            }
        }

        if dist.is_empty() {
            dist.insert("token".to_string(), 50);
            dist.insert("introspect".to_string(), 50);
        }

        dist
    }

    async fn record_result(&self, result: TestResult) {
        self.results.write().await.push(result);
    }

    async fn calculate_metrics(&self) -> TestMetrics {
        let results = self.results.read().await;
        
        if results.is_empty() {
            return TestMetrics {
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                rate_limited_requests: 0,
                avg_response_time: Duration::ZERO,
                max_response_time: Duration::ZERO,
                min_response_time: Duration::ZERO,
                p95_response_time: Duration::ZERO,
                p99_response_time: Duration::ZERO,
                throughput_rps: 0.0,
                error_rate: 0.0,
                status_codes: HashMap::new(),
            };
        }

        let total_requests = results.len() as u64;
        let successful_requests = results.iter().filter(|r| r.status >= 200 && r.status < 300).count() as u64;
        let failed_requests = total_requests - successful_requests;
        let rate_limited_requests = results.iter().filter(|r| r.status == 429).count() as u64;

        let mut durations: Vec<Duration> = results.iter().map(|r| r.duration).collect();
        durations.sort();

        let avg_response_time = Duration::from_nanos(
            durations.iter().map(|d| d.as_nanos()).sum::<u128>() as u64 / total_requests
        );
        let max_response_time = durations.iter().max().copied().unwrap_or(Duration::ZERO);
        let min_response_time = durations.iter().min().copied().unwrap_or(Duration::ZERO);
        
        let p95_index = ((durations.len() as f64) * 0.95) as usize;
        let p99_index = ((durations.len() as f64) * 0.99) as usize;
        let p95_response_time = durations.get(p95_index).copied().unwrap_or(Duration::ZERO);
        let p99_response_time = durations.get(p99_index).copied().unwrap_or(Duration::ZERO);

        // Calculate throughput
        let test_duration = results.iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(Instant::now())
            .duration_since(
                results.iter()
                    .map(|r| r.timestamp)
                    .min()
                    .unwrap_or(Instant::now())
            );
        
        let throughput_rps = if test_duration.as_secs_f64() > 0.0 {
            total_requests as f64 / test_duration.as_secs_f64()
        } else {
            0.0
        };

        let error_rate = failed_requests as f64 / total_requests as f64;

        // Status code distribution
        let mut status_codes = HashMap::new();
        for result in results.iter() {
            *status_codes.entry(result.status).or_insert(0) += 1;
        }

        TestMetrics {
            total_requests,
            successful_requests,
            failed_requests,
            rate_limited_requests,
            avg_response_time,
            max_response_time,
            min_response_time,
            p95_response_time,
            p99_response_time,
            throughput_rps,
            error_rate,
            status_codes,
        }
    }

    fn print_metrics(&self, metrics: &TestMetrics) {
        println!("\n=== Load Test Results ===");
        println!("Total Requests: {}", metrics.total_requests);
        println!("Successful Requests: {}", metrics.successful_requests);
        println!("Failed Requests: {}", metrics.failed_requests);
        println!("Rate Limited Requests: {}", metrics.rate_limited_requests);
        println!("Error Rate: {:.2}%", metrics.error_rate * 100.0);
        println!("Throughput: {:.2} RPS", metrics.throughput_rps);
        println!("\n=== Response Times ===");
        println!("Average: {:?}", metrics.avg_response_time);
        println!("Minimum: {:?}", metrics.min_response_time);
        println!("Maximum: {:?}", metrics.max_response_time);
        println!("95th Percentile: {:?}", metrics.p95_response_time);
        println!("99th Percentile: {:?}", metrics.p99_response_time);
        println!("\n=== Status Code Distribution ===");
        for (status, count) in &metrics.status_codes {
            println!("HTTP {}: {} requests", status, count);
        }
    }
}

impl Clone for LoadTestExecutor {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            base_url: self.base_url.clone(),
            results: self.results.clone(),
            semaphore: self.semaphore.clone(),
        }
    }
}

#[derive(Debug)]
struct RequestResult {
    status_code: u16,
    response_size: usize,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(level)
        .init();

    let executor = LoadTestExecutor::new(cli.base_url.clone(), cli.clients * 2);
    let duration = Duration::from_secs(cli.duration);

    let metrics = match cli.command {
        Commands::TokenEndpoint { rps } => {
            executor.test_token_endpoint(cli.clients, duration, rps).await
        }
        Commands::Introspection { rps } => {
            executor.test_introspection_endpoint(cli.clients, duration, rps).await
        }
        Commands::AttackSimulation { attack_type } => {
            executor.simulate_attack(attack_type, cli.clients, duration).await
        }
        Commands::MixedWorkload { distribution } => {
            executor.test_mixed_workload(cli.clients, duration, &distribution).await
        }
        Commands::RateLimitTest { target_rps } => {
            executor.test_rate_limiting(target_rps, duration).await
        }
        Commands::CircuitBreakerTest => {
            executor.test_circuit_breaker(duration).await
        }
        Commands::StressTest { start_rps, max_rps, increment_interval } => {
            executor.stress_test(start_rps, max_rps, Duration::from_secs(increment_interval)).await
        }
    };

    executor.print_metrics(&metrics);

    // Save results to file if specified
    if let Some(output_file) = cli.output {
        let json_metrics = serde_json::to_string_pretty(&metrics)?;
        std::fs::write(output_file, json_metrics)?;
        println!("Results saved to file");
    }

    Ok(())
}

// Add the missing dependencies to Cargo.toml:
/*
[dependencies]
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["full"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4", features = ["derive"] }
futures = "0.3"
rand = "0.8"
chrono = { version = "0.4", features = ["serde"] }
*/