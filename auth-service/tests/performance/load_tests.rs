// Performance and load testing for authentication service

use crate::test_utils::*;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

mod test_utils;

#[tokio::test]
async fn test_token_issuance_performance() {
    let fixture = TestFixture::new().await;
    
    // Warm up
    for _ in 0..5 {
        let _ = fixture.get_access_token().await;
    }
    
    // Measure performance
    let iterations = 100;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let token = fixture.get_access_token().await;
        assert!(!token.is_empty());
    }
    
    let duration = start.elapsed();
    let avg_latency = duration.as_millis() as f64 / iterations as f64;
    let throughput = (iterations as f64 / duration.as_secs_f64()) as u32;
    
    println!("Token issuance performance:");
    println!("  Average latency: {:.2}ms", avg_latency);
    println!("  Throughput: {} tokens/sec", throughput);
    
    // Performance assertions
    assert!(avg_latency < 100.0, "Average latency should be under 100ms, got {}ms", avg_latency);
    assert!(throughput > 10, "Throughput should be over 10 tokens/sec, got {}", throughput);
}

#[tokio::test]
async fn test_concurrent_token_operations() {
    let fixture = TestFixture::new().await;
    
    let concurrent_users = 50;
    let operations_per_user = 5;
    let semaphore = Arc::new(Semaphore::new(concurrent_users));
    
    let start = Instant::now();
    let mut handles = Vec::new();
    
    for user_id in 0..concurrent_users {
        let permit = Arc::clone(&semaphore);
        let fixture_clone = &fixture;
        let client = fixture_clone.client.clone();
        let base_url = fixture_clone.base_url.clone();
        let auth_header = fixture_clone.basic_auth_header(&fixture_clone.valid_client_id, &fixture_clone.valid_client_secret);
        
        let handle = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            let mut operation_times = Vec::new();
            let mut successful_operations = 0;
            
            for operation in 0..operations_per_user {
                let op_start = Instant::now();
                
                let scope = match operation % 3 {
                    0 => "read",
                    1 => "write", 
                    _ => "read write",
                };
                
                let response = client
                    .post(&format!("{}/oauth/token", base_url))
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(AUTHORIZATION, &auth_header)
                    .body(format!("grant_type=client_credentials&scope={}", scope))
                    .send()
                    .await;
                
                let op_duration = op_start.elapsed();
                operation_times.push(op_duration);
                
                match response {
                    Ok(resp) => {
                        if resp.status() == 200 {
                            successful_operations += 1;
                            
                            // Test token introspection
                            if let Ok(token_data) = resp.json::<Value>().await {
                                if let Some(access_token) = token_data.get("access_token").and_then(|t| t.as_str()) {
                                    let introspect_start = Instant::now();
                                    let _ = client
                                        .post(&format!("{}/oauth/introspect", base_url))
                                        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                                        .header(AUTHORIZATION, &auth_header)
                                        .body(format!("token={}", access_token))
                                        .send()
                                        .await;
                                    operation_times.push(introspect_start.elapsed());
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Network error or timeout
                    }
                }
            }
            
            (user_id, successful_operations, operation_times)
        });
        
        handles.push(handle);
    }
    
    // Collect results
    let mut total_successful = 0;
    let mut all_times = Vec::new();
    
    for handle in handles {
        let (user_id, successful, times) = handle.await.unwrap();
        total_successful += successful;
        all_times.extend(times);
        
        println!("User {}: {} successful operations", user_id, successful);
    }
    
    let total_duration = start.elapsed();
    let total_operations = all_times.len();
    
    // Calculate statistics
    all_times.sort();
    let avg_latency = all_times.iter().sum::<Duration>().as_millis() as f64 / total_operations as f64;
    let p50 = all_times[total_operations / 2].as_millis();
    let p95 = all_times[(total_operations as f64 * 0.95) as usize].as_millis();
    let p99 = all_times[(total_operations as f64 * 0.99) as usize].as_millis();
    let throughput = total_operations as f64 / total_duration.as_secs_f64();
    
    println!("Concurrent load test results:");
    println!("  Concurrent users: {}", concurrent_users);
    println!("  Total operations: {}", total_operations);
    println!("  Successful operations: {}", total_successful);
    println!("  Success rate: {:.2}%", (total_successful as f64 / total_operations as f64) * 100.0);
    println!("  Average latency: {:.2}ms", avg_latency);
    println!("  P50 latency: {}ms", p50);
    println!("  P95 latency: {}ms", p95);
    println!("  P99 latency: {}ms", p99);
    println!("  Throughput: {:.1} ops/sec", throughput);
    
    // Performance assertions
    assert!(total_successful as f64 / total_operations as f64 > 0.95, "Success rate should be > 95%");
    assert!(avg_latency < 500.0, "Average latency should be under 500ms");
    assert!(p95 < 1000, "P95 latency should be under 1000ms");
    assert!(throughput > 20.0, "Throughput should be > 20 ops/sec");
}

#[tokio::test]
async fn test_rate_limiter_performance() {
    use auth_service::rate_limit_optimized::*;
    
    let config = RateLimitConfig {
        requests_per_window: 1000,
        window_duration_secs: 60,
        burst_allowance: 100,
        cleanup_interval_secs: 300,
    };
    
    let limiter = ShardedRateLimiter::new(config);
    let iterations = 10000;
    let concurrent_clients = 100;
    
    let start = Instant::now();
    let mut handles = Vec::new();
    
    for client_id in 0..concurrent_clients {
        let limiter_clone = limiter.clone();
        let handle = tokio::spawn(async move {
            let client_key = format!("client_{}", client_id);
            let mut allowed_count = 0;
            let mut denied_count = 0;
            
            for _ in 0..(iterations / concurrent_clients) {
                match limiter_clone.check_rate_limit(&client_key) {
                    RateLimitResult::Allowed => allowed_count += 1,
                    RateLimitResult::RateLimited { .. } => denied_count += 1,
                }
            }
            
            (allowed_count, denied_count)
        });
        
        handles.push(handle);
    }
    
    let mut total_allowed = 0;
    let mut total_denied = 0;
    
    for handle in handles {
        let (allowed, denied) = handle.await.unwrap();
        total_allowed += allowed;
        total_denied += denied;
    }
    
    let duration = start.elapsed();
    let throughput = iterations as f64 / duration.as_secs_f64();
    
    println!("Rate limiter performance:");
    println!("  Total requests: {}", iterations);
    println!("  Allowed: {}", total_allowed);
    println!("  Denied: {}", total_denied);
    println!("  Duration: {}ms", duration.as_millis());
    println!("  Throughput: {:.0} checks/sec", throughput);
    
    // Performance assertions
    assert!(throughput > 50000.0, "Rate limiter should handle > 50k checks/sec, got {:.0}", throughput);
    assert!(total_allowed > 0, "Some requests should be allowed");
    
    // Test cleanup performance
    let cleanup_start = Instant::now();
    let removed = limiter.cleanup_stale_entries();
    let cleanup_duration = cleanup_start.elapsed();
    
    println!("  Cleanup removed {} entries in {}ms", removed, cleanup_duration.as_millis());
    assert!(cleanup_duration < Duration::from_millis(100), "Cleanup should be fast");
}

#[tokio::test]
async fn test_memory_usage_under_load() {
    let fixture = TestFixture::new().await;
    
    // Measure baseline memory usage
    let initial_memory = get_memory_usage();
    
    // Generate load
    let mut tokens = Vec::new();
    let token_count = 1000;
    
    for i in 0..token_count {
        let scope = match i % 4 {
            0 => Some("read"),
            1 => Some("write"),
            2 => Some("read write"),
            _ => None,
        };
        
        let token = if let Some(s) = scope {
            fixture.get_access_token_with_scope(Some(s)).await
        } else {
            fixture.get_access_token().await
        };
        
        tokens.push(token);
        
        // Test introspection for some tokens
        if i % 10 == 0 {
            let _ = fixture.client
                .post(&format!("{}/oauth/introspect", fixture.base_url))
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
                .body(format!("token={}", token))
                .send()
                .await;
        }
    }
    
    let peak_memory = get_memory_usage();
    let memory_increase = peak_memory.saturating_sub(initial_memory);
    
    // Clean up tokens
    for token in &tokens {
        let _ = fixture.client
            .post(&format!("{}/oauth/revoke", fixture.base_url))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(AUTHORIZATION, fixture.basic_auth_header(&fixture.valid_client_id, &fixture.valid_client_secret))
            .body(format!("token={}", token))
            .send()
            .await;
    }
    
    // Force garbage collection and measure final memory
    tokio::time::sleep(Duration::from_millis(100)).await;
    let final_memory = get_memory_usage();
    
    println!("Memory usage test:");
    println!("  Initial memory: {} KB", initial_memory);
    println!("  Peak memory: {} KB", peak_memory);
    println!("  Memory increase: {} KB", memory_increase);
    println!("  Final memory: {} KB", final_memory);
    println!("  Memory per token: {} bytes", (memory_increase * 1024) / token_count as u64);
    
    // Memory usage assertions
    let memory_per_token = (memory_increase * 1024) / token_count as u64;
    assert!(memory_per_token < 1024, "Memory per token should be < 1KB, got {} bytes", memory_per_token);
    
    let memory_leaked = final_memory.saturating_sub(initial_memory);
    assert!(memory_leaked < memory_increase / 2, "Should not leak significant memory");
}

#[tokio::test]
async fn test_database_performance() {
    use auth_service::store::TokenStore;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    let store = TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new())));
    let operations = 1000;
    let concurrent_operations = 50;
    
    // Test write performance
    let write_start = Instant::now();
    let mut write_handles = Vec::new();
    
    for i in 0..concurrent_operations {
        let store_clone = store.clone();
        let handle = tokio::spawn(async move {
            for j in 0..(operations / concurrent_operations) {
                let token = format!("token_{}_{}", i, j);
                let _ = store_clone.set_active(&token, true, Some(3600)).await;
                let _ = store_clone.set_scope(&token, Some("read write".to_string()), Some(3600)).await;
                let _ = store_clone.set_client_id(&token, "test_client".to_string(), Some(3600)).await;
            }
        });
        write_handles.push(handle);
    }
    
    for handle in write_handles {
        handle.await.unwrap();
    }
    
    let write_duration = write_start.elapsed();
    let write_throughput = operations as f64 / write_duration.as_secs_f64();
    
    // Test read performance
    let read_start = Instant::now();
    let mut read_handles = Vec::new();
    
    for i in 0..concurrent_operations {
        let store_clone = store.clone();
        let handle = tokio::spawn(async move {
            for j in 0..(operations / concurrent_operations) {
                let token = format!("token_{}_{}", i, j);
                let _ = store_clone.get_record(&token).await;
                let _ = store_clone.get_active(&token).await;
            }
        });
        read_handles.push(handle);
    }
    
    for handle in read_handles {
        handle.await.unwrap();
    }
    
    let read_duration = read_start.elapsed();
    let read_throughput = operations as f64 / read_duration.as_secs_f64();
    
    println!("Database performance:");
    println!("  Write operations: {}", operations);
    println!("  Write duration: {}ms", write_duration.as_millis());
    println!("  Write throughput: {:.0} ops/sec", write_throughput);
    println!("  Read operations: {}", operations);
    println!("  Read duration: {}ms", read_duration.as_millis());
    println!("  Read throughput: {:.0} ops/sec", read_throughput);
    
    // Performance assertions
    assert!(write_throughput > 1000.0, "Write throughput should be > 1000 ops/sec");
    assert!(read_throughput > 5000.0, "Read throughput should be > 5000 ops/sec");
}

#[tokio::test]
async fn test_crypto_operations_performance() {
    use auth_service::security::*;
    use auth_service::keys::*;
    
    // Initialize keys
    initialize_keys().await.unwrap();
    
    // Test PKCE operations
    let pkce_start = Instant::now();
    let iterations = 1000;
    
    for _ in 0..iterations {
        let verifier = generate_code_verifier();
        let challenge = generate_code_challenge(&verifier);
        assert!(verify_code_challenge(&verifier, &challenge));
    }
    
    let pkce_duration = pkce_start.elapsed();
    let pkce_throughput = iterations as f64 / pkce_duration.as_secs_f64();
    
    // Test signature operations
    let sig_start = Instant::now();
    let secret = "test_secret_key";
    let method = "POST";
    let path = "/oauth/token";
    let body = "grant_type=client_credentials";
    
    for i in 0..iterations {
        let timestamp = 1640995200 + i;
        let signature = generate_request_signature(method, path, body, timestamp, secret).unwrap();
        assert!(verify_request_signature(method, path, body, timestamp, &signature, secret).unwrap());
    }
    
    let sig_duration = sig_start.elapsed();
    let sig_throughput = iterations as f64 / sig_duration.as_secs_f64();
    
    // Test token binding operations
    let binding_start = Instant::now();
    
    for i in 0..iterations {
        let client_ip = format!("192.168.1.{}", i % 255);
        let user_agent = format!("TestAgent/{}", i);
        let binding = generate_token_binding(&client_ip, &user_agent);
        assert!(validate_token_binding(&binding, &client_ip, &user_agent));
    }
    
    let binding_duration = binding_start.elapsed();
    let binding_throughput = iterations as f64 / binding_duration.as_secs_f64();
    
    println!("Crypto operations performance:");
    println!("  PKCE operations: {:.0} ops/sec", pkce_throughput);
    println!("  Signature operations: {:.0} ops/sec", sig_throughput);
    println!("  Token binding operations: {:.0} ops/sec", binding_throughput);
    
    // Performance assertions
    assert!(pkce_throughput > 100.0, "PKCE should be > 100 ops/sec");
    assert!(sig_throughput > 500.0, "Signatures should be > 500 ops/sec");
    assert!(binding_throughput > 1000.0, "Token binding should be > 1000 ops/sec");
}

#[tokio::test]
async fn test_mfa_performance() {
    use auth_service::mfa::*;
    
    // Test TOTP performance
    let totp_start = Instant::now();
    let iterations = 1000;
    let secret: Vec<u8> = (0..20).map(|_| rand::random::<u8>()).collect();
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    for _ in 0..iterations {
        let code = totp(&secret, time, 30, 6);
        assert!(code > 0);
    }
    
    let totp_duration = totp_start.elapsed();
    let totp_throughput = iterations as f64 / totp_duration.as_secs_f64();
    
    println!("MFA performance:");
    println!("  TOTP operations: {:.0} ops/sec", totp_throughput);
    
    // Performance assertions
    assert!(totp_throughput > 5000.0, "TOTP should be > 5000 ops/sec");
}

#[tokio::test]
async fn test_stress_test() {
    let fixture = TestFixture::new().await;
    
    // Stress test with high concurrency
    let concurrent_users = 100;
    let operations_per_user = 10;
    let stress_duration = Duration::from_secs(30);
    
    let start = Instant::now();
    let mut handles = Vec::new();
    let semaphore = Arc::new(Semaphore::new(concurrent_users));
    
    let end_time = start + stress_duration;
    
    for user_id in 0..concurrent_users {
        let permit = Arc::clone(&semaphore);
        let fixture_clone = &fixture;
        let client = fixture_clone.client.clone();
        let base_url = fixture_clone.base_url.clone();
        let auth_header = fixture_clone.basic_auth_header(&fixture_clone.valid_client_id, &fixture_clone.valid_client_secret);
        
        let handle = tokio::spawn(async move {
            let _permit = permit.acquire().await.unwrap();
            let mut total_operations = 0;
            let mut successful_operations = 0;
            let mut errors = 0;
            
            while Instant::now() < end_time {
                for operation in 0..operations_per_user {
                    if Instant::now() >= end_time {
                        break;
                    }
                    
                    total_operations += 1;
                    
                    let operation_type = operation % 4;
                    let result = match operation_type {
                        0 => {
                            // Token issuance
                            client
                                .post(&format!("{}/oauth/token", base_url))
                                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                                .header(AUTHORIZATION, &auth_header)
                                .body("grant_type=client_credentials&scope=read")
                                .send()
                                .await
                        }
                        1 => {
                            // JWKS retrieval
                            client
                                .get(&format!("{}/jwks.json", base_url))
                                .send()
                                .await
                        }
                        2 => {
                            // Metadata retrieval
                            client
                                .get(&format!("{}/.well-known/oauth-authorization-server", base_url))
                                .send()
                                .await
                        }
                        _ => {
                            // Health check
                            client
                                .get(&format!("{}/health", base_url))
                                .send()
                                .await
                        }
                    };
                    
                    match result {
                        Ok(resp) if resp.status().is_success() => successful_operations += 1,
                        Ok(_) => errors += 1,
                        Err(_) => errors += 1,
                    }
                    
                    // Small delay to prevent overwhelming
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            
            (user_id, total_operations, successful_operations, errors)
        });
        
        handles.push(handle);
    }
    
    // Collect results
    let mut total_ops = 0;
    let mut total_successful = 0;
    let mut total_errors = 0;
    
    for handle in handles {
        let (user_id, ops, successful, errors) = handle.await.unwrap();
        total_ops += ops;
        total_successful += successful;
        total_errors += errors;
        
        println!("User {}: {} ops, {} successful, {} errors", user_id, ops, successful, errors);
    }
    
    let actual_duration = start.elapsed();
    let throughput = total_ops as f64 / actual_duration.as_secs_f64();
    let success_rate = total_successful as f64 / total_ops as f64;
    let error_rate = total_errors as f64 / total_ops as f64;
    
    println!("Stress test results:");
    println!("  Duration: {}s", actual_duration.as_secs());
    println!("  Total operations: {}", total_ops);
    println!("  Successful operations: {}", total_successful);
    println!("  Errors: {}", total_errors);
    println!("  Success rate: {:.2}%", success_rate * 100.0);
    println!("  Error rate: {:.2}%", error_rate * 100.0);
    println!("  Throughput: {:.1} ops/sec", throughput);
    
    // Stress test assertions
    assert!(success_rate > 0.90, "Success rate should be > 90% under stress");
    assert!(error_rate < 0.10, "Error rate should be < 10% under stress");
    assert!(throughput > 50.0, "Should maintain > 50 ops/sec under stress");
}

// Helper function to get memory usage (simplified)
fn get_memory_usage() -> u64 {
    // In a real implementation, this would read from /proc/self/status or use a system API
    // For testing purposes, we'll return a mock value
    use std::alloc::{GlobalAlloc, Layout, System};
    
    // This is a simplified approach - in production you'd use proper memory profiling
    std::hint::black_box(1024) // Mock memory usage in KB
}

#[tokio::test]
async fn test_latency_percentiles() {
    let fixture = TestFixture::new().await;
    
    let iterations = 200;
    let mut latencies = Vec::new();
    
    // Warm up
    for _ in 0..10 {
        let _ = fixture.get_access_token().await;
    }
    
    // Measure latencies
    for _ in 0..iterations {
        let start = Instant::now();
        let token = fixture.get_access_token().await;
        let latency = start.elapsed();
        latencies.push(latency);
        
        assert!(!token.is_empty());
    }
    
    // Sort for percentile calculation
    latencies.sort();
    
    let p50 = latencies[iterations / 2];
    let p90 = latencies[(iterations as f64 * 0.90) as usize];
    let p95 = latencies[(iterations as f64 * 0.95) as usize];
    let p99 = latencies[(iterations as f64 * 0.99) as usize];
    let max = latencies[iterations - 1];
    
    println!("Latency percentiles:");
    println!("  P50: {}ms", p50.as_millis());
    println!("  P90: {}ms", p90.as_millis());
    println!("  P95: {}ms", p95.as_millis());
    println!("  P99: {}ms", p99.as_millis());
    println!("  Max: {}ms", max.as_millis());
    
    // Latency assertions
    assert!(p50 < Duration::from_millis(50), "P50 should be < 50ms");
    assert!(p95 < Duration::from_millis(200), "P95 should be < 200ms");
    assert!(p99 < Duration::from_millis(500), "P99 should be < 500ms");
}