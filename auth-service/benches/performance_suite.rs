#![allow(
    clippy::unused_async,
    clippy::significant_drop_tightening,
    clippy::unreadable_literal,
    clippy::no_effect_underscore_binding,
    clippy::cast_sign_loss
)]
use base64::Engine as _;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::{rngs::OsRng, Rng as _};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::RwLock;

// Mock implementations for benchmarking
mod mock_auth_service {
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub struct MockAuthService {
        tokens: HashMap<String, TokenInfo>,
    }

    #[derive(Clone)]
    pub struct TokenInfo {
        pub client_id: String,
        #[allow(dead_code)]
        pub scope: String,
        #[allow(dead_code)]
        pub expires_at: u64,
    }

    impl MockAuthService {
        pub fn new() -> Self {
            Self {
                tokens: HashMap::new(),
            }
        }

        pub async fn generate_token(&mut self, client_id: &str, scope: &str) -> String {
            let token = format!("tk_{}", uuid::Uuid::new_v4());
            let expires_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600;

            self.tokens.insert(
                token.clone(),
                TokenInfo {
                    client_id: client_id.to_string(),
                    scope: scope.to_string(),
                    expires_at,
                },
            );

            token
        }

        pub async fn introspect_token(&self, token: &str) -> Option<&TokenInfo> {
            self.tokens.get(token)
        }

        pub async fn revoke_token(&mut self, token: &str) -> bool {
            self.tokens.remove(token).is_some()
        }
    }
}

mod mock_policy_service {
    use serde_json::Value;

    pub struct MockPolicyService;

    impl MockPolicyService {
        pub const fn new() -> Self {
            Self
        }

        pub async fn evaluate_policy(&self, request: &Value) -> bool {
            // Simple mock policy evaluation
            request
                .get("action")
                .and_then(|a| a.as_str())
                .is_some_and(|action| {
                    // Allow read operations, deny write operations for benchmarking
                    !action.contains("write") && !action.contains("delete")
                })
        }
    }
}

// Benchmark functions
fn bench_token_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_generation");
    group.sample_size(100);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Setup runtime and service once outside the benchmark loop
    let rt = Arc::new(Runtime::new().unwrap());

    for concurrent_requests in &[1, 10, 50, 100] {
        group.throughput(Throughput::Elements(*concurrent_requests as u64));
        group.bench_with_input(
            BenchmarkId::new("concurrent", concurrent_requests),
            concurrent_requests,
            |b, &concurrent_requests| {
                let rt = Arc::clone(&rt);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for i in 0..concurrent_requests {
                            let client_id = format!("client_{i}");
                            let scope = "read write".to_string();

                            let handle = tokio::spawn(async move {
                                let mut service = mock_auth_service::MockAuthService::new();
                                service.generate_token(&client_id, &scope).await
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            black_box(handle.await.unwrap());
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_token_introspection(c: &mut Criterion) {
    let mut group = c.benchmark_group("token_introspection");
    group.sample_size(100);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Setup runtime and pre-populated service once outside benchmark loop
    let rt = Arc::new(Runtime::new().unwrap());

    // Pre-generate tokens and create a shared service with all tokens
    let (tokens, service): (Vec<String>, Arc<RwLock<mock_auth_service::MockAuthService>>) = rt
        .block_on(async {
            let mut service = mock_auth_service::MockAuthService::new();
            let mut tokens = Vec::new();

            for i in 0..1000 {
                let token = service
                    .generate_token(&format!("client_{i}"), "read write")
                    .await;
                tokens.push(token);
            }

            (tokens, Arc::new(RwLock::new(service)))
        });

    for batch_size in &[1, 10, 50, 100] {
        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("batch", batch_size),
            batch_size,
            |b, &batch_size| {
                let rt = Arc::clone(&rt);
                let tokens = tokens.clone();
                let service = Arc::clone(&service);
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for i in 0..batch_size {
                            let token = tokens[i % tokens.len()].clone();
                            let service = Arc::clone(&service);

                            let handle = tokio::spawn(async move {
                                let service_read = service.read().await;
                                service_read.introspect_token(&token).await.cloned()
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            black_box(handle.await.unwrap());
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_policy_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_evaluation");
    group.sample_size(100);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    let test_requests = vec![
        serde_json::json!({
            "principal": {"type": "User", "id": "user1"},
            "action": "orders:read",
            "resource": {"type": "Order", "id": "order1"}
        }),
        serde_json::json!({
            "principal": {"type": "User", "id": "user2"},
            "action": "orders:write",
            "resource": {"type": "Order", "id": "order2"}
        }),
        serde_json::json!({
            "principal": {"type": "Admin", "id": "admin1"},
            "action": "users:delete",
            "resource": {"type": "User", "id": "user3"}
        }),
    ];

    // Setup runtime once outside benchmark loop
    let rt = Arc::new(Runtime::new().unwrap());

    for request_count in &[1, 10, 50, 100] {
        group.throughput(Throughput::Elements(*request_count as u64));
        group.bench_with_input(
            BenchmarkId::new("requests", request_count),
            request_count,
            |b, &request_count| {
                let rt = Arc::clone(&rt);
                let test_requests = test_requests.clone();
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();

                        for i in 0..request_count {
                            let request = test_requests[i % test_requests.len()].clone();
                            let handle = tokio::spawn(async move {
                                let service = mock_policy_service::MockPolicyService::new();
                                service.evaluate_policy(&request).await
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            black_box(handle.await.unwrap());
                        }
                    });
                });
            },
        );
    }
    group.finish();
}

fn bench_jwt_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("jwt_operations");
    group.sample_size(100);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Mock JWT operations
    let _secret = "test-secret-key-for-benchmarking-purposes-only";
    let claims = serde_json::json!({
        "sub": "user123",
        "iat": 1234567890,
        "exp": 1234571490,
        "scope": "read write"
    });

    group.bench_function("jwt_encode", |b| {
        b.iter(|| {
            // Mock JWT encoding
            let header =
                base64::engine::general_purpose::STANDARD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
            let payload = base64::engine::general_purpose::STANDARD.encode(claims.to_string());
            let signature = base64::engine::general_purpose::STANDARD.encode("mock_signature");
            black_box(format!("{header}.{payload}.{signature}"))
        });
    });

    let mock_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxMjM0NTY3ODkwLCJleHAiOjEyMzQ1NzE0OTAsInNjb3BlIjoicmVhZCB3cml0ZSJ9.mock_signature";

    group.bench_function("jwt_decode", |b| {
        b.iter(|| {
            // Mock JWT decoding
            let parts: Vec<&str> = mock_jwt.split('.').collect();
            if parts.len() == 3 {
                let _header = base64::engine::general_purpose::STANDARD
                    .decode(parts[0])
                    .unwrap_or_default();
                let payload = base64::engine::general_purpose::STANDARD
                    .decode(parts[1])
                    .unwrap_or_default();
                let _signature = base64::engine::general_purpose::STANDARD
                    .decode(parts[2])
                    .unwrap_or_default();
                black_box(String::from_utf8_lossy(&payload).to_string())
            } else {
                black_box(String::new())
            }
        });
    });

    group.finish();
}

fn bench_security_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("security_operations");
    group.sample_size(100);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Benchmark password hashing
    group.bench_function("password_hash", |b| {
        b.iter(|| {
            let password = "test_password_123";
            // Mock bcrypt hashing (simplified)
            let salt = "mock_salt_value";
            let hash = format!(
                "$2b$12${}${}",
                salt,
                base64::engine::general_purpose::STANDARD.encode(password)
            );
            black_box(hash)
        });
    });

    // Benchmark HMAC generation
    group.bench_function("hmac_generation", |b| {
        b.iter(|| {
            let message = "test message for hmac";
            let secret = "hmac_secret_key";
            // Mock HMAC (simplified)
            let hash = format!("hmac_{}_{}", secret.len(), message.len());
            black_box(hash)
        });
    });

    // Benchmark token binding
    group.bench_function("token_binding", |b| {
        b.iter(|| {
            let client_ip = "192.168.1.100";
            let user_agent = "Mozilla/5.0 (compatible; benchmark)";
            // Mock token binding generation
            let binding = format!("binding_{}_{}", client_ip.len(), user_agent.len());
            black_box(binding)
        });
    });

    group.finish();
}

fn bench_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_operations");
    group.sample_size(100);
    group.warm_up_time(std::time::Duration::from_secs(1));
    group.measurement_time(std::time::Duration::from_secs(3));

    // Mock cache implementation

    let cache: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));

    // Setup runtime and pre-populate cache once outside benchmark loop
    let rt = Arc::new(Runtime::new().unwrap());
    rt.block_on(async {
        let mut cache_write = cache.write().await;
        for i in 0..1000 {
            cache_write.insert(format!("key_{i}"), format!("value_{i}"));
        }
    });

    group.bench_function("cache_read", |b| {
        let cache = Arc::clone(&cache);
        let rt = Arc::clone(&rt);
        b.iter(|| {
            rt.block_on(async {
                let cache_read = cache.read().await;
                let key = format!("key_{}", OsRng.gen::<usize>() % 1000);
                // Clone the value to avoid lifetime issues with the lock guard
                let result = cache_read.get(&key).cloned();
                black_box(result)
            })
        });
    });

    group.bench_function("cache_write", |b| {
        let cache = Arc::clone(&cache);
        let rt = Arc::clone(&rt);
        b.iter(|| {
            rt.block_on(async {
                let mut cache_write = cache.write().await;
                let key = format!("new_key_{}", OsRng.gen::<usize>());
                let value = format!("new_value_{}", OsRng.gen::<usize>());
                black_box(cache_write.insert(key, value))
            })
        });
    });

    group.finish();
}

// Configure benchmark groups
criterion_group!(
    benches,
    bench_token_generation,
    bench_token_introspection,
    bench_policy_evaluation,
    bench_jwt_operations,
    bench_security_operations,
    bench_cache_operations
);

criterion_main!(benches);

// Additional benchmark configuration

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_auth_service() {
        let mut service = mock_auth_service::MockAuthService::new();

        let token = service.generate_token("test_client", "read write").await;
        assert!(!token.is_empty());

        let info = service.introspect_token(&token).await;
        assert!(info.is_some());
        assert_eq!(info.unwrap().client_id, "test_client");

        let revoked = service.revoke_token(&token).await;
        assert!(revoked);

        let info_after_revoke = service.introspect_token(&token).await;
        assert!(info_after_revoke.is_none());
    }

    #[tokio::test]
    async fn test_mock_policy_service() {
        let service = mock_policy_service::MockPolicyService::new();

        let read_request = serde_json::json!({
            "action": "orders:read"
        });
        assert!(service.evaluate_policy(&read_request).await);

        let write_request = serde_json::json!({
            "action": "orders:write"
        });
        assert!(!service.evaluate_policy(&write_request).await);
    }
}
