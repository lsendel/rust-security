//! # Cryptographic Operations Benchmark
//!
//! Performance profiling tool for cryptographic operations under load.
//!
//! ## Usage
//!
//! ```bash
//! # Benchmark all crypto operations
//! cargo run --bin crypto_benchmark --release
//!
//! # Benchmark specific operations
//! cargo run --bin crypto_benchmark --release -- --operation encryption
//! cargo run --bin crypto_benchmark --release -- --operation hashing
//! cargo run --bin crypto_benchmark --release -- --operation jwt
//!
//! # Stress test with concurrent operations
//! cargo run --bin crypto_benchmark --release -- --concurrent 100 --duration 60
//!
//! # Profile memory usage
//! cargo run --bin crypto_benchmark --release -- --profile-memory
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{info, warn, error};

#[cfg(feature = "crypto")]
use auth_service::security::{
    initialize_global_crypto, get_global_crypto, 
    initialize_global_jwt_manager, get_global_jwt_manager,
    CryptoConfig, JwtConfig, Claims
};

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let config = parse_benchmark_config(&args);

    info!("Starting cryptographic operations benchmark");
    info!("Configuration: {:?}", config);

    // Initialize crypto systems
    #[cfg(feature = "crypto")]
    {
        let crypto_config = CryptoConfig::production();
        initialize_global_crypto(crypto_config).await
            .expect("Failed to initialize crypto system");

        let jwt_config = JwtConfig::production();
        initialize_global_jwt_manager(jwt_config).await
            .expect("Failed to initialize JWT manager");
    }

    // Run benchmarks based on configuration
    match config.operation.as_deref() {
        Some("encryption") => benchmark_encryption(&config).await,
        Some("hashing") => benchmark_hashing(&config).await,
        Some("jwt") => benchmark_jwt_operations(&config).await,
        Some("post-quantum") => benchmark_post_quantum(&config).await,
        _ => benchmark_all_operations(&config).await,
    }

    info!("Benchmark completed");
}

#[derive(Debug, Clone)]
struct BenchmarkConfig {
    operation: Option<String>,
    concurrent_operations: usize,
    duration_seconds: u64,
    data_size_bytes: usize,
    iterations: usize,
    profile_memory: bool,
}

fn parse_benchmark_config(args: &[String]) -> BenchmarkConfig {
    let mut config = BenchmarkConfig {
        operation: None,
        concurrent_operations: 10,
        duration_seconds: 30,
        data_size_bytes: 1024,
        iterations: 1000,
        profile_memory: false,
    };

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--operation" if i + 1 < args.len() => {
                config.operation = Some(args[i + 1].clone());
                i += 2;
            }
            "--concurrent" if i + 1 < args.len() => {
                config.concurrent_operations = args[i + 1].parse().unwrap_or(10);
                i += 2;
            }
            "--duration" if i + 1 < args.len() => {
                config.duration_seconds = args[i + 1].parse().unwrap_or(30);
                i += 2;
            }
            "--data-size" if i + 1 < args.len() => {
                config.data_size_bytes = args[i + 1].parse().unwrap_or(1024);
                i += 2;
            }
            "--iterations" if i + 1 < args.len() => {
                config.iterations = args[i + 1].parse().unwrap_or(1000);
                i += 2;
            }
            "--profile-memory" => {
                config.profile_memory = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    config
}

async fn benchmark_all_operations(config: &BenchmarkConfig) {
    info!("Running comprehensive cryptographic benchmark");
    
    benchmark_hashing(config).await;
    benchmark_encryption(config).await;
    benchmark_jwt_operations(config).await;
    
    #[cfg(feature = "post-quantum")]
    benchmark_post_quantum(config).await;
}

async fn benchmark_hashing(config: &BenchmarkConfig) {
    info!("Benchmarking password hashing operations");
    
    let test_passwords = generate_test_passwords(config.iterations);
    let semaphore = Arc::new(Semaphore::new(config.concurrent_operations));
    
    let start_time = Instant::now();
    let mut handles = Vec::new();
    
    for password in test_passwords {
        let semaphore = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            let hash_start = Instant::now();
            
            #[cfg(feature = "crypto")]
            let result = {
                use auth_service::security::hash_password_global;
                hash_password_global(&password).await
            };
            #[cfg(not(feature = "crypto"))]
            let result = Ok("simulated_hash".to_string());
            
            let hash_duration = hash_start.elapsed();
            
            match result {
                Ok(_) => Some(hash_duration),
                Err(e) => {
                    error!("Hashing failed: {}", e);
                    None
                }
            }
        });
        handles.push(handle);
    }
    
    // Collect results
    let mut successful_operations = 0;
    let mut total_hash_time = Duration::ZERO;
    
    for handle in handles {
        if let Ok(Some(duration)) = handle.await {
            successful_operations += 1;
            total_hash_time += duration;
        }
    }
    
    let total_time = start_time.elapsed();
    
    info!("=== Password Hashing Benchmark Results ===");
    info!("Total operations: {}", config.iterations);
    info!("Successful operations: {}", successful_operations);
    info!("Total benchmark time: {:?}", total_time);
    info!("Average hash time: {:?}", total_hash_time / successful_operations as u32);
    info!("Operations per second: {:.2}", successful_operations as f64 / total_time.as_secs_f64());
}

async fn benchmark_encryption(config: &BenchmarkConfig) {
    info!("Benchmarking encryption operations");
    
    let test_data = generate_test_data(config.data_size_bytes, config.iterations);
    let semaphore = Arc::new(Semaphore::new(config.concurrent_operations));
    
    let start_time = Instant::now();
    let mut handles = Vec::new();
    
    for data in test_data {
        let semaphore = semaphore.clone();
        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            
            let encrypt_start = Instant::now();
            
            #[cfg(feature = "crypto")]
            let result = {
                use auth_service::security::encrypt_global;
                encrypt_global(&data).await
            };
            #[cfg(not(feature = "crypto"))]
            let result = Ok("simulated_encrypted_data".as_bytes().to_vec());
            
            let encrypt_duration = encrypt_start.elapsed();
            
            match result {
                Ok(encrypted_data) => {
                    // Test decryption as well
                    let decrypt_start = Instant::now();
                    
                    #[cfg(feature = "crypto")]
                    let decrypt_result = {
                        use auth_service::security::decrypt_global;
                        decrypt_global(&encrypted_data).await
                    };
                    #[cfg(not(feature = "crypto"))]
                    let decrypt_result = Ok(data.clone());
                    
                    let decrypt_duration = decrypt_start.elapsed();
                    
                    match decrypt_result {
                        Ok(_) => Some((encrypt_duration, decrypt_duration)),
                        Err(e) => {
                            error!("Decryption failed: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!("Encryption failed: {}", e);
                    None
                }
            }
        });
        handles.push(handle);
    }
    
    // Collect results
    let mut successful_operations = 0;
    let mut total_encrypt_time = Duration::ZERO;
    let mut total_decrypt_time = Duration::ZERO;
    
    for handle in handles {
        if let Ok(Some((encrypt_time, decrypt_time))) = handle.await {
            successful_operations += 1;
            total_encrypt_time += encrypt_time;
            total_decrypt_time += decrypt_time;
        }
    }
    
    let total_time = start_time.elapsed();
    
    info!("=== Encryption Benchmark Results ===");
    info!("Data size per operation: {} bytes", config.data_size_bytes);
    info!("Total operations: {}", config.iterations);
    info!("Successful operations: {}", successful_operations);
    info!("Total benchmark time: {:?}", total_time);
    info!("Average encrypt time: {:?}", total_encrypt_time / successful_operations as u32);
    info!("Average decrypt time: {:?}", total_decrypt_time / successful_operations as u32);
    info!("Operations per second: {:.2}", successful_operations as f64 / total_time.as_secs_f64());
    info!("Throughput: {:.2} MB/s", 
          (successful_operations * config.data_size_bytes) as f64 / (1024.0 * 1024.0) / total_time.as_secs_f64());
}

async fn benchmark_jwt_operations(config: &BenchmarkConfig) {
    info!("Benchmarking JWT operations");
    
    #[cfg(not(feature = "crypto"))]
    {
        warn!("JWT benchmarking requires crypto feature");
        return;
    }
    
    #[cfg(feature = "crypto")]
    {
        let test_claims = generate_test_claims(config.iterations);
        let semaphore = Arc::new(Semaphore::new(config.concurrent_operations));
        
        let start_time = Instant::now();
        let mut handles = Vec::new();
        
        for claims in test_claims {
            let semaphore = semaphore.clone();
            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let create_start = Instant::now();
                
                let result = {
                    use auth_service::security::create_token_global;
                    create_token_global(&claims).await
                };
                
                let create_duration = create_start.elapsed();
                
                match result {
                    Ok(token) => {
                        // Test token validation
                        let validate_start = Instant::now();
                        
                        let validate_result = {
                            use auth_service::security::validate_token_global;
                            validate_token_global(&token).await
                        };
                        
                        let validate_duration = validate_start.elapsed();
                        
                        match validate_result {
                            Ok(_) => Some((create_duration, validate_duration)),
                            Err(e) => {
                                error!("Token validation failed: {}", e);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        error!("Token creation failed: {}", e);
                        None
                    }
                }
            });
            handles.push(handle);
        }
        
        // Collect results
        let mut successful_operations = 0;
        let mut total_create_time = Duration::ZERO;
        let mut total_validate_time = Duration::ZERO;
        
        for handle in handles {
            if let Ok(Some((create_time, validate_time))) = handle.await {
                successful_operations += 1;
                total_create_time += create_time;
                total_validate_time += validate_time;
            }
        }
        
        let total_time = start_time.elapsed();
        
        info!("=== JWT Benchmark Results ===");
        info!("Total operations: {}", config.iterations);
        info!("Successful operations: {}", successful_operations);
        info!("Total benchmark time: {:?}", total_time);
        info!("Average create time: {:?}", total_create_time / successful_operations as u32);
        info!("Average validate time: {:?}", total_validate_time / successful_operations as u32);
        info!("Operations per second: {:.2}", successful_operations as f64 / total_time.as_secs_f64());
    }
}

#[cfg(feature = "post-quantum")]
async fn benchmark_post_quantum(_config: &BenchmarkConfig) {
    info!("Benchmarking post-quantum cryptographic operations");
    warn!("Post-quantum benchmarking not yet implemented");
    // TODO: Implement post-quantum crypto benchmarking
}

#[cfg(not(feature = "post-quantum"))]
async fn benchmark_post_quantum(_config: &BenchmarkConfig) {
    warn!("Post-quantum benchmarking requires post-quantum feature");
}

// Helper functions

fn generate_test_passwords(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("test_password_{}_with_sufficient_entropy", i))
        .collect()
}

fn generate_test_data(size_bytes: usize, count: usize) -> Vec<Vec<u8>> {
    use fastrand::Rng;
    
    let rng = Rng::new();
    (0..count)
        .map(|_| {
            (0..size_bytes)
                .map(|_| rng.u8(..))
                .collect()
        })
        .collect()
}

#[cfg(feature = "crypto")]
fn generate_test_claims(count: usize) -> Vec<Claims> {
    (0..count)
        .map(|i| Claims {
            sub: format!("user_{}", i),
            exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
            iat: chrono::Utc::now().timestamp() as usize,
            iss: Some("benchmark".to_string()),
            aud: Some(vec!["test".to_string()]),
            custom_claims: std::collections::HashMap::new(),
        })
        .collect()
}

#[cfg(not(feature = "crypto"))]
fn generate_test_claims(_count: usize) -> Vec<()> {
    Vec::new()
}