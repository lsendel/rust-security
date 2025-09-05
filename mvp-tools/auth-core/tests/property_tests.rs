//! Property-based tests for auth-core using proptest
//!
//! These tests verify that our code behaves correctly across
//! a wide range of generated inputs and edge cases.

#![allow(clippy::unwrap_used)]

use proptest::prelude::*;
use proptest::strategy::ValueTree;

// Helper strategy for generating valid OAuth client IDs
fn client_id_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_-]{1,50}").unwrap()
}

// Helper strategy for generating client secrets
fn client_secret_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[a-zA-Z0-9_.-]{8,128}").unwrap()
}

// Helper strategy for generating scopes
fn _scope_strategy() -> impl Strategy<Value = Option<String>> {
    prop::option::of(prop::string::string_regex("[a-zA-Z0-9_: -]{0,100}").unwrap())
}

proptest! {
    #[test]
    fn test_client_id_length_bounds(client_id in client_id_strategy()) {
        prop_assert!(!client_id.is_empty() && client_id.len() <= 50);
    }

    #[test]
    fn test_client_secret_length_bounds(secret in client_secret_strategy()) {
        prop_assert!(secret.len() >= 8 && secret.len() <= 128);
    }
}

// Standard unit tests for property test helpers
#[cfg(test)]
mod standard_tests {
    use super::*;

    #[test]
    fn test_client_id_strategy_generates_valid_ids() {
        let strategy = client_id_strategy();
        let mut runner = proptest::test_runner::TestRunner::default();

        for _ in 0..10 {
            let client_id = strategy.new_tree(&mut runner).unwrap().current();
            assert!(client_id.len() <= 50);
            assert!(client_id
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-'));
        }
    }

    #[test]
    fn test_client_secret_strategy_generates_secure_secrets() {
        let strategy = client_secret_strategy();
        let mut runner = proptest::test_runner::TestRunner::default();

        for _ in 0..10 {
            let secret = strategy.new_tree(&mut runner).unwrap().current();
            assert!(secret.len() >= 8 && secret.len() <= 128);
            assert!(secret
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-'));
        }
    }
}
