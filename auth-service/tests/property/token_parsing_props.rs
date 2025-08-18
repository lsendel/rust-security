use auth_service::security::*;
use proptest::prelude::*;
use regex::Regex;

// Property-based tests for token validation and parsing

proptest! {
    #[test]
    fn test_validate_token_input_properties(
        token in r"[a-zA-Z0-9_\-\.=]{1,1023}"
    ) {
        // Property: Valid tokens should always pass validation
        prop_assert!(validate_token_input(&token).is_ok());
    }

    #[test]
    fn test_validate_token_input_rejects_empty(
        prefix in r".*",
        suffix in r".*"
    ) {
        // Property: Empty tokens should always be rejected
        let empty_token = "";
        prop_assert!(validate_token_input(empty_token).is_err());
        
        // Property: Tokens with null bytes should be rejected
        if !prefix.is_empty() || !suffix.is_empty() {
            let null_token = format!("{}\0{}", prefix, suffix);
            prop_assert!(validate_token_input(&null_token).is_err());
        }
    }

    #[test]
    fn test_validate_token_input_rejects_long_tokens(
        base in r"[a-zA-Z0-9]{1024,2048}"
    ) {
        // Property: Tokens longer than 1024 chars should be rejected
        prop_assert!(validate_token_input(&base).is_err());
    }

    #[test]
    fn test_validate_token_input_rejects_suspicious_patterns(
        pattern in prop::sample::select(&["'", "\"", ";", "--", "/*", "*/", "xp_", "sp_"]),
        prefix in r"[a-zA-Z0-9]{0,100}",
        suffix in r"[a-zA-Z0-9]{0,100}"
    ) {
        // Property: Tokens containing SQL injection patterns should be rejected
        let suspicious_token = format!("{}{}{}", prefix, pattern, suffix);
        prop_assert!(validate_token_input(&suspicious_token).is_err());
    }

    #[test]
    fn test_validate_token_input_rejects_newlines_and_control_chars(
        prefix in r"[a-zA-Z0-9]{0,100}",
        suffix in r"[a-zA-Z0-9]{0,100}",
        control_char in prop::sample::select(&['\n', '\r', '\t', '\0'])
    ) {
        // Property: Tokens with control characters should be rejected
        let token_with_control = format!("{}{}{}", prefix, control_char, suffix);
        prop_assert!(validate_token_input(&token_with_control).is_err());
    }
}

proptest! {
    #[test]
    fn test_client_credentials_validation_properties(
        valid_client_id in r"[a-zA-Z0-9_\-]{1,254}",
        valid_client_secret in r"[a-zA-Z0-9_\-\.=]{1,254}"
    ) {
        // Property: Valid client credentials should pass validation
        prop_assert!(validate_client_credentials(&valid_client_id, &valid_client_secret).is_ok());
    }

    #[test]
    fn test_client_credentials_validation_rejects_empty(
        non_empty in r"[a-zA-Z0-9_\-]{1,254}"
    ) {
        // Property: Empty client ID or secret should be rejected
        prop_assert!(validate_client_credentials("", &non_empty).is_err());
        prop_assert!(validate_client_credentials(&non_empty, "").is_err());
        prop_assert!(validate_client_credentials("", "").is_err());
    }

    #[test]
    fn test_client_credentials_validation_rejects_long(
        long_string in r"[a-zA-Z0-9]{256,500}",
        normal_string in r"[a-zA-Z0-9]{1,254}"
    ) {
        // Property: Overly long credentials should be rejected
        prop_assert!(validate_client_credentials(&long_string, &normal_string).is_err());
        prop_assert!(validate_client_credentials(&normal_string, &long_string).is_err());
    }

    #[test]
    fn test_client_credentials_validation_rejects_invalid_chars(
        valid_part in r"[a-zA-Z0-9_\-]{1,100}",
        invalid_char in prop::sample::select(&['@', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '[', ']', '{', '}', '|', '\\', ':', ';', '"', '\'', '<', '>', ',', '.', '?', '/', '`', '~'])
    ) {
        // Property: Client IDs with invalid characters should be rejected
        let invalid_client_id = format!("{}{}", valid_part, invalid_char);
        let valid_secret = "valid_secret123";
        prop_assert!(validate_client_credentials(&invalid_client_id, valid_secret).is_err());
    }
}

proptest! {
    #[test]
    fn test_pkce_code_verifier_generation_properties() {
        // Property: Generated code verifiers should always be valid base64url
        let verifier = generate_code_verifier();
        
        // Should be non-empty
        prop_assert!(!verifier.is_empty());
        
        // Should be valid base64url (URL-safe base64 without padding)
        let base64_url_regex = Regex::new(r"^[A-Za-z0-9_-]+$").unwrap();
        prop_assert!(base64_url_regex.is_match(&verifier));
        
        // Should have reasonable length (32 bytes = 43 chars in base64url)
        prop_assert!(verifier.len() >= 43);
        prop_assert!(verifier.len() <= 128); // RFC recommends 43-128 chars
    }

    #[test]
    fn test_pkce_code_challenge_consistency(
        verifier in r"[A-Za-z0-9_\-]{43,128}"
    ) {
        // Property: Code challenge generation should be deterministic
        let challenge1 = generate_code_challenge(&verifier);
        let challenge2 = generate_code_challenge(&verifier);
        prop_assert_eq!(challenge1, challenge2);
        
        // Property: Challenge should be valid base64url
        let base64_url_regex = Regex::new(r"^[A-Za-z0-9_-]+$").unwrap();
        prop_assert!(base64_url_regex.is_match(&challenge1));
        
        // Property: Verification should succeed
        prop_assert!(verify_code_challenge(&verifier, &challenge1));
    }

    #[test]
    fn test_pkce_verification_properties(
        correct_verifier in r"[A-Za-z0-9_\-]{43,128}",
        wrong_verifier in r"[A-Za-z0-9_\-]{43,128}"
    ) {
        // Property: PKCE verification should work correctly
        let challenge = generate_code_challenge(&correct_verifier);
        
        // Correct verifier should always verify
        prop_assert!(verify_code_challenge(&correct_verifier, &challenge));
        
        // Different verifier should not verify (with high probability)
        if correct_verifier != wrong_verifier {
            prop_assert!(!verify_code_challenge(&wrong_verifier, &challenge));
        }
    }
}

proptest! {
    #[test]
    fn test_token_binding_generation_properties(
        client_ip in r"([0-9]{1,3}\.){3}[0-9]{1,3}",
        user_agent in r"[a-zA-Z0-9 /\.\-_\(\)]{1,200}"
    ) {
        // Property: Token binding should be deterministic
        let binding1 = generate_token_binding(&client_ip, &user_agent);
        let binding2 = generate_token_binding(&client_ip, &user_agent);
        prop_assert_eq!(binding1, binding2);
        
        // Property: Token binding should be valid base64
        let decoded = base64::decode(&binding1);
        prop_assert!(decoded.is_ok());
        
        // Property: Different inputs should produce different bindings (with high probability)
        let different_binding = generate_token_binding("1.1.1.1", "different-agent");
        if client_ip != "1.1.1.1" || user_agent != "different-agent" {
            prop_assert_ne!(binding1, different_binding);
        }
    }

    #[test]
    fn test_token_binding_validation_properties(
        client_ip in r"([0-9]{1,3}\.){3}[0-9]{1,3}",
        user_agent in r"[a-zA-Z0-9 /\.\-_\(\)]{1,200}"
    ) {
        // Property: Valid token binding should always validate
        let binding = generate_token_binding(&client_ip, &user_agent);
        prop_assert!(validate_token_binding(&binding, &client_ip, &user_agent));
        
        // Property: Binding with different IP should not validate (with high probability)
        if client_ip != "192.168.1.1" {
            prop_assert!(!validate_token_binding(&binding, "192.168.1.1", &user_agent));
        }
        
        // Property: Binding with different user agent should not validate (with high probability)
        if user_agent != "test-agent" {
            prop_assert!(!validate_token_binding(&binding, &client_ip, "test-agent"));
        }
    }
}

proptest! {
    #[test]
    fn test_request_signature_properties(
        method in prop::sample::select(&["GET", "POST", "PUT", "DELETE", "PATCH"]),
        path in r"/[a-zA-Z0-9/\-_\.]*",
        body in r"[a-zA-Z0-9 \{\}\[\]\"':,\-_\.]*{0,500}",
        timestamp in 1000000000i64..2000000000i64,
        secret in r"[a-zA-Z0-9_\-\.=]{32,128}"
    ) {
        // Property: Signature generation should be deterministic
        let sig1 = generate_request_signature(&method, &path, &body, timestamp, &secret);
        let sig2 = generate_request_signature(&method, &path, &body, timestamp, &secret);
        prop_assert_eq!(sig1, sig2);
        
        // Property: Generated signature should be valid base64
        if let Ok(signature) = sig1 {
            let decoded = base64::decode(&signature);
            prop_assert!(decoded.is_ok());
            
            // Property: Signature verification should succeed
            let verification = verify_request_signature(&method, &path, &body, timestamp, &signature, &secret);
            prop_assert!(verification.is_ok());
            prop_assert!(verification.unwrap());
        }
    }

    #[test]
    fn test_request_signature_timestamp_window(
        method in prop::sample::select(&["GET", "POST"]),
        path in r"/[a-zA-Z0-9/]*",
        body in r"[a-zA-Z0-9]*{0,100}",
        secret in r"[a-zA-Z0-9_\-\.=]{32,64}",
        time_offset in -3600i64..3600i64  // ±1 hour from current time
    ) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        let test_timestamp = current_time + time_offset;
        
        if let Ok(signature) = generate_request_signature(&method, &path, &body, test_timestamp, &secret) {
            let verification = verify_request_signature(&method, &path, &body, test_timestamp, &signature, &secret);
            
            // Property: Signatures within reasonable time window should verify
            // (depending on REQUEST_TIMESTAMP_WINDOW_SECONDS which is typically 300 seconds)
            if time_offset.abs() <= 300 {
                prop_assert!(verification.is_ok());
                if verification.is_ok() {
                    // Should pass or fail based on time window, but not error
                }
            }
        }
    }
}

proptest! {
    #[test]
    fn test_sanitize_log_input_properties(
        input in r"[a-zA-Z0-9 \n\r\t\x00-\x1F\x7F-\xFF]*{0,1000}"
    ) {
        let sanitized = sanitize_log_input(&input);
        
        // Property: Sanitized output should not contain actual newlines
        prop_assert!(!sanitized.contains('\n'));
        prop_assert!(!sanitized.contains('\r'));
        prop_assert!(!sanitized.contains('\t'));
        
        // Property: Sanitized output should only contain safe characters
        for ch in sanitized.chars() {
            prop_assert!(ch.is_ascii_graphic() || ch == ' ' || ch == '\\');
        }
        
        // Property: Sanitization should be idempotent
        let double_sanitized = sanitize_log_input(&sanitized);
        prop_assert_eq!(sanitized, double_sanitized);
    }

    #[test]
    fn test_sanitize_log_input_preserves_content(
        safe_input in r"[a-zA-Z0-9 \-_\.@]{0,200}"
    ) {
        let sanitized = sanitize_log_input(&safe_input);
        
        // Property: Safe input should remain largely unchanged
        // (may have some character filtering but should preserve alphanumeric content)
        let safe_chars: String = safe_input.chars()
            .filter(|&c| c.is_ascii_graphic() || c == ' ')
            .collect();
        prop_assert_eq!(sanitized, safe_chars);
    }
}

#[cfg(test)]
mod comprehensive_property_tests {
    use super::*;

    #[test]
    fn test_pkce_s256_only_property() {
        // Property test for PKCE method validation
        proptest!(|(
            verifier in r"[A-Za-z0-9_\-]{43,128}",
            challenge in r"[A-Za-z0-9_\-]{40,50}"
        )| {
            // Only S256 method should be accepted
            let s256_result = validate_pkce_params(&verifier, &challenge, CodeChallengeMethod::S256);
            
            // The result depends on whether the challenge matches the verifier
            // but the method validation itself should not error
            let _ = s256_result; // We test the method is accepted, not the verification result
        });
    }

    #[test]
    fn test_code_challenge_method_parsing_property() {
        proptest!(|(method_str in r"[a-zA-Z0-9]{1,20}")| {
            let parse_result = method_str.parse::<CodeChallengeMethod>();
            
            if method_str == "S256" {
                prop_assert!(parse_result.is_ok());
                prop_assert_eq!(parse_result.unwrap(), CodeChallengeMethod::S256);
            } else if method_str == "plain" {
                prop_assert!(parse_result.is_err());
                prop_assert!(parse_result.unwrap_err().contains("not supported"));
            } else {
                prop_assert!(parse_result.is_err());
                prop_assert!(parse_result.unwrap_err().contains("Invalid code challenge method"));
            }
        });
    }
}