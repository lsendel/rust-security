use auth_service::pii_protection::*;
use proptest::prelude::*;
use regex::Regex;

// Property-based tests for PII detection and redaction

proptest! {
    #[test]
    fn test_email_redaction_properties(
        local_part in r"[a-zA-Z0-9]{1,20}",
        domain in r"[a-zA-Z0-9]{1,10}",
        tld in r"[a-zA-Z]{2,4}",
        prefix in r"[a-zA-Z0-9 ]{0,50}",
        suffix in r"[a-zA-Z0-9 ]{0,50}"
    ) {
        let email = format!("{}@{}.{}", local_part, domain, tld);
        let input = format!("{} {} {}", prefix, email, suffix);
        
        let redacted = redact_pii(&input);
        
        // Property: Email should be redacted
        prop_assert!(!redacted.contains(&email), "Email {} should be redacted in: {}", email, redacted);
        
        // Property: Redacted output should contain redaction marker
        prop_assert!(redacted.contains("[REDACTED_EMAIL]") || redacted.contains("***"));
        
        // Property: Non-email content should be preserved
        if !prefix.trim().is_empty() {
            prop_assert!(redacted.contains(prefix.trim()));
        }
        if !suffix.trim().is_empty() {
            prop_assert!(redacted.contains(suffix.trim()));
        }
    }

    #[test]
    fn test_phone_number_redaction_properties(
        area_code in r"[0-9]{3}",
        exchange in r"[0-9]{3}",
        number in r"[0-9]{4}",
        prefix in r"[a-zA-Z ]{0,20}",
        suffix in r"[a-zA-Z ]{0,20}"
    ) {
        // Test various phone number formats
        let phone_formats = vec![
            format!("{}-{}-{}", area_code, exchange, number),
            format!("({}) {}-{}", area_code, exchange, number),
            format!("{}.{}.{}", area_code, exchange, number),
            format!("{}{}{}", area_code, exchange, number),
        ];
        
        for phone in phone_formats {
            let input = format!("{} {} {}", prefix, phone, suffix);
            let redacted = redact_pii(&input);
            
            // Property: Phone number should be redacted
            prop_assert!(!redacted.contains(&phone), "Phone {} should be redacted in: {}", phone, redacted);
            
            // Property: Redacted output should contain redaction marker
            prop_assert!(redacted.contains("[REDACTED_PHONE]") || redacted.contains("***"));
        }
    }

    #[test]
    fn test_ssn_redaction_properties(
        area in r"[0-9]{3}",
        group in r"[0-9]{2}",
        serial in r"[0-9]{4}",
        context in r"[a-zA-Z ]{0,30}"
    ) {
        let ssn_formats = vec![
            format!("{}-{}-{}", area, group, serial),
            format!("{} {} {}", area, group, serial),
            format!("{}{}{}", area, group, serial),
        ];
        
        for ssn in ssn_formats {
            let input = format!("{} SSN: {} end", context, ssn);
            let redacted = redact_pii(&input);
            
            // Property: SSN should be redacted
            prop_assert!(!redacted.contains(&ssn), "SSN {} should be redacted in: {}", ssn, redacted);
            
            // Property: Redacted output should contain appropriate marker
            prop_assert!(redacted.contains("[REDACTED_SSN]") || redacted.contains("***"));
        }
    }

    #[test]
    fn test_credit_card_redaction_properties(
        first_four in r"[0-9]{4}",
        second_four in r"[0-9]{4}",
        third_four in r"[0-9]{4}",
        fourth_four in r"[0-9]{4}",
        text_before in r"[a-zA-Z ]{0,20}",
        text_after in r"[a-zA-Z ]{0,20}"
    ) {
        let cc_formats = vec![
            format!("{} {} {} {}", first_four, second_four, third_four, fourth_four),
            format!("{}-{}-{}-{}", first_four, second_four, third_four, fourth_four),
            format!("{}{}{}{}", first_four, second_four, third_four, fourth_four),
        ];
        
        for cc in cc_formats {
            let input = format!("{} card: {} {}", text_before, cc, text_after);
            let redacted = redact_pii(&input);
            
            // Property: Credit card should be redacted
            prop_assert!(!redacted.contains(&cc), "Credit card {} should be redacted in: {}", cc, redacted);
            
            // Property: Should contain redaction marker
            prop_assert!(redacted.contains("[REDACTED_CC]") || redacted.contains("***"));
        }
    }
}

proptest! {
    #[test]
    fn test_multiple_pii_types_redaction(
        email_local in r"[a-zA-Z0-9]{1,10}",
        email_domain in r"[a-zA-Z0-9]{1,8}",
        phone_area in r"[0-9]{3}",
        phone_exchange in r"[0-9]{3}",
        phone_number in r"[0-9]{4}",
        safe_text in r"[a-zA-Z ]{0,30}"
    ) {
        let email = format!("{}@{}.com", email_local, email_domain);
        let phone = format!("{}-{}-{}", phone_area, phone_exchange, phone_number);
        
        let input = format!("{} Contact: {} Phone: {} {}", safe_text, email, phone, safe_text);
        let redacted = redact_pii(&input);
        
        // Property: All PII should be redacted
        prop_assert!(!redacted.contains(&email), "Email should be redacted");
        prop_assert!(!redacted.contains(&phone), "Phone should be redacted");
        
        // Property: Safe text should be preserved
        if !safe_text.trim().is_empty() {
            let words: Vec<&str> = safe_text.split_whitespace().collect();
            for word in words {
                if word.len() > 2 { // Skip very short words that might be false positives
                    prop_assert!(redacted.contains(word), "Safe word '{}' should be preserved", word);
                }
            }
        }
    }

    #[test]
    fn test_redaction_idempotency(
        text_with_email in r"[a-zA-Z ]{0,20}[a-zA-Z0-9]{1,10}@[a-zA-Z0-9]{1,8}\.com[a-zA-Z ]{0,20}"
    ) {
        let redacted_once = redact_pii(&text_with_email);
        let redacted_twice = redact_pii(&redacted_once);
        
        // Property: Redaction should be idempotent
        prop_assert_eq!(redacted_once, redacted_twice, 
            "Redaction should be idempotent. First: {}, Second: {}", 
            redacted_once, redacted_twice);
    }

    #[test]
    fn test_safe_text_preservation(
        safe_text in r"[a-zA-Z0-9 \.\-_]{1,200}"
    ) {
        // Filter out potential PII patterns
        let email_regex = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
        let phone_regex = Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap();
        let ssn_regex = Regex::new(r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b").unwrap();
        let cc_regex = Regex::new(r"\b\d{4}[-.]?\d{4}[-.]?\d{4}[-.]?\d{4}\b").unwrap();
        
        if !email_regex.is_match(&safe_text) && 
           !phone_regex.is_match(&safe_text) && 
           !ssn_regex.is_match(&safe_text) && 
           !cc_regex.is_match(&safe_text) {
            
            let redacted = redact_pii(&safe_text);
            
            // Property: Text without PII should remain largely unchanged
            // (allowing for minor whitespace normalization)
            let normalized_original = safe_text.split_whitespace().collect::<Vec<_>>().join(" ");
            let normalized_redacted = redacted.split_whitespace().collect::<Vec<_>>().join(" ");
            
            prop_assert_eq!(normalized_original, normalized_redacted,
                "Safe text should be preserved. Original: '{}', Redacted: '{}'", 
                safe_text, redacted);
        }
    }
}

proptest! {
    #[test]
    fn test_edge_case_patterns(
        numbers in r"[0-9]{1,20}",
        letters in r"[a-zA-Z]{1,20}",
        symbols in prop::sample::select(&["@", ".", "-", "_", " "])
    ) {
        let mixed_input = format!("{}{}{}", numbers, symbols, letters);
        let redacted = redact_pii(&mixed_input);
        
        // Property: Redaction should not crash on edge cases
        prop_assert!(!redacted.is_empty(), "Redacted output should not be empty");
        
        // Property: Output should be valid UTF-8
        prop_assert!(redacted.is_ascii() || redacted.chars().all(|c| c.is_ascii() || c.is_alphabetic()));
    }

    #[test]
    fn test_boundary_conditions(
        very_long_string in r"[a-zA-Z0-9@\.\- ]{1000,2000}"
    ) {
        let redacted = redact_pii(&very_long_string);
        
        // Property: Should handle long strings without panic
        prop_assert!(!redacted.is_empty());
        
        // Property: Should not significantly expand the string length
        // (some expansion is expected due to redaction markers)
        prop_assert!(redacted.len() <= very_long_string.len() * 2, 
            "Redacted string should not be more than 2x original length");
    }

    #[test]
    fn test_nested_pii_patterns(
        email_part1 in r"[a-zA-Z0-9]{1,5}",
        email_part2 in r"[a-zA-Z0-9]{1,5}",
        domain in r"[a-zA-Z]{1,8}",
        digits in r"[0-9]{3,15}"
    ) {
        // Create input with potential overlapping or nested patterns
        let complex_input = format!("{}@{}.com and {} more digits {}", 
            email_part1, domain, digits, email_part2);
        
        let redacted = redact_pii(&complex_input);
        
        // Property: Should handle complex nested patterns
        prop_assert!(!redacted.is_empty());
        
        // Property: Should redact the email
        let full_email = format!("{}@{}.com", email_part1, domain);
        prop_assert!(!redacted.contains(&full_email));
    }
}

proptest! {
    #[test]
    fn test_pii_detection_accuracy(
        definitely_pii_email in r"[a-zA-Z]{1,10}@(gmail|yahoo|hotmail|outlook)\.com",
        definitely_not_pii in r"[a-zA-Z ]{1,50}"
    ) {
        let mixed_input = format!("Contact email: {} and note: {}", definitely_pii_email, definitely_not_pii);
        let redacted = redact_pii(&mixed_input);
        
        // Property: Known PII should be redacted
        prop_assert!(!redacted.contains(&definitely_pii_email), 
            "Email {} should be redacted", definitely_pii_email);
        
        // Property: Non-PII text should be preserved
        let words: Vec<&str> = definitely_not_pii.split_whitespace().collect();
        for word in words {
            if word.len() > 3 && !word.contains('@') && !word.chars().all(|c| c.is_numeric()) {
                prop_assert!(redacted.contains(word), 
                    "Non-PII word '{}' should be preserved in: {}", word, redacted);
            }
        }
    }

    #[test]
    fn test_classification_consistency(
        input_text in r"[a-zA-Z0-9@\.\- ]{1,200}"
    ) {
        let classification1 = classify_data_sensitivity(&input_text);
        let classification2 = classify_data_sensitivity(&input_text);
        
        // Property: Classification should be deterministic
        prop_assert_eq!(classification1, classification2, 
            "Data classification should be consistent for input: {}", input_text);
        
        // Property: Classification should be a valid enum value
        match classification1 {
            DataClassification::Public | 
            DataClassification::Internal | 
            DataClassification::Confidential | 
            DataClassification::Restricted => {
                // Valid classification
            }
        }
    }
}

#[cfg(test)]
mod regression_property_tests {
    use super::*;

    #[test]
    fn test_redaction_performance_property() {
        proptest!(|(input in r"[a-zA-Z0-9@\.\-_ ]{100,500}")| {
            let start_time = std::time::Instant::now();
            let _redacted = redact_pii(&input);
            let duration = start_time.elapsed();
            
            // Property: Redaction should complete quickly
            prop_assert!(duration.as_millis() < 100, 
                "Redaction took too long: {:?} for input length {}", 
                duration, input.len());
        });
    }

    #[test]
    fn test_memory_safety_property() {
        proptest!(|(inputs in prop::collection::vec(r"[a-zA-Z0-9@\.\- ]{0,100}", 1..50))| {
            // Test that multiple redactions don't cause memory issues
            let mut results = Vec::new();
            
            for input in &inputs {
                results.push(redact_pii(input));
            }
            
            // Property: All redactions should succeed
            prop_assert_eq!(results.len(), inputs.len());
            
            // Property: Results should be valid
            for result in results {
                prop_assert!(!result.is_empty() || inputs.iter().any(|i| i.trim().is_empty()));
            }
        });
    }
}