#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::pii_protection::{redact_pii, classify_data_sensitivity};

#[derive(Arbitrary, Debug)]
struct PiiInput {
    text: String,
    email: String,
    phone: String,
    ssn: String,
    credit_card: String,
}

fuzz_target!(|input: PiiInput| {
    // Fuzz PII redaction - should never panic
    let _ = redact_pii(&input.text);
    
    // Test with constructed PII-containing text
    let mixed_text = format!(
        "{} email: {} phone: {} ssn: {} cc: {} {}",
        input.text, input.email, input.phone, input.ssn, input.credit_card, input.text
    );
    let _ = redact_pii(&mixed_text);
    
    // Fuzz data classification - should never panic
    let _ = classify_data_sensitivity(&input.text);
    let _ = classify_data_sensitivity(&mixed_text);
});

// Fuzz with raw bytes to test edge cases
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    
    // Test PII redaction with potentially invalid UTF-8
    let _ = redact_pii(&text);
    let _ = classify_data_sensitivity(&text);
    
    // Test idempotency - redacting twice should be safe
    let redacted_once = redact_pii(&text);
    let _ = redact_pii(&redacted_once);
});

// Fuzz with common PII patterns
fuzz_target!(|data: &[u8]| {
    if data.len() >= 10 {
        let base_text = String::from_utf8_lossy(data);
        
        // Create various email-like patterns
        let email_patterns = vec![
            format!("{}@{}.com", &base_text[0..5.min(base_text.len())], &base_text[5..10.min(base_text.len())]),
            format!("user@{}.org", base_text),
            format!("{}@domain.{}", base_text, "net"),
        ];
        
        for pattern in email_patterns {
            let _ = redact_pii(&pattern);
        }
        
        // Create phone-like patterns
        if data.len() >= 10 {
            let digits: String = data.iter().take(10).map(|b| (b % 10 + 48) as char).collect();
            let phone_patterns = vec![
                format!("{}-{}-{}", &digits[0..3], &digits[3..6], &digits[6..10]),
                format!("({}) {}-{}", &digits[0..3], &digits[3..6], &digits[6..10]),
                digits.clone(),
            ];
            
            for pattern in phone_patterns {
                let _ = redact_pii(&pattern);
            }
        }
    }
});

// Fuzz with Unicode and special characters
fuzz_target!(|data: &[u8]| {
    // Create mixed content with Unicode
    let mut text = String::from_utf8_lossy(data).to_string();
    
    // Add some Unicode characters
    text.push_str("测试 🔒 Ñiño @example.com");
    text.push_str(&format!(" {} más texto", String::from_utf8_lossy(data)));
    
    let _ = redact_pii(&text);
    let _ = classify_data_sensitivity(&text);
});

// Fuzz performance with large inputs
fuzz_target!(|data: &[u8]| {
    if !data.is_empty() {
        // Create a large input by repeating the data
        let large_input = String::from_utf8_lossy(data).repeat(100);
        
        // This should complete in reasonable time
        let start = std::time::Instant::now();
        let _ = redact_pii(&large_input);
        let duration = start.elapsed();
        
        // Assert it doesn't take too long (though this won't panic in fuzzing)
        if duration.as_secs() > 5 {
            // Log performance issue but don't panic
            eprintln!("PII redaction took too long: {:?} for {} chars", duration, large_input.len());
        }
    }
});

// Fuzz edge cases with mixed content types
fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    
    // Test with various delimiters and patterns
    let test_cases = vec![
        format!("Contact: {}", text),
        format!("Data: {} END", text),
        format!("{}|{}|{}", text, text, text),
        format!("{}\n{}\t{}", text, text, text),
        format!("{}; DROP TABLE users; -- {}", text, text),
        format!("<script>{}</script>", text),
        format!("javascript:{}", text),
    ];
    
    for test_case in test_cases {
        let _ = redact_pii(&test_case);
        let _ = classify_data_sensitivity(&test_case);
    }
});