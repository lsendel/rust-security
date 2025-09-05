#![no_main]

use libfuzzer_sys::fuzz_target;
use input_validation::{
    validation::{SecurityValidator, ValidatorConfig, InputType},
    sanitization::{Sanitizer, SanitizationConfig},
};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string
    if let Ok(input) = std::str::from_utf8(data) {
        // Skip inputs that are too large
        if input.len() > 10000 {
            return;
        }
        
        // Create validator and sanitizer
        if let Ok(validator) = SecurityValidator::new(ValidatorConfig::production()) {
            let sanitizer = Sanitizer::strict();
            
            // Test validation for different input types
            let input_types = [
                InputType::Email,
                InputType::Text,
                InputType::Username,
                InputType::ScimFilter,
                InputType::OAuth,
                InputType::Url,
                InputType::Phone,
            ];
            
            for input_type in input_types {
                // Validate input
                let _ = validator.validate(input, input_type);
                
                // Check injection patterns
                let _ = validator.check_injection(input);
                
                // Sanitize input
                let _ = sanitizer.sanitize(input, input_type);
            }
        }
    }
});
