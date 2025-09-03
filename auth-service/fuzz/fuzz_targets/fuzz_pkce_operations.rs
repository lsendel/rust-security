#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::security::{
    generate_code_challenge, verify_code_challenge, 
    validate_pkce_params, CodeChallengeMethod
};

#[derive(Arbitrary, Debug)]
struct PkceInput {
    verifier: String,
    challenge: String,
}

fuzz_target!(|input: PkceInput| {
    // Fuzz PKCE challenge generation - should never panic
    let _ = generate_code_challenge(&input.verifier);
    
    // Fuzz PKCE verification - should never panic
    let _ = verify_code_challenge(&input.verifier, &input.challenge);
    
    // Fuzz PKCE validation with S256 method - should never panic
    let _ = validate_pkce_params(&input.verifier, &input.challenge, &CodeChallengeMethod::S256);
});

// Fuzz code challenge method parsing
fuzz_target!(|data: &[u8]| {
    if let Ok(method_str) = std::str::from_utf8(data) {
        let _ = method_str.parse::<CodeChallengeMethod>();
    }
});

// Fuzz with various edge cases
fuzz_target!(|data: &[u8]| {
    let input_str = String::from_utf8_lossy(data);
    
    // Test challenge generation with arbitrary input
    let _ = generate_code_challenge(&input_str);
    
    // Test verification with same input as both verifier and challenge
    let _ = verify_code_challenge(&input_str, &input_str);
    
    // Test with empty strings
    let _ = verify_code_challenge("", &input_str);
    let _ = verify_code_challenge(&input_str, "");
});
