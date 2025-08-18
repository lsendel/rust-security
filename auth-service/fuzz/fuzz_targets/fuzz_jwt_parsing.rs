#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::keys;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};

#[derive(Arbitrary, Debug)]
struct JwtInput {
    token: String,
    algorithm: u8, // Will be mapped to Algorithm enum
}

impl JwtInput {
    fn get_algorithm(&self) -> Algorithm {
        match self.algorithm % 8 {
            0 => Algorithm::HS256,
            1 => Algorithm::HS384,
            2 => Algorithm::HS512,
            3 => Algorithm::RS256,
            4 => Algorithm::RS384,
            5 => Algorithm::RS512,
            6 => Algorithm::ES256,
            7 => Algorithm::ES384,
            _ => Algorithm::RS256, // default
        }
    }
}

fuzz_target!(|input: JwtInput| {
    // Fuzz JWT header decoding - should never panic
    let _ = decode_header(&input.token);
    
    // Fuzz JWT decoding with various algorithms and keys
    let algorithm = input.get_algorithm();
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = false; // Disable expiration for fuzzing
    validation.validate_aud = false; // Disable audience validation for fuzzing
    
    // Try decoding with various keys
    let dummy_secret = b"dummy_secret_for_fuzzing";
    let dummy_key = DecodingKey::from_secret(dummy_secret);
    let _ = decode::<serde_json::Value>(&input.token, &dummy_key, &validation);
    
    // Try with RSA key if available
    if let Ok(rsa_key) = keys::get_public_key() {
        let rsa_decoding_key = DecodingKey::from_rsa_pem(&rsa_key);
        if let Ok(key) = rsa_decoding_key {
            let _ = decode::<serde_json::Value>(&input.token, &key, &validation);
        }
    }
});

// Fuzz with raw bytes to test malformed JWT tokens
fuzz_target!(|data: &[u8]| {
    let token_str = String::from_utf8_lossy(data);
    
    // Test header decoding
    let _ = decode_header(&token_str);
    
    // Test with base64-like input
    if let Ok(token_utf8) = std::str::from_utf8(data) {
        let _ = decode_header(token_utf8);
        
        // Test manual JWT part splitting
        let parts: Vec<&str> = token_utf8.split('.').collect();
        if parts.len() == 3 {
            // Try to decode each part as base64
            for part in parts {
                let _ = base64::decode_config(part, base64::URL_SAFE_NO_PAD);
                let _ = base64::decode(part);
            }
        }
    }
});

// Fuzz JWT creation and parsing round-trip
fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        // Use first 32 bytes as secret
        let secret = &data[0..32];
        let key = jsonwebtoken::EncodingKey::from_secret(secret);
        let decode_key = jsonwebtoken::DecodingKey::from_secret(secret);
        
        // Create a simple claims object
        let claims = serde_json::json!({
            "sub": "test",
            "exp": 1000000000, // Fixed timestamp to avoid expiration issues
            "iat": 999999999,
        });
        
        let header = jsonwebtoken::Header::new(Algorithm::HS256);
        
        // Try to encode
        if let Ok(token) = jsonwebtoken::encode(&header, &claims, &key) {
            // Try to decode back
            let mut validation = Validation::new(Algorithm::HS256);
            validation.validate_exp = false;
            let _ = decode::<serde_json::Value>(&token, &decode_key, &validation);
        }
    }
});

// Fuzz malformed JWT structures
fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    
    // Test various malformed JWT patterns
    let malformed_jwts = vec![
        format!("{}..", input), // Missing parts
        format!("..{}", input), // Missing header and payload
        format!("{}.{}", input, input), // Missing signature
        format!("{}.{}.{}.{}", input, input, input, input), // Too many parts
        input.replace('.', ""), // No separators
        input.replace('.', ".."), // Double separators
    ];
    
    for malformed in malformed_jwts {
        let _ = decode_header(&malformed);
        
        // Try with a dummy key
        let dummy_key = DecodingKey::from_secret(b"test");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        let _ = decode::<serde_json::Value>(&malformed, &dummy_key, &validation);
    }
});