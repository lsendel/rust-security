#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::security::{generate_request_signature, verify_request_signature};

#[derive(Arbitrary, Debug)]
struct SignatureInput {
    method: String,
    path: String,
    body: String,
    timestamp: i64,
    secret: String,
    signature: String,
}

fuzz_target!(|input: SignatureInput| {
    // Fuzz signature generation - should never panic
    let _ = generate_request_signature(
        &input.method,
        &input.path,
        &input.body,
        input.timestamp,
        &input.secret,
    );
    
    // Fuzz signature verification - should never panic
    let _ = verify_request_signature(
        &input.method,
        &input.path,
        &input.body,
        input.timestamp,
        &input.signature,
        &input.secret,
    );
});

// Fuzz with common HTTP methods and edge cases
fuzz_target!(|data: &[u8]| {
    if data.len() >= 20 {
        let method = String::from_utf8_lossy(&data[0..4]);
        let path = String::from_utf8_lossy(&data[4..8]);
        let body = String::from_utf8_lossy(&data[8..12]);
        let secret = String::from_utf8_lossy(&data[12..16]);
        let signature = String::from_utf8_lossy(&data[16..20]);
        
        // Use current timestamp to avoid time window issues
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        
        let _ = generate_request_signature(&method, &path, &body, timestamp, &secret);
        let _ = verify_request_signature(&method, &path, &body, timestamp, &signature, &secret);
    }
});

// Fuzz timestamp edge cases
fuzz_target!(|data: &[u8]| {
    if data.len() >= 8 {
        let timestamp = i64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]);
        
        let method = "POST";
        let path = "/test";
        let body = "test=value";
        let secret = "test_secret";
        
        let _ = generate_request_signature(method, path, body, timestamp, secret);
        
        // Test with obviously invalid signature
        let _ = verify_request_signature(method, path, body, timestamp, "invalid", secret);
    }
});