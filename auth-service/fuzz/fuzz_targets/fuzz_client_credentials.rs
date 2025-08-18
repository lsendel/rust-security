#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use auth_service::security::validate_client_credentials;

#[derive(Arbitrary, Debug)]
struct ClientCredentials {
    client_id: String,
    client_secret: String,
}

fuzz_target!(|input: ClientCredentials| {
    // Fuzz client credentials validation - should never panic
    let _ = validate_client_credentials(&input.client_id, &input.client_secret);
});

// Fuzz with raw bytes to test edge cases
fuzz_target!(|data: &[u8]| {
    if data.len() >= 2 {
        let mid = data.len() / 2;
        let client_id = String::from_utf8_lossy(&data[..mid]);
        let client_secret = String::from_utf8_lossy(&data[mid..]);
        
        let _ = validate_client_credentials(&client_id, &client_secret);
    }
});