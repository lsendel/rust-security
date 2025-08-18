#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct OAuthRequest {
    grant_type: String,
    client_id: String,
    client_secret: String,
    scope: String,
    redirect_uri: String,
    code: String,
    code_verifier: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
    response_type: String,
}

fuzz_target!(|input: OAuthRequest| {
    // Fuzz OAuth parameter parsing by creating form-encoded data
    let form_data = format!(
        "grant_type={}&client_id={}&client_secret={}&scope={}&redirect_uri={}&code={}&code_verifier={}&code_challenge={}&code_challenge_method={}&state={}&response_type={}",
        urlencoding::encode(&input.grant_type),
        urlencoding::encode(&input.client_id),
        urlencoding::encode(&input.client_secret),
        urlencoding::encode(&input.scope),
        urlencoding::encode(&input.redirect_uri),
        urlencoding::encode(&input.code),
        urlencoding::encode(&input.code_verifier),
        urlencoding::encode(&input.code_challenge),
        urlencoding::encode(&input.code_challenge_method),
        urlencoding::encode(&input.state),
        urlencoding::encode(&input.response_type),
    );
    
    // Test form parsing
    let _ = serde_urlencoded::from_str::<serde_json::Value>(&form_data);
    
    // Test JSON parsing as well
    let json_data = serde_json::json!({
        "grant_type": input.grant_type,
        "client_id": input.client_id,
        "client_secret": input.client_secret,
        "scope": input.scope,
        "redirect_uri": input.redirect_uri,
        "code": input.code,
        "code_verifier": input.code_verifier,
        "code_challenge": input.code_challenge,
        "code_challenge_method": input.code_challenge_method,
        "state": input.state,
        "response_type": input.response_type,
    });
    
    let _ = serde_json::to_string(&json_data);
});

// Fuzz raw form data parsing
fuzz_target!(|data: &[u8]| {
    if let Ok(form_str) = std::str::from_utf8(data) {
        // Test various parsing functions that might be used
        let _ = serde_urlencoded::from_str::<serde_json::Value>(form_str);
        let _ = url::form_urlencoded::parse(form_str.as_bytes());
        
        // Test URL parsing
        if let Ok(url_str) = format!("https://example.com?{}", form_str).parse::<url::Url>() {
            for (key, value) in url_str.query_pairs() {
                // Simulate processing query parameters
                let _ = (key.to_string(), value.to_string());
            }
        }
    }
});

// Fuzz authorization URL parsing
fuzz_target!(|data: &[u8]| {
    if let Ok(url_str) = std::str::from_utf8(data) {
        // Test URL parsing for authorization endpoints
        if url_str.starts_with("http") {
            if let Ok(parsed_url) = url_str.parse::<url::Url>() {
                // Extract query parameters that OAuth endpoints would process
                for (key, value) in parsed_url.query_pairs() {
                    match key.as_ref() {
                        "client_id" | "redirect_uri" | "scope" | "state" | 
                        "response_type" | "code_challenge" | "code_challenge_method" => {
                            // Simulate validation that endpoints would do
                            let _ = auth_service::security::validate_token_input(&value);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
});