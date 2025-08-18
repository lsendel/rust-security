use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign a request using the same scheme as the service middleware
/// message = method + "\n" + path + "\n" + body + "\n" + timestamp
pub fn sign_request(method: &str, path: &str, body: &str) -> (String, String) {
    let secret = std::env::var("REQUEST_SIGNING_SECRET").unwrap_or_else(|_| "test_secret".to_string());
    let ts = chrono::Utc::now().timestamp();
    let message = format!("{}\n{}\n{}\n{}", method, path, body, ts);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    use base64::Engine;
    let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    (sig, ts.to_string())
}


