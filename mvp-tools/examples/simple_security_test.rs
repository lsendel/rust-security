//! Simple test to verify our security concepts work
//! Run with: rustc simple_security_test.rs && ./simple_security_test

// Simple input sanitizer
fn sanitize_input(input: &str) -> String {
    input
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
        .replace("&", "&amp;")
}

// Basic input validation
fn is_valid_username(username: &str) -> bool {
    // Allow letters, numbers, underscore and dash only, 3-20 chars
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let len = username.chars().count();
    (3..=20).contains(&len) && username.chars().all(allowed)
}

// Basic port validation
fn parse_port(s: &str) -> Option<u16> {
    s.parse().ok()
}

// Safe command builder - NEVER execute directly in shell
fn build_safe_command(cmd: &str, args: &[&str]) -> Vec<String> {
    let mut result = vec![cmd.to_string()];
    for arg in args {
        // Keep only safe characters
        let safe: String = arg
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "-_./:@".contains(*c))
            .collect();
        result.push(safe);
    }
    result
}

// Simple secure random generator
fn generate_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// Simple secure hasher
fn hash_password(password: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

// Configuration security
fn get_env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) Input sanitization
    let dirty = "<script>alert('xss')</script>";
    let clean = sanitize_input(dirty);
    assert!(!clean.contains("<script>"));

    // 2) Username validation
    assert!(is_valid_username("alice_123"));
    assert!(!is_valid_username("bad user name"));

    // 3) Port parsing
    assert_eq!(parse_port("8080"), Some(8080));
    assert_eq!(parse_port("bad"), None);

    // 4) Command building
    let cmd = build_safe_command("curl", &["http://example.com?a=1&b=2", "-H", "X-Foo:bar"]);
    assert_eq!(cmd[0], "curl");

    // 5) Secure random
    let sid = generate_session_id();
    assert_eq!(sid.len(), 32);

    // 6) Hashing
    let h = hash_password("secret");
    assert_eq!(h.len(), 64);

    // 7) Env read
    let _ = get_env_var("PATH");

    println!("OK");
    Ok(())
}
