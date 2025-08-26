use std::time::{SystemTime, UNIX_EPOCH};

/// Generate a realistic-looking TOTP code for testing
pub fn generate_realistic_totp() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    generate_totp_for_time(timestamp)
}

/// Generate TOTP code for specific timestamp
pub fn generate_totp_for_time(timestamp: u64) -> String {
    // Simple TOTP-like generation for testing purposes
    // In real implementation, this would use proper HMAC-SHA1
    let time_step = timestamp / 30; // 30-second window
    let code = (time_step % 1000000) as u32;
    format!("{:06}", code)
}

/// Generate common TOTP patterns for brute force testing
pub fn generate_common_patterns() -> Vec<String> {
    vec![
        "000000".to_string(),
        "123456".to_string(),
        "111111".to_string(),
        "222222".to_string(),
        "333333".to_string(),
        "444444".to_string(),
        "555555".to_string(),
        "666666".to_string(),
        "777777".to_string(),
        "888888".to_string(),
        "999999".to_string(),
        "012345".to_string(),
        "654321".to_string(),
        "987654".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let totp = generate_realistic_totp();
        assert_eq!(totp.len(), 6);
        assert!(totp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_totp_for_time() {
        let timestamp = 1640995200; // Fixed timestamp
        let totp = generate_totp_for_time(timestamp);
        assert_eq!(totp.len(), 6);
        
        // Same timestamp should generate same TOTP
        let totp2 = generate_totp_for_time(timestamp);
        assert_eq!(totp, totp2);
    }
}
