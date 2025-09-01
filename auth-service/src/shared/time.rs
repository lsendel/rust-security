//! Time Utilities
//!
//! Common time-related utilities and helpers.

use chrono::{DateTime, Duration, Utc};

/// Get current UTC timestamp
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// Check if a timestamp is expired
pub fn is_expired(timestamp: DateTime<Utc>) -> bool {
    Utc::now() > timestamp
}

/// Calculate time remaining until expiration
pub fn time_remaining(until: DateTime<Utc>) -> Duration {
    if is_expired(until) {
        Duration::zero()
    } else {
        until - Utc::now()
    }
}

/// Add duration to current time
pub fn add_duration(duration: Duration) -> DateTime<Utc> {
    Utc::now() + duration
}

/// Parse ISO 8601 timestamp
pub fn parse_iso8601(s: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
    DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn test_now() {
        let before = Utc::now();
        let now_time = now();
        let after = Utc::now();

        assert!(now_time >= before);
        assert!(now_time <= after);
    }

    #[test]
    fn test_time_remaining() {
        let future = Utc::now() + chrono::Duration::seconds(1);
        let remaining = time_remaining(future);
        assert!(remaining > chrono::Duration::zero());

        let past = Utc::now() - chrono::Duration::seconds(1);
        let remaining = time_remaining(past);
        assert_eq!(remaining, chrono::Duration::zero());
    }

    #[test]
    fn test_is_expired() {
        let future = Utc::now() + chrono::Duration::seconds(1);
        assert!(!is_expired(future));

        let past = Utc::now() - chrono::Duration::seconds(1);
        assert!(is_expired(past));
    }

    #[test]
    fn test_parse_iso8601() {
        let timestamp = "2023-01-01T12:00:00Z";
        let parsed = parse_iso8601(timestamp);
        assert!(parsed.is_ok());

        let invalid = "invalid-timestamp";
        let parsed = parse_iso8601(invalid);
        assert!(parsed.is_err());
    }
}
