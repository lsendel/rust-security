use std::borrow::Cow;
use std::sync::Arc;

/// Optimized string handling for configuration and shared data
pub type SharedString = Arc<str>;
pub type OptionalString<'a> = Cow<'a, str>;

/// Create a shared string from a regular string
pub fn shared_string(s: impl Into<String>) -> SharedString {
    s.into().into()
}

/// Format error message with conditional allocation
pub fn format_error_message<'a>(
    template: &'a str,
    dynamic_part: Option<&str>,
) -> Cow<'a, str> {
    match dynamic_part {
        Some(part) => Cow::Owned(format!("{}: {}", template, part)),
        None => Cow::Borrowed(template),
    }
}

/// Optimized configuration struct using shared strings
#[derive(Clone)]
pub struct OptimizedConfig {
    pub database_url: SharedString,
    pub redis_url: SharedString,
    pub jwt_secret: SharedString,
}

impl OptimizedConfig {
    pub fn new(database_url: String, redis_url: String, jwt_secret: String) -> Self {
        Self {
            database_url: shared_string(database_url),
            redis_url: shared_string(redis_url),
            jwt_secret: shared_string(jwt_secret),
        }
    }
}
