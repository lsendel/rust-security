// Enhanced Security Logging Implementation
// Privacy-safe, structured security event logging with correlation

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    // Authentication events
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthenticationAttempt,

    // Authorization events
    AuthorizationSuccess,
    AuthorizationFailure,
    PermissionDenied,

    // Session events
    SessionCreated,
    SessionDestroyed,
    SessionExpired,
    SessionHijackAttempt,

    // Rate limiting events
    RateLimitExceeded,
    RateLimitWarning,

    // Security violations
    CsrfTokenMissing,
    CsrfTokenInvalid,
    SqlInjectionAttempt,
    XssAttempt,
    SuspiciousActivity,
    SecurityViolation,
    DataAccess,

    // System events
    ConfigurationChange,
    SecurityPolicyViolation,
    ThreatDetected,

    // Attack patterns
    BruteForceAttempt,
    CredentialStuffing,
    AccountEnumeration,
    PrivilegeEscalation,
}

impl std::fmt::Display for SecurityEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SecurityEventType::AuthenticationSuccess => "authentication_success",
            SecurityEventType::AuthenticationFailure => "authentication_failure",
            SecurityEventType::AuthenticationAttempt => "authentication_attempt",
            SecurityEventType::AuthorizationSuccess => "authorization_success",
            SecurityEventType::AuthorizationFailure => "authorization_failure",
            SecurityEventType::PermissionDenied => "permission_denied",
            SecurityEventType::SessionCreated => "session_created",
            SecurityEventType::SessionDestroyed => "session_destroyed",
            SecurityEventType::SessionExpired => "session_expired",
            SecurityEventType::SessionHijackAttempt => "session_hijack_attempt",
            SecurityEventType::RateLimitExceeded => "rate_limit_exceeded",
            SecurityEventType::RateLimitWarning => "rate_limit_warning",
            SecurityEventType::CsrfTokenMissing => "csrf_token_missing",
            SecurityEventType::CsrfTokenInvalid => "csrf_token_invalid",
            SecurityEventType::SqlInjectionAttempt => "sql_injection_attempt",
            SecurityEventType::XssAttempt => "xss_attempt",
            SecurityEventType::SuspiciousActivity => "suspicious_activity",
            SecurityEventType::ConfigurationChange => "configuration_change",
            SecurityEventType::SecurityPolicyViolation => "security_policy_violation",
            SecurityEventType::ThreatDetected => "threat_detected",
            SecurityEventType::BruteForceAttempt => "brute_force_attempt",
            SecurityEventType::CredentialStuffing => "credential_stuffing",
            SecurityEventType::AccountEnumeration => "account_enumeration",
            SecurityEventType::PrivilegeEscalation => "privilege_escalation",
            SecurityEventType::SecurityViolation => "security_violation",
            SecurityEventType::DataAccess => "data_access",
        };
        write!(f, "{}", s)
    }
}

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Warning,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SecuritySeverity::Info => "info",
            SecuritySeverity::Low => "low",
            SecuritySeverity::Medium => "medium",
            SecuritySeverity::High => "high",
            SecuritySeverity::Critical => "critical",
            SecuritySeverity::Warning => "warning",
        };
        write!(f, "{}", s)
    }
}

/// Security event metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetadata {
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub response_status: Option<u16>,
    pub response_time_ms: Option<u64>,
    pub request_size: Option<usize>,
    pub response_size: Option<usize>,
    pub additional_data: HashMap<String, serde_json::Value>,
}

impl Default for SecurityMetadata {
    fn default() -> Self {
        Self {
            user_agent: None,
            referer: None,
            endpoint: None,
            method: None,
            response_status: None,
            response_time_ms: None,
            request_size: None,
            response_size: None,
            additional_data: HashMap::new(),
        }
    }
}

/// Main security event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier
    pub event_id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Type of security event
    pub event_type: SecurityEventType,
    /// Event severity
    pub severity: SecuritySeverity,
    /// Source IP address (optional for privacy)
    pub source_ip: Option<IpAddr>,
    /// Privacy-safe user identifier hash
    pub user_id_hash: Option<String>,
    /// Request correlation ID
    pub correlation_id: String,
    /// Session identifier hash
    pub session_id_hash: Option<String>,
    /// Event description
    pub description: String,
    /// Additional metadata
    pub metadata: SecurityMetadata,
    /// Threat intelligence data
    pub threat_intel: Option<ThreatIntelligence>,
}

/// Threat intelligence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub ip_reputation: Option<IpReputation>,
    pub known_attack_patterns: Vec<String>,
    pub risk_score: f64, // 0.0 to 1.0
    pub country_code: Option<String>,
    pub asn: Option<u32>,
    pub is_tor_exit: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
}

impl SecurityEvent {
    /// Create a new security event
    pub fn new(
        event_type: SecurityEventType,
        severity: SecuritySeverity,
        correlation_id: String,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            severity,
            source_ip: None,
            user_id_hash: None,
            correlation_id,
            session_id_hash: None,
            user_agent: None,
            request_path: None,
            request_method: None,
            response_status: None,
            latency_ms: None,
            threat_indicators: Vec::new(),
            geo_location: None,
            ip_reputation: None,
            additional_context: serde_json::Map::new(),
            tags: Vec::new(),
            privacy_safe_details: None,
        }
    }

    /// Add additional context and return self for method chaining
    pub fn with_context(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional_context.insert(key, value);
        self
    }

    /// Add user information
    pub fn with_user(mut self, user_id_hash: String) -> Self {
        self.user_id_hash = Some(user_id_hash);
        self
    }

    /// Add IP information
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Add reason for the event
    pub fn with_reason(mut self, reason: String) -> Self {
        self.additional_context.insert("reason".to_string(), serde_json::Value::String(reason));
        self
    }
}

/// IP reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpReputation {
    pub score: f64, // 0.0 (bad) to 1.0 (good)
    pub categories: Vec<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub source: String,
}

/// PII detection patterns
pub struct PiiDetector {
    email_regex: Regex,
    phone_regex: Regex,
    ssn_regex: Regex,
    credit_card_regex: Regex,
}

impl PiiDetector {
    pub fn new() -> Self {
        Self {
            email_regex: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
                .unwrap(),
            phone_regex: Regex::new(r"\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b").unwrap(),
            ssn_regex: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            credit_card_regex: Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(),
        }
    }

    pub fn sanitize_text(&self, text: &str) -> String {
        let mut sanitized = text.to_string();

        // Replace email addresses
        sanitized = self
            .email_regex
            .replace_all(&sanitized, "[EMAIL_REDACTED]")
            .to_string();

        // Replace phone numbers
        sanitized = self
            .phone_regex
            .replace_all(&sanitized, "[PHONE_REDACTED]")
            .to_string();

        // Replace SSNs
        sanitized = self
            .ssn_regex
            .replace_all(&sanitized, "[SSN_REDACTED]")
            .to_string();

        // Replace credit card numbers
        sanitized = self
            .credit_card_regex
            .replace_all(&sanitized, "[CC_REDACTED]")
            .to_string();

        sanitized
    }

    /// Convenience method for PII redaction (alias for sanitize_text)
    pub fn redact_pii(&self, text: &str) -> String {
        self.sanitize_text(text)
    }

    /// Hash an identifier for privacy-safe logging
    pub fn hash_identifier(&self, identifier: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        identifier.hash(&mut hasher);
        format!("hash:{:x}", hasher.finish())
    }
}

/// Security event logger configuration
#[derive(Debug, Clone)]
pub struct SecurityLoggerConfig {
    /// Enable PII detection and redaction
    pub enable_pii_protection: bool,
    /// Enable threat intelligence integration
    pub enable_threat_intel: bool,
    /// Log level threshold
    pub min_severity: SecuritySeverity,
    /// Enable structured JSON logging
    pub structured_logging: bool,
    /// Enable log forwarding to SIEM
    pub enable_siem_forwarding: bool,
    /// SIEM endpoint URL
    pub siem_endpoint: Option<String>,
}

impl Default for SecurityLoggerConfig {
    fn default() -> Self {
        Self {
            enable_pii_protection: true,
            enable_threat_intel: true,
            min_severity: SecuritySeverity::Info,
            structured_logging: true,
            enable_siem_forwarding: false,
            siem_endpoint: None,
        }
    }
}

/// Enhanced security logger
pub struct SecurityLogger {
    config: SecurityLoggerConfig,
    pii_detector: PiiDetector,
    event_buffer: Arc<RwLock<Vec<SecurityEvent>>>,
    threat_intel_cache: Arc<RwLock<HashMap<IpAddr, ThreatIntelligence>>>,
}

impl SecurityLogger {
    /// Create new security logger
    pub fn new(config: SecurityLoggerConfig) -> Self {
        Self {
            config,
            pii_detector: PiiDetector::new(),
            event_buffer: Arc::new(RwLock::new(Vec::new())),
            threat_intel_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Log a security event
    pub async fn log_event(&self, mut event: SecurityEvent) {
        // Check severity threshold
        if event.severity < self.config.min_severity {
            return;
        }

        // Sanitize PII if enabled
        if self.config.enable_pii_protection {
            event.description = self.pii_detector.sanitize_text(&event.description);

            // Sanitize metadata
            if let Some(ref mut user_agent) = event.metadata.user_agent {
                *user_agent = self.pii_detector.sanitize_text(user_agent);
            }
        }

        // Add threat intelligence if enabled
        if self.config.enable_threat_intel && event.source_ip.is_some() {
            event.threat_intel = self.get_threat_intelligence(event.source_ip.unwrap()).await;
        }

        // Log the event
        if self.config.structured_logging {
            self.log_structured(&event).await;
        } else {
            self.log_text(&event).await;
        }

        // Buffer for SIEM forwarding
        if self.config.enable_siem_forwarding {
            let mut buffer = self.event_buffer.write().await;
            buffer.push(event);
        }
    }

    /// Create a security event builder
    pub fn event_builder(&self) -> SecurityEventBuilder {
        SecurityEventBuilder::new()
    }

    /// Log authentication success
    pub async fn log_auth_success(&self, user_id: &str, ip: IpAddr, correlation_id: &str) {
        let event = self
            .event_builder()
            .event_type(SecurityEventType::AuthenticationSuccess)
            .severity(SecuritySeverity::Info)
            .source_ip(ip)
            .user_id(user_id)
            .correlation_id(correlation_id)
            .description("User authentication successful".to_string())
            .build();

        self.log_event(event).await;
    }

    /// Log authentication failure
    pub async fn log_auth_failure(
        &self,
        attempted_user: &str,
        ip: IpAddr,
        correlation_id: &str,
        reason: &str,
    ) {
        let event = self
            .event_builder()
            .event_type(SecurityEventType::AuthenticationFailure)
            .severity(SecuritySeverity::Medium)
            .source_ip(ip)
            .user_id(attempted_user)
            .correlation_id(correlation_id)
            .description(format!("Authentication failed: {}", reason))
            .build();

        self.log_event(event).await;
    }

    /// Log rate limit exceeded
    pub async fn log_rate_limit_exceeded(&self, ip: IpAddr, endpoint: &str, correlation_id: &str) {
        let mut metadata = SecurityMetadata::default();
        metadata.endpoint = Some(endpoint.to_string());

        let event = self
            .event_builder()
            .event_type(SecurityEventType::RateLimitExceeded)
            .severity(SecuritySeverity::Medium)
            .source_ip(ip)
            .correlation_id(correlation_id)
            .description(format!("Rate limit exceeded for endpoint: {}", endpoint))
            .metadata(metadata)
            .build();

        self.log_event(event).await;
    }

    /// Log CSRF token violation
    pub async fn log_csrf_violation(&self, ip: IpAddr, endpoint: &str, correlation_id: &str) {
        let mut metadata = SecurityMetadata::default();
        metadata.endpoint = Some(endpoint.to_string());

        let event = self
            .event_builder()
            .event_type(SecurityEventType::CsrfTokenInvalid)
            .severity(SecuritySeverity::High)
            .source_ip(ip)
            .correlation_id(correlation_id)
            .description(format!("CSRF token violation on endpoint: {}", endpoint))
            .metadata(metadata)
            .build();

        self.log_event(event).await;
    }

    /// Log suspicious activity
    pub async fn log_suspicious_activity(
        &self,
        ip: IpAddr,
        description: &str,
        correlation_id: &str,
    ) {
        let event = self
            .event_builder()
            .event_type(SecurityEventType::SuspiciousActivity)
            .severity(SecuritySeverity::High)
            .source_ip(ip)
            .correlation_id(correlation_id)
            .description(description.to_string())
            .build();

        self.log_event(event).await;
    }

    /// Get threat intelligence for IP
    async fn get_threat_intelligence(&self, ip: IpAddr) -> Option<ThreatIntelligence> {
        // Check cache first
        {
            let cache = self.threat_intel_cache.read().await;
            if let Some(intel) = cache.get(&ip) {
                return Some(intel.clone());
            }
        }

        // Mock threat intelligence (in real implementation, query external services)
        let intel = ThreatIntelligence {
            ip_reputation: Some(IpReputation {
                score: 0.8,
                categories: vec!["clean".to_string()],
                last_seen: Some(Utc::now()),
                source: "mock_provider".to_string(),
            }),
            known_attack_patterns: vec![],
            risk_score: 0.1,
            country_code: Some("US".to_string()),
            asn: Some(12345),
            is_tor_exit: false,
            is_vpn: false,
            is_proxy: false,
        };

        // Cache the result
        {
            let mut cache = self.threat_intel_cache.write().await;
            cache.insert(ip, intel.clone());
        }

        Some(intel)
    }

    /// Log structured event
    async fn log_structured(&self, event: &SecurityEvent) {
        let json = serde_json::to_string(event)
            .unwrap_or_else(|_| "Failed to serialize event".to_string());

        match event.severity {
            SecuritySeverity::Critical => error!(target: "security", "{}", json),
            SecuritySeverity::High => error!(target: "security", "{}", json),
            SecuritySeverity::Medium => warn!(target: "security", "{}", json),
            SecuritySeverity::Low => info!(target: "security", "{}", json),
            SecuritySeverity::Info => debug!(target: "security", "{}", json),
            SecuritySeverity::Warning => warn!(target: "security", "{}", json),
        }
    }

    /// Log text event
    async fn log_text(&self, event: &SecurityEvent) {
        let message = format!(
            "[{}] {} - {} (IP: {:?}, User: {:?}, Correlation: {})",
            event.severity,
            event.event_type,
            event.description,
            event.source_ip,
            event.user_id_hash,
            event.correlation_id
        );

        match event.severity {
            SecuritySeverity::Critical => error!(target: "security", "{}", message),
            SecuritySeverity::High => error!(target: "security", "{}", message),
            SecuritySeverity::Medium => warn!(target: "security", "{}", message),
            SecuritySeverity::Low => info!(target: "security", "{}", message),
            SecuritySeverity::Info => debug!(target: "security", "{}", message),
            SecuritySeverity::Warning => warn!(target: "security", "{}", message),
        }
    }

    /// Get buffered events for SIEM forwarding
    pub async fn get_buffered_events(&self) -> Vec<SecurityEvent> {
        let mut buffer = self.event_buffer.write().await;
        let events = buffer.clone();
        buffer.clear();
        events
    }

    /// Get security event statistics
    pub async fn get_event_stats(&self) -> SecurityEventStats {
        let buffer = self.event_buffer.read().await;
        let total_events = buffer.len();

        let mut severity_counts = HashMap::new();
        let mut event_type_counts = HashMap::new();

        for event in buffer.iter() {
            *severity_counts.entry(event.severity.clone()).or_insert(0) += 1;
            *event_type_counts
                .entry(event.event_type.clone())
                .or_insert(0) += 1;
        }

        SecurityEventStats {
            total_events,
            severity_counts,
            event_type_counts,
        }
    }
}

/// Security event statistics
#[derive(Debug, Serialize)]
pub struct SecurityEventStats {
    pub total_events: usize,
    pub severity_counts: HashMap<SecuritySeverity, usize>,
    pub event_type_counts: HashMap<SecurityEventType, usize>,
}

/// Security event builder for fluent API
pub struct SecurityEventBuilder {
    event: SecurityEvent,
}

impl SecurityEventBuilder {
    pub fn new() -> Self {
        Self {
            event: SecurityEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                event_type: SecurityEventType::SuspiciousActivity,
                severity: SecuritySeverity::Info,
                source_ip: None,
                user_id_hash: None,
                correlation_id: Uuid::new_v4().to_string(),
                session_id_hash: None,
                description: String::new(),
                metadata: SecurityMetadata::default(),
                threat_intel: None,
            },
        }
    }

    pub fn event_type(mut self, event_type: SecurityEventType) -> Self {
        self.event.event_type = event_type;
        self
    }

    pub fn severity(mut self, severity: SecuritySeverity) -> Self {
        self.event.severity = severity;
        self
    }

    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.event.source_ip = Some(ip);
        self
    }

    pub fn user_id(mut self, user_id: &str) -> Self {
        // Create privacy-safe hash
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        self.event.user_id_hash = Some(hash);
        self
    }

    pub fn correlation_id(mut self, correlation_id: &str) -> Self {
        self.event.correlation_id = correlation_id.to_string();
        self
    }

    pub fn session_id(mut self, session_id: &str) -> Self {
        // Create privacy-safe hash
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        self.event.session_id_hash = Some(hash);
        self
    }

    pub fn description(mut self, description: String) -> Self {
        self.event.description = description;
        self
    }

    pub fn metadata(mut self, metadata: SecurityMetadata) -> Self {
        self.event.metadata = metadata;
        self
    }

    pub fn build(self) -> SecurityEvent {
        self.event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_pii_detection() {
        let detector = PiiDetector::new();

        let text = "Contact john.doe@example.com or call 555-123-4567";
        let sanitized = detector.sanitize_text(text);

        assert!(sanitized.contains("[EMAIL_REDACTED]"));
        assert!(sanitized.contains("[PHONE_REDACTED]"));
    }

    #[tokio::test]
    async fn test_security_event_logging() {
        let config = SecurityLoggerConfig::default();
        let logger = SecurityLogger::new(config);

        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        logger.log_auth_success("user123", ip, "corr-123").await;

        let stats = logger.get_event_stats().await;
        assert_eq!(stats.total_events, 1);
    }

    #[test]
    fn test_event_builder() {
        let event = SecurityEventBuilder::new()
            .event_type(SecurityEventType::AuthenticationSuccess)
            .severity(SecuritySeverity::Info)
            .user_id("test_user")
            .description("Test event".to_string())
            .build();

        assert_eq!(event.event_type, SecurityEventType::AuthenticationSuccess);
        assert_eq!(event.severity, SecuritySeverity::Info);
        assert!(event.user_id_hash.is_some());
    }

    #[test]
    fn test_severity_ordering() {
        assert!(SecuritySeverity::Critical > SecuritySeverity::High);
        assert!(SecuritySeverity::High > SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium > SecuritySeverity::Low);
        assert!(SecuritySeverity::Low > SecuritySeverity::Info);
    }
}
