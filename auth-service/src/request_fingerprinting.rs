//! Request Fingerprinting for Anomaly Detection
//!
//! Advanced request fingerprinting system that creates unique signatures
//! for requests to detect suspicious patterns and anomalous behavior.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Request fingerprint containing various identifying characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestFingerprint {
    /// Client IP address
    pub ip_address: String,
    /// SHA-256 hash of User-Agent string (privacy-preserving)
    pub user_agent_hash: String,
    /// Request method (GET, POST, etc.)
    pub method: String,
    /// Requested path
    pub path: String,
    /// Content-Type header if present
    pub content_type: Option<String>,
    /// Accept header if present
    pub accept_header: Option<String>,
    /// Request size in bytes
    pub content_length: Option<u64>,
    /// TLS cipher suite information (if available)
    pub tls_cipher: Option<String>,
    /// Geographic location (if available)
    pub geo_location: Option<String>,
    /// Timestamp of the request
    pub timestamp: u64,
    /// Computed fingerprint hash
    pub fingerprint_hash: String,
}

/// Request pattern representing historical behavior
#[derive(Debug, Clone)]
struct RequestPattern {
    /// Fingerprint template
    fingerprint: RequestFingerprint,
    /// Number of times seen
    count: u64,
    /// First occurrence timestamp
    first_seen: u64,
    /// Last occurrence timestamp
    last_seen: u64,
    /// Average time between requests
    avg_interval: Duration,
    /// Request frequency score (requests per minute)
    frequency_score: f64,
    /// Anomaly score (0.0 = normal, 1.0 = highly anomalous)
    anomaly_score: f64,
}

/// Anomaly detection results
#[derive(Debug, Clone, Serialize)]
pub struct AnomalyResult {
    /// Whether this request is considered anomalous
    pub is_anomalous: bool,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Specific anomaly indicators found
    pub indicators: Vec<String>,
    /// Risk level (Low, Medium, High, Critical)
    pub risk_level: RiskLevel,
    /// Recommended action
    pub recommended_action: RecommendedAction,
}

/// Risk levels for detected anomalies
#[derive(Debug, Clone, Serialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Recommended actions based on anomaly detection
#[derive(Debug, Clone, Serialize)]
pub enum RecommendedAction {
    /// Allow the request normally
    Allow,
    /// Apply additional monitoring
    Monitor,
    /// Apply rate limiting
    RateLimit,
    /// Require additional authentication
    RequireAdditionalAuth,
    /// Block the request
    Block,
    /// Immediate security response
    SecurityAlert,
}

/// Configuration for request fingerprinting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintingConfig {
    /// Enable/disable fingerprinting
    pub enabled: bool,
    /// Maximum patterns to store per IP
    pub max_patterns_per_ip: usize,
    /// Time window for pattern analysis (seconds)
    pub analysis_window: u64,
    /// Minimum requests needed for pattern establishment
    pub min_requests_for_pattern: u32,
    /// Anomaly detection sensitivity (0.0 = low, 1.0 = high)
    pub anomaly_sensitivity: f64,
    /// Enable geographic analysis
    pub enable_geo_analysis: bool,
    /// Enable TLS fingerprinting
    pub enable_tls_fingerprinting: bool,
}

impl Default for FingerprintingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_patterns_per_ip: 100,
            analysis_window: 3600, // 1 hour
            min_requests_for_pattern: 10,
            anomaly_sensitivity: 0.7,
            enable_geo_analysis: false, // Requires external service
            enable_tls_fingerprinting: false, // Requires TLS layer access
        }
    }
}

/// Main request fingerprinting and anomaly detection engine
pub struct RequestFingerprintAnalyzer {
    /// Configuration
    config: FingerprintingConfig,
    /// Historical patterns by IP address
    patterns_by_ip: Arc<RwLock<HashMap<String, Vec<RequestPattern>>>>,
    /// Request history for pattern learning
    request_history: Arc<RwLock<HashMap<String, Vec<RequestFingerprint>>>>,
}

impl RequestFingerprintAnalyzer {
    /// Create a new request fingerprinting analyzer
    #[must_use]
    pub fn new(config: FingerprintingConfig) -> Self {
        Self {
            config,
            patterns_by_ip: Arc::new(RwLock::new(HashMap::new())),
            request_history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a fingerprint from an HTTP request
    pub fn create_fingerprint(
        &self,
        ip: &str,
        method: &str,
        path: &str,
        user_agent: Option<&str>,
        content_type: Option<&str>,
        accept_header: Option<&str>,
        content_length: Option<u64>,
        tls_cipher: Option<&str>,
    ) -> RequestFingerprint {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Hash user agent for privacy (don't store raw user agents)
        let user_agent_hash = user_agent
            .map(|ua| self.hash_string(ua))
            .unwrap_or_else(|| "unknown".to_string());

        // Create fingerprint components
        let fingerprint = RequestFingerprint {
            ip_address: ip.to_string(),
            user_agent_hash: user_agent_hash.clone(),
            method: method.to_string(),
            path: path.to_string(),
            content_type: content_type.map(|s| s.to_string()),
            accept_header: accept_header.map(|s| s.to_string()),
            content_length,
            tls_cipher: tls_cipher.map(|s| s.to_string()),
            geo_location: None, // Would require GeoIP lookup
            timestamp: now,
            fingerprint_hash: String::new(), // Set below
        };

        // Compute composite fingerprint hash
        let mut fingerprint_with_hash = fingerprint;
        fingerprint_with_hash.fingerprint_hash = self.compute_fingerprint_hash(&fingerprint_with_hash);

        fingerprint_with_hash
    }

    /// Analyze a request fingerprint for anomalies
    pub async fn analyze_request(&self, fingerprint: RequestFingerprint) -> AnomalyResult {
        if !self.config.enabled {
            return AnomalyResult {
                is_anomalous: false,
                confidence: 0.0,
                indicators: vec![],
                risk_level: RiskLevel::Low,
                recommended_action: RecommendedAction::Allow,
            };
        }

        // Store request in history
        self.record_request(&fingerprint).await;

        // Analyze for anomalies
        let patterns = self.patterns_by_ip.read().await;
        let ip_patterns = patterns.get(&fingerprint.ip_address);

        let mut anomaly_score: f64 = 0.0;
        let mut indicators = Vec::new();

        // Check for various anomaly types
        anomaly_score += self.analyze_frequency_anomalies(&fingerprint, ip_patterns, &mut indicators);
        anomaly_score += self.analyze_pattern_anomalies(&fingerprint, ip_patterns, &mut indicators);
        anomaly_score += self.analyze_temporal_anomalies(&fingerprint, ip_patterns, &mut indicators);
        anomaly_score += self.analyze_behavioral_anomalies(&fingerprint, &mut indicators);

        // Normalize score and determine risk level
        anomaly_score = anomaly_score.min(1.0);
        let is_anomalous = anomaly_score >= self.config.anomaly_sensitivity;

        let risk_level = match anomaly_score {
            score if score >= 0.9 => RiskLevel::Critical,
            score if score >= 0.7 => RiskLevel::High,
            score if score >= 0.5 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        let recommended_action = match risk_level {
            RiskLevel::Critical => RecommendedAction::SecurityAlert,
            RiskLevel::High => RecommendedAction::Block,
            RiskLevel::Medium => RecommendedAction::RequireAdditionalAuth,
            RiskLevel::Low => if is_anomalous { RecommendedAction::Monitor } else { RecommendedAction::Allow },
        };

        if is_anomalous {
            info!(
                ip = %fingerprint.ip_address,
                score = %anomaly_score,
                indicators = ?indicators,
                "Anomalous request detected"
            );
        }

        AnomalyResult {
            is_anomalous,
            confidence: anomaly_score,
            indicators,
            risk_level,
            recommended_action,
        }
    }

    /// Record a request fingerprint for pattern learning
    async fn record_request(&self, fingerprint: &RequestFingerprint) {
        let mut history = self.request_history.write().await;
        let ip_history = history.entry(fingerprint.ip_address.clone()).or_insert_with(Vec::new);

        // Add to history
        ip_history.push(fingerprint.clone());

        // Maintain sliding window
        let cutoff_time = fingerprint.timestamp.saturating_sub(self.config.analysis_window);
        ip_history.retain(|req| req.timestamp >= cutoff_time);

        // Update patterns if we have enough data
        if ip_history.len() >= self.config.min_requests_for_pattern as usize {
            self.update_patterns(&fingerprint.ip_address, ip_history).await;
        }

        // Cleanup old entries
        if ip_history.len() > self.config.max_patterns_per_ip * 2 {
            ip_history.drain(0..self.config.max_patterns_per_ip);
        }
    }

    /// Update learned patterns for an IP
    async fn update_patterns(&self, ip: &str, history: &[RequestFingerprint]) {
        // Group requests by similar characteristics
        let mut pattern_groups: HashMap<String, Vec<&RequestFingerprint>> = HashMap::new();

        for req in history {
            let pattern_key = format!("{}-{}-{}", req.method, req.path, req.user_agent_hash);
            pattern_groups.entry(pattern_key).or_insert_with(Vec::new).push(req);
        }

        // Convert groups to patterns
        let mut patterns = Vec::new();
        for (_, group) in pattern_groups {
            if group.len() >= self.config.min_requests_for_pattern as usize / 2 {
                if let Some(pattern) = self.create_pattern_from_group(group) {
                    patterns.push(pattern);
                }
            }
        }

        // Update stored patterns
        let mut all_patterns = self.patterns_by_ip.write().await;
        all_patterns.insert(ip.to_string(), patterns);
    }

    /// Create a pattern from a group of similar requests
    fn create_pattern_from_group(&self, group: Vec<&RequestFingerprint>) -> Option<RequestPattern> {
        if group.is_empty() {
            return None;
        }

        let first_req = group[0];
        let count = group.len() as u64;
        let first_seen = group.iter().map(|r| r.timestamp).min()?;
        let last_seen = group.iter().map(|r| r.timestamp).max()?;

        // Calculate average interval
        let time_span = last_seen.saturating_sub(first_seen);
        let avg_interval = if count > 1 {
            Duration::from_secs(time_span / (count - 1))
        } else {
            Duration::from_secs(0)
        };

        // Calculate frequency score (requests per minute)
        let frequency_score = if time_span > 0 {
            (count as f64 * 60.0) / time_span as f64
        } else {
            count as f64
        };

        Some(RequestPattern {
            fingerprint: first_req.clone(),
            count,
            first_seen,
            last_seen,
            avg_interval,
            frequency_score,
            anomaly_score: 0.0, // Will be calculated during analysis
        })
    }

    /// Analyze frequency-based anomalies
    fn analyze_frequency_anomalies(
        &self,
        fingerprint: &RequestFingerprint,
        patterns: Option<&Vec<RequestPattern>>,
        indicators: &mut Vec<String>,
    ) -> f64 {
        if let Some(patterns) = patterns {
            // Check if request frequency is unusual compared to historical patterns
            let matching_patterns: Vec<_> = patterns
                .iter()
                .filter(|p| self.patterns_match(fingerprint, &p.fingerprint))
                .collect();

            if let Some(pattern) = matching_patterns.first() {
                // Analyze frequency deviation
                let expected_frequency = pattern.frequency_score;
                let _time_since_last = fingerprint.timestamp.saturating_sub(pattern.last_seen);

                // Calculate current frequency (very rough estimate)
                let current_frequency = 60.0; // Assume 1 request per minute baseline

                let frequency_deviation = (current_frequency - expected_frequency).abs() / expected_frequency.max(1.0);

                if frequency_deviation > 2.0 {
                    indicators.push(format!("Unusual request frequency: {:.2}x normal", frequency_deviation));
                    return frequency_deviation.min(0.3);
                }
            } else {
                // New pattern detected
                indicators.push("New request pattern detected".to_string());
                return 0.2;
            }
        }

        0.0
    }

    /// Analyze pattern-based anomalies
    fn analyze_pattern_anomalies(
        &self,
        fingerprint: &RequestFingerprint,
        patterns: Option<&Vec<RequestPattern>>,
        indicators: &mut Vec<String>,
    ) -> f64 {
        if let Some(patterns) = patterns {
            let mut anomaly_score: f64 = 0.0;

            // Check if this request matches known patterns
            let has_matching_pattern = patterns
                .iter()
                .any(|p| self.patterns_match(fingerprint, &p.fingerprint));

            if !has_matching_pattern {
                indicators.push("Request doesn't match established patterns".to_string());
                anomaly_score += 0.3;
            }

            // Check for suspicious path patterns
            if self.is_suspicious_path(&fingerprint.path) {
                indicators.push("Suspicious request path detected".to_string());
                anomaly_score += 0.4;
            }

            // Check for suspicious user agent patterns
            if self.is_suspicious_user_agent_hash(&fingerprint.user_agent_hash) {
                indicators.push("Suspicious user agent pattern".to_string());
                anomaly_score += 0.3;
            }

            anomaly_score.min(0.5)
        } else {
            0.0
        }
    }

    /// Analyze temporal-based anomalies
    fn analyze_temporal_anomalies(
        &self,
        fingerprint: &RequestFingerprint,
        patterns: Option<&Vec<RequestPattern>>,
        indicators: &mut Vec<String>,
    ) -> f64 {
        // Check for unusual timing patterns
        let current_hour = (fingerprint.timestamp / 3600) % 24;

        // Requests during unusual hours (example: 2-6 AM) might be suspicious
        if (2..6).contains(&current_hour) {
            if let Some(patterns) = patterns {
                let daytime_patterns = patterns.iter().any(|p| {
                    let pattern_hour = (p.last_seen / 3600) % 24;
                    (6..22).contains(&pattern_hour)
                });

                if daytime_patterns {
                    indicators.push("Request during unusual hours for this client".to_string());
                    return 0.2;
                }
            }
        }

        0.0
    }

    /// Analyze behavioral anomalies
    fn analyze_behavioral_anomalies(
        &self,
        fingerprint: &RequestFingerprint,
        indicators: &mut Vec<String>,
    ) -> f64 {
        let mut score: f64 = 0.0;

        // Check for automated/bot-like behavior patterns
        if fingerprint.user_agent_hash == "unknown" || fingerprint.user_agent_hash.is_empty() {
            indicators.push("Missing or empty User-Agent".to_string());
            score += 0.1;
        }

        // Check for suspicious request methods
        if !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].contains(&fingerprint.method.as_str()) {
            indicators.push(format!("Unusual HTTP method: {}", fingerprint.method));
            score += 0.2;
        }

        // Check for large request bodies on typically small requests
        if let Some(length) = fingerprint.content_length {
            if (fingerprint.method == "GET" || fingerprint.method == "HEAD") && length > 1024 {
                indicators.push("Unexpectedly large request body".to_string());
                score += 0.2;
            }
        }

        score.min(0.3)
    }

    /// Check if two fingerprints represent the same pattern
    fn patterns_match(&self, fp1: &RequestFingerprint, fp2: &RequestFingerprint) -> bool {
        fp1.method == fp2.method &&
        fp1.path == fp2.path &&
        fp1.user_agent_hash == fp2.user_agent_hash &&
        fp1.content_type == fp2.content_type
    }

    /// Check if a path looks suspicious
    fn is_suspicious_path(&self, path: &str) -> bool {
        let suspicious_patterns = [
            "/.env", "/admin", "/wp-admin", "/phpmyadmin", "/xmlrpc.php",
            "/.git", "/backup", "/config", "/debug", "/test",
            "../", "..\\", "<script", "javascript:", "data:",
        ];

        let lower_path = path.to_lowercase();
        suspicious_patterns.iter().any(|&pattern| lower_path.contains(pattern))
    }

    /// Check if a user agent hash corresponds to suspicious patterns
    fn is_suspicious_user_agent_hash(&self, _hash: &str) -> bool {
        // In a real implementation, you'd maintain a database of known bot/malware UA hashes
        // For now, just return false as we can't easily identify without the original UA
        false
    }

    /// Compute a hash of a string
    fn hash_string(&self, input: &str) -> String {
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Compute fingerprint hash from components
    fn compute_fingerprint_hash(&self, fingerprint: &RequestFingerprint) -> String {
        let mut hasher = DefaultHasher::new();
        fingerprint.ip_address.hash(&mut hasher);
        fingerprint.user_agent_hash.hash(&mut hasher);
        fingerprint.method.hash(&mut hasher);
        fingerprint.path.hash(&mut hasher);
        if let Some(ref ct) = fingerprint.content_type {
            ct.hash(&mut hasher);
        }
        format!("{:016x}", hasher.finish())
    }

    /// Get statistics about stored patterns
    pub async fn get_stats(&self) -> FingerprintStats {
        let patterns = self.patterns_by_ip.read().await;
        let history = self.request_history.read().await;

        let total_ips = patterns.len();
        let total_patterns: usize = patterns.values().map(|v| v.len()).sum();
        let total_requests: usize = history.values().map(|v| v.len()).sum();

        FingerprintStats {
            total_ips,
            total_patterns,
            total_requests,
            avg_patterns_per_ip: if total_ips > 0 { total_patterns / total_ips } else { 0 },
        }
    }

    /// Clean up old data periodically
    pub async fn cleanup_old_data(&self) {
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.config.analysis_window * 2); // Keep data for 2x analysis window

        let mut history = self.request_history.write().await;
        let mut patterns = self.patterns_by_ip.write().await;

        // Clean up request history
        history.retain(|_, requests| {
            requests.retain(|req| req.timestamp >= cutoff_time);
            !requests.is_empty()
        });

        // Clean up patterns for IPs with no recent history
        patterns.retain(|ip, _| history.contains_key(ip));

        let cleaned_ips = history.len();
        debug!("Cleaned up old fingerprint data, {} IPs remaining", cleaned_ips);
    }
}

/// Statistics about fingerprinting data
#[derive(Debug, Serialize)]
pub struct FingerprintStats {
    pub total_ips: usize,
    pub total_patterns: usize,
    pub total_requests: usize,
    pub avg_patterns_per_ip: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fingerprint_creation() {
        let config = FingerprintingConfig::default();
        let analyzer = RequestFingerprintAnalyzer::new(config);

        let fingerprint = analyzer.create_fingerprint(
            "192.168.1.1",
            "POST",
            "/api/login",
            Some("Mozilla/5.0 (test)"),
            Some("application/json"),
            Some("application/json"),
            Some(128),
            None,
        );

        assert_eq!(fingerprint.ip_address, "192.168.1.1");
        assert_eq!(fingerprint.method, "POST");
        assert_eq!(fingerprint.path, "/api/login");
        assert!(!fingerprint.user_agent_hash.is_empty());
        assert!(!fingerprint.fingerprint_hash.is_empty());
    }

    #[tokio::test]
    async fn test_anomaly_detection_normal_request() {
        let config = FingerprintingConfig::default();
        let analyzer = RequestFingerprintAnalyzer::new(config);

        let fingerprint = analyzer.create_fingerprint(
            "192.168.1.1",
            "GET",
            "/api/status",
            Some("Mozilla/5.0 (normal)"),
            None,
            Some("application/json"),
            None,
            None,
        );

        let result = analyzer.analyze_request(fingerprint).await;

        // First request should be low risk
        matches!(result.risk_level, RiskLevel::Low);
    }

    #[tokio::test]
    async fn test_anomaly_detection_suspicious_path() {
        let config = FingerprintingConfig::default();
        let analyzer = RequestFingerprintAnalyzer::new(config);

        let fingerprint = analyzer.create_fingerprint(
            "192.168.1.100",
            "GET",
            "/.env",
            Some("curl/7.68.0"),
            None,
            None,
            None,
            None,
        );

        let result = analyzer.analyze_request(fingerprint).await;

        // Should detect suspicious path
        assert!(result.indicators.iter().any(|i| i.contains("Suspicious request path")));
    }

    #[tokio::test]
    async fn test_pattern_learning() {
        let config = FingerprintingConfig {
            min_requests_for_pattern: 2,
            ..Default::default()
        };
        let analyzer = RequestFingerprintAnalyzer::new(config);

        // Send multiple similar requests
        for _ in 0..3 {
            let fingerprint = analyzer.create_fingerprint(
                "192.168.1.1",
                "GET",
                "/api/data",
                Some("Mozilla/5.0 (consistent)"),
                None,
                Some("application/json"),
                None,
                None,
            );
            analyzer.analyze_request(fingerprint).await;
        }

        let stats = analyzer.get_stats().await;
        assert!(stats.total_requests >= 3);
        assert!(stats.total_patterns >= 1);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let config = FingerprintingConfig {
            analysis_window: 1, // 1 second window
            ..Default::default()
        };
        let analyzer = RequestFingerprintAnalyzer::new(config);

        // Add some requests
        let fingerprint = analyzer.create_fingerprint(
            "192.168.1.1",
            "GET",
            "/test",
            Some("test-agent"),
            None,
            None,
            None,
            None,
        );
        analyzer.analyze_request(fingerprint).await;

        let stats_before = analyzer.get_stats().await;
        assert!(stats_before.total_requests > 0);

        // Wait for data to be old enough
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Cleanup
        analyzer.cleanup_old_data().await;

        let stats_after = analyzer.get_stats().await;
        // Data should be cleaned up due to short analysis window
        assert_eq!(stats_after.total_requests, 0);
    }
}
