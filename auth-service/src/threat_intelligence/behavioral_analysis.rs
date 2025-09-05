//! AI-Based Behavioral Analysis for Threat Detection
//!
//! Advanced threat detection using machine learning algorithms to identify
//! anomalous behavior patterns and potential security threats.

use crate::monitoring::security_alerts::{SecurityEvent, SecurityEventType, AlertSeverity};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// User behavior profile for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorProfile {
    pub user_id: String,
    pub login_patterns: LoginPatterns,
    pub device_patterns: DevicePatterns,
    pub location_patterns: LocationPatterns,
    pub activity_patterns: ActivityPatterns,
    pub risk_score: f64,
    pub last_updated: u64,
}

/// Login behavior patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginPatterns {
    pub typical_hours: Vec<u8>, // Hours of day (0-23)
    pub typical_days: Vec<u8>,  // Days of week (0-6)
    pub avg_session_duration: f64,
    pub login_frequency: f64,
    pub failed_attempts_baseline: f64,
}

/// Device fingerprint patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePatterns {
    pub known_user_agents: Vec<String>,
    pub screen_resolutions: Vec<String>,
    pub timezone_patterns: Vec<String>,
    pub browser_features: HashMap<String, bool>,
}

/// Location-based patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationPatterns {
    pub typical_countries: Vec<String>,
    pub typical_cities: Vec<String>,
    pub typical_ip_ranges: Vec<String>,
    pub travel_velocity_threshold: f64, // km/h
}

/// Activity patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityPatterns {
    pub api_call_frequency: HashMap<String, f64>,
    pub data_access_patterns: Vec<String>,
    pub typical_endpoints: Vec<String>,
    pub request_rate_baseline: f64,
}

/// Real-time behavior analysis data
#[derive(Debug, Clone)]
pub struct BehaviorSnapshot {
    pub user_id: String,
    pub timestamp: u64,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub endpoint: Option<String>,
    pub session_duration: Option<f64>,
    pub request_count: u32,
    pub failed_attempts: u32,
    pub geolocation: Option<GeoLocation>,
}

/// Geographic location data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// Anomaly detection result
#[derive(Debug, Clone)]
pub struct AnomalyDetection {
    pub user_id: String,
    pub anomaly_type: AnomalyType,
    pub risk_score: f64,
    pub confidence: f64,
    pub details: String,
    pub timestamp: u64,
}

/// Types of behavioral anomalies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnomalyType {
    UnusualLoginTime,
    UnusualLocation,
    UnusualDevice,
    UnusualActivityPattern,
    SuspiciousVelocity,
    AbnormalRequestRate,
    UnknownEndpointAccess,
    SessionAnomalies,
}

/// Machine learning model for behavioral analysis
pub struct BehavioralAnalysisEngine {
    user_profiles: Arc<RwLock<HashMap<String, UserBehaviorProfile>>>,
    recent_activity: Arc<RwLock<HashMap<String, VecDeque<BehaviorSnapshot>>>>,
    anomaly_thresholds: AnomalyThresholds,
    learning_enabled: bool,
}

/// Configurable thresholds for anomaly detection
#[derive(Debug, Clone)]
pub struct AnomalyThresholds {
    pub login_time_deviation: f64,
    pub location_distance_km: f64,
    pub device_similarity_threshold: f64,
    pub velocity_threshold_kmh: f64,
    pub request_rate_multiplier: f64,
    pub session_duration_deviation: f64,
    pub minimum_risk_score: f64,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        Self {
            login_time_deviation: 2.0,      // 2 hours deviation
            location_distance_km: 500.0,    // 500km from typical location
            device_similarity_threshold: 0.7, // 70% similarity required
            velocity_threshold_kmh: 800.0,  // 800 km/h (airplane speed)
            request_rate_multiplier: 3.0,   // 3x normal request rate
            session_duration_deviation: 2.0, // 2x normal session time
            minimum_risk_score: 0.3,        // Minimum risk score to alert
        }
    }
}

impl BehavioralAnalysisEngine {
    /// Create new behavioral analysis engine
    pub fn new() -> Self {
        Self {
            user_profiles: Arc::new(RwLock::new(HashMap::new())),
            recent_activity: Arc::new(RwLock::new(HashMap::new())),
            anomaly_thresholds: AnomalyThresholds::default(),
            learning_enabled: true,
        }
    }

    /// Configure anomaly detection thresholds
    pub fn with_thresholds(mut self, thresholds: AnomalyThresholds) -> Self {
        self.anomaly_thresholds = thresholds;
        self
    }

    /// Enable or disable learning mode
    pub fn set_learning_enabled(&mut self, enabled: bool) {
        self.learning_enabled = enabled;
        info!("Behavioral learning mode: {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Analyze behavior snapshot for anomalies
    pub async fn analyze_behavior(&self, snapshot: BehaviorSnapshot) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();
        let user_id = snapshot.user_id.clone();

        // Get or create user profile
        let profile = {
            let profiles = self.user_profiles.read().await;
            profiles.get(&user_id).cloned()
        };

        if let Some(profile) = profile {
            // Perform various anomaly checks
            anomalies.extend(self.check_temporal_anomalies(&snapshot, &profile).await);
            anomalies.extend(self.check_location_anomalies(&snapshot, &profile).await);
            anomalies.extend(self.check_device_anomalies(&snapshot, &profile).await);
            anomalies.extend(self.check_activity_anomalies(&snapshot, &profile).await);
            anomalies.extend(self.check_velocity_anomalies(&snapshot, &profile).await);
        } else {
            // New user - create initial profile
            debug!("Creating initial profile for user: {}", user_id);
            if self.learning_enabled {
                self.create_initial_profile(&snapshot).await;
            }
        }

        // Update recent activity
        self.update_recent_activity(snapshot.clone()).await;

        // Update profile with new data if learning is enabled
        if self.learning_enabled {
            self.update_user_profile(&snapshot).await;
        }

        anomalies
    }

    /// Check for temporal anomalies (unusual login times)
    async fn check_temporal_anomalies(
        &self,
        snapshot: &BehaviorSnapshot,
        profile: &UserBehaviorProfile,
    ) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();
        let now = chrono::DateTime::from_timestamp(snapshot.timestamp as i64, 0)
            .unwrap_or_default();
        let hour = now.hour() as u8;
        let weekday = now.weekday().number_from_monday() as u8 - 1;

        // Check if login time is unusual
        let is_unusual_hour = !profile.login_patterns.typical_hours.contains(&hour);
        let is_unusual_day = !profile.login_patterns.typical_days.contains(&weekday);

        if is_unusual_hour || is_unusual_day {
            let risk_score = if is_unusual_hour && is_unusual_day { 0.8 } else { 0.4 };
            
            anomalies.push(AnomalyDetection {
                user_id: snapshot.user_id.clone(),
                anomaly_type: AnomalyType::UnusualLoginTime,
                risk_score,
                confidence: 0.7,
                details: format!(
                    "Login at unusual time: {}:00 on day {} (typical hours: {:?}, days: {:?})",
                    hour, weekday, profile.login_patterns.typical_hours, profile.login_patterns.typical_days
                ),
                timestamp: snapshot.timestamp,
            });
        }

        anomalies
    }

    /// Check for location-based anomalies
    async fn check_location_anomalies(
        &self,
        snapshot: &BehaviorSnapshot,
        profile: &UserBehaviorProfile,
    ) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();

        if let Some(geo) = &snapshot.geolocation {
            let is_unusual_country = !profile.location_patterns.typical_countries.contains(&geo.country);
            let is_unusual_city = !profile.location_patterns.typical_cities.contains(&geo.city);

            if is_unusual_country {
                anomalies.push(AnomalyDetection {
                    user_id: snapshot.user_id.clone(),
                    anomaly_type: AnomalyType::UnusualLocation,
                    risk_score: 0.6,
                    confidence: 0.8,
                    details: format!(
                        "Login from unusual country: {} (typical: {:?})",
                        geo.country, profile.location_patterns.typical_countries
                    ),
                    timestamp: snapshot.timestamp,
                });
            } else if is_unusual_city {
                anomalies.push(AnomalyDetection {
                    user_id: snapshot.user_id.clone(),
                    anomaly_type: AnomalyType::UnusualLocation,
                    risk_score: 0.3,
                    confidence: 0.6,
                    details: format!(
                        "Login from unusual city: {} (typical: {:?})",
                        geo.city, profile.location_patterns.typical_cities
                    ),
                    timestamp: snapshot.timestamp,
                });
            }
        }

        // Check IP range patterns
        if let Some(ip) = snapshot.ip_address {
            let ip_string = ip.to_string();
            let ip_prefix = match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    format!("{}.{}.{}", octets[0], octets[1], octets[2])
                },
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();
                    format!("{:x}:{:x}:{:x}", segments[0], segments[1], segments[2])
                },
            };

            let is_known_range = profile.location_patterns.typical_ip_ranges
                .iter()
                .any(|range| ip_string.starts_with(range));

            if !is_known_range {
                anomalies.push(AnomalyDetection {
                    user_id: snapshot.user_id.clone(),
                    anomaly_type: AnomalyType::UnusualLocation,
                    risk_score: 0.4,
                    confidence: 0.5,
                    details: format!(
                        "Login from unknown IP range: {} (known ranges: {:?})",
                        ip_prefix, profile.location_patterns.typical_ip_ranges
                    ),
                    timestamp: snapshot.timestamp,
                });
            }
        }

        anomalies
    }

    /// Check for device-based anomalies
    async fn check_device_anomalies(
        &self,
        snapshot: &BehaviorSnapshot,
        profile: &UserBehaviorProfile,
    ) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();

        if let Some(user_agent) = &snapshot.user_agent {
            let similarity = self.calculate_user_agent_similarity(
                user_agent,
                &profile.device_patterns.known_user_agents,
            );

            if similarity < self.anomaly_thresholds.device_similarity_threshold {
                anomalies.push(AnomalyDetection {
                    user_id: snapshot.user_id.clone(),
                    anomaly_type: AnomalyType::UnusualDevice,
                    risk_score: 0.5,
                    confidence: 0.7,
                    details: format!(
                        "Login from unknown device (similarity: {:.2}, threshold: {:.2})",
                        similarity, self.anomaly_thresholds.device_similarity_threshold
                    ),
                    timestamp: snapshot.timestamp,
                });
            }
        }

        anomalies
    }

    /// Check for activity pattern anomalies
    async fn check_activity_anomalies(
        &self,
        snapshot: &BehaviorSnapshot,
        profile: &UserBehaviorProfile,
    ) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();

        // Check request rate
        if snapshot.request_count as f64 > profile.activity_patterns.request_rate_baseline * self.anomaly_thresholds.request_rate_multiplier {
            anomalies.push(AnomalyDetection {
                user_id: snapshot.user_id.clone(),
                anomaly_type: AnomalyType::AbnormalRequestRate,
                risk_score: 0.6,
                confidence: 0.8,
                details: format!(
                    "Abnormal request rate: {} (baseline: {:.1}, threshold: {:.1})",
                    snapshot.request_count,
                    profile.activity_patterns.request_rate_baseline,
                    profile.activity_patterns.request_rate_baseline * self.anomaly_thresholds.request_rate_multiplier
                ),
                timestamp: snapshot.timestamp,
            });
        }

        // Check endpoint access patterns
        if let Some(endpoint) = &snapshot.endpoint {
            if !profile.activity_patterns.typical_endpoints.contains(endpoint) {
                anomalies.push(AnomalyDetection {
                    user_id: snapshot.user_id.clone(),
                    anomaly_type: AnomalyType::UnknownEndpointAccess,
                    risk_score: 0.3,
                    confidence: 0.6,
                    details: format!(
                        "Access to unknown endpoint: {} (typical: {:?})",
                        endpoint, profile.activity_patterns.typical_endpoints
                    ),
                    timestamp: snapshot.timestamp,
                });
            }
        }

        anomalies
    }

    /// Check for impossible travel velocity
    async fn check_velocity_anomalies(
        &self,
        snapshot: &BehaviorSnapshot,
        _profile: &UserBehaviorProfile,
    ) -> Vec<AnomalyDetection> {
        let mut anomalies = Vec::new();

        if let Some(current_geo) = &snapshot.geolocation {
            // Get recent activity for this user
            let recent = self.recent_activity.read().await;
            if let Some(activity_queue) = recent.get(&snapshot.user_id) {
                if let Some(last_snapshot) = activity_queue.back() {
                    if let Some(last_geo) = &last_snapshot.geolocation {
                        let time_diff = snapshot.timestamp.saturating_sub(last_snapshot.timestamp) as f64 / 3600.0; // hours
                        let distance = self.calculate_distance(last_geo, current_geo);
                        
                        if time_diff > 0.0 {
                            let velocity = distance / time_diff;
                            
                            if velocity > self.anomaly_thresholds.velocity_threshold_kmh {
                                anomalies.push(AnomalyDetection {
                                    user_id: snapshot.user_id.clone(),
                                    anomaly_type: AnomalyType::SuspiciousVelocity,
                                    risk_score: 0.9,
                                    confidence: 0.9,
                                    details: format!(
                                        "Impossible travel velocity: {:.1} km/h ({:.1} km in {:.2} hours)",
                                        velocity, distance, time_diff
                                    ),
                                    timestamp: snapshot.timestamp,
                                });
                            }
                        }
                    }
                }
            }
        }

        anomalies
    }

    /// Create initial user profile from first behavior snapshot
    async fn create_initial_profile(&self, snapshot: &BehaviorSnapshot) {
        let now = chrono::DateTime::from_timestamp(snapshot.timestamp as i64, 0)
            .unwrap_or_default();
        
        let mut device_patterns = DevicePatterns {
            known_user_agents: Vec::new(),
            screen_resolutions: Vec::new(),
            timezone_patterns: Vec::new(),
            browser_features: HashMap::new(),
        };

        if let Some(user_agent) = &snapshot.user_agent {
            device_patterns.known_user_agents.push(user_agent.clone());
        }

        let mut location_patterns = LocationPatterns {
            typical_countries: Vec::new(),
            typical_cities: Vec::new(),
            typical_ip_ranges: Vec::new(),
            travel_velocity_threshold: self.anomaly_thresholds.velocity_threshold_kmh,
        };

        if let Some(geo) = &snapshot.geolocation {
            location_patterns.typical_countries.push(geo.country.clone());
            location_patterns.typical_cities.push(geo.city.clone());
        }

        if let Some(ip) = snapshot.ip_address {
            let ip_prefix = match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    format!("{}.{}.{}", octets[0], octets[1], octets[2])
                },
                IpAddr::V6(ipv6) => {
                    let segments = ipv6.segments();
                    format!("{:x}:{:x}:{:x}", segments[0], segments[1], segments[2])
                },
            };
            location_patterns.typical_ip_ranges.push(ip_prefix);
        }

        let mut activity_patterns = ActivityPatterns {
            api_call_frequency: HashMap::new(),
            data_access_patterns: Vec::new(),
            typical_endpoints: Vec::new(),
            request_rate_baseline: snapshot.request_count as f64,
        };

        if let Some(endpoint) = &snapshot.endpoint {
            activity_patterns.typical_endpoints.push(endpoint.clone());
        }

        let profile = UserBehaviorProfile {
            user_id: snapshot.user_id.clone(),
            login_patterns: LoginPatterns {
                typical_hours: vec![now.hour() as u8],
                typical_days: vec![now.weekday().number_from_monday() as u8 - 1],
                avg_session_duration: snapshot.session_duration.unwrap_or(3600.0),
                login_frequency: 1.0,
                failed_attempts_baseline: snapshot.failed_attempts as f64,
            },
            device_patterns,
            location_patterns,
            activity_patterns,
            risk_score: 0.0,
            last_updated: snapshot.timestamp,
        };

        let mut profiles = self.user_profiles.write().await;
        profiles.insert(snapshot.user_id.clone(), profile);
        
        info!("Created initial behavior profile for user: {}", snapshot.user_id);
    }

    /// Update user profile with new behavior data
    async fn update_user_profile(&self, snapshot: &BehaviorSnapshot) {
        let mut profiles = self.user_profiles.write().await;
        if let Some(profile) = profiles.get_mut(&snapshot.user_id) {
            let now = chrono::DateTime::from_timestamp(snapshot.timestamp as i64, 0)
                .unwrap_or_default();
            
            // Update temporal patterns
            let hour = now.hour() as u8;
            let weekday = now.weekday().number_from_monday() as u8 - 1;
            
            if !profile.login_patterns.typical_hours.contains(&hour) {
                profile.login_patterns.typical_hours.push(hour);
            }
            if !profile.login_patterns.typical_days.contains(&weekday) {
                profile.login_patterns.typical_days.push(weekday);
            }

            // Update device patterns
            if let Some(user_agent) = &snapshot.user_agent {
                if !profile.device_patterns.known_user_agents.contains(user_agent) {
                    profile.device_patterns.known_user_agents.push(user_agent.clone());
                }
            }

            // Update location patterns
            if let Some(geo) = &snapshot.geolocation {
                if !profile.location_patterns.typical_countries.contains(&geo.country) {
                    profile.location_patterns.typical_countries.push(geo.country.clone());
                }
                if !profile.location_patterns.typical_cities.contains(&geo.city) {
                    profile.location_patterns.typical_cities.push(geo.city.clone());
                }
            }

            // Update activity patterns with moving average
            profile.activity_patterns.request_rate_baseline = 
                (profile.activity_patterns.request_rate_baseline * 0.9) + (snapshot.request_count as f64 * 0.1);
            
            if let Some(endpoint) = &snapshot.endpoint {
                if !profile.activity_patterns.typical_endpoints.contains(endpoint) {
                    profile.activity_patterns.typical_endpoints.push(endpoint.clone());
                }
            }

            profile.last_updated = snapshot.timestamp;
            
            debug!("Updated behavior profile for user: {}", snapshot.user_id);
        }
    }

    /// Update recent activity buffer for velocity calculations
    async fn update_recent_activity(&self, snapshot: BehaviorSnapshot) {
        let mut recent = self.recent_activity.write().await;
        let activity_queue = recent.entry(snapshot.user_id.clone()).or_insert_with(VecDeque::new);
        
        activity_queue.push_back(snapshot);
        
        // Keep only last 10 activities for velocity calculations
        while activity_queue.len() > 10 {
            activity_queue.pop_front();
        }
    }

    /// Calculate similarity between user agents
    fn calculate_user_agent_similarity(&self, current: &str, known: &[String]) -> f64 {
        if known.is_empty() {
            return 0.0;
        }

        let max_similarity = known.iter()
            .map(|ua| self.string_similarity(current, ua))
            .fold(0.0f64, |a, b| a.max(b));

        max_similarity
    }

    /// Simple string similarity calculation (Jaccard similarity)
    fn string_similarity(&self, s1: &str, s2: &str) -> f64 {
        let words1: std::collections::HashSet<&str> = s1.split_whitespace().collect();
        let words2: std::collections::HashSet<&str> = s2.split_whitespace().collect();
        
        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union == 0 {
            return 1.0; // Both strings are empty
        }
        
        intersection as f64 / union as f64
    }

    /// Calculate distance between two geographic points (Haversine formula)
    fn calculate_distance(&self, point1: &GeoLocation, point2: &GeoLocation) -> f64 {
        let earth_radius_km = 6371.0;
        
        let lat1_rad = point1.latitude.to_radians();
        let lat2_rad = point2.latitude.to_radians();
        let delta_lat = (point2.latitude - point1.latitude).to_radians();
        let delta_lon = (point2.longitude - point1.longitude).to_radians();
        
        let a = (delta_lat / 2.0).sin().powi(2) +
            lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        
        let c = 2.0 * a.sqrt().asin();
        
        earth_radius_km * c
    }

    /// Generate security event from anomaly detection
    pub fn create_security_event(&self, anomaly: &AnomalyDetection) -> SecurityEvent {
        let event_type = match anomaly.anomaly_type {
            AnomalyType::UnusualLoginTime => SecurityEventType::SuspiciousActivity,
            AnomalyType::UnusualLocation => SecurityEventType::GeolocationAnomaly,
            AnomalyType::UnusualDevice => SecurityEventType::DeviceAnomaly,
            AnomalyType::SuspiciousVelocity => SecurityEventType::ImpossibleTravel,
            AnomalyType::AbnormalRequestRate => SecurityEventType::AbnormalBehavior,
            _ => SecurityEventType::SuspiciousActivity,
        };

        let severity = if anomaly.risk_score >= 0.8 {
            AlertSeverity::Critical
        } else if anomaly.risk_score >= 0.6 {
            AlertSeverity::Warning
        } else {
            AlertSeverity::Info
        };

        SecurityEvent {
            event_type,
            severity,
            timestamp: anomaly.timestamp,
            source_ip: None, // Could be extracted from snapshot
            user_id: Some(anomaly.user_id.clone()),
            session_id: None,
            user_agent: None,
            endpoint: None,
            message: format!("Behavioral anomaly detected: {}", anomaly.details),
            metadata: {
                let mut metadata = HashMap::new();
                metadata.insert("anomaly_type".to_string(), format!("{:?}", anomaly.anomaly_type));
                metadata.insert("risk_score".to_string(), anomaly.risk_score.to_string());
                metadata.insert("confidence".to_string(), anomaly.confidence.to_string());
                metadata
            },
            count: 1,
        }
    }

    /// Get user profile for inspection
    pub async fn get_user_profile(&self, user_id: &str) -> Option<UserBehaviorProfile> {
        let profiles = self.user_profiles.read().await;
        profiles.get(user_id).cloned()
    }

    /// Get analysis statistics
    pub async fn get_analytics(&self) -> BehavioralAnalytics {
        let profiles = self.user_profiles.read().await;
        let recent = self.recent_activity.read().await;

        BehavioralAnalytics {
            total_profiles: profiles.len(),
            active_users: recent.len(),
            average_risk_score: profiles.values().map(|p| p.risk_score).sum::<f64>() / profiles.len() as f64,
            learning_enabled: self.learning_enabled,
        }
    }
}

/// Analytics data for behavioral analysis system
#[derive(Debug, Clone, Serialize)]
pub struct BehavioralAnalytics {
    pub total_profiles: usize,
    pub active_users: usize,
    pub average_risk_score: f64,
    pub learning_enabled: bool,
}

/// Extended security event types for behavioral analysis
impl SecurityEventType {
    pub const SuspiciousActivity: Self = Self::AuthenticationFailure;
    pub const GeolocationAnomaly: Self = Self::SuspiciousActivity;
    pub const DeviceAnomaly: Self = Self::SuspiciousActivity;
    pub const ImpossibleTravel: Self = Self::SuspiciousActivity;
    pub const AbnormalBehavior: Self = Self::SuspiciousActivity;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_behavioral_analysis_engine() {
        let engine = BehavioralAnalysisEngine::new();
        
        let snapshot = BehaviorSnapshot {
            user_id: "test_user".to_string(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
            endpoint: Some("/api/v1/auth/login".to_string()),
            session_duration: Some(3600.0),
            request_count: 10,
            failed_attempts: 0,
            geolocation: Some(GeoLocation {
                country: "US".to_string(),
                city: "New York".to_string(),
                latitude: 40.7128,
                longitude: -74.0060,
            }),
        };

        let anomalies = engine.analyze_behavior(snapshot).await;
        
        // First login should create profile with no anomalies
        assert!(anomalies.is_empty());
        
        // Verify profile was created
        let profile = engine.get_user_profile("test_user").await;
        assert!(profile.is_some());
    }

    #[tokio::test]
    async fn test_velocity_anomaly_detection() {
        let engine = BehavioralAnalysisEngine::new();
        
        // First login in New York
        let snapshot1 = BehaviorSnapshot {
            user_id: "test_user".to_string(),
            timestamp: 1000,
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            user_agent: Some("Mozilla/5.0".to_string()),
            endpoint: Some("/login".to_string()),
            session_duration: Some(3600.0),
            request_count: 5,
            failed_attempts: 0,
            geolocation: Some(GeoLocation {
                country: "US".to_string(),
                city: "New York".to_string(),
                latitude: 40.7128,
                longitude: -74.0060,
            }),
        };

        let _anomalies1 = engine.analyze_behavior(snapshot1).await;

        // Second login in London 1 hour later (impossible travel)
        let snapshot2 = BehaviorSnapshot {
            user_id: "test_user".to_string(),
            timestamp: 4600, // 1 hour later
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            user_agent: Some("Mozilla/5.0".to_string()),
            endpoint: Some("/login".to_string()),
            session_duration: Some(3600.0),
            request_count: 5,
            failed_attempts: 0,
            geolocation: Some(GeoLocation {
                country: "UK".to_string(),
                city: "London".to_string(),
                latitude: 51.5074,
                longitude: -0.1278,
            }),
        };

        let anomalies2 = engine.analyze_behavior(snapshot2).await;
        
        // Should detect impossible travel velocity
        assert!(!anomalies2.is_empty());
        assert!(anomalies2.iter().any(|a| matches!(a.anomaly_type, AnomalyType::SuspiciousVelocity)));
    }

    #[test]
    fn test_string_similarity() {
        let engine = BehavioralAnalysisEngine::new();
        
        let s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        let s2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        
        let similarity = engine.string_similarity(s1, s2);
        assert!(similarity > 0.5);
    }

    #[test]
    fn test_distance_calculation() {
        let engine = BehavioralAnalysisEngine::new();
        
        let nyc = GeoLocation {
            country: "US".to_string(),
            city: "New York".to_string(),
            latitude: 40.7128,
            longitude: -74.0060,
        };
        
        let london = GeoLocation {
            country: "UK".to_string(),
            city: "London".to_string(),
            latitude: 51.5074,
            longitude: -0.1278,
        };
        
        let distance = engine.calculate_distance(&nyc, &london);
        
        // Distance between NYC and London is approximately 5585 km
        assert!(distance > 5000.0 && distance < 6000.0);
    }
}