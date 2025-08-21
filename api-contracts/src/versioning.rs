//! API versioning system with semantic versioning and deprecation policies

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use chrono::{DateTime, Utc};
use crate::{ApiConfig, errors::VersioningError};

/// Semantic version for APIs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl ApiVersion {
    /// Create a new API version
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
    
    /// Parse version from string (e.g., "1.2.3")
    pub fn parse(version: &str) -> Result<Self, VersioningError> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(VersioningError::InvalidVersion(version.to_string()));
        }
        
        let major = parts[0].parse()
            .map_err(|_| VersioningError::InvalidVersion(version.to_string()))?;
        let minor = parts[1].parse()
            .map_err(|_| VersioningError::InvalidVersion(version.to_string()))?;
        let patch = parts[2].parse()
            .map_err(|_| VersioningError::InvalidVersion(version.to_string()))?;
            
        Ok(Self::new(major, minor, patch))
    }
    
    /// Check if this version is compatible with another version
    pub fn is_compatible_with(&self, other: &ApiVersion) -> bool {
        // Major version must match for compatibility
        self.major == other.major
    }
    
    /// Check if this version is deprecated
    pub fn is_deprecated(&self, deprecated_versions: &HashMap<ApiVersion, DateTime<Utc>>) -> bool {
        deprecated_versions.contains_key(self)
    }
    
    /// Get deprecation date if deprecated
    pub fn deprecation_date(&self, deprecated_versions: &HashMap<ApiVersion, DateTime<Utc>>) -> Option<DateTime<Utc>> {
        deprecated_versions.get(self).cloned()
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for ApiVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ApiVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

/// Versioned API endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedEndpoint {
    /// Endpoint path
    pub path: String,
    /// Supported versions
    pub supported_versions: Vec<ApiVersion>,
    /// Default version when no version specified
    pub default_version: ApiVersion,
    /// Version-specific handlers
    pub version_handlers: HashMap<ApiVersion, String>,
}

impl VersionedEndpoint {
    /// Create a new versioned endpoint
    pub fn new(path: String, default_version: ApiVersion) -> Self {
        Self {
            path,
            supported_versions: vec![default_version.clone()],
            default_version,
            version_handlers: HashMap::new(),
        }
    }
    
    /// Add support for a new version
    pub fn add_version(&mut self, version: ApiVersion, handler: String) {
        self.supported_versions.push(version.clone());
        self.version_handlers.insert(version, handler);
    }
    
    /// Check if version is supported
    pub fn supports_version(&self, version: &ApiVersion) -> bool {
        self.supported_versions.contains(version)
    }
    
    /// Get handler for version
    pub fn get_handler(&self, version: &ApiVersion) -> Option<&String> {
        self.version_handlers.get(version)
    }
    
    /// Get the best compatible version
    pub fn resolve_version(&self, requested: Option<&ApiVersion>) -> Result<ApiVersion, VersioningError> {
        match requested {
            Some(version) => {
                if self.supports_version(version) {
                    Ok(version.clone())
                } else {
                    // Try to find compatible version
                    let compatible = self.supported_versions.iter()
                        .filter(|v| v.is_compatible_with(version))
                        .max()
                        .cloned();
                    
                    compatible.ok_or_else(|| VersioningError::UnsupportedVersion(version.clone()))
                }
            },
            None => Ok(self.default_version.clone()),
        }
    }
}

/// API deprecation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationPolicy {
    /// Notice period in days before deprecation
    pub notice_period_days: u32,
    /// Sunset period in days after deprecation
    pub sunset_period_days: u32,
    /// Required migration documentation
    pub migration_guide_required: bool,
    /// Notification channels
    pub notification_channels: Vec<String>,
}

impl Default for DeprecationPolicy {
    fn default() -> Self {
        Self {
            notice_period_days: 90,  // 3 months notice
            sunset_period_days: 180, // 6 months to sunset
            migration_guide_required: true,
            notification_channels: vec![
                "email".to_string(),
                "documentation".to_string(),
                "api-headers".to_string(),
            ],
        }
    }
}

/// Version manager for handling API versioning
#[derive(Debug, Clone)]
pub struct VersionManager {
    /// Available versions
    pub supported_versions: Vec<ApiVersion>,
    /// Current version
    pub current_version: ApiVersion,
    /// Deprecated versions with sunset dates
    pub deprecated_versions: HashMap<ApiVersion, DateTime<Utc>>,
    /// Deprecation policy
    pub deprecation_policy: DeprecationPolicy,
    /// Versioned endpoints
    pub endpoints: HashMap<String, VersionedEndpoint>,
}

impl VersionManager {
    /// Create a new version manager
    pub fn new(current_version: ApiVersion, deprecation_policy: DeprecationPolicy) -> Self {
        Self {
            supported_versions: vec![current_version.clone()],
            current_version,
            deprecated_versions: HashMap::new(),
            deprecation_policy,
            endpoints: HashMap::new(),
        }
    }
    
    /// Add a new version
    pub fn add_version(&mut self, version: ApiVersion) {
        if !self.supported_versions.contains(&version) {
            self.supported_versions.push(version);
            self.supported_versions.sort();
        }
    }
    
    /// Deprecate a version
    pub fn deprecate_version(&mut self, version: ApiVersion) -> Result<(), VersioningError> {
        if !self.supported_versions.contains(&version) {
            return Err(VersioningError::VersionNotFound(version));
        }
        
        if version == self.current_version {
            return Err(VersioningError::CannotDeprecateCurrentVersion(version));
        }
        
        let deprecation_date = Utc::now();
        self.deprecated_versions.insert(version, deprecation_date);
        
        tracing::info!("Version {} deprecated at {}", version, deprecation_date);
        Ok(())
    }
    
    /// Remove a deprecated version (sunset)
    pub fn sunset_version(&mut self, version: &ApiVersion) -> Result<(), VersioningError> {
        if let Some(deprecation_date) = self.deprecated_versions.get(version) {
            let sunset_date = *deprecation_date + chrono::Duration::days(self.deprecation_policy.sunset_period_days as i64);
            
            if Utc::now() >= sunset_date {
                self.deprecated_versions.remove(version);
                self.supported_versions.retain(|v| v != version);
                self.endpoints.iter_mut().for_each(|(_, endpoint)| {
                    endpoint.supported_versions.retain(|v| v != version);
                    endpoint.version_handlers.remove(version);
                });
                
                tracing::info!("Version {} sunset", version);
                Ok(())
            } else {
                Err(VersioningError::TooEarlyForSunset(version.clone(), sunset_date))
            }
        } else {
            Err(VersioningError::VersionNotDeprecated(version.clone()))
        }
    }
    
    /// Register a versioned endpoint
    pub fn register_endpoint(&mut self, endpoint: VersionedEndpoint) {
        self.endpoints.insert(endpoint.path.clone(), endpoint);
    }
    
    /// Resolve version for a request
    pub fn resolve_version(&self, path: &str, requested_version: Option<&ApiVersion>) -> Result<ApiVersion, VersioningError> {
        if let Some(endpoint) = self.endpoints.get(path) {
            endpoint.resolve_version(requested_version)
        } else {
            // For non-versioned endpoints, use current version
            Ok(self.current_version.clone())
        }
    }
    
    /// Get deprecation info for version
    pub fn get_deprecation_info(&self, version: &ApiVersion) -> Option<DeprecationInfo> {
        self.deprecated_versions.get(version).map(|deprecation_date| {
            let sunset_date = *deprecation_date + chrono::Duration::days(self.deprecation_policy.sunset_period_days as i64);
            DeprecationInfo {
                deprecation_date: *deprecation_date,
                sunset_date,
                migration_guide_available: self.deprecation_policy.migration_guide_required,
            }
        })
    }
}

/// Deprecation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecationInfo {
    pub deprecation_date: DateTime<Utc>,
    pub sunset_date: DateTime<Utc>,
    pub migration_guide_available: bool,
}

/// Initialize versioning system
pub fn init_versioning(config: &ApiConfig) -> Result<VersionManager, VersioningError> {
    let mut manager = VersionManager::new(
        config.current_version.clone(),
        DeprecationPolicy::default(),
    );
    
    // Add all supported versions
    for version in &config.supported_versions {
        manager.add_version(version.clone());
    }
    
    // Add deprecated versions
    for (version, date) in &config.deprecated_versions {
        manager.deprecated_versions.insert(version.clone(), *date);
    }
    
    Ok(manager)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let version = ApiVersion::parse("1.2.3").unwrap();
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 2);
        assert_eq!(version.patch, 3);
    }

    #[test]
    fn test_version_compatibility() {
        let v1_0_0 = ApiVersion::new(1, 0, 0);
        let v1_1_0 = ApiVersion::new(1, 1, 0);
        let v2_0_0 = ApiVersion::new(2, 0, 0);
        
        assert!(v1_0_0.is_compatible_with(&v1_1_0));
        assert!(!v1_0_0.is_compatible_with(&v2_0_0));
    }

    #[test]
    fn test_version_ordering() {
        let v1_0_0 = ApiVersion::new(1, 0, 0);
        let v1_0_1 = ApiVersion::new(1, 0, 1);
        let v1_1_0 = ApiVersion::new(1, 1, 0);
        
        assert!(v1_0_0 < v1_0_1);
        assert!(v1_0_1 < v1_1_0);
    }

    #[test]
    fn test_versioned_endpoint() {
        let mut endpoint = VersionedEndpoint::new(
            "/api/auth".to_string(),
            ApiVersion::new(1, 0, 0),
        );
        
        endpoint.add_version(ApiVersion::new(1, 1, 0), "handler_v1_1".to_string());
        
        assert!(endpoint.supports_version(&ApiVersion::new(1, 0, 0)));
        assert!(endpoint.supports_version(&ApiVersion::new(1, 1, 0)));
        assert!(!endpoint.supports_version(&ApiVersion::new(2, 0, 0)));
    }

    #[test]
    fn test_version_manager() {
        let mut manager = VersionManager::new(
            ApiVersion::new(1, 0, 0),
            DeprecationPolicy::default(),
        );
        
        let v1_1_0 = ApiVersion::new(1, 1, 0);
        manager.add_version(v1_1_0.clone());
        
        assert!(manager.supported_versions.contains(&v1_1_0));
        
        // Test deprecation
        manager.deprecate_version(v1_1_0.clone()).unwrap();
        assert!(manager.deprecated_versions.contains_key(&v1_1_0));
    }
}