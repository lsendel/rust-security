//! JWKS (JSON Web Key Set) endpoint implementation with hardening
//!
//! Provides secure JWKS endpoint with ETag support, caching headers,
//! and CDN compatibility for efficient key distribution.

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// JWKS response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,         // Key type (RSA, EC, etc.)
    pub use_: String,        // Key use (sig, enc)
    pub kid: String,         // Key ID
    pub alg: String,         // Algorithm
    pub n: Option<String>,   // RSA modulus
    pub e: Option<String>,   // RSA exponent
    pub x: Option<String>,   // EC x coordinate
    pub y: Option<String>,   // EC y coordinate
    pub crv: Option<String>, // EC curve
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>, // X.509 certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>, // X.509 certificate SHA-1 thumbprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>, // X.509 certificate SHA-256 thumbprint
}

/// JWKS cache entry
#[derive(Debug, Clone)]
pub struct JwksCacheEntry {
    pub jwks: JwksResponse,
    pub etag: String,
    pub last_modified: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// JWKS cache manager
pub struct JwksCache {
    entries: Arc<RwLock<HashMap<String, JwksCacheEntry>>>,
    default_ttl: Duration,
}

impl JwksCache {
    pub fn new(ttl_seconds: i64) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: Duration::seconds(ttl_seconds),
        }
    }

    /// Get cached JWKS with ETag validation
    pub async fn get(&self, key: &str, if_none_match: Option<&str>) -> Option<JwksCacheEntry> {
        let entries = self.entries.read().await;

        if let Some(entry) = entries.get(key) {
            // Check if entry is expired
            if entry.expires_at < Utc::now() {
                debug!("JWKS cache entry expired for key: {}", key);
                return None;
            }

            // Check ETag if provided
            if let Some(client_etag) = if_none_match {
                if client_etag == entry.etag {
                    debug!("JWKS ETag match, returning 304 for key: {}", key);
                    return Some(entry.clone());
                }
            }

            debug!("Returning cached JWKS for key: {}", key);
            return Some(entry.clone());
        }

        None
    }

    /// Store JWKS in cache with calculated ETag
    pub async fn set(&self, key: String, jwks: JwksResponse) -> JwksCacheEntry {
        let jwks_json = serde_json::to_string(&jwks).unwrap_or_default();
        let etag = calculate_etag(&jwks_json);
        let now = Utc::now();

        let entry = JwksCacheEntry {
            jwks,
            etag: etag.clone(),
            last_modified: now,
            expires_at: now + self.default_ttl,
        };

        let mut entries = self.entries.write().await;
        entries.insert(key, entry.clone());

        info!("Cached JWKS with ETag: {}", etag);
        entry
    }

    /// Clean up expired entries
    pub async fn cleanup_expired(&self) {
        let mut entries = self.entries.write().await;
        let now = Utc::now();

        entries.retain(|key, entry| {
            let expired = entry.expires_at < now;
            if expired {
                debug!("Removing expired JWKS cache entry: {}", key);
            }
            !expired
        });
    }
}

/// Calculate ETag for content
fn calculate_etag(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    format!("W/\"{:x}\"", result)
}

/// JWKS query parameters
#[derive(Debug, Deserialize)]
pub struct JwksQuery {
    pub kid: Option<String>, // Filter by specific key ID
}

/// JWKS endpoint handler with hardening
pub async fn jwks_handler(
    Query(params): Query<JwksQuery>,
    headers: HeaderMap,
    State(cache): State<Arc<JwksCache>>,
    State(key_manager): State<Arc<dyn KeyManager>>,
) -> Response {
    // Rate limiting is handled by middleware

    // Get If-None-Match header for ETag validation
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());

    // Determine cache key
    let cache_key = params.kid.as_deref().unwrap_or("default");

    // Check cache first
    if let Some(cached_entry) = cache.get(cache_key, if_none_match).await {
        // If ETag matches, return 304 Not Modified
        if if_none_match.is_some() && if_none_match.unwrap() == cached_entry.etag {
            return not_modified_response(cached_entry);
        }

        // Return cached response with headers
        return jwks_response(cached_entry);
    }

    // Generate JWKS from key manager
    let jwks = match generate_jwks(&key_manager, params.kid.as_deref()).await {
        Ok(jwks) => jwks,
        Err(e) => {
            warn!("Failed to generate JWKS: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate JWKS").into_response();
        }
    };

    // Store in cache
    let cache_entry = cache.set(cache_key.to_string(), jwks).await;

    // Return response with caching headers
    jwks_response(cache_entry)
}

/// Generate JWKS from key manager
async fn generate_jwks(
    key_manager: &Arc<dyn KeyManager>,
    kid_filter: Option<&str>,
) -> Result<JwksResponse, Box<dyn std::error::Error>> {
    let keys = if let Some(kid) = kid_filter {
        // Get specific key
        vec![key_manager.get_public_key(kid).await?]
    } else {
        // Get all active public keys
        key_manager.get_all_public_keys().await?
    };

    Ok(JwksResponse { keys })
}

/// Build JWKS response with caching headers
fn jwks_response(entry: JwksCacheEntry) -> Response {
    let mut headers = HeaderMap::new();

    // ETag header
    headers.insert(header::ETAG, HeaderValue::from_str(&entry.etag).unwrap());

    // Last-Modified header
    headers.insert(
        header::LAST_MODIFIED,
        HeaderValue::from_str(&entry.last_modified.to_rfc2822()).unwrap(),
    );

    // Cache-Control header (1 hour cache, must revalidate)
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, must-revalidate"),
    );

    // Expires header (1 hour from now)
    let expires = Utc::now() + Duration::hours(1);
    headers.insert(
        header::EXPIRES,
        HeaderValue::from_str(&expires.to_rfc2822()).unwrap(),
    );

    // Security headers
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // CORS headers for JWKS (should be publicly accessible)
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );

    (StatusCode::OK, headers, Json(entry.jwks)).into_response()
}

/// Build 304 Not Modified response
fn not_modified_response(entry: JwksCacheEntry) -> Response {
    let mut headers = HeaderMap::new();

    // ETag header (must be included in 304)
    headers.insert(header::ETAG, HeaderValue::from_str(&entry.etag).unwrap());

    // Cache-Control header
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, must-revalidate"),
    );

    (StatusCode::NOT_MODIFIED, headers).into_response()
}

/// Key manager trait (to be implemented by actual key management)
#[async_trait::async_trait]
pub trait KeyManager: Send + Sync {
    async fn get_public_key(&self, kid: &str) -> Result<Jwk, Box<dyn std::error::Error>>;
    async fn get_all_public_keys(&self) -> Result<Vec<Jwk>, Box<dyn std::error::Error>>;
}

/// Start background task to clean up expired cache entries
pub async fn start_cache_cleanup(cache: Arc<JwksCache>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // Every 5 minutes

    loop {
        interval.tick().await;
        cache.cleanup_expired().await;
        debug!("JWKS cache cleanup completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etag_calculation() {
        let content = r#"{"keys":[{"kty":"RSA","use":"sig","kid":"test"}]}"#;
        let etag = calculate_etag(content);
        assert!(etag.starts_with("W/\""));
        assert!(etag.ends_with("\""));

        // Same content should produce same ETag
        let etag2 = calculate_etag(content);
        assert_eq!(etag, etag2);

        // Different content should produce different ETag
        let different_content = r#"{"keys":[]}"#;
        let different_etag = calculate_etag(different_content);
        assert_ne!(etag, different_etag);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let cache = JwksCache::new(60);
        let jwks = JwksResponse { keys: vec![] };

        // Store in cache
        let entry = cache.set("test".to_string(), jwks.clone()).await;
        assert!(!entry.etag.is_empty());

        // Retrieve from cache
        let cached = cache.get("test", None).await;
        assert!(cached.is_some());

        // Test ETag matching
        let cached_with_etag = cache.get("test", Some(&entry.etag)).await;
        assert!(cached_with_etag.is_some());

        // Test non-existent key
        let not_found = cache.get("nonexistent", None).await;
        assert!(not_found.is_none());
    }
}
