//! Production Post-Quantum Cryptography Integration
//!
//! This module enables post-quantum cryptography for production deployments
//! by setting the appropriate environment variables and configuration.

use anyhow::Result;
use std::env;
use tracing::info;

/// Enable post-quantum cryptography for production
pub fn enable_production_post_quantum() -> Result<()> {
    // Set environment variables to enable post-quantum features
    env::set_var("POST_QUANTUM_ENABLED", "true");
    env::set_var("HYBRID_CRYPTO_ENABLED", "true");
    env::set_var("PQ_SECURITY_LEVEL", "Level3"); // 192-bit security for production
    env::set_var("DEPLOYMENT_ENVIRONMENT", "production");
    
    info!("Post-quantum cryptography enabled for production environment");
    info!("Security level set to Level3 (192-bit equivalent)");
    info!("Hybrid cryptography enabled for backward compatibility");
    
    Ok(())
}

/// Check if post-quantum cryptography is enabled
pub fn is_post_quantum_enabled() -> bool {
    env::var("POST_QUANTUM_ENABLED")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Get the current post-quantum security level
pub fn get_pq_security_level() -> String {
    env::var("PQ_SECURITY_LEVEL").unwrap_or_else(|_| "Level3".to_string())
}

/// Initialize post-quantum cryptography for production
pub async fn initialize_production_pq() -> Result<()> {
    enable_production_post_quantum()?;
    
    // Verify environment is properly configured
    if !is_post_quantum_enabled() {
        return Err(anyhow::anyhow!("Failed to enable post-quantum cryptography"));
    }
    
    info!("Production post-quantum cryptography initialized successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enable_post_quantum() {
        assert!(enable_production_post_quantum().is_ok());
        assert!(is_post_quantum_enabled());
        assert_eq!(get_pq_security_level(), "Level3");
    }

    #[tokio::test]
    async fn test_initialize_production_pq() {
        assert!(initialize_production_pq().await.is_ok());
    }
}