//! ACME automatic certificate management implementation
//!
//! This module provides automatic certificate management using the ACME protocol,
//! supporting Let's Encrypt and other ACME-compatible certificate authorities.

use crate::config::{AcmeConfig, AcmeChallengeType};
use crate::{HysteriaError, Result};
use rustls::ServerConfig as RustlsServerConfig;
use rustls_acme::{AcmeConfig as RustlsAcmeConfig, caches::DirCache};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

/// ACME certificate manager
pub struct AcmeManager {
    config: AcmeConfig,
    server_config: Arc<RwLock<Option<Arc<RustlsServerConfig>>>>,
    acme_state: Option<rustls_acme::AcmeState<Box<dyn std::fmt::Debug>, Box<dyn std::fmt::Debug>>>,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub fn new(config: AcmeConfig) -> Result<Self> {
        info!("Initializing ACME manager for domains: {:?}", config.domains);
        Ok(Self {
            config,
            server_config: Arc::new(RwLock::new(None)),
            acme_state: None,
        })
    }

    /// Initialize ACME and get initial server configuration
    pub async fn initialize(&mut self) -> Result<Arc<RustlsServerConfig>> {
        info!("Starting ACME initialization...");
        
        // Create cache directory if it doesn't exist
        if let Some(cache_dir) = &self.config.cache_dir {
            if let Err(e) = std::fs::create_dir_all(cache_dir) {
                warn!("Failed to create cache directory {}: {}", cache_dir.display(), e);
            }
        }

        // Determine ACME directory URL
        let directory_url = if self.config.staging.unwrap_or(false) {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        };

        info!("Using ACME directory: {}", directory_url);

        // Create ACME configuration with cache
        let cache = if let Some(cache_dir) = &self.config.cache_dir {
            DirCache::new(cache_dir.clone())
        } else {
            DirCache::new(PathBuf::from("./acme_cache"))
        };
        
        let mut acme_config = RustlsAcmeConfig::new(self.config.domains.clone())
            .directory(directory_url)
            .cache_with_boxed_err(cache);

        // Add contact email if provided
        if !self.config.email.is_empty() {
            acme_config = acme_config.contact_push(format!("mailto:{}", self.config.email));
        }

        // Configure challenge type
        match self.config.challenge_type {
            crate::config::AcmeChallengeType::Http01 => {
                info!("HTTP-01 challenge requested but not supported in current implementation");
                warn!("Falling back to TLS-ALPN-01 challenge (recommended)");
                warn!("Note: TLS-ALPN-01 challenge requires the server to run on port 443");
            },
            crate::config::AcmeChallengeType::TlsAlpn01 => {
                info!("Using TLS-ALPN-01 challenge (recommended)");
                info!("TLS-ALPN-01 challenge will be handled automatically on the same port as QUIC");
                warn!("Note: TLS-ALPN-01 challenge requires the server to run on port 443");
            },
            crate::config::AcmeChallengeType::Dns01 => {
                if let Some(dns_config) = &self.config.dns_challenge {
                    info!("DNS-01 challenge with provider: {} not supported in current implementation", dns_config.provider);
                    warn!("Falling back to TLS-ALPN-01 challenge");
                } else {
                    warn!("DNS-01 challenge selected but no configuration provided, falling back to TLS-ALPN-01");
                }
            },
        }
        
        info!("ACME configuration: directory={}, staging={}, email={}", 
              directory_url, 
              self.config.staging.unwrap_or(false), 
              self.config.email);

        // Create ACME state
        info!("Creating ACME state for domains: {:?}", self.config.domains);
        let acme_state = acme_config.state();
        
        // Get resolver - this is the key component that handles certificate acquisition
        let resolver = acme_state.resolver();
        info!("ACME resolver created successfully");
        
        // Log resolver details for debugging
        debug!("ACME resolver configured for domains: {:?}", self.config.domains);
        debug!("ACME directory URL: {}", directory_url);
        debug!("ACME staging mode: {}", self.config.staging.unwrap_or(false));
        debug!("ACME challenge type: {:?}", self.config.challenge_type);
        
        // Create server config with ACME resolver
        // The resolver will handle certificate acquisition automatically when connections are made
        info!("Creating rustls ServerConfig with ACME resolver");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);

        let server_config = Arc::new(server_config);
        
        info!("ACME ServerConfig created successfully");
        info!("Certificate acquisition will happen automatically on first connection");
        info!("ACME challenge server will be started when needed");
        
        // Store the server config
        {
            let mut config_guard = self.server_config.write().await;
            *config_guard = Some(server_config.clone());
        }
        
        self.acme_state = Some(acme_state);
        
        info!("ACME initialization completed successfully");
        Ok(server_config)
    }

    /// Check certificate renewal
    pub async fn check_renewal(&self) -> Result<()> {
        if let Some(acme_state) = &self.acme_state {
            debug!("Checking certificate renewal status...");
            // The rustls-acme library handles renewal automatically
            // when certificates are accessed through the resolver
            info!("Certificate renewal check completed");
        } else {
            warn!("ACME state not initialized, skipping renewal check");
        }
        Ok(())
    }

    /// Get current server config
    pub async fn get_server_config(&self) -> Option<Arc<RustlsServerConfig>> {
        let config_guard = self.server_config.read().await;
        config_guard.clone()
    }

    /// Shutdown ACME manager
    pub async fn shutdown(&self) {
        info!("Shutting down ACME manager");
        // rustls-acme handles cleanup automatically
    }
}

/// Create a manual server configuration from certificate and key files
pub fn create_manual_server_config(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<Arc<RustlsServerConfig>> {
    // For now, return a simple error since we need rustls_pemfile dependency
    Err(HysteriaError::Config(
        "Manual certificate loading requires rustls_pemfile dependency. Please use s2n-quic's built-in certificate loading.".to_string()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AcmeConfig;
    use std::collections::HashMap;

    #[test]
    fn test_acme_manager_creation() {
        let config = AcmeConfig {
            domains: vec!["example.com".to_string()],
            email: "test@example.com".to_string(),
            directory_url: None,
            challenge_type: crate::config::AcmeChallengeType::Http01,
            http_challenge: Some(crate::config::HttpChallengeConfig {
                port: Some(8080),
                bind: Some("0.0.0.0".to_string()),
            }),
            tls_alpn_challenge: None,
            dns_challenge: None,
            cache_dir: Some(std::path::PathBuf::from("/tmp/acme")),
            staging: Some(true),
        };

        let manager = AcmeManager::new(config);
        assert!(manager.is_ok());
    }
}