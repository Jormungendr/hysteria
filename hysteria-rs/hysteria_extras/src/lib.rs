//! Hysteria 2 Extras - Additional features for Hysteria 2
//!
//! This crate provides additional functionality for Hysteria 2, including:
//! - Authentication mechanisms (password, HTTP, userpass)
//! - Obfuscation (Salamander)
//! - Access Control Lists (ACL)
//! - Outbound connections
//! - Traffic sniffing
//! - Masquerading
//! - Utilities

pub mod auth;
pub mod obfs;
pub mod acl;
pub mod outbound;
pub mod sniff;
// pub mod masquerade;  // TODO: Implement masquerade module
// pub mod utils;       // TODO: Implement utils module

// Re-export commonly used types
pub use auth::{Authenticator, PasswordAuthenticator, HttpAuthenticator, UserPassAuthenticator};
pub use obfs::{Obfuscator, SalamanderObfuscator};
pub use acl::{AclEngine, Rule, RuleSet};
pub use outbound::{OutboundManager, DirectOutbound, HttpProxyOutbound, Socks5Outbound};

/// Common error types for extras functionality
#[derive(Debug, thiserror::Error)]
pub enum ExtrasError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Obfuscation error: {0}")]
    ObfuscationError(String),
    
    #[error("ACL error: {0}")]
    AclError(String),
    
    #[error("Outbound error: {0}")]
    OutboundError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Sniff error: {0}")]
    SniffError(String),
    
    #[error("Masquerade error: {0}")]
    MasqueradeError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, ExtrasError>;

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");