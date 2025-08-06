//! Hysteria 2 Core Protocol Implementation
//!
//! This crate provides the core protocol implementation for Hysteria 2,
//! a feature-packed proxy & relay tool optimized for lossy, unstable connections.
//!
//! The implementation is based on the Hysteria 2 Protocol Specification
//! and uses QUIC as the underlying transport protocol.

pub mod auth;
pub mod congestion;
pub mod error;
pub mod obfs;
pub mod protocol;
pub mod quic;
pub mod udp;

pub use error::{HysteriaError, Result};

/// Hysteria protocol version
pub const PROTOCOL_VERSION: &str = "2.0.0";

/// Default HTTP/3 authentication path
pub const AUTH_PATH: &str = "/auth";

/// Hysteria authentication success status code
pub const AUTH_SUCCESS_STATUS: u16 = 233;

/// TCP request message ID
pub const TCP_REQUEST_ID: u64 = 0x401;

/// UDP message types
pub mod message_types {
    /// TCP request status codes
    pub mod tcp_status {
        pub const OK: u8 = 0x00;
        pub const ERROR: u8 = 0x01;
    }
}
