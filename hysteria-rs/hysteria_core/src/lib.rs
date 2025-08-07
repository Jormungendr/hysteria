//! Hysteria Core Library
//!
//! This crate provides the core functionality for the Hysteria protocol,
//! including QUIC transport, authentication, congestion control, hooks,
//! logging, masquerading, outbound connections, and more.

pub mod acme;
pub mod auth;
pub mod congestion;
pub mod config;
pub mod error;
pub mod hooks;
pub mod logger;
pub mod masquerade;
pub mod message_types;
pub mod obfs;
pub mod outbound;
pub mod protocol;
pub mod quic;
pub mod udp;

pub use error::{HysteriaError, Result};

/// Default QUIC port
pub const DEFAULT_PORT: u16 = 443;

/// Default UDP session timeout in seconds
pub const DEFAULT_UDP_TIMEOUT: u64 = 60;

/// Default maximum UDP sessions
pub const DEFAULT_MAX_UDP_SESSIONS: u32 = 1000;

/// Default congestion control window
pub const DEFAULT_CC_WINDOW: u32 = 1024;

/// Default authentication timeout in seconds
pub const DEFAULT_AUTH_TIMEOUT: u64 = 10;

/// Default connection timeout in seconds
pub const DEFAULT_CONNECTION_TIMEOUT: u64 = 30;

/// Default maximum concurrent connections
pub const DEFAULT_MAX_CONNECTIONS: u32 = 10000;

/// Default bandwidth measurement window in seconds
pub const DEFAULT_BANDWIDTH_WINDOW: u64 = 5;

/// Default log buffer size
pub const DEFAULT_LOG_BUFFER_SIZE: usize = 1000;

/// Authentication path for HTTP/3 masquerading
pub const AUTH_PATH: &str = "/auth";

/// Authentication success status code
pub const AUTH_SUCCESS_STATUS: u16 = 233;

/// TCP request ID for protocol messages
pub const TCP_REQUEST_ID: u64 = 0x01;
