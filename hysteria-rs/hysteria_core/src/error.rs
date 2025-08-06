//! Error types for Hysteria protocol implementation

use thiserror::Error;

/// Result type alias for Hysteria operations
pub type Result<T> = std::result::Result<T, HysteriaError>;

/// Main error type for Hysteria protocol operations
#[derive(Error, Debug)]
pub enum HysteriaError {
    /// QUIC transport errors
    #[error("QUIC error: {0}")]
    Quic(String),

    /// Authentication errors
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Protocol errors
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Network I/O errors
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Congestion control errors
    #[error("Congestion control error: {0}")]
    CongestionControl(String),

    /// UDP session errors
    #[error("UDP session error: {0}")]
    UdpSession(String),

    /// Obfuscation errors
    #[error("Obfuscation error: {0}")]
    Obfuscation(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Timeout errors
    #[error("Operation timed out")]
    Timeout,

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Invalid data format
    #[error("Invalid data format: {0}")]
    InvalidData(String),

    /// Generic error
    #[error("Generic error: {0}")]
    Generic(String),
}

impl HysteriaError {
    /// Create a new QUIC error
    pub fn quic<S: Into<String>>(msg: S) -> Self {
        Self::Quic(msg.into())
    }

    /// Create a new authentication error
    pub fn auth<S: Into<String>>(msg: S) -> Self {
        Self::Authentication(msg.into())
    }

    /// Create a new protocol error
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        Self::Protocol(msg.into())
    }

    /// Create a new congestion control error
    pub fn congestion_control<S: Into<String>>(msg: S) -> Self {
        Self::CongestionControl(msg.into())
    }

    /// Create a new UDP session error
    pub fn udp_session<S: Into<String>>(msg: S) -> Self {
        Self::UdpSession(msg.into())
    }

    /// Create a new obfuscation error
    pub fn obfuscation<S: Into<String>>(msg: S) -> Self {
        Self::Obfuscation(msg.into())
    }

    /// Create a new configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::Config(msg.into())
    }

    /// Create a new invalid data error
    pub fn invalid_data<S: Into<String>>(msg: S) -> Self {
        Self::InvalidData(msg.into())
    }

    /// Create a new generic error
    pub fn generic<S: Into<String>>(msg: S) -> Self {
        Self::Generic(msg.into())
    }
}