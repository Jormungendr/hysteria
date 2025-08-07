//! Message types for Hysteria protocol
//!
//! Defines various message types and status codes used in the protocol.

/// TCP status codes
pub mod tcp_status {
    /// TCP connection successful
    pub const OK: u8 = 0;
    
    /// TCP connection error
    pub const ERROR: u8 = 1;
    
    /// TCP connection timeout
    pub const TIMEOUT: u8 = 2;
    
    /// TCP connection refused
    pub const REFUSED: u8 = 3;
    
    /// TCP host unreachable
    pub const HOST_UNREACHABLE: u8 = 4;
    
    /// TCP network unreachable
    pub const NETWORK_UNREACHABLE: u8 = 5;
}

/// UDP status codes
pub mod udp_status {
    /// UDP operation successful
    pub const OK: u8 = 0;
    
    /// UDP operation error
    pub const ERROR: u8 = 1;
    
    /// UDP session timeout
    pub const TIMEOUT: u8 = 2;
    
    /// UDP session closed
    pub const CLOSED: u8 = 3;
}

/// Authentication status codes
pub mod auth_status {
    /// Authentication successful
    pub const OK: u8 = 0;
    
    /// Authentication failed
    pub const FAILED: u8 = 1;
    
    /// Authentication timeout
    pub const TIMEOUT: u8 = 2;
    
    /// Authentication required
    pub const REQUIRED: u8 = 3;
}

/// Message type identifiers
pub mod message_type {
    /// TCP connection request
    pub const TCP_CONNECT: u8 = 1;
    
    /// TCP data transfer
    pub const TCP_DATA: u8 = 2;
    
    /// TCP connection close
    pub const TCP_CLOSE: u8 = 3;
    
    /// UDP packet
    pub const UDP_PACKET: u8 = 4;
    
    /// UDP session close
    pub const UDP_CLOSE: u8 = 5;
    
    /// Authentication request
    pub const AUTH_REQUEST: u8 = 6;
    
    /// Authentication response
    pub const AUTH_RESPONSE: u8 = 7;
    
    /// Heartbeat
    pub const HEARTBEAT: u8 = 8;
}