//! Authentication module for Hysteria protocol
//!
//! Implements the HTTP/3 masquerading authentication mechanism
//! as specified in the Hysteria 2 protocol.

use crate::{HysteriaError, Result, AUTH_PATH, AUTH_SUCCESS_STATUS};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication request headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    /// Authentication credentials
    pub auth: String,
    /// Client's maximum receive rate in bytes per second (0 = unknown)
    pub cc_rx: u64,
    /// Random padding string
    pub padding: Option<String>,
}

/// Authentication response headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// Whether the server supports UDP relay
    pub udp: bool,
    /// Server's maximum receive rate (0 = unlimited, "auto" = use congestion control)
    pub cc_rx: CongestionControlRate,
    /// Random padding string
    pub padding: Option<String>,
}

/// Congestion control rate specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CongestionControlRate {
    /// Specific rate in bytes per second (0 = unlimited)
    Rate(u64),
    /// Use automatic congestion control
    Auto,
}

impl std::fmt::Display for CongestionControlRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CongestionControlRate::Rate(rate) => write!(f, "{}", rate),
            CongestionControlRate::Auto => write!(f, "auto"),
        }
    }
}

impl std::str::FromStr for CongestionControlRate {
    type Err = HysteriaError;

    fn from_str(s: &str) -> Result<Self> {
        if s == "auto" {
            Ok(CongestionControlRate::Auto)
        } else {
            s.parse::<u64>()
                .map(CongestionControlRate::Rate)
                .map_err(|_| HysteriaError::invalid_data(format!("Invalid CC rate: {}", s)))
        }
    }
}

/// HTTP/3 request representation
#[derive(Debug, Clone)]
pub struct Http3Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// HTTP/3 response representation
#[derive(Debug, Clone)]
pub struct Http3Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// Authentication handler trait
pub trait AuthHandler: Send + Sync {
    /// Authenticate a client request
    fn authenticate(&self, auth: &str) -> Result<bool>;
    
    /// Get server configuration for authenticated client
    fn get_server_config(&self) -> AuthResponse;
}

/// Simple password-based authentication handler
#[derive(Debug, Clone)]
pub struct PasswordAuthHandler {
    password: String,
    udp_enabled: bool,
    cc_rx: CongestionControlRate,
}

impl PasswordAuthHandler {
    /// Create a new password authentication handler
    pub fn new(password: String, udp_enabled: bool, cc_rx: CongestionControlRate) -> Self {
        Self {
            password,
            udp_enabled,
            cc_rx,
        }
    }
}

impl AuthHandler for PasswordAuthHandler {
    fn authenticate(&self, auth: &str) -> Result<bool> {
        Ok(auth == self.password)
    }

    fn get_server_config(&self) -> AuthResponse {
        AuthResponse {
            udp: self.udp_enabled,
            cc_rx: self.cc_rx.clone(),
            padding: Some(generate_random_padding()),
        }
    }
}

/// Parse Hysteria authentication request from HTTP/3 request
pub fn parse_auth_request(request: &Http3Request) -> Result<Option<AuthRequest>> {
    // Check if this is a Hysteria authentication request
    if request.method != "POST" || request.path != AUTH_PATH {
        return Ok(None);
    }

    let host = request.headers.get(":host")
        .ok_or_else(|| HysteriaError::auth("Missing :host header"))?;
    
    if host != "hysteria" {
        return Ok(None);
    }

    let auth = request.headers.get("hysteria-auth")
        .ok_or_else(|| HysteriaError::auth("Missing Hysteria-Auth header"))?;

    let cc_rx = request.headers.get("hysteria-cc-rx")
        .ok_or_else(|| HysteriaError::auth("Missing Hysteria-CC-RX header"))?
        .parse::<u64>()
        .map_err(|_| HysteriaError::auth("Invalid Hysteria-CC-RX value"))?;

    let padding = request.headers.get("hysteria-padding").cloned();

    Ok(Some(AuthRequest {
        auth: auth.clone(),
        cc_rx,
        padding,
    }))
}

/// Create Hysteria authentication response
pub fn create_auth_response(response: &AuthResponse) -> Http3Response {
    let mut headers = HashMap::new();
    headers.insert(":status".to_string(), format!("{} HyOK", AUTH_SUCCESS_STATUS));
    headers.insert("hysteria-udp".to_string(), response.udp.to_string());
    headers.insert("hysteria-cc-rx".to_string(), response.cc_rx.to_string());
    
    if let Some(padding) = &response.padding {
        headers.insert("hysteria-padding".to_string(), padding.clone());
    }

    Http3Response {
        status: AUTH_SUCCESS_STATUS,
        headers,
        body: Vec::new(),
    }
}

/// Generate random padding string
fn generate_random_padding() -> String {
    use rand::{distr::Alphanumeric, Rng};
    
    let length = rand::rng().random_range(10..=100);
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_control_rate_parsing() {
        assert!(matches!(
            "auto".parse::<CongestionControlRate>().unwrap(),
            CongestionControlRate::Auto
        ));
        
        assert!(matches!(
            "1000".parse::<CongestionControlRate>().unwrap(),
            CongestionControlRate::Rate(1000)
        ));
        
        assert!("invalid".parse::<CongestionControlRate>().is_err());
    }

    #[test]
    fn test_password_auth_handler() {
        let handler = PasswordAuthHandler::new(
            "test_password".to_string(),
            true,
            CongestionControlRate::Rate(1000000),
        );
        
        assert!(handler.authenticate("test_password").unwrap());
        assert!(!handler.authenticate("wrong_password").unwrap());
        
        let config = handler.get_server_config();
        assert!(config.udp);
        assert!(matches!(config.cc_rx, CongestionControlRate::Rate(1000000)));
    }

    #[test]
    fn test_auth_request_parsing() {
        let mut headers = HashMap::new();
        headers.insert(":host".to_string(), "hysteria".to_string());
        headers.insert("hysteria-auth".to_string(), "test_auth".to_string());
        headers.insert("hysteria-cc-rx".to_string(), "1000".to_string());
        
        let request = Http3Request {
            method: "POST".to_string(),
            path: "/auth".to_string(),
            headers,
            body: Vec::new(),
        };
        
        let auth_req = parse_auth_request(&request).unwrap().unwrap();
        assert_eq!(auth_req.auth, "test_auth");
        assert_eq!(auth_req.cc_rx, 1000);
    }
}