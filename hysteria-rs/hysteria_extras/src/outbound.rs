//! Outbound connections for Hysteria 2
//!
//! This module provides different types of outbound connections
//! including direct, SOCKS5, HTTP proxy, and custom outbounds.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use async_trait::async_trait;
use base64::prelude::*;
use crate::{ExtrasError, Result};

/// Trait for outbound connections
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Connect to the target address
    async fn connect(&self, addr: &str, port: u16) -> Result<Box<dyn Connection>>;
    
    /// Get the outbound name
    fn name(&self) -> &str;
}

/// Trait for network connections
#[async_trait]
pub trait Connection: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    /// Get the local address
    fn local_addr(&self) -> Result<SocketAddr>;
    
    /// Get the remote address
    fn remote_addr(&self) -> Result<SocketAddr>;
}

#[async_trait]
impl Connection for TcpStream {
    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr().map_err(|e| ExtrasError::NetworkError(e.to_string()))
    }
    
    fn remote_addr(&self) -> Result<SocketAddr> {
        self.peer_addr().map_err(|e| ExtrasError::NetworkError(e.to_string()))
    }
}

/// Direct outbound connection
#[derive(Debug, Clone)]
pub struct DirectOutbound {
    name: String,
}

impl DirectOutbound {
    /// Create a new direct outbound
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    async fn connect(&self, addr: &str, port: u16) -> Result<Box<dyn Connection>> {
        let target = format!("{}:{}", addr, port);
        let stream = TcpStream::connect(&target).await
            .map_err(|e| ExtrasError::NetworkError(format!("Failed to connect to {}: {}", target, e)))?;
        Ok(Box::new(stream))
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

/// SOCKS5 outbound connection
#[derive(Debug, Clone)]
pub struct Socks5Outbound {
    name: String,
    proxy_addr: String,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Outbound {
    /// Create a new SOCKS5 outbound
    pub fn new(name: String, proxy_addr: String, username: Option<String>, password: Option<String>) -> Self {
        Self {
            name,
            proxy_addr,
            username,
            password,
        }
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    async fn connect(&self, addr: &str, port: u16) -> Result<Box<dyn Connection>> {
        // Connect to SOCKS5 proxy
        let mut stream = TcpStream::connect(&self.proxy_addr).await
            .map_err(|e| ExtrasError::NetworkError(format!("Failed to connect to SOCKS5 proxy {}: {}", self.proxy_addr, e)))?;
        
        // Perform SOCKS5 handshake
        socks5_handshake(&mut stream, &self.username, &self.password).await?;
        
        // Connect to target through proxy
        socks5_connect(&mut stream, addr, port).await?;
        
        Ok(Box::new(stream))
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

/// HTTP proxy outbound connection
#[derive(Debug, Clone)]
pub struct HttpProxyOutbound {
    name: String,
    proxy_addr: String,
    username: Option<String>,
    password: Option<String>,
}

impl HttpProxyOutbound {
    /// Create a new HTTP proxy outbound
    pub fn new(name: String, proxy_addr: String, username: Option<String>, password: Option<String>) -> Self {
        Self {
            name,
            proxy_addr,
            username,
            password,
        }
    }
}

#[async_trait]
impl Outbound for HttpProxyOutbound {
    async fn connect(&self, addr: &str, port: u16) -> Result<Box<dyn Connection>> {
        // Connect to HTTP proxy
        let mut stream = TcpStream::connect(&self.proxy_addr).await
            .map_err(|e| ExtrasError::NetworkError(format!("Failed to connect to HTTP proxy {}: {}", self.proxy_addr, e)))?;
        
        // Send CONNECT request
        http_connect(&mut stream, addr, port, &self.username, &self.password).await?;
        
        Ok(Box::new(stream))
    }
    
    fn name(&self) -> &str {
        &self.name
    }
}

/// Outbound manager
pub struct OutboundManager {
    outbounds: std::collections::HashMap<String, Arc<dyn Outbound>>,
    default_outbound: String,
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundManager")
            .field("outbound_names", &self.outbounds.keys().collect::<Vec<_>>())
            .field("default_outbound", &self.default_outbound)
            .finish()
    }
}

impl OutboundManager {
    /// Create a new outbound manager
    pub fn new(default_outbound: String) -> Self {
        Self {
            outbounds: std::collections::HashMap::new(),
            default_outbound,
        }
    }
    
    /// Add an outbound
    pub fn add_outbound(&mut self, outbound: Arc<dyn Outbound>) {
        self.outbounds.insert(outbound.name().to_string(), outbound);
    }
    
    /// Get an outbound by name
    pub fn get_outbound(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(name).cloned()
    }
    
    /// Get the default outbound
    pub fn get_default_outbound(&self) -> Option<Arc<dyn Outbound>> {
        self.get_outbound(&self.default_outbound)
    }
    
    /// Connect using the specified outbound
    pub async fn connect(&self, outbound_name: &str, addr: &str, port: u16) -> Result<Box<dyn Connection>> {
        let outbound = self.get_outbound(outbound_name)
            .ok_or_else(|| ExtrasError::OutboundError(format!("Outbound not found: {}", outbound_name)))?;
        outbound.connect(addr, port).await
    }
    
    /// Connect using the default outbound
    pub async fn connect_default(&self, addr: &str, port: u16) -> Result<Box<dyn Connection>> {
        let outbound = self.get_default_outbound()
            .ok_or_else(|| ExtrasError::OutboundError("Default outbound not found".to_string()))?;
        outbound.connect(addr, port).await
    }
}

/// SOCKS5 handshake implementation
async fn socks5_handshake(
    stream: &mut TcpStream,
    username: &Option<String>,
    password: &Option<String>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    // Send authentication methods
    let auth_methods = if username.is_some() && password.is_some() {
        vec![0x05, 0x02, 0x00, 0x02] // Version 5, 2 methods, No auth, Username/Password
    } else {
        vec![0x05, 0x01, 0x00] // Version 5, 1 method, No auth
    };
    
    stream.write_all(&auth_methods).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 handshake write error: {}", e)))?;
    
    // Read server response
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 handshake read error: {}", e)))?;
    
    if response[0] != 0x05 {
        return Err(ExtrasError::NetworkError("Invalid SOCKS5 version".to_string()));
    }
    
    match response[1] {
        0x00 => {}, // No authentication required
        0x02 => {
            // Username/password authentication
            if let (Some(user), Some(pass)) = (username, password) {
                socks5_auth(stream, user, pass).await?;
            } else {
                return Err(ExtrasError::NetworkError("SOCKS5 authentication required but no credentials provided".to_string()));
            }
        }
        0xFF => return Err(ExtrasError::NetworkError("SOCKS5 no acceptable authentication methods".to_string())),
        _ => return Err(ExtrasError::NetworkError("SOCKS5 unknown authentication method".to_string())),
    }
    
    Ok(())
}

/// SOCKS5 username/password authentication
async fn socks5_auth(stream: &mut TcpStream, username: &str, password: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    let mut auth_request = vec![0x01]; // Version 1
    auth_request.push(username.len() as u8);
    auth_request.extend_from_slice(username.as_bytes());
    auth_request.push(password.len() as u8);
    auth_request.extend_from_slice(password.as_bytes());
    
    stream.write_all(&auth_request).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 auth write error: {}", e)))?;
    
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 auth read error: {}", e)))?;
    
    if response[1] != 0x00 {
        return Err(ExtrasError::NetworkError("SOCKS5 authentication failed".to_string()));
    }
    
    Ok(())
}

/// SOCKS5 connect request
async fn socks5_connect(stream: &mut TcpStream, addr: &str, port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::net::IpAddr;
    
    let mut request = vec![0x05, 0x01, 0x00]; // Version 5, Connect, Reserved
    
    // Address type and address
    if let Ok(ip) = addr.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ipv4) => {
                request.push(0x01); // IPv4
                request.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                request.push(0x04); // IPv6
                request.extend_from_slice(&ipv6.octets());
            }
        }
    } else {
        // Domain name
        request.push(0x03); // Domain
        request.push(addr.len() as u8);
        request.extend_from_slice(addr.as_bytes());
    }
    
    // Port
    request.extend_from_slice(&port.to_be_bytes());
    
    stream.write_all(&request).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 connect write error: {}", e)))?;
    
    // Read response
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 connect read error: {}", e)))?;
    
    if response[0] != 0x05 {
        return Err(ExtrasError::NetworkError("Invalid SOCKS5 version in connect response".to_string()));
    }
    
    if response[1] != 0x00 {
        let error_msg = match response[1] {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            _ => "Unknown error",
        };
        return Err(ExtrasError::NetworkError(format!("SOCKS5 connect failed: {}", error_msg)));
    }
    
    // Skip the rest of the response (bound address and port)
    let addr_type = response[3];
    let skip_len = match addr_type {
        0x01 => 4 + 2, // IPv4 + port
        0x03 => {
            let mut domain_len = [0u8; 1];
            stream.read_exact(&mut domain_len).await
                .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 domain length read error: {}", e)))?;
            domain_len[0] as usize + 2 // domain + port
        }
        0x04 => 16 + 2, // IPv6 + port
        _ => return Err(ExtrasError::NetworkError("Invalid address type in SOCKS5 response".to_string())),
    };
    
    let mut skip_buf = vec![0u8; skip_len];
    stream.read_exact(&mut skip_buf).await
        .map_err(|e| ExtrasError::NetworkError(format!("SOCKS5 response skip error: {}", e)))?;
    
    Ok(())
}

/// HTTP CONNECT implementation
async fn http_connect(
    stream: &mut TcpStream,
    addr: &str,
    port: u16,
    username: &Option<String>,
    password: &Option<String>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    
    let mut request = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n", addr, port, addr, port);
    
    // Add authentication if provided
    if let (Some(user), Some(pass)) = (username, password) {
        let credentials = base64::prelude::BASE64_STANDARD.encode(format!("{}:{}", user, pass));
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", credentials));
    }
    
    request.push_str("\r\n");
    
    stream.write_all(request.as_bytes()).await
        .map_err(|e| ExtrasError::NetworkError(format!("HTTP CONNECT write error: {}", e)))?;
    
    // Read response
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await
        .map_err(|e| ExtrasError::NetworkError(format!("HTTP CONNECT read error: {}", e)))?;
    
    if !status_line.contains("200") {
        return Err(ExtrasError::NetworkError(format!("HTTP CONNECT failed: {}", status_line.trim())));
    }
    
    // Skip headers
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await
            .map_err(|e| ExtrasError::NetworkError(format!("HTTP CONNECT header read error: {}", e)))?;
        if line.trim().is_empty() {
            break;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_direct_outbound_creation() {
        let outbound = DirectOutbound::new("direct".to_string());
        assert_eq!(outbound.name(), "direct");
    }
    
    #[test]
    fn test_socks5_outbound_creation() {
        let outbound = Socks5Outbound::new(
            "socks5".to_string(),
            "127.0.0.1:1080".to_string(),
            Some("user".to_string()),
            Some("pass".to_string()),
        );
        assert_eq!(outbound.name(), "socks5");
    }
    
    #[test]
    fn test_http_proxy_outbound_creation() {
        let outbound = HttpProxyOutbound::new(
            "http".to_string(),
            "127.0.0.1:8080".to_string(),
            None,
            None,
        );
        assert_eq!(outbound.name(), "http");
    }
    
    #[test]
    fn test_outbound_manager() {
        let mut manager = OutboundManager::new("direct".to_string());
        
        let direct = Arc::new(DirectOutbound::new("direct".to_string()));
        manager.add_outbound(direct.clone());
        
        assert!(manager.get_outbound("direct").is_some());
        assert!(manager.get_outbound("nonexistent").is_none());
        assert!(manager.get_default_outbound().is_some());
    }
}