//! Outbound connection management for Hysteria protocol
//!
//! Provides various outbound connection types including direct connections,
//! SOCKS5 proxy, HTTP proxy, and custom outbound handlers.

use crate::{HysteriaError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

/// Outbound connection trait
pub trait OutboundConnection: Send + Sync {
    /// Connect to target address
    fn connect_tcp<'a>(&'a self, target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn AsyncReadWrite>>> + Send + 'a>>;
    
    /// Create UDP socket for target
    fn connect_udp<'a>(&'a self, target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<UdpSocket>>> + Send + 'a>>;
    
    /// Get connection statistics
    fn get_stats<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutboundStats> + Send + 'a>>;
}

/// Combined AsyncRead + AsyncWrite trait
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// Implement AsyncReadWrite for any type that implements the required traits
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

/// Outbound connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundStats {
    /// Total connections established
    pub total_connections: u64,
    
    /// Active connections
    pub active_connections: u64,
    
    /// Failed connections
    pub failed_connections: u64,
    
    /// Total bytes sent
    pub bytes_sent: u64,
    
    /// Total bytes received
    pub bytes_received: u64,
    
    /// Average connection time in milliseconds
    pub avg_connection_time_ms: u64,
}

impl Default for OutboundStats {
    fn default() -> Self {
        Self {
            total_connections: 0,
            active_connections: 0,
            failed_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            avg_connection_time_ms: 0,
        }
    }
}

/// Direct outbound connection
#[derive(Debug, Clone)]
pub struct DirectOutbound {
    /// Optional bind address
    pub bind_addr: Option<SocketAddr>,
    
    /// Connection timeout
    pub timeout: Duration,
    
    /// Connection statistics
    stats: Arc<RwLock<OutboundStats>>,
}

impl DirectOutbound {
    /// Create a new direct outbound connection
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            timeout: Duration::from_secs(30),
            stats: Arc::new(RwLock::new(OutboundStats::default())),
        }
    }
    
    /// Set bind address
    pub fn with_bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }
    
    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl OutboundConnection for DirectOutbound {
    fn connect_tcp<'a>(&'a self, target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn AsyncReadWrite>>> + Send + 'a>> {
        Box::pin(async move {
            let stream = TcpStream::connect(target).await
                 .map_err(|e| HysteriaError::Io(e))?;
            
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.total_connections += 1;
                stats.active_connections += 1;
            }
            
            Ok(Box::new(stream) as Box<dyn AsyncReadWrite>)
        })
    }
    
    fn connect_udp<'a>(&'a self, target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<UdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            let socket = UdpSocket::bind("0.0.0.0:0").await
                 .map_err(|e| HysteriaError::Io(e))?;
             
             socket.connect(target).await
                 .map_err(|e| HysteriaError::Io(e))?;
            
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.total_connections += 1;
                stats.active_connections += 1;
            }
            
            Ok(Arc::new(socket))
        })
    }
    
    fn get_stats<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutboundStats> + Send + 'a>> {
        Box::pin(async move {
            self.stats.read().await.clone()
        })
    }
}

/// SOCKS5 outbound connection (simplified)
#[derive(Debug, Clone)]
pub struct Socks5Outbound {
    /// SOCKS5 proxy address
    pub proxy_addr: SocketAddr,
    
    /// Connection timeout
    pub timeout: Duration,
    
    /// Connection statistics
    stats: Arc<RwLock<OutboundStats>>,
}

impl Socks5Outbound {
    /// Create a new SOCKS5 outbound connection
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            timeout: Duration::from_secs(30),
            stats: Arc::new(RwLock::new(OutboundStats::default())),
        }
    }
    
    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl OutboundConnection for Socks5Outbound {
    fn connect_tcp<'a>(&'a self, target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn AsyncReadWrite>>> + Send + 'a>> {
        Box::pin(async move {
            // Simplified SOCKS5 implementation - just return error for now
            Err(HysteriaError::Generic("SOCKS5 not implemented in simplified version".to_string()))
        })
    }
    
    fn connect_udp<'a>(&'a self, _target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<UdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            Err(HysteriaError::Generic("SOCKS5 UDP not implemented".to_string()))
        })
    }
    
    fn get_stats<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutboundStats> + Send + 'a>> {
        Box::pin(async move {
            self.stats.read().await.clone()
        })
    }
}

/// HTTP proxy outbound connection (simplified)
#[derive(Debug, Clone)]
pub struct HttpProxyOutbound {
    /// HTTP proxy address
    pub proxy_addr: SocketAddr,
    
    /// Connection timeout
    pub timeout: Duration,
    
    /// Connection statistics
    stats: Arc<RwLock<OutboundStats>>,
}

impl HttpProxyOutbound {
    /// Create a new HTTP proxy outbound connection
    pub fn new(proxy_addr: SocketAddr) -> Self {
        Self {
            proxy_addr,
            timeout: Duration::from_secs(30),
            stats: Arc::new(RwLock::new(OutboundStats::default())),
        }
    }
    
    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl OutboundConnection for HttpProxyOutbound {
    fn connect_tcp<'a>(&'a self, target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn AsyncReadWrite>>> + Send + 'a>> {
        Box::pin(async move {
            // Simplified HTTP proxy implementation - just return error for now
            Err(HysteriaError::Generic("HTTP proxy not implemented in simplified version".to_string()))
        })
    }
    
    fn connect_udp<'a>(&'a self, _target: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Arc<UdpSocket>>> + Send + 'a>> {
        Box::pin(async move {
            Err(HysteriaError::Generic("HTTP proxy does not support UDP".to_string()))
        })
    }
    
    fn get_stats<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = OutboundStats> + Send + 'a>> {
        Box::pin(async move {
            self.stats.read().await.clone()
        })
    }
}

/// Outbound connection manager
pub struct OutboundManager {
    outbounds: HashMap<String, Arc<dyn OutboundConnection>>,
    default_outbound: Option<Arc<dyn OutboundConnection>>,
}

impl OutboundManager {
    /// Create a new outbound manager
    pub fn new() -> Self {
        Self {
            outbounds: HashMap::new(),
            default_outbound: None,
        }
    }
    
    /// Add an outbound connection
    pub fn add_outbound(&mut self, name: String, outbound: Arc<dyn OutboundConnection>) {
        self.outbounds.insert(name, outbound);
    }
    
    /// Set default outbound connection
    pub fn set_default_outbound(&mut self, outbound: Arc<dyn OutboundConnection>) {
        self.default_outbound = Some(outbound);
    }
    
    /// Get outbound connection by name
    pub fn get_outbound(&self, name: &str) -> Option<Arc<dyn OutboundConnection>> {
        self.outbounds.get(name).cloned()
    }
    
    /// Get default outbound connection
    pub fn get_default_outbound(&self) -> Option<Arc<dyn OutboundConnection>> {
        self.default_outbound.clone()
    }
    
    /// Connect TCP using specified or default outbound
    pub async fn connect_tcp(&self, outbound_name: Option<&str>, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        let outbound = if let Some(name) = outbound_name {
            self.get_outbound(name)
                .ok_or_else(|| HysteriaError::Generic(format!("Outbound '{}' not found", name)))?
        } else {
            self.get_default_outbound()
                .ok_or_else(|| HysteriaError::Generic("No default outbound configured".to_string()))?
        };
        
        outbound.connect_tcp(target).await
    }
    
    /// Connect UDP using specified or default outbound
    pub async fn connect_udp(&self, outbound_name: Option<&str>, target: &str) -> Result<Arc<UdpSocket>> {
        let outbound = if let Some(name) = outbound_name {
            self.get_outbound(name)
                .ok_or_else(|| HysteriaError::Generic(format!("Outbound '{}' not found", name)))?
        } else {
            self.get_default_outbound()
                .ok_or_else(|| HysteriaError::Generic("No default outbound configured".to_string()))?
        };
        
        outbound.connect_udp(target).await
    }
    
    /// Get statistics for all outbound connections
    pub async fn get_all_stats(&self) -> HashMap<String, OutboundStats> {
        let mut stats = HashMap::new();
        
        for (name, outbound) in &self.outbounds {
            stats.insert(name.clone(), outbound.get_stats().await);
        }
        
        stats
    }
}

impl Default for OutboundManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundManager")
             .field("outbounds", &format!("{} outbound connections", self.outbounds.len()))
             .field("default_outbound", &self.default_outbound.is_some())
             .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_direct_outbound() {
        let outbound = DirectOutbound::new();
        let stats = outbound.get_stats().await;
        assert_eq!(stats.total_connections, 0);
    }
    
    #[tokio::test]
    async fn test_outbound_manager() {
        let mut manager = OutboundManager::new();
        let direct = Arc::new(DirectOutbound::new());
        
        manager.add_outbound("direct".to_string(), direct.clone());
        manager.set_default_outbound(direct);
        
        assert!(manager.get_outbound("direct").is_some());
        assert!(manager.get_default_outbound().is_some());
    }
}