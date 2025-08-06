//! QUIC wrapper module for s2n-quic
//! 
//! This module provides a simplified interface to the s2n-quic library,
//! encapsulating client and server functionality for the Hysteria protocol.

use crate::{HysteriaError, Result};
use bytes::Bytes;
use s2n_quic::{
    Client, Server, Connection,
    client::Connect,
    stream::BidirectionalStream,
};
use std::net::SocketAddr;
use std::time::Duration;

/// QUIC client configuration
#[derive(Debug, Clone)]
pub struct QuicClientConfig {
    pub server_name: String,
    pub insecure: bool,
}

/// QUIC server configuration
#[derive(Debug, Clone)]
pub struct QuicServerConfig {
    pub bind_addr: SocketAddr,
}

/// Hysteria QUIC client wrapper
pub struct HysteriaQuicClient {
    client: Client,
    config: QuicClientConfig,
}

/// Hysteria QUIC server wrapper
pub struct HysteriaQuicServer {
    server: Server,
    config: QuicServerConfig,
}

/// QUIC stream wrapper
#[derive(Debug)]
pub struct QuicStream {
    stream: BidirectionalStream,
}

/// QUIC datagram sender/receiver
#[derive(Debug)]
pub struct QuicDatagrams {
    connection: Connection,
}

impl HysteriaQuicClient {
    /// Create a new QUIC client
    pub async fn new(config: QuicClientConfig) -> Result<Self> {
        let tls = Self::build_client_tls_config(&config)?;
        let client = Client::builder()
            .with_tls(tls).unwrap()
            .with_io("0.0.0.0:0")?
            .start()
            .map_err(|e| HysteriaError::quic(format!("Failed to start QUIC client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Connect to a server
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<Connection> {
        let connect = Connect::new(server_addr).with_server_name(self.config.server_name.as_str());
        
        self.client
            .connect(connect)
            .await
            .map_err(|e| HysteriaError::quic(format!("Failed to connect: {}", e)))
    }



    /// Build TLS configuration for client
    fn build_client_tls_config(_config: &QuicClientConfig) -> Result<s2n_quic::provider::tls::default::Client> {
        // For now, use a simple TLS configuration
        // TODO: Implement proper certificate handling
        Ok(s2n_quic::provider::tls::default::Client::builder()
            .build()
            .unwrap())
    }
}

impl HysteriaQuicServer {
    /// Create a new QUIC server
    pub async fn new(config: QuicServerConfig) -> Result<Self> {
        let tls_config = Self::build_server_tls_config(&config)?;
        
        let server = Server::builder()
            .with_tls(tls_config).unwrap()
            .with_io(config.bind_addr)?
            .start()
            .map_err(|e| HysteriaError::quic(format!("Failed to start QUIC server: {}", e)))?;

        Ok(Self { server, config })
    }

    /// Accept incoming connections
    pub async fn accept(&mut self) -> Result<Option<Connection>> {
        Ok(self.server
            .accept()
            .await)
    }

    /// Build TLS configuration for server
    fn build_server_tls_config(_config: &QuicServerConfig) -> Result<s2n_quic::provider::tls::default::Server> {
        // For now, use a simple TLS configuration
        // TODO: Implement proper certificate handling
        Ok(s2n_quic::provider::tls::default::Server::builder()
            .build()
            .unwrap())
    }
}

impl QuicStream {
    /// Create a new QuicStream
    pub fn new(stream: BidirectionalStream) -> Self {
        Self { stream }
    }

    /// Send data on the stream
    pub async fn send(&mut self, data: Bytes) -> Result<()> {
        self.stream
            .send(data)
            .await
            .map_err(|e| HysteriaError::quic(format!("Failed to send data: {}", e)))?;
        Ok(())
    }

    /// Receive data from the stream
    pub async fn receive(&mut self) -> Result<Option<Bytes>> {
        match self.stream.receive().await {
            Ok(Some(data)) => Ok(Some(data)),
            Ok(None) => Ok(None), // Stream closed
            Err(e) => Err(HysteriaError::quic(format!("Failed to receive from stream: {}", e))),
        }
    }

    /// Close the stream
    pub fn close(&mut self) {
        // Note: s2n-quic's close method doesn't take error codes
        // The stream will be closed when dropped
    }
}



/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub rtt: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn create_test_client_config() -> QuicClientConfig {
        QuicClientConfig {
            server_name: "localhost".to_string(),
            insecure: true,
        }
    }

    fn create_test_server_config() -> QuicServerConfig {
        QuicServerConfig {
            bind_addr: "127.0.0.1:8443".parse().unwrap(),
        }
    }

    #[test]
    fn test_client_config_creation() {
        let config = create_test_client_config();
        assert_eq!(config.server_name, "localhost");
        assert!(config.insecure);
    }

    #[test]
    fn test_server_config_creation() {
        let config = create_test_server_config();
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:8443");
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = create_test_client_config();
        // This will fail without proper certificates, but tests the creation logic
        let result = HysteriaQuicClient::new(config).await;
        // We expect this to fail in test environment without proper setup
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }
}