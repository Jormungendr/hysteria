//! QUIC wrapper module for Quinn
//! 
//! This module provides a simplified interface to the Quinn library,
//! encapsulating client and server functionality for the Hysteria protocol.
//! Quinn supports ACME automatic certificate management through rustls.

use crate::acme::AcmeManager;
use crate::config::TlsConfig;
use crate::{HysteriaError, Result};
use bytes::Bytes;
use quinn::{
    ClientConfig, Connection, Endpoint, ServerConfig,
    crypto::rustls::QuicClientConfig, crypto::rustls::QuicServerConfig,
    VarInt,
};
use quinn::ClientConfig as QuinnClientConfig;
use quinn::ServerConfig as QuinnServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// QUIC client configuration
#[derive(Debug, Clone)]
pub struct HysteriaQuicClientConfig {
    pub server_name: String,
    pub insecure: bool,
}

/// QUIC server configuration
#[derive(Debug, Clone)]
pub struct HysteriaQuicServerConfig {
    pub bind_addr: SocketAddr,
    pub tls: TlsConfig,
}

/// Hysteria QUIC client wrapper
pub struct HysteriaQuicClient {
    endpoint: Endpoint,
    config: HysteriaQuicClientConfig,
}

/// Hysteria QUIC server wrapper
pub struct HysteriaQuicServer {
    endpoint: Endpoint,
    config: HysteriaQuicServerConfig,
}

/// QUIC stream wrapper
#[derive(Debug)]
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

/// QUIC datagram sender/receiver
#[derive(Debug)]
pub struct QuicDatagrams {
    connection: Connection,
}

impl HysteriaQuicClient {
    /// Create a new QUIC client
    pub async fn new(config: HysteriaQuicClientConfig) -> Result<Self> {
        let client_config = Self::build_client_config(&config)?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| HysteriaError::quic(format!("Failed to create client endpoint: {}", e)))?;
        
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, config })
    }

    /// Connect to a server
    pub async fn connect(&self, server_addr: SocketAddr) -> Result<Connection> {
        self.endpoint
            .connect(server_addr, &self.config.server_name)
            .map_err(|e| HysteriaError::quic(format!("Failed to initiate connection: {}", e)))?
            .await
            .map_err(|e| HysteriaError::quic(format!("Failed to establish connection: {}", e)))
    }

    /// Build client configuration
    fn build_client_config(config: &HysteriaQuicClientConfig) -> Result<QuinnClientConfig> {
        let mut rustls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        if config.insecure {
            // For testing purposes - disable certificate verification
            rustls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(InsecureVerifier));
        }

        let quic_config = QuicClientConfig::try_from(rustls_config)
            .map_err(|e| HysteriaError::quic(format!("Failed to create QUIC client config: {}", e)))?;

        Ok(QuinnClientConfig::new(Arc::new(quic_config)))
    }
}

impl HysteriaQuicServer {
    /// Create a new QUIC server
    pub async fn new(config: HysteriaQuicServerConfig) -> Result<Self> {
        let server_config = Self::build_server_config(&config).await?;
        let endpoint = Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| HysteriaError::quic(format!("Failed to create server endpoint: {}", e)))?;

        info!("QUIC server listening on {}", config.bind_addr);
        Ok(Self { endpoint, config })
    }

    /// Accept incoming connections
    pub async fn accept(&mut self) -> Result<Option<Connection>> {
        match self.endpoint.accept().await {
            Some(connecting) => {
                let connection = connecting.await
                    .map_err(|e| HysteriaError::quic(format!("Failed to accept connection: {}", e)))?;
                Ok(Some(connection))
            }
            None => Ok(None),
        }
    }

    /// Build server configuration with ACME support
    async fn build_server_config(config: &HysteriaQuicServerConfig) -> Result<QuinnServerConfig> {
        let rustls_config = match (&config.tls.cert, &config.tls.key, &config.tls.acme) {
             (Some(cert_path), Some(key_path), None) => {
                 // Manual certificate configuration
                 info!("Using manual certificate configuration");
                 Arc::new(Self::build_manual_server_config(cert_path, key_path).await?)
             }
             (None, None, Some(acme_config)) => {
                 // ACME automatic certificate
                 info!("Using ACME automatic certificate");
                 let mut acme_manager = AcmeManager::new(acme_config.clone())
                     .map_err(|e| HysteriaError::config(format!("Failed to create ACME manager: {}", e)))?;
                 
                 acme_manager.initialize().await
                     .map_err(|e| HysteriaError::config(format!("Failed to initialize ACME: {}", e)))?
             }
             _ => {
                 return Err(HysteriaError::config(
                     "Either manual certificate (cert + key) or ACME configuration must be provided, but not both".to_string()
                 ));
             }
         };

         let quic_config = QuicServerConfig::try_from((*rustls_config).clone())
             .map_err(|e| HysteriaError::quic(format!("Failed to create QUIC server config: {}", e)))?;

        

        let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_config));
        
        // Configure transport parameters
        let transport_config = Arc::get_mut(&mut server_config.transport)
            .ok_or_else(|| HysteriaError::quic("Failed to get mutable transport config".to_string()))?;
        
        transport_config
            .max_concurrent_uni_streams(VarInt::from_u32(100))
            .max_concurrent_bidi_streams(VarInt::from_u32(100))
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .max_idle_timeout(Some(Duration::from_secs(60).try_into().unwrap()));

        Ok(server_config)
    }

    /// Build manual server configuration from certificate files
    async fn build_manual_server_config(
        cert_path: &std::path::PathBuf,
        key_path: &std::path::PathBuf,
    ) -> Result<RustlsServerConfig> {
        let cert_chain = Self::load_cert_chain(cert_path).await?;
        let private_key = Self::load_private_key(key_path).await?;

        RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| HysteriaError::config(format!("Failed to build server config: {}", e)))
    }

    /// Load certificate chain from file
    async fn load_cert_chain(cert_path: &std::path::PathBuf) -> Result<Vec<CertificateDer<'static>>> {
        let cert_data = tokio::fs::read(cert_path).await
            .map_err(|e| HysteriaError::config(format!("Failed to read certificate file: {}", e)))?;
        
        let certs = rustls_pemfile::certs(&mut cert_data.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| HysteriaError::config(format!("Failed to parse certificate: {}", e)))?;
        
        if certs.is_empty() {
            return Err(HysteriaError::config("No certificates found in file".to_string()));
        }
        
        Ok(certs)
    }

    /// Load private key from file
    async fn load_private_key(key_path: &std::path::PathBuf) -> Result<PrivateKeyDer<'static>> {
        let key_data = tokio::fs::read(key_path).await
            .map_err(|e| HysteriaError::config(format!("Failed to read private key file: {}", e)))?;
        
        let keys = rustls_pemfile::private_key(&mut key_data.as_slice())
            .map_err(|e| HysteriaError::config(format!("Failed to parse private key: {}", e)))?;
        
        keys.ok_or_else(|| HysteriaError::config("No private key found in file".to_string()))
    }
}

impl QuicStream {
    /// Create a new QUIC stream wrapper
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    /// Send data on the stream
    pub async fn send(&mut self, data: Bytes) -> Result<()> {
        self.send.write_all(&data).await
            .map_err(|e| HysteriaError::quic(format!("Failed to send data: {}", e)))?;
        Ok(())
    }

    /// Receive data from the stream
    pub async fn receive(&mut self) -> Result<Option<Bytes>> {
        let mut buf = [0u8; 4096];
        match self.recv.read(&mut buf).await {
            Ok(Some(n)) => {
                Ok(Some(Bytes::copy_from_slice(&buf[..n])))
            }
            Ok(None) => Ok(None), // EOF
            Err(e) => Err(HysteriaError::quic(format!("Failed to receive data: {}", e))),
        }
    }

    /// Close the stream
    pub fn close(&mut self) {
        let _ = self.send.finish();
    }
}

/// Insecure certificate verifier for testing
#[derive(Debug)]
struct InsecureVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
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

    fn create_test_client_config() -> HysteriaQuicClientConfig {
        HysteriaQuicClientConfig {
            server_name: "localhost".to_string(),
            insecure: true,
        }
    }

    fn create_test_server_config() -> HysteriaQuicServerConfig {
        HysteriaQuicServerConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            tls: TlsConfig {
                cert: Some(std::path::PathBuf::from("tests/server.crt")),
                key: Some(std::path::PathBuf::from("tests/server.key")),
                cert_chain: None,
                acme: None,
                min_version: None,
                max_version: None,
                cipher_suites: None,
                alpn: Some(vec!["h3".to_string()]),
            },
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
        assert!(config.tls.cert.is_some());
        assert!(config.tls.key.is_some());
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = create_test_client_config();
        let result = HysteriaQuicClient::new(config).await;
        // This might fail without proper certificates, but should not panic
        match result {
            Ok(_) => println!("Client created successfully"),
            Err(e) => println!("Expected error: {}", e),
        }
    }

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.rtt, Duration::from_secs(0));
    }
}