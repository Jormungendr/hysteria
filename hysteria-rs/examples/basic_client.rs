//! Basic Hysteria client example
//! 
//! This example demonstrates how to create a basic Hysteria client
//! and connect to a server.

use hysteria_core::{
    auth::{AuthRequest, PasswordAuthHandler},
    quic::{QuicClientConfig, HysteriaQuicClient},
    protocol::TcpRequest,
    Result,
};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create client configuration
    let config = QuicClientConfig {
        server_name: "localhost".to_string(),
        insecure: true, // For testing only
    };

    // Create QUIC client
    let client = HysteriaQuicClient::new(config).await?;
    println!("Hysteria client created successfully");

    // Connect to server
    let server_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    let connection = client.connect(server_addr).await?;
    println!("Connected to server at {}", server_addr);

    // Open a bidirectional stream
    let mut stream = connection.open_bidirectional_stream().await
        .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to open stream: {}", e)))?;
    
    // Create authentication request
    let auth_request = AuthRequest {
        auth: "password:mypassword".to_string(),
        tx: Some(1000000), // 1 Mbps upload
    };

    // Send authentication
    let auth_data = serde_json::to_vec(&auth_request)
        .map_err(|e| hysteria_core::error::HysteriaError::generic(format!("Auth serialization failed: {}", e)))?;
    
    stream.send(auth_data.into()).await
        .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to send auth: {}", e)))?;

    println!("Authentication sent");

    // Create TCP request to connect to a target
    let tcp_request = TcpRequest {
        host: "httpbin.org".to_string(),
        port: 80,
    };

    // Send TCP request
    let request_data = tcp_request.encode()?;
    stream.send(request_data).await
        .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to send request: {}", e)))?;

    println!("TCP request sent to httpbin.org:80");

    // Send HTTP request
    let http_request = b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
    stream.send(http_request.as_slice().into()).await
        .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to send HTTP request: {}", e)))?;

    println!("HTTP request sent");

    // Read response
    if let Some(response_data) = stream.receive().await? {
        let response = String::from_utf8_lossy(&response_data);
        println!("Received response: {}", response);
    }

    println!("Client example completed successfully");
    Ok(())
}