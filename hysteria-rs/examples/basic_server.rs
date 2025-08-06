//! Basic Hysteria server example
//! 
//! This example demonstrates how to create a basic Hysteria server
//! that accepts client connections and handles requests.

use hysteria_core::{
    auth::{AuthRequest, AuthResponse, PasswordAuthHandler, AuthHandler, CongestionControlRate},
    quic::{QuicServerConfig, HysteriaQuicServer},
    protocol::{TcpRequest, TcpResponse},
    udp::UdpSessionManager,
    Result,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create server configuration
    let config = QuicServerConfig {
        bind_addr: "127.0.0.1:8443".parse().unwrap(),
    };

    // Create QUIC server
    let mut server = HysteriaQuicServer::new(config).await?;
    println!("Hysteria server started on 127.0.0.1:8443");

    // Create authentication handler
    let auth_handler = PasswordAuthHandler::new("mypassword".to_string());
    
    // Create UDP session manager
    let mut udp_manager = UdpSessionManager::new();

    // Accept connections
    loop {
        match server.accept().await? {
            Some(connection) => {
                println!("New client connected");
                
                // Handle connection in a separate task
                let auth_handler = auth_handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(connection, auth_handler).await {
                        eprintln!("Connection error: {}", e);
                    }
                });
            }
            None => {
                // No connection available, continue
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(
    connection: s2n_quic::Connection,
    auth_handler: PasswordAuthHandler,
) -> Result<()> {
    // Accept incoming streams
    while let Ok(Some(mut stream)) = connection.accept_bidirectional_stream().await {
        println!("New stream opened");
        
        // Handle authentication
        if let Some(auth_data) = stream.receive().await? {
            let auth_request: AuthRequest = serde_json::from_slice(&auth_data)
                .map_err(|e| hysteria_core::error::HysteriaError::auth(format!("Invalid auth request: {}", e)))?;
            
            println!("Received auth request: {}", auth_request.auth);
            
            // Validate authentication
            let auth_result = auth_handler.authenticate(&auth_request).await?;
            
            let auth_response = if auth_result {
                AuthResponse {
                    ok: true,
                    message: Some("Authentication successful".to_string()),
                    rx: Some(CongestionControlRate::Value(2000000)), // 2 Mbps download
                }
            } else {
                AuthResponse {
                    ok: false,
                    message: Some("Authentication failed".to_string()),
                    rx: None,
                }
            };
            
            // Send authentication response
            let response_data = serde_json::to_vec(&auth_response)
                .map_err(|e| hysteria_core::error::HysteriaError::auth(format!("Auth response serialization failed: {}", e)))?;
            
            stream.send(response_data.into()).await
                .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to send auth response: {}", e)))?;
            
            if !auth_result {
                println!("Authentication failed, closing connection");
                return Ok(());
            }
            
            println!("Client authenticated successfully");
        }
        
        // Handle TCP requests
        if let Some(request_data) = stream.receive().await? {
            let tcp_request = TcpRequest::decode(request_data)?;
            println!("Received TCP request: {}:{}", tcp_request.host, tcp_request.port);
            
            // Connect to target server
            match TcpStream::connect(format!("{}:{}", tcp_request.host, tcp_request.port)).await {
                Ok(mut target_stream) => {
                    println!("Connected to target: {}:{}", tcp_request.host, tcp_request.port);
                    
                    // Send success response
                    let tcp_response = TcpResponse {
                        ok: true,
                        message: Some("Connection established".to_string()),
                    };
                    
                    let response_data = tcp_response.encode()?;
                    stream.send(response_data).await
                        .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to send TCP response: {}", e)))?;
                    
                    // Relay data between client and target
                    tokio::spawn(async move {
                        let mut client_buf = [0u8; 4096];
                        let mut target_buf = [0u8; 4096];
                        
                        loop {
                            tokio::select! {
                                // Client to target
                                result = stream.receive() => {
                                    match result {
                                        Ok(Some(data)) => {
                                            if let Err(e) = target_stream.write_all(&data).await {
                                                eprintln!("Failed to write to target: {}", e);
                                                break;
                                            }
                                        }
                                        Ok(None) => break, // Stream closed
                                        Err(e) => {
                                            eprintln!("Failed to read from client: {}", e);
                                            break;
                                        }
                                    }
                                }
                                // Target to client
                                result = target_stream.read(&mut target_buf) => {
                                    match result {
                                        Ok(0) => break, // EOF
                                        Ok(n) => {
                                            if let Err(e) = stream.send(target_buf[..n].into()).await {
                                                eprintln!("Failed to send to client: {}", e);
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to read from target: {}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        
                        println!("Relay finished");
                    });
                }
                Err(e) => {
                    println!("Failed to connect to target: {}", e);
                    
                    // Send error response
                    let tcp_response = TcpResponse {
                        ok: false,
                        message: Some(format!("Connection failed: {}", e)),
                    };
                    
                    let response_data = tcp_response.encode()?;
                    stream.send(response_data).await
                        .map_err(|e| hysteria_core::error::HysteriaError::quic(format!("Failed to send TCP response: {}", e)))?;
                }
            }
        }
    }
    
    println!("Connection closed");
    Ok(())
}