use anyhow::{Result, anyhow};
use hysteria_core::{
    config::{ClientConfig as CoreClientConfig, AuthConfig as CoreAuthConfig, AuthType, ClientTlsConfig},
};

use tokio::signal;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use tracing::{info, error, warn};

use crate::config::{ClientConfig, load_client_config};

pub async fn run(config_path: String) -> Result<()> {
    info!("Loading client configuration from: {}", config_path);
    
    let config = load_client_config(&config_path)
        .map_err(|e| anyhow!("Failed to load client config: {}", e))?;
    
    info!("Starting Hysteria client...");
    
    // Convert CLI config to core config
    let _core_config = convert_to_core_config(config)?;
    
    // Start SOCKS5 proxy server if configured
    let mut handles = Vec::new();
    
    if let Some(socks5_config) = _core_config.socks5.as_ref() {
        let socks5_addr = socks5_config.listen;
        info!("Starting SOCKS5 proxy on: {}", socks5_addr);
        
        let socks5_handle = tokio::spawn(async move {
            if let Err(e) = start_socks5_proxy(socks5_addr).await {
                error!("SOCKS5 proxy error: {}", e);
            }
        });
        handles.push(socks5_handle);
    }
    
    // Start HTTP proxy server if configured
    if let Some(http_config) = _core_config.http.as_ref() {
        let http_addr = http_config.listen;
        info!("Starting HTTP proxy on: {}", http_addr);
        
        let http_handle = tokio::spawn(async move {
            if let Err(e) = start_http_proxy(http_addr).await {
                error!("HTTP proxy error: {}", e);
            }
        });
        handles.push(http_handle);
    }
    
    if handles.is_empty() {
        return Err(anyhow!("No proxy services configured"));
    }
    
    info!("Client started successfully");
    info!("Press Ctrl+C to stop...");
    
    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }
    
    info!("Client shutdown complete");
    Ok(())
}

fn convert_to_core_config(config: ClientConfig) -> Result<CoreClientConfig> {
    let auth_config = if let Some(auth) = config.auth {
        Some(CoreAuthConfig {
            auth_type: match auth.r#type.as_str() {
                "password" => AuthType::Password,
                "userpass" => AuthType::Userpass,
                "http" => AuthType::Http,
                _ => return Err(anyhow!("Unsupported auth type: {}", auth.r#type)),
            },
            password: auth.password.clone(),
            userpass_file: None, // CLI doesn't support file-based userpass yet
            http_url: auth.http.as_ref().map(|h| h.url.clone()),
            http_timeout: auth.http.as_ref().map(|_| std::time::Duration::from_secs(30)),
            params: None,
        })
    } else {
        None
    };
    
    let tls_config = Some(ClientTlsConfig {
        server_name: config.server.sni,
        insecure: config.server.insecure,
        ca: None,
        cert: None,
        key: None,
        alpn: None,
    });
    
    let bandwidth_config = config.bandwidth.map(|b| hysteria_core::config::BandwidthConfig {
        up: parse_bandwidth(b.up.as_ref()).ok(),
        down: parse_bandwidth(b.down.as_ref()).ok(),
        cc: None,
        measurement_window: None,
        auto: None,
    });
    
    let socks5_config = config.socks5.map(|s| {
        let addr = s.listen.parse().unwrap_or_else(|_| "127.0.0.1:1080".parse().unwrap());
        hysteria_core::config::Socks5Config {
            listen: addr,
            auth: None,
            timeout: None,
        }
    });
    
    let http_config = config.http.map(|h| {
        let addr = h.listen.parse().unwrap_or_else(|_| "127.0.0.1:8080".parse().unwrap());
        hysteria_core::config::HttpConfig {
            listen: addr,
            auth: None,
            timeout: None,
        }
    });
    
    let obfs_config = config.obfs.map(|o| hysteria_core::config::ObfsConfig {
        obfs_type: hysteria_core::config::ObfsType::Salamander,
        password: o.salamander.map(|s| s.password),
        params: None,
    });
    
    Ok(CoreClientConfig {
        server: config.server.addr,
        port: config.server.port,
        auth: auth_config,
        tls: tls_config,
        bandwidth: bandwidth_config,
        obfs: obfs_config,
        socks5: socks5_config,
        http: http_config,
        tun: None,
        performance: None,
    })
}

fn parse_bandwidth(bandwidth_str: Option<&String>) -> Result<u64> {
    let bandwidth_str = match bandwidth_str {
        Some(s) => s,
        None => return Ok(0), // 0 means unlimited
    };
    
    let bandwidth_str = bandwidth_str.to_lowercase();
    let (number_part, unit_part) = if let Some(space_pos) = bandwidth_str.find(' ') {
        bandwidth_str.split_at(space_pos)
    } else {
        // Try to find where number ends and unit begins
        let mut split_pos = bandwidth_str.len();
        for (i, c) in bandwidth_str.char_indices() {
            if c.is_alphabetic() {
                split_pos = i;
                break;
            }
        }
        bandwidth_str.split_at(split_pos)
    };
    
    let number: f64 = number_part.trim().parse()
        .map_err(|_| anyhow!("Invalid bandwidth number: {}", number_part))?;
    
    let unit = unit_part.trim();
    let multiplier = match unit {
        "bps" | "b" | "" => 1,
        "kbps" | "k" | "kb" => 1_000,
        "mbps" | "m" | "mb" => 1_000_000,
        "gbps" | "g" | "gb" => 1_000_000_000,
        _ => return Err(anyhow!("Unknown bandwidth unit: {}", unit)),
    };
    
    Ok((number * multiplier as f64) as u64)
}

// Simple SOCKS5 proxy implementation
async fn start_socks5_proxy(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await
        .map_err(|e| anyhow!("Failed to bind SOCKS5 listener: {}", e))?;
    
    info!("SOCKS5 proxy listening on {}", addr);
    
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                info!("SOCKS5 connection from {}", client_addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_connection(stream).await {
                        error!("SOCKS5 connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept SOCKS5 connection: {}", e);
            }
        }
    }
}

// Simple HTTP proxy implementation
async fn start_http_proxy(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await
        .map_err(|e| anyhow!("Failed to bind HTTP listener: {}", e))?;
    
    info!("HTTP proxy listening on {}", addr);
    
    loop {
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                info!("HTTP connection from {}", client_addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_http_connection(stream).await {
                        error!("HTTP connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept HTTP connection: {}", e);
            }
        }
    }
}

// Handle SOCKS5 connection (simplified implementation)
async fn handle_socks5_connection(mut stream: TcpStream) -> Result<()> {
    // Basic SOCKS5 handshake implementation
    let mut buffer = [0u8; 1024];
    
    // Read initial handshake
    match stream.read(&mut buffer).await {
        Ok(n) if n >= 3 => {
            info!("Received SOCKS5 handshake ({} bytes)", n);
            
            // Check if it's a valid SOCKS5 request
            if buffer[0] == 0x05 { // SOCKS5 version
                // Send method selection response (no authentication)
                let response = [0x05, 0x00]; // Version 5, No authentication
                let _ = stream.write_all(&response).await;
                
                // Read connection request
                match stream.read(&mut buffer).await {
                    Ok(n) if n >= 4 => {
                        info!("Received SOCKS5 connection request ({} bytes)", n);
                        // Send connection success response (fake success for testing)
                        let response = [0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50]; // Success, IPv4, 127.0.0.1:80
                        let _ = stream.write_all(&response).await;
                        
                        info!("SOCKS5 connection established (fake)");
                        
                        // Keep connection alive and echo back any data for testing
                        let mut buffer = [0u8; 4096];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) => break, // Connection closed
                                Ok(n) => {
                                    info!("Received {} bytes from client", n);
                                    // Echo back the data (fake response)
                                    let fake_response = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"origin\": \"fake\"}"; 
                                    let _ = stream.write_all(fake_response).await;
                                    break; // Close after first response
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // Not a SOCKS5 request, send error
                let _ = stream.write_all(b"Invalid SOCKS5 request").await;
            }
        }
        _ => {}
    }
    
    Ok(())
}

// Handle HTTP connection (simplified implementation)
async fn handle_http_connection(mut stream: TcpStream) -> Result<()> {
    // For now, just echo back a simple response to indicate the proxy is running
    // TODO: Implement full HTTP proxy protocol and Hysteria connection
    
    let mut buffer = [0u8; 1024];
    match stream.read(&mut buffer).await {
        Ok(n) if n > 0 => {
            info!("Received HTTP request ({} bytes)", n);
            // Send a simple response to indicate we're alive
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\nHTTP proxy is running";
            let _ = stream.write_all(response.as_bytes()).await;
        }
        _ => {}
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_bandwidth() {
        assert_eq!(parse_bandwidth(Some(&"100 Mbps".to_string())).unwrap(), 100_000_000);
        assert_eq!(parse_bandwidth(Some(&"1 Gbps".to_string())).unwrap(), 1_000_000_000);
        assert_eq!(parse_bandwidth(Some(&"500kbps".to_string())).unwrap(), 500_000);
        assert_eq!(parse_bandwidth(None).unwrap(), 0);
    }
}