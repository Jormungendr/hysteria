use anyhow::{Result, anyhow};
use hysteria_core::{
    config::{ServerConfig as CoreServerConfig, AuthConfig as CoreAuthConfig, AuthType, TlsConfig, AcmeConfig},
    acme::AcmeManager,
};
use hysteria_extras::{Authenticator, PasswordAuthenticator, SalamanderObfuscator, AclEngine};
use tokio::signal;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, error};

use crate::config::{ServerConfig, load_server_config};

pub async fn run(config_path: String) -> Result<()> {
    info!("Loading server configuration from: {}", config_path);
    
    let config = load_server_config(&config_path)
        .map_err(|e| anyhow!("Failed to load server config: {}", e))?;
    
    info!("Starting Hysteria server...");
    
    // Initialize authenticator if auth is configured
    let _authenticator: Option<Arc<dyn Authenticator>> = config.auth.as_ref().map(|auth_config| {
        if auth_config.r#type == "password" {
            Arc::new(PasswordAuthenticator::new(
                auth_config.password.clone().unwrap_or_default()
            )) as Arc<dyn Authenticator>
        } else {
            Arc::new(PasswordAuthenticator::new(String::new())) as Arc<dyn Authenticator>
        }
    });
    
    // Initialize obfuscator if configured
    let _obfuscator: Option<SalamanderObfuscator> = if let Some(obfs_config) = &config.obfs {
        if let Some(salamander_config) = &obfs_config.salamander {
            match SalamanderObfuscator::new(salamander_config.password.as_bytes().to_vec()) {
                Ok(obfs) => Some(obfs),
                Err(e) => {
                    error!("Failed to create obfuscator: {}", e);
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };
    
    // Initialize ACL engine if configured
    let _acl_engine: Option<AclEngine> = None; // TODO: Initialize based on config
    
    // Convert CLI config to core config
    let _core_config = convert_to_core_config(config)?;
    
    // Create QUIC server using hysteria_core
    let quic_config = hysteria_core::quic::HysteriaQuicServerConfig {
        bind_addr: _core_config.listen,
        tls: _core_config.tls.clone(),
    };
    
    let mut quic_server = match hysteria_core::quic::HysteriaQuicServer::new(quic_config).await {
        Ok(server) => server,
        Err(e) => {
            error!("Failed to create QUIC server: {}", e);
            return Err(anyhow!("Failed to create QUIC server: {}", e));
        }
    };
    
    info!("QUIC server listening on: {}", _core_config.listen);
    
    // Create authentication handler
    let auth_handler = if let Some(auth_config) = &_core_config.auth {
        match auth_config.auth_type {
            hysteria_core::config::AuthType::Password => {
                Some(Arc::new(hysteria_core::auth::PasswordAuthHandler::new(
                    auth_config.password.clone().unwrap_or_default(),
                    true, // UDP enabled
                    hysteria_core::auth::CongestionControlRate::Rate(0), // Unlimited
                )) as Arc<dyn hysteria_core::auth::AuthHandler>)
            }
            _ => {
                error!("Unsupported auth type: {:?}", auth_config.auth_type);
                None
            }
        }
    } else {
        None
    };
    
    // Start the server loop
    let server_handle = tokio::spawn(async move {
        info!("Hysteria server started, accepting connections...");
        
        loop {
            match quic_server.accept().await {
                Ok(Some(connection)) => {
                    info!("New client connection accepted");
                    
                    // Handle each connection in a separate task
                    let auth_handler_clone = auth_handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client_connection(auth_handler_clone).await {
                            error!("Connection handling error: {}", e);
                        }
                    });
                }
                Ok(None) => {
                    // No connection available, continue
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
    
    info!("Server started successfully");
    info!("Press Ctrl+C to stop...");
    
    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
        result = server_handle => {
            match result {
                Ok(_) => info!("Server stopped"),
                Err(e) => error!("Server task error: {}", e),
            }
        }
    }
    
    info!("Server shutdown complete");
    Ok(())
}

fn convert_to_core_config(config: ServerConfig) -> Result<CoreServerConfig> {
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
    
    // Check if ACME is configured
    let acme_config = if let Some(acme) = &config.acme {
        Some(AcmeConfig {
            domains: acme.domains.clone(),
            email: acme.email.clone(),
            directory_url: acme.directory_url.clone(),
            challenge_type: hysteria_core::config::AcmeChallengeType::TlsAlpn01,
            http_challenge: None,
            tls_alpn_challenge: None,
            dns_challenge: None,
            cache_dir: acme.cache_dir.clone(),
            staging: acme.staging,
        })
    } else {
        None
    };

    // Validate configuration: either ACME or cert/key must be provided
    if acme_config.is_none() && (config.cert.is_none() || config.key.is_none()) {
        return Err(anyhow::anyhow!("Either ACME configuration or both cert and key files must be provided"));
    }

    let tls_config = TlsConfig {
        cert: if acme_config.is_some() { 
            None 
        } else { 
            config.cert.as_ref().map(|c| PathBuf::from(c)) 
        },
        key: if acme_config.is_some() { 
            None 
        } else { 
            config.key.as_ref().map(|k| PathBuf::from(k)) 
        },
        cert_chain: None,
        acme: acme_config,
        min_version: None,
        max_version: None,
        cipher_suites: None,
        alpn: None,
    };
    
    let listen_addr = config.listen.parse()
        .map_err(|e| anyhow!("Invalid listen address: {}", e))?;
    
    let bandwidth_config = config.bandwidth.map(|b| hysteria_core::config::BandwidthConfig {
        up: parse_bandwidth(b.up.as_ref()).ok(),
        down: parse_bandwidth(b.down.as_ref()).ok(),
        cc: None,
        measurement_window: None,
        auto: None,
    });
    
    let masquerade_config = config.masquerade.map(|m| hysteria_core::config::MasqueradeConfig {
        masq_type: match m.r#type.as_str() {
            "http" => hysteria_core::config::MasqueradeType::Http,
            "https" => hysteria_core::config::MasqueradeType::Https,
            "file" => hysteria_core::config::MasqueradeType::File,
            "proxy" => hysteria_core::config::MasqueradeType::Proxy,
            _ => hysteria_core::config::MasqueradeType::Http,
        },
        target: m.proxy.map(|p| p.url).or(m.file.map(|f| f.dir)).unwrap_or_default(),
        params: None,
    });
    
    let obfs_config = config.obfs.map(|o| hysteria_core::config::ObfsConfig {
        obfs_type: hysteria_core::config::ObfsType::Salamander,
        password: o.salamander.map(|s| s.password),
        params: None,
    });
    
    // ACL configuration would be handled by hysteria_extras::AclEngine
    // but we don't add it to CoreServerConfig as it's handled separately
    
    Ok(CoreServerConfig {
        listen: listen_addr,
        tls: tls_config,
        auth: auth_config,
        bandwidth: bandwidth_config,
        obfs: obfs_config,
        hooks: None,
        logging: None,
        masquerade: masquerade_config,
        outbound: None,
        udp: None,
        limits: None,
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

async fn handle_client_connection(
    auth_handler: Option<Arc<dyn hysteria_core::auth::AuthHandler>>,
) -> Result<()> {
    info!("Handling new client connection");
    
    // For now, implement a basic connection handler
    // TODO: Implement full Hysteria protocol handling
    // This would involve:
    // 1. Accepting bidirectional streams from the QUIC connection
    // 2. Handling authentication using the auth_handler
    // 3. Processing TCP/UDP requests according to Hysteria protocol
    // 4. Relaying data between client and target servers
    
    // Simulate handling the connection
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    info!("Client connection handled (basic implementation)");
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