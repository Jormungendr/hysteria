use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server: ServerEndpoint,
    pub auth: Option<AuthConfig>,
    pub bandwidth: Option<BandwidthConfig>,
    pub socks5: Option<Socks5Config>,
    pub http: Option<HttpConfig>,
    pub tun: Option<TunConfig>,
    pub obfs: Option<ObfsConfig>,
    pub quic: Option<QuicConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub auth: Option<AuthConfig>,
    pub bandwidth: Option<BandwidthConfig>,
    pub masquerade: Option<MasqueradeConfig>,
    pub obfs: Option<ObfsConfig>,
    pub quic: Option<QuicConfig>,
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerEndpoint {
    pub addr: String,
    pub port: u16,
    pub sni: Option<String>,
    pub insecure: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub r#type: String,
    pub password: Option<String>,
    pub userpass: Option<Vec<UserPass>>,
    pub http: Option<HttpAuthConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpAuthConfig {
    pub url: String,
    pub insecure: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BandwidthConfig {
    pub up: Option<String>,
    pub down: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Socks5Config {
    pub listen: String,
    pub disable_udp: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpConfig {
    pub listen: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunConfig {
    pub name: String,
    pub mtu: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ObfsConfig {
    pub r#type: String,
    pub salamander: Option<SalamanderConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SalamanderConfig {
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuicConfig {
    pub init_stream_receive_window: Option<u32>,
    pub max_stream_receive_window: Option<u32>,
    pub init_conn_receive_window: Option<u32>,
    pub max_conn_receive_window: Option<u32>,
    pub max_idle_timeout: Option<String>,
    pub max_incoming_streams: Option<u32>,
    pub disable_path_mtu_discovery: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub email: String,
    pub directory_url: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub staging: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MasqueradeConfig {
    pub r#type: String,
    pub file: Option<FileServerConfig>,
    pub proxy: Option<ProxyConfig>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileServerConfig {
    pub dir: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub url: String,
    pub rewrite_host: Option<bool>,
}

pub async fn generate_config(output: &str, config_type: &str) -> Result<()> {
    let content = match config_type {
        "client" => generate_client_config(),
        "server" => generate_server_config(),
        _ => return Err(anyhow!("Invalid config type. Use 'client' or 'server'")),
    };
    
    fs::write(output, content)?;
    info!("Configuration generated successfully: {}", output);
    Ok(())
}

fn generate_client_config() -> String {
    let config = ClientConfig {
        server: ServerEndpoint {
            addr: "example.com".to_string(),
            port: 443,
            sni: Some("example.com".to_string()),
            insecure: Some(false),
        },
        auth: Some(AuthConfig {
            r#type: "password".to_string(),
            password: Some("your_password_here".to_string()),
            userpass: None,
            http: None,
        }),
        bandwidth: Some(BandwidthConfig {
            up: Some("100 Mbps".to_string()),
            down: Some("100 Mbps".to_string()),
        }),
        socks5: Some(Socks5Config {
            listen: "127.0.0.1:1080".to_string(),
            disable_udp: Some(false),
        }),
        http: Some(HttpConfig {
            listen: "127.0.0.1:8080".to_string(),
        }),
        tun: None,
        obfs: None,
        quic: None,
    };
    
    serde_yaml::to_string(&config).unwrap_or_else(|_| "# Error generating config".to_string())
}

fn generate_server_config() -> String {
    let config = ServerConfig {
        listen: ":443".to_string(),
        cert: Some("/path/to/cert.pem".to_string()),
        key: Some("/path/to/key.pem".to_string()),
        auth: Some(AuthConfig {
            r#type: "password".to_string(),
            password: Some("your_password_here".to_string()),
            userpass: None,
            http: None,
        }),
        bandwidth: Some(BandwidthConfig {
            up: Some("1 Gbps".to_string()),
            down: Some("1 Gbps".to_string()),
        }),
        masquerade: Some(MasqueradeConfig {
            r#type: "proxy".to_string(),
            file: None,
            proxy: Some(ProxyConfig {
                url: "https://example.com".to_string(),
                rewrite_host: Some(true),
            }),
        }),
        obfs: None,
        quic: None,
        acme: None,
    };
    
    serde_yaml::to_string(&config).unwrap_or_else(|_| "# Error generating config".to_string())
}

pub fn load_client_config<P: AsRef<Path>>(path: P) -> Result<ClientConfig> {
    let content = fs::read_to_string(path)?;
    let config: ClientConfig = serde_yaml::from_str(&content)?;
    Ok(config)
}

pub fn load_server_config<P: AsRef<Path>>(path: P) -> Result<ServerConfig> {
    let content = fs::read_to_string(path)?;
    let config: ServerConfig = serde_yaml::from_str(&content)?;
    Ok(config)
}