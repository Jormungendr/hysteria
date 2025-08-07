//! Advanced Hysteria client example
//!
//! This example demonstrates the usage of advanced client features including:
//! - Comprehensive client configuration
//! - Connection management and monitoring
//! - Performance optimization
//! - Error handling and retry logic
//! - Statistics and logging

use hysteria_core::{
    config::*,
    logger::*,
    outbound::*,
    quic::*,
    HysteriaError, Result,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// Advanced client implementation
struct AdvancedHysteriaClient {
    config: ClientConfig,
    quic_client: HysteriaQuicClient,
    event_logger: Arc<dyn EventLogger>,
    traffic_logger: Arc<dyn TrafficLogger>,
    stats: Arc<RwLock<ClientStats>>,
    connection_pool: Arc<RwLock<ConnectionPool>>,
}

/// Client statistics
#[derive(Debug, Clone, Default)]
struct ClientStats {
    total_connections: u64,
    active_connections: u64,
    successful_connections: u64,
    failed_connections: u64,
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    total_bytes_tx: u64,
    total_bytes_rx: u64,
    average_latency_ms: f64,
    connection_errors: u64,
    auth_failures: u64,
}

/// Connection pool for managing QUIC connections
#[derive(Debug, Default)]
struct ConnectionPool {
    connections: HashMap<String, PooledConnection>,
    max_connections: usize,
    max_idle_time: Duration,
}

/// Pooled connection wrapper
#[derive(Debug, Clone)]
struct PooledConnection {
    connection: QuicConnection,
    last_used: Instant,
    in_use: bool,
}

impl ConnectionPool {
    fn new(max_connections: usize, max_idle_time: Duration) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections,
            max_idle_time,
        }
    }
    
    fn get_connection(&mut self, server_addr: &str) -> Option<QuicConnection> {
        if let Some(pooled) = self.connections.get_mut(server_addr) {
            if !pooled.in_use && pooled.last_used.elapsed() < self.max_idle_time {
                pooled.in_use = true;
                pooled.last_used = Instant::now();
                return Some(pooled.connection.clone());
            }
        }
        None
    }
    
    fn return_connection(&mut self, server_addr: String, connection: QuicConnection) {
        if self.connections.len() < self.max_connections {
            let pooled = PooledConnection {
                connection,
                last_used: Instant::now(),
                in_use: false,
            };
            self.connections.insert(server_addr, pooled);
        }
    }
    
    fn cleanup_idle_connections(&mut self) {
        let now = Instant::now();
        self.connections.retain(|_, pooled| {
            !pooled.in_use && now.duration_since(pooled.last_used) < self.max_idle_time
        });
    }
}

impl AdvancedHysteriaClient {
    /// Create a new advanced client
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Validate configuration
        config.validate()?;
        
        // Create QUIC client configuration
        let quic_config = QuicClientConfig {
            server_name: config.server.clone(),
            insecure: config.tls.as_ref().map(|t| t.insecure).unwrap_or(false),
        };
        
        // Create QUIC client
        let quic_client = HysteriaQuicClient::new(quic_config).await?;
        
        // Create event logger
        let event_logger: Arc<dyn EventLogger> = if let Some(logging_config) = &config.logging {
            if let Some(event_config) = &logging_config.events {
                if event_config.enabled {
                    if let Some(file_path) = &event_config.file {
                        Arc::new(FileEventLogger::new(
                            file_path.to_string_lossy().to_string(),
                            event_config.buffer_size.unwrap_or(1000),
                        ))
                    } else {
                        Arc::new(MemoryEventLogger::new(
                            event_config.buffer_size.unwrap_or(1000)
                        ))
                    }
                } else {
                    Arc::new(MemoryEventLogger::new(100))
                }
            } else {
                Arc::new(MemoryEventLogger::new(100))
            }
        } else {
            Arc::new(MemoryEventLogger::new(100))
        };
        
        // Create traffic logger
        let traffic_logger: Arc<dyn TrafficLogger> = if let Some(logging_config) = &config.logging {
            if let Some(traffic_config) = &logging_config.traffic {
                if traffic_config.enabled {
                    Arc::new(MemoryTrafficLogger::new(
                        traffic_config.buffer_size.unwrap_or(1000)
                    ))
                } else {
                    Arc::new(MemoryTrafficLogger::new(100))
                }
            } else {
                Arc::new(MemoryTrafficLogger::new(100))
            }
        } else {
            Arc::new(MemoryTrafficLogger::new(100))
        };
        
        // Create connection pool
        let pool_config = config.performance.as_ref();
        let max_connections = pool_config
            .and_then(|p| p.worker_threads)
            .map(|t| t as usize * 10)
            .unwrap_or(50);
        let max_idle_time = Duration::from_secs(300); // 5 minutes
        
        let connection_pool = Arc::new(RwLock::new(
            ConnectionPool::new(max_connections, max_idle_time)
        ));
        
        Ok(Self {
            config,
            quic_client,
            event_logger,
            traffic_logger,
            stats: Arc::new(RwLock::new(ClientStats::default())),
            connection_pool,
        })
    }
    
    /// Connect to the server with retry logic
    pub async fn connect_with_retry(&self, max_retries: u32) -> Result<QuicConnection> {
        let mut last_error = None;
        
        for attempt in 0..=max_retries {
            // Log connection attempt
            let attempt_event = EventLogEntry::new(
                EventType::Connect,
                EventLevel::Info,
                format!("Connection attempt {} to {}", attempt + 1, self.config.server),
            );
            self.event_logger.log_event(attempt_event).await?;
            
            match self.connect_to_server().await {
                Ok(connection) => {
                    // Update statistics
                    {
                        let mut stats = self.stats.write().await;
                        stats.total_connections += 1;
                        stats.successful_connections += 1;
                        stats.active_connections += 1;
                    }
                    
                    // Log successful connection
                    let success_event = EventLogEntry::new(
                        EventType::Connect,
                        EventLevel::Info,
                        format!("Successfully connected to {} on attempt {}", self.config.server, attempt + 1),
                    );
                    self.event_logger.log_event(success_event).await?;
                    
                    return Ok(connection);
                }
                Err(e) => {
                    last_error = Some(e.clone());
                    
                    // Update statistics
                    {
                        let mut stats = self.stats.write().await;
                        stats.total_connections += 1;
                        stats.failed_connections += 1;
                        stats.connection_errors += 1;
                    }
                    
                    // Log connection failure
                    let failure_event = EventLogEntry::new(
                        EventType::Connect,
                        EventLevel::Warn,
                        format!("Connection attempt {} failed: {}", attempt + 1, e),
                    );
                    self.event_logger.log_event(failure_event).await?;
                    
                    if attempt < max_retries {
                        // Exponential backoff
                        let delay = Duration::from_millis(100 * (1 << attempt));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| {
            HysteriaError::generic("All connection attempts failed".to_string())
        }))
    }
    
    /// Connect to the server
    async fn connect_to_server(&self) -> Result<QuicConnection> {
        // Check connection pool first
        {
            let mut pool = self.connection_pool.write().await;
            if let Some(connection) = pool.get_connection(&self.config.server) {
                return Ok(connection);
            }
        }
        
        // Create new connection
        let server_addr: SocketAddr = self.config.server.parse()
            .map_err(|e| HysteriaError::generic(format!("Invalid server address: {}", e)))?;
        
        let connection = self.quic_client.connect(server_addr).await?;
        
        // Perform authentication if configured
        if let Some(auth_config) = &self.config.auth {
            self.authenticate(&connection, auth_config).await?;
        }
        
        Ok(connection)
    }
    
    /// Perform authentication
    async fn authenticate(&self, _connection: &QuicConnection, auth_config: &AuthConfig) -> Result<()> {
        match auth_config.auth_type {
            AuthType::None => Ok(()),
            AuthType::Password => {
                if let Some(_password) = &auth_config.password {
                    // Simplified authentication - in real implementation,
                    // this would involve HTTP/3 request to the server
                    println!("Authenticating with password...");
                    
                    // Simulate authentication delay
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    
                    // Log authentication success
                    let auth_event = EventLogEntry::new(
                        EventType::Auth,
                        EventLevel::Info,
                        "Authentication successful".to_string(),
                    );
                    self.event_logger.log_event(auth_event).await?;
                    
                    Ok(())
                } else {
                    Err(HysteriaError::auth("Password not configured".to_string()))
                }
            }
            _ => Err(HysteriaError::auth("Authentication type not implemented".to_string())),
        }
    }
    
    /// Create a TCP proxy request
    pub async fn tcp_request(&self, target: &str) -> Result<QuicStream> {
        let start_time = Instant::now();
        
        // Get connection
        let connection = self.connect_with_retry(3).await?;
        
        // Create stream
        let mut stream = connection.open_stream().await?;
        
        // Send request
        let request = format!("CONNECT {} HTTP/1.1\r\n\r\n", target);
        stream.write_all(request.as_bytes()).await
            .map_err(|e| HysteriaError::io(e))?;
        
        // Read response
        let mut buffer = vec![0u8; 1024];
        let n = stream.read(&mut buffer).await
            .map_err(|e| HysteriaError::io(e))?;
        
        let response = String::from_utf8_lossy(&buffer[..n]);
        if !response.starts_with("HTTP/1.1 200") {
            return Err(HysteriaError::generic(format!("Request failed: {}", response)));
        }
        
        let latency = start_time.elapsed();
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
            stats.successful_requests += 1;
            
            // Update average latency
            let total_requests = stats.successful_requests as f64;
            stats.average_latency_ms = (stats.average_latency_ms * (total_requests - 1.0) + latency.as_millis() as f64) / total_requests;
        }
        
        // Log request
        let request_event = EventLogEntry::new(
            EventType::TcpRequest,
            EventLevel::Info,
            format!("TCP request to {} completed in {}ms", target, latency.as_millis()),
        ).with_target_addr(target.to_string());
        self.event_logger.log_event(request_event).await?;
        
        Ok(stream)
    }
    
    /// Start a local SOCKS5 proxy server
    pub async fn start_socks5_proxy(&self, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await
            .map_err(|e| HysteriaError::io(e))?;
        
        println!("SOCKS5 proxy listening on {}", bind_addr);
        
        // Log proxy start
        let start_event = EventLogEntry::new(
            EventType::Connect,
            EventLevel::Info,
            format!("SOCKS5 proxy started on {}", bind_addr),
        );
        self.event_logger.log_event(start_event).await?;
        
        loop {
            match listener.accept().await {
                Ok((client_stream, client_addr)) => {
                    let client = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = client.handle_socks5_client(client_stream, client_addr).await {
                            eprintln!("SOCKS5 client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Accept error: {}", e);
                    
                    // Log error
                    let error_event = EventLogEntry::new(
                        EventType::Error,
                        EventLevel::Error,
                        format!("SOCKS5 accept error: {}", e),
                    );
                    let _ = self.event_logger.log_event(error_event).await;
                }
            }
        }
    }
    
    /// Handle SOCKS5 client connection
    async fn handle_socks5_client(&self, mut client_stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        let start_time = Instant::now();
        
        // Simplified SOCKS5 handshake
        let mut buffer = vec![0u8; 1024];
        let n = client_stream.read(&mut buffer).await
            .map_err(|e| HysteriaError::io(e))?;
        
        if n < 3 || buffer[0] != 0x05 {
            return Err(HysteriaError::generic("Invalid SOCKS5 request".to_string()));
        }
        
        // Send auth method response (no auth)
        client_stream.write_all(&[0x05, 0x00]).await
            .map_err(|e| HysteriaError::io(e))?;
        
        // Read connect request
        let n = client_stream.read(&mut buffer).await
            .map_err(|e| HysteriaError::io(e))?;
        
        if n < 10 || buffer[0] != 0x05 || buffer[1] != 0x01 {
            return Err(HysteriaError::generic("Invalid SOCKS5 connect request".to_string()));
        }
        
        // Parse target address (simplified)
        let target = match buffer[3] {
            0x01 => { // IPv4
                let ip = format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7]);
                let port = u16::from_be_bytes([buffer[8], buffer[9]]);
                format!("{}:{}", ip, port)
            }
            0x03 => { // Domain name
                let len = buffer[4] as usize;
                if n < 5 + len + 2 {
                    return Err(HysteriaError::generic("Invalid domain name".to_string()));
                }
                let domain = String::from_utf8_lossy(&buffer[5..5+len]);
                let port = u16::from_be_bytes([buffer[5+len], buffer[5+len+1]]);
                format!("{}:{}", domain, port)
            }
            _ => return Err(HysteriaError::generic("Unsupported address type".to_string())),
        };
        
        // Connect through Hysteria
        match self.tcp_request(&target).await {
            Ok(mut hysteria_stream) => {
                // Send success response
                let response = [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                client_stream.write_all(&response).await
                    .map_err(|e| HysteriaError::io(e))?;
                
                // Start data relay
                let bytes_tx = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let bytes_rx = Arc::new(std::sync::atomic::AtomicU64::new(0));
                
                let bytes_tx_clone = bytes_tx.clone();
                let bytes_rx_clone = bytes_rx.clone();
                
                let (mut client_read, mut client_write) = client_stream.into_split();
                let (mut hysteria_read, mut hysteria_write) = tokio::io::split(&mut hysteria_stream);
                
                // Client to Hysteria
                let client_to_hysteria = async {
                    let mut buffer = vec![0u8; 8192];
                    loop {
                        match client_read.read(&mut buffer).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if hysteria_write.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                                bytes_tx_clone.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(_) => break,
                        }
                    }
                };
                
                // Hysteria to client
                let hysteria_to_client = async {
                    let mut buffer = vec![0u8; 8192];
                    loop {
                        match hysteria_read.read(&mut buffer).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if client_write.write_all(&buffer[..n]).await.is_err() {
                                    break;
                                }
                                bytes_rx_clone.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(_) => break,
                        }
                    }
                };
                
                // Wait for either direction to complete
                tokio::select! {
                    _ = client_to_hysteria => {},
                    _ = hysteria_to_client => {},
                }
                
                let duration = start_time.elapsed();
                let final_bytes_tx = bytes_tx.load(std::sync::atomic::Ordering::Relaxed);
                let final_bytes_rx = bytes_rx.load(std::sync::atomic::Ordering::Relaxed);
                
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.total_bytes_tx += final_bytes_tx;
                    stats.total_bytes_rx += final_bytes_rx;
                }
                
                // Log traffic
                let traffic_entry = TrafficLogEntry::new(
                    client_addr,
                    target.clone(),
                    "SOCKS5".to_string(),
                    final_bytes_tx,
                    final_bytes_rx,
                    duration.as_millis() as u64,
                    "completed".to_string(),
                );
                self.traffic_logger.log_traffic(traffic_entry).await?;
                
                Ok(())
            }
            Err(e) => {
                // Send error response
                let response = [0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                let _ = client_stream.write_all(&response).await;
                
                // Update statistics
                {
                    let mut stats = self.stats.write().await;
                    stats.failed_requests += 1;
                }
                
                Err(e)
            }
        }
    }
    
    /// Get client statistics
    pub async fn get_stats(&self) -> ClientStats {
        self.stats.read().await.clone()
    }
    
    /// Get recent events
    pub async fn get_recent_events(&self, limit: usize) -> Result<Vec<EventLogEntry>> {
        self.event_logger.get_recent_events(limit).await
    }
    
    /// Get traffic statistics
    pub async fn get_traffic_stats(&self, start_time: u64, end_time: u64) -> Result<Vec<TrafficLogEntry>> {
        self.traffic_logger.get_traffic_stats(start_time, end_time).await
    }
    
    /// Cleanup idle connections
    pub async fn cleanup_connections(&self) {
        let mut pool = self.connection_pool.write().await;
        pool.cleanup_idle_connections();
    }
    
    /// Disconnect and cleanup
    pub async fn disconnect(&self) {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_connections = 0;
        }
        
        // Log disconnect
        let disconnect_event = EventLogEntry::new(
            EventType::Disconnect,
            EventLevel::Info,
            "Client disconnected".to_string(),
        );
        let _ = self.event_logger.log_event(disconnect_event).await;
        
        // Clear connection pool
        {
            let mut pool = self.connection_pool.write().await;
            pool.connections.clear();
        }
    }
}

// Implement Clone for AdvancedHysteriaClient
impl Clone for AdvancedHysteriaClient {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            quic_client: self.quic_client.clone(),
            event_logger: self.event_logger.clone(),
            traffic_logger: self.traffic_logger.clone(),
            stats: self.stats.clone(),
            connection_pool: self.connection_pool.clone(),
        }
    }
}

// Placeholder types for compilation
struct QuicConnection;
struct QuicStream;

impl Clone for QuicConnection {
    fn clone(&self) -> Self {
        QuicConnection
    }
}

impl QuicConnection {
    async fn open_stream(&self) -> Result<QuicStream> {
        Err(HysteriaError::generic("Not implemented".to_string()))
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::task::Poll::Ready(Ok(0))
    }
    
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    // Create advanced client configuration
    let mut config = ClientConfig::default();
    config.server = "127.0.0.1:8443".to_string();
    
    // Configure authentication
    config.auth = Some(AuthConfig {
        auth_type: AuthType::Password,
        password: Some("secret123".to_string()),
        userpass_file: None,
        http_url: None,
        http_timeout: None,
        params: None,
    });
    
    // Configure bandwidth
    config.bandwidth = Some(BandwidthConfig {
        up: Some(10_000_000), // 10 Mbps
        down: Some(50_000_000), // 50 Mbps
        cc: Some(CongestionControl::Bbr),
        measurement_window: Some(Duration::from_secs(5)),
        auto: Some(false),
    });
    
    // Configure logging
    config.logging = Some(LoggingConfig {
        events: Some(EventLoggingConfig {
            enabled: true,
            file: Some(PathBuf::from("client_events.log")),
            max_size: Some(10_000_000), // 10 MB
            max_files: Some(5),
            rotation: Some(Duration::from_secs(3600)), // 1 hour
            buffer_size: Some(1000),
        }),
        traffic: Some(TrafficLoggingConfig {
            enabled: true,
            file: Some(PathBuf::from("client_traffic.log")),
            max_size: Some(10_000_000), // 10 MB
            max_files: Some(5),
            rotation: Some(Duration::from_secs(3600)), // 1 hour
            buffer_size: Some(1000),
        }),
        level: Some(LogLevel::Info),
        format: Some(LogFormat::Json),
    });
    
    // Configure performance
    config.performance = Some(PerformanceConfig {
        send_buffer_size: Some(65536),
        recv_buffer_size: Some(65536),
        worker_threads: Some(4),
        zero_copy: Some(true),
        fast_open: Some(true),
    });
    
    // Create the client
    let client = AdvancedHysteriaClient::new(config).await?;
    
    // Start statistics reporting task
    let stats_client = client.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let stats = stats_client.get_stats().await;
            println!("Client Stats: {:?}", stats);
        }
    });
    
    // Start connection cleanup task
    let cleanup_client = client.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_client.cleanup_connections().await;
        }
    });
    
    // Start SOCKS5 proxy
    let proxy_addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    println!("Starting SOCKS5 proxy on {}", proxy_addr);
    
    // Handle shutdown gracefully
    let shutdown_client = client.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        println!("Shutting down client...");
        shutdown_client.disconnect().await;
        std::process::exit(0);
    });
    
    // Start the SOCKS5 proxy server
    client.start_socks5_proxy(proxy_addr).await
}