//! Event and traffic logging for Hysteria protocol
//!
//! Provides comprehensive logging capabilities for monitoring
//! server events, traffic statistics, and performance metrics.

use crate::{HysteriaError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use std::io::BufRead;

/// Event types for logging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    /// Client connection established
    Connect,
    /// Client disconnected
    Disconnect,
    /// Authentication attempt
    Auth,
    /// TCP request
    TcpRequest,
    /// UDP session created
    UdpSession,
    /// Error occurred
    Error,
    /// Traffic statistics
    Traffic,
}

/// Event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Event log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogEntry {
    /// Timestamp in Unix seconds
    pub timestamp: u64,
    /// Event type
    pub event_type: EventType,
    /// Event severity level
    pub level: EventLevel,
    /// Client address
    pub client_addr: Option<SocketAddr>,
    /// Target address
    pub target_addr: Option<String>,
    /// Event message
    pub message: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Traffic statistics entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficLogEntry {
    /// Timestamp in Unix seconds
    pub timestamp: u64,
    /// Client address
    pub client_addr: SocketAddr,
    /// Target address
    pub target_addr: String,
    /// Protocol type (TCP/UDP)
    pub protocol: String,
    /// Bytes sent from client to target
    pub bytes_tx: u64,
    /// Bytes received from target to client
    pub bytes_rx: u64,
    /// Connection duration in milliseconds
    pub duration_ms: u64,
    /// Connection status
    pub status: String,
}

/// Event logger trait
pub trait EventLogger: Send + Sync {
    /// Log an event
    fn log_event<'a>(&'a self, entry: EventLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    
    /// Get recent events
    fn get_recent_events<'a>(&'a self, limit: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<EventLogEntry>>> + Send + 'a>>;
}

/// Traffic logger trait
pub trait TrafficLogger: Send + Sync {
    /// Log traffic statistics
    fn log_traffic<'a>(&'a self, entry: TrafficLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    
    /// Get traffic statistics for a time period
    fn get_traffic_stats<'a>(&'a self, start_time: u64, end_time: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<TrafficLogEntry>>> + Send + 'a>>;
}

/// In-memory event logger implementation
#[derive(Debug)]
pub struct MemoryEventLogger {
    events: Arc<RwLock<Vec<EventLogEntry>>>,
    max_events: usize,
}

impl MemoryEventLogger {
    /// Create a new memory event logger
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events,
        }
    }
}

impl EventLogger for MemoryEventLogger {
    fn log_event<'a>(&'a self, entry: EventLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut events = self.events.write().await;
            events.push(entry);
            
            // Keep only the most recent events
            if events.len() > self.max_events {
                let drain_count = events.len() - self.max_events;
                events.drain(0..drain_count);
            }
            
            Ok(())
        })
    }
    
    fn get_recent_events<'a>(&'a self, limit: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<EventLogEntry>>> + Send + 'a>> {
        Box::pin(async move {
            let events = self.events.read().await;
            let start = events.len().saturating_sub(limit);
            Ok(events[start..].to_vec())
        })
    }
}

/// In-memory traffic logger implementation
#[derive(Debug)]
pub struct MemoryTrafficLogger {
    traffic: Arc<RwLock<Vec<TrafficLogEntry>>>,
    max_entries: usize,
}

impl MemoryTrafficLogger {
    /// Create a new memory traffic logger
    pub fn new(max_entries: usize) -> Self {
        Self {
            traffic: Arc::new(RwLock::new(Vec::new())),
            max_entries,
        }
    }
}

impl TrafficLogger for MemoryTrafficLogger {
    fn log_traffic<'a>(&'a self, entry: TrafficLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut traffic = self.traffic.write().await;
            traffic.push(entry);
            
            // Keep only the most recent entries
            if traffic.len() > self.max_entries {
                let drain_count = traffic.len() - self.max_entries;
                traffic.drain(0..drain_count);
            }
            
            Ok(())
        })
    }
    
    fn get_traffic_stats<'a>(&'a self, start_time: u64, end_time: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<TrafficLogEntry>>> + Send + 'a>> {
        Box::pin(async move {
            let traffic = self.traffic.read().await;
            Ok(traffic
                .iter()
                .filter(|entry| entry.timestamp >= start_time && entry.timestamp <= end_time)
                .cloned()
                .collect())
        })
    }
}

/// File-based event logger implementation
#[derive(Debug)]
pub struct FileEventLogger {
    file_path: String,
    memory_logger: MemoryEventLogger,
}

impl FileEventLogger {
    /// Create a new file event logger
    pub fn new(file_path: String, memory_buffer_size: usize) -> Self {
        Self {
            file_path,
            memory_logger: MemoryEventLogger::new(memory_buffer_size),
        }
    }
    
    /// Flush events to file
    pub async fn flush_to_file(&self) -> Result<()> {
        let events = self.memory_logger.get_recent_events(usize::MAX).await?;
        
        let mut json_lines = Vec::new();
        for event in events.iter() {
            match serde_json::to_string(event) {
                Ok(json) => json_lines.push(json),
                Err(e) => return Err(HysteriaError::Generic(format!("JSON serialization failed: {}", e))),
            }
        }
        
        let content = json_lines.join("\n") + "\n";
        
        tokio::fs::write(&self.file_path, content)
            .await
            .map_err(|e| HysteriaError::Io(e))?;
        
        Ok(())
    }
}

impl EventLogger for FileEventLogger {
    fn log_event<'a>(&'a self, entry: EventLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.memory_logger.log_event(entry).await
        })
    }
    
    fn get_recent_events<'a>(&'a self, limit: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<EventLogEntry>>> + Send + 'a>> {
        Box::pin(async move {
            self.memory_logger.get_recent_events(limit).await
        })
    }
}

/// Multi-logger that can log to multiple destinations
pub struct MultiLogger {
    event_loggers: Vec<Arc<dyn EventLogger>>,
    traffic_loggers: Vec<Arc<dyn TrafficLogger>>,
}

impl std::fmt::Debug for MultiLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiLogger")
            .field("event_loggers_count", &self.event_loggers.len())
            .field("traffic_loggers_count", &self.traffic_loggers.len())
            .finish()
    }
}

impl MultiLogger {
    /// Create a new multi-logger
    pub fn new() -> Self {
        Self {
            event_loggers: Vec::new(),
            traffic_loggers: Vec::new(),
        }
    }
    
    /// Add an event logger
    pub fn add_event_logger(&mut self, logger: Arc<dyn EventLogger>) {
        self.event_loggers.push(logger);
    }
    
    /// Add a traffic logger
    pub fn add_traffic_logger(&mut self, logger: Arc<dyn TrafficLogger>) {
        self.traffic_loggers.push(logger);
    }
}

impl EventLogger for MultiLogger {
    fn log_event<'a>(&'a self, entry: EventLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            for logger in &self.event_loggers {
                logger.log_event(entry.clone()).await?;
            }
            Ok(())
        })
    }
    
    fn get_recent_events<'a>(&'a self, limit: usize) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<EventLogEntry>>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(logger) = self.event_loggers.first() {
                logger.get_recent_events(limit).await
            } else {
                Ok(Vec::new())
            }
        })
    }
}

impl TrafficLogger for MultiLogger {
    fn log_traffic<'a>(&'a self, entry: TrafficLogEntry) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            for logger in &self.traffic_loggers {
                logger.log_traffic(entry.clone()).await?;
            }
            Ok(())
        })
    }
    
    fn get_traffic_stats<'a>(&'a self, start_time: u64, end_time: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<TrafficLogEntry>>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(logger) = self.traffic_loggers.first() {
                logger.get_traffic_stats(start_time, end_time).await
            } else {
                Ok(Vec::new())
            }
        })
    }
}

impl Default for MultiLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper functions for creating log entries
impl EventLogEntry {
    /// Create a new event log entry
    pub fn new(
        event_type: EventType,
        level: EventLevel,
        message: String,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            event_type,
            level,
            client_addr: None,
            target_addr: None,
            message,
            metadata: HashMap::new(),
        }
    }
    
    /// Set client address
    pub fn with_client_addr(mut self, addr: SocketAddr) -> Self {
        self.client_addr = Some(addr);
        self
    }
    
    /// Set target address
    pub fn with_target_addr(mut self, addr: String) -> Self {
        self.target_addr = Some(addr);
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

impl TrafficLogEntry {
    /// Create a new traffic log entry
    pub fn new(
        client_addr: SocketAddr,
        target_addr: String,
        protocol: String,
        bytes_tx: u64,
        bytes_rx: u64,
        duration_ms: u64,
        status: String,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            client_addr,
            target_addr,
            protocol,
            bytes_tx,
            bytes_rx,
            duration_ms,
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_memory_event_logger() {
        let logger = MemoryEventLogger::new(10);
        
        let entry = EventLogEntry::new(
            EventType::Connect,
            EventLevel::Info,
            "Client connected".to_string(),
        );
        
        logger.log_event(entry).await.unwrap();
        
        let events = logger.get_recent_events(5).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::Connect);
    }
    
    #[tokio::test]
    async fn test_memory_traffic_logger() {
        let logger = MemoryTrafficLogger::new(10);
        
        let entry = TrafficLogEntry::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            "example.com:80".to_string(),
            "TCP".to_string(),
            1024,
            2048,
            1000,
            "success".to_string(),
        );
        
        logger.log_traffic(entry).await.unwrap();
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let stats = logger.get_traffic_stats(now - 60, now + 60).await.unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].bytes_tx, 1024);
        assert_eq!(stats[0].bytes_rx, 2048);
    }
    
    #[tokio::test]
    async fn test_multi_logger() {
        let mut multi_logger = MultiLogger::new();
        let memory_logger = Arc::new(MemoryEventLogger::new(10));
        
        multi_logger.add_event_logger(memory_logger.clone());
        
        let entry = EventLogEntry::new(
            EventType::Auth,
            EventLevel::Info,
            "Authentication successful".to_string(),
        );
        
        multi_logger.log_event(entry).await.unwrap();
        
        let events = memory_logger.get_recent_events(5).await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, EventType::Auth);
    }
}