//! Hook mechanism for Hysteria protocol
//!
//! Provides request and response hooks for monitoring and modifying
//! traffic flow through the Hysteria server.

use crate::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Request information passed to hooks
#[derive(Debug, Clone)]
pub struct RequestInfo {
    /// Client address
    pub client_addr: SocketAddr,
    /// Target address
    pub target_addr: String,
    /// Request type (TCP/UDP)
    pub request_type: RequestType,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Response information passed to hooks
#[derive(Debug, Clone)]
pub struct ResponseInfo {
    /// Client address
    pub client_addr: SocketAddr,
    /// Target address
    pub target_addr: String,
    /// Response status
    pub status: ResponseStatus,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Connection duration in milliseconds
    pub duration_ms: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Request type enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestType {
    Tcp,
    Udp,
}

/// Response status enumeration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseStatus {
    Success,
    Error(String),
    Timeout,
    Rejected,
}

/// Hook action result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookAction {
    /// Allow the request to proceed
    Allow,
    /// Reject the request
    Reject(String),
    /// Modify the request
    Modify(RequestModification),
}

/// Request modification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestModification {
    /// New target address
    pub new_target: Option<String>,
    /// Additional metadata to add
    pub add_metadata: HashMap<String, String>,
}

/// Request hook trait
pub trait RequestHook: Send + Sync {
    /// Called before processing a request
    fn on_request<'a>(&'a self, info: &'a RequestInfo) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<HookAction>> + Send + 'a>>;
}

/// Response hook trait
pub trait ResponseHook: Send + Sync {
    /// Called after processing a request
    fn on_response<'a>(&'a self, info: &'a ResponseInfo) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

/// Hook manager for managing request and response hooks
pub struct HookManager {
    request_hooks: Arc<RwLock<Vec<Arc<dyn RequestHook>>>>,
    response_hooks: Arc<RwLock<Vec<Arc<dyn ResponseHook>>>>,
}

impl std::fmt::Debug for HookManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookManager")
            .field("request_hooks_count", &self.request_hooks.try_read().map(|h| h.len()).unwrap_or(0))
            .field("response_hooks_count", &self.response_hooks.try_read().map(|h| h.len()).unwrap_or(0))
            .finish()
    }
}

impl HookManager {
    /// Create a new hook manager
    pub fn new() -> Self {
        Self {
            request_hooks: Arc::new(RwLock::new(Vec::new())),
            response_hooks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add a request hook
    pub async fn add_request_hook(&self, hook: Arc<dyn RequestHook>) {
        let mut hooks = self.request_hooks.write().await;
        hooks.push(hook);
    }

    /// Add a response hook
    pub async fn add_response_hook(&self, hook: Arc<dyn ResponseHook>) {
        let mut hooks = self.response_hooks.write().await;
        hooks.push(hook);
    }

    /// Execute all request hooks
    pub async fn execute_request_hooks(&self, info: &RequestInfo) -> Result<HookAction> {
        let hooks = self.request_hooks.read().await;
        
        for hook in hooks.iter() {
            match hook.on_request(info).await? {
                HookAction::Allow => continue,
                action => return Ok(action),
            }
        }
        
        Ok(HookAction::Allow)
    }

    /// Execute all response hooks
    pub async fn execute_response_hooks(&self, info: &ResponseInfo) -> Result<()> {
        let hooks = self.response_hooks.read().await;
        
        for hook in hooks.iter() {
            hook.on_response(info).await?;
        }
        
        Ok(())
    }
}

impl Default for HookManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple logging hook implementation
#[derive(Debug)]
pub struct LoggingHook {
    name: String,
}

impl LoggingHook {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

impl RequestHook for LoggingHook {
    fn on_request<'a>(&'a self, info: &'a RequestInfo) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<HookAction>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                "[{}] Request: {} -> {} ({})",
                self.name,
                info.client_addr,
                info.target_addr,
                match info.request_type {
                    RequestType::Tcp => "TCP",
                    RequestType::Udp => "UDP",
                }
            );
            Ok(HookAction::Allow)
        })
    }
}

impl ResponseHook for LoggingHook {
    fn on_response<'a>(&'a self, info: &'a ResponseInfo) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            tracing::info!(
                "[{}] Response: {} -> {} ({:?}, {} bytes, {}ms)",
                self.name,
                info.client_addr,
                info.target_addr,
                info.status,
                info.bytes_transferred,
                info.duration_ms
            );
            Ok(())
        })
    }
}

/// Rate limiting hook implementation
#[derive(Debug)]
pub struct RateLimitHook {
    max_requests_per_minute: u32,
    client_requests: Arc<RwLock<HashMap<SocketAddr, Vec<u64>>>>,
}

impl RateLimitHook {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            max_requests_per_minute,
            client_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn cleanup_old_requests(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut requests = self.client_requests.write().await;
        for (_, timestamps) in requests.iter_mut() {
            timestamps.retain(|&timestamp| now - timestamp < 60);
        }
        requests.retain(|_, timestamps| !timestamps.is_empty());
    }
}

impl RequestHook for RateLimitHook {
    fn on_request<'a>(&'a self, info: &'a RequestInfo) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<HookAction>> + Send + 'a>> {
        Box::pin(async move {
            self.cleanup_old_requests().await;
            
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            let mut requests = self.client_requests.write().await;
            let client_requests = requests.entry(info.client_addr).or_insert_with(Vec::new);
            
            if client_requests.len() >= self.max_requests_per_minute as usize {
                return Ok(HookAction::Reject("Rate limit exceeded".to_string()));
            }
            
            client_requests.push(now);
            Ok(HookAction::Allow)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_request_info() -> RequestInfo {
        RequestInfo {
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            target_addr: "example.com:80".to_string(),
            request_type: RequestType::Tcp,
            metadata: HashMap::new(),
        }
    }

    fn create_test_response_info() -> ResponseInfo {
        ResponseInfo {
            client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            target_addr: "example.com:80".to_string(),
            status: ResponseStatus::Success,
            bytes_transferred: 1024,
            duration_ms: 100,
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_hook_manager() {
        let manager = HookManager::new();
        let logging_hook = Arc::new(LoggingHook::new("test".to_string()));
        
        manager.add_request_hook(logging_hook.clone()).await;
        manager.add_response_hook(logging_hook).await;
        
        let request_info = create_test_request_info();
        let response_info = create_test_response_info();
        
        let action = manager.execute_request_hooks(&request_info).await.unwrap();
        assert_eq!(action, HookAction::Allow);
        
        manager.execute_response_hooks(&response_info).await.unwrap();
    }

    #[tokio::test]
    async fn test_rate_limit_hook() {
        let hook = RateLimitHook::new(2);
        let request_info = create_test_request_info();
        
        // First two requests should be allowed
        assert_eq!(hook.on_request(&request_info).await.unwrap(), HookAction::Allow);
        assert_eq!(hook.on_request(&request_info).await.unwrap(), HookAction::Allow);
        
        // Third request should be rejected
        match hook.on_request(&request_info).await.unwrap() {
            HookAction::Reject(_) => {},
            _ => panic!("Expected rejection"),
        }
    }
}