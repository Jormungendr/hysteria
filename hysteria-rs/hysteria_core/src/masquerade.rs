//! Masquerade module for Hysteria protocol
//!
//! Provides HTTP/3 masquerading functionality to make Hysteria traffic
//! appear as legitimate HTTP traffic.

use crate::{HysteriaError, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Masquerade handler trait
pub trait MasqueradeHandler: Send + Sync {
    /// Handle masquerade request
    fn handle_request<'a>(
        &'a self,
        request: MasqueradeRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MasqueradeResponse>> + Send + 'a>>;
    
    /// Check if the request should be masqueraded
    fn should_masquerade<'a>(&'a self, request: &'a MasqueradeRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

/// Masquerade request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeRequest {
    /// HTTP method
    pub method: String,
    
    /// Request URI
    pub uri: String,
    
    /// HTTP version
    pub version: String,
    
    /// Request headers
    pub headers: Vec<(String, String)>,
    
    /// Request body
    pub body: Vec<u8>,
    
    /// Client address
    pub client_addr: Option<SocketAddr>,
}

/// Masquerade response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeResponse {
    /// HTTP status code
    pub status: u16,
    
    /// Response headers
    pub headers: Vec<(String, String)>,
    
    /// Response body
    pub body: Vec<u8>,
}

/// HTTP masquerade handler
#[derive(Debug, Clone)]
pub struct HttpMasqueradeHandler {
    /// Response status code
    pub status_code: u16,
    
    /// Response body
    pub response_body: String,
    
    /// Custom headers
    pub custom_headers: HashMap<String, String>,
    
    /// Whether to log requests
    pub log_requests: bool,
}

impl HttpMasqueradeHandler {
    /// Create a new HTTP masquerade handler
    pub fn new() -> Self {
        Self {
            status_code: 200,
            response_body: "OK".to_string(),
            custom_headers: HashMap::new(),
            log_requests: false,
        }
    }
    
    /// Set status code
    pub fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = status_code;
        self
    }
    
    /// Set response body
    pub fn with_response_body(mut self, body: String) -> Self {
        self.response_body = body;
        self
    }
    
    /// Add custom header
    pub fn with_header(mut self, name: String, value: String) -> Self {
        self.custom_headers.insert(name, value);
        self
    }
    
    /// Enable request logging
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }
}

impl Default for HttpMasqueradeHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl MasqueradeHandler for HttpMasqueradeHandler {
    fn handle_request<'a>(
        &'a self,
        request: MasqueradeRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MasqueradeResponse>> + Send + 'a>> {
        Box::pin(async move {
            if self.log_requests {
                println!(
                    "Masquerade request: {} {} from {:?}",
                    request.method, request.uri, request.client_addr
                );
            }
            
            let mut headers = vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Content-Length".to_string(), self.response_body.len().to_string()),
            ];
            
            // Add custom headers
            for (name, value) in &self.custom_headers {
                headers.push((name.clone(), value.clone()));
            }
            
            let response = MasqueradeResponse {
                status: self.status_code,
                headers,
                body: self.response_body.as_bytes().to_vec(),
            };
            
            Ok(response)
        })
    }
    
    fn should_masquerade<'a>(&'a self, request: &'a MasqueradeRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            // Check if this looks like a legitimate HTTP request
            request.headers.iter().any(|(k, _)| k.to_lowercase() == "user-agent") ||
            request.headers.iter().any(|(k, _)| k.to_lowercase() == "host") ||
            request.method == "GET" ||
            request.method == "POST"
        })
    }
}

/// File server masquerade handler
#[derive(Debug, Clone)]
pub struct FileServerMasqueradeHandler {
    /// Root directory to serve files from
    pub root_dir: PathBuf,
    
    /// Default file to serve for directory requests
    pub index_file: String,
    
    /// Whether to log requests
    pub log_requests: bool,
}

impl FileServerMasqueradeHandler {
    /// Create a new file server masquerade handler
    pub fn new(root_dir: PathBuf) -> Self {
        Self {
            root_dir,
            index_file: "index.html".to_string(),
            log_requests: false,
        }
    }
    
    /// Set index file
    pub fn with_index_file(mut self, index_file: String) -> Self {
        self.index_file = index_file;
        self
    }
    
    /// Enable request logging
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }
}

impl MasqueradeHandler for FileServerMasqueradeHandler {
    fn handle_request<'a>(
        &'a self,
        request: MasqueradeRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MasqueradeResponse>> + Send + 'a>> {
        Box::pin(async move {
            if self.log_requests {
                println!(
                    "File server request: {} {} from {:?}",
                    request.method, request.uri, request.client_addr
                );
            }
            
            // Simplified file serving - just return a basic response
            let response = MasqueradeResponse {
                status: 200,
                headers: vec![
                    ("Content-Type".to_string(), "text/html".to_string()),
                    ("Content-Length".to_string(), "13".to_string()),
                ],
                body: b"Hello, World!".to_vec(),
            };
            
            Ok(response)
        })
    }
    
    fn should_masquerade<'a>(&'a self, request: &'a MasqueradeRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            // File server handles all GET requests
            request.method == "GET"
        })
    }
}

/// Proxy masquerade handler
#[derive(Debug, Clone)]
pub struct ProxyMasqueradeHandler {
    /// Target URL to proxy requests to
    pub target_url: String,
    
    /// Request timeout
    pub timeout: Duration,
    
    /// Whether to log requests
    pub log_requests: bool,
}

impl ProxyMasqueradeHandler {
    /// Create a new proxy masquerade handler
    pub fn new(target_url: String) -> Self {
        Self {
            target_url,
            timeout: Duration::from_secs(30),
            log_requests: false,
        }
    }
    
    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Enable request logging
    pub fn with_logging(mut self, enabled: bool) -> Self {
        self.log_requests = enabled;
        self
    }
}

impl MasqueradeHandler for ProxyMasqueradeHandler {
    fn handle_request<'a>(
        &'a self,
        request: MasqueradeRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<MasqueradeResponse>> + Send + 'a>> {
        Box::pin(async move {
            if self.log_requests {
                println!(
                    "Proxy request: {} {} from {:?}",
                    request.method, request.uri, request.client_addr
                );
            }
            
            // Simplified proxy - just return a mock response
            let response = MasqueradeResponse {
                status: 200,
                headers: vec![
                    ("Content-Type".to_string(), "text/plain".to_string()),
                    ("Content-Length".to_string(), "7".to_string()),
                ],
                body: b"Proxied".to_vec(),
            };
            
            Ok(response)
        })
    }
    
    fn should_masquerade<'a>(&'a self, request: &'a MasqueradeRequest) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            // Proxy handles all requests
            true
        })
    }
}

/// Masquerade handler type enum
#[derive(Debug)]
pub enum MasqueradeHandlerType {
    /// HTTP masquerade handler
    Http(HttpMasqueradeHandler),
    
    /// File server masquerade handler
    FileServer(FileServerMasqueradeHandler),
    
    /// Proxy masquerade handler
    Proxy(ProxyMasqueradeHandler),
}

impl MasqueradeHandlerType {
    /// Handle masquerade request
    pub async fn handle_request(&self, request: MasqueradeRequest) -> Result<MasqueradeResponse> {
        match self {
            MasqueradeHandlerType::Http(handler) => handler.handle_request(request).await,
            MasqueradeHandlerType::FileServer(handler) => handler.handle_request(request).await,
            MasqueradeHandlerType::Proxy(handler) => handler.handle_request(request).await,
        }
    }
    
    /// Check if the request should be masqueraded
    pub async fn should_masquerade(&self, request: &MasqueradeRequest) -> bool {
        match self {
            MasqueradeHandlerType::Http(handler) => handler.should_masquerade(request).await,
            MasqueradeHandlerType::FileServer(handler) => handler.should_masquerade(request).await,
            MasqueradeHandlerType::Proxy(handler) => handler.should_masquerade(request).await,
        }
    }
}

/// Masquerade manager
#[derive(Debug)]
pub struct MasqueradeManager {
    /// Registered masquerade handlers
    handlers: HashMap<String, MasqueradeHandlerType>,
    
    /// Default masquerade handler
    default_handler: Option<MasqueradeHandlerType>,
}

impl MasqueradeManager {
    /// Create a new masquerade manager
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            default_handler: None,
        }
    }
    
    /// Add a masquerade handler
    pub fn add_handler(&mut self, name: String, handler: MasqueradeHandlerType) {
        self.handlers.insert(name, handler);
    }
    
    /// Set default masquerade handler
    pub fn set_default_handler(&mut self, handler: MasqueradeHandlerType) {
        self.default_handler = Some(handler);
    }
    
    /// Get masquerade handler by name
    pub fn get_handler(&self, name: &str) -> Option<&MasqueradeHandlerType> {
        self.handlers.get(name)
    }
    
    /// Handle masquerade request
    pub async fn handle_request(
        &self,
        handler_name: Option<&str>,
        request: MasqueradeRequest,
    ) -> Result<MasqueradeResponse> {
        let handler = if let Some(name) = handler_name {
            self.get_handler(name)
                .ok_or_else(|| HysteriaError::Generic(format!("Handler '{}' not found", name)))?
        } else {
            self.default_handler
                .as_ref()
                .ok_or_else(|| HysteriaError::Generic("No default handler configured".to_string()))?
        };
        
        handler.handle_request(request).await
    }
    
    /// Check if the request should be masqueraded
    pub async fn should_masquerade(
        &self,
        handler_name: Option<&str>,
        request: &MasqueradeRequest,
    ) -> bool {
        let handler = if let Some(name) = handler_name {
            self.get_handler(name)
        } else {
            self.default_handler.as_ref()
        };
        
        if let Some(handler) = handler {
            handler.should_masquerade(request).await
        } else {
            false
        }
    }
}

impl Default for MasqueradeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_http_masquerade_handler() {
        let handler = HttpMasqueradeHandler::new()
            .with_status_code(200)
            .with_response_body("Test response".to_string());
        
        let request = MasqueradeRequest {
            method: "GET".to_string(),
            uri: "/test".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("User-Agent".to_string(), "test".to_string())],
            body: Vec::new(),
            client_addr: None,
        };
        
        let response = handler.handle_request(request.clone()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"Test response");
        
        assert!(handler.should_masquerade(&request).await);
    }
    
    #[tokio::test]
    async fn test_masquerade_manager() {
        let mut manager = MasqueradeManager::new();
        let handler = MasqueradeHandlerType::Http(HttpMasqueradeHandler::new());
        
        manager.add_handler("test".to_string(), handler);
        
        let request = MasqueradeRequest {
            method: "GET".to_string(),
            uri: "/test".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![("User-Agent".to_string(), "test".to_string())],
            body: Vec::new(),
            client_addr: None,
        };
        
        let response = manager.handle_request(Some("test"), request).await.unwrap();
        assert_eq!(response.status, 200);
    }
}