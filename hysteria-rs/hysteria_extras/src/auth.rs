//! Authentication mechanisms for Hysteria 2
//!
//! This module provides various authentication methods including:
//! - Password authentication
//! - HTTP authentication
//! - Username/password authentication

use std::net::SocketAddr;
use std::time::Duration;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use reqwest::Client;
use base64::prelude::*;
use crate::{ExtrasError, Result};

/// Trait for authentication mechanisms
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Authenticate a connection
    /// 
    /// # Arguments
    /// * `addr` - Client address
    /// * `auth` - Authentication data
    /// * `tx` - Transaction ID
    /// 
    /// # Returns
    /// * `Ok((true, user_id))` - Authentication successful
    /// * `Ok((false, ""))` - Authentication failed
    /// * `Err(error)` - Authentication error
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> Result<(bool, String)>;
}

/// Simple password authenticator
#[derive(Debug, Clone)]
pub struct PasswordAuthenticator {
    password: String,
}

impl PasswordAuthenticator {
    /// Create a new password authenticator
    pub fn new(password: String) -> Self {
        Self { password }
    }
}

#[async_trait]
impl Authenticator for PasswordAuthenticator {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> Result<(bool, String)> {
        if auth == self.password {
            Ok((true, "user".to_string()))
        } else {
            Ok((false, String::new()))
        }
    }
}

/// HTTP authentication request
#[derive(Debug, Serialize)]
struct HttpAuthRequest {
    addr: String,
    auth: String,
    tx: u64,
}

/// HTTP authentication response
#[derive(Debug, Deserialize)]
struct HttpAuthResponse {
    ok: bool,
    id: Option<String>,
}

/// HTTP-based authenticator
#[derive(Debug)]
pub struct HttpAuthenticator {
    client: Client,
    url: String,
}

impl HttpAuthenticator {
    /// Create a new HTTP authenticator
    /// 
    /// # Arguments
    /// * `url` - Authentication endpoint URL
    /// * `insecure` - Whether to skip TLS verification
    pub fn new(url: String, insecure: bool) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(ExtrasError::HttpError)?;
        
        Ok(Self { client, url })
    }
    
    async fn post_auth_request(&self, req: &HttpAuthRequest) -> Result<HttpAuthResponse> {
        let response = self.client
            .post(&self.url)
            .json(req)
            .send()
            .await
            .map_err(ExtrasError::HttpError)?;
        
        if !response.status().is_success() {
            return Err(ExtrasError::AuthenticationFailed(
                format!("HTTP status: {}", response.status())
            ));
        }
        
        let auth_response: HttpAuthResponse = response
            .json()
            .await
            .map_err(ExtrasError::HttpError)?;
        
        Ok(auth_response)
    }
}

#[async_trait]
impl Authenticator for HttpAuthenticator {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> Result<(bool, String)> {
        let request = HttpAuthRequest {
            addr: addr.to_string(),
            auth: auth.to_string(),
            tx,
        };
        
        match self.post_auth_request(&request).await {
            Ok(response) => {
                if response.ok {
                    Ok((true, response.id.unwrap_or_else(|| "user".to_string())))
                } else {
                    Ok((false, String::new()))
                }
            }
            Err(e) => {
                tracing::warn!("HTTP authentication error: {}", e);
                Ok((false, String::new()))
            }
        }
    }
}

/// Username/password authenticator
#[derive(Debug, Clone)]
pub struct UserPassAuthenticator {
    credentials: std::collections::HashMap<String, String>,
}

impl UserPassAuthenticator {
    /// Create a new username/password authenticator
    pub fn new() -> Self {
        Self {
            credentials: std::collections::HashMap::new(),
        }
    }
    
    /// Add a user credential
    pub fn add_user(&mut self, username: String, password: String) {
        self.credentials.insert(username, password);
    }
    
    /// Create from a map of credentials
    pub fn from_map(credentials: std::collections::HashMap<String, String>) -> Self {
        Self { credentials }
    }
    
    fn parse_userpass(auth: &str) -> Option<(String, String)> {
        // Expected format: "username:password" (base64 encoded)
        let decoded = base64::prelude::BASE64_STANDARD.decode(auth).ok()?;
        let decoded_str = String::from_utf8(decoded).ok()?;
        let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some((parts[0].to_string(), parts[1].to_string()))
        } else {
            None
        }
    }
}

impl Default for UserPassAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Authenticator for UserPassAuthenticator {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> Result<(bool, String)> {
        if let Some((username, password)) = Self::parse_userpass(auth) {
            if let Some(stored_password) = self.credentials.get(&username) {
                if password == *stored_password {
                    return Ok((true, username));
                }
            }
        }
        Ok((false, String::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_password_authenticator() {
        let auth = PasswordAuthenticator::new("test123".to_string());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Test correct password
        let (ok, id) = auth.authenticate(addr, "test123", 1).await.unwrap();
        assert!(ok);
        assert_eq!(id, "user");
        
        // Test incorrect password
        let (ok, id) = auth.authenticate(addr, "wrong", 2).await.unwrap();
        assert!(!ok);
        assert!(id.is_empty());
    }
    
    #[tokio::test]
    async fn test_userpass_authenticator() {
        let mut auth = UserPassAuthenticator::new();
        auth.add_user("alice".to_string(), "secret".to_string());
        auth.add_user("bob".to_string(), "password".to_string());
        
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // Test valid credentials
        let encoded = base64::encode("alice:secret");
        let (ok, id) = auth.authenticate(addr, &encoded, 1).await.unwrap();
        assert!(ok);
        assert_eq!(id, "alice");
        
        // Test invalid password
        let encoded = base64::encode("alice:wrong");
        let (ok, id) = auth.authenticate(addr, &encoded, 2).await.unwrap();
        assert!(!ok);
        assert!(id.is_empty());
        
        // Test invalid user
        let encoded = base64::encode("charlie:secret");
        let (ok, id) = auth.authenticate(addr, &encoded, 3).await.unwrap();
        assert!(!ok);
        assert!(id.is_empty());
    }
}