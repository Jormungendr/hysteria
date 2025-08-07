//! Traffic sniffing and protocol detection for Hysteria 2
//!
//! This module provides functionality to detect protocols and extract
//! destination information from network traffic.

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{ExtrasError, Result};

/// Protocol detection result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
    Tls,
    Ssh,
    Ftp,
    Smtp,
    Pop3,
    Imap,
    Unknown,
}

/// Sniffed connection information
#[derive(Debug, Clone)]
pub struct SniffResult {
    pub protocol: Protocol,
    pub domain: Option<String>,
    pub destination_addr: Option<String>,
    pub destination_port: Option<u16>,
}

/// Traffic sniffer
#[derive(Debug)]
pub struct Sniffer {
    enabled: bool,
    max_bytes: usize,
}

impl Sniffer {
    /// Create a new sniffer
    pub fn new(enabled: bool, max_bytes: usize) -> Self {
        Self {
            enabled,
            max_bytes: max_bytes.min(8192), // Limit to reasonable size
        }
    }
    
    /// Sniff traffic and detect protocol
    pub fn sniff(&self, data: &[u8]) -> SniffResult {
        if !self.enabled || data.is_empty() {
            return SniffResult {
                protocol: Protocol::Unknown,
                domain: None,
                destination_addr: None,
                destination_port: None,
            };
        }
        
        let data = &data[..data.len().min(self.max_bytes)];
        
        // Try different protocol detection methods
        if let Some(result) = self.detect_http(data) {
            return result;
        }
        
        if let Some(result) = self.detect_tls(data) {
            return result;
        }
        
        if let Some(result) = self.detect_ssh(data) {
            return result;
        }
        
        if let Some(result) = self.detect_other_protocols(data) {
            return result;
        }
        
        SniffResult {
            protocol: Protocol::Unknown,
            domain: None,
            destination_addr: None,
            destination_port: None,
        }
    }
    
    /// Detect HTTP protocol
    fn detect_http(&self, data: &[u8]) -> Option<SniffResult> {
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.lines().collect();
        
        if lines.is_empty() {
            return None;
        }
        
        let first_line = lines[0];
        
        // Check for HTTP methods
        if first_line.starts_with("GET ") ||
           first_line.starts_with("POST ") ||
           first_line.starts_with("PUT ") ||
           first_line.starts_with("DELETE ") ||
           first_line.starts_with("HEAD ") ||
           first_line.starts_with("OPTIONS ") ||
           first_line.starts_with("PATCH ") ||
           first_line.starts_with("CONNECT ") {
            
            // Extract Host header
            let mut domain = None;
            for line in &lines[1..] {
                if line.to_lowercase().starts_with("host:") {
                    if let Some(host_value) = line.split(':').nth(1) {
                        domain = Some(host_value.trim().to_string());
                        break;
                    }
                }
            }
            
            return Some(SniffResult {
                protocol: Protocol::Http,
                domain,
                destination_addr: None,
                destination_port: Some(80),
            });
        }
        
        None
    }
    
    /// Detect TLS/HTTPS protocol
    fn detect_tls(&self, data: &[u8]) -> Option<SniffResult> {
        if data.len() < 6 {
            return None;
        }
        
        // Check for TLS handshake
        if data[0] == 0x16 && // Content Type: Handshake
           data[1] == 0x03 && // Version: TLS 1.x
           (data[2] == 0x01 || data[2] == 0x02 || data[2] == 0x03 || data[2] == 0x04) {
            
            // Try to extract SNI from Client Hello
            if let Some(domain) = self.extract_sni(data) {
                return Some(SniffResult {
                    protocol: Protocol::Https,
                    domain: Some(domain),
                    destination_addr: None,
                    destination_port: Some(443),
                });
            }
            
            return Some(SniffResult {
                protocol: Protocol::Tls,
                domain: None,
                destination_addr: None,
                destination_port: Some(443),
            });
        }
        
        None
    }
    
    /// Extract SNI (Server Name Indication) from TLS Client Hello
    fn extract_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 43 {
            return None;
        }
        
        // Skip TLS record header (5 bytes) and handshake header (4 bytes)
        let mut offset = 9;
        
        // Skip version (2 bytes) and random (32 bytes)
        offset += 34;
        
        if offset >= data.len() {
            return None;
        }
        
        // Skip session ID
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Skip cipher suites
        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;
        
        if offset >= data.len() {
            return None;
        }
        
        // Skip compression methods
        let compression_len = data[offset] as usize;
        offset += 1 + compression_len;
        
        if offset + 2 >= data.len() {
            return None;
        }
        
        // Extensions length
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        let extensions_end = offset + extensions_len;
        if extensions_end > data.len() {
            return None;
        }
        
        // Parse extensions
        while offset + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            
            if offset + ext_len > extensions_end {
                break;
            }
            
            // SNI extension type is 0
            if ext_type == 0 {
                return self.parse_sni_extension(&data[offset..offset + ext_len]);
            }
            
            offset += ext_len;
        }
        
        None
    }
    
    /// Parse SNI extension
    fn parse_sni_extension(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }
        
        // Skip server name list length (2 bytes)
        let mut offset = 2;
        
        // Server name type (1 byte) - should be 0 for hostname
        if data[offset] != 0 {
            return None;
        }
        offset += 1;
        
        // Server name length (2 bytes)
        let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;
        
        if offset + name_len > data.len() {
            return None;
        }
        
        // Extract hostname
        String::from_utf8(data[offset..offset + name_len].to_vec()).ok()
    }
    
    /// Detect SSH protocol
    fn detect_ssh(&self, data: &[u8]) -> Option<SniffResult> {
        let text = String::from_utf8_lossy(data);
        
        if text.starts_with("SSH-") {
            return Some(SniffResult {
                protocol: Protocol::Ssh,
                domain: None,
                destination_addr: None,
                destination_port: Some(22),
            });
        }
        
        None
    }
    
    /// Detect other protocols
    fn detect_other_protocols(&self, data: &[u8]) -> Option<SniffResult> {
        let text = String::from_utf8_lossy(data);
        
        // FTP
        if text.starts_with("220 ") || text.starts_with("USER ") || text.starts_with("PASS ") {
            return Some(SniffResult {
                protocol: Protocol::Ftp,
                domain: None,
                destination_addr: None,
                destination_port: Some(21),
            });
        }
        
        // SMTP
        if text.starts_with("220 ") || text.starts_with("HELO ") || text.starts_with("EHLO ") {
            return Some(SniffResult {
                protocol: Protocol::Smtp,
                domain: None,
                destination_addr: None,
                destination_port: Some(25),
            });
        }
        
        // POP3
        if text.starts_with("+OK ") || text.starts_with("USER ") {
            return Some(SniffResult {
                protocol: Protocol::Pop3,
                domain: None,
                destination_addr: None,
                destination_port: Some(110),
            });
        }
        
        // IMAP
        if text.contains("IMAP") || text.starts_with("* OK") {
            return Some(SniffResult {
                protocol: Protocol::Imap,
                domain: None,
                destination_addr: None,
                destination_port: Some(143),
            });
        }
        
        None
    }
}

/// SOCKS5 address parser
pub struct Socks5AddressParser;

impl Socks5AddressParser {
    /// Parse SOCKS5 address from request
    pub fn parse_address(data: &[u8]) -> Result<(String, u16)> {
        if data.len() < 7 {
            return Err(ExtrasError::SniffError("SOCKS5 request too short".to_string()));
        }
        
        // Check SOCKS version
        if data[0] != 0x05 {
            return Err(ExtrasError::SniffError("Invalid SOCKS version".to_string()));
        }
        
        // Check command (should be CONNECT = 0x01)
        if data[1] != 0x01 {
            return Err(ExtrasError::SniffError("Only CONNECT command supported".to_string()));
        }
        
        // Skip reserved byte (data[2])
        
        let addr_type = data[3];
        let mut offset = 4;
        
        let addr = match addr_type {
            0x01 => {
                // IPv4
                if data.len() < offset + 4 {
                    return Err(ExtrasError::SniffError("Invalid IPv4 address".to_string()));
                }
                let ip = Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
                offset += 4;
                ip.to_string()
            }
            0x03 => {
                // Domain name
                if data.len() < offset + 1 {
                    return Err(ExtrasError::SniffError("Invalid domain length".to_string()));
                }
                let domain_len = data[offset] as usize;
                offset += 1;
                
                if data.len() < offset + domain_len {
                    return Err(ExtrasError::SniffError("Invalid domain name".to_string()));
                }
                
                let domain = String::from_utf8(data[offset..offset + domain_len].to_vec())
                    .map_err(|_| ExtrasError::SniffError("Invalid domain encoding".to_string()))?;
                offset += domain_len;
                domain
            }
            0x04 => {
                // IPv6
                if data.len() < offset + 16 {
                    return Err(ExtrasError::SniffError("Invalid IPv6 address".to_string()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = Ipv6Addr::from(octets);
                offset += 16;
                ip.to_string()
            }
            _ => {
                return Err(ExtrasError::SniffError(format!("Unsupported address type: {}", addr_type)));
            }
        };
        
        // Parse port
        if data.len() < offset + 2 {
            return Err(ExtrasError::SniffError("Invalid port".to_string()));
        }
        
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        
        Ok((addr, port))
    }
}

/// HTTP CONNECT parser
pub struct HttpConnectParser;

impl HttpConnectParser {
    /// Parse HTTP CONNECT request
    pub fn parse_connect(data: &[u8]) -> Result<(String, u16)> {
        let text = String::from_utf8_lossy(data);
        let lines: Vec<&str> = text.lines().collect();
        
        if lines.is_empty() {
            return Err(ExtrasError::SniffError("Empty HTTP request".to_string()));
        }
        
        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        
        if parts.len() < 2 || parts[0] != "CONNECT" {
            return Err(ExtrasError::SniffError("Not a CONNECT request".to_string()));
        }
        
        let target = parts[1];
        
        // Parse host:port
        if let Some(colon_pos) = target.rfind(':') {
            let host = &target[..colon_pos];
            let port_str = &target[colon_pos + 1..];
            
            let port = port_str.parse::<u16>()
                .map_err(|_| ExtrasError::SniffError(format!("Invalid port: {}", port_str)))?;
            
            Ok((host.to_string(), port))
        } else {
            Err(ExtrasError::SniffError("Invalid CONNECT target format".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_http_detection() {
        let sniffer = Sniffer::new(true, 1024);
        
        let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = sniffer.sniff(http_request);
        
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.domain, Some("example.com".to_string()));
        assert_eq!(result.destination_port, Some(80));
    }
    
    #[test]
    fn test_tls_detection() {
        let sniffer = Sniffer::new(true, 1024);
        
        // TLS handshake header
        let tls_data = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let result = sniffer.sniff(&tls_data);
        
        assert_eq!(result.protocol, Protocol::Tls);
        assert_eq!(result.destination_port, Some(443));
    }
    
    #[test]
    fn test_ssh_detection() {
        let sniffer = Sniffer::new(true, 1024);
        
        let ssh_data = b"SSH-2.0-OpenSSH_8.0";
        let result = sniffer.sniff(ssh_data);
        
        assert_eq!(result.protocol, Protocol::Ssh);
        assert_eq!(result.destination_port, Some(22));
    }
    
    #[test]
    fn test_socks5_address_parsing() {
        // IPv4 address: 192.168.1.1:80
        let ipv4_data = vec![0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50];
        let (addr, port) = Socks5AddressParser::parse_address(&ipv4_data).unwrap();
        assert_eq!(addr, "192.168.1.1");
        assert_eq!(port, 80);
        
        // Domain name: example.com:443
        let mut domain_data = vec![0x05, 0x01, 0x00, 0x03, 11]; // 11 = length of "example.com"
        domain_data.extend_from_slice(b"example.com");
        domain_data.extend_from_slice(&[0x01, 0xBB]); // 443 in big-endian
        
        let (addr, port) = Socks5AddressParser::parse_address(&domain_data).unwrap();
        assert_eq!(addr, "example.com");
        assert_eq!(port, 443);
    }
    
    #[test]
    fn test_http_connect_parsing() {
        let connect_data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (host, port) = HttpConnectParser::parse_connect(connect_data).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }
    
    #[test]
    fn test_disabled_sniffer() {
        let sniffer = Sniffer::new(false, 1024);
        
        let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = sniffer.sniff(http_request);
        
        assert_eq!(result.protocol, Protocol::Unknown);
        assert_eq!(result.domain, None);
    }
}