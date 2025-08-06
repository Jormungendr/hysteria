//! UDP session management for Hysteria protocol
//!
//! Handles UDP packet fragmentation, reassembly, and session management
//! as specified in the Hysteria 2 protocol.

use crate::{HysteriaError, Result, protocol::UdpMessage};
use bytes::Bytes;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use std::sync::Arc;

/// UDP session manager
#[derive(Debug)]
pub struct UdpSessionManager {
    sessions: Arc<RwLock<HashMap<u32, UdpSession>>>,
    fragments: Arc<RwLock<HashMap<FragmentKey, FragmentBuffer>>>,
    session_timeout: Duration,
    fragment_timeout: Duration,
    max_sessions: usize,
}

/// UDP session information
#[derive(Debug, Clone)]
pub struct UdpSession {
    pub session_id: u32,
    pub address: String,
    pub last_activity: Instant,
    pub packet_count: u64,
    pub byte_count: u64,
}

/// Fragment key for packet reassembly
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FragmentKey {
    session_id: u32,
    packet_id: u16,
}

/// Fragment buffer for packet reassembly
#[derive(Debug)]
struct FragmentBuffer {
    fragments: HashMap<u8, Bytes>, // fragment_id -> payload
    total_fragments: u8,
    address: String,
    created_at: Instant,
}

/// UDP packet fragmentation configuration
#[derive(Debug, Clone)]
pub struct FragmentationConfig {
    /// Maximum datagram size for QUIC
    pub max_datagram_size: usize,
    /// Maximum fragment size (excluding headers)
    pub max_fragment_size: usize,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self {
            max_datagram_size: 1200, // Conservative QUIC datagram size
            max_fragment_size: 1100,  // Leave room for UDP message headers
        }
    }
}

/// Fragmented UDP packet
#[derive(Debug, Clone)]
pub struct FragmentedPacket {
    pub fragments: Vec<UdpMessage>,
}

impl UdpSessionManager {
    /// Create a new UDP session manager
    pub fn new(
        session_timeout: Duration,
        fragment_timeout: Duration,
        max_sessions: usize,
    ) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            fragments: Arc::new(RwLock::new(HashMap::new())),
            session_timeout,
            fragment_timeout,
            max_sessions,
        }
    }

    /// Create or update a UDP session
    pub async fn create_or_update_session(
        &self,
        session_id: u32,
        address: String,
    ) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        // Check session limit
        if sessions.len() >= self.max_sessions && !sessions.contains_key(&session_id) {
            // Remove oldest session
            if let Some(oldest_id) = self.find_oldest_session(&sessions).await {
                sessions.remove(&oldest_id);
            }
        }
        
        let session = sessions.entry(session_id).or_insert_with(|| UdpSession {
            session_id,
            address: address.clone(),
            last_activity: Instant::now(),
            packet_count: 0,
            byte_count: 0,
        });
        
        session.last_activity = Instant::now();
        session.address = address; // Update address in case it changed
        
        Ok(())
    }

    /// Get session information
    pub async fn get_session(&self, session_id: u32) -> Option<UdpSession> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id).cloned()
    }

    /// Update session statistics
    pub async fn update_session_stats(&self, session_id: u32, bytes: u64) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(&session_id) {
            session.last_activity = Instant::now();
            session.packet_count += 1;
            session.byte_count += bytes;
        }
        
        Ok(())
    }

    /// Process incoming UDP message (handle fragmentation)
    pub async fn process_message(&self, message: UdpMessage) -> Result<Option<Bytes>> {
        // Update session
        self.create_or_update_session(message.session_id, message.address.clone())
            .await?;
        
        // Update statistics
        self.update_session_stats(message.session_id, message.payload.len() as u64)
            .await?;
        
        if message.fragment_count == 1 {
            // Non-fragmented packet
            return Ok(Some(message.payload));
        }
        
        // Handle fragmented packet
        self.handle_fragment(message).await
    }

    /// Handle a fragmented packet
    async fn handle_fragment(&self, message: UdpMessage) -> Result<Option<Bytes>> {
        let fragment_key = FragmentKey {
            session_id: message.session_id,
            packet_id: message.packet_id,
        };
        
        let mut fragments = self.fragments.write().await;
        
        let buffer = fragments.entry(fragment_key.clone()).or_insert_with(|| {
            FragmentBuffer {
                fragments: HashMap::new(),
                total_fragments: message.fragment_count,
                address: message.address.clone(),
                created_at: Instant::now(),
            }
        });
        
        // Add fragment to buffer
        buffer.fragments.insert(message.fragment_id, message.payload);
        
        // Check if all fragments are received
        if buffer.fragments.len() == buffer.total_fragments as usize {
            // Reassemble packet
            let mut reassembled = Vec::new();
            for i in 0..buffer.total_fragments {
                if let Some(fragment) = buffer.fragments.get(&i) {
                    reassembled.extend_from_slice(fragment);
                } else {
                    return Err(HysteriaError::udp_session(
                        "Missing fragment during reassembly".to_string(),
                    ));
                }
            }
            
            // Remove completed buffer
            fragments.remove(&fragment_key);
            
            Ok(Some(Bytes::from(reassembled)))
        } else {
            // Still waiting for more fragments
            Ok(None)
        }
    }

    /// Fragment a large UDP packet
    pub fn fragment_packet(
        &self,
        session_id: u32,
        packet_id: u16,
        address: String,
        payload: Bytes,
        config: &FragmentationConfig,
    ) -> Result<FragmentedPacket> {
        if payload.len() <= config.max_fragment_size {
            // No fragmentation needed
            return Ok(FragmentedPacket {
                fragments: vec![UdpMessage::single(session_id, address, payload)],
            });
        }
        
        let mut fragments = Vec::new();
        let total_fragments = (payload.len() + config.max_fragment_size - 1) / config.max_fragment_size;
        
        if total_fragments > 255 {
            return Err(HysteriaError::udp_session(
                "Packet too large to fragment (would require > 255 fragments)".to_string(),
            ));
        }
        
        for (i, chunk) in payload.chunks(config.max_fragment_size).enumerate() {
            let fragment = UdpMessage::new(
                session_id,
                packet_id,
                i as u8,
                total_fragments as u8,
                address.clone(),
                Bytes::copy_from_slice(chunk),
            );
            fragments.push(fragment);
        }
        
        Ok(FragmentedPacket { fragments })
    }

    /// Clean up expired sessions and fragments
    pub async fn cleanup_expired(&self) -> Result<()> {
        let now = Instant::now();
        
        // Clean up expired sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                now.duration_since(session.last_activity) < self.session_timeout
            });
        }
        
        // Clean up expired fragments
        {
            let mut fragments = self.fragments.write().await;
            fragments.retain(|_, buffer| {
                now.duration_since(buffer.created_at) < self.fragment_timeout
            });
        }
        
        Ok(())
    }

    /// Get session statistics
    pub async fn get_session_stats(&self) -> HashMap<u32, UdpSession> {
        let sessions = self.sessions.read().await;
        sessions.clone()
    }

    /// Remove a specific session
    pub async fn remove_session(&self, session_id: u32) -> Option<UdpSession> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(&session_id)
    }

    /// Find the oldest session for cleanup
    async fn find_oldest_session(&self, sessions: &HashMap<u32, UdpSession>) -> Option<u32> {
        sessions
            .iter()
            .min_by_key(|(_, session)| session.last_activity)
            .map(|(id, _)| *id)
    }

    /// Get current session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Get current fragment buffer count
    pub async fn fragment_buffer_count(&self) -> usize {
        let fragments = self.fragments.read().await;
        fragments.len()
    }
}

/// UDP session configuration
#[derive(Debug, Clone)]
pub struct UdpSessionConfig {
    /// Session timeout duration
    pub session_timeout: Duration,
    /// Fragment reassembly timeout
    pub fragment_timeout: Duration,
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Fragmentation configuration
    pub fragmentation: FragmentationConfig,
}

impl Default for UdpSessionConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(60),
            fragment_timeout: Duration::from_secs(10),
            max_sessions: 1000,
            fragmentation: FragmentationConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_udp_session_creation() {
        let manager = UdpSessionManager::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            100,
        );
        
        manager
            .create_or_update_session(123, "example.com:80".to_string())
            .await
            .unwrap();
        
        let session = manager.get_session(123).await.unwrap();
        assert_eq!(session.session_id, 123);
        assert_eq!(session.address, "example.com:80");
    }

    #[tokio::test]
    async fn test_non_fragmented_message() {
        let manager = UdpSessionManager::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            100,
        );
        
        let message = UdpMessage::single(
            123,
            "example.com:80".to_string(),
            Bytes::from_static(b"test payload"),
        );
        
        let result = manager.process_message(message).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), Bytes::from_static(b"test payload"));
    }

    #[tokio::test]
    async fn test_fragmented_message() {
        let manager = UdpSessionManager::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            100,
        );
        
        // Send fragments out of order
        let fragment2 = UdpMessage::new(
            123,
            1,
            1,
            2,
            "example.com:80".to_string(),
            Bytes::from_static(b"world"),
        );
        
        let fragment1 = UdpMessage::new(
            123,
            1,
            0,
            2,
            "example.com:80".to_string(),
            Bytes::from_static(b"hello"),
        );
        
        // First fragment should return None (incomplete)
        let result1 = manager.process_message(fragment2).await.unwrap();
        assert!(result1.is_none());
        
        // Second fragment should return complete message
        let result2 = manager.process_message(fragment1).await.unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap(), Bytes::from_static(b"helloworld"));
    }

    #[test]
    fn test_packet_fragmentation() {
        let manager = UdpSessionManager::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            100,
        );
        
        let config = FragmentationConfig {
            max_datagram_size: 100,
            max_fragment_size: 10,
        };
        
        let large_payload = Bytes::from(vec![0u8; 25]); // 25 bytes
        
        let fragmented = manager
            .fragment_packet(123, 1, "example.com:80".to_string(), large_payload, &config)
            .unwrap();
        
        assert_eq!(fragmented.fragments.len(), 3); // 25 bytes / 10 = 3 fragments
        
        // Check fragment properties
        for (i, fragment) in fragmented.fragments.iter().enumerate() {
            assert_eq!(fragment.session_id, 123);
            assert_eq!(fragment.packet_id, 1);
            assert_eq!(fragment.fragment_id, i as u8);
            assert_eq!(fragment.fragment_count, 3);
        }
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let manager = UdpSessionManager::new(
            Duration::from_millis(100), // Very short timeout
            Duration::from_secs(10),
            100,
        );
        
        manager
            .create_or_update_session(123, "example.com:80".to_string())
            .await
            .unwrap();
        
        assert_eq!(manager.session_count().await, 1);
        
        // Wait for session to expire
        sleep(Duration::from_millis(150)).await;
        
        manager.cleanup_expired().await.unwrap();
        assert_eq!(manager.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_session_limit() {
        let manager = UdpSessionManager::new(
            Duration::from_secs(60),
            Duration::from_secs(10),
            2, // Limit to 2 sessions
        );
        
        // Create 3 sessions
        manager
            .create_or_update_session(1, "example1.com:80".to_string())
            .await
            .unwrap();
        manager
            .create_or_update_session(2, "example2.com:80".to_string())
            .await
            .unwrap();
        manager
            .create_or_update_session(3, "example3.com:80".to_string())
            .await
            .unwrap();
        
        // Should only have 2 sessions (oldest one removed)
        assert_eq!(manager.session_count().await, 2);
    }
}