//! Obfuscation module for Hysteria protocol
//!
//! Implements the "Salamander" obfuscation layer that encapsulates
//! QUIC packets to make them appear as random data.

use crate::{HysteriaError, Result};
use blake2::{Blake2b, Digest};
use bytes::{Bytes, BytesMut, BufMut};
use rand::RngCore;
use std::sync::Arc;

/// Salamander obfuscator
#[derive(Debug, Clone)]
pub struct SalamanderObfuscator {
    key: Arc<[u8]>,
}

/// Salamander deobfuscator
#[derive(Debug, Clone)]
pub struct SalamanderDeobfuscator {
    key: Arc<[u8]>,
}

/// Salt size for Salamander obfuscation (8 bytes)
const SALT_SIZE: usize = 8;

/// Hash size for BLAKE2b-256 (32 bytes)
const HASH_SIZE: usize = 32;

impl SalamanderObfuscator {
    /// Create a new Salamander obfuscator with the given key
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into().into(),
        }
    }

    /// Obfuscate a QUIC packet
    pub fn obfuscate(&self, payload: &[u8]) -> Result<Bytes> {
        // Generate random salt
        let mut salt = [0u8; SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);

        // Calculate BLAKE2b-256 hash of key + salt
        let hash = self.calculate_hash(&salt)?;

        // Create output buffer
        let mut output = BytesMut::with_capacity(SALT_SIZE + payload.len());
        
        // Write salt
        output.put_slice(&salt);
        
        // Obfuscate payload using XOR with hash
        for (i, &byte) in payload.iter().enumerate() {
            let obfuscated_byte = byte ^ hash[i % HASH_SIZE];
            output.put_u8(obfuscated_byte);
        }

        Ok(output.freeze())
    }

    /// Calculate BLAKE2b-256 hash of key + salt
    fn calculate_hash(&self, salt: &[u8]) -> Result<[u8; HASH_SIZE]> {
        let mut hasher = Blake2b::<blake2::digest::consts::U32>::new();
        hasher.update(&self.key);
        hasher.update(salt);
        
        let result = hasher.finalize();
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

impl SalamanderDeobfuscator {
    /// Create a new Salamander deobfuscator with the given key
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into().into(),
        }
    }

    /// Deobfuscate a Salamander-obfuscated packet
    pub fn deobfuscate(&self, data: &[u8]) -> Result<Bytes> {
        if data.len() < SALT_SIZE {
            return Err(HysteriaError::obfuscation(
                "Data too short to contain salt".to_string(),
            ));
        }

        // Extract salt from the first 8 bytes
        let salt = &data[..SALT_SIZE];
        let obfuscated_payload = &data[SALT_SIZE..];

        // Calculate BLAKE2b-256 hash of key + salt
        let hash = self.calculate_hash(salt)?;

        // Deobfuscate payload using XOR with hash
        let mut payload = BytesMut::with_capacity(obfuscated_payload.len());
        for (i, &byte) in obfuscated_payload.iter().enumerate() {
            let deobfuscated_byte = byte ^ hash[i % HASH_SIZE];
            payload.put_u8(deobfuscated_byte);
        }

        Ok(payload.freeze())
    }

    /// Calculate BLAKE2b-256 hash of key + salt
    fn calculate_hash(&self, salt: &[u8]) -> Result<[u8; HASH_SIZE]> {
        let mut hasher = Blake2b::<blake2::digest::consts::U32>::new();
        hasher.update(&self.key);
        hasher.update(salt);
        
        let result = hasher.finalize();
        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&result);
        Ok(hash)
    }
}

/// Salamander obfuscation configuration
#[derive(Debug, Clone)]
pub struct SalamanderConfig {
    /// Pre-shared key for obfuscation
    pub key: Vec<u8>,
}

impl SalamanderConfig {
    /// Create a new Salamander configuration with the given key
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// Create a new Salamander configuration from a password string
    pub fn from_password(password: &str) -> Self {
        Self {
            key: password.as_bytes().to_vec(),
        }
    }

    /// Create an obfuscator from this configuration
    pub fn create_obfuscator(&self) -> SalamanderObfuscator {
        SalamanderObfuscator::new(self.key.clone())
    }

    /// Create a deobfuscator from this configuration
    pub fn create_deobfuscator(&self) -> SalamanderDeobfuscator {
        SalamanderDeobfuscator::new(self.key.clone())
    }
}

/// Trait for packet obfuscation
pub trait PacketObfuscator: Send + Sync {
    /// Obfuscate a packet
    fn obfuscate(&self, packet: &[u8]) -> Result<Bytes>;
}

/// Trait for packet deobfuscation
pub trait PacketDeobfuscator: Send + Sync {
    /// Deobfuscate a packet
    fn deobfuscate(&self, packet: &[u8]) -> Result<Bytes>;
}

impl PacketObfuscator for SalamanderObfuscator {
    fn obfuscate(&self, packet: &[u8]) -> Result<Bytes> {
        self.obfuscate(packet)
    }
}

impl PacketDeobfuscator for SalamanderDeobfuscator {
    fn deobfuscate(&self, packet: &[u8]) -> Result<Bytes> {
        self.deobfuscate(packet)
    }
}

/// No-op obfuscator that passes packets through unchanged
#[derive(Debug, Clone, Default)]
pub struct NoOpObfuscator;

impl PacketObfuscator for NoOpObfuscator {
    fn obfuscate(&self, packet: &[u8]) -> Result<Bytes> {
        Ok(Bytes::copy_from_slice(packet))
    }
}

impl PacketDeobfuscator for NoOpObfuscator {
    fn deobfuscate(&self, packet: &[u8]) -> Result<Bytes> {
        Ok(Bytes::copy_from_slice(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salamander_obfuscation_roundtrip() {
        let key = b"test_key_12345678";
        let obfuscator = SalamanderObfuscator::new(key.to_vec());
        let deobfuscator = SalamanderDeobfuscator::new(key.to_vec());
        
        let original_data = b"Hello, Hysteria! This is a test packet.";
        
        // Obfuscate
        let obfuscated = obfuscator.obfuscate(original_data).unwrap();
        
        // Verify obfuscated data is different and longer (due to salt)
        assert_ne!(obfuscated.as_ref(), original_data);
        assert_eq!(obfuscated.len(), original_data.len() + SALT_SIZE);
        
        // Deobfuscate
        let deobfuscated = deobfuscator.deobfuscate(&obfuscated).unwrap();
        
        // Verify roundtrip
        assert_eq!(deobfuscated.as_ref(), original_data);
    }

    #[test]
    fn test_salamander_different_keys() {
        let key1 = b"key1";
        let key2 = b"key2";
        
        let obfuscator = SalamanderObfuscator::new(key1.to_vec());
        let deobfuscator = SalamanderDeobfuscator::new(key2.to_vec());
        
        let original_data = b"Test data";
        let obfuscated = obfuscator.obfuscate(original_data).unwrap();
        let deobfuscated = deobfuscator.deobfuscate(&obfuscated).unwrap();
        
        // Should not match with different keys
        assert_ne!(deobfuscated.as_ref(), original_data);
    }

    #[test]
    fn test_salamander_config() {
        let config = SalamanderConfig::from_password("test_password");
        let obfuscator = config.create_obfuscator();
        let deobfuscator = config.create_deobfuscator();
        
        let data = b"Configuration test";
        let obfuscated = obfuscator.obfuscate(data).unwrap();
        let deobfuscated = deobfuscator.deobfuscate(&obfuscated).unwrap();
        
        assert_eq!(deobfuscated.as_ref(), data);
    }

    #[test]
    fn test_deobfuscate_short_data() {
        let deobfuscator = SalamanderDeobfuscator::new(b"key".to_vec());
        let short_data = b"short"; // Less than SALT_SIZE
        
        let result = deobfuscator.deobfuscate(short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_op_obfuscator() {
        let obfuscator = NoOpObfuscator;
        let data = b"test data";
        
        let obfuscated = obfuscator.obfuscate(data).unwrap();
        let deobfuscated = obfuscator.deobfuscate(&obfuscated).unwrap();
        
        assert_eq!(obfuscated.as_ref(), data);
        assert_eq!(deobfuscated.as_ref(), data);
    }

    #[test]
    fn test_salamander_deterministic_with_same_salt() {
        let key = b"test_key";
        let obfuscator = SalamanderObfuscator::new(key.to_vec());
        let data = b"test data";
        
        // Multiple obfuscations should produce different results due to random salt
        let obfuscated1 = obfuscator.obfuscate(data).unwrap();
        let obfuscated2 = obfuscator.obfuscate(data).unwrap();
        
        // Should be different due to different salts
        assert_ne!(obfuscated1, obfuscated2);
        
        // But both should deobfuscate to the same original data
        let deobfuscator = SalamanderDeobfuscator::new(key.to_vec());
        let deobfuscated1 = deobfuscator.deobfuscate(&obfuscated1).unwrap();
        let deobfuscated2 = deobfuscator.deobfuscate(&obfuscated2).unwrap();
        
        assert_eq!(deobfuscated1.as_ref(), data);
        assert_eq!(deobfuscated2.as_ref(), data);
    }
}