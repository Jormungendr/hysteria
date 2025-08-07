//! Obfuscation mechanisms for Hysteria 2
//!
//! This module provides packet obfuscation to help bypass network filtering.
//! Currently supports the Salamander obfuscation algorithm.

use std::sync::Mutex;
use blake2::{Blake2b, Digest};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use crate::{ExtrasError, Result};

const SALAMANDER_PSK_MIN_LEN: usize = 4;
const SALAMANDER_SALT_LEN: usize = 8;
const SALAMANDER_KEY_LEN: usize = 32; // Blake2b-256

/// Trait for packet obfuscation
pub trait Obfuscator: Send + Sync {
    /// Obfuscate a packet
    /// 
    /// # Arguments
    /// * `input` - Input packet data
    /// * `output` - Output buffer (must be large enough)
    /// 
    /// # Returns
    /// Number of bytes written to output, or 0 if output buffer is too small
    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> usize;
    
    /// Deobfuscate a packet
    /// 
    /// # Arguments
    /// * `input` - Obfuscated packet data
    /// * `output` - Output buffer (must be large enough)
    /// 
    /// # Returns
    /// Number of bytes written to output, or 0 if deobfuscation failed
    fn deobfuscate(&self, input: &[u8], output: &mut [u8]) -> usize;
    
    /// Get the overhead added by obfuscation
    fn overhead(&self) -> usize;
}

/// Salamander obfuscator
/// 
/// Obfuscates each packet with the BLAKE2b-256 hash of a pre-shared key
/// combined with a random salt. Packet format: [8-byte salt][payload]
#[derive(Debug)]
pub struct SalamanderObfuscator {
    psk: Vec<u8>,
    rng: Mutex<StdRng>,
}

impl SalamanderObfuscator {
    /// Create a new Salamander obfuscator
    /// 
    /// # Arguments
    /// * `psk` - Pre-shared key (must be at least 4 bytes)
    pub fn new(psk: Vec<u8>) -> Result<Self> {
        if psk.len() < SALAMANDER_PSK_MIN_LEN {
            return Err(ExtrasError::ObfuscationError(
                format!("PSK must be at least {} bytes", SALAMANDER_PSK_MIN_LEN)
            ));
        }
        
        Ok(Self {
            psk,
            rng: Mutex::new(SeedableRng::from_os_rng()),
        })
    }
    
    /// Generate obfuscation key from salt
    fn generate_key(&self, salt: &[u8]) -> [u8; SALAMANDER_KEY_LEN] {
        let mut hasher = Blake2b::<blake2::digest::typenum::U32>::new();
        hasher.update(&self.psk);
        hasher.update(salt);
        let result = hasher.finalize();
        
        let mut key = [0u8; SALAMANDER_KEY_LEN];
        key.copy_from_slice(&result);
        key
    }
    
    /// XOR data with key
    fn xor_with_key(data: &mut [u8], key: &[u8]) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= key[i % key.len()];
        }
    }
}

impl Obfuscator for SalamanderObfuscator {
    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> usize {
        let output_len = input.len() + SALAMANDER_SALT_LEN;
        if output.len() < output_len {
            return 0;
        }
        
        // Generate random salt
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        {
            let mut rng = self.rng.lock().unwrap();
            rng.fill(&mut salt);
        }
        
        // Copy salt to output
        output[..SALAMANDER_SALT_LEN].copy_from_slice(&salt);
        
        // Copy payload to output
        output[SALAMANDER_SALT_LEN..output_len].copy_from_slice(input);
        
        // Generate key and obfuscate payload
        let key = self.generate_key(&salt);
        Self::xor_with_key(&mut output[SALAMANDER_SALT_LEN..output_len], &key);
        
        output_len
    }
    
    fn deobfuscate(&self, input: &[u8], output: &mut [u8]) -> usize {
        if input.len() < SALAMANDER_SALT_LEN {
            return 0;
        }
        
        let payload_len = input.len() - SALAMANDER_SALT_LEN;
        if output.len() < payload_len {
            return 0;
        }
        
        // Extract salt
        let salt = &input[..SALAMANDER_SALT_LEN];
        
        // Copy obfuscated payload to output
        output[..payload_len].copy_from_slice(&input[SALAMANDER_SALT_LEN..]);
        
        // Generate key and deobfuscate
        let key = self.generate_key(salt);
        Self::xor_with_key(&mut output[..payload_len], &key);
        
        payload_len
    }
    
    fn overhead(&self) -> usize {
        SALAMANDER_SALT_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_salamander_obfuscator_creation() {
        // Test valid PSK
        let psk = b"test_key_1234".to_vec();
        let obfs = SalamanderObfuscator::new(psk);
        assert!(obfs.is_ok());
        
        // Test PSK too short
        let short_psk = b"abc".to_vec();
        let obfs = SalamanderObfuscator::new(short_psk);
        assert!(obfs.is_err());
    }
    
    #[test]
    fn test_salamander_obfuscation() {
        let psk = b"test_key_1234567890".to_vec();
        let obfs = SalamanderObfuscator::new(psk).unwrap();
        
        let input = b"Hello, World! This is a test message.";
        let mut obfuscated = vec![0u8; input.len() + obfs.overhead()];
        let mut deobfuscated = vec![0u8; input.len()];
        
        // Obfuscate
        let obfs_len = obfs.obfuscate(input, &mut obfuscated);
        assert_eq!(obfs_len, input.len() + SALAMANDER_SALT_LEN);
        
        // Deobfuscate
        let deobfs_len = obfs.deobfuscate(&obfuscated[..obfs_len], &mut deobfuscated);
        assert_eq!(deobfs_len, input.len());
        assert_eq!(&deobfuscated[..deobfs_len], input);
    }
    
    #[test]
    fn test_salamander_different_salts() {
        let psk = b"test_key_1234567890".to_vec();
        let obfs = SalamanderObfuscator::new(psk).unwrap();
        
        let input = b"Same message";
        let mut obfuscated1 = vec![0u8; input.len() + obfs.overhead()];
        let mut obfuscated2 = vec![0u8; input.len() + obfs.overhead()];
        
        // Obfuscate same message twice
        let len1 = obfs.obfuscate(input, &mut obfuscated1);
        let len2 = obfs.obfuscate(input, &mut obfuscated2);
        
        assert_eq!(len1, len2);
        // Should be different due to different salts
        assert_ne!(obfuscated1, obfuscated2);
        
        // But both should deobfuscate to the same original message
        let mut deobfs1 = vec![0u8; input.len()];
        let mut deobfs2 = vec![0u8; input.len()];
        
        let deobfs_len1 = obfs.deobfuscate(&obfuscated1[..len1], &mut deobfs1);
        let deobfs_len2 = obfs.deobfuscate(&obfuscated2[..len2], &mut deobfs2);
        
        assert_eq!(deobfs_len1, input.len());
        assert_eq!(deobfs_len2, input.len());
        assert_eq!(&deobfs1[..deobfs_len1], input);
        assert_eq!(&deobfs2[..deobfs_len2], input);
    }
    
    #[test]
    fn test_salamander_buffer_too_small() {
        let psk = b"test_key_1234567890".to_vec();
        let obfs = SalamanderObfuscator::new(psk).unwrap();
        
        let input = b"Test message";
        let mut small_buffer = vec![0u8; input.len()]; // Too small for obfuscation
        
        let result = obfs.obfuscate(input, &mut small_buffer);
        assert_eq!(result, 0); // Should return 0 for insufficient buffer
    }
}