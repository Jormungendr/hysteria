//! Protocol message definitions and encoding/decoding for Hysteria 2
//!
//! This module implements the wire format for TCP and UDP messages
//! as specified in the Hysteria 2 protocol.

use crate::{HysteriaError, Result, TCP_REQUEST_ID};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{Cursor, Read, Write};

/// TCP request message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    /// Target address (host:port)
    pub address: String,
    /// Random padding
    pub padding: Bytes,
}

/// TCP response message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    /// Response status (0x00 = OK, 0x01 = Error)
    pub status: u8,
    /// Status message
    pub message: String,
    /// Random padding
    pub padding: Bytes,
}

/// UDP message
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    /// Session ID for UDP session management
    pub session_id: u32,
    /// Packet ID for fragmentation
    pub packet_id: u16,
    /// Fragment ID (starting from 0)
    pub fragment_id: u8,
    /// Total fragment count
    pub fragment_count: u8,
    /// Target address (host:port)
    pub address: String,
    /// UDP payload
    pub payload: Bytes,
}

impl TcpRequest {
    /// Create a new TCP request
    pub fn new(address: String, padding: Option<Bytes>) -> Self {
        Self {
            address,
            padding: padding.unwrap_or_else(|| generate_random_padding()),
        }
    }

    /// Encode TCP request to bytes
    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        
        // Write request ID as varint
        write_varint(&mut buf, TCP_REQUEST_ID)?;
        
        // Write address length and address
        let address_bytes = self.address.as_bytes();
        write_varint(&mut buf, address_bytes.len() as u64)?;
        buf.put_slice(address_bytes);
        
        // Write padding length and padding
        write_varint(&mut buf, self.padding.len() as u64)?;
        buf.put_slice(&self.padding);
        
        Ok(buf.freeze())
    }

    /// Decode TCP request from bytes
    pub fn decode(mut data: Bytes) -> Result<Self> {
        let mut cursor = Cursor::new(&data[..]);
        
        // Read and verify request ID
        let request_id = read_varint(&mut cursor)?;
        if request_id != TCP_REQUEST_ID {
            return Err(HysteriaError::protocol(format!(
                "Invalid TCP request ID: expected {}, got {}",
                TCP_REQUEST_ID, request_id
            )));
        }
        
        // Read address
        let address_len = read_varint(&mut cursor)? as usize;
        let mut address_bytes = vec![0u8; address_len];
        cursor.read_exact(&mut address_bytes)?;
        let address = String::from_utf8(address_bytes)
            .map_err(|e| HysteriaError::protocol(format!("Invalid address UTF-8: {}", e)))?;
        
        // Read padding
        let padding_len = read_varint(&mut cursor)? as usize;
        let mut padding_bytes = vec![0u8; padding_len];
        cursor.read_exact(&mut padding_bytes)?;
        let padding = Bytes::from(padding_bytes);
        
        Ok(Self { address, padding })
    }
}

impl TcpResponse {
    /// Create a new TCP response
    pub fn new(status: u8, message: String, padding: Option<Bytes>) -> Self {
        Self {
            status,
            message,
            padding: padding.unwrap_or_else(|| generate_random_padding()),
        }
    }

    /// Create a successful TCP response
    pub fn ok(message: String) -> Self {
        Self::new(crate::message_types::tcp_status::OK, message, None)
    }

    /// Create an error TCP response
    pub fn error(message: String) -> Self {
        Self::new(crate::message_types::tcp_status::ERROR, message, None)
    }

    /// Encode TCP response to bytes
    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        
        // Write status
        buf.put_u8(self.status);
        
        // Write message length and message
        let message_bytes = self.message.as_bytes();
        write_varint(&mut buf, message_bytes.len() as u64)?;
        buf.put_slice(message_bytes);
        
        // Write padding length and padding
        write_varint(&mut buf, self.padding.len() as u64)?;
        buf.put_slice(&self.padding);
        
        Ok(buf.freeze())
    }

    /// Decode TCP response from bytes
    pub fn decode(data: Bytes) -> Result<Self> {
        let mut cursor = Cursor::new(&data[..]);
        
        // Read status
        let status = cursor.read_u8()?;
        
        // Read message
        let message_len = read_varint(&mut cursor)? as usize;
        let mut message_bytes = vec![0u8; message_len];
        cursor.read_exact(&mut message_bytes)?;
        let message = String::from_utf8(message_bytes)
            .map_err(|e| HysteriaError::protocol(format!("Invalid message UTF-8: {}", e)))?;
        
        // Read padding
        let padding_len = read_varint(&mut cursor)? as usize;
        let mut padding_bytes = vec![0u8; padding_len];
        cursor.read_exact(&mut padding_bytes)?;
        let padding = Bytes::from(padding_bytes);
        
        Ok(Self {
            status,
            message,
            padding,
        })
    }
}

impl UdpMessage {
    /// Create a new UDP message
    pub fn new(
        session_id: u32,
        packet_id: u16,
        fragment_id: u8,
        fragment_count: u8,
        address: String,
        payload: Bytes,
    ) -> Self {
        Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            payload,
        }
    }

    /// Create a non-fragmented UDP message
    pub fn single(session_id: u32, address: String, payload: Bytes) -> Self {
        Self::new(session_id, 0, 0, 1, address, payload)
    }

    /// Check if this message is fragmented
    pub fn is_fragmented(&self) -> bool {
        self.fragment_count > 1
    }

    /// Encode UDP message to bytes
    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        
        // Write session ID (4 bytes, big endian)
        buf.put_u32(self.session_id);
        
        // Write packet ID (2 bytes, big endian)
        buf.put_u16(self.packet_id);
        
        // Write fragment ID (1 byte)
        buf.put_u8(self.fragment_id);
        
        // Write fragment count (1 byte)
        buf.put_u8(self.fragment_count);
        
        // Write address length and address
        let address_bytes = self.address.as_bytes();
        write_varint(&mut buf, address_bytes.len() as u64)?;
        buf.put_slice(address_bytes);
        
        // Write payload
        buf.put_slice(&self.payload);
        
        Ok(buf.freeze())
    }

    /// Decode UDP message from bytes
    pub fn decode(data: Bytes) -> Result<Self> {
        let mut cursor = Cursor::new(&data[..]);
        
        // Read session ID
        let session_id = cursor.read_u32::<BigEndian>()?;
        
        // Read packet ID
        let packet_id = cursor.read_u16::<BigEndian>()?;
        
        // Read fragment ID
        let fragment_id = cursor.read_u8()?;
        
        // Read fragment count
        let fragment_count = cursor.read_u8()?;
        
        // Read address
        let address_len = read_varint(&mut cursor)? as usize;
        let mut address_bytes = vec![0u8; address_len];
        cursor.read_exact(&mut address_bytes)?;
        let address = String::from_utf8(address_bytes)
            .map_err(|e| HysteriaError::protocol(format!("Invalid address UTF-8: {}", e)))?;
        
        // Read remaining bytes as payload
        let position = cursor.position() as usize;
        let payload = data.slice(position..);
        
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
            payload,
        })
    }
}

/// Write a varint to the buffer
fn write_varint(buf: &mut BytesMut, mut value: u64) -> Result<()> {
    while value >= 0x80 {
        buf.put_u8((value as u8) | 0x80);
        value >>= 7;
    }
    buf.put_u8(value as u8);
    Ok(())
}

/// Read a varint from the cursor
fn read_varint<R: Read>(cursor: &mut R) -> Result<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    
    loop {
        let byte = cursor.read_u8()?;
        result |= ((byte & 0x7F) as u64) << shift;
        
        if byte & 0x80 == 0 {
            break;
        }
        
        shift += 7;
        if shift >= 64 {
            return Err(HysteriaError::protocol("Varint too large".to_string()));
        }
    }
    
    Ok(result)
}

/// Generate random padding bytes
fn generate_random_padding() -> Bytes {
    use rand::{Rng, RngCore};
    
    let length = rand::rng().random_range(8..=64);
    let mut padding = vec![0u8; length];
    rand::rng().fill_bytes(&mut padding);
    Bytes::from(padding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0).unwrap();
        write_varint(&mut buf, 127).unwrap();
        write_varint(&mut buf, 128).unwrap();
        write_varint(&mut buf, 16383).unwrap();
        
        let mut cursor = Cursor::new(&buf[..]);
        assert_eq!(read_varint(&mut cursor).unwrap(), 0);
        assert_eq!(read_varint(&mut cursor).unwrap(), 127);
        assert_eq!(read_varint(&mut cursor).unwrap(), 128);
        assert_eq!(read_varint(&mut cursor).unwrap(), 16383);
    }

    #[test]
    fn test_tcp_request_encoding() {
        let request = TcpRequest::new(
            "example.com:80".to_string(),
            Some(Bytes::from_static(b"test_padding")),
        );
        
        let encoded = request.encode().unwrap();
        let decoded = TcpRequest::decode(encoded).unwrap();
        
        assert_eq!(request, decoded);
    }

    #[test]
    fn test_tcp_response_encoding() {
        let response = TcpResponse::ok("Connection established".to_string());
        
        let encoded = response.encode().unwrap();
        let decoded = TcpResponse::decode(encoded).unwrap();
        
        assert_eq!(response.status, decoded.status);
        assert_eq!(response.message, decoded.message);
    }

    #[test]
    fn test_udp_message_encoding() {
        let message = UdpMessage::single(
            12345,
            "example.com:53".to_string(),
            Bytes::from_static(b"DNS query"),
        );
        
        let encoded = message.encode().unwrap();
        let decoded = UdpMessage::decode(encoded).unwrap();
        
        assert_eq!(message, decoded);
    }

    #[test]
    fn test_fragmented_udp_message() {
        let message = UdpMessage::new(
            12345,
            1,
            0,
            3,
            "example.com:53".to_string(),
            Bytes::from_static(b"Fragment 1"),
        );
        
        assert!(message.is_fragmented());
        
        let encoded = message.encode().unwrap();
        let decoded = UdpMessage::decode(encoded).unwrap();
        
        assert_eq!(message, decoded);
    }
}