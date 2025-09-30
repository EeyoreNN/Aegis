// Message protocol format for Aegis
// Wire format: [Version:1][Type:1][Timestamp:8][KeyID:2][Nonce:24][Ciphertext:N][Tag:16]

use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::kyber::{PublicKey, Ciphertext as KyberCiphertext};
use super::NetworkError;

const CURRENT_PROTOCOL_VERSION: u8 = 1;
const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB limit

/// Protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u8);

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self(CURRENT_PROTOCOL_VERSION)
    }
}

/// Message types in the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Initial handshake with public key exchange
    Handshake = 0x01,

    /// Key exchange response
    HandshakeResponse = 0x02,

    /// Regular encrypted message
    EncryptedMessage = 0x03,

    /// Key rotation notification
    KeyRotation = 0x04,

    /// Acknowledgement
    Ack = 0x05,

    /// Heartbeat/keepalive
    Heartbeat = 0x06,

    /// Disconnect notification
    Disconnect = 0x07,

    /// Error message
    Error = 0xFF,
}

impl TryFrom<u8> for MessageType {
    type Error = NetworkError;

    fn try_from(value: u8) -> Result<Self, <MessageType as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(MessageType::Handshake),
            0x02 => Ok(MessageType::HandshakeResponse),
            0x03 => Ok(MessageType::EncryptedMessage),
            0x04 => Ok(MessageType::KeyRotation),
            0x05 => Ok(MessageType::Ack),
            0x06 => Ok(MessageType::Heartbeat),
            0x07 => Ok(MessageType::Disconnect),
            0xFF => Ok(MessageType::Error),
            _ => Err(NetworkError::ProtocolError(format!("Unknown message type: {}", value))),
        }
    }
}

/// Wire format message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Protocol version
    pub version: ProtocolVersion,

    /// Message type
    pub message_type: MessageType,

    /// Unix timestamp in seconds
    pub timestamp: u64,

    /// Key ID for key rotation tracking (0 for handshake messages)
    pub key_id: u16,

    /// Message payload
    pub payload: MessagePayload,
}

/// Message payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    /// Handshake with Kyber public key
    Handshake {
        public_key: Vec<u8>,
    },

    /// Handshake response with Kyber ciphertext
    HandshakeResponse {
        ciphertext: Vec<u8>,
    },

    /// Encrypted message data
    EncryptedData {
        nonce: [u8; 24],
        ciphertext: Vec<u8>,
        message_counter: u64,
    },

    /// Key rotation notification
    KeyRotation {
        new_key_id: u16,
    },

    /// Acknowledgement with message ID
    Ack {
        message_id: u64,
    },

    /// Heartbeat (empty payload)
    Heartbeat,

    /// Disconnect with optional reason
    Disconnect {
        reason: Option<String>,
    },

    /// Error with description
    Error {
        code: u16,
        message: String,
    },
}

impl Message {
    /// Create a new message with current timestamp
    pub fn new(message_type: MessageType, payload: MessagePayload) -> Self {
        Self {
            version: ProtocolVersion::default(),
            message_type,
            timestamp: current_timestamp(),
            key_id: 0,
            payload,
        }
    }

    /// Create a handshake message
    pub fn handshake(public_key: PublicKey) -> Self {
        Self::new(
            MessageType::Handshake,
            MessagePayload::Handshake {
                public_key: public_key.as_bytes().to_vec(),
            },
        )
    }

    /// Create a handshake response
    pub fn handshake_response(ciphertext: KyberCiphertext) -> Self {
        Self::new(
            MessageType::HandshakeResponse,
            MessagePayload::HandshakeResponse {
                ciphertext: ciphertext.as_bytes().to_vec(),
            },
        )
    }

    /// Create an encrypted message
    pub fn encrypted(nonce: [u8; 24], ciphertext: Vec<u8>, message_counter: u64, key_id: u16) -> Self {
        let mut msg = Self::new(
            MessageType::EncryptedMessage,
            MessagePayload::EncryptedData {
                nonce,
                ciphertext,
                message_counter,
            },
        );
        msg.key_id = key_id;
        msg
    }

    /// Create a heartbeat message
    pub fn heartbeat() -> Self {
        Self::new(MessageType::Heartbeat, MessagePayload::Heartbeat)
    }

    /// Create a disconnect message
    pub fn disconnect(reason: Option<String>) -> Self {
        Self::new(
            MessageType::Disconnect,
            MessagePayload::Disconnect { reason },
        )
    }

    /// Create an error message
    pub fn error(code: u16, message: String) -> Self {
        Self::new(
            MessageType::Error,
            MessagePayload::Error { code, message },
        )
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, NetworkError> {
        bincode::serialize(self)
            .map_err(|e| NetworkError::SerializationError(format!("Serialization failed: {}", e)))
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetworkError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(NetworkError::ProtocolError("Message too large".to_string()));
        }

        bincode::deserialize(bytes)
            .map_err(|e| NetworkError::SerializationError(format!("Deserialization failed: {}", e)))
    }

    /// Validate message structure
    pub fn validate(&self) -> Result<(), NetworkError> {
        // Check version
        if self.version.0 > CURRENT_PROTOCOL_VERSION {
            return Err(NetworkError::ProtocolError(
                format!("Unsupported protocol version: {}", self.version.0)
            ));
        }

        // Check timestamp (allow up to 5 minutes of clock skew)
        let now = current_timestamp();
        let max_skew = 300; // 5 minutes
        if self.timestamp > now + max_skew {
            return Err(NetworkError::ProtocolError("Timestamp too far in the future".to_string()));
        }

        // Validate payload based on message type
        match (&self.message_type, &self.payload) {
            (MessageType::Handshake, MessagePayload::Handshake { .. }) => Ok(()),
            (MessageType::HandshakeResponse, MessagePayload::HandshakeResponse { .. }) => Ok(()),
            (MessageType::EncryptedMessage, MessagePayload::EncryptedData { .. }) => Ok(()),
            (MessageType::KeyRotation, MessagePayload::KeyRotation { .. }) => Ok(()),
            (MessageType::Ack, MessagePayload::Ack { .. }) => Ok(()),
            (MessageType::Heartbeat, MessagePayload::Heartbeat) => Ok(()),
            (MessageType::Disconnect, MessagePayload::Disconnect { .. }) => Ok(()),
            (MessageType::Error, MessagePayload::Error { .. }) => Ok(()),
            _ => Err(NetworkError::ProtocolError("Message type and payload mismatch".to_string())),
        }
    }

    /// Check if message is recent (within last 60 seconds)
    pub fn is_recent(&self) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.timestamp) < 60
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Frame a message for transmission (add length prefix)
pub fn frame_message(message: &Message) -> Result<Vec<u8>, NetworkError> {
    let message_bytes = message.to_bytes()?;
    let len = message_bytes.len() as u32;

    let mut framed = Vec::with_capacity(4 + message_bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&message_bytes);

    Ok(framed)
}

/// Parse a framed message (extract from length-prefixed format)
pub fn parse_framed_message(data: &[u8]) -> Result<(Message, usize), NetworkError> {
    if data.len() < 4 {
        return Err(NetworkError::ProtocolError("Insufficient data for frame header".to_string()));
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(NetworkError::ProtocolError("Message too large".to_string()));
    }

    if data.len() < 4 + len {
        return Err(NetworkError::ProtocolError("Incomplete message frame".to_string()));
    }

    let message = Message::from_bytes(&data[4..4 + len])?;
    Ok((message, 4 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::try_from(0x01).unwrap(), MessageType::Handshake);
        assert_eq!(MessageType::try_from(0x03).unwrap(), MessageType::EncryptedMessage);
        assert!(MessageType::try_from(0x99).is_err());
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::heartbeat();
        let bytes = msg.to_bytes().unwrap();
        let restored = Message::from_bytes(&bytes).unwrap();

        assert_eq!(msg.message_type, restored.message_type);
        assert_eq!(msg.version.0, restored.version.0);
    }

    #[test]
    fn test_message_validation() {
        let msg = Message::heartbeat();
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_message_framing() {
        let msg = Message::heartbeat();
        let framed = frame_message(&msg).unwrap();

        let (parsed, consumed) = parse_framed_message(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert_eq!(parsed.message_type, msg.message_type);
    }

    #[test]
    fn test_invalid_frame_short() {
        let data = vec![0u8; 2]; // Too short for length prefix
        assert!(parse_framed_message(&data).is_err());
    }

    #[test]
    fn test_invalid_frame_incomplete() {
        let mut data = vec![0u8, 0u8, 0u8, 100u8]; // Says 100 bytes but doesn't have them
        data.extend_from_slice(&[0u8; 10]); // Only 10 bytes of data
        assert!(parse_framed_message(&data).is_err());
    }

    #[test]
    fn test_is_recent() {
        let msg = Message::heartbeat();
        assert!(msg.is_recent());

        let mut old_msg = Message::heartbeat();
        old_msg.timestamp = 1000; // Very old timestamp
        assert!(!old_msg.is_recent());
    }
}