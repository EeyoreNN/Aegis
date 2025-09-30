// Double Ratchet Algorithm for forward secrecy
// Automatically rotates keys every 60 seconds and per message

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::ZeroizeOnDrop;
use thiserror::Error;

use super::{
    CryptoError,
    kdf::{derive_chain_key, derive_message_key, ratchet_key_hmac},
    symmetric::SymmetricKey,
};

const ROTATION_INTERVAL_SECS: u64 = 60;
const MAX_SKIP: usize = 1000; // Maximum skipped messages
const CHAIN_ADVANCE_CONTEXT: &[u8] = b"chain-advance";

#[derive(Error, Debug)]
pub enum RatchetError {
    #[error("Too many skipped messages")]
    TooManySkippedMessages,

    #[error("Message key not found")]
    MessageKeyNotFound,

    #[error("Invalid state")]
    InvalidState,

    #[error("Time error: {0}")]
    TimeError(String),
}

/// Ratchet state for one direction of communication
#[derive(ZeroizeOnDrop)]
pub struct RatchetState {
    /// Root key for the ratchet
    #[zeroize(skip)]
    root_key: [u8; 32],

    /// Current sending chain key
    #[zeroize(skip)]
    send_chain_key: [u8; 32],

    /// Current receiving chain key
    #[zeroize(skip)]
    recv_chain_key: [u8; 32],

    /// Send message counter
    send_counter: u64,

    /// Receive message counter
    recv_counter: u64,

    /// Last rotation timestamp
    last_rotation: u64,

    /// Skipped message keys for out-of-order messages
    #[zeroize(skip)]
    skipped_message_keys: HashMap<u64, SymmetricKey>,
}

impl RatchetState {
    /// Initialize a new ratchet with a root key (as initiator)
    pub fn new(root_key: [u8; 32]) -> Self {
        let send_chain_key = ratchet_key_hmac(&root_key, b"send-chain-v1")
            .unwrap_or(root_key);
        let recv_chain_key = ratchet_key_hmac(&root_key, b"recv-chain-v1")
            .unwrap_or(root_key);

        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_counter: 0,
            recv_counter: 0,
            last_rotation: current_timestamp(),
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Initialize a new ratchet as responder (chains swapped)
    pub fn new_responder(root_key: [u8; 32]) -> Self {
        let send_chain_key = ratchet_key_hmac(&root_key, b"recv-chain-v1")
            .unwrap_or(root_key);
        let recv_chain_key = ratchet_key_hmac(&root_key, b"send-chain-v1")
            .unwrap_or(root_key);

        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_counter: 0,
            recv_counter: 0,
            last_rotation: current_timestamp(),
            skipped_message_keys: HashMap::new(),
        }
    }

    /// Get the next sending message key and advance the chain
    pub fn next_send_key(&mut self) -> Result<(SymmetricKey, u64), CryptoError> {
        // Check if rotation is needed
        self.check_and_rotate()?;

        let message_key = derive_message_key(&self.send_chain_key, self.send_counter)?;
        let counter = self.send_counter;

        // Advance the chain
        self.send_chain_key = derive_chain_key(&self.send_chain_key, CHAIN_ADVANCE_CONTEXT)?;
        self.send_counter += 1;

        Ok((message_key, counter))
    }

    /// Get the receiving message key for a given counter
    pub fn get_recv_key(&mut self, message_counter: u64) -> Result<SymmetricKey, CryptoError> {
        // Check if this is a skipped message
        if let Some(key) = self.skipped_message_keys.remove(&message_counter) {
            return Ok(key);
        }

        // If message is in the future, store skipped keys
        if message_counter > self.recv_counter {
            let skip_count = (message_counter - self.recv_counter) as usize;
            if skip_count > MAX_SKIP {
                return Err(CryptoError::RatchetError(RatchetError::TooManySkippedMessages));
            }

            // Store keys for skipped messages
            for i in self.recv_counter..message_counter {
                let skipped_key = derive_message_key(&self.recv_chain_key, i)?;
                self.skipped_message_keys.insert(i, skipped_key);
                self.recv_chain_key = derive_chain_key(&self.recv_chain_key, CHAIN_ADVANCE_CONTEXT)?;
            }

            self.recv_counter = message_counter;
        }

        // Derive the message key
        let message_key = derive_message_key(&self.recv_chain_key, message_counter)?;

        // Advance the chain if this is the next expected message
        if message_counter == self.recv_counter {
            self.recv_chain_key = derive_chain_key(&self.recv_chain_key, CHAIN_ADVANCE_CONTEXT)?;
            self.recv_counter += 1;
        }

        Ok(message_key)
    }

    /// Force a key rotation (called automatically every 60 seconds)
    pub fn rotate(&mut self) -> Result<(), CryptoError> {
        let timestamp = current_timestamp();

        // Ratchet both chains with timestamp as context
        let mut context = b"rotation-v1-".to_vec();
        context.extend_from_slice(&timestamp.to_le_bytes());

        self.send_chain_key = ratchet_key_hmac(&self.send_chain_key, &context)?;
        self.recv_chain_key = ratchet_key_hmac(&self.recv_chain_key, &context)?;

        self.last_rotation = timestamp;

        // Reset counters (optional, for additional security)
        // Uncomment if you want to reset message counters on rotation
        // self.send_counter = 0;
        // self.recv_counter = 0;

        // Clear old skipped keys to prevent memory buildup
        if self.skipped_message_keys.len() > 100 {
            self.skipped_message_keys.clear();
        }

        Ok(())
    }

    /// Check if rotation is needed and perform it
    fn check_and_rotate(&mut self) -> Result<(), CryptoError> {
        let now = current_timestamp();
        if now >= self.last_rotation + ROTATION_INTERVAL_SECS {
            self.rotate()?;
        }
        Ok(())
    }

    /// Get current send counter
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Get current receive counter
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }

    /// Get seconds until next rotation
    pub fn seconds_until_rotation(&self) -> u64 {
        let now = current_timestamp();
        let elapsed = now.saturating_sub(self.last_rotation);
        ROTATION_INTERVAL_SECS.saturating_sub(elapsed)
    }

    /// Reset the ratchet with a new root key (for rekeying)
    pub fn rekey(&mut self, new_root_key: [u8; 32]) -> Result<(), CryptoError> {
        self.root_key = new_root_key;
        self.send_chain_key = ratchet_key_hmac(&new_root_key, b"send-chain-v1")?;
        self.recv_chain_key = ratchet_key_hmac(&new_root_key, b"recv-chain-v1")?;
        self.send_counter = 0;
        self.recv_counter = 0;
        self.last_rotation = current_timestamp();
        self.skipped_message_keys.clear();
        Ok(())
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_initialization() {
        let root_key = [1u8; 32];
        let ratchet = RatchetState::new(root_key);

        assert_eq!(ratchet.send_counter(), 0);
        assert_eq!(ratchet.recv_counter(), 0);
    }

    #[test]
    fn test_send_key_generation() {
        let root_key = [2u8; 32];
        let mut ratchet = RatchetState::new(root_key);

        let (key1, counter1) = ratchet.next_send_key().unwrap();
        let (key2, counter2) = ratchet.next_send_key().unwrap();

        assert_eq!(counter1, 0);
        assert_eq!(counter2, 1);
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(ratchet.send_counter(), 2);
    }

    #[test]
    fn test_recv_key_in_order() {
        let root_key = [3u8; 32];
        let mut ratchet = RatchetState::new(root_key);

        let key1 = ratchet.get_recv_key(0).unwrap();
        let key2 = ratchet.get_recv_key(1).unwrap();

        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_eq!(ratchet.recv_counter(), 2);
    }

    #[test]
    fn test_recv_key_out_of_order() {
        let root_key = [4u8; 32];
        let mut ratchet = RatchetState::new(root_key);

        // Receive message 2 first (skip 0 and 1)
        let key2 = ratchet.get_recv_key(2).unwrap();

        // Now receive message 0 (should use skipped key)
        let key0 = ratchet.get_recv_key(0).unwrap();

        // Now receive message 1 (should use skipped key)
        let key1 = ratchet.get_recv_key(1).unwrap();

        // All keys should be different
        assert_ne!(key0.as_bytes(), key1.as_bytes());
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        assert_ne!(key0.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_too_many_skipped() {
        let root_key = [5u8; 32];
        let mut ratchet = RatchetState::new(root_key);

        // Try to skip more than MAX_SKIP messages
        let result = ratchet.get_recv_key(MAX_SKIP as u64 + 10);
        assert!(result.is_err());
    }

    #[test]
    fn test_manual_rotation() {
        let root_key = [6u8; 32];
        let mut ratchet = RatchetState::new(root_key);

        let (key1, _) = ratchet.next_send_key().unwrap();

        // Force rotation
        ratchet.rotate().unwrap();

        let (key2, _) = ratchet.next_send_key().unwrap();

        // Keys should be different after rotation
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_rekey() {
        let root_key1 = [7u8; 32];
        let mut ratchet = RatchetState::new(root_key1);

        let (key1, _) = ratchet.next_send_key().unwrap();
        assert_eq!(ratchet.send_counter(), 1);

        // Rekey with new root key
        let root_key2 = [8u8; 32];
        ratchet.rekey(root_key2).unwrap();

        assert_eq!(ratchet.send_counter(), 0);

        let (key2, _) = ratchet.next_send_key().unwrap();

        // Keys should be completely different after rekey
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_seconds_until_rotation() {
        let root_key = [9u8; 32];
        let ratchet = RatchetState::new(root_key);

        let seconds = ratchet.seconds_until_rotation();
        assert!(seconds <= ROTATION_INTERVAL_SECS);
    }
}
