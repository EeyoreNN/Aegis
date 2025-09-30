// Symmetric encryption using ChaCha20-Poly1305 AEAD
// Provides fast, authenticated encryption with 256-bit keys

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize};

use super::{CryptoError, random::generate_nonce};

const TAG_SIZE: usize = 16;

/// Encrypted message with nonce and authentication tag
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Symmetric key for ChaCha20-Poly1305 (zeroized on drop)
#[derive(Clone, ZeroizeOnDrop)]
pub struct SymmetricKey {
    key: [u8; 32],
}

impl SymmetricKey {
    /// Create a new symmetric key from bytes
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Get the key as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Create from a slice (must be exactly 32 bytes)
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Ok(Self { key })
    }
}

/// Encrypt plaintext with associated data
pub fn encrypt(
    key: &SymmetricKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedMessage, CryptoError> {
    let nonce_bytes = generate_nonce()
        .map_err(|_| CryptoError::EncryptionError("Failed to generate nonce".to_string()))?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: associated_data,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionError(format!("Encryption failed: {}", e)))?;

    Ok(EncryptedMessage {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt ciphertext with associated data
pub fn decrypt(
    key: &SymmetricKey,
    encrypted: &EncryptedMessage,
    associated_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(&encrypted.nonce);

    let payload = Payload {
        msg: &encrypted.ciphertext,
        aad: associated_data,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptionError("Authentication failed or invalid ciphertext".to_string()))?;

    Ok(plaintext)
}

/// Encrypt without associated data
pub fn encrypt_simple(key: &SymmetricKey, plaintext: &[u8]) -> Result<EncryptedMessage, CryptoError> {
    encrypt(key, plaintext, &[])
}

/// Decrypt without associated data
pub fn decrypt_simple(key: &SymmetricKey, encrypted: &EncryptedMessage) -> Result<Vec<u8>, CryptoError> {
    decrypt(key, encrypted, &[])
}

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random::generate_key;

    #[test]
    fn test_encryption_decryption() {
        let key_bytes = generate_key().unwrap();
        let key = SymmetricKey::new(key_bytes);
        let plaintext = b"Hello, Aegis!";

        let encrypted = encrypt_simple(&key, plaintext).unwrap();
        let decrypted = decrypt_simple(&key, &encrypted).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encryption_with_aad() {
        let key_bytes = generate_key().unwrap();
        let key = SymmetricKey::new(key_bytes);
        let plaintext = b"Secret message";
        let aad = b"Additional authenticated data";

        let encrypted = encrypt(&key, plaintext, aad).unwrap();
        let decrypted = decrypt(&key, &encrypted, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key_bytes = generate_key().unwrap();
        let key = SymmetricKey::new(key_bytes);
        let plaintext = b"Secret message";

        let mut encrypted = encrypt_simple(&key, plaintext).unwrap();

        // Tamper with the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 1;
        }

        // Decryption should fail
        assert!(decrypt_simple(&key, &encrypted).is_err());
    }

    #[test]
    fn test_wrong_key() {
        let key1_bytes = generate_key().unwrap();
        let key1 = SymmetricKey::new(key1_bytes);

        let key2_bytes = generate_key().unwrap();
        let key2 = SymmetricKey::new(key2_bytes);

        let plaintext = b"Secret message";

        let encrypted = encrypt_simple(&key1, plaintext).unwrap();

        // Decryption with wrong key should fail
        assert!(decrypt_simple(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_aad() {
        let key_bytes = generate_key().unwrap();
        let key = SymmetricKey::new(key_bytes);
        let plaintext = b"Secret message";
        let aad1 = b"AAD version 1";
        let aad2 = b"AAD version 2";

        let encrypted = encrypt(&key, plaintext, aad1).unwrap();

        // Decryption with different AAD should fail
        assert!(decrypt(&key, &encrypted, aad2).is_err());
    }

    #[test]
    fn test_unique_nonces() {
        let key_bytes = generate_key().unwrap();
        let key = SymmetricKey::new(key_bytes);
        let plaintext = b"Test";

        let encrypted1 = encrypt_simple(&key, plaintext).unwrap();
        let encrypted2 = encrypt_simple(&key, plaintext).unwrap();

        // Nonces should be different
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"test123";
        let b = b"test123";
        let c = b"test124";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"different length"));
    }

    #[test]
    fn test_symmetric_key_from_slice() {
        let bytes = [42u8; 32];
        let key = SymmetricKey::from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_invalid_key_length() {
        let bytes = [42u8; 16]; // Wrong length
        assert!(SymmetricKey::from_slice(&bytes).is_err());
    }
}
