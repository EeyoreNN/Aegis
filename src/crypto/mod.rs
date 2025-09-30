// Cryptography module for Aegis
// Provides quantum-resistant encryption, key exchange, and key derivation

pub mod kyber;
pub mod symmetric;
pub mod kdf;
pub mod ratchet;
pub mod random;
pub mod timing;

pub use kyber::{KeyPair, PublicKey, Ciphertext, SharedSecret};
pub use symmetric::{encrypt, decrypt, EncryptedMessage};
pub use kdf::derive_keys;
pub use ratchet::{RatchetState, RatchetError};
pub use random::secure_random_bytes;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Key exchange failed: {0}")]
    KeyExchangeError(String),

    #[error("Invalid key material")]
    InvalidKey,

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Random number generation failed")]
    RandomError,

    #[error("Ratchet error: {0}")]
    RatchetError(#[from] RatchetError),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
