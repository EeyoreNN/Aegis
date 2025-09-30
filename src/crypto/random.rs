// Cryptographically secure random number generation
// Provides a safe wrapper around the system CSPRNG

use rand::{RngCore, CryptoRng};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use super::CryptoError;

/// Generate cryptographically secure random bytes
pub fn secure_random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buffer = vec![0u8; length];
    OsRng.fill_bytes(&mut buffer);
    Ok(buffer)
}

/// Generate a 256-bit random key
pub fn generate_key() -> Result<[u8; 32], CryptoError> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    Ok(key)
}

/// Generate a 192-bit nonce for ChaCha20-Poly1305
pub fn generate_nonce() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    Ok(nonce)
}

/// Secure random number generator that zeroizes on drop
pub struct SecureRng {
    seed: Option<[u8; 32]>,
}

impl SecureRng {
    pub fn new() -> Self {
        Self { seed: None }
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }
}

impl Drop for SecureRng {
    fn drop(&mut self) {
        if let Some(ref mut seed) = self.seed {
            seed.zeroize();
        }
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_length() {
        let bytes = secure_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_random_bytes_uniqueness() {
        let bytes1 = secure_random_bytes(32).unwrap();
        let bytes2 = secure_random_bytes(32).unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce().unwrap();
        assert_eq!(nonce.len(), 24);
    }

    #[test]
    fn test_secure_rng() {
        let mut rng = SecureRng::new();
        let mut buffer = [0u8; 32];
        rng.fill_bytes(&mut buffer);
        assert_ne!(buffer, [0u8; 32]);
    }
}
