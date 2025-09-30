// Post-quantum key exchange using Kyber-1024
// Provides quantum-resistant key encapsulation mechanism

use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as PQPublicKey, SecretKey as PQSecretKey, SharedSecret as PQSharedSecret, Ciphertext as PQCiphertext};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};

use super::CryptoError;

/// Kyber-1024 keypair for quantum-resistant key exchange
#[derive(ZeroizeOnDrop)]
pub struct KeyPair {
    #[zeroize(skip)]
    pub public: PublicKey,
    secret: SecretKey,
}

/// Public key wrapper
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

/// Secret key wrapper (zeroized on drop)
#[derive(ZeroizeOnDrop)]
struct SecretKey {
    bytes: Vec<u8>,
}

/// Ciphertext from key encapsulation
#[derive(Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    bytes: Vec<u8>,
}

/// Shared secret result (zeroized on drop)
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: [u8; 32],
}

impl KeyPair {
    /// Generate a new Kyber-1024 keypair
    pub fn generate() -> Result<Self, CryptoError> {
        let (pk, sk) = kyber1024::keypair();

        Ok(Self {
            public: PublicKey {
                bytes: pk.as_bytes().to_vec(),
            },
            secret: SecretKey {
                bytes: sk.as_bytes().to_vec(),
            },
        })
    }

    /// Decapsulate a ciphertext to obtain the shared secret
    pub fn decapsulate(&self, ciphertext: &Ciphertext) -> Result<SharedSecret, CryptoError> {
        let sk = kyber1024::SecretKey::from_bytes(&self.secret.bytes)
            .map_err(|_| CryptoError::KeyExchangeError("Invalid secret key".to_string()))?;

        let ct = kyber1024::Ciphertext::from_bytes(&ciphertext.bytes)
            .map_err(|_| CryptoError::KeyExchangeError("Invalid ciphertext".to_string()))?;

        let ss = kyber1024::decapsulate(&ct, &sk);

        // Convert to 32-byte shared secret
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&ss.as_bytes()[..32]);

        Ok(SharedSecret { bytes })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
}

impl PublicKey {
    /// Encapsulate a shared secret for this public key
    pub fn encapsulate(&self) -> Result<(SharedSecret, Ciphertext), CryptoError> {
        let pk = kyber1024::PublicKey::from_bytes(&self.bytes)
            .map_err(|_| CryptoError::KeyExchangeError("Invalid public key".to_string()))?;

        let (ss, ct) = kyber1024::encapsulate(&pk);

        // Convert to 32-byte shared secret
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&ss.as_bytes()[..32]);

        Ok((
            SharedSecret { bytes },
            Ciphertext {
                bytes: ct.as_bytes().to_vec(),
            },
        ))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        // Validate the public key length
        if bytes.len() != kyber1024::public_key_bytes() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { bytes })
    }
}

impl SharedSecret {
    /// Get the shared secret as a byte slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to a 32-byte array (consuming self)
    pub fn into_bytes(self) -> [u8; 32] {
        self.bytes
    }
}

impl Ciphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        // Validate the ciphertext length
        if bytes.len() != kyber1024::ciphertext_bytes() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate().unwrap();
        assert!(!keypair.public.as_bytes().is_empty());
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        // Generate keypair
        let keypair = KeyPair::generate().unwrap();

        // Encapsulate
        let (ss_encap, ciphertext) = keypair.public_key().encapsulate().unwrap();

        // Decapsulate
        let ss_decap = keypair.decapsulate(&ciphertext).unwrap();

        // Shared secrets should match
        assert_eq!(ss_encap.as_bytes(), ss_decap.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let pk_bytes = keypair.public_key().as_bytes().to_vec();

        let pk_restored = PublicKey::from_bytes(pk_bytes).unwrap();
        assert_eq!(keypair.public_key().as_bytes(), pk_restored.as_bytes());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let keypair = KeyPair::generate().unwrap();
        let (_, ciphertext) = keypair.public_key().encapsulate().unwrap();

        let ct_bytes = ciphertext.as_bytes().to_vec();
        let ct_restored = Ciphertext::from_bytes(ct_bytes).unwrap();

        assert_eq!(ciphertext.as_bytes(), ct_restored.as_bytes());
    }

    #[test]
    fn test_invalid_public_key() {
        let invalid_bytes = vec![0u8; 10]; // Wrong length
        assert!(PublicKey::from_bytes(invalid_bytes).is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let invalid_bytes = vec![0u8; 10]; // Wrong length
        assert!(Ciphertext::from_bytes(invalid_bytes).is_err());
    }
}
