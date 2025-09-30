// Key Derivation Functions using HKDF with BLAKE3
// Provides secure key derivation for the key hierarchy

use hkdf::Hkdf;
use sha2::Sha256;
use blake3::Hasher as Blake3Hasher;
use hmac::{Hmac, Mac};

use super::{CryptoError, symmetric::SymmetricKey};

type HmacSha256 = Hmac<Sha256>;

/// Key hierarchy levels
#[derive(Clone, Copy, Debug)]
pub enum KeyLevel {
    Master,
    Chain,
    Message,
}

/// Derive a symmetric key from input key material using HKDF
pub fn derive_keys(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input_key_material);

    let mut output = vec![0u8; output_length];
    hk.expand(info, &mut output)
        .map_err(|_| CryptoError::KeyExchangeError("HKDF expansion failed".to_string()))?;

    Ok(output)
}

/// Derive a 256-bit key from a shared secret
pub fn derive_master_key(shared_secret: &[u8], salt: &[u8]) -> Result<SymmetricKey, CryptoError> {
    let derived = derive_keys(
        shared_secret,
        salt,
        b"aegis-master-key-v1",
        32,
    )?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&derived);

    Ok(SymmetricKey::new(key_bytes))
}

/// Derive chain key from previous chain key
pub fn derive_chain_key(previous_chain_key: &[u8; 32], context: &[u8]) -> Result<[u8; 32], CryptoError> {
    let derived = derive_keys(
        previous_chain_key,
        &[],
        context,
        32,
    )?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&derived);

    Ok(key_bytes)
}

/// Derive message key from chain key
pub fn derive_message_key(chain_key: &[u8; 32], message_number: u64) -> Result<SymmetricKey, CryptoError> {
    let mut info = b"aegis-message-key-v1".to_vec();
    info.extend_from_slice(&message_number.to_le_bytes());

    let derived = derive_keys(
        chain_key,
        &[],
        &info,
        32,
    )?;

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&derived);

    Ok(SymmetricKey::new(key_bytes))
}

/// HMAC-based key ratcheting (for Double Ratchet)
pub fn ratchet_key_hmac(key: &[u8; 32], constant: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| CryptoError::KeyExchangeError("HMAC initialization failed".to_string()))?;

    mac.update(constant);

    let result = mac.finalize();
    let bytes = result.into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);

    Ok(output)
}

/// BLAKE3 keyed hash (faster alternative for high-throughput scenarios)
pub fn blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Derive multiple keys at once (for efficiency)
pub fn derive_key_bundle(
    master_key: &[u8; 32],
    count: usize,
) -> Result<Vec<SymmetricKey>, CryptoError> {
    let mut keys = Vec::with_capacity(count);

    for i in 0..count {
        let mut info = b"aegis-bundle-key-v1-".to_vec();
        info.extend_from_slice(&i.to_le_bytes());

        let derived = derive_keys(master_key, &[], &info, 32)?;

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&derived);

        keys.push(SymmetricKey::new(key_bytes));
    }

    Ok(keys)
}

/// Zero-knowledge proof of key knowledge (simplified version)
/// Used for authentication without revealing the key
pub fn prove_key_knowledge(key: &[u8; 32], challenge: &[u8]) -> [u8; 32] {
    blake3_keyed_hash(key, challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let derived1 = derive_keys(ikm, salt, info, 32).unwrap();
        let derived2 = derive_keys(ikm, salt, info, 32).unwrap();

        // Deterministic derivation
        assert_eq!(derived1, derived2);
    }

    #[test]
    fn test_derive_master_key() {
        let shared_secret = [42u8; 32];
        let salt = b"salt";

        let key = derive_master_key(&shared_secret, salt).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_derive_chain_key() {
        let previous_key = [1u8; 32];
        let context = b"context";

        let chain_key = derive_chain_key(&previous_key, context).unwrap();
        assert_eq!(chain_key.len(), 32);
        assert_ne!(chain_key, previous_key);
    }

    #[test]
    fn test_derive_message_key() {
        let chain_key = [2u8; 32];

        let msg_key1 = derive_message_key(&chain_key, 0).unwrap();
        let msg_key2 = derive_message_key(&chain_key, 1).unwrap();

        // Different message numbers should produce different keys
        assert_ne!(msg_key1.as_bytes(), msg_key2.as_bytes());
    }

    #[test]
    fn test_ratchet_key_hmac() {
        let key = [3u8; 32];
        let constant = b"rotation";

        let ratcheted = ratchet_key_hmac(&key, constant).unwrap();
        assert_eq!(ratcheted.len(), 32);
        assert_ne!(ratcheted, key);
    }

    #[test]
    fn test_ratchet_deterministic() {
        let key = [4u8; 32];
        let constant = b"test";

        let ratcheted1 = ratchet_key_hmac(&key, constant).unwrap();
        let ratcheted2 = ratchet_key_hmac(&key, constant).unwrap();

        assert_eq!(ratcheted1, ratcheted2);
    }

    #[test]
    fn test_blake3_keyed_hash() {
        let key = [5u8; 32];
        let data = b"test data";

        let hash1 = blake3_keyed_hash(&key, data);
        let hash2 = blake3_keyed_hash(&key, data);

        // Deterministic
        assert_eq!(hash1, hash2);

        // Different data produces different hash
        let hash3 = blake3_keyed_hash(&key, b"different data");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_derive_key_bundle() {
        let master_key = [6u8; 32];
        let count = 5;

        let bundle = derive_key_bundle(&master_key, count).unwrap();

        assert_eq!(bundle.len(), count);

        // All keys should be different
        for i in 0..count {
            for j in (i + 1)..count {
                assert_ne!(bundle[i].as_bytes(), bundle[j].as_bytes());
            }
        }
    }

    #[test]
    fn test_prove_key_knowledge() {
        let key = [7u8; 32];
        let challenge = b"challenge123";

        let proof = prove_key_knowledge(&key, challenge);
        assert_eq!(proof.len(), 32);

        // Verify proof is deterministic
        let proof2 = prove_key_knowledge(&key, challenge);
        assert_eq!(proof, proof2);

        // Different key produces different proof
        let different_key = [8u8; 32];
        let proof3 = prove_key_knowledge(&different_key, challenge);
        assert_ne!(proof, proof3);
    }

    #[test]
    fn test_different_salts() {
        let ikm = b"secret";
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let info = b"info";

        let derived1 = derive_keys(ikm, salt1, info, 32).unwrap();
        let derived2 = derive_keys(ikm, salt2, info, 32).unwrap();

        assert_ne!(derived1, derived2);
    }
}