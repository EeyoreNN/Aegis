// Session management and handshake coordination
// Orchestrates key exchange and secure session establishment

use std::net::SocketAddr;
use tokio::time::{Duration, timeout};

use crate::crypto::{
    kyber::{KeyPair, PublicKey, Ciphertext},
    ratchet::RatchetState,
    kdf::derive_master_key,
};
use crate::network::{
    Connection,
    protocol::{Message, MessageType, MessagePayload},
    NetworkError,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Session role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,  // Client (connector)
    Responder,  // Server (listener)
}

/// Session represents an established encrypted session with a peer
pub struct Session {
    pub connection: Connection,
    pub ratchet: RatchetState,
    pub peer_addr: SocketAddr,
    pub established: bool,
    pub role: SessionRole,
}

impl Session {
    /// Initiate a session as a client (connector)
    pub async fn connect(mut connection: Connection) -> Result<Self, NetworkError> {
        // Generate ephemeral Kyber keypair
        let keypair = KeyPair::generate()
            .map_err(|e| NetworkError::ConnectionError(format!("Key generation failed: {}", e)))?;

        // Send handshake with our public key
        let handshake_msg = Message::handshake(keypair.public_key().clone());
        connection.send_message(&handshake_msg).await?;

        // Wait for handshake response
        let response = timeout(HANDSHAKE_TIMEOUT, connection.recv_message()).await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::ConnectionError(format!("Handshake failed: {}", e)))?;

        // Validate response
        response.validate()?;
        if response.message_type != MessageType::HandshakeResponse {
            return Err(NetworkError::ProtocolError("Expected handshake response".to_string()));
        }

        // Extract ciphertext and derive shared secret
        let ciphertext_bytes = match response.payload {
            MessagePayload::HandshakeResponse { ciphertext } => ciphertext,
            _ => return Err(NetworkError::ProtocolError("Invalid handshake response payload".to_string())),
        };

        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes)
            .map_err(|e| NetworkError::ProtocolError(format!("Invalid ciphertext: {}", e)))?;

        let shared_secret = keypair.decapsulate(&ciphertext)
            .map_err(|e| NetworkError::ConnectionError(format!("Decapsulation failed: {}", e)))?;

        // Derive master key from shared secret
        let salt = b"aegis-v1-salt";
        let master_key = derive_master_key(shared_secret.as_bytes(), salt)
            .map_err(|e| NetworkError::ConnectionError(format!("Key derivation failed: {}", e)))?;

        // Initialize ratchet state
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(master_key.as_bytes());
        let ratchet = RatchetState::new(root_key);

        let peer_addr = connection.peer_addr();

        Ok(Session {
            connection,
            ratchet,
            peer_addr,
            established: true,
            role: SessionRole::Initiator,
        })
    }

    /// Accept a session as a server (listener)
    pub async fn accept(mut connection: Connection) -> Result<Self, NetworkError> {
        // Wait for handshake
        let handshake = timeout(HANDSHAKE_TIMEOUT, connection.recv_message()).await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| NetworkError::ConnectionError(format!("Handshake failed: {}", e)))?;

        // Validate handshake
        handshake.validate()?;
        if handshake.message_type != MessageType::Handshake {
            return Err(NetworkError::ProtocolError("Expected handshake".to_string()));
        }

        // Extract peer's public key
        let peer_public_key_bytes = match handshake.payload {
            MessagePayload::Handshake { public_key } => public_key,
            _ => return Err(NetworkError::ProtocolError("Invalid handshake payload".to_string())),
        };

        let peer_public_key = PublicKey::from_bytes(peer_public_key_bytes)
            .map_err(|e| NetworkError::ProtocolError(format!("Invalid public key: {}", e)))?;

        // Encapsulate a shared secret for the peer
        let (shared_secret, ciphertext) = peer_public_key.encapsulate()
            .map_err(|e| NetworkError::ConnectionError(format!("Encapsulation failed: {}", e)))?;

        // Send handshake response
        let response = Message::handshake_response(ciphertext);
        connection.send_message(&response).await?;

        // Derive master key
        let salt = b"aegis-v1-salt";
        let master_key = derive_master_key(shared_secret.as_bytes(), salt)
            .map_err(|e| NetworkError::ConnectionError(format!("Key derivation failed: {}", e)))?;

        // Initialize ratchet state (responder has swapped chains)
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(master_key.as_bytes());
        let ratchet = RatchetState::new_responder(root_key);

        let peer_addr = connection.peer_addr();

        Ok(Session {
            connection,
            ratchet,
            peer_addr,
            established: true,
            role: SessionRole::Responder,
        })
    }

    /// Send an encrypted message
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), NetworkError> {
        if !self.established {
            return Err(NetworkError::ConnectionError("Session not established".to_string()));
        }

        // Get next sending key and counter
        let (message_key, counter) = self.ratchet.next_send_key()
            .map_err(|e| NetworkError::ConnectionError(format!("Key rotation failed: {}", e)))?;

        // Encrypt the message
        let encrypted = crate::crypto::symmetric::encrypt_simple(&message_key, plaintext)
            .map_err(|e| NetworkError::ConnectionError(format!("Encryption failed: {}", e)))?;

        // Create encrypted message
        let msg = Message::encrypted(encrypted.nonce, encrypted.ciphertext, counter, 0);

        // Send
        self.connection.send_message(&msg).await?;

        Ok(())
    }

    /// Receive and decrypt a message
    pub async fn recv(&mut self) -> Result<Vec<u8>, NetworkError> {
        if !self.established {
            return Err(NetworkError::ConnectionError("Session not established".to_string()));
        }

        // Receive message
        let msg = self.connection.recv_message().await?;

        // Validate
        msg.validate()?;

        // Handle different message types
        match msg.message_type {
            MessageType::EncryptedMessage => {
                // Extract encrypted data
                let (nonce, ciphertext, counter) = match msg.payload {
                    MessagePayload::EncryptedData { nonce, ciphertext, message_counter } => {
                        (nonce, ciphertext, message_counter)
                    }
                    _ => return Err(NetworkError::ProtocolError("Invalid encrypted message payload".to_string())),
                };

                // Get receiving key
                let message_key = self.ratchet.get_recv_key(counter)
                    .map_err(|e| NetworkError::ConnectionError(format!("Key retrieval failed: {}", e)))?;

                // Decrypt
                let encrypted_msg = crate::crypto::symmetric::EncryptedMessage {
                    nonce,
                    ciphertext,
                };

                let plaintext = crate::crypto::symmetric::decrypt_simple(&message_key, &encrypted_msg)
                    .map_err(|e| NetworkError::ConnectionError(format!("Decryption failed: {}", e)))?;

                Ok(plaintext)
            }
            MessageType::Heartbeat => {
                // Respond to heartbeat
                let response = Message::heartbeat();
                self.connection.send_message(&response).await?;
                // Return empty to indicate heartbeat (caller should handle)
                Ok(Vec::new())
            }
            MessageType::Disconnect => {
                self.established = false;
                Err(NetworkError::ConnectionError("Peer disconnected".to_string()))
            }
            _ => {
                Err(NetworkError::ProtocolError(format!("Unexpected message type: {:?}", msg.message_type)))
            }
        }
    }

    /// Send a heartbeat
    pub async fn send_heartbeat(&mut self) -> Result<(), NetworkError> {
        let msg = Message::heartbeat();
        self.connection.send_message(&msg).await
    }

    /// Close the session
    pub async fn close(mut self) -> Result<(), NetworkError> {
        let disconnect_msg = Message::disconnect(Some("User requested disconnect".to_string()));
        let _ = self.connection.send_message(&disconnect_msg).await;
        self.connection.close().await
    }

    /// Get seconds until next key rotation
    pub fn seconds_until_rotation(&self) -> u64 {
        self.ratchet.seconds_until_rotation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::connection::Listener;

    #[tokio::test]
    async fn test_session_handshake() {
        // Start listener
        let listener = Listener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn accept task
        let accept_handle = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            Session::accept(conn).await
        });

        // Connect
        let client_conn = crate::network::connection::connect(&addr.to_string()).await.unwrap();
        let client_session = Session::connect(client_conn).await.unwrap();

        // Accept
        let server_session = accept_handle.await.unwrap().unwrap();

        // Both sessions should be established
        assert!(client_session.established);
        assert!(server_session.established);
    }

    #[tokio::test]
    async fn test_session_message_exchange() {
        // Start listener
        let listener = Listener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server task
        let server_handle = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            let mut session = Session::accept(conn).await.unwrap();

            // Receive message
            let received = session.recv().await.unwrap();
            assert_eq!(received, b"Hello from client!");

            // Send response
            session.send(b"Hello from server!").await.unwrap();
        });

        // Client
        let client_conn = crate::network::connection::connect(&addr.to_string()).await.unwrap();
        let mut client_session = Session::connect(client_conn).await.unwrap();

        // Send message
        client_session.send(b"Hello from client!").await.unwrap();

        // Receive response
        let response = client_session.recv().await.unwrap();
        assert_eq!(response, b"Hello from server!");

        server_handle.await.unwrap();
    }
}
