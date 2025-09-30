// Network module for Aegis
// Handles message protocol, TCP connections, and peer management

pub mod protocol;
pub mod connection;
pub mod peer;

pub use connection::Connection;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Peer error: {0}")]
    PeerError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid message")]
    InvalidMessage,

    #[error("Timeout")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, NetworkError>;
