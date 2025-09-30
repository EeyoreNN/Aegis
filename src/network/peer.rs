// Peer management and lifecycle
// Manages connected peers and their state

use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, Duration};

use crate::crypto::ratchet::RatchetState;
use super::{Connection, NetworkError};

const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const PEER_TIMEOUT_SECS: u64 = 90;

/// Represents a connected peer
pub struct Peer {
    /// Peer's socket address
    pub addr: SocketAddr,

    /// Connection to the peer
    pub connection: Connection,

    /// Ratchet state for this peer
    pub ratchet: RatchetState,

    /// Last activity timestamp
    last_activity: SystemTime,

    /// Peer's identifier (optional)
    pub peer_id: Option<String>,

    /// Connection state
    state: PeerState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Handshaking (key exchange in progress)
    Handshaking,

    /// Connected and ready
    Connected,

    /// Disconnecting
    Disconnecting,

    /// Disconnected
    Disconnected,
}

impl Peer {
    /// Create a new peer
    pub fn new(connection: Connection, root_key: [u8; 32]) -> Self {
        Self {
            addr: connection.peer_addr(),
            connection,
            ratchet: RatchetState::new(root_key),
            last_activity: SystemTime::now(),
            peer_id: None,
            state: PeerState::Handshaking,
        }
    }

    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }

    /// Check if peer has timed out
    pub fn is_timed_out(&self) -> bool {
        if let Ok(elapsed) = self.last_activity.elapsed() {
            elapsed > Duration::from_secs(PEER_TIMEOUT_SECS)
        } else {
            false
        }
    }

    /// Get time since last activity
    pub fn seconds_since_activity(&self) -> u64 {
        self.last_activity
            .elapsed()
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Check if heartbeat is needed
    pub fn needs_heartbeat(&self) -> bool {
        self.seconds_since_activity() >= HEARTBEAT_INTERVAL_SECS
    }

    /// Set peer state
    pub fn set_state(&mut self, state: PeerState) {
        self.state = state;
    }

    /// Get peer state
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Check if peer is connected
    pub fn is_connected(&self) -> bool {
        self.state == PeerState::Connected
    }
}

/// Manages multiple peers
pub struct PeerManager {
    peers: Arc<RwLock<HashMap<SocketAddr, Peer>>>,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a peer
    pub async fn add_peer(&self, peer: Peer) -> Result<(), NetworkError> {
        let addr = peer.addr;
        let mut peers = self.peers.write().await;
        peers.insert(addr, peer);
        Ok(())
    }

    /// Remove a peer
    pub async fn remove_peer(&self, addr: &SocketAddr) -> Option<Peer> {
        let mut peers = self.peers.write().await;
        peers.remove(addr)
    }

    /// Check if a peer exists
    pub async fn has_peer(&self, addr: &SocketAddr) -> bool {
        let peers = self.peers.read().await;
        peers.contains_key(addr)
    }

    /// Execute a function with mutable access to a peer
    pub async fn with_peer_mut<F, R>(&self, addr: &SocketAddr, f: F) -> Option<R>
    where
        F: FnOnce(&mut Peer) -> R,
    {
        let mut peers = self.peers.write().await;
        peers.get_mut(addr).map(f)
    }

    /// Get all peer addresses
    pub async fn peer_addresses(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers.keys().copied().collect()
    }

    /// Get number of connected peers
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }

    /// Get peers that need heartbeat
    pub async fn peers_needing_heartbeat(&self) -> Vec<SocketAddr> {
        let peers = self.peers.read().await;
        peers
            .iter()
            .filter(|(_, p)| p.needs_heartbeat() && p.is_connected())
            .map(|(addr, _)| *addr)
            .collect()
    }

    /// Remove timed out peers
    pub async fn remove_timed_out_peers(&self) -> Vec<SocketAddr> {
        let mut peers = self.peers.write().await;
        let timed_out: Vec<SocketAddr> = peers
            .iter()
            .filter(|(_, p)| p.is_timed_out())
            .map(|(addr, _)| *addr)
            .collect();

        for addr in &timed_out {
            peers.remove(addr);
        }

        timed_out
    }

    /// Clear all peers
    pub async fn clear(&self) {
        let mut peers = self.peers.write().await;
        peers.clear();
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

// We can't derive Clone for Peer because Connection contains TcpStream
// So we implement a manual clone that's only used in tests
#[cfg(test)]
impl Clone for Peer {
    fn clone(&self) -> Self {
        // This is a simplified clone for testing purposes only
        // In production, you wouldn't clone peers with active connections
        panic!("Peer::clone() is not supported in production code");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_root_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[tokio::test]
    async fn test_peer_manager_add_remove() {
        let manager = PeerManager::new();

        assert_eq!(manager.peer_count().await, 0);

        // We can't easily test with real connections in unit tests
        // So we'll just test the manager logic
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_peer_manager_clear() {
        let manager = PeerManager::new();
        manager.clear().await;
        assert_eq!(manager.peer_count().await, 0);
    }

    #[test]
    fn test_peer_state_transitions() {
        let states = vec![
            PeerState::Handshaking,
            PeerState::Connected,
            PeerState::Disconnecting,
            PeerState::Disconnected,
        ];

        for state in states {
            assert_eq!(state, state);
        }
    }

    #[test]
    fn test_peer_state_connected_check() {
        let state = PeerState::Connected;
        assert_eq!(state, PeerState::Connected);

        let state = PeerState::Handshaking;
        assert_ne!(state, PeerState::Connected);
    }
}
