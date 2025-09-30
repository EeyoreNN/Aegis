// Replay protection using timestamps and sequence numbers
// Prevents replay attacks and ensures message freshness

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_WINDOW_SIZE: usize = 10000;
const MAX_TIME_SKEW_SECS: u64 = 300; // 5 minutes

/// Replay protection state
pub struct ReplayProtection {
    /// Set of seen message IDs within the window
    seen_messages: HashSet<u64>,

    /// Last seen sequence number
    last_sequence: u64,

    /// Window of acceptable sequence numbers
    window_size: usize,
}

impl ReplayProtection {
    /// Create a new replay protection instance
    pub fn new() -> Self {
        Self {
            seen_messages: HashSet::new(),
            last_sequence: 0,
            window_size: MAX_WINDOW_SIZE,
        }
    }

    /// Check if a message is a replay
    /// Returns true if the message is valid (not a replay)
    pub fn check_message(&mut self, sequence: u64, timestamp: u64) -> bool {
        // Check timestamp freshness
        if !self.is_timestamp_valid(timestamp) {
            return false;
        }

        // Check if we've seen this sequence number
        if self.seen_messages.contains(&sequence) {
            return false;
        }

        // Check if sequence is within acceptable window
        if sequence < self.last_sequence.saturating_sub(self.window_size as u64) {
            return false;
        }

        // Add to seen messages
        self.seen_messages.insert(sequence);

        // Update last sequence if this is newer
        if sequence > self.last_sequence {
            self.last_sequence = sequence;
        }

        // Cleanup old entries if set gets too large
        if self.seen_messages.len() > MAX_WINDOW_SIZE {
            self.cleanup_old_entries();
        }

        true
    }

    /// Check if timestamp is within acceptable range
    fn is_timestamp_valid(&self, timestamp: u64) -> bool {
        let now = current_timestamp();

        // Allow for clock skew in both directions
        timestamp <= now + MAX_TIME_SKEW_SECS
            && timestamp + MAX_TIME_SKEW_SECS >= now
    }

    /// Cleanup old entries from the seen messages set
    fn cleanup_old_entries(&mut self) {
        let cutoff = self.last_sequence.saturating_sub(self.window_size as u64);

        // Remove entries outside the window
        self.seen_messages.retain(|&seq| seq > cutoff);
    }

    /// Reset the replay protection state
    pub fn reset(&mut self) {
        self.seen_messages.clear();
        self.last_sequence = 0;
    }

    /// Get the current sequence number
    pub fn current_sequence(&self) -> u64 {
        self.last_sequence
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
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
    fn test_replay_protection_new_message() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();

        assert!(rp.check_message(1, now));
        assert_eq!(rp.current_sequence(), 1);
    }

    #[test]
    fn test_replay_protection_duplicate() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();

        assert!(rp.check_message(1, now));
        assert!(!rp.check_message(1, now)); // Duplicate should fail
    }

    #[test]
    fn test_replay_protection_out_of_order() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();

        assert!(rp.check_message(3, now));
        assert!(rp.check_message(1, now)); // Out of order but within window
        assert!(rp.check_message(2, now));
    }

    #[test]
    fn test_replay_protection_old_timestamp() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();
        let old = now - MAX_TIME_SKEW_SECS - 100;

        assert!(!rp.check_message(1, old)); // Too old
    }

    #[test]
    fn test_replay_protection_future_timestamp() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();
        let future = now + MAX_TIME_SKEW_SECS + 100;

        assert!(!rp.check_message(1, future)); // Too far in future
    }

    #[test]
    fn test_replay_protection_sequence_ordering() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();

        assert!(rp.check_message(5, now));
        assert_eq!(rp.current_sequence(), 5);

        assert!(rp.check_message(10, now));
        assert_eq!(rp.current_sequence(), 10);

        assert!(rp.check_message(7, now)); // Old but within window
        assert_eq!(rp.current_sequence(), 10); // Last sequence unchanged
    }

    #[test]
    fn test_replay_protection_reset() {
        let mut rp = ReplayProtection::new();
        let now = current_timestamp();

        rp.check_message(1, now);
        rp.check_message(2, now);

        rp.reset();

        assert_eq!(rp.current_sequence(), 0);
        assert!(rp.check_message(1, now)); // Should work after reset
    }

    #[test]
    fn test_timestamp_validity() {
        let rp = ReplayProtection::new();
        let now = current_timestamp();

        assert!(rp.is_timestamp_valid(now));
        assert!(rp.is_timestamp_valid(now - 100));
        assert!(rp.is_timestamp_valid(now + 100));
        assert!(!rp.is_timestamp_valid(now - MAX_TIME_SKEW_SECS - 10));
        assert!(!rp.is_timestamp_valid(now + MAX_TIME_SKEW_SECS + 10));
    }
}
