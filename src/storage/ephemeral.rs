// Ephemeral secure memory storage
// Memory is locked, zeroized, and protected against swapping

use zeroize::Zeroize;
use std::ops::{Deref, DerefMut};

/// Secure buffer that locks memory and zeroizes on drop
pub struct SecureBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl SecureBuffer {
    /// Create a new secure buffer with the given capacity
    pub fn new(capacity: usize) -> Self {
        let mut buffer = Self {
            data: Vec::with_capacity(capacity),
            locked: false,
        };

        // Try to lock memory (may fail on some systems without proper permissions)
        #[cfg(unix)]
        {
            buffer.try_lock_memory();
        }

        buffer
    }

    /// Create a secure buffer from existing data
    pub fn from_vec(data: Vec<u8>) -> Self {
        let mut buffer = Self {
            data,
            locked: false,
        };

        #[cfg(unix)]
        {
            buffer.try_lock_memory();
        }

        buffer
    }

    /// Try to lock memory to prevent swapping to disk
    #[cfg(unix)]
    fn try_lock_memory(&mut self) {
        use libc::{mlock, c_void};

        if !self.data.is_empty() {
            let ptr = self.data.as_ptr() as *const c_void;
            let len = self.data.len();

            unsafe {
                if mlock(ptr, len) == 0 {
                    self.locked = true;
                }
            }
        }
    }

    /// Unlock memory (called automatically on drop)
    #[cfg(unix)]
    fn unlock_memory(&mut self) {
        use libc::{munlock, c_void};

        if self.locked && !self.data.is_empty() {
            let ptr = self.data.as_ptr() as *const c_void;
            let len = self.data.len();

            unsafe {
                munlock(ptr, len);
            }
            self.locked = false;
        }
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a slice of the data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable slice of the data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

impl Deref for SecureBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl DerefMut for SecureBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            self.unlock_memory();
        }

        // Zeroize the data
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_creation() {
        let buffer = SecureBuffer::new(100);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), 100);
    }

    #[test]
    fn test_secure_buffer_from_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = SecureBuffer::from_vec(data.clone());
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_secure_buffer_is_empty() {
        let buffer = SecureBuffer::new(10);
        assert!(buffer.is_empty());

        let buffer2 = SecureBuffer::from_vec(vec![1]);
        assert!(!buffer2.is_empty());
    }

    #[test]
    fn test_secure_buffer_deref() {
        let mut buffer = SecureBuffer::from_vec(vec![1, 2, 3]);
        buffer.push(4);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
    }
}
