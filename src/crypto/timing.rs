// Constant-time operations to prevent timing side-channel attacks

use std::time::Instant;

/// Constant-time comparison of two byte slices
/// Returns true if equal, false otherwise
/// Running time depends only on the length, not the contents
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

/// Constant-time selection
/// Returns `a` if `choice != 0`, `b` if `choice == 0`
/// Runs in constant time regardless of choice
#[inline(always)]
pub fn constant_time_select(choice: u8, a: u8, b: u8) -> u8 {
    // Create mask: 0xFF if choice != 0, 0x00 if choice == 0
    let is_nonzero = ((choice | choice.wrapping_neg()) >> 7) & 1;
    let mask = is_nonzero.wrapping_sub(1);  // 0xFF if nonzero, 0x00 if zero
    let mask = !mask;  // Invert: 0xFF if nonzero, 0x00 if zero
    (a & mask) | (b & !mask)
}

/// Pad data to a multiple of block_size to prevent traffic analysis
pub fn pad_to_block_size(data: &[u8], block_size: usize) -> Vec<u8> {
    let data_len = data.len().min(u16::MAX as usize) as u16;

    // Calculate total size including length prefix (2 bytes) + data
    let unpadded_size = 2 + data.len();

    // Round up to next multiple of block_size
    let padding_needed = if unpadded_size % block_size == 0 {
        0
    } else {
        block_size - (unpadded_size % block_size)
    };

    let total_length = unpadded_size + padding_needed;

    let mut padded = Vec::with_capacity(total_length);

    // Add original data length as u16
    padded.extend_from_slice(&data_len.to_be_bytes());

    // Add data
    padded.extend_from_slice(data);

    // Add padding
    padded.resize(total_length, 0);

    padded
}

/// Remove padding from padded data
pub fn unpad(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 2 {
        return None;
    }

    // Extract length from first 2 bytes
    let data_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;

    if data_len + 2 > padded.len() {
        return None;
    }

    Some(padded[2..2 + data_len].to_vec())
}

/// Add random padding to obscure message length
pub fn add_random_padding(data: &[u8], min_padding: usize, max_padding: usize) -> Vec<u8> {
    use rand::Rng;

    let padding_len = if max_padding > min_padding {
        rand::thread_rng().gen_range(min_padding..=max_padding)
    } else {
        min_padding
    };

    let total_len = data.len() + padding_len + 2;
    let mut padded = Vec::with_capacity(total_len);

    // Length prefix
    let data_len = data.len().min(u16::MAX as usize) as u16;
    padded.extend_from_slice(&data_len.to_be_bytes());

    // Original data
    padded.extend_from_slice(data);

    // Random padding
    let mut padding = vec![0u8; padding_len];
    rand::thread_rng().fill(&mut padding[..]);
    padded.extend_from_slice(&padding);

    padded
}

/// Timing-safe sleep to normalize operation time
pub fn normalize_timing(target_duration_ms: u64) {
    let start = Instant::now();

    // Do the timing-critical operation here
    // (This is just a placeholder)

    let elapsed = start.elapsed();
    let target = std::time::Duration::from_millis(target_duration_ms);

    if elapsed < target {
        std::thread::sleep(target - elapsed);
    }
}

/// Constant-time u64 comparison
pub fn constant_time_eq_u64(a: u64, b: u64) -> bool {
    let diff = a ^ b;

    // Zero if equal: check all bits are zero
    let mut result = 0u64;
    for i in 0..64 {
        result |= (diff >> i) & 1;
    }

    result == 0
}

/// Constant-time greater-than comparison for u64
/// Returns 1 if a > b, 0 otherwise
pub fn constant_time_gt_u64(a: u64, b: u64) -> u8 {
    // a > b means a - b would not underflow
    let diff = a.wrapping_sub(b);

    // Check if subtraction underflowed
    let underflow = a < b;

    (!underflow as u8) & ((diff != 0) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = b"test123";
        let b = b"test123";
        let c = b"test124";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"different length"));
    }

    #[test]
    fn test_constant_time_select() {
        assert_eq!(constant_time_select(1, 0xFF, 0x00), 0xFF);
        assert_eq!(constant_time_select(0, 0xFF, 0x00), 0x00);
        assert_eq!(constant_time_select(255, 42, 17), 42);
    }

    #[test]
    fn test_pad_unpad() {
        let data = b"Hello, World!";
        let block_size = 16;

        let padded = pad_to_block_size(data, block_size);
        assert_eq!(padded.len() % block_size, 0);

        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded.as_slice(), data);
    }

    #[test]
    fn test_pad_unpad_exact_block() {
        let data = b"Exactly16Bytes!!";
        let block_size = 16;

        let padded = pad_to_block_size(data, block_size);
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded.as_slice(), data);
    }

    #[test]
    fn test_random_padding() {
        let data = b"Test message";
        let min = 10;
        let max = 20;

        let padded = add_random_padding(data, min, max);
        assert!(padded.len() >= data.len() + min + 2);
        assert!(padded.len() <= data.len() + max + 2);

        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded.as_slice(), data);
    }

    #[test]
    fn test_constant_time_eq_u64() {
        assert!(constant_time_eq_u64(12345, 12345));
        assert!(!constant_time_eq_u64(12345, 12346));
        assert!(constant_time_eq_u64(0, 0));
        assert!(!constant_time_eq_u64(0, 1));
    }

    #[test]
    fn test_constant_time_gt_u64() {
        assert_eq!(constant_time_gt_u64(10, 5), 1);
        assert_eq!(constant_time_gt_u64(5, 10), 0);
        assert_eq!(constant_time_gt_u64(5, 5), 0);
        assert_eq!(constant_time_gt_u64(u64::MAX, 0), 1);
    }

    #[test]
    fn test_unpad_invalid() {
        assert!(unpad(&[]).is_none());
        assert!(unpad(&[0]).is_none());

        // Length exceeds actual data
        assert!(unpad(&[0xFF, 0xFF, 0x01]).is_none());
    }

    #[test]
    fn test_pad_empty_data() {
        let data = b"";
        let block_size = 16;

        let padded = pad_to_block_size(data, block_size);
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(unpadded.as_slice(), data);
    }
}
