//! Compile-time integrity hash generation
//!
//! Computes region-based hashes at compile time for runtime verification.

use crate::crypto::get_build_seed;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Default region size (64 bytes)
pub const DEFAULT_REGION_SIZE: usize = 64;

/// Region integrity information (compile-time)
#[derive(Debug, Clone, Copy)]
pub struct RegionHash {
    pub start: u32,
    pub end: u32,
    pub hash: u64,
}

/// Integrity data for embedding in generated code
#[derive(Debug, Clone)]
pub struct IntegrityData {
    /// Region hashes
    pub regions: Vec<RegionHash>,
    /// Full bytecode hash (for future use in quick verification)
    #[allow(dead_code)]
    pub full_hash: u64,
    /// Region size used (for debugging/logging)
    #[allow(dead_code)]
    pub region_size: usize,
}

impl IntegrityData {
    /// Compute integrity data for bytecode
    pub fn compute(bytecode: &[u8], region_size: usize) -> Self {
        let mut regions = Vec::new();
        let mut offset = 0;

        while offset < bytecode.len() {
            let end = (offset + region_size).min(bytecode.len());
            let region_data = &bytecode[offset..end];
            let hash = fnv1a_hash_with_seed(region_data);

            regions.push(RegionHash {
                start: offset as u32,
                end: end as u32,
                hash,
            });

            offset = end;
        }

        let full_hash = fnv1a_hash_with_seed(bytecode);

        IntegrityData {
            regions,
            full_hash,
            region_size,
        }
    }

    /// Compute with default region size
    pub fn compute_default(bytecode: &[u8]) -> Self {
        Self::compute(bytecode, DEFAULT_REGION_SIZE)
    }
}

/// FNV-1a hash using build-specific constants
/// Must match the runtime implementation in aegis_vm
pub fn fnv1a_hash_with_seed(data: &[u8]) -> u64 {
    let seed = get_build_seed();

    // Derive FNV constants from seed (same as build.rs)
    let hash_result = hmac_sha256(&seed, b"fnv-constants-v1");

    let basis = u64::from_le_bytes([
        hash_result[0], hash_result[1], hash_result[2], hash_result[3],
        hash_result[4], hash_result[5], hash_result[6], hash_result[7],
    ]) | 1; // Ensure odd

    let prime_modifier = u64::from_le_bytes([
        hash_result[16], hash_result[17], hash_result[18], hash_result[19],
        hash_result[20], hash_result[21], hash_result[22], hash_result[23],
    ]);
    let prime = 0x100000001b3 ^ ((prime_modifier & 0xFFFF_0000_0000_0000) >> 8);

    // Compute FNV-1a hash
    let mut hash = basis;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(prime);
    }
    hash
}

/// HMAC-SHA256 helper
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC can take any size key");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_data_creation() {
        let bytecode = vec![0x42u8; 256];
        let data = IntegrityData::compute(&bytecode, 64);

        assert_eq!(data.regions.len(), 4);
        assert_eq!(data.region_size, 64);
    }

    #[test]
    fn test_hash_deterministic() {
        let data = b"test data";
        let hash1 = fnv1a_hash_with_seed(data);
        let hash2 = fnv1a_hash_with_seed(data);
        assert_eq!(hash1, hash2);
    }
}
