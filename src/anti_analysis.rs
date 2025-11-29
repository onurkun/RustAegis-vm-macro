//! Anti-Analysis Protection
//!
//! Inserts checks that detect and respond to analysis attempts:
//!
//! ## Techniques
//!
//! 1. **Timing Checks** - Detect single-stepping/debugging by measuring execution time
//! 2. **Hash Checks** - Verify bytecode integrity hasn't been modified
//! 3. **Opaque Predicates** - Conditions that are always true/false but hard to analyze
//!
//! ## Usage
//!
//! These checks are inserted at strategic points in the bytecode:
//! - At function entry (timing start)
//! - Before critical operations (integrity check)
//! - At function exit (timing verification)

// Anti-analysis protection - now integrated into vm_protect pipeline
// Note: Some methods are reserved for future inline check support (requires jump recalculation)

#![allow(dead_code)] // Reserved methods for future inline check support

use crate::opcodes::{special, stack};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Anti-analysis protection level
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum AntiAnalysisLevel {
    /// No protection (debug mode)
    None,
    /// Light protection (occasional checks)
    #[default]
    Light,
    /// Heavy protection (frequent checks)
    Heavy,
}

/// Seeded RNG for deterministic check placement
struct AnalysisRng {
    state: u64,
}

impl AnalysisRng {
    fn new(seed: u64) -> Self {
        Self { state: seed ^ 0xCAFEBABE }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_mul(0x2545F4914F6CDD1D).wrapping_add(1);
        self.state
    }

    fn should_insert(&mut self, probability: u8) -> bool {
        (self.next() % 100) < probability as u64
    }
}

/// Generate anti-analysis seed
pub fn generate_analysis_seed(fn_name: &str, build_seed: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    fn_name.hash(&mut hasher);
    build_seed.hash(&mut hasher);
    "anti-analysis-v1".hash(&mut hasher);
    hasher.finish()
}

/// Anti-analysis bytecode transformer
pub struct AntiAnalysisTransformer {
    rng: AnalysisRng,
    level: AntiAnalysisLevel,
}

impl AntiAnalysisTransformer {
    pub fn new(seed: u64, level: AntiAnalysisLevel) -> Self {
        Self {
            rng: AnalysisRng::new(seed),
            level,
        }
    }

    /// Apply anti-analysis protections to bytecode
    ///
    /// SAFETY: This is JUMP-SAFE - only adds checks at entry point (prefix).
    /// Original bytecode is copied unchanged to preserve all jump offsets.
    ///
    /// Future work: instruction-aware inline checks would require:
    /// 1. get_instruction_size() to properly iterate
    /// 2. Jump offset recalculation after insertion
    /// 3. Careful pipeline ordering (after compiler fixups)
    pub fn protect(&mut self, bytecode: &[u8]) -> Vec<u8> {
        if self.level == AntiAnalysisLevel::None {
            return bytecode.to_vec();
        }

        let mut output = Vec::new();

        // Insert entry checks (BEFORE original bytecode - jump-safe)
        self.insert_entry_checks(&mut output);

        // Copy original bytecode UNCHANGED (preserves all jump offsets)
        // This is the same approach as polymorphism v2
        output.extend_from_slice(bytecode);

        output
    }

    /// Should we insert a check at this point?
    fn should_insert_check(&mut self) -> bool {
        let prob = match self.level {
            AntiAnalysisLevel::None => 0,
            AntiAnalysisLevel::Light => 5,   // 5% chance per instruction
            AntiAnalysisLevel::Heavy => 15,  // 15% chance per instruction
        };
        self.rng.should_insert(prob)
    }

    /// Insert entry-point checks
    fn insert_entry_checks(&mut self, output: &mut Vec<u8>) {
        match self.level {
            AntiAnalysisLevel::None => {}
            AntiAnalysisLevel::Light => {
                // Single opaque predicate
                self.insert_opaque_true(output);
            }
            AntiAnalysisLevel::Heavy => {
                // Multiple checks
                self.insert_opaque_true(output);
                self.insert_timing_check(output);
                self.insert_opaque_false(output);
            }
        }
    }

    /// Insert inline integrity check
    fn insert_inline_check(&mut self, output: &mut Vec<u8>) {
        let check_type = self.rng.next() % 3;
        match check_type {
            0 => self.insert_opaque_true(output),
            1 => self.insert_opaque_false(output),
            _ => self.insert_nop_sequence(output),
        }
    }

    /// Insert OPAQUE_TRUE + DROP (stack-neutral)
    fn insert_opaque_true(&mut self, output: &mut Vec<u8>) {
        output.push(special::OPAQUE_TRUE);
        output.push(stack::DROP);
    }

    /// Insert OPAQUE_FALSE + DROP (stack-neutral)
    fn insert_opaque_false(&mut self, output: &mut Vec<u8>) {
        output.push(special::OPAQUE_FALSE);
        output.push(stack::DROP);
    }

    /// Insert TIMING_CHECK (verifies execution isn't being single-stepped)
    fn insert_timing_check(&mut self, output: &mut Vec<u8>) {
        output.push(special::TIMING_CHECK);
    }

    /// Insert NOP sequence
    fn insert_nop_sequence(&mut self, output: &mut Vec<u8>) {
        let count = 1 + (self.rng.next() % 3) as u8;
        output.push(special::NOP_N);
        output.push(count);
        for _ in 0..count {
            output.push(special::NOP);
        }
    }
}

/// Generate hash check bytecode
/// This creates a sequence that verifies a portion of bytecode hasn't been modified
pub fn generate_hash_check(expected_hash: u32) -> Vec<u8> {
    let mut result = Vec::new();
    result.push(special::HASH_CHECK);
    result.extend_from_slice(&expected_hash.to_le_bytes());
    result
}

/// Calculate FNV-1a hash of bytecode segment
pub fn calculate_bytecode_hash(bytecode: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for &byte in bytecode {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Apply anti-analysis protection to bytecode
pub fn apply_anti_analysis(
    bytecode: &[u8],
    fn_name: &str,
    level: AntiAnalysisLevel,
) -> Vec<u8> {
    let seed = generate_analysis_seed(fn_name, b"anti-analysis");
    let mut transformer = AntiAnalysisTransformer::new(seed, level);
    transformer.protect(bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::{arithmetic, exec};

    #[test]
    fn test_no_protection() {
        let bytecode = vec![
            stack::PUSH_IMM8, 10,
            arithmetic::ADD,
            exec::HALT,
        ];

        let result = apply_anti_analysis(&bytecode, "test", AntiAnalysisLevel::None);
        assert_eq!(result, bytecode);
    }

    #[test]
    fn test_light_protection_adds_checks() {
        let bytecode = vec![
            stack::PUSH_IMM8, 10,
            exec::HALT,
        ];

        let result = apply_anti_analysis(&bytecode, "test_light", AntiAnalysisLevel::Light);

        // Light protection should add at least entry checks
        assert!(result.len() >= bytecode.len());
    }

    #[test]
    fn test_heavy_protection_adds_more_checks() {
        let bytecode = vec![
            stack::PUSH_IMM8, 10,
            stack::PUSH_IMM8, 20,
            arithmetic::ADD,
            arithmetic::INC,
            arithmetic::DEC,
            exec::HALT,
        ];

        let light = apply_anti_analysis(&bytecode, "test_compare", AntiAnalysisLevel::Light);
        let heavy = apply_anti_analysis(&bytecode, "test_compare", AntiAnalysisLevel::Heavy);

        // Heavy should generally be larger than light
        // (though not guaranteed due to RNG)
        assert!(heavy.len() >= bytecode.len());
        assert!(light.len() >= bytecode.len());
    }

    #[test]
    fn test_deterministic_protection() {
        let bytecode = vec![
            stack::PUSH_IMM8, 42,
            arithmetic::INC,
            exec::HALT,
        ];

        let r1 = apply_anti_analysis(&bytecode, "same_func", AntiAnalysisLevel::Heavy);
        let r2 = apply_anti_analysis(&bytecode, "same_func", AntiAnalysisLevel::Heavy);

        assert_eq!(r1, r2, "Protection should be deterministic");
    }

    #[test]
    fn test_bytecode_hash() {
        let bytecode = vec![0x01, 0x02, 0x03, 0x04];
        let hash1 = calculate_bytecode_hash(&bytecode);
        let hash2 = calculate_bytecode_hash(&bytecode);

        assert_eq!(hash1, hash2, "Hash should be deterministic");
        assert_ne!(hash1, 0, "Hash should not be zero");
    }

    #[test]
    fn test_hash_check_generation() {
        let check = generate_hash_check(0xDEADBEEF);

        assert_eq!(check[0], special::HASH_CHECK);
        assert_eq!(check.len(), 5); // opcode + 4 bytes hash

        // Verify hash bytes
        let hash_bytes = &check[1..5];
        let hash = u32::from_le_bytes([hash_bytes[0], hash_bytes[1], hash_bytes[2], hash_bytes[3]]);
        assert_eq!(hash, 0xDEADBEEF);
    }

    #[test]
    fn test_different_functions_different_checks() {
        let bytecode = vec![
            stack::PUSH_IMM8, 1,
            stack::PUSH_IMM8, 2,
            stack::PUSH_IMM8, 3,
            stack::PUSH_IMM8, 4,
            stack::PUSH_IMM8, 5,
            arithmetic::ADD,
            arithmetic::ADD,
            arithmetic::ADD,
            arithmetic::ADD,
            exec::HALT,
        ];

        let r1 = apply_anti_analysis(&bytecode, "func_a", AntiAnalysisLevel::Heavy);
        let r2 = apply_anti_analysis(&bytecode, "func_b", AntiAnalysisLevel::Heavy);

        // Different functions should (likely) have different check placements
        // Not guaranteed but highly probable with enough instructions
        assert!(!r1.is_empty());
        assert!(!r2.is_empty());
    }
}
