//! Polymorphic Code Generation
//!
//! Transforms bytecode to make each compilation produce different output
//! while maintaining the same functionality.
//!
//! ## Techniques
//!
//! 1. **Prefix/Suffix junk** - Add junk at start/end (safe from jump issues)
//! 2. **NOP_N padding** - Variable-length NOPs with harmless padding
//! 3. **Opaque predicates** - Always-true/false conditions
//! 4. **Watermark embedding** - Steganographic watermark in padding bytes
//!
//! ## Safety
//!
//! This transformer is JUMP-SAFE: it only adds junk at the beginning and end
//! of the bytecode, never between instructions. This ensures that jump offsets
//! in the original bytecode remain valid.
//!
//! ## Determinism
//!
//! The seed is derived ONLY from fn_name + build_seed, NOT from system time.
//! This ensures reproducible builds.
//!
//! ## Watermarking
//!
//! Each protected function embeds a portion of the build watermark in its
//! polymorphic prefix. The watermark is spread across multiple functions,
//! making it resilient to partial code removal.

#![allow(dead_code)] // Functions available for future integration

use crate::opcodes::{stack, special};
use crate::crypto::OpcodeTable;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Polymorphic transformation level
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum PolymorphicLevel {
    /// No transformations (debug mode)
    None,
    /// Medium transformations (moderate prefix/suffix)
    #[default]
    Medium,
    /// Heavy transformations (large prefix/suffix with opaque predicates)
    Heavy,
}

/// Seeded random number generator for deterministic but varied output
struct SeededRng {
    state: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { state: seed ^ 0x5DEECE66D }
    }

    fn next(&mut self) -> u64 {
        // LCG parameters (same as java.util.Random)
        self.state = self.state.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
        self.state
    }

    fn next_u8(&mut self) -> u8 {
        (self.next() >> 32) as u8
    }

    fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 { return 0; }
        self.next() % max
    }

    /// Generate a harmless padding byte (NOP opcode or zero)
    fn next_harmless_byte(&mut self) -> u8 {
        // Only use bytes that won't cause issues if accidentally executed
        const HARMLESS: [u8; 4] = [
            0x00,           // Zero (often NOP in many VMs)
            special::NOP,   // Our NOP opcode (0x40)
            0x90,           // x86 NOP (harmless padding)
            0xCC,           // x86 INT3 (debug trap, harmless)
        ];
        HARMLESS[self.next_range(4) as usize]
    }
}

/// Generate a seed from function name and build context
/// IMPORTANT: This is DETERMINISTIC - no system time used!
pub fn generate_poly_seed(fn_name: &str, build_seed: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    fn_name.hash(&mut hasher);
    build_seed.hash(&mut hasher);
    // Add a version constant for cache-busting when algorithm changes
    "polymorphic-v2".hash(&mut hasher);
    hasher.finish()
}

/// Polymorphic bytecode transformer
pub struct PolymorphicTransformer {
    rng: SeededRng,
    level: PolymorphicLevel,
    output: Vec<u8>,
    /// Watermark bytes to embed (optional)
    watermark: Option<[u8; 16]>,
    /// Current position in watermark
    watermark_pos: usize,
    /// Opcode encoding table for shuffled opcodes
    opcode_table: OpcodeTable,
}

impl PolymorphicTransformer {
    /// Create new transformer with seed
    pub fn new(seed: u64, level: PolymorphicLevel) -> Self {
        Self {
            rng: SeededRng::new(seed),
            level,
            output: Vec::new(),
            watermark: None,
            watermark_pos: 0,
            opcode_table: crate::crypto::get_opcode_table(),
        }
    }

    /// Create transformer with watermark embedding
    pub fn with_watermark(seed: u64, level: PolymorphicLevel, watermark: [u8; 16]) -> Self {
        Self {
            rng: SeededRng::new(seed),
            level,
            output: Vec::new(),
            watermark: Some(watermark),
            watermark_pos: 0,
            opcode_table: crate::crypto::get_opcode_table(),
        }
    }

    /// Emit an opcode (encoded via shuffle table)
    fn emit_op(&mut self, base_opcode: u8) {
        self.output.push(self.opcode_table.encode(base_opcode));
    }

    /// Get next watermark byte (cycling through the 16 bytes)
    fn next_watermark_byte(&mut self) -> u8 {
        if let Some(wm) = &self.watermark {
            let byte = wm[self.watermark_pos % 16];
            self.watermark_pos += 1;
            byte
        } else {
            self.rng.next_harmless_byte()
        }
    }

    /// Transform bytecode with polymorphic techniques
    ///
    /// SAFETY: This only adds junk at the beginning, never between instructions.
    /// This ensures that all jump offsets in the original bytecode remain valid.
    pub fn transform(&mut self, bytecode: &[u8]) -> Vec<u8> {
        if self.level == PolymorphicLevel::None {
            return bytecode.to_vec();
        }

        self.output.clear();

        // Add polymorphic prefix (junk at the beginning)
        self.insert_prefix();

        // Copy original bytecode UNCHANGED (preserves all jump offsets)
        self.output.extend_from_slice(bytecode);

        self.output.clone()
    }

    /// Insert polymorphic prefix (junk code at the beginning)
    /// This is safe because it comes BEFORE any jump targets
    fn insert_prefix(&mut self) {
        let junk_count = match self.level {
            PolymorphicLevel::None => 0,
            PolymorphicLevel::Medium => 2 + self.rng.next_range(3) as usize,
            PolymorphicLevel::Heavy => 4 + self.rng.next_range(4) as usize,
        };

        for _ in 0..junk_count {
            self.insert_safe_junk();
        }
    }

    /// Insert a single piece of safe junk code
    /// All patterns are stack-neutral and use only safe operations
    fn insert_safe_junk(&mut self) {
        let junk_type = self.rng.next_range(6);

        match junk_type {
            0 => {
                // Single NOP
                self.emit_op(special::NOP);
            }
            1 => {
                // Multiple NOPs using NOP_N with watermark/harmless padding
                let count = 2 + self.rng.next_range(4) as u8;  // 2-5 bytes
                self.emit_op(special::NOP_N);
                self.output.push(count);
                // Embed watermark bytes in padding (steganographic)
                for _ in 0..count {
                    let byte = self.next_watermark_byte();
                    self.output.push(byte);
                }
            }
            2 => {
                // Push + Drop (stack-neutral)
                let val = self.rng.next_u8();
                self.emit_op(stack::PUSH_IMM8);
                self.output.push(val);
                self.emit_op(stack::DROP);
            }
            3 => {
                // Double Push + Drop (stack-neutral, more confusing)
                let val1 = self.rng.next_u8();
                let val2 = self.rng.next_u8();
                self.emit_op(stack::PUSH_IMM8);
                self.output.push(val1);
                self.emit_op(stack::PUSH_IMM8);
                self.output.push(val2);
                self.emit_op(stack::DROP);
                self.emit_op(stack::DROP);
            }
            4 => {
                // Opaque TRUE predicate + DROP (stack-neutral)
                // OPAQUE_TRUE always pushes 1 but is hard to analyze statically
                self.emit_op(special::OPAQUE_TRUE);
                self.emit_op(stack::DROP);
            }
            5 => {
                // Opaque FALSE predicate + DROP (stack-neutral)
                // OPAQUE_FALSE always pushes 0 but is hard to analyze statically
                self.emit_op(special::OPAQUE_FALSE);
                self.emit_op(stack::DROP);
            }
            _ => {
                self.emit_op(special::NOP);
            }
        }
    }
}

/// Apply polymorphic transformation to bytecode
pub fn apply_polymorphism(
    bytecode: &[u8],
    fn_name: &str,
    level: PolymorphicLevel,
) -> Vec<u8> {
    let seed = generate_poly_seed(fn_name, b"polymorphic-transform");
    let mut transformer = PolymorphicTransformer::new(seed, level);
    transformer.transform(bytecode)
}

/// Apply polymorphic transformation with watermark embedding
/// The watermark is spread across multiple functions' NOP_N padding
pub fn apply_polymorphism_with_watermark(
    bytecode: &[u8],
    fn_name: &str,
    level: PolymorphicLevel,
    watermark: [u8; 16],
) -> Vec<u8> {
    let seed = generate_poly_seed(fn_name, b"polymorphic-transform");
    let mut transformer = PolymorphicTransformer::with_watermark(seed, level, watermark);
    transformer.transform(bytecode)
}

/// Extract watermark fragments from bytecode prefix
/// Returns bytes found after NOP_N instructions
pub fn extract_watermark_fragments(bytecode: &[u8]) -> Vec<u8> {
    let mut fragments = Vec::new();
    let mut i = 0;

    while i < bytecode.len() {
        if bytecode[i] == special::NOP_N && i + 1 < bytecode.len() {
            let count = bytecode[i + 1] as usize;
            let start = i + 2;
            let end = (start + count).min(bytecode.len());

            for &byte in &bytecode[start..end] {
                fragments.push(byte);
            }
            i = end;
        } else {
            i += 1;
        }
    }

    fragments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::{arithmetic, exec};

    #[test]
    fn test_deterministic_seed() {
        // Same inputs should always produce same seed
        let seed1 = generate_poly_seed("test_func", b"seed123");
        let seed2 = generate_poly_seed("test_func", b"seed123");
        assert_eq!(seed1, seed2, "Seed should be deterministic");

        // Different names should produce different seeds
        let seed3 = generate_poly_seed("other_func", b"seed123");
        assert_ne!(seed1, seed3, "Different names should give different seeds");
    }

    #[test]
    fn test_nop_insertion() {
        let bytecode = vec![
            stack::PUSH_IMM8, 42,
            stack::PUSH_IMM8, 10,
            arithmetic::ADD,
            exec::HALT,
        ];

        let transformed = apply_polymorphism(&bytecode, "test_func", PolymorphicLevel::Heavy);

        // Should be larger due to prefix junk
        assert!(transformed.len() >= bytecode.len());

        // Should still end with the original bytecode (HALT at end)
        assert_eq!(transformed.last(), bytecode.last());

        // Original bytecode should be preserved at the end
        let orig_len = bytecode.len();
        let trans_len = transformed.len();
        assert_eq!(
            &transformed[trans_len - orig_len..],
            &bytecode[..],
            "Original bytecode should be preserved at the end"
        );
    }

    #[test]
    fn test_no_transform() {
        let bytecode = vec![
            stack::PUSH_IMM8, 42,
            exec::HALT,
        ];

        let transformed = apply_polymorphism(&bytecode, "test_func", PolymorphicLevel::None);

        // Should be identical
        assert_eq!(transformed, bytecode);
    }

    #[test]
    fn test_deterministic_transform() {
        let bytecode = vec![
            stack::PUSH_IMM8, 42,
            arithmetic::INC,
            exec::HALT,
        ];

        // Multiple transforms with same name should produce same result
        let t1 = apply_polymorphism(&bytecode, "same_name", PolymorphicLevel::Medium);
        let t2 = apply_polymorphism(&bytecode, "same_name", PolymorphicLevel::Medium);

        assert_eq!(t1, t2, "Same function name should produce same transformation");
    }

    #[test]
    fn test_different_names_different_output() {
        let bytecode = vec![
            stack::PUSH_IMM8, 42,
            exec::HALT,
        ];

        let t1 = apply_polymorphism(&bytecode, "func_a", PolymorphicLevel::Heavy);
        let t2 = apply_polymorphism(&bytecode, "func_b", PolymorphicLevel::Heavy);

        // Different function names should (likely) produce different output
        // Note: There's a tiny chance they could be the same, but very unlikely
        assert_ne!(t1, t2, "Different function names should produce different transformations");
    }

    #[test]
    fn test_watermark_embedding() {
        let bytecode = vec![
            stack::PUSH_IMM8, 42,
            exec::HALT,
        ];

        let watermark: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        ];

        // Heavy level to ensure NOP_N patterns are inserted
        let transformed = apply_polymorphism_with_watermark(
            &bytecode,
            "test_watermark",
            PolymorphicLevel::Heavy,
            watermark,
        );

        // Transformed should be larger
        assert!(transformed.len() > bytecode.len());

        // Extract watermark fragments
        let fragments = extract_watermark_fragments(&transformed);

        // If NOP_N was inserted, fragments should contain watermark bytes
        if !fragments.is_empty() {
            // Check that extracted bytes match watermark (cycling)
            for (i, &byte) in fragments.iter().enumerate() {
                assert_eq!(
                    byte,
                    watermark[i % 16],
                    "Watermark byte {} mismatch",
                    i
                );
            }
        }
    }

    #[test]
    fn test_watermark_determinism() {
        let bytecode = vec![
            stack::PUSH_IMM8, 100,
            arithmetic::INC,
            exec::HALT,
        ];

        let watermark: [u8; 16] = [0x11; 16];

        let t1 = apply_polymorphism_with_watermark(
            &bytecode, "wm_func", PolymorphicLevel::Heavy, watermark
        );
        let t2 = apply_polymorphism_with_watermark(
            &bytecode, "wm_func", PolymorphicLevel::Heavy, watermark
        );

        assert_eq!(t1, t2, "Watermarked transforms should be deterministic");
    }

    #[test]
    fn test_different_watermarks() {
        let bytecode = vec![
            stack::PUSH_IMM8, 50,
            exec::HALT,
        ];

        let wm1: [u8; 16] = [0xAA; 16];
        let wm2: [u8; 16] = [0xBB; 16];

        let t1 = apply_polymorphism_with_watermark(
            &bytecode, "same_func", PolymorphicLevel::Heavy, wm1
        );
        let t2 = apply_polymorphism_with_watermark(
            &bytecode, "same_func", PolymorphicLevel::Heavy, wm2
        );

        // Same function, different watermarks = different output
        // (only if NOP_N was inserted with watermark bytes)
        let f1 = extract_watermark_fragments(&t1);
        let f2 = extract_watermark_fragments(&t2);

        if !f1.is_empty() && !f2.is_empty() {
            assert_ne!(f1, f2, "Different watermarks should produce different fragments");
        }
    }
}
