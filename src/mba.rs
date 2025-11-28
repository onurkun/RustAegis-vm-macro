//! Mixed Boolean-Arithmetic (MBA) Transformations
//!
//! Transforms simple arithmetic operations into equivalent but complex
//! boolean-arithmetic expressions that are hard to reverse engineer.
//!
//! ## Theory
//!
//! MBA expressions exploit the relationship between boolean and arithmetic
//! operations. For example:
//!
//! ```text
//! x + y = (x ^ y) + 2 * (x & y)
//! x + y = (x | y) + (x & y)
//! x - y = (x ^ y) - 2 * (~x & y)
//! ```
//!
//! These are mathematically equivalent but much harder to pattern match.
//!
//! ## References
//!
//! - "Hacker's Delight" by Henry S. Warren
//! - VMProtect's mutation engine
//! - OLLVM's MBA pass

use crate::opcodes::{arithmetic, stack};

/// MBA transformation variants for ADD operation
/// x + y = ...
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AddVariant {
    /// Direct ADD (no transformation)
    Direct,
    /// (x ^ y) + 2 * (x & y)
    XorAndDouble,
    /// (x | y) + (x & y)
    OrAnd,
    /// (2 * (x | y)) - (x ^ y) - reserved for future use
    DoubleOrMinusXor,
}

/// MBA transformation variants for SUB operation
/// x - y = ...
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum SubVariant {
    /// Direct SUB (no transformation)
    Direct,
    /// (x ^ y) - 2 * (~x & y)
    XorMinusNotAndDouble,
    /// x + (~y) + 1 (two's complement)
    TwosComplement,
    /// (x & ~y) - (~x & y) - reserved for future use
    MaskedDifference,
}

/// MBA transformation variants for XOR operation
/// x ^ y = ...
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum XorVariant {
    /// Direct XOR (no transformation)
    Direct,
    /// (x | y) & ~(x & y)
    OrAndNotAnd,
    /// (x & ~y) | (~x & y) - reserved for future use
    MaskedOr,
    /// (x | y) - (x & y)
    OrMinusAnd,
}

/// MBA Transformer - generates obfuscated bytecode sequences
pub struct MbaTransformer {
    /// Entropy seed for variant selection
    seed: u64,
}

impl MbaTransformer {
    /// Create new transformer with given seed
    pub fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Simple LCG for deterministic randomness
    fn next_random(&mut self) -> u64 {
        self.seed = self.seed.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
        self.seed
    }

    /// Select ADD variant based on entropy
    /// ~75% Direct, ~25% obfuscated to avoid bytecode bloat
    fn select_add_variant(&mut self) -> AddVariant {
        match self.next_random() % 8 {
            0 => AddVariant::XorAndDouble,
            1 => AddVariant::OrAnd,
            _ => AddVariant::Direct, // 75% direct
        }
    }

    /// Select SUB variant based on entropy
    /// ~75% Direct, ~25% obfuscated to avoid bytecode bloat
    fn select_sub_variant(&mut self) -> SubVariant {
        match self.next_random() % 8 {
            0 => SubVariant::TwosComplement, // Simplest obfuscation
            1 => SubVariant::XorMinusNotAndDouble,
            _ => SubVariant::Direct, // 75% direct
        }
    }

    /// Select XOR variant based on entropy
    /// ~75% Direct, ~25% obfuscated to avoid bytecode bloat
    fn select_xor_variant(&mut self) -> XorVariant {
        match self.next_random() % 8 {
            0 => XorVariant::OrMinusAnd, // Simplest obfuscation
            1 => XorVariant::OrAndNotAnd,
            _ => XorVariant::Direct, // 75% direct
        }
    }

    /// Generate bytecode for ADD with MBA transformation
    /// Stack before: [... y x]  (x on top)
    /// Stack after:  [... result]
    pub fn emit_add(&mut self, output: &mut Vec<u8>, opcode_encoder: impl Fn(u8) -> u8) {
        let variant = self.select_add_variant();

        match variant {
            AddVariant::Direct => {
                // Simple: ADD
                output.push(opcode_encoder(arithmetic::ADD));
            }

            AddVariant::XorAndDouble => {
                // x + y = (x ^ y) + 2 * (x & y)
                // Stack: [y, x] (x is TOS)
                //
                // Save x and y to temp registers, then compute

                output.push(opcode_encoder(stack::DUP));      // [y, x, x]
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = x (temp register)

                output.push(opcode_encoder(stack::SWAP));     // [x, y]
                output.push(opcode_encoder(stack::DUP));      // [x, y, y]
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = y (temp register)

                // Now stack is [x, y], R7=x, R6=y
                // Compute x & y
                output.push(opcode_encoder(arithmetic::AND)); // [x & y]

                // Multiply by 2 (shift left 1)
                output.push(opcode_encoder(stack::PUSH_IMM8));
                output.push(1);
                output.push(opcode_encoder(arithmetic::SHL)); // [2*(x&y)]

                // Now compute x ^ y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7); // push x
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6); // push y
                output.push(opcode_encoder(arithmetic::XOR)); // [2*(x&y), x^y]

                // Add them
                output.push(opcode_encoder(arithmetic::ADD)); // [(x^y) + 2*(x&y)]
            }

            AddVariant::OrAnd => {
                // x + y = (x | y) + (x & y)
                // Stack: [y, x]

                // Save x and y to temp registers
                output.push(opcode_encoder(stack::DUP));      // [y, x, x]
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = x

                output.push(opcode_encoder(stack::SWAP));     // [x, y]
                output.push(opcode_encoder(stack::DUP));      // [x, y, y]
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = y

                // Stack: [x, y], R7=x, R6=y
                // Compute x | y
                output.push(opcode_encoder(arithmetic::OR));  // [x | y]

                // Compute x & y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7);
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6);
                output.push(opcode_encoder(arithmetic::AND)); // [x|y, x&y]

                // Add them
                output.push(opcode_encoder(arithmetic::ADD)); // [(x|y) + (x&y)]
            }

            AddVariant::DoubleOrMinusXor => {
                // x + y = 2*(x | y) - (x ^ y)
                // Stack: [y, x]

                // Save x and y
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = x

                output.push(opcode_encoder(stack::SWAP));
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = y

                // Compute x | y
                output.push(opcode_encoder(arithmetic::OR));  // [x | y]

                // Multiply by 2
                output.push(opcode_encoder(stack::PUSH_IMM8));
                output.push(1);
                output.push(opcode_encoder(arithmetic::SHL)); // [2*(x|y)]

                // Compute x ^ y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7);
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6);
                output.push(opcode_encoder(arithmetic::XOR)); // [2*(x|y), x^y]

                // Subtract
                output.push(opcode_encoder(arithmetic::SUB)); // [2*(x|y) - (x^y)]
            }
        }
    }

    /// Generate bytecode for SUB with MBA transformation
    /// Stack before: [... y x]  (x on top, result = y - x... wait, need to check stack order)
    /// Actually: SUB pops x, then y, computes y - x... let me verify
    /// Engine: let b = pop, let a = pop, push(a - b) -> so [a, b] -> a - b
    /// So stack [y, x] with x on top -> y - x
    pub fn emit_sub(&mut self, output: &mut Vec<u8>, opcode_encoder: impl Fn(u8) -> u8) {
        let variant = self.select_sub_variant();

        match variant {
            SubVariant::Direct => {
                output.push(opcode_encoder(arithmetic::SUB));
            }

            SubVariant::TwosComplement => {
                // x - y = x + (~y + 1) = x + (-y)
                // Stack: [x, y] where we want x - y
                // Actually with [y, x] on stack (x top), SUB gives y - x
                // So if we want y - x:
                // y - x = y + (~x + 1)

                // Stack: [y, x] (x on top)
                output.push(opcode_encoder(arithmetic::NOT)); // [y, ~x]
                output.push(opcode_encoder(arithmetic::INC)); // [y, ~x+1] = [y, -x]
                output.push(opcode_encoder(arithmetic::ADD)); // [y + (-x)] = [y - x]
            }

            SubVariant::XorMinusNotAndDouble => {
                // a - b = (a ^ b) - 2 * (~a & b)
                // Stack: [a, b] (b on top), we compute a - b

                // Save a and b
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = b

                output.push(opcode_encoder(stack::SWAP));
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = a

                // Stack: [b, a], R7=b, R6=a
                output.push(opcode_encoder(stack::SWAP)); // [a, b]

                // Compute a ^ b
                output.push(opcode_encoder(arithmetic::XOR)); // [a ^ b]

                // Compute ~a & b
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6); // push a
                output.push(opcode_encoder(arithmetic::NOT)); // [a^b, ~a]
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7); // push b
                output.push(opcode_encoder(arithmetic::AND)); // [a^b, ~a & b]

                // Multiply by 2
                output.push(opcode_encoder(stack::PUSH_IMM8));
                output.push(1);
                output.push(opcode_encoder(arithmetic::SHL)); // [a^b, 2*(~a & b)]

                // Subtract
                output.push(opcode_encoder(arithmetic::SUB)); // [(a^b) - 2*(~a & b)]
            }

            SubVariant::MaskedDifference => {
                // a - b = (a & ~b) - (~a & b)
                // This is a bit-level subtraction

                // Save operands
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = b (top of stack)

                output.push(opcode_encoder(stack::SWAP));
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = a

                output.push(opcode_encoder(stack::DROP)); // drop extra
                output.push(opcode_encoder(stack::DROP)); // drop extra

                // Compute a & ~b
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6); // push a
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7); // push b
                output.push(opcode_encoder(arithmetic::NOT)); // [a, ~b]
                output.push(opcode_encoder(arithmetic::AND)); // [a & ~b]

                // Compute ~a & b
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6); // push a
                output.push(opcode_encoder(arithmetic::NOT)); // [a&~b, ~a]
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7); // push b
                output.push(opcode_encoder(arithmetic::AND)); // [a&~b, ~a & b]

                // Subtract
                output.push(opcode_encoder(arithmetic::SUB)); // [(a&~b) - (~a&b)]
            }
        }
    }

    /// Generate bytecode for XOR with MBA transformation
    pub fn emit_xor(&mut self, output: &mut Vec<u8>, opcode_encoder: impl Fn(u8) -> u8) {
        let variant = self.select_xor_variant();

        match variant {
            XorVariant::Direct => {
                output.push(opcode_encoder(arithmetic::XOR));
            }

            XorVariant::OrAndNotAnd => {
                // x ^ y = (x | y) & ~(x & y)

                // Save operands
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = y (top)

                output.push(opcode_encoder(stack::SWAP));
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = x

                // Compute x | y
                output.push(opcode_encoder(arithmetic::OR)); // [x | y]

                // Compute x & y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6);
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7);
                output.push(opcode_encoder(arithmetic::AND)); // [x|y, x&y]

                // NOT and AND
                output.push(opcode_encoder(arithmetic::NOT)); // [x|y, ~(x&y)]
                output.push(opcode_encoder(arithmetic::AND)); // [(x|y) & ~(x&y)]
            }

            XorVariant::MaskedOr => {
                // x ^ y = (x & ~y) | (~x & y)

                // Save operands
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7); // R7 = y

                output.push(opcode_encoder(stack::SWAP));
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6); // R6 = x

                output.push(opcode_encoder(stack::DROP));
                output.push(opcode_encoder(stack::DROP));

                // Compute x & ~y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6); // x
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7); // y
                output.push(opcode_encoder(arithmetic::NOT)); // ~y
                output.push(opcode_encoder(arithmetic::AND)); // x & ~y

                // Compute ~x & y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6); // x
                output.push(opcode_encoder(arithmetic::NOT)); // ~x
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7); // y
                output.push(opcode_encoder(arithmetic::AND)); // ~x & y

                // OR them
                output.push(opcode_encoder(arithmetic::OR)); // (x&~y) | (~x&y)
            }

            XorVariant::OrMinusAnd => {
                // x ^ y = (x | y) - (x & y)

                // Save operands
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(7);

                output.push(opcode_encoder(stack::SWAP));
                output.push(opcode_encoder(stack::DUP));
                output.push(opcode_encoder(stack::POP_REG));
                output.push(6);

                // Compute x | y
                output.push(opcode_encoder(arithmetic::OR));

                // Compute x & y
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(6);
                output.push(opcode_encoder(stack::PUSH_REG));
                output.push(7);
                output.push(opcode_encoder(arithmetic::AND));

                // Subtract
                output.push(opcode_encoder(arithmetic::SUB)); // (x|y) - (x&y)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_variants() {
        let mut mba = MbaTransformer::new(12345);
        let mut output = Vec::new();

        // Test that each call produces deterministic output
        mba.emit_add(&mut output, |x| x);
        assert!(!output.is_empty());

        let first_output = output.clone();
        output.clear();

        // Same seed should produce same sequence
        let mut mba2 = MbaTransformer::new(12345);
        mba2.emit_add(&mut output, |x| x);
        assert_eq!(first_output, output);
    }

    #[test]
    fn test_variant_selection() {
        let _mba = MbaTransformer::new(0);

        // Different seeds should eventually produce different variants
        let mut variants_seen = std::collections::HashSet::new();
        for seed in 0..100 {
            let mut m = MbaTransformer::new(seed);
            let v = m.select_add_variant();
            variants_seen.insert(std::mem::discriminant(&v));
        }

        // Should see multiple variants
        assert!(variants_seen.len() > 1);
    }
}
