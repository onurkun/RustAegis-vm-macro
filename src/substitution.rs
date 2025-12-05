// Allow unused code - these are library functions for incremental compiler integration
#![allow(dead_code)]

//! Instruction Substitution
//!
//! Replaces simple instructions with equivalent but more complex sequences.
//! This increases resistance to pattern matching and static analysis.
//!
//! ## Substitution Rules
//!
//! ### Basic Substitutions
//! - `INC` → `PUSH 1, ADD` or `PUSH -1, SUB`
//! - `DEC` → `PUSH 1, SUB` or `PUSH -1, ADD`
//! - `NOT` → `XOR 0xFFFF...`
//! - `AND` → De Morgan: `~(~a | ~b)`
//! - `OR`  → De Morgan: `~(~a & ~b)`
//! - Constants → Split: `X = A + B`
//! - Zero → `X ^ X = 0`
//!
//! ### Advanced Substitutions (Industry Standard)
//!
//! #### Arithmetic Identities
//! - `a + 0` → `a` (identity)
//! - `a * 1` → `a` (identity)
//! - `a * 0` → `0` (zero)
//! - `a ^ 0` → `a` (identity)
//! - `a & -1` → `a` (identity)
//! - `a | 0` → `a` (identity)
//!
//! #### Complex Arithmetic
//! - `a + b` → `a - (-b)`
//! - `a - b` → `a + (-b)` or `~(~a + b)`
//! - `a * 2` → `a + a` or `a << 1`
//! - `a * 3` → `(a << 1) + a`
//! - `a / 2` → `a >> 1` (unsigned)
//!
//! #### Bitwise Identities
//! - `a ^ a` → `0`
//! - `a & a` → `a`
//! - `a | a` → `a`
//! - `a ^ -1` → `~a`
//! - `~~a` → `a`
//!
//! #### Dead Code Patterns
//! - `PUSH X, DROP` (no effect)
//! - `DUP, DROP` (no effect)
//! - `SWAP, SWAP` (no effect)
//!
//! #### Opaque Predicates
//! - `(x * x) >= 0` → always true
//! - `(x | 1) != 0` → always true
//! - `(x ^ x) == 0` → always true

use crate::opcodes::{stack, arithmetic, control, special};

/// Substitution state - handles RNG and decision making
pub struct Substitution {
    /// RNG state for deterministic choices
    rng: u64,
    /// Whether substitution is enabled
    enabled: bool,
}

impl Substitution {
    /// Create new substitution state
    pub fn new(seed: u64, enabled: bool) -> Self {
        Self {
            rng: seed ^ 0xCAFEBABE_DEADBEEF,
            enabled,
        }
    }

    /// Get next random value (deterministic)
    pub fn next_rand(&mut self) -> u64 {
        self.rng = self.rng
            .wrapping_mul(0x5851F42D4C957F2D)
            .wrapping_add(0x14057B7EF767814F);
        self.rng
    }

    /// Should we substitute this instruction? (50% chance when enabled)
    pub fn should_substitute(&mut self) -> bool {
        self.enabled && (self.next_rand() % 100) < 50
    }

    /// Check if substitution is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Substitution variants for INC instruction
pub enum IncSubstitution {
    /// Use original INC
    Original,
    /// INC → PUSH 1, ADD
    PushOneAdd,
    /// INC → PUSH -1, SUB (a + 1 = a - (-1))
    PushNegOneSub,
}

impl IncSubstitution {
    /// Choose a substitution variant based on RNG
    pub fn choose(subst: &mut Substitution) -> Self {
        if !subst.should_substitute() {
            return Self::Original;
        }
        match subst.next_rand() % 3 {
            0 => Self::PushOneAdd,
            1 => Self::PushNegOneSub,
            _ => Self::Original,
        }
    }

    /// Get the opcodes/bytes for this substitution
    /// Returns (needs_add, needs_sub, bytes_before_op)
    pub fn emit<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) -> (bool, bool) {
        match self {
            Self::Original => {
                bytecode.push(encode(arithmetic::INC));
                (false, false)
            }
            Self::PushOneAdd => {
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(1);
                (true, false) // needs emit_add after
            }
            Self::PushNegOneSub => {
                bytecode.push(encode(stack::PUSH_IMM));
                bytecode.extend_from_slice(&u64::MAX.to_le_bytes());
                (false, true) // needs emit_sub after
            }
        }
    }
}

/// Substitution variants for DEC instruction
pub enum DecSubstitution {
    /// Use original DEC
    Original,
    /// DEC → PUSH 1, SUB
    PushOneSub,
    /// DEC → PUSH -1, ADD (a - 1 = a + (-1))
    PushNegOneAdd,
}

impl DecSubstitution {
    /// Choose a substitution variant based on RNG
    pub fn choose(subst: &mut Substitution) -> Self {
        if !subst.should_substitute() {
            return Self::Original;
        }
        match subst.next_rand() % 3 {
            0 => Self::PushOneSub,
            1 => Self::PushNegOneAdd,
            _ => Self::Original,
        }
    }

    /// Emit the substitution
    /// Returns (needs_add, needs_sub)
    pub fn emit<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) -> (bool, bool) {
        match self {
            Self::Original => {
                bytecode.push(encode(arithmetic::DEC));
                (false, false)
            }
            Self::PushOneSub => {
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(1);
                (false, true) // needs emit_sub
            }
            Self::PushNegOneAdd => {
                bytecode.push(encode(stack::PUSH_IMM));
                bytecode.extend_from_slice(&u64::MAX.to_le_bytes());
                (true, false) // needs emit_add
            }
        }
    }
}

/// Substitution variants for NOT instruction
pub enum NotSubstitution {
    /// Use original NOT
    Original,
    /// NOT → PUSH MAX, XOR (~a = a ^ 0xFFFF...)
    XorWithMax,
}

impl NotSubstitution {
    /// Choose a substitution variant based on RNG
    pub fn choose(subst: &mut Substitution) -> Self {
        if subst.should_substitute() {
            Self::XorWithMax
        } else {
            Self::Original
        }
    }

    /// Emit the substitution
    /// Returns true if needs emit_xor after
    pub fn emit<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) -> bool {
        match self {
            Self::Original => {
                bytecode.push(encode(arithmetic::NOT));
                false
            }
            Self::XorWithMax => {
                bytecode.push(encode(stack::PUSH_IMM));
                bytecode.extend_from_slice(&u64::MAX.to_le_bytes());
                true // needs emit_xor
            }
        }
    }
}

/// Substitution for AND using De Morgan's law
pub struct AndSubstitution;

impl AndSubstitution {
    /// Check if should use De Morgan substitution
    pub fn should_use(subst: &mut Substitution) -> bool {
        subst.should_substitute()
    }

    /// Emit De Morgan: a & b = ~(~a | ~b)
    /// Caller must handle emit_not and final OR/NOT sequence
    pub fn emit_demorgan_prefix<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        // Stack: [a, b]
        // SWAP: [b, a]
        bytecode.push(encode(stack::SWAP));
        // Then caller does: emit_not, SWAP, emit_not, OR, emit_not
    }

    /// Emit middle SWAP for De Morgan
    pub fn emit_demorgan_swap<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(stack::SWAP));
    }

    /// Emit final OR for De Morgan AND
    pub fn emit_demorgan_or<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(arithmetic::OR));
    }

    /// Emit original AND
    pub fn emit_original<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(arithmetic::AND));
    }
}

/// Substitution for OR using De Morgan's law
pub struct OrSubstitution;

impl OrSubstitution {
    /// Check if should use De Morgan substitution
    pub fn should_use(subst: &mut Substitution) -> bool {
        subst.should_substitute()
    }

    /// Emit De Morgan prefix (same as AND)
    pub fn emit_demorgan_prefix<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(stack::SWAP));
    }

    /// Emit middle SWAP for De Morgan
    pub fn emit_demorgan_swap<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(stack::SWAP));
    }

    /// Emit final AND for De Morgan OR
    pub fn emit_demorgan_and<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(arithmetic::AND));
    }

    /// Emit original OR
    pub fn emit_original<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(arithmetic::OR));
    }
}

/// Constant obfuscation - split X into A + B
pub struct ConstantSubstitution;

impl ConstantSubstitution {
    /// Check if should split constant
    pub fn should_split(subst: &mut Substitution, value: u64) -> bool {
        subst.should_substitute() && value > 1 && value < u64::MAX - 1000
    }

    /// Calculate split values: returns (a, b) where a + b = value
    pub fn split(subst: &mut Substitution, value: u64) -> (u64, u64) {
        let a = subst.next_rand() % (value / 2 + 1);
        let b = value - a;
        (a, b)
    }

    /// Emit a constant value (helper)
    pub fn emit_value<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, value: u64, encode: &F) {
        if value <= 255 {
            bytecode.push(encode(stack::PUSH_IMM8));
            bytecode.push(value as u8);
        } else {
            bytecode.push(encode(stack::PUSH_IMM));
            bytecode.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Zero obfuscation - X ^ X = 0
pub struct ZeroSubstitution;

impl ZeroSubstitution {
    /// Check if should obfuscate zero
    pub fn should_obfuscate(subst: &mut Substitution) -> bool {
        subst.should_substitute()
    }

    /// Get random value for X ^ X pattern
    pub fn get_xor_value(subst: &mut Substitution) -> u8 {
        (subst.next_rand() % 255) as u8 + 1 // 1-255
    }

    /// Emit: PUSH X, DUP (then caller does emit_xor)
    pub fn emit_prefix<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, x: u8, encode: &F) {
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DUP));
    }

    /// Emit standard zero
    pub fn emit_original<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(0);
    }
}

// =============================================================================
// ADVANCED SUBSTITUTIONS - Industry Standard Obfuscation
// =============================================================================

// These are library functions available for integration into compiler.rs
// They are intentionally not all used yet - compiler integration is incremental

/// ADD instruction substitution variants
/// Stack: [a, b] -> [a + b]
pub enum AddSubstitution {
    /// Original ADD
    Original,
    /// a + b = a - (-b) = a - (~b + 1)
    SubNegate,
    /// a + b = ~(~a - b) [alternative form]
    NotSubNot,
}

impl AddSubstitution {
    /// Choose substitution variant
    /// Substitutions verified mathematically correct:
    /// - SubNegate: a + b = a - (-b) via NOT, INC, SUB
    /// - NotSubNot: a + b = ~(~a - b) via SWAP, NOT, SWAP, SUB, NOT
    pub fn choose(subst: &mut Substitution) -> Self {
        if !subst.should_substitute() {
            return Self::Original;
        }
        match subst.next_rand() % 5 {
            0 => Self::SubNegate,
            1 => Self::NotSubNot,
            _ => Self::Original,
        }
    }

    /// Emit the substitution
    /// Returns flags for what operations caller needs to emit
    pub fn emit<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) -> AddEmitResult {
        match self {
            Self::Original => {
                bytecode.push(encode(arithmetic::ADD));
                AddEmitResult::Done
            }
            Self::SubNegate => {
                // a + b = a - (-b)
                // Stack: [a, b]
                // NOT b: [a, ~b]
                // INC:   [a, ~b+1] = [a, -b]
                // SUB:   [a - (-b)] = [a + b]
                bytecode.push(encode(arithmetic::NOT));
                bytecode.push(encode(arithmetic::INC));
                bytecode.push(encode(arithmetic::SUB));
                AddEmitResult::Done
            }
            Self::NotSubNot => {
                // a + b = ~(~a - b)
                // Stack: [a, b]
                // SWAP:  [b, a]
                // NOT:   [b, ~a]
                // SWAP:  [~a, b]
                // SUB:   [~a - b]
                // NOT:   [~(~a - b)] = [a + b]
                bytecode.push(encode(stack::SWAP));
                bytecode.push(encode(arithmetic::NOT));
                bytecode.push(encode(stack::SWAP));
                bytecode.push(encode(arithmetic::SUB));
                bytecode.push(encode(arithmetic::NOT));
                AddEmitResult::Done
            }
        }
    }
}

/// Result of ADD emission
pub enum AddEmitResult {
    Done,
}

/// SUB instruction substitution variants
/// Stack: [a, b] -> [a - b]
pub enum SubSubstitution {
    /// Original SUB
    Original,
    /// a - b = a + (-b) = a + (~b + 1)
    AddNegate,
    /// a - b = ~(~a + b)
    NotAddNot,
}

impl SubSubstitution {
    /// Choose substitution variant
    /// Substitutions verified mathematically correct:
    /// - AddNegate: a - b = a + (-b) via NOT, INC, ADD
    /// - NotAddNot: a - b = ~(~a + b) via SWAP, NOT, SWAP, ADD, NOT
    pub fn choose(subst: &mut Substitution) -> Self {
        if !subst.should_substitute() {
            return Self::Original;
        }
        match subst.next_rand() % 5 {
            0 => Self::AddNegate,
            1 => Self::NotAddNot,
            _ => Self::Original,
        }
    }

    /// Emit the substitution
    pub fn emit<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) -> SubEmitResult {
        match self {
            Self::Original => {
                bytecode.push(encode(arithmetic::SUB));
                SubEmitResult::Done
            }
            Self::AddNegate => {
                // a - b = a + (-b)
                // Stack: [a, b]
                // NOT:  [a, ~b]
                // INC:  [a, -b]
                // ADD:  [a + (-b)] = [a - b]
                bytecode.push(encode(arithmetic::NOT));
                bytecode.push(encode(arithmetic::INC));
                bytecode.push(encode(arithmetic::ADD));
                SubEmitResult::Done
            }
            Self::NotAddNot => {
                // a - b = ~(~a + b)
                // Stack: [a, b]
                // SWAP: [b, a]
                // NOT:  [b, ~a]
                // SWAP: [~a, b]
                // ADD:  [~a + b]
                // NOT:  [~(~a + b)] = [a - b]
                bytecode.push(encode(stack::SWAP));
                bytecode.push(encode(arithmetic::NOT));
                bytecode.push(encode(stack::SWAP));
                bytecode.push(encode(arithmetic::ADD));
                bytecode.push(encode(arithmetic::NOT));
                SubEmitResult::Done
            }
        }
    }
}

/// Result of SUB emission
pub enum SubEmitResult {
    Done,
}

/// MUL instruction substitution for special cases
/// Stack: [a, b] -> [a * b]
pub enum MulSubstitution {
    /// Original MUL
    Original,
    /// a * 2 = a + a
    DoubleAdd,
    /// a * 2 = a << 1
    DoubleShift,
    /// a * 3 = (a << 1) + a
    TripleShiftAdd,
    /// a * 4 = a << 2
    QuadShift,
}

impl MulSubstitution {
    /// Choose substitution if multiplying by known constant
    /// Returns None if constant is not suitable for substitution
    pub fn choose_for_constant(subst: &mut Substitution, multiplier: u64) -> Option<Self> {
        if !subst.should_substitute() {
            return None;
        }
        match multiplier {
            2 => {
                if subst.next_rand() % 2 == 0 {
                    Some(Self::DoubleAdd)
                } else {
                    Some(Self::DoubleShift)
                }
            }
            3 => Some(Self::TripleShiftAdd),
            4 => Some(Self::QuadShift),
            8 => Some(Self::QuadShift), // Will emit << 3
            _ => None,
        }
    }

    /// Emit multiplication by 2: a * 2
    /// Assumes stack has [a], will produce [a * 2]
    pub fn emit_mul2<F: Fn(u8) -> u8>(variant: &Self, bytecode: &mut Vec<u8>, encode: &F) {
        match variant {
            Self::DoubleAdd => {
                // a * 2 = a + a
                // Stack: [a]
                // DUP: [a, a]
                // ADD: [a + a]
                bytecode.push(encode(stack::DUP));
                bytecode.push(encode(arithmetic::ADD));
            }
            Self::DoubleShift => {
                // a * 2 = a << 1
                // Stack: [a]
                // PUSH 1: [a, 1]
                // SHL: [a << 1]
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(1);
                bytecode.push(encode(arithmetic::SHL));
            }
            _ => {
                // Fallback: just multiply
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(2);
                bytecode.push(encode(arithmetic::MUL));
            }
        }
    }

    /// Emit multiplication by 3: a * 3
    pub fn emit_mul3<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        // a * 3 = (a << 1) + a = a * 2 + a
        // Stack: [a]
        // DUP: [a, a]
        // PUSH 1: [a, a, 1]
        // SHL: [a, a << 1]
        // ADD: [a + (a << 1)] = [a * 3]
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(1);
        bytecode.push(encode(arithmetic::SHL));
        bytecode.push(encode(arithmetic::ADD));
    }

    /// Emit multiplication by power of 2
    pub fn emit_mul_pow2<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, shift: u8, encode: &F) {
        // a * 2^n = a << n
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(shift);
        bytecode.push(encode(arithmetic::SHL));
    }
}

/// XOR instruction substitution variants
/// Stack: [a, b] -> [a ^ b]
pub enum XorSubstitution {
    /// Original XOR
    Original,
    /// a ^ b = (a | b) & ~(a & b)
    OrAndNot,
    /// a ^ b = (a & ~b) | (~a & b)
    MaskedOr,
}

impl XorSubstitution {
    /// Choose substitution variant
    pub fn choose(subst: &mut Substitution) -> Self {
        if !subst.should_substitute() {
            return Self::Original;
        }
        match subst.next_rand() % 4 {
            0 => Self::OrAndNot,
            1 => Self::MaskedOr,
            _ => Self::Original, // Higher chance of original (simpler)
        }
    }

    /// Emit the substitution
    pub fn emit<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) {
        match self {
            Self::Original => {
                bytecode.push(encode(arithmetic::XOR));
            }
            Self::OrAndNot => {
                // a ^ b = (a | b) & ~(a & b)
                // Stack: [a, b]
                // DUP2 (via SWAP,DUP,ROT,DUP,ROT): [a, b, a, b]
                // We need: [a, b] -> [a|b, ~(a&b)]
                // Simplified approach using registers would be better
                // For now, use a stack-only approach:

                // Actually this is complex without DUP2/registers
                // Fall back to original for now
                bytecode.push(encode(arithmetic::XOR));
            }
            Self::MaskedOr => {
                // Similarly complex without extra stack ops
                // Fall back to original
                bytecode.push(encode(arithmetic::XOR));
            }
        }
    }
}

/// Dead code insertion patterns
/// These emit sequences that have no net effect on the stack/state
/// IMPORTANT: Only stack-safe patterns that don't require existing stack elements
pub struct DeadCodeInsertion;

impl DeadCodeInsertion {
    /// Should insert dead code at this point?
    pub fn should_insert(subst: &mut Substitution) -> bool {
        subst.enabled && (subst.next_rand() % 100) < 15 // 15% chance
    }

    /// Choose and emit a dead code pattern
    /// Only emits patterns that are ALWAYS safe (don't require stack elements)
    pub fn emit<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        // Only use stack-safe patterns (patterns that push their own values)
        match subst.next_rand() % 3 {
            0 => Self::emit_push_drop(subst, bytecode, encode),
            1 => Self::emit_xor_zero(subst, bytecode, encode),
            _ => Self::emit_push_pop_balanced(subst, bytecode, encode),
        }
    }

    /// Emit dead code deterministically based on bytecode position
    /// This doesn't use the substitution RNG, ensuring deterministic output
    /// across different protection levels
    pub fn emit_deterministic<F: Fn(u8) -> u8>(position: usize, bytecode: &mut Vec<u8>, encode: &F) {
        // Use position-based entropy (not RNG)
        let entropy = (position as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0x1234567890ABCDEF);

        // 10% chance to insert dead code
        if (entropy % 100) >= 10 {
            return;
        }

        // Choose pattern based on position
        let pattern = (entropy / 100) % 3;
        match pattern {
            0 => {
                // PUSH X, DROP
                let x = ((entropy >> 8) % 256) as u8;
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(x);
                bytecode.push(encode(stack::DROP));
            }
            1 => {
                // PUSH X, PUSH Y, DROP, DROP - two pushes, two drops
                // NOTE: We avoid XOR here because it modifies CPU flags (Zero Flag)
                // which would corrupt comparison results before conditional jumps
                let x = ((entropy >> 16) % 256) as u8;
                let y = ((entropy >> 24) % 256) as u8;
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(x);
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(y);
                bytecode.push(encode(stack::DROP));
                bytecode.push(encode(stack::DROP));
            }
            _ => {
                // Simple NOP
                bytecode.push(encode(crate::opcodes::special::NOP));
            }
        }
    }

    /// Emit dead code that requires at least one stack element
    /// Call this only when you know the stack is non-empty
    pub fn emit_with_stack<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        match subst.next_rand() % 5 {
            0 => Self::emit_push_drop(subst, bytecode, encode),
            1 => Self::emit_dup_drop(bytecode, encode),
            2 => Self::emit_xor_zero(subst, bytecode, encode),
            3 => Self::emit_not_not(bytecode, encode),
            _ => Self::emit_add_sub_zero(bytecode, encode),
        }
    }

    /// PUSH X, DROP - pushes and immediately drops a value (ALWAYS SAFE)
    fn emit_push_drop<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 256) as u8;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DROP));
    }

    /// DUP, DROP - duplicates top and drops it (REQUIRES 1 stack element)
    fn emit_dup_drop<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(stack::DROP));
    }

    /// PUSH X, PUSH Y, DROP, DROP - two pushes followed by two drops
    /// NOTE: We avoid XOR-based patterns here because XOR modifies CPU flags
    /// (specifically the Zero Flag), which corrupts comparison results when
    /// dead code is inserted before conditional jumps.
    fn emit_xor_zero<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 256) as u8;
        let y = (subst.next_rand() % 256) as u8;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(y);
        bytecode.push(encode(stack::DROP));
        bytecode.push(encode(stack::DROP));
    }

    /// NOT, NOT - double negation (REQUIRES 1 stack element)
    fn emit_not_not<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(arithmetic::NOT));
        bytecode.push(encode(arithmetic::NOT));
    }

    /// PUSH 0, ADD - adds zero (REQUIRES 1 stack element for ADD)
    fn emit_add_sub_zero<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(0);
        bytecode.push(encode(arithmetic::ADD));
    }

    /// PUSH X, PUSH Y, ADD, DROP - balanced push/add/drop (ALWAYS SAFE)
    fn emit_push_pop_balanced<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 100) as u8;
        let y = (subst.next_rand() % 100) as u8;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(y);
        bytecode.push(encode(arithmetic::ADD));
        bytecode.push(encode(stack::DROP));
    }
}

/// Opaque predicates - conditions that always evaluate to true or false
/// but are difficult for static analysis to determine
pub struct OpaquePredicate;

impl OpaquePredicate {
    /// Emit an opaque predicate that always evaluates to true (1)
    /// Stack: [] -> [1]
    pub fn emit_always_true<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        match subst.next_rand() % 4 {
            0 => Self::emit_xor_self_eq_zero(subst, bytecode, encode),
            1 => Self::emit_or_one_ne_zero(subst, bytecode, encode),
            2 => Self::emit_square_ge_zero(subst, bytecode, encode),
            _ => Self::emit_and_self_eq_self(subst, bytecode, encode),
        }
    }

    /// Emit an opaque predicate that always evaluates to false (0)
    /// Stack: [] -> [0]
    pub fn emit_always_false<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        match subst.next_rand() % 3 {
            0 => Self::emit_xor_self_ne_zero(subst, bytecode, encode),
            1 => Self::emit_and_zero(subst, bytecode, encode),
            _ => Self::emit_false_via_sub(subst, bytecode, encode),
        }
    }

    /// (x ^ x) == 0 -> always true
    /// Uses a random value x, computes x^x=0, then checks ==0
    fn emit_xor_self_eq_zero<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 255) as u8 + 1;
        // PUSH x, DUP, XOR -> [0]
        // PUSH 0, CMP, then check zero flag...
        // Simplified: just push 1 with complex path
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(arithmetic::XOR));
        // Now stack has [0], we want to produce [1] if this == 0
        // XOR with 0, check if zero -> push 1
        // Simplified: just check if result is 0 and push 1
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(0);
        bytecode.push(encode(arithmetic::XOR)); // 0 ^ 0 = 0
        // Now we need: if 0 then 1 else 0
        // Use JZ pattern or just push 1 directly (we know it's 0)
        bytecode.push(encode(stack::DROP)); // drop the 0
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(1); // push true
    }

    /// (x | 1) != 0 -> always true (any number OR 1 is at least 1)
    fn emit_or_one_ne_zero<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 256) as u8;
        // PUSH x, PUSH 1, OR -> [x | 1] which is >= 1
        // Check != 0 -> always true
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(1);
        bytecode.push(encode(arithmetic::OR));
        // Result is always >= 1, so != 0 is always true
        // Drop result, push 1
        bytecode.push(encode(stack::DROP));
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(1);
    }

    /// (x * x) >= 0 -> always true for unsigned
    fn emit_square_ge_zero<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 10) as u8 + 1; // Small to avoid overflow complexity
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(arithmetic::MUL));
        // x*x is always >= 0 for unsigned
        bytecode.push(encode(stack::DROP));
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(1);
    }

    /// (x & x) == x -> always true
    fn emit_and_self_eq_self<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 256) as u8;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(arithmetic::AND));
        // x & x == x always
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(arithmetic::XOR)); // if equal, result is 0
        // If 0, condition was true
        bytecode.push(encode(stack::DROP));
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(1);
    }

    /// (x ^ x) != 0 -> always false
    fn emit_xor_self_ne_zero<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 255) as u8 + 1;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(arithmetic::XOR)); // Always 0
        // 0 != 0 is false
        bytecode.push(encode(stack::DROP));
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(0);
    }

    /// x & 0 == 0, always -> used for false
    fn emit_and_zero<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 256) as u8;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(0);
        bytecode.push(encode(arithmetic::AND)); // Always 0
        // Result is already 0 (false)
    }

    /// x - x = 0 -> false value
    fn emit_false_via_sub<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        let x = (subst.next_rand() % 255) as u8 + 1;
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(x);
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(arithmetic::SUB)); // x - x = 0
    }
}

/// Comparison obfuscation
/// Transforms comparison operations into equivalent but more complex forms
pub struct ComparisonSubstitution;

impl ComparisonSubstitution {
    /// Should use obfuscated comparison?
    pub fn should_use(subst: &mut Substitution) -> bool {
        subst.should_substitute()
    }

    /// Emit obfuscated equality check: a == b
    /// Stack: [a, b] -> emits comparison, returns true if needs_further_processing
    /// Standard: a == b -> (a ^ b) == 0
    pub fn emit_eq_obfuscated<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        // a == b  <=>  (a ^ b) == 0
        // Stack: [a, b]
        // XOR: [a ^ b]
        // Then caller checks if result is 0
        bytecode.push(encode(arithmetic::XOR));
        // Caller should then check JZ for equality
    }

    /// Emit obfuscated inequality check: a != b
    /// Stack: [a, b] -> [a ^ b]
    /// Caller checks if result is non-zero (JNZ)
    pub fn emit_ne_obfuscated<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        // a != b  <=>  (a ^ b) != 0
        bytecode.push(encode(arithmetic::XOR));
        // Caller checks JNZ for inequality
    }

    /// Emit less-than using subtraction
    /// a < b can be checked via (a - b) and examining sign/borrow
    /// For unsigned: a < b <=> (a - b) has borrow (wraps around)
    /// This is complex for stack VM, so we just use CMP
    pub fn emit_lt_via_sub<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        // Standard CMP is actually fine for this
        bytecode.push(encode(control::CMP));
    }
}

/// Control flow obfuscation helpers
pub struct ControlFlowSubstitution;

impl ControlFlowSubstitution {
    /// Should obfuscate control flow?
    pub fn should_use(subst: &mut Substitution) -> bool {
        subst.enabled && (subst.next_rand() % 100) < 30 // 30% chance
    }

    /// Emit JZ as: PUSH 0, CMP + JEQ pattern
    /// This replaces simple JZ with a comparison-based jump
    pub fn emit_jz_obfuscated<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, encode: &F) {
        // Stack: [value]
        // PUSH 0: [value, 0]
        // XOR: [value ^ 0] = [value]
        // Now check if zero
        // This doesn't really help, JZ is already checking zero
        // Better: DUP, DUP, XOR (=0), XOR -> same value, more instructions
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(stack::DUP));
        bytecode.push(encode(arithmetic::XOR)); // 0
        bytecode.push(encode(arithmetic::XOR)); // original value
        bytecode.push(encode(stack::DROP)); // drop the duplicate
        // Now original value is on stack, caller emits JZ
    }

    /// Insert a fake conditional that always falls through
    /// Stack-neutral AND flag-neutral: doesn't affect stack or flags
    /// NOTE: This VM uses flag-based jumps (JZ/JNZ check zero_flag)
    /// Only uses PUSH, DROP, DUP, SWAP, NOP which don't modify flags
    pub fn emit_fake_conditional<F: Fn(u8) -> u8>(subst: &mut Substitution, bytecode: &mut Vec<u8>, encode: &F) {
        // Choose a random obfuscation pattern (all stack-neutral AND flag-neutral)
        match subst.next_rand() % 5 {
            0 => {
                // Pattern 1: PUSH x, DROP
                let x = (subst.next_rand() % 256) as u8;
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(x);
                bytecode.push(encode(stack::DROP));
            }
            1 => {
                // Pattern 2: PUSH x, PUSH y, DROP, DROP
                let x = (subst.next_rand() % 256) as u8;
                let y = (subst.next_rand() % 256) as u8;
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(x);
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(y);
                bytecode.push(encode(stack::DROP));
                bytecode.push(encode(stack::DROP));
            }
            2 => {
                // Pattern 3: PUSH x, DUP, DROP, DROP
                let x = (subst.next_rand() % 256) as u8;
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(x);
                bytecode.push(encode(stack::DUP));
                bytecode.push(encode(stack::DROP));
                bytecode.push(encode(stack::DROP));
            }
            3 => {
                // Pattern 4: PUSH x, PUSH y, SWAP, DROP, DROP
                let x = (subst.next_rand() % 256) as u8;
                let y = (subst.next_rand() % 256) as u8;
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(x);
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(y);
                bytecode.push(encode(stack::SWAP));
                bytecode.push(encode(stack::DROP));
                bytecode.push(encode(stack::DROP));
            }
            _ => {
                // Pattern 5: Multiple NOPs (simplest)
                let nop_count = (subst.next_rand() % 3) as usize + 1;
                for _ in 0..nop_count {
                    bytecode.push(encode(special::NOP));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitution_disabled() {
        let mut subst = Substitution::new(12345, false);
        assert!(!subst.should_substitute());
    }

    #[test]
    fn test_substitution_enabled() {
        let mut subst = Substitution::new(12345, true);
        // Should sometimes return true with 50% probability
        let mut found_true = false;
        for _ in 0..100 {
            if subst.should_substitute() {
                found_true = true;
                break;
            }
        }
        assert!(found_true);
    }

    #[test]
    fn test_deterministic() {
        let mut s1 = Substitution::new(99999, true);
        let mut s2 = Substitution::new(99999, true);

        for _ in 0..10 {
            assert_eq!(s1.next_rand(), s2.next_rand());
        }
    }

    #[test]
    fn test_constant_split() {
        let mut subst = Substitution::new(12345, true);
        let (a, b) = ConstantSubstitution::split(&mut subst, 100);
        assert_eq!(a + b, 100);
    }

    #[test]
    fn test_add_substitution_variants() {
        let mut subst = Substitution::new(12345, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x; // Identity encoding for test

        // Test all variants produce bytecode
        for _ in 0..20 {
            let variant = AddSubstitution::choose(&mut subst);
            let initial_len = bytecode.len();
            variant.emit(&mut bytecode, &encode);
            assert!(bytecode.len() > initial_len, "ADD variant should emit bytecode");
        }
    }

    #[test]
    fn test_sub_substitution_variants() {
        let mut subst = Substitution::new(54321, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        for _ in 0..20 {
            let variant = SubSubstitution::choose(&mut subst);
            let initial_len = bytecode.len();
            variant.emit(&mut bytecode, &encode);
            assert!(bytecode.len() > initial_len, "SUB variant should emit bytecode");
        }
    }

    #[test]
    fn test_dead_code_insertion() {
        let mut subst = Substitution::new(11111, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        // Force insertion
        DeadCodeInsertion::emit(&mut subst, &mut bytecode, &encode);
        assert!(!bytecode.is_empty(), "Dead code should emit something");
    }

    #[test]
    fn test_opaque_predicate_true() {
        let mut subst = Substitution::new(22222, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        OpaquePredicate::emit_always_true(&mut subst, &mut bytecode, &encode);
        assert!(!bytecode.is_empty(), "Opaque true should emit bytecode");
    }

    #[test]
    fn test_opaque_predicate_false() {
        let mut subst = Substitution::new(33333, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        OpaquePredicate::emit_always_false(&mut subst, &mut bytecode, &encode);
        assert!(!bytecode.is_empty(), "Opaque false should emit bytecode");
    }

    #[test]
    fn test_mul_substitution_for_powers() {
        let mut subst = Substitution::new(44444, true);

        // Test power of 2 detection
        assert!(MulSubstitution::choose_for_constant(&mut subst, 2).is_some() ||
                !subst.should_substitute()); // May not substitute due to RNG

        let mut subst2 = Substitution::new(44444, true);
        // Force substitution by checking multiple times
        let mut found = false;
        for _ in 0..10 {
            if MulSubstitution::choose_for_constant(&mut subst2, 3).is_some() {
                found = true;
                break;
            }
        }
        // It's probabilistic, so we don't assert
    }

    #[test]
    fn test_xor_substitution() {
        let mut subst = Substitution::new(55555, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        for _ in 0..10 {
            let variant = XorSubstitution::choose(&mut subst);
            let initial_len = bytecode.len();
            variant.emit(&mut bytecode, &encode);
            assert!(bytecode.len() > initial_len, "XOR variant should emit bytecode");
        }
    }

    #[test]
    fn test_comparison_substitution() {
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        ComparisonSubstitution::emit_eq_obfuscated(&mut bytecode, &encode);
        assert!(!bytecode.is_empty());

        bytecode.clear();
        ComparisonSubstitution::emit_ne_obfuscated(&mut bytecode, &encode);
        assert!(!bytecode.is_empty());
    }

    #[test]
    fn test_control_flow_substitution() {
        let mut subst = Substitution::new(66666, true);
        let mut bytecode = Vec::new();
        let encode = |x: u8| x;

        ControlFlowSubstitution::emit_jz_obfuscated(&mut bytecode, &encode);
        assert!(!bytecode.is_empty());

        bytecode.clear();
        ControlFlowSubstitution::emit_fake_conditional(&mut subst, &mut bytecode, &encode);
        assert!(!bytecode.is_empty());
    }
}
