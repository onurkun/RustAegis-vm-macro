//! ValueCryptor - VMProtect-style value encryption
//!
//! Encrypts constant values at compile-time and emits a chain of arithmetic
//! operations to decrypt them at runtime. This prevents constants from appearing
//! in plaintext in the bytecode.
//!
//! ## How it works
//!
//! Instead of emitting `PUSH 0xDEADBEEF`, we:
//! 1. Generate a random encryption chain (ADD, SUB, XOR, ROL, ROR, NOT, NEG)
//! 2. Encrypt the value through this chain at compile-time
//! 3. Emit bytecode that pushes the encrypted value
//! 4. Emit the inverse operations to decrypt at runtime
//!
//! ## Example
//!
//! Original: `PUSH 42`
//!
//! With ValueCryptor:
//! ```text
//! PUSH <encrypted_42>    ; Push encrypted value
//! PUSH 0x1234            ; XOR constant
//! XOR                    ; Decrypt step 1
//! PUSH 5                 ; ROL amount
//! ROR                    ; Decrypt step 2 (inverse of ROL)
//! PUSH 100               ; SUB constant
//! ADD                    ; Decrypt step 3 (inverse of SUB)
//! ; Stack now contains 42
//! ```

use crate::opcodes::{stack, arithmetic};

/// Cryptographic command in the encryption chain
#[derive(Clone, Copy, Debug)]
pub enum CryptCommand {
    /// Add constant: value = value + c
    Add(u64),
    /// Subtract constant: value = value - c
    Sub(u64),
    /// XOR with constant: value = value ^ c
    Xor(u64),
    /// Rotate left by n bits: value = value.rotate_left(n)
    Rol(u32),
    /// Rotate right by n bits: value = value.rotate_right(n)
    Ror(u32),
    /// Bitwise NOT: value = !value
    Not,
    /// Negation: value = -value (two's complement)
    Neg,
}

impl CryptCommand {
    /// Apply this command to encrypt a value
    pub fn encrypt(&self, value: u64) -> u64 {
        match self {
            CryptCommand::Add(c) => value.wrapping_add(*c),
            CryptCommand::Sub(c) => value.wrapping_sub(*c),
            CryptCommand::Xor(c) => value ^ c,
            CryptCommand::Rol(n) => value.rotate_left(*n),
            CryptCommand::Ror(n) => value.rotate_right(*n),
            CryptCommand::Not => !value,
            CryptCommand::Neg => (value as i64).wrapping_neg() as u64,
        }
    }

    /// Apply inverse operation to decrypt a value
    pub fn decrypt(&self, value: u64) -> u64 {
        match self {
            CryptCommand::Add(c) => value.wrapping_sub(*c), // Inverse of ADD is SUB
            CryptCommand::Sub(c) => value.wrapping_add(*c), // Inverse of SUB is ADD
            CryptCommand::Xor(c) => value ^ c,              // XOR is self-inverse
            CryptCommand::Rol(n) => value.rotate_right(*n), // Inverse of ROL is ROR
            CryptCommand::Ror(n) => value.rotate_left(*n),  // Inverse of ROR is ROL
            CryptCommand::Not => !value,                    // NOT is self-inverse
            CryptCommand::Neg => (value as i64).wrapping_neg() as u64, // NEG is self-inverse
        }
    }

    /// Emit the decryption bytecode for this command
    /// Note: We emit the INVERSE operation since we're decrypting
    pub fn emit_decrypt<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) {
        match self {
            CryptCommand::Add(c) => {
                // Decrypt: SUB the constant (inverse of ADD)
                emit_push_value(bytecode, *c, encode);
                bytecode.push(encode(arithmetic::SUB));
            }
            CryptCommand::Sub(c) => {
                // Decrypt: ADD the constant (inverse of SUB)
                emit_push_value(bytecode, *c, encode);
                bytecode.push(encode(arithmetic::ADD));
            }
            CryptCommand::Xor(c) => {
                // XOR is self-inverse
                emit_push_value(bytecode, *c, encode);
                bytecode.push(encode(arithmetic::XOR));
            }
            CryptCommand::Rol(n) => {
                // Decrypt: ROR (inverse of ROL)
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(*n as u8);
                bytecode.push(encode(arithmetic::ROR));
            }
            CryptCommand::Ror(n) => {
                // Decrypt: ROL (inverse of ROR)
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(*n as u8);
                bytecode.push(encode(arithmetic::ROL));
            }
            CryptCommand::Not => {
                // NOT is self-inverse
                bytecode.push(encode(arithmetic::NOT));
            }
            CryptCommand::Neg => {
                // NEG is self-inverse (we don't have NEG opcode, use 0 - value)
                // Stack: [value] -> [value, 0] -> [0, value] -> [0 - value]
                bytecode.push(encode(stack::PUSH_IMM8));
                bytecode.push(0);
                bytecode.push(encode(stack::SWAP));
                bytecode.push(encode(arithmetic::SUB));
            }
        }
    }
}

/// Helper to emit a push instruction for a value
fn emit_push_value<F: Fn(u8) -> u8>(bytecode: &mut Vec<u8>, value: u64, encode: &F) {
    if value <= 0xFF {
        bytecode.push(encode(stack::PUSH_IMM8));
        bytecode.push(value as u8);
    } else if value <= 0xFFFF {
        bytecode.push(encode(stack::PUSH_IMM16));
        bytecode.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xFFFFFFFF {
        bytecode.push(encode(stack::PUSH_IMM32));
        bytecode.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        bytecode.push(encode(stack::PUSH_IMM));
        bytecode.extend_from_slice(&value.to_le_bytes());
    }
}

/// ValueCryptor - generates and applies encryption chains
pub struct ValueCryptor {
    /// The encryption commands (applied in order for encryption)
    commands: Vec<CryptCommand>,
    /// RNG state for deterministic generation
    rng: u64,
}

impl ValueCryptor {
    /// Create a new ValueCryptor with given seed
    pub fn new(seed: u64) -> Self {
        Self {
            commands: Vec::new(),
            rng: seed ^ 0x9E3779B97F4A7C15, // Mix with golden ratio constant
        }
    }

    /// Get next random value
    fn next_rand(&mut self) -> u64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Generate a random encryption chain
    /// Returns the number of commands generated (3-7)
    pub fn generate_chain(&mut self) -> &[CryptCommand] {
        self.commands.clear();

        // Generate 3-7 commands
        let count = 3 + (self.next_rand() % 5) as usize;

        let mut last_cmd_type = 255u8; // Invalid, forces first command to be different

        for _ in 0..count {
            let cmd = loop {
                let cmd_type = (self.next_rand() % 7) as u8;

                // Avoid consecutive same operations (reduces effectiveness)
                if cmd_type == last_cmd_type {
                    continue;
                }

                // Avoid ADD/SUB after each other (they can cancel out easily)
                if (cmd_type == 0 || cmd_type == 1) && (last_cmd_type == 0 || last_cmd_type == 1) {
                    continue;
                }

                // Avoid ROL/ROR after each other
                if (cmd_type == 3 || cmd_type == 4) && (last_cmd_type == 3 || last_cmd_type == 4) {
                    continue;
                }

                last_cmd_type = cmd_type;

                break match cmd_type {
                    0 => CryptCommand::Add(self.next_rand()),
                    1 => CryptCommand::Sub(self.next_rand()),
                    2 => CryptCommand::Xor(self.next_rand()),
                    3 => CryptCommand::Rol(1 + (self.next_rand() % 63) as u32),
                    4 => CryptCommand::Ror(1 + (self.next_rand() % 63) as u32),
                    5 => CryptCommand::Not,
                    _ => CryptCommand::Neg,
                };
            };

            self.commands.push(cmd);
        }

        &self.commands
    }

    /// Encrypt a value using the current chain
    pub fn encrypt(&self, mut value: u64) -> u64 {
        for cmd in &self.commands {
            value = cmd.encrypt(value);
        }
        value
    }

    /// Decrypt a value using the current chain (apply inverse in reverse order)
    #[allow(dead_code)]
    pub fn decrypt(&self, mut value: u64) -> u64 {
        for cmd in self.commands.iter().rev() {
            value = cmd.decrypt(value);
        }
        value
    }

    /// Emit bytecode to decrypt a value at runtime
    /// The encrypted value should already be on the stack
    pub fn emit_decrypt_chain<F: Fn(u8) -> u8>(&self, bytecode: &mut Vec<u8>, encode: &F) {
        // Apply inverse operations in REVERSE order
        for cmd in self.commands.iter().rev() {
            cmd.emit_decrypt(bytecode, encode);
        }
    }

    /// Encrypt a value and emit full decryption bytecode
    /// This is the main entry point for compiler integration
    pub fn emit_encrypted_value<F: Fn(u8) -> u8>(
        &mut self,
        value: u64,
        bytecode: &mut Vec<u8>,
        encode: &F,
    ) {
        // Generate new chain for this value
        self.generate_chain();

        // Encrypt the value
        let encrypted = self.encrypt(value);

        // Emit: PUSH encrypted_value
        emit_push_value(bytecode, encrypted, encode);

        // Emit decryption chain
        self.emit_decrypt_chain(bytecode, encode);
    }

    /// Get the current command count (for statistics/debugging)
    #[allow(dead_code)]
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }
}

/// Lightweight ValueCryptor for simple values (fewer operations)
/// Used when we want some obfuscation but not too much overhead
/// Reserved for future use in Standard level protection
#[allow(dead_code)]
pub struct LightValueCryptor {
    rng: u64,
}

#[allow(dead_code)]
impl LightValueCryptor {
    pub fn new(seed: u64) -> Self {
        Self {
            rng: seed ^ 0xDEADBEEF_CAFEBABE,
        }
    }

    fn next_rand(&mut self) -> u64 {
        self.rng = self.rng.wrapping_mul(0x5851F42D4C957F2D).wrapping_add(0x14057B7EF767814F);
        self.rng
    }

    /// Emit a value with light obfuscation (1-2 operations)
    /// For small values or when performance is critical
    pub fn emit_light<F: Fn(u8) -> u8>(
        &mut self,
        value: u64,
        bytecode: &mut Vec<u8>,
        encode: &F,
    ) {
        // 50% chance: just XOR obfuscation
        // 50% chance: ADD/SUB split
        if self.next_rand().is_multiple_of(2) {
            // XOR obfuscation: value = encrypted ^ key
            let key = self.next_rand();
            let encrypted = value ^ key;

            emit_push_value(bytecode, encrypted, encode);
            emit_push_value(bytecode, key, encode);
            bytecode.push(encode(arithmetic::XOR));
        } else {
            // ADD split: value = a + b
            let a = self.next_rand();
            let b = value.wrapping_sub(a);

            emit_push_value(bytecode, a, encode);
            emit_push_value(bytecode, b, encode);
            bytecode.push(encode(arithmetic::ADD));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut cryptor = ValueCryptor::new(12345);

        for value in [0u64, 1, 42, 0xDEADBEEF, u64::MAX, 0x123456789ABCDEF0] {
            cryptor.generate_chain();
            let encrypted = cryptor.encrypt(value);
            let decrypted = cryptor.decrypt(encrypted);
            assert_eq!(value, decrypted, "Roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_chain_generation_deterministic() {
        let mut cryptor1 = ValueCryptor::new(42);
        let mut cryptor2 = ValueCryptor::new(42);

        cryptor1.generate_chain();
        cryptor2.generate_chain();

        assert_eq!(cryptor1.commands.len(), cryptor2.commands.len());

        // Verify same seed produces same chain
        let val = 0xCAFEBABE;
        assert_eq!(cryptor1.encrypt(val), cryptor2.encrypt(val));
    }

    #[test]
    fn test_different_seeds_different_chains() {
        let mut cryptor1 = ValueCryptor::new(1);
        let mut cryptor2 = ValueCryptor::new(2);

        cryptor1.generate_chain();
        cryptor2.generate_chain();

        let val = 0xDEADBEEF;
        // Different seeds should (almost certainly) produce different encrypted values
        assert_ne!(cryptor1.encrypt(val), cryptor2.encrypt(val));
    }

    #[test]
    fn test_individual_commands() {
        // Test each command type
        let value = 0x123456789ABCDEF0u64;

        // ADD
        let cmd = CryptCommand::Add(100);
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);

        // SUB
        let cmd = CryptCommand::Sub(100);
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);

        // XOR
        let cmd = CryptCommand::Xor(0xFFFF);
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);

        // ROL
        let cmd = CryptCommand::Rol(13);
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);

        // ROR
        let cmd = CryptCommand::Ror(27);
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);

        // NOT
        let cmd = CryptCommand::Not;
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);

        // NEG
        let cmd = CryptCommand::Neg;
        assert_eq!(cmd.decrypt(cmd.encrypt(value)), value);
    }
}
