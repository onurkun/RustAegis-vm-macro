//! Literal Compilation
//!
//! Handles compilation of literals: integers, booleans, strings, bytes, chars.

use syn::Lit;
use super::{Compiler, CompileError};

impl Compiler {
    /// Compile a literal expression
    /// Supports: integers, booleans, strings, bytes, chars
    pub(crate) fn compile_literal(&mut self, lit: &Lit) -> Result<(), CompileError> {
        match lit {
            // Integer literal: 42, 0xFF, 0b1010
            Lit::Int(int_lit) => {
                let value: u64 = int_lit.base10_parse()
                    .map_err(|e| CompileError(format!("Invalid integer: {}", e)))?;

                if value == 0 {
                    self.emit_zero();
                } else {
                    self.emit_constant(value);
                }
            }

            // Boolean literal: true, false
            Lit::Bool(bool_lit) => {
                if bool_lit.value {
                    self.emit_constant(1);
                } else {
                    self.emit_zero();
                }
            }

            // String literal: "hello"
            // Compiles to: STR_NEW + STR_PUSH for each byte
            Lit::Str(str_lit) => {
                self.compile_string_literal(&str_lit.value())?;
            }

            // Byte string literal: b"hello"
            Lit::ByteStr(byte_str) => {
                self.compile_byte_string_literal(&byte_str.value())?;
            }

            // Char literal: 'a'
            Lit::Char(char_lit) => {
                let c = char_lit.value();
                // UTF-8 encode the character
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                // Push first byte as u64 (for single-byte chars)
                // For multi-byte, we'd need string support
                if encoded.len() == 1 {
                    self.emit_constant(buf[0] as u64);
                } else {
                    // Multi-byte char: create a string
                    self.compile_string_literal(encoded)?;
                }
            }

            // Byte literal: b'a'
            Lit::Byte(byte_lit) => {
                self.emit_constant(byte_lit.value() as u64);
            }

            // Float literals not supported (VM is integer-only)
            Lit::Float(_) => {
                return Err(CompileError("Float literals not supported (VM is integer-only)".to_string()));
            }

            // Verbatim literals
            _ => {
                return Err(CompileError("Unsupported literal type".to_string()));
            }
        }
        Ok(())
    }

    /// Compile a string literal to VM bytecode
    /// Generates: STR_NEW(capacity) then STR_PUSH for each byte
    /// Result: string address on stack
    pub(crate) fn compile_string_literal(&mut self, s: &str) -> Result<(), CompileError> {
        let bytes = s.as_bytes();
        let len = bytes.len();

        // Create string with exact capacity
        // Stack: [capacity] -> [str_addr]
        self.emit_constant(len as u64);
        self.emit_str_new();

        // Push each byte
        // STR_PUSH: Stack: [str_addr, byte] -> []
        for &byte in bytes {
            self.emit_dup();                    // [str_addr, str_addr]
            self.emit_constant(byte as u64);    // [str_addr, str_addr, byte]
            self.emit_str_push();               // [str_addr]
        }

        // String address remains on stack
        Ok(())
    }

    /// Compile a byte string literal (b"...")
    /// Same as string literal but from raw bytes
    pub(crate) fn compile_byte_string_literal(&mut self, bytes: &[u8]) -> Result<(), CompileError> {
        let len = bytes.len();

        // Create string with exact capacity
        self.emit_constant(len as u64);
        self.emit_str_new();

        // Push each byte
        for &byte in bytes {
            self.emit_dup();
            self.emit_constant(byte as u64);
            self.emit_str_push();
        }

        Ok(())
    }

    /// Compile String::new() or String::with_capacity(n)
    pub(crate) fn compile_string_constructor(&mut self, capacity: Option<u64>) -> Result<(), CompileError> {
        match capacity {
            Some(cap) => self.emit_constant(cap),
            None => self.emit_zero(),
        }
        self.emit_str_new();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_string_encoding() {
        let s = "hello";
        let bytes = s.as_bytes();
        assert_eq!(bytes, &[104, 101, 108, 108, 111]);
    }

    #[test]
    fn test_utf8_encoding() {
        let s = "こんにちは";
        let bytes = s.as_bytes();
        // Japanese characters are 3 bytes each in UTF-8
        assert_eq!(bytes.len(), 15);
    }
}
