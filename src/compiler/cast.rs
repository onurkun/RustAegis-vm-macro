//! Type Cast Compilation
//!
//! Handles type casts: as u8, as u16, as u32, as u64, as i8, as i16, as i32, as i64

use syn::{ExprCast, Type, TypePath};
use super::{Compiler, CompileError};

impl Compiler {
    /// Compile a type cast expression: expr as Type
    pub(crate) fn compile_cast(&mut self, cast: &ExprCast) -> Result<(), CompileError> {
        // First compile the expression being cast
        self.compile_expr(&cast.expr)?;

        // Then apply the appropriate conversion based on target type
        let target_type = extract_type_name(&cast.ty)?;

        match target_type.as_str() {
            // Unsigned truncations
            "u8" => {
                self.emit_trunc8();
            }
            "u16" => {
                self.emit_trunc16();
            }
            "u32" => {
                self.emit_trunc32();
            }
            "u64" | "usize" => {
                // No-op: already u64 internally
            }

            // Signed types - need sign extension for smaller types
            "i8" => {
                // Truncate to 8 bits, then sign-extend
                self.emit_trunc8();
                self.emit_sext8();
            }
            "i16" => {
                // Truncate to 16 bits, then sign-extend
                self.emit_trunc16();
                self.emit_sext16();
            }
            "i32" => {
                // Truncate to 32 bits, then sign-extend
                self.emit_trunc32();
                self.emit_sext32();
            }
            "i64" | "isize" => {
                // No-op for conversion, value is already 64-bit
                // Sign interpretation is handled by operations (IDIV, IMOD, etc.)
            }

            // Boolean cast
            "bool" => {
                // Convert to 0 or 1: value != 0 -> 1, value == 0 -> 0
                // Use XOR with 0 to check if zero
                self.emit_dup();
                self.emit_zero();
                self.emit_xor();

                let is_zero_label = self.unique_label("cast_bool_zero");
                let end_label = self.unique_label("cast_bool_end");

                self.emit_jump(crate::opcodes::control::JZ, &is_zero_label);
                // Non-zero: drop original, push 1
                self.emit_drop();
                self.emit_constant(1);
                self.emit_jump(crate::opcodes::control::JMP, &end_label);
                self.mark_label(&is_zero_label);
                // Zero: drop original, push 0
                self.emit_drop();
                self.emit_zero();
                self.mark_label(&end_label);
            }

            // Char cast (from integer)
            "char" => {
                // Truncate to 32-bit (Unicode code point range)
                self.emit_trunc32();
            }

            // Pointer types (treated as u64)
            "*const" | "*mut" | "&" | "&mut" => {
                // No-op: pointers are addresses (u64)
            }

            _ => {
                return Err(CompileError(format!("Unsupported cast target type: {}", target_type)));
            }
        }

        Ok(())
    }

    /// Compile conversion from signed to unsigned or vice versa
    /// This is often a no-op at the bit level, but affects operation interpretation
    #[allow(dead_code)]
    pub(crate) fn compile_reinterpret_cast(&mut self, _from_signed: bool, to_signed: bool, bits: u8) -> Result<(), CompileError> {
        // The bit pattern doesn't change, but for smaller types we need truncation
        match bits {
            8 => {
                self.emit_trunc8();
                if to_signed {
                    self.emit_sext8();
                }
            }
            16 => {
                self.emit_trunc16();
                if to_signed {
                    self.emit_sext16();
                }
            }
            32 => {
                self.emit_trunc32();
                if to_signed {
                    self.emit_sext32();
                }
            }
            64 => {
                // No-op
            }
            _ => {
                return Err(CompileError(format!("Unsupported bit width: {}", bits)));
            }
        }
        Ok(())
    }
}

/// Extract the type name from a syn::Type
fn extract_type_name(ty: &Type) -> Result<String, CompileError> {
    match ty {
        Type::Path(TypePath { path, .. }) => {
            // Get the last segment (e.g., "u32" from "std::u32")
            if let Some(segment) = path.segments.last() {
                Ok(segment.ident.to_string())
            } else {
                Err(CompileError("Empty type path".to_string()))
            }
        }
        Type::Ptr(ptr) => {
            // *const T or *mut T
            if ptr.mutability.is_some() {
                Ok("*mut".to_string())
            } else {
                Ok("*const".to_string())
            }
        }
        Type::Reference(reference) => {
            // &T or &mut T
            if reference.mutability.is_some() {
                Ok("&mut".to_string())
            } else {
                Ok("&".to_string())
            }
        }
        Type::Tuple(tuple) if tuple.elems.is_empty() => {
            // () - unit type
            Ok("()".to_string())
        }
        _ => {
            Err(CompileError(format!("Unsupported type in cast: {:?}", ty)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_extraction() {
        // Basic sanity test - actual parsing would need syn
    }
}
