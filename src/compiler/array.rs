//! Array/Vector Compilation
//!
//! Handles array literals [1, 2, 3], repeat syntax [0; 10], and index operations arr[i].

use syn::Expr;
use super::{Compiler, CompileError, VarType};

impl Compiler {
    /// Compile array literal: [1, 2, 3]
    /// Generates: VEC_NEW + VEC_PUSH for each element
    /// Result: array address on stack
    pub(crate) fn compile_array_literal(&mut self, elems: &syn::punctuated::Punctuated<Expr, syn::token::Comma>) -> Result<(), CompileError> {
        let count = elems.len();

        if count == 0 {
            // Empty array: create with capacity 0
            self.emit_zero();        // capacity = 0
            self.emit_constant(8);   // elem_size = 8 (u64)
            self.emit_vec_new();
            return Ok(());
        }

        // Create vector with capacity = element count
        self.emit_constant(count as u64);  // capacity
        self.emit_constant(8);              // elem_size = 8 bytes (u64)
        self.emit_vec_new();                // -> [vec_addr]

        // Push each element
        for elem in elems.iter() {
            self.emit_dup();                // [vec_addr, vec_addr]
            self.compile_expr(elem)?;       // [vec_addr, vec_addr, value]
            self.emit_vec_push();           // [vec_addr]
        }

        // vec_addr remains on stack
        Ok(())
    }

    /// Compile array repeat: [value; count]
    /// Generates: VEC_REPEAT opcode
    /// Result: array address on stack
    pub(crate) fn compile_array_repeat(&mut self, value: &Expr, len: &Expr) -> Result<(), CompileError> {
        // Stack order for VEC_REPEAT: [value, count, elem_size] -> [vec_addr]
        self.compile_expr(value)?;          // [value]
        self.compile_expr(len)?;            // [value, count]
        self.emit_constant(8);              // [value, count, 8] - elem_size = 8 (u64)
        self.emit_vec_repeat();             // [vec_addr]
        Ok(())
    }

    /// Compile index expression: arr[i]
    /// Generates: VEC_GET opcode
    /// Result: element value on stack
    pub(crate) fn compile_index_expr(&mut self, base: &Expr, index: &Expr) -> Result<(), CompileError> {
        // Check if this is a string or array
        let is_string = self.is_string_base(base);

        // Get base address
        self.compile_expr(base)?;           // [addr]
        // Get index
        self.compile_expr(index)?;          // [addr, index]

        // Get element
        if is_string {
            self.emit_str_get();            // [byte]
        } else {
            self.emit_vec_get();            // [value]
        }

        Ok(())
    }

    /// Compile index assignment: arr[i] = value
    pub(crate) fn compile_index_assignment(&mut self, base: &Expr, index: &Expr, value: &Expr) -> Result<(), CompileError> {
        let is_string = self.is_string_base(base);

        // Stack order for VEC_SET/STR_SET: [addr, index, value] -> []
        self.compile_expr(base)?;           // [addr]
        self.compile_expr(index)?;          // [addr, index]
        self.compile_expr(value)?;          // [addr, index, value]

        if is_string {
            self.emit_str_set();            // []
        } else {
            self.emit_vec_set();            // []
        }

        Ok(())
    }

    /// Check if base expression is a string
    pub(crate) fn is_string_base(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Lit(lit) => {
                matches!(&lit.lit, syn::Lit::Str(_) | syn::Lit::ByteStr(_))
            }
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    matches!(self.get_var_type(&name), Some(VarType::String))
                } else {
                    false
                }
            }
            _ => false
        }
    }
}
