//! Statement Compilation
//!
//! Handles: let bindings, assignments, compound assignments

use syn::{Expr, Local, BinOp};
use super::{Compiler, CompileError, VarLocation, VarType};

impl Compiler {
    /// Compile a local variable binding: let x = expr;
    pub(crate) fn compile_local(&mut self, local: &Local) -> Result<(), CompileError> {
        if let Some(init) = &local.init {
            // Compile initializer first (leaves value on stack)
            self.compile_expr(&init.expr)?;

            // Extract variable name
            let name = Self::extract_pat_name(&local.pat)?;

            // Detect type from explicit annotation or initializer
            let (var_type, is_signed) = self.detect_full_type(&local.pat, &init.expr);

            // Define variable in current scope (allocates register)
            let reg = self.define_var(&name, var_type, is_signed)?;

            // Pop value to register
            self.emit_pop_reg(reg);
        } else {
            return Err(CompileError("Uninitialized let bindings not supported".to_string()));
        }
        Ok(())
    }

    /// Detect full type information from pattern and initializer
    fn detect_full_type(&self, pat: &syn::Pat, init: &Expr) -> (VarType, bool) {
        // Check explicit type annotation first
        if let syn::Pat::Type(pat_type) = pat {
            if let syn::Type::Path(type_path) = &*pat_type.ty {
                if let Some(segment) = type_path.path.segments.last() {
                    let type_name = segment.ident.to_string();
                    return match type_name.as_str() {
                        "i8" | "i16" | "i32" | "i64" | "isize" => (VarType::Integer, true),
                        "u8" | "u16" | "u32" | "u64" | "usize" => (VarType::Integer, false),
                        "bool" => (VarType::Bool, false),
                        "String" => (VarType::String, false),
                        "Vec" => (VarType::Vector, false),
                        _ => self.infer_type_from_expr(init),
                    };
                }
            }
        }
        // Infer from initializer
        self.infer_type_from_expr(init)
    }

    /// Infer type from initializer expression
    fn infer_type_from_expr(&self, expr: &Expr) -> (VarType, bool) {
        match expr {
            // String literals
            Expr::Lit(lit) => {
                match &lit.lit {
                    syn::Lit::Str(_) | syn::Lit::ByteStr(_) => (VarType::String, false),
                    syn::Lit::Bool(_) => (VarType::Bool, false),
                    syn::Lit::Int(i) => {
                        let suffix = i.suffix();
                        let is_signed = suffix.starts_with('i');
                        (VarType::Integer, is_signed)
                    }
                    _ => (VarType::Integer, false),
                }
            }
            // Array literals
            Expr::Array(_) | Expr::Repeat(_) => (VarType::Vector, false),
            // Method calls that return strings
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if matches!(method.as_str(), "concat" | "to_string") {
                    (VarType::String, false)
                } else {
                    // Check receiver type
                    if let Some(var_type) = self.infer_method_result_type(mc) {
                        (var_type, false)
                    } else {
                        (VarType::Integer, false)
                    }
                }
            }
            // Path expressions - check existing type
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(var_type) = self.get_var_type(&name) {
                        let is_signed = self.is_var_signed(&name);
                        (var_type, is_signed)
                    } else {
                        (VarType::Integer, false)
                    }
                } else {
                    (VarType::Integer, false)
                }
            }
            // Unary negation implies signed
            Expr::Unary(unary) => {
                if matches!(unary.op, syn::UnOp::Neg(_)) {
                    (VarType::Integer, true)
                } else {
                    self.infer_type_from_expr(&unary.expr)
                }
            }
            // Binary expression - use left operand type
            Expr::Binary(binary) => {
                self.infer_type_from_expr(&binary.left)
            }
            // Default to integer
            _ => (VarType::Integer, false),
        }
    }

    /// Infer result type from method call
    fn infer_method_result_type(&self, mc: &syn::ExprMethodCall) -> Option<VarType> {
        let method = mc.method.to_string();
        match method.as_str() {
            "len" | "capacity" | "count_ones" | "count_zeros" |
            "leading_zeros" | "trailing_zeros" => Some(VarType::Integer),
            "is_empty" => Some(VarType::Bool),
            "concat" | "to_string" => Some(VarType::String),
            "get" => {
                // Get returns element type - check receiver
                if let Expr::Path(path) = &*mc.receiver {
                    if path.path.segments.len() == 1 {
                        let name = path.path.segments[0].ident.to_string();
                        if let Some(VarType::String) = self.get_var_type(&name) {
                            return Some(VarType::Integer); // String.get returns byte
                        }
                    }
                }
                Some(VarType::Integer)
            }
            _ => None,
        }
    }

    /// Compile simple assignment: x = expr
    pub(crate) fn compile_assignment(&mut self, target: &Expr, value: &Expr) -> Result<(), CompileError> {
        match target {
            // Simple variable assignment: x = value
            Expr::Path(path) => {
                if path.path.segments.len() != 1 {
                    return Err(CompileError("Complex paths not supported in assignment".to_string()));
                }

                let name = path.path.segments[0].ident.to_string();
                match self.get_var_location(&name) {
                    Some(VarLocation::Register(reg)) => {
                        self.compile_expr(value)?;
                        self.emit_pop_reg(reg);
                    }
                    Some(VarLocation::Array(reg, _)) | Some(VarLocation::String(reg)) => {
                        // Reassigning array/string variable
                        self.compile_expr(value)?;
                        self.emit_pop_reg(reg);
                    }
                    Some(VarLocation::InputOffset(_)) => {
                        return Err(CompileError("Cannot assign to function argument".to_string()));
                    }
                    None => {
                        return Err(CompileError(format!("Unknown variable: {}", name)));
                    }
                }
            }

            // Index assignment: arr[i] = value
            Expr::Index(index) => {
                self.compile_index_assignment(&index.expr, &index.index, value)?;
            }

            _ => {
                return Err(CompileError("Only simple variable or index assignment supported".to_string()));
            }
        }
        Ok(())
    }

    /// Compile compound assignment: x += value, x -= value, etc.
    pub(crate) fn compile_assign_op(&mut self, target: &Expr, op: &BinOp, value: &Expr) -> Result<(), CompileError> {
        // Get target variable register
        let reg = if let Expr::Path(path) = target {
            if path.path.segments.len() == 1 {
                let name = path.path.segments[0].ident.to_string();
                match self.get_var_location(&name) {
                    Some(VarLocation::Register(reg)) => reg,
                    Some(VarLocation::Array(reg, _)) => reg,
                    Some(VarLocation::String(reg)) => reg,
                    Some(VarLocation::InputOffset(_)) => {
                        return Err(CompileError("Cannot assign to function argument".to_string()));
                    }
                    None => {
                        return Err(CompileError(format!("Unknown variable: {}", name)));
                    }
                }
            } else {
                return Err(CompileError("Complex paths not supported".to_string()));
            }
        } else {
            return Err(CompileError("Only simple variable assignment supported".to_string()));
        };

        // Push current value
        self.emit_push_reg(reg);

        // Compile RHS
        self.compile_expr(value)?;

        // Apply operation
        match op {
            BinOp::AddAssign(_) => self.emit_add(),
            BinOp::SubAssign(_) => self.emit_sub(),
            BinOp::MulAssign(_) => self.emit_mul(),
            BinOp::DivAssign(_) => self.emit_div(),
            BinOp::RemAssign(_) => self.emit_mod(),
            BinOp::BitXorAssign(_) => self.emit_xor(),
            BinOp::BitAndAssign(_) => self.emit_and(),
            BinOp::BitOrAssign(_) => self.emit_or(),
            BinOp::ShlAssign(_) => self.emit_shl(),
            BinOp::ShrAssign(_) => self.emit_shr(),
            _ => return Err(CompileError(format!("Unsupported assignment operator: {:?}", op))),
        }

        // Store result back
        self.emit_pop_reg(reg);

        Ok(())
    }
}
