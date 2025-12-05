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

            // Check if this is a borrowed tuple extraction (let inner = t.0)
            // Borrowed values don't need cleanup since the original owns the memory
            let is_borrowed = self.is_borrowed_tuple_extraction(&init.expr);

            // Define variable in current scope (allocates register)
            let reg = if is_borrowed {
                self.define_var_borrowed(&name, var_type, is_signed)?
            } else {
                self.define_var(&name, var_type, is_signed)?
            };

            // Pop value to register
            self.emit_pop_reg(reg);
        } else {
            return Err(CompileError("Uninitialized let bindings not supported".to_string()));
        }
        Ok(())
    }

    /// Check if expression extracts a tuple from another variable (borrowed reference)
    fn is_borrowed_tuple_extraction(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Field(field) => {
                if let syn::Member::Unnamed(_) = &field.member {
                    // Check if base is a tuple variable or another tuple extraction
                    self.is_tuple_expr_for_assignment(&field.base) ||
                    self.is_borrowed_tuple_extraction(&field.base)
                } else {
                    false
                }
            }
            Expr::Paren(paren) => self.is_borrowed_tuple_extraction(&paren.expr),
            _ => false,
        }
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
                        _ => {
                            // Check if it's a known struct type
                            if self.struct_defs.contains_key(&type_name) {
                                (VarType::Struct(type_name), false)
                            } else {
                                self.infer_type_from_expr(init)
                            }
                        }
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
            // Path expressions - check existing type or unit struct
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    // First check if it's an existing variable
                    if let Some(var_type) = self.get_var_type(&name) {
                        let is_signed = self.is_var_signed(&name);
                        (var_type, is_signed)
                    // Then check if it's a unit struct instantiation
                    } else if self.struct_defs.contains_key(&name) {
                        (VarType::Struct(name), false)
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
            // Struct literal
            Expr::Struct(expr_struct) => {
                let struct_name = expr_struct.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                (VarType::Struct(struct_name), false)
            }
            // Tuple literal - infer each element's type
            Expr::Tuple(tuple) => {
                let elem_types: Vec<VarType> = tuple.elems.iter()
                    .map(|elem| self.infer_type_from_expr(elem).0)
                    .collect();
                (VarType::Tuple(elem_types), false)
            }
            // Field access - might be tuple index (t.0) returning nested tuple
            Expr::Field(field) => {
                if let syn::Member::Unnamed(idx) = &field.member {
                    // Try to get tuple element type
                    if let Some(elem_type) = self.get_tuple_element_type_for_inference(&field.base, idx.index as usize) {
                        return (elem_type, false);
                    }
                }
                // Not a tuple index, default to integer
                (VarType::Integer, false)
            }
            // Function call - might be tuple struct
            Expr::Call(call) => {
                if let Expr::Path(path) = &*call.func {
                    let func_name = path.path.segments.iter()
                        .map(|s| s.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");
                    // Check if it's a known struct (tuple struct)
                    if self.struct_defs.contains_key(&func_name) {
                        return (VarType::Struct(func_name), false);
                    }
                }
                (VarType::Integer, false)
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

            // Field assignment: p.x = value
            Expr::Field(field_expr) => {
                self.compile_field_assignment(field_expr, value)?;
            }

            _ => {
                return Err(CompileError("Only simple variable, index, or field assignment supported".to_string()));
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

    /// Compile field assignment: p.x = value or t.0 = value
    fn compile_field_assignment(&mut self, field: &syn::ExprField, value: &Expr) -> Result<(), CompileError> {
        // Check if this is tuple index assignment (t.0, t.1, etc.)
        if let syn::Member::Unnamed(index) = &field.member {
            if self.is_tuple_expr_for_assignment(&field.base) {
                return self.compile_tuple_index_assignment(field, index.index as usize, value);
            }
        }

        // Compile base expression (pushes struct address)
        self.compile_expr(&field.base)?;

        // Get field name
        let field_name = match &field.member {
            syn::Member::Named(ident) => ident.to_string(),
            syn::Member::Unnamed(index) => index.index.to_string(),
        };

        // Infer struct type from base expression
        let struct_name = self.infer_struct_type_for_assignment(&field.base)?;

        // Look up struct definition
        let struct_def = self.struct_defs.get(&struct_name)
            .ok_or_else(|| CompileError(format!("Unknown struct: {}", struct_name)))?;

        // Get field offset
        let offset = struct_def.get_field_offset(&field_name)
            .ok_or_else(|| CompileError(format!("Unknown field: {}.{}", struct_name, field_name)))?;

        // Add offset to get target address
        if offset > 0 {
            self.emit_constant(offset as u64);
            self.emit_add();
        }

        // Compile value
        self.compile_expr(value)?;

        // Store: [addr, value] -> []
        self.emit_heap_store64();

        Ok(())
    }

    /// Check if expression is a tuple (for assignment)
    fn is_tuple_expr_for_assignment(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    matches!(self.get_var_type(&name), Some(VarType::Tuple(_)))
                } else {
                    false
                }
            }
            Expr::Paren(paren) => self.is_tuple_expr_for_assignment(&paren.expr),
            _ => false,
        }
    }

    /// Compile tuple index assignment: t.0 = value
    fn compile_tuple_index_assignment(&mut self, field: &syn::ExprField, index: usize, value: &Expr) -> Result<(), CompileError> {
        // Get tuple type to calculate proper offset
        let tuple_type = self.get_tuple_type_for_assignment(&field.base);

        // Compile base expression (pushes tuple address)
        self.compile_expr(&field.base)?;

        // Calculate offset based on element types
        let offset = if let Some(elems) = &tuple_type {
            // Sum of aligned sizes of elements before index
            elems.iter().take(index).map(|t| t.aligned_size()).sum()
        } else {
            // Fallback to 8 bytes per element
            index * 8
        };

        // Add offset to get target address
        if offset > 0 {
            self.emit_constant(offset as u64);
            self.emit_add();
        }

        // Compile value
        self.compile_expr(value)?;

        // Store: [addr, value] -> []
        self.emit_heap_store64();

        Ok(())
    }

    /// Get tuple element type at given index (for type inference)
    fn get_tuple_element_type_for_inference(&self, expr: &Expr, index: usize) -> Option<VarType> {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(VarType::Tuple(elems)) = self.get_var_type(&name) {
                        return elems.get(index).cloned();
                    }
                }
                None
            }
            Expr::Tuple(tuple) => {
                // Infer type from literal element
                tuple.elems.iter().nth(index).map(|elem| self.infer_type_from_expr(elem).0)
            }
            Expr::Paren(paren) => self.get_tuple_element_type_for_inference(&paren.expr, index),
            Expr::Field(field) => {
                // Nested field access: (t.0).1
                if let syn::Member::Unnamed(idx) = &field.member {
                    if let Some(VarType::Tuple(inner_elems)) = self.get_tuple_element_type_for_inference(&field.base, idx.index as usize) {
                        return inner_elems.get(index).cloned();
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get tuple type for assignment (to calculate proper offsets)
    fn get_tuple_type_for_assignment(&self, expr: &Expr) -> Option<Vec<VarType>> {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(VarType::Tuple(elems)) = self.get_var_type(&name) {
                        return Some(elems);
                    }
                }
                None
            }
            Expr::Paren(paren) => self.get_tuple_type_for_assignment(&paren.expr),
            _ => None,
        }
    }

    /// Infer struct type for field assignment
    fn infer_struct_type_for_assignment(&self, expr: &Expr) -> Result<String, CompileError> {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(VarType::Struct(struct_name)) = self.get_var_type(&name) {
                        return Ok(struct_name);
                    }
                }
                Err(CompileError(format!("Cannot infer struct type from variable '{}'",
                    path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"))))
            }
            Expr::Paren(paren) => {
                self.infer_struct_type_for_assignment(&paren.expr)
            }
            _ => Err(CompileError("Cannot infer struct type for assignment".to_string())),
        }
    }
}
