//! Expression Compilation
//!
//! Main dispatcher for compiling all expression types.
//! Delegates to specialized modules (literal, array, method, cast, control).

use syn::{Expr, BinOp, UnOp};
use super::{Compiler, CompileError, VarLocation};
use crate::opcodes::control;

impl Compiler {
    /// Compile any expression (result pushed to stack)
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        match expr {
            // =========================================================
            // Literals (int, bool, string, char, byte)
            // =========================================================
            Expr::Lit(lit) => {
                self.compile_literal(&lit.lit)?;
            }

            // =========================================================
            // Variable reference (or unit struct instantiation)
            // =========================================================
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();

                    // Check if this is a unit struct instantiation (e.g., `let m = Marker;`)
                    if let Some(struct_def) = self.struct_defs.get(&name) {
                        if struct_def.size == 0 {
                            // Unit struct - just push 0 as sentinel value
                            self.emit_zero();
                            return Ok(());
                        } else {
                            // Non-unit struct requires braces
                            return Err(CompileError(format!(
                                "Non-unit struct '{}' requires braces for instantiation", name
                            )));
                        }
                    }

                    match self.get_var_location(&name) {
                        Some(VarLocation::InputOffset(offset)) => {
                            self.emit_native_read(offset as u16);
                        }
                        Some(VarLocation::Register(reg)) => {
                            self.emit_push_reg(reg);
                        }
                        Some(VarLocation::Array(reg, _)) | Some(VarLocation::String(reg)) => {
                            self.emit_push_reg(reg);
                        }
                        None => {
                            return Err(CompileError(format!("Unknown variable: {}", name)));
                        }
                    }
                } else if path.path.segments.len() == 2 {
                    // Handle type constants like u64::MAX, i64::MIN, etc.
                    let type_name = path.path.segments[0].ident.to_string();
                    let const_name = path.path.segments[1].ident.to_string();

                    let value = match (type_name.as_str(), const_name.as_str()) {
                        // Unsigned MAX values
                        ("u8", "MAX") => u8::MAX as u64,
                        ("u16", "MAX") => u16::MAX as u64,
                        ("u32", "MAX") => u32::MAX as u64,
                        ("u64", "MAX") => u64::MAX,
                        ("usize", "MAX") => usize::MAX as u64,
                        // Unsigned MIN values (all 0)
                        ("u8", "MIN") | ("u16", "MIN") | ("u32", "MIN") |
                        ("u64", "MIN") | ("usize", "MIN") => 0,
                        // Signed MAX values
                        ("i8", "MAX") => i8::MAX as u64,
                        ("i16", "MAX") => i16::MAX as u64,
                        ("i32", "MAX") => i32::MAX as u64,
                        ("i64", "MAX") => i64::MAX as u64,
                        ("isize", "MAX") => isize::MAX as u64,
                        // Signed MIN values (as two's complement)
                        ("i8", "MIN") => i8::MIN as i64 as u64,
                        ("i16", "MIN") => i16::MIN as i64 as u64,
                        ("i32", "MIN") => i32::MIN as i64 as u64,
                        ("i64", "MIN") => i64::MIN as u64,
                        ("isize", "MIN") => isize::MIN as i64 as u64,
                        // BITS constants
                        ("u8", "BITS") | ("i8", "BITS") => 8,
                        ("u16", "BITS") | ("i16", "BITS") => 16,
                        ("u32", "BITS") | ("i32", "BITS") => 32,
                        ("u64", "BITS") | ("i64", "BITS") => 64,
                        ("usize", "BITS") | ("isize", "BITS") => std::mem::size_of::<usize>() as u64 * 8,
                        _ => {
                            return Err(CompileError(format!(
                                "Unsupported type constant: {}::{}", type_name, const_name
                            )));
                        }
                    };

                    self.emit_constant(value);
                } else {
                    return Err(CompileError("Complex paths not supported".to_string()));
                }
            }

            // =========================================================
            // Binary operations
            // =========================================================
            Expr::Binary(binary) => {
                // Check for compound assignment first
                match binary.op {
                    BinOp::AddAssign(_) | BinOp::SubAssign(_) | BinOp::MulAssign(_) |
                    BinOp::DivAssign(_) | BinOp::RemAssign(_) | BinOp::BitXorAssign(_) |
                    BinOp::BitAndAssign(_) | BinOp::BitOrAssign(_) | BinOp::ShlAssign(_) |
                    BinOp::ShrAssign(_) => {
                        self.compile_assign_op(&binary.left, &binary.op, &binary.right)?;
                        self.emit_zero();  // Assignment produces unit
                        return Ok(());
                    }
                    _ => {}
                }

                // Compile operands
                self.compile_expr(&binary.left)?;
                self.compile_expr(&binary.right)?;

                // Check if operands are signed for division
                let use_signed = self.is_signed_expr(&binary.left) || self.is_signed_expr(&binary.right);

                // Apply operation
                match binary.op {
                    // Arithmetic
                    BinOp::Add(_) => self.emit_add(),
                    BinOp::Sub(_) => self.emit_sub(),
                    BinOp::Mul(_) => self.emit_mul(),
                    BinOp::Div(_) => {
                        if use_signed {
                            self.emit_idiv();
                        } else {
                            self.emit_div();
                        }
                    }
                    BinOp::Rem(_) => {
                        if use_signed {
                            self.emit_imod();
                        } else {
                            self.emit_mod();
                        }
                    }

                    // Bitwise
                    BinOp::BitXor(_) => self.emit_xor(),
                    BinOp::BitAnd(_) => self.emit_and(),
                    BinOp::BitOr(_) => self.emit_or(),
                    BinOp::Shl(_) => self.emit_shl(),
                    BinOp::Shr(_) => self.emit_shr(),

                    // Logical (same as bitwise for 0/1 values)
                    BinOp::And(_) => self.emit_and(),
                    BinOp::Or(_) => self.emit_or(),

                    // Comparisons
                    BinOp::Eq(_) => self.compile_eq()?,
                    BinOp::Ne(_) => self.compile_ne()?,
                    BinOp::Lt(_) => self.compile_lt()?,
                    BinOp::Gt(_) => self.compile_gt()?,
                    BinOp::Le(_) => self.compile_le()?,
                    BinOp::Ge(_) => self.compile_ge()?,

                    _ => return Err(CompileError(format!("Unsupported binary operator: {:?}", binary.op))),
                }
            }

            // =========================================================
            // Unary operations
            // =========================================================
            Expr::Unary(unary) => {
                self.compile_expr(&unary.expr)?;
                match unary.op {
                    UnOp::Neg(_) => {
                        // -x = 0 - x
                        self.emit_zero();
                        self.emit_swap();
                        self.emit_sub();
                    }
                    UnOp::Not(_) => {
                        // For booleans: !x = 1 - x (flip 0<->1)
                        // For integers: !x = bitwise NOT
                        self.emit_not();
                    }
                    UnOp::Deref(_) => {
                        // *x - dereference pointer (load from heap)
                        self.emit_heap_load64();
                    }
                    _ => return Err(CompileError("Unsupported unary operator".to_string())),
                }
            }

            // =========================================================
            // Type cast: expr as Type
            // =========================================================
            Expr::Cast(cast) => {
                self.compile_cast(cast)?;
            }

            // =========================================================
            // Method call: receiver.method(args)
            // =========================================================
            Expr::MethodCall(method_call) => {
                self.compile_method_call(method_call)?;
            }

            // =========================================================
            // Array literal: [1, 2, 3]
            // =========================================================
            Expr::Array(array) => {
                self.compile_array_literal(&array.elems)?;
            }

            // =========================================================
            // Array repeat: [0; 10]
            // =========================================================
            Expr::Repeat(repeat) => {
                self.compile_array_repeat(&repeat.expr, &repeat.len)?;
            }

            // =========================================================
            // Index expression: arr[i]
            // =========================================================
            Expr::Index(index) => {
                self.compile_index_expr(&index.expr, &index.index)?;
            }

            // =========================================================
            // If expression
            // =========================================================
            Expr::If(if_expr) => {
                let else_expr = if_expr.else_branch.as_ref().map(|(_, e)| e.as_ref());
                self.compile_if(&if_expr.cond, &if_expr.then_branch, else_expr)?;
            }

            // =========================================================
            // While loop
            // =========================================================
            Expr::While(while_expr) => {
                self.compile_while(&while_expr.cond, &while_expr.body)?;
            }

            // =========================================================
            // Infinite loop
            // =========================================================
            Expr::Loop(loop_expr) => {
                self.compile_loop(&loop_expr.body)?;
            }

            // =========================================================
            // For loop
            // =========================================================
            Expr::ForLoop(for_loop) => {
                self.compile_for_loop(for_loop)?;
            }

            // =========================================================
            // Break
            // =========================================================
            Expr::Break(brk) => {
                if brk.expr.is_some() {
                    return Err(CompileError("break with value not supported".to_string()));
                }
                self.compile_break()?;
                self.emit_zero();  // Placeholder value
            }

            // =========================================================
            // Continue
            // =========================================================
            Expr::Continue(_) => {
                self.compile_continue()?;
                self.emit_zero();  // Placeholder value
            }

            // =========================================================
            // Return (early return)
            // =========================================================
            Expr::Return(ret) => {
                if let Some(expr) = &ret.expr {
                    self.compile_expr(expr)?;
                } else {
                    self.emit_zero();
                }
                // Clean up ALL scopes before returning (scope 0 is function args, no cleanup needed)
                // This prevents memory leaks from early returns
                self.emit_scope_cleanup(1);
                self.emit_op(crate::opcodes::exec::HALT);
            }

            // =========================================================
            // Block expression
            // =========================================================
            Expr::Block(block) => {
                self.compile_block(&block.block)?;
            }

            // =========================================================
            // Match expression
            // =========================================================
            Expr::Match(match_expr) => {
                self.compile_match(match_expr)?;
            }

            // =========================================================
            // Parenthesized expression
            // =========================================================
            Expr::Paren(paren) => {
                self.compile_expr(&paren.expr)?;
            }

            // =========================================================
            // Assignment: x = value
            // =========================================================
            Expr::Assign(assign) => {
                self.compile_assignment(&assign.left, &assign.right)?;
                self.emit_zero();  // Assignment produces unit
            }

            // =========================================================
            // Tuple: (), (a,), (a, b), (a, b, c)
            // =========================================================
            Expr::Tuple(tuple) => {
                self.compile_tuple_expr(tuple)?;
            }

            // =========================================================
            // Struct literal: Point { x: 1, y: 2 }
            // =========================================================
            Expr::Struct(expr_struct) => {
                self.compile_struct_expr(expr_struct)?;
            }

            // =========================================================
            // Field access: p.x
            // =========================================================
            Expr::Field(field_expr) => {
                self.compile_field_access(field_expr)?;
            }

            // =========================================================
            // Reference: &x, &mut x
            // =========================================================
            Expr::Reference(reference) => {
                // Get address of variable
                if let Expr::Path(path) = &*reference.expr {
                    if path.path.segments.len() == 1 {
                        let name = path.path.segments[0].ident.to_string();
                        match self.get_var_location(&name) {
                            Some(VarLocation::Array(reg, _)) | Some(VarLocation::String(reg)) => {
                                // Array/string: register holds the address already
                                self.emit_push_reg(reg);
                            }
                            _ => {
                                return Err(CompileError("Cannot take reference of non-array type".to_string()));
                            }
                        }
                    } else {
                        return Err(CompileError("Complex paths not supported".to_string()));
                    }
                } else {
                    return Err(CompileError("Can only take reference of variables".to_string()));
                }
            }

            // =========================================================
            // Range expressions (for iterators)
            // =========================================================
            Expr::Range(_) => {
                return Err(CompileError("Range expressions only supported in for loops".to_string()));
            }

            // =========================================================
            // Function call: func(args) or tuple struct: Position(0, 0)
            // =========================================================
            Expr::Call(call) => {
                // Check for built-in constructors or tuple struct
                if let Expr::Path(path) = &*call.func {
                    let func_name = path.path.segments.iter()
                        .map(|s| s.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::");

                    match func_name.as_str() {
                        "String::new" => {
                            self.compile_string_constructor(None)?;
                            return Ok(());
                        }
                        "String::with_capacity" => {
                            if call.args.len() == 1 {
                                self.compile_expr(&call.args[0])?;
                                self.emit_str_new();
                                return Ok(());
                            }
                        }
                        "Vec::new" => {
                            self.emit_zero();      // capacity = 0
                            self.emit_constant(8); // elem_size = 8
                            self.emit_vec_new();
                            return Ok(());
                        }
                        "Vec::with_capacity" => {
                            if call.args.len() == 1 {
                                self.compile_expr(&call.args[0])?;
                                self.emit_constant(8);
                                self.emit_vec_new();
                                return Ok(());
                            }
                        }
                        _ => {
                            // Check if this is a tuple struct instantiation
                            if let Some(struct_def) = self.struct_defs.get(&func_name).cloned() {
                                // Verify it's a tuple struct (has numeric field names)
                                if struct_def.fields.first().map(|f| f.name == "0").unwrap_or(true) {
                                    self.compile_tuple_struct_expr(&func_name, &struct_def, &call.args)?;
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
                return Err(CompileError("Function calls not yet supported (use native calls)".to_string()));
            }

            // =========================================================
            // Unsupported expressions
            // =========================================================
            _ => {
                return Err(CompileError(format!(
                    "Unsupported expression type: {:?}",
                    std::any::type_name_of_val(expr)
                )));
            }
        }

        Ok(())
    }

    // =========================================================================
    // Comparison Operations
    // =========================================================================

    /// Compile equality: a == b
    fn compile_eq(&mut self) -> Result<(), CompileError> {
        // XOR: if equal, result is 0
        self.emit_xor();

        let else_label = self.unique_label("eq_else");
        let end_label = self.unique_label("eq_end");

        self.emit_jump(control::JNZ, &else_label);
        self.emit_constant(1);  // Equal: true
        self.emit_jump(control::JMP, &end_label);
        self.mark_label(&else_label);
        self.emit_zero();       // Not equal: false
        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile inequality: a != b
    fn compile_ne(&mut self) -> Result<(), CompileError> {
        self.emit_xor();

        let else_label = self.unique_label("ne_else");
        let end_label = self.unique_label("ne_end");

        self.emit_jump(control::JZ, &else_label);
        self.emit_constant(1);  // Not equal: true
        self.emit_jump(control::JMP, &end_label);
        self.mark_label(&else_label);
        self.emit_zero();       // Equal: false
        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile less than: a < b
    fn compile_lt(&mut self) -> Result<(), CompileError> {
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();

        let else_label = self.unique_label("lt_else");
        let end_label = self.unique_label("lt_end");

        self.emit_jump(control::JGE, &else_label);
        self.emit_constant(1);
        self.emit_jump(control::JMP, &end_label);
        self.mark_label(&else_label);
        self.emit_zero();
        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile greater than: a > b
    fn compile_gt(&mut self) -> Result<(), CompileError> {
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();

        let else_label = self.unique_label("gt_else");
        let end_label = self.unique_label("gt_end");

        self.emit_jump(control::JLE, &else_label);
        self.emit_constant(1);
        self.emit_jump(control::JMP, &end_label);
        self.mark_label(&else_label);
        self.emit_zero();
        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile less than or equal: a <= b
    fn compile_le(&mut self) -> Result<(), CompileError> {
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();

        let else_label = self.unique_label("le_else");
        let end_label = self.unique_label("le_end");

        self.emit_jump(control::JGT, &else_label);
        self.emit_constant(1);
        self.emit_jump(control::JMP, &end_label);
        self.mark_label(&else_label);
        self.emit_zero();
        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile greater than or equal: a >= b
    fn compile_ge(&mut self) -> Result<(), CompileError> {
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();

        let else_label = self.unique_label("ge_else");
        let end_label = self.unique_label("ge_end");

        self.emit_jump(control::JLT, &else_label);
        self.emit_constant(1);
        self.emit_jump(control::JMP, &end_label);
        self.mark_label(&else_label);
        self.emit_zero();
        self.mark_label(&end_label);

        Ok(())
    }

    /// Check if an expression is signed (i8, i16, i32, i64)
    fn is_signed_expr(&self, expr: &Expr) -> bool {
        match expr {
            // Variable reference - check if marked as signed
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    self.is_var_signed(&name)
                } else {
                    false
                }
            }
            // Cast to signed type
            Expr::Cast(cast) => {
                if let syn::Type::Path(type_path) = &*cast.ty {
                    if let Some(segment) = type_path.path.segments.last() {
                        let type_name = segment.ident.to_string();
                        matches!(type_name.as_str(), "i8" | "i16" | "i32" | "i64" | "isize")
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            // Unary negation implies signed
            Expr::Unary(unary) => {
                matches!(unary.op, syn::UnOp::Neg(_))
            }
            // Parenthesized - check inner
            Expr::Paren(paren) => self.is_signed_expr(&paren.expr),
            // Negative literals
            Expr::Lit(lit) => {
                matches!(&lit.lit, syn::Lit::Int(i) if i.suffix() == "i8" || i.suffix() == "i16" || i.suffix() == "i32" || i.suffix() == "i64" || i.suffix() == "isize")
            }
            _ => false,
        }
    }

    // =========================================================================
    // Struct Operations
    // =========================================================================

    /// Compile struct literal expression: Point { x: 1, y: 2 } or Point { x, y } or Point { x: 1, ..base }
    fn compile_struct_expr(&mut self, expr_struct: &syn::ExprStruct) -> Result<(), CompileError> {
        // Get struct name
        let struct_name = expr_struct.path.segments.iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");

        // Look up struct definition
        let struct_def = self.struct_defs.get(&struct_name)
            .ok_or_else(|| CompileError(format!("Unknown struct: {}", struct_name)))?
            .clone();

        // Handle zero-sized structs (unit structs)
        if struct_def.size == 0 {
            // Just return 0 as a sentinel value for unit structs
            self.emit_zero();
            return Ok(());
        }

        // Allocate memory: push size, call HEAP_ALLOC
        self.emit_constant(struct_def.size as u64);
        self.emit_heap_alloc();

        // Stack now has: [struct_addr]
        // Store in temp register to preserve across field writes
        let temp_reg = self.next_local_reg;
        self.next_local_reg += 1;
        self.emit_dup();  // Keep address on stack for return
        self.emit_pop_reg(temp_reg);

        // Collect explicitly specified field names
        let mut specified_fields: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Write each explicitly specified field
        for field_value in &expr_struct.fields {
            let field_name = match &field_value.member {
                syn::Member::Named(ident) => ident.to_string(),
                syn::Member::Unnamed(index) => index.index.to_string(),
            };

            specified_fields.insert(field_name.clone());

            let offset = struct_def.get_field_offset(&field_name)
                .ok_or_else(|| CompileError(format!("Unknown field: {}.{}", struct_name, field_name)))?;

            // Push base address + offset
            self.emit_push_reg(temp_reg);
            if offset > 0 {
                self.emit_constant(offset as u64);
                self.emit_add();
            }

            // Compile field value (handles shorthand like Point { x, y } where x means x: x)
            self.compile_expr(&field_value.expr)?;

            // Store: [addr, value] -> []
            self.emit_heap_store64();
        }

        // Handle functional update syntax: Point { x: 1, ..base }
        if let Some(rest) = &expr_struct.rest {
            // Compile base expression (pushes base struct address)
            self.compile_expr(rest)?;
            let base_reg = self.next_local_reg;
            self.next_local_reg += 1;
            self.emit_pop_reg(base_reg);

            // Copy unspecified fields from base
            for field_def in &struct_def.fields {
                if !specified_fields.contains(&field_def.name) {
                    // Load value from base struct
                    self.emit_push_reg(base_reg);
                    if field_def.offset > 0 {
                        self.emit_constant(field_def.offset as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    // Store to new struct
                    let value_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(value_reg);

                    self.emit_push_reg(temp_reg);
                    if field_def.offset > 0 {
                        self.emit_constant(field_def.offset as u64);
                        self.emit_add();
                    }
                    self.emit_push_reg(value_reg);
                    self.emit_heap_store64();
                }
            }
        }

        // struct address is already on stack from the DUP earlier

        Ok(())
    }

    /// Compile tuple struct expression: Position(0, 0, 0)
    fn compile_tuple_struct_expr(&mut self, struct_name: &str, struct_def: &super::StructDef, args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>) -> Result<(), CompileError> {
        // Handle zero-sized tuple structs
        if struct_def.size == 0 {
            self.emit_zero();
            return Ok(());
        }

        // Verify argument count matches field count
        if args.len() != struct_def.fields.len() {
            return Err(CompileError(format!(
                "Tuple struct {} expects {} fields, got {}",
                struct_name, struct_def.fields.len(), args.len()
            )));
        }

        // Allocate memory
        self.emit_constant(struct_def.size as u64);
        self.emit_heap_alloc();

        // Store in temp register
        let temp_reg = self.next_local_reg;
        self.next_local_reg += 1;
        self.emit_dup();
        self.emit_pop_reg(temp_reg);

        // Write each field by position
        for (i, arg) in args.iter().enumerate() {
            let offset = i * 8;

            // Push base address + offset
            self.emit_push_reg(temp_reg);
            if offset > 0 {
                self.emit_constant(offset as u64);
                self.emit_add();
            }

            // Compile argument value
            self.compile_expr(arg)?;

            // Store
            self.emit_heap_store64();
        }

        Ok(())
    }

    /// Compile field access expression: p.x or tuple.0
    fn compile_field_access(&mut self, field_expr: &syn::ExprField) -> Result<(), CompileError> {
        // Check if this is tuple indexing (t.0, t.1, etc.)
        if let syn::Member::Unnamed(index) = &field_expr.member {
            // Try to detect if base is a tuple
            if self.is_tuple_expr(&field_expr.base) {
                return self.compile_tuple_index(field_expr, index.index as usize);
            }
        }

        // Compile base expression (pushes struct/tuple address)
        self.compile_expr(&field_expr.base)?;

        // Get field name
        let field_name = match &field_expr.member {
            syn::Member::Named(ident) => ident.to_string(),
            syn::Member::Unnamed(index) => index.index.to_string(),
        };

        // Determine struct type from base expression
        let struct_name = self.infer_struct_type(&field_expr.base)?;

        // Look up struct definition
        let struct_def = self.struct_defs.get(&struct_name)
            .ok_or_else(|| CompileError(format!("Unknown struct: {}", struct_name)))?;

        // Get field offset
        let offset = struct_def.get_field_offset(&field_name)
            .ok_or_else(|| CompileError(format!("Unknown field: {}.{}", struct_name, field_name)))?;

        // Add offset to base address
        if offset > 0 {
            self.emit_constant(offset as u64);
            self.emit_add();
        }

        // Load value from heap
        self.emit_heap_load64();

        Ok(())
    }

    /// Check if expression is a tuple
    fn is_tuple_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    matches!(self.get_var_type(&name), Some(super::VarType::Tuple(_)))
                } else {
                    false
                }
            }
            Expr::Tuple(_) => true,
            Expr::Paren(paren) => self.is_tuple_expr(&paren.expr),
            // Nested field access - check if the result type is a tuple
            Expr::Field(field) => {
                if let syn::Member::Unnamed(idx) = &field.member {
                    if let Some(elem_type) = self.get_tuple_element_type(&field.base, idx.index as usize) {
                        return matches!(elem_type, super::VarType::Tuple(_));
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Get tuple element type at given index
    fn get_tuple_element_type(&self, expr: &Expr, index: usize) -> Option<super::VarType> {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(super::VarType::Tuple(elems)) = self.get_var_type(&name) {
                        return elems.get(index).cloned();
                    }
                }
                None
            }
            Expr::Tuple(tuple) => {
                // Infer type from tuple literal element
                tuple.elems.iter().nth(index).map(|elem| self.infer_expr_type(elem))
            }
            Expr::Paren(paren) => self.get_tuple_element_type(&paren.expr, index),
            Expr::Field(field) => {
                // Nested field access: (t.0).1
                if let syn::Member::Unnamed(idx) = &field.member {
                    if let Some(super::VarType::Tuple(inner_elems)) = self.get_tuple_element_type(&field.base, idx.index as usize) {
                        return inner_elems.get(index).cloned();
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Get full tuple type from expression
    fn get_tuple_type(&self, expr: &Expr) -> Option<Vec<super::VarType>> {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(super::VarType::Tuple(elems)) = self.get_var_type(&name) {
                        return Some(elems);
                    }
                }
                None
            }
            Expr::Tuple(tuple) => {
                Some(tuple.elems.iter().map(|e| self.infer_expr_type(e)).collect())
            }
            Expr::Paren(paren) => self.get_tuple_type(&paren.expr),
            Expr::Field(field) => {
                // Nested: get the tuple element type and if it's a tuple, return its elements
                if let syn::Member::Unnamed(idx) = &field.member {
                    if let Some(super::VarType::Tuple(inner)) = self.get_tuple_element_type(&field.base, idx.index as usize) {
                        return Some(inner);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Infer type of an expression (simplified version for tuple elements)
    fn infer_expr_type(&self, expr: &Expr) -> super::VarType {
        match expr {
            Expr::Lit(lit) => {
                match &lit.lit {
                    syn::Lit::Str(_) | syn::Lit::ByteStr(_) => super::VarType::String,
                    syn::Lit::Bool(_) => super::VarType::Bool,
                    _ => super::VarType::Integer,
                }
            }
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    self.get_var_type(&name).unwrap_or(super::VarType::Integer)
                } else {
                    super::VarType::Integer
                }
            }
            Expr::Tuple(tuple) => {
                let elems: Vec<super::VarType> = tuple.elems.iter()
                    .map(|e| self.infer_expr_type(e))
                    .collect();
                super::VarType::Tuple(elems)
            }
            Expr::Array(_) | Expr::Repeat(_) => super::VarType::Vector,
            Expr::Paren(paren) => self.infer_expr_type(&paren.expr),
            _ => super::VarType::Integer,
        }
    }

    /// Compile tuple index expression: t.0, t.1, or nested t.0.1
    fn compile_tuple_index(&mut self, field_expr: &syn::ExprField, index: usize) -> Result<(), CompileError> {
        // Get tuple type to calculate proper offset
        let tuple_type = self.get_tuple_type(&field_expr.base);

        // Compile base expression (pushes tuple address)
        self.compile_expr(&field_expr.base)?;

        // Calculate offset based on element types
        let offset = if let Some(elems) = &tuple_type {
            // Sum of aligned sizes of elements before index
            elems.iter().take(index).map(|t| t.aligned_size()).sum()
        } else {
            // Fallback to 8 bytes per element
            index * 8
        };

        // Add offset to base address
        if offset > 0 {
            self.emit_constant(offset as u64);
            self.emit_add();
        }

        // Load value from heap
        self.emit_heap_load64();

        Ok(())
    }

    /// Infer struct type from expression
    fn infer_struct_type(&self, expr: &Expr) -> Result<String, CompileError> {
        match expr {
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    if let Some(super::VarType::Struct(struct_name)) = self.get_var_type(&name) {
                        return Ok(struct_name);
                    }
                }
                Err(CompileError(format!("Cannot infer struct type from variable '{}'",
                    path.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().join("::"))))
            }
            Expr::Field(_field) => {
                // Nested field access - for now, we don't support nested structs returning struct types
                // This would need to be extended to track field types
                Err(CompileError("Nested struct field access not yet supported".to_string()))
            }
            Expr::Struct(expr_struct) => {
                // Direct struct literal - return its type
                let struct_name = expr_struct.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                Ok(struct_name)
            }
            Expr::Paren(paren) => {
                // Parenthesized expression - check inner
                self.infer_struct_type(&paren.expr)
            }
            _ => Err(CompileError("Cannot infer struct type from expression".to_string())),
        }
    }

    // =========================================================================
    // Tuple Operations
    // =========================================================================

    /// Compile tuple literal expression: (), (a,), (a, b), (a, b, c)
    fn compile_tuple_expr(&mut self, tuple: &syn::ExprTuple) -> Result<(), CompileError> {
        let num_elems = tuple.elems.len();

        // Empty tuple () - just return 0
        if num_elems == 0 {
            self.emit_zero();
            return Ok(());
        }

        // Allocate memory: num_elems * 8 bytes
        let size = num_elems * 8;
        self.emit_constant(size as u64);
        self.emit_heap_alloc();

        // Store in temp register to preserve across element writes
        let temp_reg = self.next_local_reg;
        self.next_local_reg += 1;
        self.emit_dup();  // Keep address on stack for return
        self.emit_pop_reg(temp_reg);

        // Write each element
        for (i, elem) in tuple.elems.iter().enumerate() {
            let offset = i * 8;

            // Push base address + offset
            self.emit_push_reg(temp_reg);
            if offset > 0 {
                self.emit_constant(offset as u64);
                self.emit_add();
            }

            // Compile element value
            self.compile_expr(elem)?;

            // Store: [addr, value] -> []
            self.emit_heap_store64();
        }

        // Tuple address is already on stack from the DUP earlier
        Ok(())
    }
}
