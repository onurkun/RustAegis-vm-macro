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
            // Variable reference
            // =========================================================
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();

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
                self.emit_op(crate::opcodes::exec::HALT);
            }

            // =========================================================
            // Block expression
            // =========================================================
            Expr::Block(block) => {
                self.compile_block(&block.block)?;
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
            // Tuple (limited support)
            // =========================================================
            Expr::Tuple(tuple) => {
                if tuple.elems.is_empty() {
                    // Unit tuple ()
                    self.emit_zero();
                } else {
                    return Err(CompileError("Non-unit tuples not yet supported".to_string()));
                }
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
            // Function call: func(args)
            // =========================================================
            Expr::Call(call) => {
                // Check for built-in constructors
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
                        _ => {}
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
}
