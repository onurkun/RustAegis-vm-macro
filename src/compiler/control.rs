//! Control Flow Compilation
//!
//! Handles: if/else, while, loop, for, break, continue, match, struct definitions

use syn::{Expr, Block, Item, Pat};
use super::{Compiler, CompileError, LoopContext, FieldDef, StructDef, VarType};
use crate::opcodes::control;

impl Compiler {
    /// Compile if expression
    /// if cond { then_block } else { else_block }
    pub(crate) fn compile_if(&mut self, cond: &Expr, then_block: &Block, else_branch: Option<&Expr>) -> Result<(), CompileError> {
        let else_label = self.unique_label("if_else");
        let end_label = self.unique_label("if_end");

        // Compile condition
        self.compile_expr(cond)?;

        // Test condition: XOR with 0 sets ZF if value is 0
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();  // Drop XOR result, keep original condition
        self.emit_drop();  // Drop original condition

        // Jump to else if condition is false (zero)
        self.emit_jump(control::JZ, &else_label);

        // Then block
        self.compile_block(then_block)?;
        self.emit_jump(control::JMP, &end_label);

        // Else block
        self.mark_label(&else_label);
        if let Some(else_expr) = else_branch {
            match else_expr {
                Expr::Block(block) => {
                    self.compile_block(&block.block)?;
                }
                Expr::If(else_if) => {
                    // else if ...
                    let else_expr = else_if.else_branch.as_ref().map(|(_, e)| e.as_ref());
                    self.compile_if(&else_if.cond, &else_if.then_branch, else_expr)?;
                }
                _ => {
                    self.compile_expr(else_expr)?;
                }
            }
        } else {
            // No else: push unit (0)
            self.emit_zero();
        }

        self.mark_label(&end_label);
        Ok(())
    }

    /// Compile while loop
    /// while cond { body }
    pub(crate) fn compile_while(&mut self, cond: &Expr, body: &Block) -> Result<(), CompileError> {
        let loop_start = self.unique_label("while_start");
        let loop_end = self.unique_label("while_end");

        // Push loop context for break/continue (before pushing loop's scope)
        self.loop_stack.push(LoopContext {
            continue_label: loop_start.clone(),
            break_label: loop_end.clone(),
            scope_depth: self.current_scope_depth(),
        });

        // Loop start
        self.mark_label(&loop_start);

        // Compile condition
        self.compile_expr(cond)?;
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();
        self.emit_drop();

        // Exit if condition is false
        self.emit_jump(control::JZ, &loop_end);

        // Body (as statements - drop any expression result)
        self.compile_block_stmt(body)?;

        // Jump back to condition
        self.emit_jump(control::JMP, &loop_start);

        // Loop end
        self.mark_label(&loop_end);

        // Pop loop context
        self.loop_stack.pop();

        // While loops produce unit
        self.emit_zero();

        Ok(())
    }

    /// Compile infinite loop
    /// loop { body }
    pub(crate) fn compile_loop(&mut self, body: &Block) -> Result<(), CompileError> {
        let loop_start = self.unique_label("loop_start");
        let loop_end = self.unique_label("loop_end");

        // Push loop context (before pushing loop's scope)
        self.loop_stack.push(LoopContext {
            continue_label: loop_start.clone(),
            break_label: loop_end.clone(),
            scope_depth: self.current_scope_depth(),
        });

        // Loop start
        self.mark_label(&loop_start);

        // Body
        self.compile_block_stmt(body)?;

        // Jump back
        self.emit_jump(control::JMP, &loop_start);

        // Loop end (reached via break)
        self.mark_label(&loop_end);

        // Pop loop context
        self.loop_stack.pop();

        // Infinite loops produce unit (unless break with value, not supported)
        self.emit_zero();

        Ok(())
    }

    /// Compile for loop
    /// for i in start..end { body }
    pub(crate) fn compile_for_loop(&mut self, for_loop: &syn::ExprForLoop) -> Result<(), CompileError> {
        // Push a scope for the for loop (loop variable lives here)
        self.push_scope();

        // Extract loop variable name
        let var_name = Self::extract_pat_name(&for_loop.pat)?;

        // Define loop variable in scope (Integer type, unsigned for range)
        let loop_var_reg = self.define_var(&var_name, super::VarType::Integer, false)?;

        // Parse range expression
        let (start, end, inclusive) = self.parse_range_expr(&for_loop.expr)?;

        // Labels
        let loop_start = self.unique_label("for_start");
        let loop_continue = self.unique_label("for_continue");
        let loop_end = self.unique_label("for_end");

        // Push loop context (continue jumps to increment, not condition)
        // Note: scope_depth is AFTER push_scope() so it includes loop var scope
        self.loop_stack.push(LoopContext {
            continue_label: loop_continue.clone(),
            break_label: loop_end.clone(),
            scope_depth: self.current_scope_depth(),
        });

        // Initialize loop variable
        self.compile_expr(&start)?;
        self.emit_pop_reg(loop_var_reg);

        // Compile end value and store in temp register
        let end_reg = self.next_local_reg;
        self.next_local_reg += 1;
        self.compile_expr(&end)?;
        self.emit_pop_reg(end_reg);

        // Loop start (condition check)
        self.mark_label(&loop_start);

        // Compare: loop_var < end (or <= for inclusive)
        self.emit_push_reg(loop_var_reg);
        self.emit_push_reg(end_reg);
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();

        if inclusive {
            // Exit if loop_var > end
            self.emit_jump(control::JGT, &loop_end);
        } else {
            // Exit if loop_var >= end
            self.emit_jump(control::JGE, &loop_end);
        }

        // Body
        self.compile_block_stmt(&for_loop.body)?;

        // Continue label (increment)
        self.mark_label(&loop_continue);

        // Increment loop variable
        self.emit_push_reg(loop_var_reg);
        self.emit_inc();
        self.emit_pop_reg(loop_var_reg);

        // Jump back to condition
        self.emit_jump(control::JMP, &loop_start);

        // Loop end
        self.mark_label(&loop_end);

        // Pop loop context
        self.loop_stack.pop();

        // Pop scope (for loop variable cleanup)
        self.pop_scope();

        // For loops produce unit
        self.emit_zero();

        Ok(())
    }

    /// Parse a range expression (start..end or start..=end)
    pub(crate) fn parse_range_expr(&self, expr: &Expr) -> Result<(Expr, Expr, bool), CompileError> {
        match expr {
            Expr::Range(range) => {
                let start = range.start.as_ref()
                    .ok_or_else(|| CompileError("Range must have start".to_string()))?;
                let end = range.end.as_ref()
                    .ok_or_else(|| CompileError("Range must have end".to_string()))?;

                // Check if inclusive (..=)
                let inclusive = matches!(range.limits, syn::RangeLimits::Closed(_));

                Ok((*start.clone(), *end.clone(), inclusive))
            }
            _ => Err(CompileError("For loop requires range expression".to_string())),
        }
    }

    /// Compile break statement
    pub(crate) fn compile_break(&mut self) -> Result<(), CompileError> {
        let ctx = self.loop_stack.last()
            .ok_or_else(|| CompileError("break outside of loop".to_string()))?;

        // Clone needed values before mutable borrow
        let target_depth = ctx.scope_depth;
        let break_label = ctx.break_label.clone();

        // Emit cleanup for all scopes we're exiting (from current to loop's scope)
        self.emit_scope_cleanup(target_depth);

        self.emit_jump(control::JMP, &break_label);
        Ok(())
    }

    /// Compile continue statement
    pub(crate) fn compile_continue(&mut self) -> Result<(), CompileError> {
        let ctx = self.loop_stack.last()
            .ok_or_else(|| CompileError("continue outside of loop".to_string()))?;

        // Clone needed values before mutable borrow
        let target_depth = ctx.scope_depth;
        let continue_label = ctx.continue_label.clone();

        // Emit cleanup for all scopes we're exiting (from current to loop's scope)
        self.emit_scope_cleanup(target_depth);

        self.emit_jump(control::JMP, &continue_label);
        Ok(())
    }

    /// Compile a block as statements (for loop bodies)
    /// Unlike compile_block, this drops ALL expression results
    pub(crate) fn compile_block_stmt(&mut self, block: &Block) -> Result<(), CompileError> {
        // Push new scope for this block
        self.push_scope();

        for stmt in &block.stmts {
            match stmt {
                // Handle struct definitions (compile-time only, no bytecode)
                syn::Stmt::Item(Item::Struct(item_struct)) => {
                    self.register_struct_from_item(item_struct)?;
                }
                syn::Stmt::Expr(expr, _) => {
                    self.compile_expr(expr)?;
                    self.emit_drop();  // Always drop expression result
                }
                syn::Stmt::Local(local) => {
                    self.compile_local(local)?;
                }
                _ => return Err(CompileError("Unsupported statement type".to_string())),
            }
        }

        // Pop scope and cleanup heap variables
        self.pop_scope();

        Ok(())
    }

    /// Compile a block as expression (returns value on stack)
    pub(crate) fn compile_block(&mut self, block: &Block) -> Result<(), CompileError> {
        // Push new scope for this block
        self.push_scope();

        let stmts = &block.stmts;
        let len = stmts.len();

        // Empty block produces unit (0)
        if len == 0 {
            self.pop_scope();
            self.emit_zero();
            return Ok(());
        }

        // Process all statements except the last
        for stmt in stmts.iter().take(len.saturating_sub(1)) {
            match stmt {
                // Handle struct definitions (compile-time only, no bytecode)
                syn::Stmt::Item(Item::Struct(item_struct)) => {
                    self.register_struct_from_item(item_struct)?;
                }
                syn::Stmt::Expr(expr, Some(_)) => {
                    // Expression with semicolon - drop result
                    self.compile_expr(expr)?;
                    self.emit_drop();
                }
                syn::Stmt::Expr(expr, None) => {
                    // Expression without semicolon in middle - drop anyway
                    self.compile_expr(expr)?;
                    self.emit_drop();
                }
                syn::Stmt::Local(local) => {
                    self.compile_local(local)?;
                }
                _ => return Err(CompileError("Unsupported statement type".to_string())),
            }
        }

        // Last statement determines block value
        if let Some(last) = stmts.last() {
            match last {
                // Handle struct definitions (compile-time only, no bytecode)
                syn::Stmt::Item(Item::Struct(item_struct)) => {
                    self.register_struct_from_item(item_struct)?;
                    self.emit_zero();  // struct def produces unit
                }
                syn::Stmt::Expr(expr, None) => {
                    // Expression without semicolon - keep result
                    self.compile_expr(expr)?;
                }
                syn::Stmt::Expr(expr, Some(_)) => {
                    // Expression with semicolon - drop and push unit
                    self.compile_expr(expr)?;
                    self.emit_drop();
                    self.emit_zero();
                }
                syn::Stmt::Local(local) => {
                    self.compile_local(local)?;
                    self.emit_zero();  // let binding produces unit
                }
                _ => return Err(CompileError("Unsupported statement type".to_string())),
            }
        }

        // Pop scope and cleanup heap variables
        self.pop_scope();

        Ok(())
    }

    // =========================================================================
    // Struct Definition Registration
    // =========================================================================

    /// Parse and register a struct definition from the function body
    /// struct Point { x: u64, y: u64 }
    pub(crate) fn register_struct_from_item(&mut self, item_struct: &syn::ItemStruct) -> Result<(), CompileError> {
        let struct_name = item_struct.ident.to_string();

        let mut fields = Vec::new();
        let mut offset = 0usize;

        match &item_struct.fields {
            syn::Fields::Named(named) => {
                for field in &named.named {
                    let field_name = field.ident.as_ref()
                        .ok_or_else(|| CompileError("Struct field must have name".to_string()))?
                        .to_string();

                    fields.push(FieldDef {
                        name: field_name,
                        offset,
                    });
                    offset += 8;  // All fields are 8 bytes (u64)
                }
            }
            syn::Fields::Unnamed(unnamed) => {
                // Tuple struct: struct Point(u64, u64)
                for (i, _field) in unnamed.unnamed.iter().enumerate() {
                    fields.push(FieldDef {
                        name: i.to_string(),  // "0", "1", etc.
                        offset,
                    });
                    offset += 8;
                }
            }
            syn::Fields::Unit => {
                // Unit struct: struct Marker;
                // No fields, size = 0
            }
        }

        self.struct_defs.insert(struct_name.clone(), StructDef {
            name: struct_name,
            fields,
            size: offset,
        });

        Ok(())
    }

    // =========================================================================
    // Match Expression Compilation
    // =========================================================================

    /// Compile match expression
    /// match expr { pat => body, ... }
    pub(crate) fn compile_match(&mut self, match_expr: &syn::ExprMatch) -> Result<(), CompileError> {
        let end_label = self.unique_label("match_end");

        // Evaluate the scrutinee (value being matched) and store in temp register
        self.compile_expr(&match_expr.expr)?;
        let scrutinee_reg = self.next_local_reg;
        self.next_local_reg += 1;
        self.emit_pop_reg(scrutinee_reg);

        // Process each arm
        let arms = &match_expr.arms;
        for (i, arm) in arms.iter().enumerate() {
            let next_arm_label = self.unique_label(&format!("match_arm_{}", i + 1));
            let body_label = self.unique_label(&format!("match_body_{}", i));

            // Compile pattern check
            // If pattern doesn't match, jump to next_arm_label
            self.compile_pattern_check(&arm.pat, scrutinee_reg, &next_arm_label)?;

            // Pattern matched - mark body label
            self.mark_label(&body_label);

            // Push scope for pattern bindings (must be done before guard check!)
            self.push_scope();

            // Bind pattern variables BEFORE checking guard (guard uses bound vars)
            self.bind_pattern_vars(&arm.pat, scrutinee_reg)?;

            // If there's a guard, check it AFTER binding variables
            if let Some((_, guard_expr)) = &arm.guard {
                self.compile_expr(guard_expr)?;
                // Test guard: if false (0), jump to next arm
                self.emit_dup();
                self.emit_zero();
                self.emit_xor();
                self.emit_drop();
                self.emit_drop();
                // If guard fails, pop scope and try next arm
                self.emit_jump(control::JZ, &next_arm_label);
            }

            // Compile arm body
            self.compile_expr(&arm.body)?;

            // Pop pattern scope
            self.pop_scope();

            // Jump to end (we found a match)
            self.emit_jump(control::JMP, &end_label);

            // Next arm
            self.mark_label(&next_arm_label);
        }

        // If no arm matched, this is a runtime error (unreachable in well-typed code)
        // For safety, push 0 as default value
        self.emit_zero();

        // End of match
        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile pattern check - leaves result on stack or jumps to fail_label
    fn compile_pattern_check(&mut self, pat: &Pat, scrutinee_reg: u8, fail_label: &str) -> Result<(), CompileError> {
        match pat {
            // Wildcard matches everything
            Pat::Wild(_) => {
                // Always matches - do nothing
            }

            // Variable binding matches everything (binding happens later)
            // Also handles @ bindings: n @ 1..=5
            Pat::Ident(pat_ident) => {
                // If there's a subpattern (@ binding), check it first
                if let Some((_, subpat)) = &pat_ident.subpat {
                    self.compile_pattern_check(subpat, scrutinee_reg, fail_label)?;
                }
                // The variable binding itself always matches (happens in bind_pattern_vars)
            }

            // Literal pattern: match against constant
            Pat::Lit(pat_lit) => {
                // Push scrutinee value
                self.emit_push_reg(scrutinee_reg);
                // Compile literal (PatLit is ExprLit in syn 2.0)
                self.compile_literal(&pat_lit.lit)?;
                // Compare
                self.emit_cmp();
                self.emit_drop();
                self.emit_drop();
                // If not equal, jump to fail (JNZ because CMP sets ZF=1 if equal)
                self.emit_jump(control::JNZ, fail_label);
            }

            // Range pattern: 1..=5
            Pat::Range(pat_range) => {
                // Check: scrutinee >= start AND scrutinee <= end
                let in_range_label = self.unique_label("range_ok");

                // First check: scrutinee >= start
                if let Some(start) = &pat_range.start {
                    self.emit_push_reg(scrutinee_reg);
                    self.compile_expr(start)?;
                    self.emit_cmp();
                    self.emit_drop();
                    self.emit_drop();
                    // If scrutinee < start, fail
                    self.emit_jump(control::JLT, fail_label);
                }

                // Second check: scrutinee <= end (or < for exclusive)
                if let Some(end) = &pat_range.end {
                    self.emit_push_reg(scrutinee_reg);
                    self.compile_expr(end)?;
                    self.emit_cmp();
                    self.emit_drop();
                    self.emit_drop();

                    // Check if inclusive (..) or exclusive (..=)
                    match &pat_range.limits {
                        syn::RangeLimits::Closed(_) => {
                            // Inclusive: fail if scrutinee > end
                            self.emit_jump(control::JGT, fail_label);
                        }
                        syn::RangeLimits::HalfOpen(_) => {
                            // Exclusive: fail if scrutinee >= end
                            self.emit_jump(control::JGE, fail_label);
                        }
                    }
                }

                self.mark_label(&in_range_label);
            }

            // Or pattern: pat1 | pat2 | pat3
            Pat::Or(pat_or) => {
                let match_label = self.unique_label("or_match");

                // Try each alternative - if any matches, jump to match_label
                for (i, case) in pat_or.cases.iter().enumerate() {
                    let is_last = i == pat_or.cases.len() - 1;
                    let next_case_label = if !is_last {
                        self.unique_label(&format!("or_case_{}", i + 1))
                    } else {
                        String::new() // won't be used
                    };

                    // For or-patterns, check each case
                    // If this case matches, jump to match_label
                    // If this case fails, continue to next case (or fail_label for last)
                    self.compile_or_pattern_case(case, scrutinee_reg, &match_label)?;

                    if !is_last {
                        // Not matched, mark next case label
                        self.mark_label(&next_case_label);
                    } else {
                        // Last case didn't match - jump to fail
                        self.emit_jump(control::JMP, fail_label);
                    }
                }

                self.mark_label(&match_label);
            }

            // Tuple pattern: (a, b, c)
            Pat::Tuple(pat_tuple) => {
                // For each element in the tuple pattern, check if it matches
                for (i, elem_pat) in pat_tuple.elems.iter().enumerate() {
                    // Load tuple element from heap
                    // scrutinee_reg holds heap address of tuple
                    self.emit_push_reg(scrutinee_reg);
                    if i > 0 {
                        self.emit_constant((i * 8) as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    // Store in temp register for pattern check
                    let elem_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(elem_reg);

                    // Check element pattern
                    self.compile_pattern_check(elem_pat, elem_reg, fail_label)?;
                }
            }

            // Struct pattern: Point { x, y } or Point { x: a, y: b }
            Pat::Struct(pat_struct) => {
                // Get struct name
                let struct_name = pat_struct.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");

                // Look up struct definition
                let struct_def = self.struct_defs.get(&struct_name)
                    .ok_or_else(|| CompileError(format!("Unknown struct in pattern: {}", struct_name)))?
                    .clone();

                // Check each field pattern
                for field_pat in &pat_struct.fields {
                    let field_name = field_pat.member.clone();
                    let field_name_str = match &field_name {
                        syn::Member::Named(ident) => ident.to_string(),
                        syn::Member::Unnamed(idx) => idx.index.to_string(),
                    };

                    // Get field offset
                    let offset = struct_def.get_field_offset(&field_name_str)
                        .ok_or_else(|| CompileError(format!("Unknown field in pattern: {}", field_name_str)))?;

                    // Load field value
                    self.emit_push_reg(scrutinee_reg);
                    if offset > 0 {
                        self.emit_constant(offset as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    // Store in temp register
                    let field_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(field_reg);

                    // Check field pattern
                    self.compile_pattern_check(&field_pat.pat, field_reg, fail_label)?;
                }
            }

            // Parenthesized pattern
            Pat::Paren(pat_paren) => {
                self.compile_pattern_check(&pat_paren.pat, scrutinee_reg, fail_label)?;
            }

            // Type ascription pattern: x: Type
            Pat::Type(pat_type) => {
                self.compile_pattern_check(&pat_type.pat, scrutinee_reg, fail_label)?;
            }

            // TupleStruct pattern: Point(x, y) or Some(value)
            Pat::TupleStruct(pat_tuple_struct) => {
                // Get struct name
                let struct_name = pat_tuple_struct.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");

                // Look up struct definition
                let struct_def = self.struct_defs.get(&struct_name)
                    .ok_or_else(|| CompileError(format!("Unknown tuple struct in pattern: {}", struct_name)))?
                    .clone();

                // Check each element pattern (like tuple but uses struct definition)
                for (i, elem_pat) in pat_tuple_struct.elems.iter().enumerate() {
                    // Get field offset (tuple structs use numeric field names)
                    let offset = struct_def.get_field_offset(&i.to_string())
                        .ok_or_else(|| CompileError(format!("Tuple struct {} has no field {}", struct_name, i)))?;

                    // Load element from heap
                    self.emit_push_reg(scrutinee_reg);
                    if offset > 0 {
                        self.emit_constant(offset as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    // Store in temp register for pattern check
                    let elem_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(elem_reg);

                    // Check element pattern
                    self.compile_pattern_check(elem_pat, elem_reg, fail_label)?;
                }
            }

            // Slice pattern: [first, .., last]
            Pat::Slice(pat_slice) => {
                // For arrays/slices, scrutinee_reg holds the heap address
                // We need to check each element pattern
                for (i, elem_pat) in pat_slice.elems.iter().enumerate() {
                    // Load element from heap
                    self.emit_push_reg(scrutinee_reg);
                    if i > 0 {
                        self.emit_constant((i * 8) as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    // Store in temp register
                    let elem_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(elem_reg);

                    // Check element pattern
                    self.compile_pattern_check(elem_pat, elem_reg, fail_label)?;
                }
            }

            // Reference pattern: &x, &mut x
            Pat::Reference(pat_ref) => {
                // For references, the scrutinee is already the dereferenced value
                // (our VM doesn't have true references, values are already by-value)
                // Just check the inner pattern
                self.compile_pattern_check(&pat_ref.pat, scrutinee_reg, fail_label)?;
            }

            // Rest pattern (..) - matches any remaining elements
            Pat::Rest(_) => {
                // Always matches - used in slice patterns like [first, .., last]
            }

            _ => {
                return Err(CompileError(format!("Unsupported pattern type: {:?}", pat)));
            }
        }
        Ok(())
    }

    /// Compile a single case in an or-pattern
    /// If matched, jumps to match_label. Otherwise falls through.
    fn compile_or_pattern_case(&mut self, pat: &Pat, scrutinee_reg: u8, match_label: &str) -> Result<(), CompileError> {
        match pat {
            Pat::Lit(pat_lit) => {
                self.emit_push_reg(scrutinee_reg);
                self.compile_literal(&pat_lit.lit)?;
                self.emit_cmp();
                self.emit_drop();
                self.emit_drop();
                // If equal (ZF=1), we have a match - jump with JZ
                self.emit_jump(control::JZ, match_label);
                // Otherwise fall through to try next case
            }
            Pat::Wild(_) | Pat::Ident(_) => {
                // These always match in or-patterns
                self.emit_jump(control::JMP, match_label);
            }
            Pat::Range(pat_range) => {
                // Range in or-pattern: check if in range, jump to match if yes
                let not_in_range = self.unique_label("or_range_no");

                // Check start bound
                if let Some(start) = &pat_range.start {
                    self.emit_push_reg(scrutinee_reg);
                    self.compile_expr(start)?;
                    self.emit_cmp();
                    self.emit_drop();
                    self.emit_drop();
                    self.emit_jump(control::JLT, &not_in_range);
                }

                // Check end bound
                if let Some(end) = &pat_range.end {
                    self.emit_push_reg(scrutinee_reg);
                    self.compile_expr(end)?;
                    self.emit_cmp();
                    self.emit_drop();
                    self.emit_drop();
                    match &pat_range.limits {
                        syn::RangeLimits::Closed(_) => {
                            self.emit_jump(control::JGT, &not_in_range);
                        }
                        syn::RangeLimits::HalfOpen(_) => {
                            self.emit_jump(control::JGE, &not_in_range);
                        }
                    }
                }

                // In range - match!
                self.emit_jump(control::JMP, match_label);
                self.mark_label(&not_in_range);
            }
            _ => {
                // For complex patterns, check and jump
                let temp_fail = self.unique_label("or_temp_fail");
                self.compile_pattern_check(pat, scrutinee_reg, &temp_fail)?;
                // If we get here, pattern matched
                self.emit_jump(control::JMP, match_label);
                self.mark_label(&temp_fail);
            }
        }
        Ok(())
    }

    /// Bind pattern variables to registers
    fn bind_pattern_vars(&mut self, pat: &Pat, scrutinee_reg: u8) -> Result<(), CompileError> {
        match pat {
            Pat::Wild(_) => {
                // No binding for wildcard
            }

            Pat::Ident(pat_ident) => {
                let name = pat_ident.ident.to_string();
                // Skip underscore-prefixed names (they're intentionally unused)
                if !name.starts_with('_') {
                    // Bind scrutinee value to variable
                    let reg = self.define_var(&name, VarType::Integer, false)?;
                    self.emit_push_reg(scrutinee_reg);
                    self.emit_pop_reg(reg);
                }
            }

            Pat::Lit(_) | Pat::Range(_) => {
                // No bindings for literal or range patterns
            }

            Pat::Or(pat_or) => {
                // For or-patterns, bind from the first case (all cases must bind same vars)
                if let Some(first) = pat_or.cases.first() {
                    self.bind_pattern_vars(first, scrutinee_reg)?;
                }
            }

            Pat::Tuple(pat_tuple) => {
                // Bind each element
                for (i, elem_pat) in pat_tuple.elems.iter().enumerate() {
                    // Load element from tuple
                    self.emit_push_reg(scrutinee_reg);
                    if i > 0 {
                        self.emit_constant((i * 8) as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    let elem_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(elem_reg);

                    // Bind element pattern vars
                    self.bind_pattern_vars(elem_pat, elem_reg)?;
                }
            }

            Pat::Struct(pat_struct) => {
                let struct_name = pat_struct.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");

                let struct_def = self.struct_defs.get(&struct_name)
                    .ok_or_else(|| CompileError(format!("Unknown struct: {}", struct_name)))?
                    .clone();

                for field_pat in &pat_struct.fields {
                    let field_name = match &field_pat.member {
                        syn::Member::Named(ident) => ident.to_string(),
                        syn::Member::Unnamed(idx) => idx.index.to_string(),
                    };

                    let offset = struct_def.get_field_offset(&field_name)
                        .ok_or_else(|| CompileError(format!("Unknown field: {}", field_name)))?;

                    // Load field value
                    self.emit_push_reg(scrutinee_reg);
                    if offset > 0 {
                        self.emit_constant(offset as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    let field_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(field_reg);

                    // Bind field pattern vars
                    self.bind_pattern_vars(&field_pat.pat, field_reg)?;
                }
            }

            Pat::Paren(pat_paren) => {
                self.bind_pattern_vars(&pat_paren.pat, scrutinee_reg)?;
            }

            Pat::Type(pat_type) => {
                self.bind_pattern_vars(&pat_type.pat, scrutinee_reg)?;
            }

            // TupleStruct pattern: Point(x, y)
            Pat::TupleStruct(pat_tuple_struct) => {
                let struct_name = pat_tuple_struct.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");

                let struct_def = self.struct_defs.get(&struct_name)
                    .ok_or_else(|| CompileError(format!("Unknown tuple struct: {}", struct_name)))?
                    .clone();

                for (i, elem_pat) in pat_tuple_struct.elems.iter().enumerate() {
                    let offset = struct_def.get_field_offset(&i.to_string())
                        .ok_or_else(|| CompileError(format!("Tuple struct {} has no field {}", struct_name, i)))?;

                    // Load element value
                    self.emit_push_reg(scrutinee_reg);
                    if offset > 0 {
                        self.emit_constant(offset as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    let elem_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(elem_reg);

                    // Bind element pattern vars
                    self.bind_pattern_vars(elem_pat, elem_reg)?;
                }
            }

            // Slice pattern binding: [a, b, c]
            Pat::Slice(pat_slice) => {
                for (i, elem_pat) in pat_slice.elems.iter().enumerate() {
                    // Skip rest patterns (..)
                    if matches!(elem_pat, Pat::Rest(_)) {
                        continue;
                    }

                    // Load element value
                    self.emit_push_reg(scrutinee_reg);
                    if i > 0 {
                        self.emit_constant((i * 8) as u64);
                        self.emit_add();
                    }
                    self.emit_heap_load64();

                    let elem_reg = self.next_local_reg;
                    self.next_local_reg += 1;
                    self.emit_pop_reg(elem_reg);

                    // Bind element pattern vars
                    self.bind_pattern_vars(elem_pat, elem_reg)?;
                }
            }

            // Reference pattern: &x
            Pat::Reference(pat_ref) => {
                self.bind_pattern_vars(&pat_ref.pat, scrutinee_reg)?;
            }

            // Rest pattern (..) - no binding needed
            Pat::Rest(_) => {}

            _ => {}
        }
        Ok(())
    }
}
