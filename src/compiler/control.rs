//! Control Flow Compilation
//!
//! Handles: if/else, while, loop, for, break, continue

use syn::{Expr, Block};
use super::{Compiler, CompileError, LoopContext};
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

        // Push loop context for break/continue
        self.loop_stack.push(LoopContext {
            continue_label: loop_start.clone(),
            break_label: loop_end.clone(),
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

        // Push loop context
        self.loop_stack.push(LoopContext {
            continue_label: loop_start.clone(),
            break_label: loop_end.clone(),
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
        self.loop_stack.push(LoopContext {
            continue_label: loop_continue.clone(),
            break_label: loop_end.clone(),
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

        self.emit_jump(control::JMP, &ctx.break_label.clone());
        Ok(())
    }

    /// Compile continue statement
    pub(crate) fn compile_continue(&mut self) -> Result<(), CompileError> {
        let ctx = self.loop_stack.last()
            .ok_or_else(|| CompileError("continue outside of loop".to_string()))?;

        self.emit_jump(control::JMP, &ctx.continue_label.clone());
        Ok(())
    }

    /// Compile a block as statements (for loop bodies)
    /// Unlike compile_block, this drops ALL expression results
    pub(crate) fn compile_block_stmt(&mut self, block: &Block) -> Result<(), CompileError> {
        // Push new scope for this block
        self.push_scope();

        for stmt in &block.stmts {
            match stmt {
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
}
