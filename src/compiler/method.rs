//! Method Call Compilation
//!
//! Handles method calls like .len(), .push(), .pop(), .clear(), etc.
//! Works for both arrays (Vec) and strings.

use syn::{Expr, ExprMethodCall};
use super::{Compiler, CompileError, VarLocation};

impl Compiler {
    /// Compile a method call expression
    /// Supports: .len(), .push(), .pop(), .get(), .clear(), .capacity(), .is_empty()
    ///           .concat() for strings, .reserve() for vectors
    pub(crate) fn compile_method_call(&mut self, method_call: &ExprMethodCall) -> Result<(), CompileError> {
        let method_name = method_call.method.to_string();
        let receiver = &method_call.receiver;
        let args = &method_call.args;

        match method_name.as_str() {
            // =========================================================
            // Common methods for both Vec and String
            // =========================================================

            "len" => {
                // receiver.len() -> length
                self.compile_expr(receiver)?;

                // Detect type from receiver
                if self.is_string_receiver(receiver) {
                    self.emit_str_len();
                } else {
                    self.emit_vec_len();
                }
            }

            "capacity" => {
                // receiver.capacity() -> capacity
                self.compile_expr(receiver)?;
                self.emit_vec_cap();
            }

            "is_empty" => {
                // receiver.is_empty() -> len == 0
                self.compile_expr(receiver)?;

                if self.is_string_receiver(receiver) {
                    self.emit_str_len();
                } else {
                    self.emit_vec_len();
                }

                // Check if length is 0
                self.emit_zero();
                self.emit_xor();  // len ^ 0 = len, sets ZF if len == 0

                // Convert to boolean: 1 if zero, 0 otherwise
                let else_label = self.unique_label("is_empty_else");
                let end_label = self.unique_label("is_empty_end");
                self.emit_jump(crate::opcodes::control::JNZ, &else_label);
                self.emit_constant(1);  // Empty: true
                self.emit_jump(crate::opcodes::control::JMP, &end_label);
                self.mark_label(&else_label);
                self.emit_zero();       // Not empty: false
                self.mark_label(&end_label);
            }

            "clear" => {
                // receiver.clear() - sets length to 0
                self.compile_expr(receiver)?;
                self.emit_vec_clear();
                // clear returns (), push 0
                self.emit_zero();
            }

            "reserve" => {
                // receiver.reserve(additional)
                if args.len() != 1 {
                    return Err(CompileError("reserve() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_vec_reserve();
                self.emit_zero();  // Returns ()
            }

            // =========================================================
            // Vec-specific methods
            // =========================================================

            "push" => {
                // receiver.push(value)
                if args.len() != 1 {
                    return Err(CompileError("push() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;

                if self.is_string_receiver(receiver) {
                    self.emit_str_push();
                } else {
                    self.emit_vec_push();
                }
                self.emit_zero();  // Returns ()
            }

            "pop" => {
                // receiver.pop() -> Option<T> (we return value or 0)
                self.compile_expr(receiver)?;

                if self.is_string_receiver(receiver) {
                    // String doesn't have pop in our VM, error
                    return Err(CompileError("pop() not supported for strings".to_string()));
                }

                self.emit_vec_pop();
            }

            "get" => {
                // receiver.get(index) -> Option<&T> (we return value)
                if args.len() != 1 {
                    return Err(CompileError("get() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;

                if self.is_string_receiver(receiver) {
                    self.emit_str_get();
                } else {
                    self.emit_vec_get();
                }
            }

            // =========================================================
            // String-specific methods
            // =========================================================

            "as_bytes" => {
                // String.as_bytes() - returns the string itself (it's already bytes)
                self.compile_expr(receiver)?;
            }

            "chars" => {
                // String.chars() - not fully supported, returns string address
                // Would need iterator support for full implementation
                self.compile_expr(receiver)?;
            }

            "concat" => {
                // str1.concat(str2) -> new string
                if args.len() != 1 {
                    return Err(CompileError("concat() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_str_concat();
            }

            "eq" | "equals" => {
                // str1.eq(str2) -> bool
                if args.len() != 1 {
                    return Err(CompileError("eq() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_str_eq();
            }

            "cmp" | "compare" => {
                // str1.cmp(str2) -> ordering (-1, 0, 1)
                if args.len() != 1 {
                    return Err(CompileError("cmp() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_str_cmp();
            }

            "hash" => {
                // string.hash() -> u64 hash
                self.compile_expr(receiver)?;
                self.emit_str_hash();
            }

            "bytes" => {
                // string.bytes() - returns string address (same as as_bytes)
                self.compile_expr(receiver)?;
            }

            // =========================================================
            // Numeric methods
            // =========================================================

            "abs" => {
                // value.abs() - absolute value
                // For signed: if negative, negate
                self.compile_expr(receiver)?;
                self.emit_dup();
                // Check sign bit (shift right 63 bits)
                self.emit_constant(63);
                self.emit_shr();
                // If sign bit is 1, negate
                let positive_label = self.unique_label("abs_positive");
                let end_label = self.unique_label("abs_end");
                self.emit_jump(crate::opcodes::control::JZ, &positive_label);
                // Negative: negate (0 - value)
                self.emit_zero();
                self.emit_swap();
                self.emit_sub();
                self.emit_jump(crate::opcodes::control::JMP, &end_label);
                self.mark_label(&positive_label);
                // Positive: keep as is (drop the duplicate)
                self.mark_label(&end_label);
            }

            "min" => {
                // a.min(b) -> smaller value
                if args.len() != 1 {
                    return Err(CompileError("min() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;  // [a]
                self.compile_expr(&args[0])?;  // [a, b]

                // Save both values in registers
                self.emit_pop_reg(250);        // [a], R250=b
                self.emit_pop_reg(251);        // [], R251=a

                // Compare a and b
                self.emit_push_reg(251);       // [a]
                self.emit_push_reg(250);       // [a, b]
                self.emit_cmp();               // Compare, sets flags
                self.emit_drop();              // [a]
                self.emit_drop();              // []

                let use_b_label = self.unique_label("min_use_b");
                let end_label = self.unique_label("min_end");

                // JGT: if a > b, use b
                self.emit_jump(crate::opcodes::control::JGT, &use_b_label);
                // a <= b, use a
                self.emit_push_reg(251);
                self.emit_jump(crate::opcodes::control::JMP, &end_label);
                self.mark_label(&use_b_label);
                // a > b, use b
                self.emit_push_reg(250);
                self.mark_label(&end_label);
            }

            "max" => {
                // a.max(b) -> larger value
                if args.len() != 1 {
                    return Err(CompileError("max() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;  // [a]
                self.compile_expr(&args[0])?;  // [a, b]

                // Save both values in registers
                self.emit_pop_reg(250);        // [a], R250=b
                self.emit_pop_reg(251);        // [], R251=a

                // Compare a and b
                self.emit_push_reg(251);       // [a]
                self.emit_push_reg(250);       // [a, b]
                self.emit_cmp();               // Compare, sets flags
                self.emit_drop();              // [a]
                self.emit_drop();              // []

                let use_b_label = self.unique_label("max_use_b");
                let end_label = self.unique_label("max_end");

                // JLT: if a < b, use b
                self.emit_jump(crate::opcodes::control::JLT, &use_b_label);
                // a >= b, use a
                self.emit_push_reg(251);
                self.emit_jump(crate::opcodes::control::JMP, &end_label);
                self.mark_label(&use_b_label);
                // a < b, use b
                self.emit_push_reg(250);
                self.mark_label(&end_label);
            }

            "wrapping_add" => {
                if args.len() != 1 {
                    return Err(CompileError("wrapping_add() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_add();  // VM ADD already wraps
            }

            "wrapping_sub" => {
                if args.len() != 1 {
                    return Err(CompileError("wrapping_sub() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_sub();  // VM SUB already wraps
            }

            "wrapping_mul" => {
                if args.len() != 1 {
                    return Err(CompileError("wrapping_mul() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_mul();  // VM MUL already wraps
            }

            "rotate_left" => {
                if args.len() != 1 {
                    return Err(CompileError("rotate_left() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_rol();
            }

            "rotate_right" => {
                if args.len() != 1 {
                    return Err(CompileError("rotate_right() takes exactly 1 argument".to_string()));
                }
                self.compile_expr(receiver)?;
                self.compile_expr(&args[0])?;
                self.emit_ror();
            }

            "count_ones" => {
                // Popcount implementation using parallel bit counting
                self.compile_expr(receiver)?;
                self.compile_count_ones()?;
            }

            "count_zeros" => {
                // 64 - count_ones
                self.compile_expr(receiver)?;
                self.compile_count_ones()?;
                // 64 - result
                self.emit_constant(64);
                self.emit_swap();
                self.emit_sub();
            }

            "leading_zeros" => {
                // Count leading zeros using binary search
                self.compile_expr(receiver)?;
                self.compile_leading_zeros()?;
            }

            "trailing_zeros" => {
                // Count trailing zeros
                self.compile_expr(receiver)?;
                self.compile_trailing_zeros()?;
            }

            _ => {
                // =========================================================
                // Unknown method: treat as native call
                // Compile receiver and args, register call, emit NATIVE_CALL
                // =========================================================

                // 1. Compile receiver (will be passed as first argument)
                self.compile_expr(receiver)?;

                // 2. Compile all arguments
                for arg in args {
                    self.compile_expr(arg)?;
                }

                // 3. Register this method call and get its index
                let index = self.native_collector.register_method(method_call)?;

                // 4. Emit NATIVE_CALL opcode
                if index > 255 {
                    return Err(CompileError("Too many native calls (max 256)".to_string()));
                }

                // arg_count = receiver + args
                let arg_count = args.len() + 1;
                if arg_count > 255 {
                    return Err(CompileError("Too many arguments for native call (max 255)".to_string()));
                }

                self.emit_native_call(index as u8, arg_count as u8);
            }
        }

        Ok(())
    }

    /// Check if the receiver expression is likely a string type
    fn is_string_receiver(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Lit(lit) => {
                matches!(&lit.lit, syn::Lit::Str(_) | syn::Lit::ByteStr(_))
            }
            Expr::Path(path) => {
                if path.path.segments.len() == 1 {
                    let name = path.path.segments[0].ident.to_string();
                    // Check if variable is registered as a string
                    matches!(self.var_types.get(&name), Some(VarLocation::String(_)))
                } else {
                    false
                }
            }
            Expr::MethodCall(mc) => {
                // Check if method returns a string
                let method = mc.method.to_string();
                matches!(method.as_str(), "concat" | "to_string" | "to_uppercase" | "to_lowercase")
            }
            _ => false
        }
    }

    /// Compile count_ones (popcount) - counts number of 1 bits
    /// Uses parallel bit counting algorithm
    fn compile_count_ones(&mut self) -> Result<(), CompileError> {
        // Value is on stack
        // Use register to accumulate count
        let count_reg = 249;
        let value_reg = 248;

        // Save value to register
        self.emit_pop_reg(value_reg);

        // Initialize count to 0
        self.emit_zero();
        self.emit_pop_reg(count_reg);

        // Loop: while value != 0
        let loop_start = self.unique_label("popcount_loop");
        let loop_end = self.unique_label("popcount_end");

        self.mark_label(&loop_start);

        // Check if value is 0
        self.emit_push_reg(value_reg);
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();
        self.emit_drop();
        self.emit_jump(crate::opcodes::control::JZ, &loop_end);

        // count += value & 1
        self.emit_push_reg(value_reg);
        self.emit_constant(1);
        self.emit_and();
        self.emit_push_reg(count_reg);
        self.emit_add();
        self.emit_pop_reg(count_reg);

        // value >>= 1
        self.emit_push_reg(value_reg);
        self.emit_constant(1);
        self.emit_shr();
        self.emit_pop_reg(value_reg);

        self.emit_jump(crate::opcodes::control::JMP, &loop_start);

        self.mark_label(&loop_end);

        // Push result
        self.emit_push_reg(count_reg);

        Ok(())
    }

    /// Compile leading_zeros - counts leading zero bits
    fn compile_leading_zeros(&mut self) -> Result<(), CompileError> {
        let count_reg = 249;
        let value_reg = 248;

        // Save value
        self.emit_pop_reg(value_reg);

        // If value is 0, return 64
        self.emit_push_reg(value_reg);
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();
        self.emit_drop();

        let not_zero = self.unique_label("clz_not_zero");
        let end_label = self.unique_label("clz_end");

        self.emit_jump(crate::opcodes::control::JNZ, &not_zero);
        self.emit_constant(64);
        self.emit_jump(crate::opcodes::control::JMP, &end_label);

        self.mark_label(&not_zero);

        // Initialize count = 0
        self.emit_zero();
        self.emit_pop_reg(count_reg);

        // Loop: check bit 63-count, if 0 increment count
        let loop_start = self.unique_label("clz_loop");
        let loop_end = self.unique_label("clz_loop_end");

        self.mark_label(&loop_start);

        // Check if count >= 64 (safety)
        self.emit_push_reg(count_reg);
        self.emit_constant(64);
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();
        self.emit_jump(crate::opcodes::control::JGE, &loop_end);

        // Check bit (63 - count): value >> (63 - count) & 1
        self.emit_push_reg(value_reg);
        self.emit_constant(63);
        self.emit_push_reg(count_reg);
        self.emit_sub();
        self.emit_shr();
        self.emit_constant(1);
        self.emit_and();

        // If bit is 1, we're done
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();
        self.emit_drop();
        self.emit_jump(crate::opcodes::control::JNZ, &loop_end);

        // Increment count
        self.emit_push_reg(count_reg);
        self.emit_inc();
        self.emit_pop_reg(count_reg);

        self.emit_jump(crate::opcodes::control::JMP, &loop_start);

        self.mark_label(&loop_end);

        // Push result
        self.emit_push_reg(count_reg);

        self.mark_label(&end_label);

        Ok(())
    }

    /// Compile trailing_zeros - counts trailing zero bits
    fn compile_trailing_zeros(&mut self) -> Result<(), CompileError> {
        let count_reg = 249;
        let value_reg = 248;

        // Save value
        self.emit_pop_reg(value_reg);

        // If value is 0, return 64
        self.emit_push_reg(value_reg);
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();
        self.emit_drop();

        let not_zero = self.unique_label("ctz_not_zero");
        let end_label = self.unique_label("ctz_end");

        self.emit_jump(crate::opcodes::control::JNZ, &not_zero);
        self.emit_constant(64);
        self.emit_jump(crate::opcodes::control::JMP, &end_label);

        self.mark_label(&not_zero);

        // Initialize count = 0
        self.emit_zero();
        self.emit_pop_reg(count_reg);

        // Loop: check bit at position count
        let loop_start = self.unique_label("ctz_loop");
        let loop_end = self.unique_label("ctz_loop_end");

        self.mark_label(&loop_start);

        // Check if count >= 64 (safety)
        self.emit_push_reg(count_reg);
        self.emit_constant(64);
        self.emit_cmp();
        self.emit_drop();
        self.emit_drop();
        self.emit_jump(crate::opcodes::control::JGE, &loop_end);

        // Check bit at position count: (value >> count) & 1
        self.emit_push_reg(value_reg);
        self.emit_push_reg(count_reg);
        self.emit_shr();
        self.emit_constant(1);
        self.emit_and();

        // If bit is 1, we're done
        self.emit_dup();
        self.emit_zero();
        self.emit_xor();
        self.emit_drop();
        self.emit_drop();
        self.emit_jump(crate::opcodes::control::JNZ, &loop_end);

        // Increment count
        self.emit_push_reg(count_reg);
        self.emit_inc();
        self.emit_pop_reg(count_reg);

        self.emit_jump(crate::opcodes::control::JMP, &loop_start);

        self.mark_label(&loop_end);

        // Push result
        self.emit_push_reg(count_reg);

        self.mark_label(&end_label);

        Ok(())
    }
}
