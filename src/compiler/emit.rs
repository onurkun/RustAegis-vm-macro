//! Bytecode Emission Helpers
//!
//! All emit_* functions for generating bytecode with optional obfuscation.

use super::Compiler;
use crate::opcodes::{stack, arithmetic, control, native, vector, string, heap, convert, special};
use crate::substitution::{
    IncSubstitution, NotSubstitution,
    AndSubstitution, OrSubstitution, ConstantSubstitution, ZeroSubstitution,
    AddSubstitution, SubSubstitution, DeadCodeInsertion,
    ControlFlowSubstitution,
};

impl Compiler {
    /// Emit an opcode (automatically encoded via shuffle table)
    pub(crate) fn emit_op(&mut self, base_opcode: u8) {
        // Dead Code Insertion
        if self.subst.is_enabled() {
            let table = self.opcode_table.clone();
            let encode = |op: u8| table.encode(op);
            DeadCodeInsertion::emit_deterministic(
                self.bytecode.len(),
                &mut self.bytecode,
                &encode,
            );
        }

        // Junk Code Insertion (10% chance for NOP)
        let entropy = (self.bytecode.len() as u64)
            .wrapping_mul(0x5deece66d)
            .wrapping_add(0xb);

        if (entropy % 100) < 10 {
            let nop_shuffled = self.opcode_table.encode(special::NOP);
            self.bytecode.push(nop_shuffled);
        }

        let shuffled = self.opcode_table.encode(base_opcode);
        self.bytecode.push(shuffled);
    }

    /// Emit a single byte
    pub(crate) fn emit(&mut self, byte: u8) {
        self.bytecode.push(byte);
    }

    /// Emit a u16 (little-endian)
    pub(crate) fn emit_u16(&mut self, value: u16) {
        self.bytecode.extend_from_slice(&value.to_le_bytes());
    }

    /// Emit jump with fixup
    pub(crate) fn emit_jump(&mut self, opcode: u8, label: &str) {
        // Opaque predicate injection (~15% chance)
        if self.opaque_predicates_enabled && self.should_inject_opaque() {
            let table = self.opcode_table.clone();
            let encode = |op: u8| table.encode(op);
            ControlFlowSubstitution::emit_fake_conditional(
                &mut self.subst,
                &mut self.bytecode,
                &encode,
            );
        }

        self.emit_op(opcode);
        let fixup_pos = self.pos();
        self.emit_u16(0); // Placeholder
        self.fixups.push((fixup_pos, label.to_string()));
    }

    /// Deterministic check for opaque predicate injection
    fn should_inject_opaque(&self) -> bool {
        let entropy = (self.bytecode.len() as u64)
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(0xC6A4A7935BD1E995);
        (entropy % 100) < 15
    }

    // =========================================================================
    // Arithmetic Operations (with MBA/Substitution)
    // =========================================================================

    /// Emit ADD instruction
    pub(crate) fn emit_add(&mut self) {
        if self.mba_enabled {
            let table = self.opcode_table.clone();
            self.mba.emit_add(&mut self.bytecode, |op| table.encode(op));
        } else {
            let table = self.opcode_table.clone();
            let encode = |op: u8| table.encode(op);
            let variant = AddSubstitution::choose(&mut self.subst);
            variant.emit(&mut self.bytecode, &encode);
        }
    }

    /// Emit SUB instruction
    pub(crate) fn emit_sub(&mut self) {
        if self.mba_enabled {
            let table = self.opcode_table.clone();
            self.mba.emit_sub(&mut self.bytecode, |op| table.encode(op));
        } else {
            let table = self.opcode_table.clone();
            let encode = |op: u8| table.encode(op);
            let variant = SubSubstitution::choose(&mut self.subst);
            variant.emit(&mut self.bytecode, &encode);
        }
    }

    /// Emit MUL instruction
    pub(crate) fn emit_mul(&mut self) {
        self.emit_op(arithmetic::MUL);
    }

    /// Emit DIV instruction
    pub(crate) fn emit_div(&mut self) {
        self.emit_op(arithmetic::DIV);
    }

    /// Emit MOD instruction
    pub(crate) fn emit_mod(&mut self) {
        self.emit_op(arithmetic::MOD);
    }

    /// Emit IDIV instruction (signed)
    pub(crate) fn emit_idiv(&mut self) {
        self.emit_op(arithmetic::IDIV);
    }

    /// Emit IMOD instruction (signed)
    pub(crate) fn emit_imod(&mut self) {
        self.emit_op(arithmetic::IMOD);
    }

    /// Emit XOR instruction
    pub(crate) fn emit_xor(&mut self) {
        if self.mba_enabled {
            let table = self.opcode_table.clone();
            self.mba.emit_xor(&mut self.bytecode, |op| table.encode(op));
        } else {
            self.emit_op(arithmetic::XOR);
        }
    }

    /// Emit AND instruction
    pub(crate) fn emit_and(&mut self) {
        let table = self.opcode_table.clone();
        let encode = |op: u8| table.encode(op);
        if AndSubstitution::should_use(&mut self.subst) {
            // De Morgan: a & b = ~(~a | ~b)
            AndSubstitution::emit_demorgan_prefix(&mut self.bytecode, &encode);
            self.emit_not();
            AndSubstitution::emit_demorgan_swap(&mut self.bytecode, &encode);
            self.emit_not();
            AndSubstitution::emit_demorgan_or(&mut self.bytecode, &encode);
            self.emit_not();
        } else {
            AndSubstitution::emit_original(&mut self.bytecode, &encode);
        }
    }

    /// Emit OR instruction
    pub(crate) fn emit_or(&mut self) {
        let table = self.opcode_table.clone();
        let encode = |op: u8| table.encode(op);
        if OrSubstitution::should_use(&mut self.subst) {
            // De Morgan: a | b = ~(~a & ~b)
            OrSubstitution::emit_demorgan_prefix(&mut self.bytecode, &encode);
            self.emit_not();
            OrSubstitution::emit_demorgan_swap(&mut self.bytecode, &encode);
            self.emit_not();
            OrSubstitution::emit_demorgan_and(&mut self.bytecode, &encode);
            self.emit_not();
        } else {
            OrSubstitution::emit_original(&mut self.bytecode, &encode);
        }
    }

    /// Emit NOT instruction
    pub(crate) fn emit_not(&mut self) {
        let table = self.opcode_table.clone();
        let encode = |op: u8| table.encode(op);
        let variant = NotSubstitution::choose(&mut self.subst);
        let needs_xor = variant.emit(&mut self.bytecode, &encode);
        if needs_xor {
            self.emit_xor();
        }
    }

    /// Emit SHL instruction
    pub(crate) fn emit_shl(&mut self) {
        self.emit_op(arithmetic::SHL);
    }

    /// Emit SHR instruction
    pub(crate) fn emit_shr(&mut self) {
        self.emit_op(arithmetic::SHR);
    }

    /// Emit ROL instruction
    pub(crate) fn emit_rol(&mut self) {
        self.emit_op(arithmetic::ROL);
    }

    /// Emit ROR instruction
    pub(crate) fn emit_ror(&mut self) {
        self.emit_op(arithmetic::ROR);
    }

    /// Emit INC instruction
    pub(crate) fn emit_inc(&mut self) {
        let table = self.opcode_table.clone();
        let encode = |op: u8| table.encode(op);
        let variant = IncSubstitution::choose(&mut self.subst);
        let (needs_add, needs_sub) = variant.emit(&mut self.bytecode, &encode);
        if needs_add {
            self.emit_add();
        } else if needs_sub {
            self.emit_sub();
        }
    }

    // =========================================================================
    // Constants and Zero
    // =========================================================================

    /// Emit a constant value with potential obfuscation
    pub(crate) fn emit_constant(&mut self, value: u64) {
        let table = self.opcode_table.clone();
        let encode = |op: u8| table.encode(op);

        if self.value_cryptor_enabled {
            self.value_cryptor.emit_encrypted_value(value, &mut self.bytecode, &encode);
        } else if ConstantSubstitution::should_split(&mut self.subst, value) {
            let (a, b) = ConstantSubstitution::split(&mut self.subst, value);
            ConstantSubstitution::emit_value(&mut self.bytecode, a, &encode);
            ConstantSubstitution::emit_value(&mut self.bytecode, b, &encode);
            self.emit_add();
        } else {
            ConstantSubstitution::emit_value(&mut self.bytecode, value, &encode);
        }
    }

    /// Emit zero with potential obfuscation
    pub(crate) fn emit_zero(&mut self) {
        let table = self.opcode_table.clone();
        let encode = |op: u8| table.encode(op);
        if ZeroSubstitution::should_obfuscate(&mut self.subst) {
            let x = ZeroSubstitution::get_xor_value(&mut self.subst);
            ZeroSubstitution::emit_prefix(&mut self.bytecode, x, &encode);
            self.emit_xor();
        } else {
            ZeroSubstitution::emit_original(&mut self.bytecode, &encode);
        }
    }

    // =========================================================================
    // Type Conversions
    // =========================================================================

    /// Sign-extend 8-bit to 64-bit
    pub(crate) fn emit_sext8(&mut self) {
        self.emit_op(convert::SEXT8);
    }

    /// Sign-extend 16-bit to 64-bit
    pub(crate) fn emit_sext16(&mut self) {
        self.emit_op(convert::SEXT16);
    }

    /// Sign-extend 32-bit to 64-bit
    pub(crate) fn emit_sext32(&mut self) {
        self.emit_op(convert::SEXT32);
    }

    /// Truncate to 8-bit
    pub(crate) fn emit_trunc8(&mut self) {
        self.emit_op(convert::TRUNC8);
    }

    /// Truncate to 16-bit
    pub(crate) fn emit_trunc16(&mut self) {
        self.emit_op(convert::TRUNC16);
    }

    /// Truncate to 32-bit
    pub(crate) fn emit_trunc32(&mut self) {
        self.emit_op(convert::TRUNC32);
    }

    // =========================================================================
    // Stack Operations
    // =========================================================================

    /// Emit DUP instruction
    pub(crate) fn emit_dup(&mut self) {
        self.emit_op(stack::DUP);
    }

    /// Emit DROP instruction
    pub(crate) fn emit_drop(&mut self) {
        self.emit_op(stack::DROP);
    }

    /// Emit SWAP instruction
    pub(crate) fn emit_swap(&mut self) {
        self.emit_op(stack::SWAP);
    }

    /// Emit PUSH_REG instruction
    pub(crate) fn emit_push_reg(&mut self, reg: u8) {
        self.emit_op(stack::PUSH_REG);
        self.emit(reg);
    }

    /// Emit POP_REG instruction
    pub(crate) fn emit_pop_reg(&mut self, reg: u8) {
        self.emit_op(stack::POP_REG);
        self.emit(reg);
    }

    // =========================================================================
    // Vector Operations
    // =========================================================================

    /// Emit VEC_NEW: Stack: [capacity, elem_size] -> [vec_addr]
    pub(crate) fn emit_vec_new(&mut self) {
        self.emit_op(vector::VEC_NEW);
    }

    /// Emit VEC_LEN: Stack: [vec_addr] -> [length]
    pub(crate) fn emit_vec_len(&mut self) {
        self.emit_op(vector::VEC_LEN);
    }

    /// Emit VEC_CAP: Stack: [vec_addr] -> [capacity]
    pub(crate) fn emit_vec_cap(&mut self) {
        self.emit_op(vector::VEC_CAP);
    }

    /// Emit VEC_PUSH: Stack: [vec_addr, value] -> []
    pub(crate) fn emit_vec_push(&mut self) {
        self.emit_op(vector::VEC_PUSH);
    }

    /// Emit VEC_POP: Stack: [vec_addr] -> [value]
    pub(crate) fn emit_vec_pop(&mut self) {
        self.emit_op(vector::VEC_POP);
    }

    /// Emit VEC_GET: Stack: [vec_addr, index] -> [value]
    pub(crate) fn emit_vec_get(&mut self) {
        self.emit_op(vector::VEC_GET);
    }

    /// Emit VEC_SET: Stack: [vec_addr, index, value] -> []
    pub(crate) fn emit_vec_set(&mut self) {
        self.emit_op(vector::VEC_SET);
    }

    /// Emit VEC_REPEAT: Stack: [value, count, elem_size] -> [vec_addr]
    pub(crate) fn emit_vec_repeat(&mut self) {
        self.emit_op(vector::VEC_REPEAT);
    }

    /// Emit VEC_CLEAR: Stack: [vec_addr] -> []
    pub(crate) fn emit_vec_clear(&mut self) {
        self.emit_op(vector::VEC_CLEAR);
    }

    /// Emit VEC_RESERVE: Stack: [vec_addr, additional] -> []
    pub(crate) fn emit_vec_reserve(&mut self) {
        self.emit_op(vector::VEC_RESERVE);
    }

    // =========================================================================
    // String Operations
    // =========================================================================

    /// Emit STR_NEW: Stack: [capacity] -> [str_addr]
    pub(crate) fn emit_str_new(&mut self) {
        self.emit_op(string::STR_NEW);
    }

    /// Emit STR_LEN: Stack: [str_addr] -> [length]
    pub(crate) fn emit_str_len(&mut self) {
        self.emit_op(string::STR_LEN);
    }

    /// Emit STR_PUSH: Stack: [str_addr, byte] -> []
    pub(crate) fn emit_str_push(&mut self) {
        self.emit_op(string::STR_PUSH);
    }

    /// Emit STR_GET: Stack: [str_addr, index] -> [byte]
    pub(crate) fn emit_str_get(&mut self) {
        self.emit_op(string::STR_GET);
    }

    /// Emit STR_SET: Stack: [str_addr, index, byte] -> []
    pub(crate) fn emit_str_set(&mut self) {
        self.emit_op(string::STR_SET);
    }

    /// Emit STR_CMP: Stack: [str1_addr, str2_addr] -> [result]
    pub(crate) fn emit_str_cmp(&mut self) {
        self.emit_op(string::STR_CMP);
    }

    /// Emit STR_EQ: Stack: [str1_addr, str2_addr] -> [0/1]
    pub(crate) fn emit_str_eq(&mut self) {
        self.emit_op(string::STR_EQ);
    }

    /// Emit STR_HASH: Stack: [str_addr] -> [hash]
    pub(crate) fn emit_str_hash(&mut self) {
        self.emit_op(string::STR_HASH);
    }

    /// Emit STR_CONCAT: Stack: [str1_addr, str2_addr] -> [new_str_addr]
    pub(crate) fn emit_str_concat(&mut self) {
        self.emit_op(string::STR_CONCAT);
    }

    // =========================================================================
    // Heap Operations
    // =========================================================================

    /// Emit HEAP_ALLOC: Stack: [size] -> [address]
    pub(crate) fn emit_heap_alloc(&mut self) {
        self.emit_op(heap::HEAP_ALLOC);
    }

    /// Emit HEAP_FREE: Stack: [address] -> []
    pub(crate) fn emit_heap_free(&mut self) {
        self.emit_op(heap::HEAP_FREE);
    }

    /// Emit HEAP_LOAD64: Stack: [address] -> [value]
    pub(crate) fn emit_heap_load64(&mut self) {
        self.emit_op(heap::HEAP_LOAD64);
    }

    /// Emit HEAP_STORE64: Stack: [address, value] -> []
    pub(crate) fn emit_heap_store64(&mut self) {
        self.emit_op(heap::HEAP_STORE64);
    }

    // =========================================================================
    // Native Operations
    // =========================================================================

    /// Emit NATIVE_READ: Read from input buffer
    pub(crate) fn emit_native_read(&mut self, offset: u16) {
        self.emit_op(native::NATIVE_READ);
        self.emit_u16(offset);
    }

    // =========================================================================
    // Control Flow
    // =========================================================================

    /// Emit CMP instruction
    pub(crate) fn emit_cmp(&mut self) {
        self.emit_op(control::CMP);
    }
}
