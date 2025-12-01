//! Opcode constants for bytecode generation
//!
//! These must match the opcodes in anticheat-vm exactly.

#![allow(dead_code)]

/// Stack Operations
pub mod stack {
    pub const PUSH_IMM: u8 = 0x01;
    pub const PUSH_IMM8: u8 = 0x02;
    pub const PUSH_REG: u8 = 0x03;
    pub const POP_REG: u8 = 0x04;
    pub const DUP: u8 = 0x05;
    pub const SWAP: u8 = 0x06;
    pub const DROP: u8 = 0x07;
    pub const PUSH_IMM16: u8 = 0x08;
    pub const PUSH_IMM32: u8 = 0x09;
}

/// Register Operations (R0-R255)
pub mod register {
    pub const MOV_IMM: u8 = 0x10;
    pub const MOV_REG: u8 = 0x11;
    pub const LOAD_MEM: u8 = 0x12;
    pub const STORE_MEM: u8 = 0x13;
}

/// Arithmetic Operations
pub mod arithmetic {
    pub const ADD: u8 = 0x20;
    pub const SUB: u8 = 0x21;
    pub const MUL: u8 = 0x22;
    pub const XOR: u8 = 0x23;
    pub const AND: u8 = 0x24;
    pub const OR: u8 = 0x25;
    pub const SHL: u8 = 0x26;
    pub const SHR: u8 = 0x27;
    pub const NOT: u8 = 0x28;
    pub const ROL: u8 = 0x29;
    pub const ROR: u8 = 0x2A;
    pub const INC: u8 = 0x2B;
    pub const DEC: u8 = 0x2C;
    pub const DIV: u8 = 0x46;
    pub const MOD: u8 = 0x47;
    pub const IDIV: u8 = 0x48;
    pub const IMOD: u8 = 0x49;
}

/// Comparison & Control Flow
pub mod control {
    pub const CMP: u8 = 0x30;
    pub const JMP: u8 = 0x31;
    pub const JZ: u8 = 0x32;
    pub const JNZ: u8 = 0x33;
    pub const JGT: u8 = 0x34;
    pub const JLT: u8 = 0x35;
    pub const JGE: u8 = 0x36;
    pub const JLE: u8 = 0x37;
    pub const CALL: u8 = 0x38;
    pub const RET: u8 = 0x39;
}

/// Special Operations
pub mod special {
    pub const NOP: u8 = 0x40;
    pub const NOP_N: u8 = 0x41;
    pub const OPAQUE_TRUE: u8 = 0x42;
    pub const OPAQUE_FALSE: u8 = 0x43;
    pub const HASH_CHECK: u8 = 0x44;
    pub const TIMING_CHECK: u8 = 0x45;
}

/// Type Conversion Operations
pub mod convert {
    pub const SEXT8: u8 = 0x50;
    pub const SEXT16: u8 = 0x51;
    pub const SEXT32: u8 = 0x52;
    pub const TRUNC8: u8 = 0x53;
    pub const TRUNC16: u8 = 0x54;
    pub const TRUNC32: u8 = 0x55;
}

/// Memory Operations (sized loads/stores)
pub mod memory {
    pub const LOAD8: u8 = 0x60;
    pub const LOAD16: u8 = 0x61;
    pub const LOAD32: u8 = 0x62;
    pub const LOAD64: u8 = 0x63;
    pub const STORE8: u8 = 0x64;
    pub const STORE16: u8 = 0x65;
    pub const STORE32: u8 = 0x66;
    pub const STORE64: u8 = 0x67;
}

/// Vector Operations (Dynamic Arrays)
/// Supports [expr.array.array], [expr.array.repeat], [expr.array.index.array]
pub mod vector {
    /// Create new vector: [capacity, elem_size] -> [vec_addr]
    pub const VEC_NEW: u8 = 0x80;
    /// Get length: [vec_addr] -> [len]
    pub const VEC_LEN: u8 = 0x81;
    /// Get capacity: [vec_addr] -> [capacity]
    pub const VEC_CAP: u8 = 0x82;
    /// Push element: [vec_addr, value] -> []
    pub const VEC_PUSH: u8 = 0x83;
    /// Pop element: [vec_addr] -> [value]
    pub const VEC_POP: u8 = 0x84;
    /// Get element (arr[i]): [vec_addr, index] -> [value]
    pub const VEC_GET: u8 = 0x85;
    /// Set element (arr[i] = x): [vec_addr, index, value] -> []
    pub const VEC_SET: u8 = 0x86;
    /// Create with repeat ([val; N]): [value, count, elem_size] -> [vec_addr]
    pub const VEC_REPEAT: u8 = 0x87;
    /// Clear vector: [vec_addr] -> []
    pub const VEC_CLEAR: u8 = 0x88;
    /// Reserve capacity: [vec_addr, additional] -> []
    pub const VEC_RESERVE: u8 = 0x89;
}

/// Heap Operations (Dynamic Memory)
pub mod heap {
    /// Allocate memory: [size] -> [address]
    pub const HEAP_ALLOC: u8 = 0x70;
    /// Free memory: [address] -> []
    pub const HEAP_FREE: u8 = 0x71;
    /// Load u8: [address] -> [value]
    pub const HEAP_LOAD8: u8 = 0x72;
    /// Load u16: [address] -> [value]
    pub const HEAP_LOAD16: u8 = 0x73;
    /// Load u32: [address] -> [value]
    pub const HEAP_LOAD32: u8 = 0x74;
    /// Load u64: [address] -> [value]
    pub const HEAP_LOAD64: u8 = 0x75;
    /// Store u8: [address, value] -> []
    pub const HEAP_STORE8: u8 = 0x76;
    /// Store u16: [address, value] -> []
    pub const HEAP_STORE16: u8 = 0x77;
    /// Store u32: [address, value] -> []
    pub const HEAP_STORE32: u8 = 0x78;
    /// Store u64: [address, value] -> []
    pub const HEAP_STORE64: u8 = 0x79;
    /// Get heap size: [] -> [size]
    pub const HEAP_SIZE: u8 = 0x7A;
}

/// String Operations
pub mod string {
    /// Create new string: [capacity] -> [str_addr]
    pub const STR_NEW: u8 = 0x90;
    /// Get length: [str_addr] -> [len]
    pub const STR_LEN: u8 = 0x91;
    /// Push byte: [str_addr, byte] -> []
    pub const STR_PUSH: u8 = 0x92;
    /// Get byte: [str_addr, index] -> [byte]
    pub const STR_GET: u8 = 0x93;
    /// Set byte: [str_addr, index, byte] -> []
    pub const STR_SET: u8 = 0x94;
    /// Compare strings: [str1, str2] -> [result]
    pub const STR_CMP: u8 = 0x95;
    /// Check equality: [str1, str2] -> [0/1]
    pub const STR_EQ: u8 = 0x96;
    /// Hash string: [str_addr] -> [hash]
    pub const STR_HASH: u8 = 0x97;
    /// Concatenate: [str1, str2] -> [new_str]
    pub const STR_CONCAT: u8 = 0x98;
}

/// Native Calls
pub mod native {
    pub const NATIVE_CALL: u8 = 0xF0;
    pub const NATIVE_READ: u8 = 0xF1;
    pub const NATIVE_WRITE: u8 = 0xF2;
    pub const INPUT_LEN: u8 = 0xF3;
}

/// Execution Control
pub mod exec {
    pub const HALT: u8 = 0xFF;
    pub const HALT_ERR: u8 = 0xFE;
}
