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

/// Register Operations (R0-R7)
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
