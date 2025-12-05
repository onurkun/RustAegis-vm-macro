//! Modular AST to Bytecode Compiler
//!
//! Converts Rust expressions to VM bytecode at compile time.
//!
//! Module structure:
//! - mod.rs: Compiler struct and core infrastructure
//! - emit.rs: Bytecode emission helpers
//! - literal.rs: Literal compilation (int, bool, string)
//! - expr.rs: Expression compilation
//! - stmt.rs: Statement compilation
//! - array.rs: Array/vector operations
//! - control.rs: Control flow (if, while, loop, for)
//! - method.rs: Method call compilation (.len(), .push(), etc.)
//! - cast.rs: Type cast compilation (as i32, as u8, etc.)

mod emit;
mod literal;
mod expr;
mod stmt;
mod array;
mod control;
mod method;
mod cast;

use syn::{ItemFn, Pat, FnArg};
use std::collections::BTreeMap;
use crate::opcodes::exec;
use crate::crypto::OpcodeTable;
use crate::mba::MbaTransformer;
use crate::substitution::Substitution;
use crate::value_cryptor::ValueCryptor;

/// Compilation error
#[derive(Debug)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Variable type for proper method dispatch
#[allow(dead_code)] // IntegerSized reserved for future packed storage optimization
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum VarType {
    /// Integer (u8, u16, u32, u64, i8, i16, i32, i64) with optional size in bytes
    Integer,
    /// Sized integer with explicit byte size (1, 2, 4, or 8)
    IntegerSized(u8),
    /// String (heap allocated)
    String,
    /// Vector/Array (heap allocated)
    Vector,
    /// Boolean (1 byte logically, but stored as 8 bytes for alignment)
    Bool,
    /// Struct (heap allocated) - contains struct type name
    Struct(std::string::String),
    /// Tuple (heap allocated) - contains element types for proper offset calculation
    Tuple(Vec<VarType>),
}

#[allow(dead_code)] // Reserved for future packed storage optimization
impl VarType {
    /// Get the size in bytes for this type (for tuple offset calculation)
    /// All types are stored as 8 bytes for alignment, but this tracks logical size
    pub fn size_bytes(&self) -> usize {
        match self {
            VarType::Integer => 8,
            VarType::IntegerSized(size) => *size as usize,
            VarType::String => 8,  // pointer
            VarType::Vector => 8,  // pointer
            VarType::Bool => 8,    // stored as u64 for alignment
            VarType::Struct(_) => 8, // pointer
            VarType::Tuple(elems) => {
                // Sum of all element sizes (each aligned to 8 bytes)
                elems.iter().map(|e| e.aligned_size()).sum()
            }
        }
    }

    /// Get aligned size (always 8 bytes for heap storage)
    pub fn aligned_size(&self) -> usize {
        // For now, all values are stored as 8 bytes for simplicity
        // This could be optimized later for packed storage
        8
    }

    /// Check if this type needs heap cleanup
    pub fn needs_cleanup(&self) -> bool {
        match self {
            VarType::String | VarType::Vector => true,
            VarType::Struct(_) => true, // checked separately for unit structs
            VarType::Tuple(elems) => {
                // Tuple needs cleanup if it has elements (allocated on heap)
                // or if any element needs cleanup
                !elems.is_empty() || elems.iter().any(|e| e.needs_cleanup())
            }
            _ => false,
        }
    }
}

/// Struct field definition
#[derive(Debug, Clone)]
pub(crate) struct FieldDef {
    /// Field name
    pub name: std::string::String,
    /// Byte offset from struct start
    pub offset: usize,
}

/// Struct definition for compile-time field lookup
#[derive(Debug, Clone)]
pub(crate) struct StructDef {
    /// Struct name (kept for debugging/error messages)
    #[allow(dead_code)]
    pub name: std::string::String,
    /// Fields with their offsets
    pub fields: Vec<FieldDef>,
    /// Total size in bytes
    pub size: usize,
}

impl StructDef {
    /// Get field offset by name
    pub fn get_field_offset(&self, field_name: &str) -> Option<usize> {
        self.fields.iter()
            .find(|f| f.name == field_name)
            .map(|f| f.offset)
    }
}

/// Variable information - register and type
#[derive(Debug, Clone)]
pub(crate) struct VarInfo {
    /// Register index
    pub reg: u8,
    /// Variable type
    pub var_type: VarType,
    /// Is signed (for integers)
    pub is_signed: bool,
    /// Needs heap cleanup on scope exit
    pub needs_cleanup: bool,
}

/// Variable location - either in input buffer or in a register
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum VarLocation {
    /// Input buffer offset (for function arguments)
    InputOffset(usize),
    /// Register index (for local variables)
    Register(u8),
    /// Array stored in register (register holds heap address)
    /// Contains: register index, element size (1, 2, 4, or 8 bytes)
    Array(u8, u8),
    /// String stored in register (register holds heap address)
    String(u8),
}

/// Loop context for break/continue support
#[derive(Debug, Clone)]
pub(crate) struct LoopContext {
    /// Label for continue (jump to condition/increment)
    pub continue_label: String,
    /// Label for break (jump past loop end)
    pub break_label: String,
    /// Scope depth when loop started (for cleanup on break/continue)
    pub scope_depth: usize,
}

/// Compiler state
pub struct Compiler {
    /// Generated bytecode
    pub(crate) bytecode: Vec<u8>,
    /// Function argument name -> input buffer offset
    pub(crate) arg_offsets: BTreeMap<String, usize>,
    /// Scoped variable storage - Vec of scopes, each scope maps name -> VarInfo
    /// Innermost scope is at the end of the Vec
    pub(crate) scopes: Vec<BTreeMap<String, VarInfo>>,
    /// Legacy: Variable types for method dispatch (will be deprecated)
    pub(crate) var_types: BTreeMap<String, VarLocation>,
    /// Struct definitions for compile-time field lookup
    pub(crate) struct_defs: BTreeMap<String, StructDef>,
    /// Next available register for locals
    pub(crate) next_local_reg: u8,
    /// Current input buffer offset for next argument
    pub(crate) next_arg_offset: usize,
    /// Label name -> bytecode offset for jumps
    pub(crate) labels: BTreeMap<String, usize>,
    /// Pending jump fixups (bytecode offset, label name)
    pub(crate) fixups: Vec<(usize, String)>,
    /// Unique label counter
    pub(crate) label_counter: usize,
    /// Stack of active loops for break/continue
    pub(crate) loop_stack: Vec<LoopContext>,
    /// Opcode encoding table
    pub(crate) opcode_table: OpcodeTable,
    /// MBA transformer
    pub(crate) mba: MbaTransformer,
    /// Enable MBA transformations
    pub(crate) mba_enabled: bool,
    /// Substitution state
    pub(crate) subst: Substitution,
    /// ValueCryptor for constant obfuscation
    pub(crate) value_cryptor: ValueCryptor,
    /// Enable heavy value encryption
    pub(crate) value_cryptor_enabled: bool,
    /// Enable opaque predicates injection
    pub(crate) opaque_predicates_enabled: bool,
}

impl Compiler {
    /// Create new compiler
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_options(false, false)
    }

    /// Create compiler with MBA transformations enabled
    #[allow(dead_code)]
    pub fn with_mba(mba_enabled: bool) -> Self {
        Self::with_options(mba_enabled, false)
    }

    /// Create compiler with full options
    pub fn with_options(mba_enabled: bool, substitution_enabled: bool) -> Self {
        let seed = crate::crypto::get_opcode_table().get_seed();

        // Start with one global scope
        let mut scopes = Vec::new();
        scopes.push(BTreeMap::new());

        Self {
            bytecode: Vec::new(),
            arg_offsets: BTreeMap::new(),
            scopes,
            var_types: BTreeMap::new(),
            struct_defs: BTreeMap::new(),
            next_local_reg: 0,
            next_arg_offset: 0,
            labels: BTreeMap::new(),
            fixups: Vec::new(),
            label_counter: 0,
            loop_stack: Vec::new(),
            opcode_table: crate::crypto::get_opcode_table(),
            mba: MbaTransformer::new(seed),
            mba_enabled,
            subst: Substitution::new(seed, substitution_enabled),
            value_cryptor: ValueCryptor::new(seed),
            value_cryptor_enabled: mba_enabled,
            // Opaque predicates enabled for standard+ protection (when substitution is on)
            opaque_predicates_enabled: substitution_enabled,
        }
    }

    /// Current bytecode position
    pub(crate) fn pos(&self) -> usize {
        self.bytecode.len()
    }

    /// Generate unique label
    pub(crate) fn unique_label(&mut self, prefix: &str) -> String {
        let label = format!("{}_{}", prefix, self.label_counter);
        self.label_counter += 1;
        label
    }

    /// Mark current position as label
    pub(crate) fn mark_label(&mut self, name: &str) {
        self.labels.insert(name.to_string(), self.pos());
    }

    /// Register a function argument
    pub(crate) fn register_arg(&mut self, name: &str) {
        self.arg_offsets.insert(name.to_string(), self.next_arg_offset);
        self.next_arg_offset += 8;
    }

    // =========================================================================
    // Scope Management
    // =========================================================================

    /// Push a new scope (called at block entry)
    pub(crate) fn push_scope(&mut self) {
        self.scopes.push(BTreeMap::new());
    }

    /// Pop current scope and emit cleanup for heap variables
    pub(crate) fn pop_scope(&mut self) {
        if let Some(scope) = self.scopes.pop() {
            // Emit HEAP_FREE for variables that need cleanup
            for (_name, info) in scope.iter() {
                if info.needs_cleanup {
                    // Push the heap address from register, then free it
                    self.emit_push_reg(info.reg);
                    self.emit_heap_free();
                }
            }
        }
    }

    /// Get current scope depth (number of active scopes)
    pub(crate) fn current_scope_depth(&self) -> usize {
        self.scopes.len()
    }

    /// Emit cleanup code for all scopes from current down to target_depth (exclusive)
    /// Used for early exits (return, break, continue) to properly free heap memory
    ///
    /// Example: If we have scopes [global, func, loop, inner] (depth=4)
    /// and target_depth=2 (loop level), we clean up [inner, loop] -> scopes at index 3, 2
    pub(crate) fn emit_scope_cleanup(&mut self, target_depth: usize) {
        let current_depth = self.scopes.len();

        // Clean up scopes from innermost to target (exclusive)
        // We iterate backwards from current to target
        if current_depth <= target_depth {
            return; // Nothing to clean up
        }

        // First, collect all registers that need cleanup (to avoid borrow issues)
        let mut regs_to_free = Vec::new();
        for depth in (target_depth..current_depth).rev() {
            if let Some(scope) = self.scopes.get(depth) {
                for (_name, info) in scope.iter() {
                    if info.needs_cleanup {
                        regs_to_free.push(info.reg);
                    }
                }
            }
        }

        // Now emit cleanup code
        for reg in regs_to_free {
            self.emit_push_reg(reg);
            self.emit_heap_free();
        }
    }

    /// Define a variable in the current scope
    pub(crate) fn define_var(&mut self, name: &str, var_type: VarType, is_signed: bool) -> Result<u8, CompileError> {
        self.define_var_internal(name, var_type, is_signed, false)
    }

    /// Define a variable that borrows from another (no cleanup needed)
    /// Used when extracting tuple elements: let inner = t.0
    pub(crate) fn define_var_borrowed(&mut self, name: &str, var_type: VarType, is_signed: bool) -> Result<u8, CompileError> {
        self.define_var_internal(name, var_type, is_signed, true)
    }

    /// Internal variable definition
    fn define_var_internal(&mut self, name: &str, var_type: VarType, is_signed: bool, is_borrowed: bool) -> Result<u8, CompileError> {
        if self.next_local_reg >= 248 {
            return Err(CompileError("Too many local variables (max 248)".to_string()));
        }

        let reg = self.next_local_reg;
        self.next_local_reg += 1;

        // Determine if cleanup is needed - borrowed values never need cleanup
        // Unit structs/tuples (size 0) also don't need cleanup
        let needs_cleanup = if is_borrowed {
            false
        } else {
            match &var_type {
                VarType::String | VarType::Vector => true,
                VarType::Struct(struct_name) => {
                    // Check struct size - unit structs don't need cleanup
                    self.struct_defs.get(struct_name)
                        .map(|def| def.size > 0)
                        .unwrap_or(false)
                }
                VarType::Tuple(elems) => !elems.is_empty(),  // Empty tuple () doesn't need cleanup
                _ => false,
            }
        };

        // Update legacy var_types for compatibility (using reference before move)
        match &var_type {
            VarType::String => {
                self.var_types.insert(name.to_string(), VarLocation::String(reg));
            }
            VarType::Vector => {
                self.var_types.insert(name.to_string(), VarLocation::Array(reg, 8));
            }
            _ => {
                self.var_types.insert(name.to_string(), VarLocation::Register(reg));
            }
        }

        let info = VarInfo {
            reg,
            var_type,
            is_signed,
            needs_cleanup,
        };

        // Add to current scope
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name.to_string(), info);
        }

        Ok(reg)
    }

    /// Lookup a variable in all scopes (innermost first)
    pub(crate) fn lookup_var(&self, name: &str) -> Option<&VarInfo> {
        // Search from innermost to outermost scope
        for scope in self.scopes.iter().rev() {
            if let Some(info) = scope.get(name) {
                return Some(info);
            }
        }
        None
    }

    /// Check if a variable is signed
    pub(crate) fn is_var_signed(&self, name: &str) -> bool {
        if let Some(info) = self.lookup_var(name) {
            return info.is_signed;
        }
        false
    }

    /// Get variable type
    pub(crate) fn get_var_type(&self, name: &str) -> Option<VarType> {
        if let Some(info) = self.lookup_var(name) {
            return Some(info.var_type.clone());
        }
        None
    }

    /// Get variable location (argument or local) - uses new scope system
    pub(crate) fn get_var_location(&self, name: &str) -> Option<VarLocation> {
        // Check scopes first (innermost to outermost)
        if let Some(info) = self.lookup_var(name) {
            return match info.var_type {
                VarType::String => Some(VarLocation::String(info.reg)),
                VarType::Vector => Some(VarLocation::Array(info.reg, 8)),
                _ => Some(VarLocation::Register(info.reg)),
            };
        }
        // Check arguments
        if let Some(&offset) = self.arg_offsets.get(name) {
            return Some(VarLocation::InputOffset(offset));
        }
        // Legacy fallback
        if let Some(loc) = self.var_types.get(name) {
            return Some(loc.clone());
        }
        None
    }

    /// Apply all jump fixups
    pub(crate) fn apply_fixups(&mut self) -> Result<(), CompileError> {
        for (fixup_pos, label) in &self.fixups {
            let target = self.labels.get(label)
                .ok_or_else(|| CompileError(format!("Unknown label: {}", label)))?;

            let from = fixup_pos + 2;
            let offset = (*target as isize) - (from as isize);

            if offset < i16::MIN as isize || offset > i16::MAX as isize {
                return Err(CompileError(format!("Jump offset out of range: {}", offset)));
            }

            let offset_bytes = (offset as i16).to_le_bytes();
            self.bytecode[*fixup_pos] = offset_bytes[0];
            self.bytecode[*fixup_pos + 1] = offset_bytes[1];
        }
        Ok(())
    }

    /// Extract variable name from pattern
    pub(crate) fn extract_pat_name(pat: &Pat) -> Result<String, CompileError> {
        match pat {
            Pat::Ident(pat_ident) => Ok(pat_ident.ident.to_string()),
            Pat::Type(pat_type) => Self::extract_pat_name(&pat_type.pat),
            _ => Err(CompileError("Unsupported pattern in let binding".to_string())),
        }
    }

    /// Finalize compilation
    pub(crate) fn finalize(&mut self) -> Result<Vec<u8>, CompileError> {
        self.apply_fixups()?;

        if self.bytecode.is_empty() || self.bytecode.last().copied() != Some(exec::HALT) {
            self.emit_op(exec::HALT);
        }

        Ok(self.bytecode.clone())
    }
}

// ============================================================================
// Public API - Compile functions
// ============================================================================

/// Compile a function to bytecode (without MBA or substitution)
#[allow(dead_code)]
pub fn compile_function(func: &ItemFn) -> Result<Vec<u8>, CompileError> {
    compile_function_full(func, false, false)
}

/// Compile a function to bytecode with MBA transformations
#[allow(dead_code)]
pub fn compile_function_with_mba(func: &ItemFn) -> Result<Vec<u8>, CompileError> {
    compile_function_full(func, true, false)
}

/// Compile a function with substitution obfuscation
#[allow(dead_code)]
pub fn compile_function_with_substitution(func: &ItemFn) -> Result<Vec<u8>, CompileError> {
    compile_function_full(func, false, true)
}

/// Compile a function with full obfuscation (MBA + Substitution)
#[allow(dead_code)]
pub fn compile_function_paranoid(func: &ItemFn) -> Result<Vec<u8>, CompileError> {
    compile_function_full(func, true, true)
}

/// Compile a function with configurable options
pub fn compile_function_full(func: &ItemFn, mba_enabled: bool, substitution_enabled: bool) -> Result<Vec<u8>, CompileError> {
    let mut compiler = Compiler::with_options(mba_enabled, substitution_enabled);

    // Register function arguments
    for arg in &func.sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(pat_ident) = &*pat_type.pat {
                compiler.register_arg(&pat_ident.ident.to_string());
            }
        }
    }

    // Compile function body
    compiler.compile_block(&func.block)?;

    compiler.finalize()
}
