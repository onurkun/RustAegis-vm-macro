# RustAegis Macros

Proc-macro crate for [RustAegis](https://github.com/onurkun/RustAegis) - a code virtualization and obfuscation framework.

## Usage

This crate is re-exported by `aegis_vm`. You should use `aegis_vm` directly:

```toml
[dependencies]
aegis_vm = "0.2.2"
```

```rust
use aegis_vm::vm_protect;

#[vm_protect]
fn secret_function(x: u64) -> u64 {
    x + 42
}

// NEW in v0.2.2: Native function calls work automatically!
fn external_check() -> bool { true }

#[vm_protect]
fn protected_with_calls() -> bool {
    let result: bool = external_check();  // Auto-wrapped
    result
}
```

## Features

- **VM Bytecode Compilation:** Converts Rust AST to custom VM bytecode
- **Native Function Calls:** External functions automatically wrapped and callable from VM
- **String Obfuscation:** `aegis_str!` macro for compile-time string encryption
- **White-Box Cryptography:** AES key derivation without exposing keys
- **Protection Levels:** debug, standard, paranoid

## Important Notes

- Use explicit `bool` type annotations: `let x: bool = func();`
- Rust macros (`println!`, etc.) not supported - use wrapper functions
- Supported types: `u64`, `u32`, `i64`, `i32`, `u16`, `u8`, `bool`, `char`

## License

MIT
