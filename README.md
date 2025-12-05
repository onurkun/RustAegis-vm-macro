# RustAegis Macros

Proc-macro crate for [RustAegis](https://github.com/onurkun/RustAegis) - a code virtualization and obfuscation framework.

## Usage

This crate is re-exported by `aegis_vm`. You should use `aegis_vm` directly:

```toml
[dependencies]
aegis_vm = "0.2.0"
```

```rust
use aegis_vm::vm_protect;

#[vm_protect]
fn secret_function(x: u64) -> u64 {
    x + 42
}
```

## Features

- **VM Bytecode Compilation:** Converts Rust AST to custom VM bytecode
- **String Obfuscation:** `aegis_str!` macro for compile-time string encryption
- **White-Box Cryptography:** AES key derivation without exposing keys
- **Protection Levels:** debug, standard, paranoid

## License

MIT
