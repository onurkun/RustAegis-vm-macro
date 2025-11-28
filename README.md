# RustAegis Macros

Proc-macro crate for [RustAegis](https://github.com/onurkun/RustAegis) - a code virtualization and obfuscation framework.

## Usage

This crate is re-exported by `aegis_vm`. You should use `aegis_vm` directly:

```toml
[dependencies]
aegis_vm = "0.1.0"
```

```rust
use aegis_vm::vm_protect;

#[vm_protect]
fn secret_function(x: u64) -> u64 {
    x + 42
}
```

## License

MIT
