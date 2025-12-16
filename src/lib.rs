//! # RustAegis VM Macro
//!
//! Proc-macro for converting Rust functions to VM bytecode at compile time.
//!
//! ## Usage
//!
//! ```ignore
//! use aegis_vm_macro::vm_protect;
//!
//! #[vm_protect]
//! fn check_value(x: u64) -> u64 {
//!     x + 42
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, ReturnType, FnArg, Pat, Type};

mod anti_analysis;
mod compiler;
mod crypto;
mod integrity;
mod mba;
mod opcodes;
mod polymorphic;
mod string_obfuscation;
mod substitution;
mod value_cryptor;
mod whitebox;

/// Protection level for VM-protected functions
#[derive(Debug, Clone, Copy, PartialEq, Default)]
enum ProtectionLevel {
    /// Plaintext bytecode (for debugging)
    Debug,
    /// Encrypted bytecode (default)
    #[default]
    Standard,
    /// Maximum protection with additional checks
    Paranoid,
}

/// Parse protection level from attribute arguments
fn parse_protection_level(attr: &str) -> ProtectionLevel {
    if attr.contains("debug") {
        ProtectionLevel::Debug
    } else if attr.contains("paranoid") {
        ProtectionLevel::Paranoid
    } else {
        ProtectionLevel::Standard
    }
}

/// VM protection attribute macro
///
/// Converts a Rust function to VM bytecode at compile time.
/// The function body is replaced with VM execution code.
///
/// ## Supported Rust Subset
///
/// ### Types (parameters and return)
/// - `u64`, `u32`, `i64`, `i32`, `u16`, `u8`, `i16`, `i8` - integers
/// - `bool` - converted to u64 (0/1)
/// - `char` - single characters
///
/// ### Literals
/// - Integer literals: `42`, `0xDEAD`, `0b1010`
/// - Boolean literals: `true`, `false`
/// - String literals: `"hello"` - creates heap string
/// - Char literals: `'a'`
/// - Byte literals: `b'a'`, `b"hello"`
///
/// ### Expressions
/// - Binary operators: `+`, `-`, `*`, `/`, `%`, `^`, `&`, `|`, `<<`, `>>`
/// - Comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`
/// - Unary operators: `!`, `-`, `*` (deref)
/// - Type casts: `x as u32`, `y as i64`
/// - Parentheses: `(a + b) * c`
///
/// ### Control Flow
/// - `if`/`else` expressions
/// - `while` loops
/// - `for i in 0..n` loops (ranges)
/// - `loop` (infinite)
/// - `break`, `continue`
/// - `return` (early return)
///
/// ### Arrays & Vectors
/// - Array literals: `[1, 2, 3]`
/// - Repeat syntax: `[0; 10]`
/// - Index access: `arr[i]`
/// - Index assignment: `arr[i] = value`
///
/// ### Method Calls (NEW!)
/// - `.len()` - get length
/// - `.push(value)` - add element
/// - `.pop()` - remove last element
/// - `.get(index)` - get element
/// - `.clear()` - clear collection
/// - `.capacity()` - get capacity
/// - `.is_empty()` - check if empty
/// - `.concat(other)` - concatenate strings
/// - `.eq(other)` - string equality
/// - `.hash()` - string hash
/// - `.min(other)`, `.max(other)` - numeric min/max
/// - `.wrapping_add()`, `.wrapping_sub()`, `.wrapping_mul()`
/// - `.rotate_left()`, `.rotate_right()`
///
/// ### String Support (NEW!)
/// - String literals: `let s = "hello";`
/// - String concatenation: `s1.concat(s2)`
/// - String comparison: `s1.eq(s2)`
/// - String methods: `.len()`, `.push()`, `.get()`
///
/// ### Constructors
/// - `String::new()`, `String::with_capacity(n)`
/// - `Vec::new()`, `Vec::with_capacity(n)`
///
/// ### Not Supported
/// - Match expressions
/// - Closures
/// - Async/await
/// - Panic, unwrap, expect
/// - Struct/enum construction
/// - Complex borrowing patterns
///
/// ## Attributes
///
/// - `#[vm_protect]` - Default: encrypted bytecode
/// - `#[vm_protect(level = "debug")]` - Plaintext for debugging
/// - `#[vm_protect(level = "paranoid")]` - Maximum protection
///
/// ## Example
///
/// ```ignore
/// #[vm_protect]
/// fn add_secret(x: u64) -> u64 {
///     x + 0xDEADBEEF
/// }
///
/// #[vm_protect(level = "debug")]
/// fn debug_func(x: u64) -> u64 {
///     x * 2
/// }
/// ```
#[proc_macro_attribute]
pub fn vm_protect(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let attr_str = attr.to_string();
    let protection_level = parse_protection_level(&attr_str);

    // Extract function info
    let fn_name = &input.sig.ident;
    let fn_vis = &input.vis;
    let fn_generics = &input.sig.generics;
    let fn_inputs = &input.sig.inputs;
    let fn_output = &input.sig.output;

    // Generate a unique function ID based on name (for nonce derivation)
    let fn_id = {
        let name_str = fn_name.to_string();
        let mut hash = 0xcbf29ce484222325u64;
        for byte in name_str.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    };

    // Compile function body to bytecode
    // Use MBA transformations for Paranoid level
    // Use instruction substitution for Standard and Paranoid levels
    let use_mba = protection_level == ProtectionLevel::Paranoid;
    let use_substitution = protection_level != ProtectionLevel::Debug;
    let compile_result = compiler::compile_function_with_natives(&input, use_mba, use_substitution);

    let (raw_bytecode, native_collector) = match compile_result {
        Ok(result) => result,
        Err(e) => {
            return syn::Error::new_spanned(&input, format!("VM compilation error: {}", e))
                .to_compile_error()
                .into();
        }
    };

    // Generate native call wrappers and table if there are any native calls
    let has_native_calls = native_collector.has_calls();
    let native_wrappers = if has_native_calls {
        native_collector.generate_wrappers()
    } else {
        quote! {}
    };
    let native_table = if has_native_calls {
        native_collector.generate_table()
    } else {
        quote! { let __native_table: &[fn(&[u64]) -> u64] = &[]; }
    };
    let native_conversion_helper = if has_native_calls {
        compiler::native_call::NativeCallCollector::generate_conversion_helper()
    } else {
        quote! {}
    };

    // Determine polymorphic level based on protection level
    let poly_level = match protection_level {
        ProtectionLevel::Debug => polymorphic::PolymorphicLevel::None,
        ProtectionLevel::Standard => polymorphic::PolymorphicLevel::Medium,
        ProtectionLevel::Paranoid => polymorphic::PolymorphicLevel::Heavy,
    };

    // Apply polymorphic transformations (junk code, padding)
    // NOTE: Instruction substitution is now applied at compile time (inside compiler.rs)
    // so jump offsets are calculated correctly after substitution.
    // anti_analysis module is still disabled because it adds prefix bytes that break jumps.
    // TODO: Implement jump offset recalculation to enable anti_analysis checks.
    let fn_name_str = fn_name.to_string();
    let bytecode = polymorphic::apply_polymorphism(&raw_bytecode, &fn_name_str, poly_level);

    // Generate input preparation from function args
    let input_prep = generate_input_prep(fn_inputs);

    // Generate output extraction based on return type
    let output_extract = generate_output_extract(fn_output);

    // Generate code based on protection level
    let expanded = match protection_level {
        ProtectionLevel::Debug => {
            // Plaintext bytecode (for debugging) - no polymorphism
            let bytecode_len = raw_bytecode.len();
            let bytecode_bytes = raw_bytecode.iter().map(|b| quote! { #b });

            quote! {
                #fn_vis fn #fn_name #fn_generics(#fn_inputs) #fn_output {
                    // DEBUG MODE: Plaintext bytecode (no polymorphism)
                    static BYTECODE: [u8; #bytecode_len] = [#(#bytecode_bytes),*];

                    // Native call support: type conversion helper
                    #native_conversion_helper

                    // Native call support: wrapper functions for external calls
                    #native_wrappers

                    // Native call support: function table
                    #native_table

                    let input_buffer: aegis_vm::StdVec<u8> = { #input_prep };

                    let result = aegis_vm::execute_with_native_table(&BYTECODE, &input_buffer, &__native_table)
                        .expect("VM execution failed");

                    #output_extract
                }
            }
        }

        ProtectionLevel::Standard | ProtectionLevel::Paranoid => {
            // Apply polymorphism + encrypt bytecode at compile time
            let package = match crypto::encrypt_with_seed(&bytecode, fn_id) {
                Ok(p) => p,
                Err(e) => {
                    return syn::Error::new_spanned(
                        &input,
                        format!("VM encryption error: {}", e)
                    ).to_compile_error().into();
                }
            };

            // Compute integrity hash for the plaintext bytecode
            // This will be verified after decryption at runtime
            let integrity_hash = integrity::fnv1a_hash_with_seed(&bytecode);

            let ciphertext_len = package.ciphertext.len();
            let ciphertext_bytes = package.ciphertext.iter().map(|b| quote! { #b });
            let nonce_bytes = package.nonce.iter().map(|b| quote! { #b });
            let tag_bytes = package.tag.iter().map(|b| quote! { #b });
            let build_id = package.build_id;

            // For Paranoid level, also compute region hashes for detailed tampering detection
            let region_check = if protection_level == ProtectionLevel::Paranoid {
                let integrity_data = integrity::IntegrityData::compute_default(&bytecode);
                let num_regions = integrity_data.regions.len();
                let region_starts: Vec<_> = integrity_data.regions.iter().map(|r| r.start).collect();
                let region_ends: Vec<_> = integrity_data.regions.iter().map(|r| r.end).collect();
                let region_hashes: Vec<_> = integrity_data.regions.iter().map(|r| r.hash).collect();

                quote! {
                    // Region-based integrity check (Paranoid level)
                    static REGION_STARTS: [u32; #num_regions] = [#(#region_starts),*];
                    static REGION_ENDS: [u32; #num_regions] = [#(#region_ends),*];
                    static REGION_HASHES: [u64; #num_regions] = [#(#region_hashes),*];

                    // Verify each region
                    for i in 0..#num_regions {
                        let start = REGION_STARTS[i] as usize;
                        let end = REGION_ENDS[i] as usize;
                        let region_data = &bytecode[start..end];
                        let computed = aegis_vm::compute_hash(region_data);
                        if computed != REGION_HASHES[i] {
                            panic!("E05:{:02x}", i);
                        }
                    }
                }
            } else {
                quote! {}
            };

            // Generate code that works in both std and no_std environments
            // The user's crate decides which path to use via cfg attributes
            quote! {
                #fn_vis fn #fn_name #fn_generics(#fn_inputs) #fn_output {
                    // Encrypted bytecode package (compile-time encrypted)
                    static ENCRYPTED: [u8; #ciphertext_len] = [#(#ciphertext_bytes),*];
                    static NONCE: [u8; 12] = [#(#nonce_bytes),*];
                    static TAG: [u8; 16] = [#(#tag_bytes),*];
                    static BUILD_ID: u64 = #build_id;
                    static INTEGRITY_HASH: u64 = #integrity_hash;

                    // Native call support: type conversion helper
                    #native_conversion_helper

                    // Native call support: wrapper functions for external calls
                    #native_wrappers

                    // Native call support: function table
                    #native_table

                    // Decryption helper - inlined to avoid static caching issues in no_std
                    #[inline(always)]
                    fn __aegis_decrypt() -> aegis_vm::VmResult<aegis_vm::StdVec<u8>> {
                        // Verify build ID matches (E01 = build mismatch)
                        let runtime_build_id = aegis_vm::build_config::BUILD_ID;
                        if BUILD_ID != runtime_build_id {
                            return Err(aegis_vm::VmError::InvalidBytecode);
                        }

                        // Create crypto context and decrypt
                        let seed = aegis_vm::build_config::get_build_seed();
                        let ctx = aegis_vm::CryptoContext::new(seed);
                        let decrypted = ctx.decrypt(&ENCRYPTED, &NONCE, &TAG)
                            .map_err(|_| aegis_vm::VmError::InvalidBytecode)?;

                        // Verify integrity hash
                        let computed_hash = aegis_vm::compute_hash(&decrypted);
                        if computed_hash != INTEGRITY_HASH {
                            return Err(aegis_vm::VmError::InvalidBytecode);
                        }

                        Ok(decrypted)
                    }

                    // Cache decrypted bytecode using aegis_vm re-exports (works for both std and no_std)
                    {
                        static DECRYPTED: aegis_vm::SpinOnce<aegis_vm::StdVec<u8>> = aegis_vm::SpinOnce::new();

                        let bytecode = DECRYPTED.call_once(|| {
                            __aegis_decrypt().expect("E02")
                        });

                        #region_check

                        let input_buffer: aegis_vm::StdVec<u8> = { #input_prep };

                        let result = aegis_vm::execute_with_native_table(bytecode, &input_buffer, &__native_table)
                            .expect("E04");

                        #output_extract
                    }
                }
            }
        }
    };

    expanded.into()
}

/// Generate code to prepare input buffer from function arguments
fn generate_input_prep(inputs: &syn::punctuated::Punctuated<FnArg, syn::token::Comma>) -> proc_macro2::TokenStream {
    let mut prep_code = Vec::new();

    for (idx, arg) in inputs.iter().enumerate() {
        if let FnArg::Typed(pat_type) = arg {
            if let Pat::Ident(pat_ident) = &*pat_type.pat {
                let arg_name = &pat_ident.ident;
                let offset = idx * 8;

                // Check type and generate appropriate conversion
                if is_u64_type(&pat_type.ty) {
                    prep_code.push(quote! {
                        buf[#offset..#offset + 8].copy_from_slice(&#arg_name.to_le_bytes());
                    });
                } else if is_bool_type(&pat_type.ty) {
                    prep_code.push(quote! {
                        buf[#offset..#offset + 8].copy_from_slice(&(#arg_name as u64).to_le_bytes());
                    });
                } else {
                    // Default: try to cast to u64
                    prep_code.push(quote! {
                        buf[#offset..#offset + 8].copy_from_slice(&(#arg_name as u64).to_le_bytes());
                    });
                }
            }
        }
    }

    let num_args = inputs.len();
    let buffer_size = num_args * 8;

    if num_args == 0 {
        quote! { aegis_vm::StdVec::new() }
    } else {
        quote! {
            let mut buf = {
                let mut v = aegis_vm::StdVec::with_capacity(#buffer_size);
                v.resize(#buffer_size, 0u8);
                v
            };
            #(#prep_code)*
            buf
        }
    }
}

/// Generate code to extract output from VM result
fn generate_output_extract(output: &ReturnType) -> proc_macro2::TokenStream {
    match output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => {
            if is_u64_type(ty) {
                quote! { result }
            } else if is_bool_type(ty) {
                quote! { result != 0 }
            } else if is_u32_type(ty) {
                quote! { result as u32 }
            } else if is_i64_type(ty) {
                quote! { result as i64 }
            } else {
                // Default: return as u64
                quote! { result as _ }
            }
        }
    }
}

fn is_u64_type(ty: &Type) -> bool {
    if let Type::Path(path) = ty {
        path.path.is_ident("u64")
    } else {
        false
    }
}

fn is_u32_type(ty: &Type) -> bool {
    if let Type::Path(path) = ty {
        path.path.is_ident("u32")
    } else {
        false
    }
}

fn is_i64_type(ty: &Type) -> bool {
    if let Type::Path(path) = ty {
        path.path.is_ident("i64")
    } else {
        false
    }
}

fn is_bool_type(ty: &Type) -> bool {
    if let Type::Path(path) = ty {
        path.path.is_ident("bool")
    } else {
        false
    }
}

/// String obfuscation attribute macro
///
/// Encrypts all string literals in a function at compile time.
/// Each build produces different ciphertext (based on build seed).
///
/// ## Usage
///
/// ```ignore
/// use aegis_vm_macro::obfuscate_strings;
///
/// #[obfuscate_strings]
/// fn error_handler(code: u32) -> &'static str {
///     match code {
///         1 => "Invalid input",      // Encrypted!
///         2 => "Access denied",      // Encrypted!
///         _ => "Unknown error",      // Encrypted!
///     }
/// }
/// ```
///
/// ## How It Works
///
/// 1. At compile time, all string literals are found and encrypted
/// 2. Each string gets a unique key derived from: build_seed + string_id
/// 3. At runtime, strings are decrypted on first use and cached
/// 4. No plaintext strings appear in the binary
///
/// ## Security Features
///
/// - **Build-specific**: Same source produces different ciphertext each build
/// - **Position-dependent**: Same string at different locations = different ciphertext
/// - **No static keys**: Keys derived from build seed (not in binary)
/// - **Lazy decryption**: Strings decrypted only when accessed
///
/// ## Performance
///
/// - First access: ~100ns decryption overhead
/// - Subsequent access: Zero overhead (cached)
/// - Memory: Encrypted + decrypted versions both in memory after first use
///
/// ## Example Output (in binary)
///
/// ```text
/// // Before: plaintext visible
/// "VM bytecode decryption failed"
///
/// // After: only encrypted bytes visible
/// [0x4a, 0x7f, 0x2c, 0x91, 0x3e, ...]
/// ```
#[proc_macro_attribute]
pub fn obfuscate_strings(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    // Transform the function, encrypting all string literals
    let output = string_obfuscation::obfuscate_function(input);

    output.into()
}

/// Obfuscate a single string literal at compile time
///
/// This macro encrypts a string at compile time and decrypts it at runtime.
/// Use this for individual strings anywhere in your code.
///
/// ## Usage
///
/// ```ignore
/// use aegis_vm::aegis_str;
///
/// // Basic usage
/// let secret = aegis_str!("my secret string");
///
/// // In panic/expect
/// panic!("{}", aegis_str!("VM execution failed"));
/// result.expect(&aegis_str!("Should not fail"));
///
/// // In match arms
/// match error_code {
///     1 => aegis_str!("Invalid input"),
///     2 => aegis_str!("Access denied"),
///     _ => aegis_str!("Unknown error"),
/// }
/// ```
///
/// ## How It Works
///
/// At compile time:
/// ```text
/// aegis_str!("secret")
/// ```
///
/// Becomes:
/// ```text
/// {
///     static ENCRYPTED: [u8; 6] = [0x4a, 0x7f, 0x2c, 0x91, 0x3e, 0x8b];
///     aegis_vm::string_obfuscation::decrypt_static(&ENCRYPTED, 0x1234567890abcdef)
/// }
/// ```
///
/// ## Security
///
/// - String is encrypted with build-seed-derived key
/// - Different key every build
/// - No plaintext in binary
/// - Decrypted on first access, cached thereafter
///
/// Internal version for use within aegis_vm crate.
/// Uses `crate::` path instead of `aegis_vm::`.
#[proc_macro]
pub fn aegis_str_internal(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as syn::LitStr);
    let content = lit_str.value();

    // Skip empty strings
    if content.is_empty() {
        return quote! { "" }.into();
    }

    // Generate unique ID and encrypt
    let string_id = string_obfuscation::generate_string_id(&content, 0);
    let encrypted = string_obfuscation::encrypt_string(&content, string_id);
    let encrypted_len = encrypted.len();
    let encrypted_bytes: Vec<_> = encrypted.iter().map(|b| quote! { #b }).collect();

    let expanded = quote! {
        {
            static __AEGIS_ENC: [u8; #encrypted_len] = [#(#encrypted_bytes),*];
            crate::string_obfuscation::decrypt_static(&__AEGIS_ENC, #string_id)
        }
    };

    expanded.into()
}

#[proc_macro]
pub fn aegis_str(input: TokenStream) -> TokenStream {
    let lit_str = parse_macro_input!(input as syn::LitStr);
    let content = lit_str.value();

    // Skip empty strings
    if content.is_empty() {
        return quote! { "" }.into();
    }

    // Generate unique ID and encrypt
    let string_id = string_obfuscation::generate_string_id(&content, 0);
    let encrypted = string_obfuscation::encrypt_string(&content, string_id);
    let encrypted_len = encrypted.len();
    let encrypted_bytes: Vec<_> = encrypted.iter().map(|b| quote! { #b }).collect();

    let expanded = quote! {
        {
            static __AEGIS_ENC: [u8; #encrypted_len] = [#(#encrypted_bytes),*];
            aegis_vm::string_obfuscation::decrypt_static(&__AEGIS_ENC, #string_id)
        }
    };

    expanded.into()
}
