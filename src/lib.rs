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
mod substitution;
mod value_cryptor;

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
/// - `u64`, `u32`, `i64`, `i32` - integers
/// - `bool` - converted to u64 (0/1)
///
/// ### Expressions
/// - Integer literals: `42`, `0xDEAD`, `0b1010`
/// - Binary operators: `+`, `-`, `*`, `^`, `&`, `|`, `<<`, `>>`
/// - Comparisons: `==`, `!=`, `<`, `>`, `<=`, `>=`
/// - Unary operators: `!`, `-`
/// - Parentheses: `(a + b) * c`
/// - Simple if/else: `if cond { a } else { b }`
///
/// ### Not Supported
/// - Heap allocation (Box, Vec, String)
/// - References and borrowing
/// - Loops (for, while, loop)
/// - Match expressions
/// - Closures
/// - Async/await
/// - Panic, unwrap, expect
/// - Method calls
/// - Struct/enum construction
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
    let raw_bytecode = compiler::compile_function_full(&input, use_mba, use_substitution);

    let raw_bytecode = match raw_bytecode {
        Ok(bc) => bc,
        Err(e) => {
            return syn::Error::new_spanned(&input, format!("VM compilation error: {}", e))
                .to_compile_error()
                .into();
        }
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

                    let input_buffer: Vec<u8> = { #input_prep };

                    let result = aegis_vm::execute(&BYTECODE, &input_buffer)
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
                        let region_data = &decrypted[start..end];
                        let computed = aegis_vm::compute_hash(region_data);
                        if computed != REGION_HASHES[i] {
                            panic!("VM bytecode tampering detected in region {}", i);
                        }
                    }
                }
            } else {
                quote! {}
            };

            quote! {
                #fn_vis fn #fn_name #fn_generics(#fn_inputs) #fn_output {
                    use std::sync::OnceLock;

                    // Encrypted bytecode package (compile-time encrypted)
                    static ENCRYPTED: [u8; #ciphertext_len] = [#(#ciphertext_bytes),*];
                    static NONCE: [u8; 12] = [#(#nonce_bytes),*];
                    static TAG: [u8; 16] = [#(#tag_bytes),*];
                    static BUILD_ID: u64 = #build_id;
                    static INTEGRITY_HASH: u64 = #integrity_hash;

                    // Decrypt once and cache
                    static DECRYPTED: OnceLock<Vec<u8>> = OnceLock::new();

                    let bytecode = DECRYPTED.get_or_init(|| {
                        // Verify build ID matches
                        let runtime_build_id = aegis_vm::build_config::BUILD_ID;
                        if BUILD_ID != runtime_build_id {
                            panic!("VM build ID mismatch: bytecode was compiled with different build");
                        }

                        // Create crypto context and decrypt
                        let seed = aegis_vm::build_config::get_build_seed();
                        let ctx = aegis_vm::CryptoContext::new(seed);
                        let decrypted = ctx.decrypt(&ENCRYPTED, &NONCE, &TAG)
                            .expect("VM bytecode decryption failed - possible tampering");

                        // Verify integrity hash (quick check)
                        let computed_hash = aegis_vm::compute_hash(&decrypted);
                        if computed_hash != INTEGRITY_HASH {
                            panic!("VM bytecode integrity check failed - tampering detected");
                        }

                        #region_check

                        decrypted
                    });

                    let input_buffer: Vec<u8> = { #input_prep };

                    let result = aegis_vm::execute(bytecode, &input_buffer)
                        .expect("VM execution failed");

                    #output_extract
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
        quote! { Vec::new() }
    } else {
        quote! {
            let mut buf = vec![0u8; #buffer_size];
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
