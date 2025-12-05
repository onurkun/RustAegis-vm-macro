//! String obfuscation for compile-time encryption of string literals
//!
//! This module provides the `obfuscate_strings` attribute macro that encrypts
//! all string literals in a function at compile time using the build seed.
//!
//! ## Usage
//! ```ignore
//! #[obfuscate_strings]
//! fn my_function() {
//!     println!("This string will be encrypted"); // Encrypted at compile time
//!     let msg = "Secret message"; // Also encrypted
//! }
//! ```
//!
//! ## Security
//! - Each string gets a unique key derived from build seed + string position
//! - Strings are XOR encrypted with a key stream
//! - Keys change every build (based on build seed)
//! - No plaintext strings in binary

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    visit_mut::{self, VisitMut},
    Expr, ExprLit, Lit,
};

use crate::crypto::get_build_seed;

/// XOR-based string encryption using build seed
///
/// Key derivation: HMAC-like construction
/// key_stream[i] = hash(build_seed || string_id || position || i)
pub fn encrypt_string(plaintext: &str, string_id: u64) -> Vec<u8> {
    let build_seed = get_build_seed();
    let bytes = plaintext.as_bytes();
    let mut encrypted = vec![0u8; bytes.len()];

    // Generate key stream using FNV-1a based PRNG
    // Each byte position gets a unique key byte
    for (i, &byte) in bytes.iter().enumerate() {
        let key_byte = derive_key_byte(&build_seed, string_id, i as u64);
        encrypted[i] = byte ^ key_byte;
    }

    encrypted
}

/// Derive a single key byte for position i
fn derive_key_byte(seed: &[u8; 32], string_id: u64, position: u64) -> u8 {
    // FNV-1a hash of (seed || string_id || position)
    let mut hash = 0xcbf29ce484222325u64;

    // Mix in seed
    for &byte in seed {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    // Mix in string_id
    for &byte in &string_id.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    // Mix in position
    for &byte in &position.to_le_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    // Return single byte
    (hash & 0xFF) as u8
}

/// Generate a unique string ID based on content and location
pub fn generate_string_id(content: &str, index: usize) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;

    // Hash the content
    for byte in content.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    // Mix in index to make each occurrence unique
    hash ^= index as u64;
    hash = hash.wrapping_mul(0x100000001b3);

    hash
}

/// Visitor that transforms string literals to encrypted versions
pub struct StringObfuscator {
    /// Counter for unique string IDs
    string_counter: usize,
    /// Collected encrypted strings (id, encrypted_bytes, original_len)
    pub encrypted_strings: Vec<(u64, Vec<u8>)>,
}

impl StringObfuscator {
    pub fn new() -> Self {
        Self {
            string_counter: 0,
            encrypted_strings: Vec::new(),
        }
    }
}

impl VisitMut for StringObfuscator {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        // First, recursively visit nested expressions
        visit_mut::visit_expr_mut(self, expr);

        // Then check if this is a string literal
        if let Expr::Lit(ExprLit { lit: Lit::Str(lit_str), .. }) = expr {
            let content = lit_str.value();

            // Skip empty strings
            if content.is_empty() {
                return;
            }

            // Generate unique ID for this string
            let string_id = generate_string_id(&content, self.string_counter);
            self.string_counter += 1;

            // Encrypt the string
            let encrypted = encrypt_string(&content, string_id);
            let encrypted_len = encrypted.len();

            // Store for later (to generate static data)
            self.encrypted_strings.push((string_id, encrypted.clone()));

            // Replace with decryption call
            // aegis_vm::decrypt_string(&ENCRYPTED_STRING_N, string_id)
            let encrypted_bytes: Vec<_> = encrypted.iter().map(|b| quote! { #b }).collect();

            let replacement = quote! {
                {
                    // Encrypted string (compile-time)
                    static ENCRYPTED: [u8; #encrypted_len] = [#(#encrypted_bytes),*];
                    static STRING_ID: u64 = #string_id;

                    // Decrypt at runtime (lazy, cached)
                    aegis_vm::string_obfuscation::decrypt_static(&ENCRYPTED, STRING_ID)
                }
            };

            // Parse the replacement and swap
            *expr = syn::parse2(replacement).expect("Failed to parse replacement expression");
        }
    }
}

/// Process a function and obfuscate all string literals
pub fn obfuscate_function(mut func: syn::ItemFn) -> TokenStream {
    let mut obfuscator = StringObfuscator::new();

    // Visit and transform all string literals in the function body
    obfuscator.visit_item_fn_mut(&mut func);

    // Generate the transformed function
    func.to_token_stream()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = "Hello, World!";
        let string_id = generate_string_id(original, 0);
        let encrypted = encrypt_string(original, string_id);

        // Decrypt manually
        let build_seed = get_build_seed();
        let mut decrypted = vec![0u8; encrypted.len()];
        for (i, &byte) in encrypted.iter().enumerate() {
            let key_byte = derive_key_byte(&build_seed, string_id, i as u64);
            decrypted[i] = byte ^ key_byte;
        }

        assert_eq!(original.as_bytes(), &decrypted[..]);
    }

    #[test]
    fn test_different_ids_different_encryption() {
        let content = "same content";
        let enc1 = encrypt_string(content, 1);
        let enc2 = encrypt_string(content, 2);

        // Same content with different IDs should produce different ciphertext
        assert_ne!(enc1, enc2);
    }
}
