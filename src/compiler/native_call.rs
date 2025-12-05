//! Native Call Support
//!
//! Enables calling external Rust functions from VM-protected code.
//!
//! # How It Works
//!
//! 1. Macro collects all function calls in the protected function
//! 2. Each unique call gets an index in the native table
//! 3. NATIVE_CALL <index> <arg_count> bytecode is emitted
//! 4. At runtime, the native table maps index -> actual function
//!
//! # Example
//!
//! ```ignore
//! // Input:
//! #[vm_protect]
//! fn protected() -> u64 {
//!     is_license_valid() as u64
//! }
//!
//! // Generated:
//! fn protected() -> u64 {
//!     fn __native_0(args: &[u64]) -> u64 {
//!         if is_license_valid() { 1 } else { 0 }
//!     }
//!     static __NATIVE_TABLE: [fn(&[u64]) -> u64; 1] = [__native_0];
//!     __aegis_execute(&BYTECODE, &__NATIVE_TABLE)
//! }
//! ```

use proc_macro2::TokenStream;
use quote::{quote, format_ident};
use syn::{Expr, ExprCall, ExprMethodCall};
use std::collections::HashMap;

use super::CompileError;

/// Type of function call
#[derive(Debug, Clone, PartialEq)]
pub enum CallKind {
    /// Regular function call: foo(), module::func()
    Function,
    /// Method call: obj.method()
    Method,
    /// Associated function: Type::func()
    AssociatedFn,
    /// Closure call: closure_var()
    Closure,
}

/// Information about a native call
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct NativeCallInfo {
    /// Index in the native table
    pub index: usize,
    /// The original call expression (for wrapper generation)
    pub call_expr: Expr,
    /// Number of arguments
    pub arg_count: usize,
    /// Type of call
    pub call_kind: CallKind,
    /// String key for deduplication
    pub call_key: String,
}

/// Collects and manages native calls
pub struct NativeCallCollector {
    /// All registered native calls
    calls: Vec<NativeCallInfo>,
    /// Map from call key to index (for deduplication)
    call_map: HashMap<String, usize>,
}

impl NativeCallCollector {
    /// Create a new collector
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            call_map: HashMap::new(),
        }
    }

    /// Check if there are any native calls
    pub fn has_calls(&self) -> bool {
        !self.calls.is_empty()
    }

    /// Get number of native calls
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Register a function call, returns the index
    pub fn register_call(&mut self, call: &ExprCall) -> Result<usize, CompileError> {
        // Generate a unique key for this call
        let call_key = self.call_to_key_expr(&Expr::Call(call.clone()));

        // Check if already registered (dedup)
        if let Some(&index) = self.call_map.get(&call_key) {
            return Ok(index);
        }

        // Determine call kind
        let call_kind = self.determine_call_kind(&call.func);

        let index = self.calls.len();
        let info = NativeCallInfo {
            index,
            call_expr: Expr::Call(call.clone()),
            arg_count: call.args.len(),
            call_kind,
            call_key: call_key.clone(),
        };

        self.calls.push(info);
        self.call_map.insert(call_key, index);

        Ok(index)
    }

    /// Register a method call, returns the index
    pub fn register_method(&mut self, method: &ExprMethodCall) -> Result<usize, CompileError> {
        // Generate a unique key for this call
        let call_key = self.method_to_key(method);

        // Check if already registered (dedup)
        if let Some(&index) = self.call_map.get(&call_key) {
            return Ok(index);
        }

        let index = self.calls.len();
        let info = NativeCallInfo {
            index,
            call_expr: Expr::MethodCall(method.clone()),
            arg_count: method.args.len() + 1, // +1 for receiver
            call_kind: CallKind::Method,
            call_key: call_key.clone(),
        };

        self.calls.push(info);
        self.call_map.insert(call_key, index);

        Ok(index)
    }

    /// Generate wrapper functions for all native calls
    pub fn generate_wrappers(&self) -> TokenStream {
        let wrappers: Vec<TokenStream> = self.calls.iter().map(|info| {
            let wrapper_name = format_ident!("__native_{}", info.index);

            match &info.call_expr {
                Expr::Call(call) => self.generate_call_wrapper(&wrapper_name, call, info),
                Expr::MethodCall(method) => self.generate_method_wrapper(&wrapper_name, method, info),
                _ => quote! {},
            }
        }).collect();

        quote! {
            #(#wrappers)*
        }
    }

    /// Generate the native table
    pub fn generate_table(&self) -> TokenStream {
        if self.calls.is_empty() {
            return quote! {
                let __native_table: &[fn(&[u64]) -> u64] = &[];
            };
        }

        let wrapper_refs: Vec<TokenStream> = self.calls.iter().map(|info| {
            let wrapper_name = format_ident!("__native_{}", info.index);
            quote! { #wrapper_name }
        }).collect();

        let count = self.calls.len();

        quote! {
            let __native_table: [fn(&[u64]) -> u64; #count] = [
                #(#wrapper_refs),*
            ];
        }
    }

    /// Generate wrapper for a function call
    fn generate_call_wrapper(&self, wrapper_name: &syn::Ident, call: &ExprCall, _info: &NativeCallInfo) -> TokenStream {
        let func = &call.func;
        let arg_count = call.args.len();

        // Generate argument extraction
        let arg_extracts: Vec<TokenStream> = (0..arg_count).map(|i| {
            quote! { args[#i] }
        }).collect();

        // Generate the call
        let call_expr = if arg_extracts.is_empty() {
            quote! { #func() }
        } else {
            quote! { #func(#(#arg_extracts as _),*) }
        };

        // Wrapper function - convert result to u64
        quote! {
            #[inline(never)]
            fn #wrapper_name(args: &[u64]) -> u64 {
                let __result = #call_expr;
                __to_u64(__result)
            }
        }
    }

    /// Generate wrapper for a method call
    fn generate_method_wrapper(&self, wrapper_name: &syn::Ident, method: &ExprMethodCall, _info: &NativeCallInfo) -> TokenStream {
        let method_name = &method.method;
        let arg_count = method.args.len();

        // args[0] is the receiver, args[1..] are the method arguments
        let receiver_extract = quote! { args[0] };

        let arg_extracts: Vec<TokenStream> = (0..arg_count).map(|i| {
            let idx = i + 1; // Skip receiver
            quote! { args[#idx] }
        }).collect();

        // Generate the method call
        // We need to reconstruct the receiver type - for now use unsafe pointer cast
        let call_expr = if arg_extracts.is_empty() {
            quote! {
                let __receiver_ptr = #receiver_extract as *mut ();
                // Method call on raw pointer - caller must ensure safety
                unsafe { (*(__receiver_ptr as *mut _)).#method_name() }
            }
        } else {
            quote! {
                let __receiver_ptr = #receiver_extract as *mut ();
                unsafe { (*(__receiver_ptr as *mut _)).#method_name(#(#arg_extracts as _),*) }
            }
        };

        quote! {
            #[inline(never)]
            fn #wrapper_name(args: &[u64]) -> u64 {
                let __result = #call_expr;
                __to_u64(__result)
            }
        }
    }

    /// Generate the u64 conversion helper
    pub fn generate_conversion_helper() -> TokenStream {
        quote! {
            // Convert any type to u64
            #[inline(always)]
            fn __to_u64<T>(value: T) -> u64 {
                // Handle common types
                let size = std::mem::size_of::<T>();
                if size == 0 {
                    // Unit type ()
                    return 0;
                }
                if size <= 8 {
                    // Fits in u64 - direct transmute
                    let mut result = 0u64;
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            &value as *const T as *const u8,
                            &mut result as *mut u64 as *mut u8,
                            size,
                        );
                    }
                    std::mem::forget(value);
                    result
                } else {
                    // Larger types - return pointer (leaks memory, but safe for now)
                    let boxed = Box::new(value);
                    Box::into_raw(boxed) as u64
                }
            }

            // Convert u64 back to bool
            #[inline(always)]
            fn __from_u64_bool(value: u64) -> bool {
                value != 0
            }
        }
    }

    /// Determine the kind of call from the function expression
    fn determine_call_kind(&self, func: &Expr) -> CallKind {
        match func {
            Expr::Path(path) => {
                // Check if it's an associated function (has ::)
                if path.path.segments.len() > 1 {
                    CallKind::AssociatedFn
                } else {
                    // Could be a closure or regular function
                    // For now, treat single-segment paths as functions
                    CallKind::Function
                }
            }
            _ => CallKind::Closure,
        }
    }

    /// Generate a unique key for a call expression
    fn call_to_key_expr(&self, expr: &Expr) -> String {
        match expr {
            Expr::Call(call) => {
                let func_key = self.expr_to_key(&call.func);
                let args_key: Vec<String> = call.args.iter()
                    .map(|arg| self.expr_to_key(arg))
                    .collect();
                format!("call:{}({})", func_key, args_key.join(","))
            }
            _ => format!("{:?}", expr),
        }
    }

    /// Generate a unique key for a method call
    fn method_to_key(&self, method: &ExprMethodCall) -> String {
        let receiver_key = self.expr_to_key(&method.receiver);
        let method_name = method.method.to_string();
        let args_key: Vec<String> = method.args.iter()
            .map(|arg| self.expr_to_key(arg))
            .collect();
        format!("method:{}.{}({})", receiver_key, method_name, args_key.join(","))
    }

    /// Generate a simple string key for an expression (for dedup)
    fn expr_to_key(&self, expr: &Expr) -> String {
        match expr {
            Expr::Path(path) => {
                path.path.segments.iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::")
            }
            Expr::Lit(lit) => format!("{:?}", lit.lit),
            _ => format!("{:p}", expr), // Fallback: use pointer address for uniqueness
        }
    }
}

impl Default for NativeCallCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_new() {
        let collector = NativeCallCollector::new();
        assert_eq!(collector.len(), 0);
        assert!(!collector.has_calls());
    }
}
