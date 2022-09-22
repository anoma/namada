//! Anoma macros for generating WASM binding code for transactions and validity
//! predicates.

#![doc(html_favicon_url = "https://dev.anoma.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.anoma.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Generate WASM binding for a transaction main entrypoint function.
///
/// This macro expects a function with signature:
///
/// ```compiler_fail
/// fn apply_tx(tx_data: Vec<u8>)
/// ```
#[proc_macro_attribute]
pub fn transaction(_attr: TokenStream, input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as ItemFn);
    let ident = &ast.sig.ident;
    let gen = quote! {
        // Use `wee_alloc` as the global allocator.
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

        #ast

        // The module entrypoint callable by wasm runtime
        #[no_mangle]
        extern "C" fn _apply_tx(tx_data_ptr: u64, tx_data_len: u64) {
            let slice = unsafe {
                core::slice::from_raw_parts(
                    tx_data_ptr as *const u8,
                    tx_data_len as _,
                )
            };
            let tx_data = slice.to_vec();
            #ident(tx_data);
        }
    };
    TokenStream::from(gen)
}

/// Generate WASM binding for validity predicate main entrypoint function.
///
/// This macro expects a function with signature:
///
/// ```compiler_fail
/// fn validate_tx(
///     tx_data: Vec<u8>,
///     addr: Address,
///     keys_changed: BTreeSet<storage::Key>,
///     verifiers: BTreeSet<Address>
/// ) -> bool
/// ```
#[proc_macro_attribute]
pub fn validity_predicate(
    _attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let ast = parse_macro_input!(input as ItemFn);
    let ident = &ast.sig.ident;
    let gen = quote! {
        // Use `wee_alloc` as the global allocator.
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

        #ast

        // The module entrypoint callable by wasm runtime
        #[no_mangle]
        extern "C" fn _validate_tx(
            // VP's account's address
            // TODO Should the address be on demand (a call to host function?)
            addr_ptr: u64,
            addr_len: u64,
            tx_data_ptr: u64,
            tx_data_len: u64,
            keys_changed_ptr: u64,
            keys_changed_len: u64,
            verifiers_ptr: u64,
            verifiers_len: u64,
        ) -> u64 {
            let slice = unsafe {
                core::slice::from_raw_parts(addr_ptr as *const u8, addr_len as _)
            };
            let addr = Address::try_from_slice(slice).unwrap();

            let slice = unsafe {
                core::slice::from_raw_parts(
                    tx_data_ptr as *const u8,
                    tx_data_len as _,
                )
            };
            let tx_data = slice.to_vec();

            let slice = unsafe {
                core::slice::from_raw_parts(
                    keys_changed_ptr as *const u8,
                    keys_changed_len as _,
                )
            };
            let keys_changed: BTreeSet<storage::Key> = BTreeSet::try_from_slice(slice).unwrap();

            let slice = unsafe {
                core::slice::from_raw_parts(
                    verifiers_ptr as *const u8,
                    verifiers_len as _,
                )
            };
            let verifiers: BTreeSet<Address> = BTreeSet::try_from_slice(slice).unwrap();

            // run validation with the concrete type(s)
            if #ident(tx_data, addr, keys_changed, verifiers) {
                1
            } else {
                0
            }
        }
    };
    TokenStream::from(gen)
}
