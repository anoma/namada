//! Namada macros for generating WASM binding code for transactions and validity
//! predicates.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

use proc_macro::TokenStream;
use proc_macro2::{Span as Span2, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, ExprAssign, FnArg, ItemFn, ItemStruct, Pat};

/// Generate WASM binding for a transaction main entrypoint function.
///
/// It expects an attribute in the form: `gas = u64`, so that a call to the gas
/// meter can be injected as the first instruction of the transaction to account
/// for the whitelisted gas amount.
///
/// This macro expects a function with signature:
///
/// ```compiler_fail
/// fn apply_tx(
///     ctx: &mut Ctx,
///     tx_data: Vec<u8>
/// ) -> TxResult
/// ```
#[proc_macro_attribute]
pub fn transaction(attr: TokenStream, input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as ItemFn);
    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = ast;
    let stmts = &block.stmts;
    let ident = &sig.ident;
    let attr_ast = parse_macro_input!(attr as ExprAssign);
    let gas = attr_ast.right;
    let ctx = match sig.inputs.first() {
        Some(FnArg::Typed(pat_type)) => {
            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                &pat_ident.ident
            } else {
                panic!("Unexpected token, expected ctx ident")
            }
        }
        _ => panic!("Unexpected token, expected ctx ident"),
    };
    let gen = quote! {
        // Use `wee_alloc` as the global allocator.
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

        #(#attrs)* #vis #sig {
            // Consume the whitelisted gas
            #ctx.charge_gas(#gas)?;
            #(#stmts)*
        }

        // The module entrypoint callable by wasm runtime
        #[no_mangle]
        extern "C" fn _apply_tx(tx_data_ptr: u64, tx_data_len: u64) {
            let slice = unsafe {
                core::slice::from_raw_parts(
                    tx_data_ptr as *const u8,
                    tx_data_len as _,
                )
            };
            let tx_data = Tx::try_from_slice(slice).unwrap();

            // The context on WASM side is only provided by the VM once its
            // being executed (in here it's implicit). But because we want to
            // have interface consistent with the VP interface, in which the
            // context is explicit, in here we're just using an empty `Ctx`
            // to "fake" it.
            let mut ctx = unsafe { namada_tx_prelude::Ctx::new() };

            if let Err(err) = #ident(&mut ctx, tx_data) {
                namada_tx_prelude::debug_log!("Transaction error: {}", err);
                // crash the transaction to abort
                panic!();
            }
        }
    };
    TokenStream::from(gen)
}

/// Generate WASM binding for validity predicate main entrypoint function.
///
/// It expects an attribute in the form: `gas = u64`, so that a call to the gas
/// meter can be injected as the first instruction of the validity predicate to
/// account for the whitelisted gas amount.
///
/// This macro expects a function with signature:
///
/// ```compiler_fail
/// fn validate_tx(
///     ctx: &Ctx,
///     tx_data: Vec<u8>,
///     addr: Address,
///     keys_changed: BTreeSet<storage::Key>,
///     verifiers: BTreeSet<Address>
/// ) -> VpResult
/// ```
#[proc_macro_attribute]
pub fn validity_predicate(
    attr: TokenStream,
    input: TokenStream,
) -> TokenStream {
    let ast = parse_macro_input!(input as ItemFn);
    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = ast;
    let stmts = &block.stmts;
    let ident = &sig.ident;
    let attr_ast = parse_macro_input!(attr as ExprAssign);
    let gas = attr_ast.right;
    let ctx = match sig.inputs.first() {
        Some(FnArg::Typed(pat_type)) => {
            if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                &pat_ident.ident
            } else {
                panic!("Unexpected token, expected ctx ident")
            }
        }
        _ => panic!("Unexpected token, expected ctx ident"),
    };
    let gen = quote! {
        // Use `wee_alloc` as the global allocator.
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

        #(#attrs)* #vis #sig {
            // Consume the whitelisted gas
            #ctx.charge_gas(#gas)?;
            #(#stmts)*
        }

        // The module entrypoint callable by wasm runtime
        #[no_mangle]
        extern "C" fn _validate_tx(
            // VP's account's address
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
            let tx_data = Tx::try_from_slice(slice).unwrap();

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

            // The context on WASM side is only provided by the VM once its
            // being executed (in here it's implicit). But because we want to
            // have interface identical with the native VPs, in which the
            // context is explicit, in here we're just using an empty `Ctx`
            // to "fake" it.
            let ctx = unsafe { namada_vp_prelude::Ctx::new() };

            // run validation with the concrete type(s)
            match #ident(&ctx, tx_data, addr, keys_changed, verifiers)
            {
                Ok(true) => 1,
                Ok(false) => 0,
                Err(err) => {
                    namada_vp_prelude::debug_log!("Validity predicate error: {}", err);
                    0
                },
            }
        }
    };
    TokenStream::from(gen)
}

#[proc_macro_derive(StorageKeys)]
pub fn derive_storage_keys(struct_def: TokenStream) -> TokenStream {
    derive_storage_keys_inner(struct_def.into()).into()
}

#[inline]
// TODO: use this crate for errors: https://crates.io/crates/proc-macro-error
fn derive_storage_keys_inner(struct_def: TokenStream2) -> TokenStream2 {
    let struct_def: ItemStruct = syn::parse2(struct_def)
        .expect("Expected a struct in the StorageKeys derive");

    // type check the struct - all fields must be of type `&'static str`
    let fields = match &struct_def.fields {
        syn::Fields::Named(fields) => &fields.named,
        _ => panic!(
            "Only named struct fields are accepted in StorageKeys derives"
        ),
    };

    let mut idents = vec![];

    for field in fields {
        let field_type = field.ty.to_token_stream().to_string();
        if field_type != "& 'static str" {
            panic!(
                "Expected `&'static str` field type in StorageKeys derive, \
                 but got `{field_type}` instead"
            );
        }
        idents.push(field.ident.clone().expect("Expected a named field"));
    }

    idents.sort();

    let ident_list = create_punctuated(&idents, |ident| ident.clone());
    let values_list = create_punctuated(&idents, |ident| {
        let storage_key = ident.to_token_stream().to_string();
        syn::FieldValue {
            attrs: vec![],
            member: syn::Member::Named(ident.clone()),
            colon_token: Some(syn::token::Colon {
                spans: [Span2::call_site()],
            }),
            expr: syn::Expr::Lit(syn::ExprLit {
                attrs: vec![],
                lit: syn::Lit::Str(syn::LitStr::new(
                    storage_key.as_str(),
                    Span2::call_site(),
                )),
            }),
        }
    });

    let struct_def_ident = &struct_def.ident;

    let helper_fns = idents
        .iter()
        .fold(vec![], |mut accum, ident| {
            let is_fn = {
                let id = format!("is_{ident}_key_at_addr");
                let id = syn::Ident::new(&id, ident.span());
                quote! {
                    #[allow(missing_docs)]
                    pub fn #id(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                        matches!(&key.segments[..], [
                            namada_core::types::storage::DbKeySeg::AddressSeg(a),
                            namada_core::types::storage::DbKeySeg::StringSeg(#ident),
                        ] if a == address && #ident == #struct_def_ident::VALUES.#ident)
                    }
                }
            };
            let get_fn = {
                let id = format!("get_{ident}_key_at_addr");
                let id = syn::Ident::new(&id, ident.span());
                quote! {
                    #[allow(missing_docs)]
                    pub fn #id(address: Address) -> namada_core::types::storage::Key {
                        namada_core::types::storage::Key {
                            segments: vec![
                                namada_core::types::storage::DbKeySeg::AddressSeg(address),
                                namada_core::types::storage::DbKeySeg::StringSeg(#struct_def_ident::VALUES.#ident.to_string()),
                            ],
                        }
                    }
                }
            };
            accum.push(is_fn);
            accum.push(get_fn);
            accum
        });

    quote! {
        impl #struct_def_ident {
            /// A list of all storage keys
            pub const ALL: &[&'static str] = {
                let #struct_def_ident {
                    #ident_list
                } = Self::VALUES;

                &[ #ident_list ]
            };

            /// Storage keys values
            pub const VALUES: #struct_def_ident = Self {
                #values_list
            };
        }

        #(#helper_fns)*
    }
}

#[inline]
fn create_punctuated<F, M>(
    idents: &[syn::Ident],
    mut map: F,
) -> Punctuated<M, syn::token::Comma>
where
    F: FnMut(&syn::Ident) -> M,
{
    idents.iter().fold(Punctuated::new(), |mut accum, ident| {
        accum.push(map(ident));
        accum
    })
}

#[cfg(test)]
mod test_proc_macros {
    use syn::File;

    use super::*;

    /// Test if we reject enums in `StorageKeys` derives.
    #[test]
    #[should_panic(expected = "Expected a struct in the StorageKeys derive")]
    fn test_storage_keys_panics_on_enum() {
        derive_storage_keys_inner(quote! {
            enum What {
                The,
                Funk,
            }
        });
    }

    /// Test if we reject unit structs in `StorageKeys` derives.
    #[test]
    #[should_panic(expected = "Only named struct fields are accepted in \
                               StorageKeys derives")]
    fn test_storage_keys_panics_on_unit_structs() {
        derive_storage_keys_inner(quote! {
            struct WhatTheFunk;
        });
    }

    /// Test if we reject tuple structs in `StorageKeys` derives.
    #[test]
    #[should_panic(expected = "Only named struct fields are accepted in \
                               StorageKeys derives")]
    fn test_storage_keys_panics_on_tuple_structs() {
        derive_storage_keys_inner(quote! {
            struct WhatTheFunk(&'static str);
        });
    }

    /// Test if the `ALL` slice generated in `StorageKeys` macro
    /// derives is sorted in ascending order.
    #[test]
    fn test_storage_keys_derive_sorted_slice() {
        let test_struct = quote! {
            struct Keys {
                word: &'static str,
                is: &'static str,
                bird: &'static str,
                the: &'static str,
            }
        };
        let test_impl: File =
            syn::parse2(derive_storage_keys_inner(test_struct))
                .expect("Test failed");

        let expected_impl = quote! {
            impl Keys {
                /// A list of all storage keys
                pub const ALL: &[&'static str] = {
                    let Keys { bird, is, the, word } = Self::VALUES;
                    &[bird, is, the, word]
                };

                /// Storage keys values
                pub const VALUES: Keys = Self {
                    bird: "bird",
                    is: "is",
                    the: "the",
                    word: "word"
                };
            }
            #[allow(missing_docs)]
            pub fn is_bird_key_at_addr(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::types::storage::DbKeySeg::AddressSeg(a),
                    namada_core::types::storage::DbKeySeg::StringSeg(bird),
                ] if a == address && bird == Keys::VALUES.bird)
            }
            #[allow(missing_docs)]
            pub fn get_bird_key_at_addr(address: Address) -> namada_core::types::storage::Key {
                namada_core::types::storage::Key {
                    segments: vec![
                        namada_core::types::storage::DbKeySeg::AddressSeg(address),
                        namada_core::types::storage::DbKeySeg::StringSeg(Keys::VALUES.bird.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_is_key_at_addr(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::types::storage::DbKeySeg::AddressSeg(a),
                    namada_core::types::storage::DbKeySeg::StringSeg(is),
                ] if a == address && is == Keys::VALUES.is)
            }
            #[allow(missing_docs)]
            pub fn get_is_key_at_addr(address: Address) -> namada_core::types::storage::Key {
                namada_core::types::storage::Key {
                    segments: vec![
                        namada_core::types::storage::DbKeySeg::AddressSeg(address),
                        namada_core::types::storage::DbKeySeg::StringSeg(Keys::VALUES.is.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_the_key_at_addr(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::types::storage::DbKeySeg::AddressSeg(a),
                    namada_core::types::storage::DbKeySeg::StringSeg(the),
                ] if a == address && the == Keys::VALUES.the)
            }
            #[allow(missing_docs)]
            pub fn get_the_key_at_addr(address: Address) -> namada_core::types::storage::Key {
                namada_core::types::storage::Key {
                    segments: vec![
                        namada_core::types::storage::DbKeySeg::AddressSeg(address),
                        namada_core::types::storage::DbKeySeg::StringSeg(Keys::VALUES.the.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_word_key_at_addr(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::types::storage::DbKeySeg::AddressSeg(a),
                    namada_core::types::storage::DbKeySeg::StringSeg(word),
                ] if a == address && word == Keys::VALUES.word)
            }
            #[allow(missing_docs)]
            pub fn get_word_key_at_addr(address: Address) -> namada_core::types::storage::Key {
                namada_core::types::storage::Key {
                    segments: vec![
                        namada_core::types::storage::DbKeySeg::AddressSeg(address),
                        namada_core::types::storage::DbKeySeg::StringSeg(Keys::VALUES.word.to_string()),
                    ],
                }
            }
        };
        let expected_impl: File =
            syn::parse2(expected_impl).expect("Test failed");

        pretty_assertions::assert_eq!(test_impl, expected_impl);
    }

    /// Test if we reject structs with non static string fields in
    /// `StorageKeys` macro derives.
    #[test]
    #[should_panic(
        expected = "Expected `&'static str` field type in StorageKeys derive"
    )]
    fn test_typecheck_storage_keys_derive() {
        derive_storage_keys_inner(quote! {
            struct Keys {
                x: &'static str,
                y: i32,
                z: u64,
            }
        });
    }

    /// Test if we reject structs with non static lifetimes.
    #[test]
    #[should_panic(
        expected = "Expected `&'static str` field type in StorageKeys derive"
    )]
    fn test_storage_keys_derive_with_non_static_str() {
        derive_storage_keys_inner(quote! {
            struct Keys<'a> {
                x: &'static str,
                y: &'a str,
            }
        });
    }

    /// Test that the create storage keys produces
    /// the expected code.
    #[test]
    fn test_derive_storage_keys() {
        let test_struct = quote! {
            struct Keys {
                param1: &'static str,
                param2: &'static str,
            }
        };
        let test_impl: File =
            syn::parse2(derive_storage_keys_inner(test_struct))
                .expect("Test failed");

        let expected_impl = quote! {
            impl Keys {
                /// A list of all storage keys
                pub const ALL: &[&'static str] = {
                    let Keys { param1, param2 } = Self::VALUES;
                    &[param1, param2]
                };
                /// Storage keys values
                pub const VALUES: Keys = Self {
                    param1: "param1",
                    param2: "param2"
                };
            }
            #[allow(missing_docs)]
            pub fn is_param1_key_at_addr(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::types::storage::DbKeySeg::AddressSeg(a),
                    namada_core::types::storage::DbKeySeg::StringSeg(param1),
                ] if a == address && param1 == Keys::VALUES.param1)
            }
            #[allow(missing_docs)]
            pub fn get_param1_key_at_addr(address: Address) -> namada_core::types::storage::Key {
                namada_core::types::storage::Key {
                    segments: vec![
                        namada_core::types::storage::DbKeySeg::AddressSeg(address),
                        namada_core::types::storage::DbKeySeg::StringSeg(Keys::VALUES.param1.to_string()),
                    ],
                }
            }
            #[allow(missing_docs)]
            pub fn is_param2_key_at_addr(key: &namada_core::types::storage::Key, address: &Address) -> bool {
                matches!(&key.segments[..], [
                    namada_core::types::storage::DbKeySeg::AddressSeg(a),
                    namada_core::types::storage::DbKeySeg::StringSeg(param2),
                ] if a == address && param2 == Keys::VALUES.param2)
            }
            #[allow(missing_docs)]
            pub fn get_param2_key_at_addr(address: Address) -> namada_core::types::storage::Key {
                namada_core::types::storage::Key {
                    segments: vec![
                        namada_core::types::storage::DbKeySeg::AddressSeg(address),
                        namada_core::types::storage::DbKeySeg::StringSeg(Keys::VALUES.param2.to_string()),
                    ],
                }
            }
        };
        let expected_impl: File =
            syn::parse2(expected_impl).expect("Test failed");

        pretty_assertions::assert_eq!(test_impl, expected_impl);
    }
}
