/*
 * tx status
 * block height
 * account balance
 * anything else if needed
 */
// pub mod reading;

// either sync or async tx submission - prints tx hashes that can be used for tracking
// pub mod writing;
// pub mod wallet;

// ====

/*
   SDK for building transactions without having to pass in an entire Namada chain

   Requirements:
       * Don't try to refactor the existing sdk - this shouldn't cause any merge conflicts with anything
       * Minimal dependencies - no filesystem, no multi-threading, no IO, no wasm decoding
           * core with default features turned off seems fine
       * No lifetimes or abstract types
           * it should be dump-ass simple to use this from other languages or contexts
       * Callers should never have to worry about TxType::Raw or TxType::Wrapper - this should be hidden in the implementation
       * No usage of async
           * None of this signing code requires any async behavior - it's crazy to force all callers into async

   Proposed Flow:
       * the crate should expose 1 struct and an implementation for that struct for every transaction type
           * every struct (ie Bond) should have these functions
               * new() - to create a new type of Bond - it takes all parameters, like chain_id (this will lead to duplication, which is desired for a simple API (if desired the caller can build their own TxFactory))
               * sign_bytes() - the bytes that need to be signed by the signer
       * the crate should expose 1 struct and an implementation for a wrapper transaction
           * new()
               * should take a correctly signed inner tx (this is not enforced but rather documented, you can use this API to create garbage)
               * takes the inner tx & the inner signature
               * should take all the fields that are required by the wrapper
           * sign_bytes() - the bytes that need to be signed by the signer

    Future Development:
       * !!! AVOID ABSTRACT TYPES (that a caller needs to pass in) or LIFETIMES (in the caller api) LIKE THE PLAGUE !!!
       * around this core light_sdk we can build more complex features
           * get data via helper functions from a connected node
               * can have an query endpoint that just takes a Tendermint RPC node and allows me to query it
           * verify signatures
           * support multi-sig signers
           * dry-run these transactions
               * ALWAYS EXPOSE SYNC AND ASYNC FUNCTIONALITY
                   * never force callers into using async - we must always support an API that synchronous
       * none of this extra stuff should leak into the core
           * need to be able to import the core to iOS or other languages without complex dependencies
       * key backends
           * file based key backends that callers can use
           * libudev based key backends that call out to HSMs

    Questions:
       * Can a single wrapper contain more than 1 inner transaction? Yes but it will not be executed (just extra payload for which gas is paid)
       * Can the signer of the inner tx be different than of the wrapper transaction? Yes it can
       * Is the signature of the outer transaction dependent on the signature of the inner one? Not at all, we only sign headers of transactions, so the inner signature is not part of the message that is signed for the wrapper
       * How do the tags work again? Can I only sign over the tags and not the wasm_hash?
           * If we need wasm_hashes, those should be saved as constants in the binary and a caller can decide to pass in their own wasm hashes or load the constants.

           MAINNET_BOND_WASM_HASH: &str = "mainnet_wasm_hash";
           Bond::new("wasm_hash");
           Bond::new(MAINNET_BOND_WASM_HASH)
*/

/*
   * need a function sign_bytes() that just returns me the bytes to sign
   * need a function that takes a transaction and some sign_bytes and forms a submittable tx from them
   * this is roughly the API that we want
   ```rust
       let keypair = gen_keypair();

       let mut wrapper =
           Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
               Fee {
                   amount_per_gas_unit: 0.into(),
                   token: shell.wl_storage.storage.native_token.clone(),
               },
               keypair.ref_to(),
               Epoch(0),
               0.into(),
               None,
           ))));
       wrapper.header.chain_id = shell.chain_id.clone();
       wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
       wrapper.set_data(Data::new(
           "Encrypted transaction data".as_bytes().to_owned(),
       ));
       wrapper.add_section(Section::Signature(Signature::new(
           wrapper.sechashes(),
           [(0, keypair)].into_iter().collect(),
           None,
       )));
   ```
*/

pub mod reading;
pub mod transaction;
pub mod writing;
