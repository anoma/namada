

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
        * Can a single wrapper contain more than 1 inner transaction?
        * Can the signer of the inner tx be different than of the wrapper transaction?
        * Is the signature of the outer transaction dependent on the signature of the inner one?
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

use namada_core::proto::Tx;
use namada_core::types::chain::ChainId;
use namada_core::types::transaction::{TxType, WrapperTx};

/*
    * takes a single publickey and builds an inner reveal_pk transaction
    * expose decode and encode functions for Borsh in this sdk so that users don't have to pass an abstract parameter to `add_data`
        * maybe don't expose this and just accept parameter like PKs and encode them under the hood
 */
pub fn build_reveal_pk() -> () {
    /*
    * create a tx with TxType::Raw and set all the data on that one (including a correct chain id and some expiration time)
     */
    let chain_id = "";
    let tx_code_hash = ""; // this needs to be the actual hash
    let tx_tag = ""; // this needs

    // this should all be hidden in a constructor that just takes the parameters to the RevealPk transaction and does all the rest

    // Tx::new creates a TxType::Raw
    let mut inner_tx = Tx::new(ChainId(chain_id.to_owned()), None);
    inner_tx.add_code_from_hash(namada_core::types::hash::Hash::from_str(tx_code_hash).unwrap(), Some(tx_tag.to_owned()));
    inner_tx.add_serialized_data(); // takes the borsh encoded data

    // call - inner_tx.add_wrapper()
    // Does this call really just mutate the inner_tx.header.tx_type away from TxType::Raw and replace it with TxType::Wrapper?
    let outer_tx = WrapperTx::new(fee, fee_payer, epoch, gas_limit, None);
    inner_tx.header.tx_type = TxType::Wrapper(Box::new(outer_tx));

    // the entire tx now exists and can be signed; expose signing functionality by having to call sign_bytes() on the tx object and then passing this to some signing oracle
    /*
    ```rust
        // The inner tx signer signs the Decrypted version of the Header
        let hashes = vec![self.raw_header_hash()];
        self.protocol_filter();

        self.add_section(Section::Signature(Signature::new(
            hashes,
            account_public_keys_map.index_secret_keys(keypairs),
            signer,
        )));
    ```
     */
    // set the tx.header.tx_type to TxType::Raw and then turn it into a section hash with Section::Header(raw_header).get_hash()
    // then sign over that hash and add it into a section

    // now try to sign the outer header
    /*
    ```rust
    pub fn sign_wrapper(&mut self, keypair: common::SecretKey) -> &mut Self {
        self.protocol_filter();
        self.add_section(Section::Signature(Signature::new(
            self.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        self
    }
    ```
     */
    // signs over all the sections

    // now the bytes should be submittable to cometbft `broadcast_tx` - just call tx.to_bytes() and submit

    println!("{:?}", inner_tx);
}

/*
    * takes a reveal pk transaction and wraps it in a wrapper transaction
 */
pub fn wrap_reveal_pk() -> () {

}

/*
    * takes a wrapped reveal_pk transaction and signs it
 */
pub fn sign_reveal_pk() -> () {

}

/*
    * takes any kind of inner tx and gives me back my sign bytes
 */
pub fn get_inner_sign_bytes() -> () {

}

/*
    * takes any kind of outer tx and gives me back my sign bytes
 */
pub fn get_outer_sign_bytes() -> () {

}



pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
