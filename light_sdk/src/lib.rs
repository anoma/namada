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

use borsh_ext::BorshSerializeExt;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::proto::Section;
use namada_core::proto::Signer;
use namada_core::proto::TxError;
use namada_core::proto::{Signature, Tx};
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::dec::Dec;
use namada_core::types::hash::Hash;
use namada_core::types::key::{common, secp256k1};
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::token;
use namada_core::types::token::{Amount, DenominatedAmount, MaspDenom};
use namada_core::types::transaction::Fee;
use namada_core::types::transaction::GasLimit;
use std::collections::BTreeMap;
use std::str::FromStr;

pub mod tx_builders;

//FIXME: check that we covered all the transactions

//FIXME: move these to the proper files
/// Transfer transaction WASM path
pub const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";
/// IBC transaction WASM path
pub const TX_IBC_WASM: &str = "tx_ibc.wasm";
/// Bridge pool WASM path
pub const TX_BRIDGE_POOL_WASM: &str = "tx_bridge_pool.wasm";

pub struct Transfer(Tx);

impl Transfer {
    /// Build a raw Bond transaction from the given parameters
    pub fn new(
        source: Address,
        target: Address,
        token: Address,
        amount: DenominatedAmount,
        key: Option<String>,
        shielded: Option<Hash>,
        timestamp: DateTimeUtc,
        expiration: Option<DateTimeUtc>,
        code_hash: &str,
        chain_id: &str,
    ) -> Result<Self, Error> {
        let init_proposal = namada_core::types::token::Transfer {
            source,
            target,
            token,
            amount,
            key,
            shielded,
        };

        build_tx(
            init_proposal.serialize_to_vec(),
            timestamp,
            expiration,
            code_hash,
            TX_TRANSFER_WASM,
            chain_id,
        )
        .map(Self)
    }

    /// Takes any kind of inner tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        sign_bytes(&self.0)
    }

    /// Attach the given inner signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: Signer,
        signatures: BTreeMap<u8, common::Signature>,
    ) -> Self {
        Self(attach_inner_signatures(&self.0, signer, signatures))
    }
}

pub struct Wrapper(Tx);

impl Wrapper {
    /// Takes a transaction and some signatures and wraps them in a wrapper
    /// transaction
    pub fn new(
        tx: &Tx,
        fee: Fee,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
        unshield_hash: Option<Hash>,
    ) -> Self {
        let mut tx = tx.clone();
        tx.add_wrapper(fee, fee_payer, epoch, gas_limit, unshield_hash);
        Self(tx)
    }

    /// Takes any kind of outer tx and gives me back my sign bytes
    pub fn sign_bytes(&self) -> Hash {
        let mut tx = self.0.clone();
        tx.protocol_filter();
        Signature {
            targets: tx.sechashes(),
            signer: Signer::PubKeys(vec![]),
            signatures: BTreeMap::new(),
        }
        .get_raw_hash()
    }

    /// Attach the given outer signatures to the transaction
    pub fn attach_signatures(
        &self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        let mut tx = self.0.clone();
        tx.add_section(Section::Signature(Signature {
            targets: tx.sechashes(),
            signer: Signer::PubKeys(vec![signer]),
            signatures: [(0, signature)].into_iter().collect(),
        }));
        Self(tx)
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(
        &self,
    ) -> std::result::Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}
