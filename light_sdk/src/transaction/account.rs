use crate::transaction;
use borsh_ext::BorshSerializeExt;
use namada_core::ledger::governance::storage::proposal::ProposalType;
use namada_core::proto::Section;
use namada_core::proto::SignatureIndex;
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

use super::GlobalArgs;

const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_REVEAL_PK_WASM: &str = "tx_reveal_pk.wasm";
const TX_UPDATE_ACCOUNT_WASM: &str = "tx_update_account.wasm";

pub struct InitAccount(Tx);

impl InitAccount {
    /// Build a raw InitAccount transaction from the given parameters
    pub fn new(
        public_keys: Vec<common::PublicKey>,
        vp_code_hash: Hash,
        threshold: u8,
        args: GlobalArgs,
    ) -> Self {
        let init_account =
            namada_core::types::transaction::account::InitAccount {
                public_keys,
                vp_code_hash,
                threshold,
            };

        Self(transaction::build_tx(
            args,
            init_account,
            TX_INIT_ACCOUNT_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct RevealPk(Tx);

impl RevealPk {
    /// Build a raw Reveal Public Key transaction from the given parameters
    pub fn new(public_key: common::PublicKey, args: GlobalArgs) -> Self {
        Self(transaction::build_tx(
            args,
            public_key,
            TX_REVEAL_PK_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}

pub struct UpdateAccount(Tx);

impl UpdateAccount {
    /// Build a raw UpdateAccount transaction from the given parameters
    pub fn new(
        addr: Address,
        vp_code_hash: Option<Hash>,
        public_keys: Vec<common::PublicKey>,
        threshold: Option<u8>,
        args: GlobalArgs,
    ) -> Self {
        let update_account =
            namada_core::types::transaction::account::UpdateAccount {
                addr,
                vp_code_hash,
                public_keys,
                threshold,
            };

        Self(transaction::build_tx(
            args,
            update_account,
            TX_UPDATE_ACCOUNT_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_msg_to_sign(&self) -> Vec<u8> {
        transaction::get_msg_to_sign(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        mut self,
        signatures: Vec<SignatureIndex>,
    ) -> Self {
        Self(transaction::attach_raw_signatures(self.0, signatures))
    }
}
