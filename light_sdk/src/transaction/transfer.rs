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

const TX_TRANSFER_WASM: &str = "tx_transfer.wasm";

pub struct Transfer(Tx);

impl Transfer {
    /// Build a raw Transfer transaction from the given parameters
    pub fn new(
        source: Address,
        target: Address,
        token: Address,
        amount: DenominatedAmount,
        key: Option<String>,
        //FIXME: handle masp here
        shielded: Option<Hash>,
        args: GlobalArgs,
    ) -> Self {
        let init_proposal = namada_core::types::token::Transfer {
            source,
            target,
            token,
            amount,
            key,
            shielded,
        };

        Self(transaction::build_tx(
            args,
            init_proposal.serialize_to_vec(),
            TX_TRANSFER_WASM.to_string(),
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
