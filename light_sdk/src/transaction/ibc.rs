use crate::transaction;
use borsh_ext::BorshSerializeExt;
use ibc::core::Msg;
pub use namada_core::ibc::applications::transfer::msgs::transfer::MsgTransfer;
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

const TX_IBC_WASM: &str = "tx_ibc.wasm";

pub struct IbcTransfer(Tx);

impl IbcTransfer {
    /// Build a raw IbcTransfer transaction from the given parameters
    pub fn new(
        packet_data: MsgTransfer,
        GlobalArgs {
            timestamp,
            expiration,
            code_hash,
            chain_id,
        }: GlobalArgs,
    ) -> Self {
        let mut tx = Tx::new(chain_id, expiration);
        tx.header.timestamp = timestamp;
        tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_string()));

        let mut data = vec![];
        prost::Message::encode(&packet_data.to_any(), &mut data).unwrap();
        tx.set_data(namada_core::proto::Data::new(data));

        Self(tx)
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
