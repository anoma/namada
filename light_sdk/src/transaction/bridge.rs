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

pub use namada_core::types::eth_bridge_pool::{GasFee, TransferToEthereum};

use super::GlobalArgs;

const TX_BRIDGE_POOL_WASM: &str = "tx_bridge_pool.wasm";

/// A transfer over the Ethereum bridge
pub struct BridgeTransfer(Tx);

impl BridgeTransfer {
    /// Build a raw BridgeTransfer transaction from the given parameters
    pub fn new(
        transfer: TransferToEthereum,
        gas_fee: GasFee,
        args: GlobalArgs,
    ) -> Self {
        let pending_transfer =
            namada_core::types::eth_bridge_pool::PendingTransfer {
                transfer,
                gas_fee,
            };

        Self(transaction::build_tx(
            args,
            pending_transfer,
            TX_BRIDGE_POOL_WASM.to_string(),
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
