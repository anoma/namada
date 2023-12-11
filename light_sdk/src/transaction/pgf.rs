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
use std::collections::HashMap;
use std::str::FromStr;

use super::GlobalArgs;

const TX_RESIGN_STEWARD: &str = "tx_resign_steward.wasm";
const TX_UPDATE_STEWARD_COMMISSION: &str = "tx_update_steward_commission.wasm";

pub struct ResignSteward(Tx);

impl ResignSteward {
    /// Build a raw ResignSteward transaction from the given parameters
    pub fn new(steward: Address, args: GlobalArgs) -> Self {
        Self(transaction::build_tx(
            args,
            steward,
            TX_RESIGN_STEWARD.to_string(),
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

pub struct UpdateStewardCommission(Tx);

impl UpdateStewardCommission {
    /// Build a raw UpdateStewardCommission transaction from the given parameters
    pub fn new(
        steward: Address,
        commission: HashMap<Address, Dec>,
        args: GlobalArgs,
    ) -> Self {
        let update_commission =
            namada_core::types::transaction::pgf::UpdateStewardCommission {
                steward,
                commission,
            };

        Self(transaction::build_tx(
            args,
            update_commission,
            TX_UPDATE_STEWARD_COMMISSION.to_string(),
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
