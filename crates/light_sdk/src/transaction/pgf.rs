use std::collections::HashMap;

use namada_sdk::tx::Tx;
use namada_sdk::types::address::Address;
use namada_sdk::types::dec::Dec;
use namada_sdk::types::hash::Hash;
use namada_sdk::types::key::common;

use super::GlobalArgs;
use crate::transaction;

const TX_RESIGN_STEWARD: &str = "tx_resign_steward.wasm";
const TX_UPDATE_STEWARD_COMMISSION: &str = "tx_update_steward_commission.wasm";

/// A transaction to resign from stewarding pgf
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

/// Transaction to update a pgf steward's commission rate
pub struct UpdateStewardCommission(Tx);

impl UpdateStewardCommission {
    /// Build a raw UpdateStewardCommission transaction from the given
    /// parameters
    pub fn new(
        steward: Address,
        commission: HashMap<Address, Dec>,
        args: GlobalArgs,
    ) -> Self {
        let update_commission =
            namada_sdk::tx::data::pgf::UpdateStewardCommission {
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
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
