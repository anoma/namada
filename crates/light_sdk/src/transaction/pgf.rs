use std::collections::HashMap;

use namada_sdk::address::Address;
use namada_sdk::dec::Dec;
use namada_sdk::hash::Hash;
use namada_sdk::key::common;
use namada_sdk::storage::Epoch;
use namada_sdk::token::DenominatedAmount;
use namada_sdk::tx::data::GasLimit;
use namada_sdk::tx::{Signature, Tx, TxError};

use super::{attach_fee, attach_fee_signature, GlobalArgs};
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

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, epoch, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
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

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, epoch, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}
